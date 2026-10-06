from uuid import uuid4

from .audit import AuditTrail
from .domain import ConflictError, InvalidTransition, NotFoundError, PermissionDenied, ValidationError
from .repository import utcnow
from .rules import RuleEngine


class DomainService:
    def __init__(self, repository, rules=None):
        self.repository = repository
        self.rules = rules or RuleEngine()
        self.audit = AuditTrail(repository)

    def _lookup(self, kind, field, value):
        return self.repository.find_entities(self.rules.normalize_kind(kind), field, value)

    def health(self):
        return {"status": "ok" if self.repository.ping() else "error"}

    def create(self, actor, kind, data, idempotency_key=None):
        kind = self.rules.normalize_kind(kind)
        payload = dict(data or {})
        if idempotency_key:
            existing = self.repository.get_idempotency(actor.user_id, idempotency_key)
            if existing:
                entity = self.repository.get_entity(existing)
                if entity:
                    return entity
        self.rules.validate_create(actor, kind, payload, self._lookup)
        entity_id = str(payload.pop("id", "") or uuid4())
        if self.repository.get_entity(entity_id):
            raise ConflictError("entity already exists: " + entity_id)
        status = self.rules.initial_status(kind)
        if kind == "dataset":
            payload.setdefault("policy_version", 1)
            payload.setdefault("policy_updated_at", utcnow())
        elif kind == "application":
            dataset = self.repository.find_entities("dataset", "id", payload.get("dataset_id"))
            if dataset:
                payload.setdefault(
                    "policy_version", dataset[0]["data"].get("policy_version", 1)
                )
        entity = self.repository.create_entity(entity_id, kind, status, payload, actor.user_id)
        self.audit.record(entity_id, actor, "create", None, status, {"kind": kind})
        if idempotency_key:
            self.repository.save_idempotency(actor.user_id, idempotency_key, entity_id)
        return entity

    def transition(self, actor, entity_id, action, data=None, expected_version=None):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        if entity["kind"] == "dataset" and action == "update_policy":
            return self._update_policy(actor, entity, data or {}, expected_version)
        if entity["kind"] == "dataset" and action == "reconcile":
            return self._reconcile(actor, entity)
        if entity["kind"] == "application" and action == "reconfirm":
            return self._reconfirm(actor, entity)
        if entity["kind"] == "grant" and action == "fetch":
            return self._fetch(actor, entity)
        if entity["kind"] == "grant" and action == "suspend":
            return self._suspend(actor, entity, data or {}, expected_version)
        expected = int(expected_version) if expected_version is not None else entity["version"]
        next_status, patch = self.rules.validate_transition(
            actor, entity, action, dict(data or {}), self._lookup
        )
        merged = dict(entity["data"])
        merged.update(patch)
        updated = self.repository.update_entity(entity_id, expected, next_status, merged)
        self.audit.record(
            entity_id,
            actor,
            action,
            entity["status"],
            updated["status"],
            {"patch": patch},
        )
        return updated

    def _update_policy(self, actor, dataset, data, expected_version):
        self.rules._ensure_role(actor, ("admin", "committee"))
        access_policy = data.get("access_policy")
        if not access_policy or len(access_policy) < 3:
            raise ValidationError("access_policy is required")
        now = utcnow()
        new_data = dict(dataset["data"])
        new_data["access_policy"] = access_policy
        new_data["policy_version"] = int(new_data.get("policy_version", 1)) + 1
        new_data["policy_updated_at"] = now
        expected = int(expected_version) if expected_version is not None else dataset["version"]
        updated = self.repository.update_entity(
            dataset["id"], expected, dataset["status"], new_data
        )
        self.audit.record(
            dataset["id"],
            actor,
            "update_policy",
            dataset["status"],
            updated["status"],
            {
                "policy_version": new_data["policy_version"],
                "policy_updated_at": now,
                "access_policy": access_policy,
            },
        )
        self._cascade_policy(actor, dataset["id"], new_data["policy_version"])
        return updated

    def _cascade_policy(self, actor, dataset_id, policy_version):
        applications = self.repository.find_entities(
            "application", "data.dataset_id", dataset_id
        )
        for app in applications:
            app_version = int(app["data"].get("policy_version", 1))
            if app_version >= policy_version:
                continue
            try:
                self._apply_policy_to_application(actor, app, policy_version)
            except Exception:
                break

    def _apply_policy_to_application(self, actor, app, policy_version):
        status = app["status"]
        if status in ("submitted", "under_review"):
            new_data = dict(app["data"])
            new_data["policy_version"] = policy_version
            updated = self.repository.update_entity(
                app["id"], app["version"], "invalidated", new_data
            )
            self.audit.record(
                app["id"],
                actor,
                "policy_invalidated",
                app["status"],
                updated["status"],
                {"policy_version": policy_version},
            )
        elif status == "approved":
            new_data = dict(app["data"])
            new_data["policy_version"] = policy_version
            updated = self.repository.update_entity(
                app["id"], app["version"], "reconfirming", new_data
            )
            self.audit.record(
                app["id"],
                actor,
                "policy_reconfirm_required",
                app["status"],
                updated["status"],
                {"policy_version": policy_version},
            )
            grants = self.repository.find_entities(
                "grant", "data.application_id", app["id"]
            )
            for grant in grants:
                if grant["status"] == "active":
                    grant_data = dict(grant["data"])
                    grant_data["policy_version"] = policy_version
                    suspended = self.repository.update_entity(
                        grant["id"], grant["version"], "suspended", grant_data
                    )
                    self.audit.record(
                        grant["id"],
                        actor,
                        "suspend",
                        "active",
                        suspended["status"],
                        {"policy_version": policy_version, "reason": "policy changed"},
                    )
                    self.repository.record_external_ledger(
                        grant["id"], "suspend", policy_version, False
                    )
        elif status == "draft":
            new_data = dict(app["data"])
            new_data["policy_version"] = policy_version
            updated = self.repository.update_entity(
                app["id"], app["version"], "draft", new_data
            )
            self.audit.record(
                app["id"],
                actor,
                "policy_recalculated",
                app["status"],
                updated["status"],
                {"policy_version": policy_version},
            )

    def _reconcile(self, actor, dataset):
        self.rules._ensure_role(actor, ("admin", "committee"))
        policy_version = int(dataset["data"].get("policy_version", 1))
        self._cascade_policy(actor, dataset["id"], policy_version)
        return self.repository.get_entity(dataset["id"])

    def _reconfirm(self, actor, application):
        self.rules._ensure_role(actor, ("admin", "committee"))
        if application["status"] != "reconfirming":
            raise InvalidTransition(
                "cannot reconfirm from status %s" % application["status"]
            )
        dataset = self.repository.find_entities(
            "dataset", "id", application["data"].get("dataset_id")
        )
        policy_version = int(dataset[0]["data"].get("policy_version", 1)) if dataset else 1
        new_data = dict(application["data"])
        new_data["policy_version"] = policy_version
        updated = self.repository.update_entity(
            application["id"], application["version"], "approved", new_data
        )
        self.audit.record(
            application["id"],
            actor,
            "reconfirm",
            application["status"],
            updated["status"],
            {"policy_version": policy_version},
        )
        grants = self.repository.find_entities(
            "grant", "data.application_id", application["id"]
        )
        for grant in grants:
            if grant["status"] == "suspended":
                grant_data = dict(grant["data"])
                grant_data["policy_version"] = policy_version
                resumed = self.repository.update_entity(
                    grant["id"], grant["version"], "active", grant_data
                )
                self.audit.record(
                    grant["id"],
                    actor,
                    "reconfirm",
                    "suspended",
                    resumed["status"],
                    {"policy_version": policy_version},
                )
                self.repository.record_external_ledger(
                    grant["id"], "reconfirm", policy_version, True
                )
        return updated

    def _suspend(self, actor, grant, data, expected_version):
        self.rules._ensure_role(actor, ("admin", "committee"))
        if grant["status"] != "active":
            raise InvalidTransition("cannot suspend from status %s" % grant["status"])
        reason = data.get("reason")
        if not reason:
            raise ValidationError("missing required field: reason")
        policy_version = int(grant["data"].get("policy_version", 1))
        expected = int(expected_version) if expected_version is not None else grant["version"]
        updated = self.repository.update_entity(
            grant["id"], expected, "suspended", dict(grant["data"])
        )
        self.audit.record(
            grant["id"],
            actor,
            "suspend",
            grant["status"],
            updated["status"],
            {"reason": reason, "policy_version": policy_version},
        )
        self.repository.record_external_ledger(
            grant["id"], "suspend", policy_version, False
        )
        return updated

    def _fetch(self, actor, grant):
        policy_version = int(grant["data"].get("policy_version", 1))
        if grant["status"] == "active":
            self.repository.record_external_ledger(
                grant["id"], "fetch", policy_version, True
            )
            self.audit.record(
                grant["id"],
                actor,
                "fetch",
                grant["status"],
                grant["status"],
                {"policy_version": policy_version, "decision": "allowed"},
            )
            return {
                "decision": "allowed",
                "grant_id": grant["id"],
                "policy_version": policy_version,
            }
        self.repository.record_external_ledger(
            grant["id"], "fetch", policy_version, False
        )
        self.audit.record(
            grant["id"],
            actor,
            "fetch",
            grant["status"],
            grant["status"],
            {"policy_version": policy_version, "decision": "denied"},
        )
        raise PermissionDenied(
            "grant %s is not active (status=%s); fetch denied"
            % (grant["id"], grant["status"])
        )

    def batch_reconfirm(self, actor, dataset_id, application_ids):
        self.rules._ensure_role(actor, ("admin", "committee"))
        dataset = self.repository.get_entity(dataset_id)
        if not dataset:
            raise NotFoundError("dataset not found: " + dataset_id)
        if not application_ids:
            raise ValidationError("application_ids is required")
        apps = []
        skipped = []
        for aid in application_ids:
            app = self.repository.get_entity(aid)
            if not app or app["kind"] != "application":
                raise ValidationError("application not found: " + aid)
            if app["data"].get("dataset_id") != dataset_id:
                raise ValidationError(
                    "application %s does not belong to dataset %s" % (aid, dataset_id)
                )
            if app["status"] == "approved" and int(app["data"].get("policy_version", 0)) >= int(
                dataset["data"].get("policy_version", 1)
            ):
                skipped.append(app)
                continue
            if app["status"] != "reconfirming":
                raise ValidationError(
                    "application %s is not reconfirming (status=%s)" % (aid, app["status"])
                )
            apps.append(app)
        results = [{"id": app["id"], "status": "reconfirmed"} for app in skipped]
        for app in apps:
            try:
                self._reconfirm(actor, app)
                results.append({"id": app["id"], "status": "reconfirmed"})
            except Exception as exc:
                results.append(
                    {"id": app["id"], "status": "failed", "error": str(exc)}
                )
                break
        return {"dataset_id": dataset_id, "results": results}

    def reconcile_audit(self, actor):
        if actor.role != "auditor":
            raise PermissionDenied("only auditor can reconcile the audit ledger")
        grants = self.repository.list_entities("grant")
        matched = []
        mismatched = []
        for grant in grants:
            local_active = grant["status"] == "active"
            external = self.repository.latest_external_ledger(grant["id"])
            if external is None:
                continue
            external_allowed = external["allowed"]
            policy_version = int(grant["data"].get("policy_version", 1))
            if local_active == external_allowed:
                matched.append(
                    {
                        "grant_id": grant["id"],
                        "state": "active" if local_active else "inactive",
                        "policy_version": policy_version,
                    }
                )
            else:
                mismatched.append(
                    {
                        "grant_id": grant["id"],
                        "local_active": local_active,
                        "external_allowed": external_allowed,
                        "policy_version": policy_version,
                    }
                )
        return {"matched": matched, "mismatched": mismatched}

    def get(self, entity_id):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        return entity

    def list(self, kind=None, status=None):
        if kind:
            kind = self.rules.normalize_kind(kind)
        return self.repository.list_entities(kind=kind, status=status)

    def audit_log(self, entity_id=None):
        return self.repository.list_audit(entity_id=entity_id)
