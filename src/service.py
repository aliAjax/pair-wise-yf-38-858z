from uuid import uuid4

from .audit import AuditTrail
from .domain import (
    Actor,
    BatchFailed,
    ConflictError,
    NotFoundError,
    PermissionDenied,
    PolicyConflictError,
)
from .repository import utcnow
from .rules import (
    APPLICATION_TERMINAL_STATUSES,
    POLICY_CHANGE_ACTIONS,
    RuleEngine,
    evaluate_application,
    normalize_policy_rules,
    policy_rules_of,
)

SYSTEM_ACTOR = Actor("policy-system", "system")

# 外部台账可能用 allow/deny，本地用 allowed/denied，对账前统一
_DECISION_ALIASES = {"allow": "allowed", "denied": "denied", "deny": "denied"}


def normalize_decision(value):
    return _DECISION_ALIASES.get(str(value), str(value))


class DomainService:
    def __init__(self, repository, rules=None, ledger=None):
        self.repository = repository
        self.rules = rules or RuleEngine()
        self.audit = AuditTrail(repository)
        self.ledger = ledger

    def _lookup(self, kind, field, value):
        return self.repository.find_entities(self.rules.normalize_kind(kind), field, value)

    def _find(self, kind, entity_id):
        rows = self._lookup(kind, "id", entity_id)
        return rows[0] if rows else None

    def _dataset_of(self, entity):
        return self._find("dataset", (entity or {}).get("data", {}).get("dataset_id"))

    @staticmethod
    def _policy_version_of(entity_data, dataset=None):
        if entity_data and entity_data.get("policy_version") is not None:
            return entity_data.get("policy_version")
        if dataset and dataset.get("data", {}).get("policy_version") is not None:
            return dataset["data"]["policy_version"]
        return None

    def health(self):
        return {"status": "ok" if self.repository.ping() else "error"}

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------
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
        now = utcnow()

        if kind == "dataset":
            payload["policy_version"] = 1
            payload["policy_committed_at"] = now
            payload["policy_rules"] = normalize_policy_rules(payload.get("policy_rules"))
            with self.repository.transaction("create_dataset") as conn:
                self.repository.tx_insert_entity(
                    conn, entity_id, kind, status, payload, actor.user_id, now
                )
                self.repository.tx_insert_policy_version(
                    conn, entity_id, 1, payload["access_policy"],
                    payload["policy_rules"], actor.user_id, now, reason="registered",
                )
                self.audit.tx_record(
                    conn, entity_id, actor, "create", None, status,
                    {"kind": kind, "policy_version": 1}, policy_version=1,
                )
        else:
            dataset = self._find("dataset", payload.get("dataset_id"))
            if dataset:
                payload["policy_version"] = dataset["data"].get("policy_version")
            entity = self.repository.create_entity(
                entity_id, kind, status, payload, actor.user_id
            )
            self.audit.record(
                entity_id, actor, "create", None, status, {"kind": kind},
                policy_version=self._policy_version_of(payload, dataset),
            )
        entity = self.repository.get_entity(entity_id)
        if idempotency_key:
            self.repository.save_idempotency(actor.user_id, idempotency_key, entity_id)
        return entity

    # ------------------------------------------------------------------
    # Transitions
    # ------------------------------------------------------------------
    def transition(self, actor, entity_id, action, data=None, expected_version=None):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        if entity["kind"] == "dataset" and action in POLICY_CHANGE_ACTIONS:
            return self.commit_policy_change(
                actor, entity, action, dict(data or {}), expected_version
            )
        expected = int(expected_version) if expected_version is not None else entity["version"]
        next_status, patch = self.rules.validate_transition(
            actor, entity, action, dict(data or {}), self._lookup
        )
        merged = dict(entity["data"])
        merged.update(patch)

        dataset = self._dataset_of(entity)
        current_version = (
            dataset["data"].get("policy_version") if dataset else merged.get("policy_version")
        )
        if entity["kind"] == "application" and action in ("submit", "approve", "reconfirm"):
            merged["policy_version"] = current_version
            if action in ("approve", "reconfirm"):
                merged["confirmed_at"] = utcnow()
        if entity["kind"] == "grant" and action in ("activate", "suspend", "restore"):
            merged["policy_version"] = current_version

        updated = self.repository.update_entity(entity_id, expected, next_status, merged)
        self.audit.record(
            entity_id, actor, action, entity["status"], updated["status"],
            {"patch": patch},
            policy_version=self._policy_version_of(merged, dataset),
        )
        return updated

    # ------------------------------------------------------------------
    # Policy change: version commit + cascading batch
    # ------------------------------------------------------------------
    def commit_policy_change(self, actor, dataset, action, data, expected_version=None):
        next_status, patch = self.rules.validate_transition(
            actor, dataset, action, data, self._lookup
        )
        expected = (
            int(expected_version)
            if expected_version is not None else dataset["version"]
        )
        now = utcnow()
        batch_id = "BATCH-" + uuid4().hex[:12]
        new_version = int(dataset["data"].get("policy_version") or 1) + 1
        # restrict 可能只收紧访问而不改写策略文本；amend_policy 必须给新策略
        access_policy = patch.get("access_policy", dataset["data"].get("access_policy"))
        policy_rules = patch.get(
            "policy_rules",
            normalize_policy_rules(dataset["data"].get("policy_rules")),
        )

        merged = dict(dataset["data"])
        merged.update(patch)
        merged["policy_version"] = new_version
        merged["policy_committed_at"] = now

        try:
            with self.repository.transaction("policy_commit") as conn:
                updated = self.repository.tx_update_entity(
                    conn, dataset["id"], expected, next_status, merged, now
                )
                if updated is None:
                    raise ConflictError(
                        "dataset version conflict on policy change: %s" % dataset["id"]
                    )
                self.repository.tx_insert_policy_version(
                    conn, dataset["id"], new_version, access_policy, policy_rules,
                    actor.user_id, now, reason=data.get("reason"), batch_id=batch_id,
                )
                items = self._plan_batch_items(
                    conn, dataset["id"], updated, new_version, data.get("reason")
                )
                self.repository.tx_insert_batch(
                    conn, batch_id, dataset["id"], new_version, "policy_change",
                    len(items), actor.user_id, now,
                )
                for item in items:
                    self.repository.tx_insert_batch_item(
                        conn, batch_id, item["entity_kind"], item["entity_id"],
                        item["action"], item["detail"], now,
                    )
                self.audit.tx_record(
                    conn, dataset["id"], actor, action, dataset["status"],
                    updated["status"],
                    {
                        "patch": {
                            key: value
                            for key, value in patch.items()
                            if key not in ("access_policy", "policy_rules")
                        },
                        "policy_version": new_version,
                        "committed_at": now,
                        "batch_id": batch_id,
                    },
                    policy_version=new_version,
                )
        except ConflictError:
            # 后到的改动：先落库的版本生效，后来者拿冲突编号
            versions = self.repository.list_policy_versions(dataset["id"])
            winner_batch_id = versions[-1]["batch_id"] if versions else None
            conflict = self.repository.insert_conflict(
                "CF-" + uuid4().hex[:12],
                dataset["id"], actor.user_id, actor.role,
                {
                    "reason": "concurrent policy change",
                    "expected_version": expected,
                    "current_policy_version": versions[-1]["version"] if versions else None,
                    "winner_batch_id": winner_batch_id,
                },
                winner_batch_id=winner_batch_id,
            )
            raise PolicyConflictError(
                "policy change conflict for dataset %s; winning change committed first"
                % dataset["id"],
                conflict_id=conflict["conflict_id"],
            )

        self._run_batch(batch_id, actor)
        updated = self.repository.get_entity(dataset["id"])
        updated["batch"] = self._batch_summary(batch_id)
        return updated

    def _plan_batch_items(self, conn, dataset_id, updated_dataset, new_version, reason):
        # 在同一事务内读取：此时新策略已写入 entities，但尚未提交
        applications = [
            self.repository._entity_from_row(row)
            for row in conn.execute(
                "SELECT * FROM entities WHERE kind = 'application'"
            ).fetchall()
        ]
        grants = [
            self.repository._entity_from_row(row)
            for row in conn.execute(
                "SELECT * FROM entities WHERE kind = 'grant'"
            ).fetchall()
        ]
        items = []
        covered_applications = set()
        for application in applications:
            if application["data"].get("dataset_id") != dataset_id:
                continue
            status = application["status"]
            if status in APPLICATION_TERMINAL_STATUSES:
                continue
            covered_applications.add(application["id"])
            if status in ("approved",):
                items.append({
                    "entity_kind": "application",
                    "entity_id": application["id"],
                    "action": "stale",
                    "detail": {
                        "policy_version": new_version,
                        "reason": reason,
                    },
                })
            elif status == "stale":
                # 上一版还没重新确认，新策略又落地：继续挂起，等待按最新版确认
                items.append({
                    "entity_kind": "application",
                    "entity_id": application["id"],
                    "action": "keep_stale",
                    "detail": {"policy_version": new_version, "reason": reason},
                })
            else:
                eligible, why = evaluate_application(
                    policy_rules_of(updated_dataset), application
                )
                if eligible:
                    items.append({
                        "entity_kind": "application",
                        "entity_id": application["id"],
                        "action": "recompute",
                        "detail": {"policy_version": new_version, "eligible": True},
                    })
                else:
                    items.append({
                        "entity_kind": "application",
                        "entity_id": application["id"],
                        "action": "auto_reject",
                        "detail": {
                            "policy_version": new_version,
                            "eligible": False,
                            "reason": why,
                        },
                    })
        for grant in grants:
            if grant["data"].get("dataset_id") != dataset_id:
                continue
            if grant["status"] != "active":
                continue
            items.append({
                "entity_kind": "grant",
                "entity_id": grant["id"],
                "action": "suspend",
                "detail": {
                    "policy_version": new_version,
                    "reason": reason or "policy changed",
                    "application_id": grant["data"].get("application_id"),
                    "application_covered": grant["data"].get("application_id")
                    in covered_applications,
                },
            })
        items.sort(key=lambda item: (item["entity_kind"], item["entity_id"]))
        return items

    def _run_batch(self, batch_id, triggered_by):
        batch = self.repository.get_batch(batch_id)
        if not batch:
            raise NotFoundError("batch not found: " + batch_id)
        # 重试时把上次 failed 的项重新排回待办；初次运行没有 failed 项（0 行）
        with self.repository.transaction("batch_retry") as conn:
            conn.execute(
                "UPDATE batch_items SET status = 'pending', error = NULL, "
                "updated_at = ? WHERE batch_id = ? AND status = 'failed'",
                (utcnow(), batch_id),
            )
        pending = self.repository.list_batch_items(batch_id, status="pending")
        for item in pending:
            try:
                self._process_item(batch, item, triggered_by)
            except Exception as exc:  # 单项写库失败：该项事务回滚，整批挂起等待重试
                self._mark_item_failed(batch_id, item, exc)
                raise BatchFailed(
                    "policy batch %s stopped at %s %s: %s"
                    % (batch_id, item["entity_kind"], item["entity_id"], exc),
                    batch_id=batch_id,
                )
        completed = self.repository.list_batch_items(batch_id, status="completed")
        with self.repository.transaction("batch_close") as conn:
            self.repository.tx_set_batch_status(
                conn, batch_id, "completed", processed_items=len(completed)
            )

    def _process_item(self, batch, item, triggered_by):
        version = batch["policy_version"]
        detail = {"policy_version": version, "batch_id": batch["id"],
                  "triggered_by": triggered_by.user_id}
        with self.repository.transaction("batch_item") as conn:
            entity = None
            row = conn.execute(
                "SELECT * FROM entities WHERE id = ?", (item["entity_id"],)
            ).fetchone()
            if row:
                entity = self.repository._entity_from_row(row)
            if item["entity_kind"] == "application":
                entity = self._process_application_item(conn, batch, item, entity)
            else:
                entity = self._process_grant_item(conn, batch, item, entity)
            self.repository.tx_touch_batch_item(
                conn, batch["id"], item["entity_kind"], item["entity_id"], "completed",
                detail=dict(item["detail"], outcome=item["action"]),
            )
            processed = self.repository.tx_count_completed_items(conn, batch["id"])
            self.repository.tx_set_batch_status(
                conn, batch["id"], "processing", processed_items=processed
            )

    def _process_application_item(self, conn, batch, item, application):
        version = batch["policy_version"]
        if application is None:
            raise NotFoundError("application vanished from batch: " + item["entity_id"])
        data = dict(application["data"])
        action = item["action"]
        system_detail = {
            "batch_id": batch["id"],
            "policy_version": version,
            "triggered_by": batch["created_by"],
        }
        now = utcnow()
        if action == "stale":
            _, patch = self.rules.validate_transition(
                SYSTEM_ACTOR, application, "cascade_stale", {}, self._lookup
            )
            data.update(patch)
            data["superseded_by_policy_version"] = version
            data["stale_since"] = now
            data["stale_reason"] = item["detail"].get("reason")
            updated = self.repository.tx_update_entity(
                conn, application["id"], None, "stale", data, now
            )
            self.audit.tx_record(
                conn, application["id"], SYSTEM_ACTOR, "cascade_stale",
                application["status"], "stale", system_detail, policy_version=version,
            )
        elif action == "keep_stale":
            data["superseded_by_policy_version"] = version
            data["stale_reason"] = item["detail"].get("reason")
            updated = self.repository.tx_update_entity(
                conn, application["id"], None, "stale", data, now
            )
            self.audit.tx_record(
                conn, application["id"], SYSTEM_ACTOR, "cascade_restale",
                "stale", "stale", system_detail, policy_version=version,
            )
        elif action == "recompute":
            _, patch = self.rules.validate_transition(
                SYSTEM_ACTOR, application, "cascade_recompute", {}, self._lookup
            )
            data.update(patch)
            data["policy_version"] = version
            data["recomputed_at"] = now
            data["recompute_result"] = "eligible"
            updated = self.repository.tx_update_entity(
                conn, application["id"], None, application["status"], data, now
            )
            self.audit.tx_record(
                conn, application["id"], SYSTEM_ACTOR, "cascade_recompute",
                application["status"], application["status"],
                dict(system_detail, result="eligible"), policy_version=version,
            )
        elif action == "auto_reject":
            reason = item["detail"].get("reason") or "disallowed by new policy"
            _, patch = self.rules.validate_transition(
                SYSTEM_ACTOR, application, "cascade_auto_reject",
                {"reason": reason}, self._lookup
            )
            data.update(patch)
            data["policy_version"] = version
            data["auto_rejected_at"] = now
            updated = self.repository.tx_update_entity(
                conn, application["id"], None, "auto_rejected", data, now
            )
            self.audit.tx_record(
                conn, application["id"], SYSTEM_ACTOR, "cascade_auto_reject",
                application["status"], "auto_rejected",
                dict(system_detail, reason=reason), policy_version=version,
            )
        else:
            raise NotFoundError("unknown batch action: " + action)
        return updated

    def _process_grant_item(self, conn, batch, item, grant):
        version = batch["policy_version"]
        if grant is None:
            raise NotFoundError("grant vanished from batch: " + item["entity_id"])
        data = dict(grant["data"])
        now = utcnow()
        reason = item["detail"].get("reason") or "policy changed"
        _, patch = self.rules.validate_transition(
            SYSTEM_ACTOR, grant, "cascade_suspend", {"reason": reason}, self._lookup
        )
        data.update(patch)
        data["policy_version"] = version
        data["suspended_at"] = now
        data["suspend_reason"] = reason
        updated = self.repository.tx_update_entity(
            conn, grant["id"], None, "suspended", data, now
        )
        self.audit.tx_record(
            conn, grant["id"], SYSTEM_ACTOR, "cascade_suspend",
            grant["status"], "suspended",
            {
                "batch_id": batch["id"],
                "policy_version": version,
                "triggered_by": batch["created_by"],
                "reason": reason,
            },
            policy_version=version,
        )
        return updated

    def _mark_item_failed(self, batch_id, item, exc):
        message = str(exc) or type(exc).__name__
        try:
            with self.repository.transaction("batch_fail") as conn:
                self.repository.tx_touch_batch_item(
                    conn, batch_id, item["entity_kind"], item["entity_id"],
                    "failed", detail=item["detail"], error=message,
                )
                self.repository.tx_set_batch_status(conn, batch_id, "failed", error=message)
        except Exception:
            # 连失败标记都写不进去时，原异常仍然抛给调用方
            pass

    def retry_batch(self, actor, batch_id):
        batch = self.repository.get_batch(batch_id)
        if not batch:
            raise NotFoundError("batch not found: " + batch_id)
        if actor.role not in ("admin", "committee"):
            raise PermissionDenied("role %s cannot retry policy batches" % actor.role)
        if batch["status"] == "completed":
            return self._batch_summary(batch_id)
        # 只补没完成的申请：pending 项继续跑，completed 项不重放
        self._run_batch(batch_id, actor)
        return self._batch_summary(batch_id)

    def _batch_summary(self, batch_id):
        batch = self.repository.get_batch(batch_id)
        if not batch:
            return None
        summary = dict(batch)
        summary["items"] = self.repository.list_batch_items(batch_id)
        return summary

    # ------------------------------------------------------------------
    # Data access requests (effective grant enforcement)
    # ------------------------------------------------------------------
    def request_access(self, actor, dataset_id, data=None):
        data = dict(data or {})
        dataset = self._find("dataset", dataset_id)
        if not dataset:
            raise NotFoundError("dataset not found: " + dataset_id)
        version = dataset["data"].get("policy_version")
        request_id = str(data.pop("request_id", "") or "REQ-" + uuid4().hex[:12])

        def deny(reason, message, application_id=None, grant_id=None, forbidden=False):
            record = self.repository.insert_access_request(
                request_id, dataset_id, actor.user_id, actor.role,
                "denied", reason, version,
                application_id=application_id, grant_id=grant_id,
            )
            self._record_access_audit(
                dataset, actor, "access_denied", reason, version,
                {"request_id": request_id, "grant_id": grant_id,
                 "application_id": application_id},
            )
            error = PermissionDenied if forbidden else None
            exc = self._access_denied(reason, message, version, forbidden)
            exc.record = record
            raise exc

        grant = None
        grant_id = data.get("grant_id")
        if grant_id:
            grant = self._find("grant", grant_id)
            if not grant or grant["data"].get("dataset_id") != dataset_id:
                deny("grant_not_found", "grant does not exist for this dataset",
                     grant_id=grant_id)
        else:
            candidates = [
                item for item in self.repository.list_entities(kind="grant")
                if item["data"].get("dataset_id") == dataset_id
                and item["data"].get("recipient") == actor.user_id
            ]
            if candidates:
                grant = sorted(candidates, key=lambda item: item["created_at"])[-1]

        if not grant:
            deny("no_active_grant", "no grant covers this data access request")

        application = self._find("application", grant["data"].get("application_id"))
        application_id = application["id"] if application else None

        # 越权：拿别人的凭证取数
        if grant["data"].get("recipient") != actor.user_id and actor.role != "admin":
            deny(
                "recipient_mismatch",
                "grant %s belongs to another recipient" % grant["id"],
                application_id=application_id, grant_id=grant["id"], forbidden=True,
            )

        if grant["status"] == "revoked":
            deny("grant_revoked", "grant %s has been revoked" % grant["id"],
                 application_id=application_id, grant_id=grant["id"])
        if grant["status"] == "suspended":
            deny("grant_suspended",
                 "grant %s is suspended pending policy reconfirmation" % grant["id"],
                 application_id=application_id, grant_id=grant["id"])
        if grant["status"] != "active":
            deny("grant_not_active", "grant %s is not active" % grant["id"],
                 application_id=application_id, grant_id=grant["id"])

        expires_at = grant["data"].get("expires_at")
        if expires_at and str(expires_at) < utcnow()[:10]:
            deny("grant_expired", "grant %s is past its expiry" % grant["id"],
                 application_id=application_id, grant_id=grant["id"])

        if not application or application["status"] != "approved":
            deny("application_not_approved",
                 "backing application is not approved under the current policy",
                 application_id=application_id, grant_id=grant["id"])
        if application["data"].get("policy_version") != version:
            deny(
                "policy_changed_pending_reconfirmation",
                "application was confirmed under policy v%s; current policy is v%s"
                % (application["data"].get("policy_version"), version),
                application_id=application_id, grant_id=grant["id"],
            )

        record = self.repository.insert_access_request(
            request_id, dataset_id, actor.user_id, actor.role,
            "allowed", None, version,
            application_id=application_id, grant_id=grant["id"],
        )
        self._record_access_audit(
            dataset, actor, "access_allowed", None, version,
            {"request_id": request_id, "grant_id": grant["id"],
             "application_id": application_id},
        )
        return record

    @staticmethod
    def _access_denied(reason, message, version, forbidden):
        from .domain import AccessDenied

        return AccessDenied(message, reason=reason, policy_version=version)

    def _record_access_audit(self, dataset, actor, action, reason, version, detail):
        payload = dict(detail)
        if reason:
            payload["reason"] = reason
        self.audit.record(
            dataset["id"], actor, action, dataset["status"], dataset["status"],
            payload, policy_version=version,
        )

    # ------------------------------------------------------------------
    # Audit reconciliation
    # ------------------------------------------------------------------
    def reconcile(self, actor, dataset_id=None):
        if actor.role != "auditor":
            # 越权请求直接拒绝并留痕
            self.audit.record(
                dataset_id or "*", actor, "reconcile_denied", None, "denied",
                {"reason": "auditor role required"},
            )
            raise PermissionDenied("only auditors may reconcile ledgers")
        local = self.repository.list_access_requests(dataset_id=dataset_id)
        external = self.ledger.fetch(dataset_id=dataset_id) if self.ledger else []
        local_by_id = {row["id"]: row for row in local}

        matched_external = set()
        items = []
        unauthorized = []
        for ext in external:
            ext = dict(ext)
            ext["decision"] = normalize_decision(ext.get("decision"))
            local_row = self._match_local(ext, local_by_id, local)
            if local_row:
                matched_external.add(ext.get("id"))
                if local_row["decision"] != ext.get("decision"):
                    status = "decision_mismatch"
                elif (
                    ext.get("policy_version") is not None
                    and int(ext["policy_version"]) != int(local_row["policy_version"])
                ):
                    status = "version_mismatch"
                else:
                    status = "match"
                items.append({
                    "status": status,
                    "external": ext,
                    "local_id": local_row["id"],
                })
                continue
            status = (
                "unauthorized_external_access"
                if ext.get("decision") == "allowed" else "external_only"
            )
            entry = {"status": status, "external": ext, "local_id": None}
            items.append(entry)
            if status == "unauthorized_external_access":
                unauthorized.append(entry)
                # 外部台账里有、本地没有对应放行：按越权请求补记一条拒绝
                ext_actor = Actor(str(ext.get("actor_id", "unknown")), "viewer")
                self.repository.insert_access_request(
                    "DENY-" + uuid4().hex[:12], str(ext.get("dataset_id")),
                    ext_actor.user_id, ext_actor.role, "denied",
                    "unauthorized_external_access",
                    ext.get("policy_version"),
                )
                dataset = self._find("dataset", ext.get("dataset_id"))
                if dataset:
                    self._record_access_audit(
                        dataset, ext_actor, "access_denied",
                        "unauthorized_external_access",
                        ext.get("policy_version") or dataset["data"].get("policy_version"),
                        {"external_event_id": ext.get("id")},
                    )

        external_ids = {row.get("id") for row in external}
        for row in local:
            if row["id"] in external_ids:
                continue
            match = self._match_local({"dataset_id": row["dataset_id"],
                                       "actor_id": row["actor_id"],
                                       "decision": row["decision"],
                                       "policy_version": row["policy_version"]},
                                      local_by_id, local, exclude_id=row["id"])
            if match:
                continue
            items.append({"status": "local_only", "external": None, "local_id": row["id"]})

        summary = {
            "dataset_id": dataset_id,
            "checked_at": utcnow(),
            "local_records": len(local),
            "external_records": len(external),
            "unauthorized_external_access": len(unauthorized),
            "items": items,
        }
        self.audit.record(
            dataset_id or "*", actor, "reconcile", None, "completed",
            {"local": len(local), "external": len(external),
             "unauthorized": len(unauthorized)},
        )
        return summary

    @staticmethod
    def _match_local(ext, local_by_id, local, exclude_id=None):
        ext_id = ext.get("id")
        if ext_id and ext_id in local_by_id and ext_id != exclude_id:
            return local_by_id[ext_id]
        local_ref = ext.get("local_ref")
        if local_ref and local_ref in local_by_id and local_ref != exclude_id:
            return local_by_id[local_ref]
        for row in local:
            if exclude_id and row["id"] == exclude_id:
                continue
            if (
                str(row["dataset_id"]) == str(ext.get("dataset_id"))
                and row["actor_id"] == ext.get("actor_id")
                and row["decision"] == ext.get("decision")
                and (
                    ext.get("policy_version") is None
                    or int(row["policy_version"]) == int(ext["policy_version"])
                )
            ):
                return row
        return None

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------
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

    def policy_versions(self, dataset_id=None):
        return self.repository.list_policy_versions(dataset_id)

    def get_batch(self, entity_id):
        batch = self.repository.get_batch(entity_id)
        if not batch:
            raise NotFoundError("batch not found: " + entity_id)
        return self._batch_summary(entity_id)

    def list_batches(self, dataset_id=None, status=None):
        return self.repository.list_batches(dataset_id=dataset_id, status=status)

    def list_access_requests(self, dataset_id=None, decision=None):
        return self.repository.list_access_requests(
            dataset_id=dataset_id, decision=decision
        )
