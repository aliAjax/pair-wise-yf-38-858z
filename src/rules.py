from datetime import datetime

from .domain import (
    ConflictError,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)


DEFAULT_MINIMUM_APPROVALS = 3

# 申请进入终态后不再随策略改动被级联处理
APPLICATION_TERMINAL_STATUSES = {
    "rejected",
    "withdrawn",
    "auto_rejected",
}


def _validate_dataset(actor, data, lookup):
    if len(data.get("access_policy", "")) < 3:
        raise ValidationError("access_policy is required")


def _validate_application(actor, data, lookup):
    dataset = _find_one(lookup, "dataset", "id", data.get("dataset_id"))
    if not dataset:
        raise ValidationError("dataset does not exist")
    if not data.get("purpose", "").strip():
        raise ValidationError("purpose is required")


def normalize_policy_rules(raw):
    """策略规则既支持结构化 dict，也兼容只给 access_policy 字符串的老数据。"""
    rules = dict(raw) if isinstance(raw, dict) else {}
    rules.setdefault("minimum_approvals", DEFAULT_MINIMUM_APPROVALS)
    allowed_purposes = rules.get("allowed_purposes") or []
    rules["allowed_purposes"] = [str(item).strip() for item in allowed_purposes]
    allowed_applicants = rules.get("allowed_applicants") or []
    rules["allowed_applicants"] = [str(item).strip() for item in allowed_applicants]
    try:
        rules["minimum_approvals"] = max(1, int(rules["minimum_approvals"]))
    except (TypeError, ValueError):
        raise ValidationError("minimum_approvals must be an integer")
    return rules


def policy_rules_of(dataset):
    data = (dataset or {}).get("data") or {}
    if isinstance(data.get("policy_rules"), dict):
        return normalize_policy_rules(data["policy_rules"])
    if isinstance(data.get("policy_rules"), str) and data["policy_rules"].strip().startswith("{"):
        import json

        try:
            return normalize_policy_rules(json.loads(data["policy_rules"]))
        except ValueError:
            pass
    return normalize_policy_rules({})


def minimum_approvals_of(dataset):
    return policy_rules_of(dataset)["minimum_approvals"]


def evaluate_application(policy_rules, application):
    """按新策略重算一份申请：返回 (eligible, reason)。"""
    data = (application or {}).get("data") or {}
    allowed_purposes = policy_rules.get("allowed_purposes") or []
    if allowed_purposes and str(data.get("purpose", "")).strip() not in allowed_purposes:
        return False, "purpose not allowed by current policy"
    allowed_applicants = policy_rules.get("allowed_applicants") or []
    if allowed_applicants and str(data.get("applicant_id", "")).strip() not in allowed_applicants:
        return False, "applicant not allowed by current policy"
    return True, None


def _validate_approve(actor, entity, data, lookup):
    dataset = _find_one(lookup, "dataset", "id", entity["data"].get("dataset_id"))
    minimum = minimum_approvals_of(dataset)
    approvals = data.get("approvals") or []
    if len(set(approvals)) < minimum:
        raise ValidationError(
            "at least %s distinct committee approvals are required" % minimum
        )
    if data.get("conflict_of_interest"):
        raise PermissionDenied("conflicted reviewer cannot approve access")


def _validate_reconfirm(actor, entity, data, lookup):
    dataset = _find_one(lookup, "dataset", "id", entity["data"].get("dataset_id"))
    minimum = minimum_approvals_of(dataset)
    approvals = data.get("approvals") or []
    if len(set(approvals)) < minimum:
        raise ValidationError(
            "reconfirmation needs %s distinct committee approvals" % minimum
        )
    if data.get("conflict_of_interest"):
        raise PermissionDenied("conflicted reviewer cannot reconfirm access")


def valid_grant_window(expires_at, as_of):
    return str(expires_at) >= str(as_of)


def _validate_grant_activate(actor, entity, data, lookup):
    if data.get("expires_at") < data.get("starts_at"):
        raise ValidationError("grant expiry must be after start")
    return {"activated_by": actor.user_id}


def _validate_grant_suspend(actor, entity, data, lookup):
    return {
        "suspended_by": actor.user_id,
        "suspend_reason": data.get("reason"),
    }


def _validate_grant_restore(actor, entity, data, lookup):
    application = _find_one(lookup, "application", "id", entity["data"].get("application_id"))
    if not application:
        raise InvalidTransition("grant has no approved application")
    dataset = _find_one(lookup, "dataset", "id", entity["data"].get("dataset_id"))
    current_version = (dataset or {}).get("data", {}).get("policy_version")
    if application["status"] != "approved":
        raise InvalidTransition("application has not been reconfirmed under the current policy")
    if application["data"].get("policy_version") != current_version:
        raise InvalidTransition(
            "reconfirmation must match the current policy version before restoring a grant"
        )
    return {
        "restored_by": actor.user_id,
        "policy_version": current_version,
    }


def _validate_amend_policy(actor, entity, data, lookup):
    if len(str(data.get("access_policy", ""))) < 3:
        raise ValidationError("access_policy is required")
    patch = {
        "access_policy": str(data["access_policy"]),
        "policy_rules": normalize_policy_rules(data.get("policy_rules")),
        "amended_by": actor.user_id,
    }
    return patch


CUSTOM_CREATE = {'dataset': _validate_dataset, 'application': _validate_application}
CUSTOM_TRANSITIONS = {
    ('application', 'approve'): _validate_approve,
    ('application', 'reconfirm'): _validate_reconfirm,
    ('grant', 'activate'): _validate_grant_activate,
    ('grant', 'suspend'): _validate_grant_suspend,
    ('grant', 'restore'): _validate_grant_restore,
    ('dataset', 'amend_policy'): _validate_amend_policy,
}

# 改动访问策略的动作：由服务层走“版本提交 + 级联批处理”
POLICY_CHANGE_ACTIONS = {"amend_policy", "restrict"}


class RuleEngine:
    ALIASES = {'datasets': 'dataset', 'applications': 'application', 'grants': 'grant'}
    INITIAL_STATUS = {'dataset': 'registered', 'application': 'draft', 'grant': 'issued'}
    TRANSITIONS = {
        'dataset': {
            'restrict': (('registered', 'published'), 'restricted'),
            'publish': (('restricted',), 'published'),
            'amend_policy': (('registered', 'restricted', 'published'), '__KEEP__'),
        },
        'application': {
            'submit': (('draft',), 'submitted'),
            'review': (('submitted',), 'under_review'),
            'approve': (('under_review',), 'approved'),
            'reject': (('under_review',), 'rejected'),
            'withdraw': (('submitted', 'under_review'), 'withdrawn'),
            # 策略改动后：通过的先失效，委员会按新策略重新确认；不满足新策略的直接驳回
            'reconfirm': (('stale',), 'approved'),
            'cascade_stale': (('approved',), 'stale'),
            'cascade_auto_reject': (
                ('draft', 'submitted', 'under_review', 'stale'),
                'auto_rejected',
            ),
            'cascade_recompute': (
                ('draft', 'submitted', 'under_review'),
                '__KEEP__',
            ),
        },
        'grant': {
            'activate': (('issued',), 'active'),
            'suspend': (('active',), 'suspended'),
            'restore': (('suspended',), 'active'),
            'revoke': (('active', 'suspended'), 'revoked'),
            'expire': (('active',), 'expired'),
            'cascade_suspend': (('active',), 'suspended'),
        },
    }
    CREATE_REQUIRED = {
        'dataset': ('name', 'access_policy'),
        'application': ('dataset_id', 'applicant_id', 'purpose'),
        'grant': ('application_id', 'dataset_id', 'recipient'),
    }
    ACTION_REQUIRED = {
        ('dataset', 'restrict'): ('reason',),
        ('dataset', 'amend_policy'): ('reason',),
        ('application', 'review'): ('committee_id',),
        ('application', 'approve'): ('approvals', 'terms', 'expires_at'),
        ('application', 'reconfirm'): ('approvals',),
        ('application', 'reject'): ('reason',),
        ('application', 'withdraw'): ('reason',),
        ('grant', 'activate'): ('starts_at', 'expires_at'),
        ('grant', 'suspend'): ('reason',),
        ('grant', 'restore'): (),
        ('grant', 'revoke'): ('reason',),
        ('grant', 'expire'): ('expired_at',),
    }
    CREATE_ROLES = {
        'dataset': ('admin', 'committee'),
        'application': ('admin', 'applicant'),
        'grant': ('admin', 'committee'),
    }
    ROLE_ACTIONS = {
        'restrict': ('admin', 'committee'),
        'publish': ('admin', 'committee'),
        'amend_policy': ('admin', 'committee'),
        'submit': ('admin', 'applicant'),
        'review': ('admin', 'committee'),
        'approve': ('admin', 'committee'),
        'reconfirm': ('admin', 'committee'),
        'reject': ('admin', 'committee'),
        'withdraw': ('admin', 'applicant'),
        'activate': ('admin', 'committee'),
        'suspend': ('admin', 'committee'),
        'restore': ('admin', 'committee'),
        'revoke': ('admin', 'committee'),
        'expire': ('admin', 'committee'),
        # 系统级级联动作，只能由服务编排触发（system 角色）
        'cascade_stale': ('system',),
        'cascade_auto_reject': ('system',),
        'cascade_recompute': ('system',),
        'cascade_suspend': ('system',),
    }

    def normalize_kind(self, kind):
        return self.ALIASES.get(kind, kind)

    def initial_status(self, kind):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        return self.INITIAL_STATUS[kind]

    @staticmethod
    def _ensure_role(actor, allowed):
        if "*" not in allowed and actor.role not in allowed:
            raise PermissionDenied("role %s is not allowed here" % actor.role)

    @staticmethod
    def _require(data, fields):
        for field in fields:
            value = data.get(field)
            if value is None or value == "" or value == [] or value == {}:
                raise ValidationError("missing required field: " + field)

    def validate_create(self, actor, kind, data, lookup=None):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        self._ensure_role(actor, self.CREATE_ROLES.get(kind, ("admin",)))
        self._require(data, self.CREATE_REQUIRED.get(kind, ()))
        custom = CUSTOM_CREATE.get(kind)
        if custom:
            custom(actor, data, lookup)
        return dict(data)

    def validate_transition(self, actor, entity, action, data, lookup=None):
        kind = self.normalize_kind(entity["kind"])
        transition = self.TRANSITIONS.get(kind, {}).get(action)
        if not transition:
            raise InvalidTransition("unknown action %s for %s" % (action, kind))
        allowed_statuses, next_status = transition
        if entity["status"] not in allowed_statuses:
            raise InvalidTransition(
                "cannot %s from status %s" % (action, entity["status"])
            )
        if next_status == "__KEEP__":
            next_status = entity["status"]
        allowed_roles = self.ROLE_ACTIONS.get(
            (kind, action), self.ROLE_ACTIONS.get(action, ("admin",))
        )
        self._ensure_role(actor, allowed_roles)
        self._require(data, self.ACTION_REQUIRED.get((kind, action), ()))
        custom = CUSTOM_TRANSITIONS.get((kind, action))
        extra = custom(actor, entity, data, lookup) if custom else {}
        patch = dict(data)
        if extra:
            patch.update(extra)
        return next_status, patch


def _find_one(lookup, kind, field, value):
    if lookup is None:
        return None
    rows = lookup(kind, field, value) or []
    return rows[0] if rows else None


def _date_ordinal(value):
    return datetime.fromisoformat(str(value)[:10]).date().toordinal()
