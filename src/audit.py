from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AuditTrail:
    def __init__(self, repository):
        self.repository = repository

    def record(
        self, entity_id, actor, action, from_status, to_status,
        detail=None, policy_version=None,
    ):
        self.repository.append_audit(
            entity_id=entity_id,
            actor_id=actor.user_id,
            actor_role=actor.role,
            action=action,
            from_status=from_status,
            to_status=to_status,
            detail=detail or {},
            policy_version=policy_version,
        )

    def tx_record(
        self, conn, entity_id, actor, action, from_status, to_status,
        detail=None, policy_version=None,
    ):
        self.repository.tx_append_audit(
            conn,
            entity_id=entity_id,
            actor_id=actor.user_id,
            actor_role=actor.role,
            action=action,
            from_status=from_status,
            to_status=to_status,
            detail=detail or {},
            policy_version=policy_version,
        )

    def list(self, entity_id=None):
        return self.repository.list_audit(entity_id=entity_id)
