from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional


class DomainError(Exception):
    """Base error for domain failures."""


class ValidationError(DomainError):
    """Input does not satisfy a domain rule."""


class PermissionDenied(DomainError):
    """Actor is not allowed to perform the action."""


class NotFoundError(DomainError):
    """Requested record does not exist."""


class ConflictError(DomainError):
    """A version or uniqueness constraint was violated."""


class InvalidTransition(DomainError):
    """The requested state transition is not valid."""


class PolicyConflictError(ConflictError):
    """Two committee members changed the same dataset policy concurrently."""

    def __init__(self, message, conflict_id=None):
        super().__init__(message)
        self.conflict_id = conflict_id


class AccessDenied(PermissionDenied):
    """A data access request was denied by the policy chain."""

    def __init__(self, message, reason=None, policy_version=None):
        super().__init__(message)
        self.reason = reason
        self.policy_version = policy_version


class BatchFailed(DomainError):
    """A cascading policy change batch stopped midway; it can be retried."""

    def __init__(self, message, batch_id=None):
        super().__init__(message)
        self.batch_id = batch_id


class Role(str, Enum):
    viewer = "viewer"
    admin = "admin"
    applicant = "applicant"
    committee = "committee"
    auditor = "auditor"


@dataclass
class Actor:
    user_id: str
    role: str

    @classmethod
    def from_headers(cls, headers):
        user_id = headers.get("X-User-Id", "anonymous")
        role = headers.get("X-Role", "viewer")
        if role not in {item.value for item in Role}:
            raise PermissionDenied("unknown role: " + role)
        return cls(user_id=user_id, role=role)


@dataclass
class Entity:
    id: str
    kind: str
    status: str
    version: int
    data: Dict[str, Any]
    created_by: str
    created_at: str
    updated_at: str

    @classmethod
    def from_row(cls, row):
        return cls(
            id=row["id"],
            kind=row["kind"],
            status=row["status"],
            version=row["version"],
            data=row["data"],
            created_by=row["created_by"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
