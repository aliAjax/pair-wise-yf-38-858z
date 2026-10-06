import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from .domain import ConflictError, NotFoundError


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class SQLiteRepository:
    def __init__(self, path):
        self.path = str(path)
        # 测试用故障注入：{event_name: Exception}，命中一次即失效
        self._failures = {}
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------
    def _initialize(self):
        with self._connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS entities (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    data TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_entities_kind_status
                    ON entities(kind, status);
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    actor_role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    from_status TEXT,
                    to_status TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_entity
                    ON audit_log(entity_id, id);
                CREATE INDEX IF NOT EXISTS idx_audit_created
                    ON audit_log(created_at, id);
                CREATE TABLE IF NOT EXISTS idempotency (
                    actor_id TEXT NOT NULL,
                    idem_key TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(actor_id, idem_key)
                );
                CREATE TABLE IF NOT EXISTS policy_versions (
                    dataset_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    access_policy TEXT NOT NULL,
                    policy_rules TEXT NOT NULL,
                    reason TEXT,
                    committed_by TEXT NOT NULL,
                    committed_at TEXT NOT NULL,
                    batch_id TEXT,
                    PRIMARY KEY(dataset_id, version)
                );
                CREATE TABLE IF NOT EXISTS change_batches (
                    id TEXT PRIMARY KEY,
                    dataset_id TEXT NOT NULL,
                    policy_version INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    total_items INTEGER NOT NULL,
                    processed_items INTEGER NOT NULL DEFAULT 0,
                    created_by TEXT NOT NULL,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_batches_dataset
                    ON change_batches(dataset_id, id);
                CREATE TABLE IF NOT EXISTS batch_items (
                    batch_id TEXT NOT NULL,
                    entity_kind TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '{}',
                    error TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(batch_id, entity_kind, entity_id)
                );
                CREATE TABLE IF NOT EXISTS policy_conflicts (
                    conflict_id TEXT PRIMARY KEY,
                    dataset_id TEXT NOT NULL,
                    winner_batch_id TEXT,
                    actor_id TEXT NOT NULL,
                    actor_role TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS access_requests (
                    id TEXT PRIMARY KEY,
                    dataset_id TEXT NOT NULL,
                    application_id TEXT,
                    grant_id TEXT,
                    actor_id TEXT NOT NULL,
                    actor_role TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT,
                    policy_version INTEGER,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_access_dataset
                    ON access_requests(dataset_id, id);
                CREATE INDEX IF NOT EXISTS idx_access_decision
                    ON access_requests(decision, id);
            """)
            self._migrate(connection)

    @staticmethod
    def _migrate(connection):
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(audit_log)")
        }
        if "policy_version" not in columns:
            connection.execute("ALTER TABLE audit_log ADD COLUMN policy_version INTEGER")

    # ------------------------------------------------------------------
    # Fault injection (tests only)
    # ------------------------------------------------------------------
    def inject_failure(self, event, message="injected write failure"):
        self._failures[event] = RuntimeError(message)

    def _maybe_fail(self, event):
        exc = self._failures.pop(event, None)
        if exc is not None:
            raise exc

    @contextmanager
    def transaction(self, event="commit"):
        """序列化写事务；提交前命中故障钩子会整体回滚。"""
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            self._maybe_fail(event)
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    # ------------------------------------------------------------------
    # Entities
    # ------------------------------------------------------------------
    @staticmethod
    def _entity_from_row(row):
        return {
            "id": row["id"],
            "kind": row["kind"],
            "status": row["status"],
            "version": int(row["version"]),
            "data": json.loads(row["data"]),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _dump(data):
        return json.dumps(data, ensure_ascii=False, sort_keys=True)

    def create_entity(self, entity_id, kind, status, data, actor_id):
        now = utcnow()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO entities(id, kind, status, version, data, created_by, created_at, updated_at) "
                "VALUES (?, ?, ?, 1, ?, ?, ?, ?)",
                (entity_id, kind, status, self._dump(data), actor_id, now, now),
            )
        return self.get_entity(entity_id)

    def tx_insert_entity(self, conn, entity_id, kind, status, data, actor_id, now=None):
        now = now or utcnow()
        conn.execute(
            "INSERT INTO entities(id, kind, status, version, data, created_by, created_at, updated_at) "
            "VALUES (?, ?, ?, 1, ?, ?, ?, ?)",
            (entity_id, kind, status, self._dump(data), actor_id, now, now),
        )

    def get_entity(self, entity_id):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM entities WHERE id = ?", (entity_id,)
            ).fetchone()
        return self._entity_from_row(row) if row else None

    def list_entities(self, kind=None, status=None):
        clauses = []
        params = []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM entities" + where + " ORDER BY created_at, id", params
            ).fetchall()
        return [self._entity_from_row(row) for row in rows]

    def find_entities(self, kind, field, value):
        return [
            entity
            for entity in self.list_entities(kind=kind)
            if (entity["id"] == value if field == "id" else entity["data"].get(field) == value)
        ]

    def update_entity(self, entity_id, expected_version, status, data):
        now = utcnow()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT version FROM entities WHERE id = ?", (entity_id,)
            ).fetchone()
            if not row:
                raise NotFoundError("entity not found: " + entity_id)
            current_version = int(row["version"])
            if expected_version is not None and current_version != int(expected_version):
                raise ConflictError(
                    "version conflict: expected %s, found %s"
                    % (expected_version, current_version)
                )
            connection.execute(
                "UPDATE entities SET status = ?, version = version + 1, data = ?, updated_at = ? "
                "WHERE id = ? AND version = ?",
                (status, self._dump(data), now, entity_id, current_version),
            )
            self._maybe_fail("update_entity")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.get_entity(entity_id)

    def tx_update_entity(self, conn, entity_id, expected_version, status, data, now=None):
        """在给定事务内做乐观锁更新，返回新行 dict；版本不符返回 None；不存在抛 NotFoundError。"""
        now = now or utcnow()
        row = conn.execute(
            "SELECT id, version FROM entities WHERE id = ?", (entity_id,)
        ).fetchone()
        if not row:
            raise NotFoundError("entity not found: " + entity_id)
        current_version = int(row["version"])
        if expected_version is not None and current_version != int(expected_version):
            return None
        conn.execute(
            "UPDATE entities SET status = ?, version = version + 1, data = ?, updated_at = ? "
            "WHERE id = ? AND version = ?",
            (status, self._dump(data), now, entity_id, current_version),
        )
        new_row = conn.execute("SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()
        return self._entity_from_row(new_row)

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------
    def append_audit(
        self, entity_id, actor_id, actor_role, action, from_status, to_status,
        detail, policy_version=None,
    ):
        with self._connect() as connection:
            self.tx_append_audit(
                connection, entity_id, actor_id, actor_role, action,
                from_status, to_status, detail, policy_version,
            )

    def tx_append_audit(
        self, conn, entity_id, actor_id, actor_role, action, from_status,
        to_status, detail, policy_version=None, now=None,
    ):
        conn.execute(
            "INSERT INTO audit_log(entity_id, actor_id, actor_role, action, from_status, "
            "to_status, detail, created_at, policy_version) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                entity_id, actor_id, actor_role, action, from_status, to_status,
                self._dump(detail or {}), now or utcnow(), policy_version,
            ),
        )

    def list_audit(self, entity_id=None):
        with self._connect() as connection:
            if entity_id:
                rows = connection.execute(
                    "SELECT * FROM audit_log WHERE entity_id = ? ORDER BY id", (entity_id,)
                ).fetchall()
            else:
                rows = connection.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
        return [self._audit_from_row(row) for row in rows]

    @staticmethod
    def _audit_from_row(row):
        return {
            "id": row["id"],
            "entity_id": row["entity_id"],
            "actor_id": row["actor_id"],
            "actor_role": row["actor_role"],
            "action": row["action"],
            "from_status": row["from_status"],
            "to_status": row["to_status"],
            "detail": json.loads(row["detail"]),
            "created_at": row["created_at"],
            "policy_version": row["policy_version"] if "policy_version" in row.keys() else None,
        }

    # ------------------------------------------------------------------
    # Idempotency
    # ------------------------------------------------------------------
    def get_idempotency(self, actor_id, idem_key):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT entity_id FROM idempotency WHERE actor_id = ? AND idem_key = ?",
                (actor_id, idem_key),
            ).fetchone()
        return row["entity_id"] if row else None

    def save_idempotency(self, actor_id, idem_key, entity_id):
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO idempotency(actor_id, idem_key, entity_id, created_at) "
                "VALUES (?, ?, ?, ?)",
                (actor_id, idem_key, entity_id, utcnow()),
            )

    # ------------------------------------------------------------------
    # Policy versions
    # ------------------------------------------------------------------
    def tx_insert_policy_version(
        self, conn, dataset_id, version, access_policy, policy_rules,
        committed_by, committed_at, reason=None, batch_id=None,
    ):
        conn.execute(
            "INSERT INTO policy_versions(dataset_id, version, access_policy, policy_rules, "
            "reason, committed_by, committed_at, batch_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                dataset_id, version, access_policy, self._dump(policy_rules or {}),
                reason, committed_by, committed_at, batch_id,
            ),
        )

    def get_policy_version(self, dataset_id, version):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM policy_versions WHERE dataset_id = ? AND version = ?",
                (dataset_id, version),
            ).fetchone()
        return self._policy_version_from_row(row) if row else None

    def list_policy_versions(self, dataset_id=None):
        clauses, params = [], []
        if dataset_id:
            clauses.append("dataset_id = ?")
            params.append(dataset_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM policy_versions" + where + " ORDER BY dataset_id, version",
                params,
            ).fetchall()
        return [self._policy_version_from_row(row) for row in rows]

    @staticmethod
    def _policy_version_from_row(row):
        return {
            "dataset_id": row["dataset_id"],
            "version": int(row["version"]),
            "access_policy": row["access_policy"],
            "policy_rules": json.loads(row["policy_rules"]),
            "reason": row["reason"],
            "committed_by": row["committed_by"],
            "committed_at": row["committed_at"],
            "batch_id": row["batch_id"],
        }

    # ------------------------------------------------------------------
    # Change batches and items
    # ------------------------------------------------------------------
    def tx_insert_batch(
        self, conn, batch_id, dataset_id, policy_version, kind, total_items,
        actor_id, now=None,
    ):
        now = now or utcnow()
        conn.execute(
            "INSERT INTO change_batches(id, dataset_id, policy_version, kind, status, "
            "total_items, processed_items, created_by, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 'processing', ?, 0, ?, ?, ?)",
            (batch_id, dataset_id, policy_version, kind, total_items, actor_id, now, now),
        )

    def tx_insert_batch_item(self, conn, batch_id, entity_kind, entity_id, action, detail=None, now=None):
        conn.execute(
            "INSERT INTO batch_items(batch_id, entity_kind, entity_id, action, status, detail, updated_at) "
            "VALUES (?, ?, ?, ?, 'pending', ?, ?)",
            (batch_id, entity_kind, entity_id, action, self._dump(detail or {}), now or utcnow()),
        )

    def get_batch(self, batch_id):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM change_batches WHERE id = ?", (batch_id,)
            ).fetchone()
        return self._batch_from_row(row) if row else None

    def list_batches(self, dataset_id=None, status=None):
        clauses, params = [], []
        if dataset_id:
            clauses.append("dataset_id = ?")
            params.append(dataset_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM change_batches" + where + " ORDER BY created_at, id", params
            ).fetchall()
        return [self._batch_from_row(row) for row in rows]

    @staticmethod
    def _batch_from_row(row):
        return {
            "id": row["id"],
            "dataset_id": row["dataset_id"],
            "policy_version": int(row["policy_version"]),
            "kind": row["kind"],
            "status": row["status"],
            "total_items": int(row["total_items"]),
            "processed_items": int(row["processed_items"]),
            "created_by": row["created_by"],
            "error": row["error"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_batch_items(self, batch_id, status=None):
        with self._connect() as connection:
            if status:
                rows = connection.execute(
                    "SELECT * FROM batch_items WHERE batch_id = ? AND status = ? "
                    "ORDER BY entity_kind, entity_id",
                    (batch_id, status),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM batch_items WHERE batch_id = ? "
                    "ORDER BY entity_kind, entity_id",
                    (batch_id,),
                ).fetchall()
        return [
            {
                "batch_id": row["batch_id"],
                "entity_kind": row["entity_kind"],
                "entity_id": row["entity_id"],
                "action": row["action"],
                "status": row["status"],
                "detail": json.loads(row["detail"]),
                "error": row["error"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def tx_touch_batch_item(self, conn, batch_id, entity_kind, entity_id, status, detail=None, error=None):
        conn.execute(
            "UPDATE batch_items SET status = ?, detail = ?, error = ?, updated_at = ? "
            "WHERE batch_id = ? AND entity_kind = ? AND entity_id = ?",
            (
                status,
                self._dump(detail or {}),
                error,
                utcnow(),
                batch_id, entity_kind, entity_id,
            ),
        )

    def tx_set_batch_status(self, conn, batch_id, status, processed_items=None, error=None):
        if processed_items is None:
            conn.execute(
                "UPDATE change_batches SET status = ?, error = ?, updated_at = ? WHERE id = ?",
                (status, error, utcnow(), batch_id),
            )
        else:
            conn.execute(
                "UPDATE change_batches SET status = ?, processed_items = ?, error = ?, "
                "updated_at = ? WHERE id = ?",
                (status, processed_items, error, utcnow(), batch_id),
            )

    def tx_count_completed_items(self, conn, batch_id):
        row = conn.execute(
            "SELECT COUNT(1) AS c FROM batch_items WHERE batch_id = ? AND status = 'completed'",
            (batch_id,),
        ).fetchone()
        return int(row["c"])

    # ------------------------------------------------------------------
    # Conflict tickets
    # ------------------------------------------------------------------
    def insert_conflict(
        self, conflict_id, dataset_id, actor_id, actor_role, detail, winner_batch_id=None,
    ):
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO policy_conflicts(conflict_id, dataset_id, winner_batch_id, "
                "actor_id, actor_role, detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    conflict_id, dataset_id, winner_batch_id, actor_id, actor_role,
                    self._dump(detail), utcnow(),
                ),
            )
        return self.get_conflict(conflict_id)

    def get_conflict(self, conflict_id):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM policy_conflicts WHERE conflict_id = ?", (conflict_id,)
            ).fetchone()
        if not row:
            return None
        return {
            "conflict_id": row["conflict_id"],
            "dataset_id": row["dataset_id"],
            "winner_batch_id": row["winner_batch_id"],
            "actor_id": row["actor_id"],
            "actor_role": row["actor_role"],
            "detail": json.loads(row["detail"]),
            "created_at": row["created_at"],
        }

    # ------------------------------------------------------------------
    # Data access requests
    # ------------------------------------------------------------------
    def insert_access_request(
        self, request_id, dataset_id, actor_id, actor_role, decision, reason,
        policy_version, application_id=None, grant_id=None,
    ):
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO access_requests(id, dataset_id, application_id, grant_id, "
                "actor_id, actor_role, decision, reason, policy_version, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    request_id, dataset_id, application_id, grant_id, actor_id,
                    actor_role, decision, reason, policy_version, utcnow(),
                ),
            )
        return self.get_access_request(request_id)

    def get_access_request(self, request_id):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM access_requests WHERE id = ?", (request_id,)
            ).fetchone()
        return self._access_from_row(row) if row else None

    def list_access_requests(self, dataset_id=None, decision=None):
        clauses, params = [], []
        if dataset_id:
            clauses.append("dataset_id = ?")
            params.append(dataset_id)
        if decision:
            clauses.append("decision = ?")
            params.append(decision)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM access_requests" + where + " ORDER BY created_at, id", params
            ).fetchall()
        return [self._access_from_row(row) for row in rows]

    @staticmethod
    def _access_from_row(row):
        return {
            "id": row["id"],
            "dataset_id": row["dataset_id"],
            "application_id": row["application_id"],
            "grant_id": row["grant_id"],
            "actor_id": row["actor_id"],
            "actor_role": row["actor_role"],
            "decision": row["decision"],
            "reason": row["reason"],
            "policy_version": row["policy_version"],
            "created_at": row["created_at"],
        }

    def ping(self):
        with self._connect() as connection:
            connection.execute("SELECT 1").fetchone()
        return True
