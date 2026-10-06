import json
import os


class LedgerError(Exception):
    """The external ledger cannot be read."""


class ExternalLedger:
    """外部台账（只读）。

    演示实现从 JSON 文件读取，每条记录形如：
        {"id": "ext-1", "dataset_id": "d1", "actor_id": "u1",
         "event": "access", "decision": "allow",
         "policy_version": 2, "created_at": "2026-10-06T10:00:00+00:00"}
    生产环境可替换成跨机构只读拉取的实现，接口保持不变。
    """

    def __init__(self, path=None):
        self.path = path

    def fetch(self, dataset_id=None):
        if not self.path:
            return []
        if not os.path.exists(self.path):
            raise LedgerError("external ledger not found: " + self.path)
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                records = json.load(handle)
        except ValueError as exc:
            raise LedgerError("external ledger is not valid JSON: %s" % exc)
        if not isinstance(records, list):
            raise LedgerError("external ledger must be a JSON array")
        if dataset_id:
            records = [
                row for row in records if str(row.get("dataset_id")) == str(dataset_id)
            ]
        return records
