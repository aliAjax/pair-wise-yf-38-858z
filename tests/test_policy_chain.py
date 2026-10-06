import tempfile
import unittest
from pathlib import Path

from src.domain import (
    AccessDenied,
    Actor,
    BatchFailed,
    PermissionDenied,
    PolicyConflictError,
)
from src.ledger import ExternalLedger
from src.repository import SQLiteRepository
from src.rules import RuleEngine
from src.service import DomainService


ADMIN = Actor("admin-1", "admin")
COMMITTEE = Actor("cm-1", "committee")
APPLICANT = Actor("researcher-1", "applicant")
AUDITOR = Actor("auditor-1", "auditor")


class PolicyChainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.service = DomainService(
            self.repo, RuleEngine(), ledger=ExternalLedger()
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _approved_flow(self, rules=None):
        dataset = self.service.create(
            ADMIN, "dataset",
            {
                "name": "Cohort",
                "access_policy": "controlled",
                "policy_rules": rules or {},
            },
        )
        application = self.service.create(
            APPLICANT, "application",
            {"dataset_id": dataset["id"], "applicant_id": "researcher-1",
             "purpose": "variant analysis"},
        )
        self.service.transition(APPLICANT, application["id"], "submit", {})
        self.service.transition(
            COMMITTEE, application["id"], "review", {"committee_id": "c-a"}
        )
        self.service.transition(
            COMMITTEE, application["id"], "approve",
            {"approvals": ["r1", "r2", "r3"], "terms": "nc",
             "expires_at": "2099-01-01"},
        )
        grant = self.service.create(
            COMMITTEE, "grant",
            {"application_id": application["id"], "dataset_id": dataset["id"],
             "recipient": "researcher-1"},
        )
        self.service.transition(
            COMMITTEE, grant["id"], "activate",
            {"starts_at": "2026-09-01", "expires_at": "2099-01-01"},
        )
        return dataset, application, grant

    def test_policy_change_versions_and_cascades(self):
        dataset, application, grant = self._approved_flow()
        self.assertEqual(dataset["data"]["policy_version"], 1)
        self.assertIn("policy_committed_at", dataset["data"])

        amended = self.service.transition(
            COMMITTEE, dataset["id"], "amend_policy",
            {"access_policy": "controlled-v2",
             "policy_rules": {"minimum_approvals": 2},
             "reason": "annual review"},
        )
        self.assertEqual(amended["data"]["policy_version"], 2)
        self.assertEqual(amended["data"]["access_policy"], "controlled-v2")
        self.assertIn("policy_committed_at", amended["data"])

        versions = self.service.policy_versions(dataset["id"])
        self.assertEqual([v["version"] for v in versions], [1, 2])
        self.assertEqual(versions[1]["access_policy"], "controlled-v2")
        self.assertTrue(versions[1]["batch_id"])

        # 旧申请先失效；旧授权被暂停
        app_row = self.service.get(application["id"])
        self.assertEqual(app_row["status"], "stale")
        self.assertEqual(app_row["data"]["superseded_by_policy_version"], 2)
        grant_row = self.service.get(grant["id"])
        self.assertEqual(grant_row["status"], "suspended")
        self.assertEqual(grant_row["data"]["policy_version"], 2)

        batch = amended["batch"]
        self.assertEqual(batch["status"], "completed")
        kinds = {(item["entity_kind"], item["action"]) for item in batch["items"]}
        self.assertIn(("application", "stale"), kinds)
        self.assertIn(("grant", "suspend"), kinds)

        # 审计带上策略版本，能说清按的是哪一版
        audit = self.service.audit_log(dataset["id"])
        amend_entries = [row for row in audit if row["action"] == "amend_policy"]
        self.assertEqual(amend_entries[-1]["policy_version"], 2)
        self.assertEqual(
            amend_entries[-1]["detail"]["batch_id"], batch["id"]
        )

    def test_pending_applications_are_recomputed_under_new_policy(self):
        dataset = self.service.create(
            ADMIN, "dataset",
            {"name": "C", "access_policy": "controlled", "policy_rules": {}},
        )
        allowed = self.service.create(
            APPLICANT, "application",
            {"dataset_id": dataset["id"], "applicant_id": "u-ok",
             "purpose": "variant analysis"},
        )
        blocked = self.service.create(
            Actor("u-no", "applicant"), "application",
            {"dataset_id": dataset["id"], "applicant_id": "u-no",
             "purpose": "marketing"},
        )
        for app in (allowed, blocked):
            self.service.transition(
                Actor(app["data"]["applicant_id"], "applicant"),
                app["id"], "submit", {},
            )

        result = self.service.transition(
            COMMITTEE, dataset["id"], "amend_policy",
            {"access_policy": "controlled-v2",
             "policy_rules": {"allowed_purposes": ["variant analysis"]},
             "reason": "tighten"},
        )
        self.assertEqual(self.service.get(allowed["id"])["status"], "submitted")
        self.assertEqual(
            self.service.get(allowed["id"])["data"]["policy_version"], 2
        )
        self.assertEqual(
            self.service.get(blocked["id"])["status"], "auto_rejected"
        )
        self.assertEqual(
            self.service.get(blocked["id"])["data"]["policy_version"], 2
        )
        actions = {
            item["entity_id"]: item["status"]
            for item in result["batch"]["items"]
        }
        self.assertEqual(actions[allowed["id"]], "completed")
        self.assertEqual(actions[blocked["id"]], "completed")

    def test_reconfirm_then_restore_grant(self):
        dataset, application, grant = self._approved_flow()
        self.service.transition(
            COMMITTEE, dataset["id"], "amend_policy",
            {"access_policy": "controlled-v2", "policy_rules": {},
             "reason": "review"},
        )

        # 暂停期间取数直接拒绝，并记下策略版本
        with self.assertRaises(AccessDenied) as suspended:
            self.service.request_access(APPLICANT, dataset["id"])
        self.assertEqual(suspended.exception.reason, "grant_suspended")
        self.assertEqual(suspended.exception.policy_version, 2)

        # 重新确认需要按新策略的最少委员数
        with self.assertRaises(PermissionDenied):
            self.service.transition(
                APPLICANT, application["id"], "reconfirm",
                {"approvals": ["r1"]},
            )
        self.service.transition(
            COMMITTEE, application["id"], "reconfirm",
            {"approvals": ["r1", "r2", "r3"]},
        )
        app_row = self.service.get(application["id"])
        self.assertEqual(app_row["status"], "approved")
        self.assertEqual(app_row["data"]["policy_version"], 2)

        with self.assertRaises(PermissionDenied):
            self.service.transition(APPLICANT, grant["id"], "restore", {})
        self.service.transition(COMMITTEE, grant["id"], "restore", {})
        self.assertEqual(self.service.get(grant["id"])["status"], "active")

        allowed = self.service.request_access(APPLICANT, dataset["id"])
        self.assertEqual(allowed["decision"], "allowed")
        self.assertEqual(allowed["policy_version"], 2)

    def test_revoked_grant_can_never_access(self):
        dataset, application, grant = self._approved_flow()
        self.service.transition(
            COMMITTEE, grant["id"], "revoke", {"reason": "misuse"}
        )
        with self.assertRaises(AccessDenied) as denied:
            self.service.request_access(APPLICANT, dataset["id"])
        self.assertEqual(denied.exception.reason, "grant_revoked")

    def test_overreach_request_is_denied_and_audited(self):
        dataset, application, grant = self._approved_flow()
        thief = Actor("researcher-2", "applicant")
        with self.assertRaises(AccessDenied) as denied:
            self.service.request_access(
                thief, dataset["id"], {"grant_id": grant["id"]}
            )
        self.assertEqual(denied.exception.reason, "recipient_mismatch")
        entries = [
            row for row in self.service.audit_log(dataset["id"])
            if row["action"] == "access_denied"
        ]
        self.assertTrue(entries)
        self.assertEqual(entries[-1]["actor_id"], "researcher-2")
        self.assertEqual(entries[-1]["detail"]["reason"], "recipient_mismatch")

    def test_concurrent_policy_changes_loser_gets_conflict_id(self):
        dataset, _, _ = self._approved_flow()

        def stale_change():
            # expected_version=1 模拟基于旧版本并发提交
            return self.service.transition(
                COMMITTEE, dataset["id"], "amend_policy",
                {"access_policy": "stale-text", "policy_rules": {},
                 "reason": "late"},
                expected_version=1,
            )

        self.service.transition(
            Actor("cm-2", "committee"), dataset["id"], "amend_policy",
            {"access_policy": "controlled-v2", "policy_rules": {},
             "reason": "first"},
        )
        with self.assertRaises(PolicyConflictError) as conflict:
            stale_change()
        self.assertTrue(conflict.exception.conflict_id.startswith("CF-"))
        self.assertEqual(
            self.service.get(dataset["id"])["data"]["access_policy"],
            "controlled-v2",
        )
        versions = self.service.policy_versions(dataset["id"])
        self.assertEqual([v["version"] for v in versions], [1, 2])


class BatchFailureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.service = DomainService(self.repo, RuleEngine())

    def tearDown(self):
        self.tmp.cleanup()

    def _setup(self):
        dataset = self.service.create(
            Actor("admin", "admin"), "dataset",
            {"name": "C", "access_policy": "controlled"},
        )
        applications = []
        for index in range(3):
            app = self.service.create(
                Actor("u%s" % index, "applicant"), "application",
                {"dataset_id": dataset["id"], "applicant_id": "u%s" % index,
                 "purpose": "variant analysis"},
            )
            self.service.transition(
                Actor("u%s" % index, "applicant"), app["id"], "submit", {}
            )
            applications.append(app)
        return dataset, applications

    def test_commit_failure_rolls_back_entirely(self):
        dataset, _ = self._setup()
        before = self.service.get(dataset["id"])
        self.repo.inject_failure("policy_commit", "disk full")
        with self.assertRaises(Exception):
            self.service.transition(
                Actor("cm", "committee"), dataset["id"], "amend_policy",
                {"access_policy": "controlled-v2", "reason": "boom"},
            )
        after = self.service.get(dataset["id"])
        self.assertEqual(after["version"], before["version"])
        self.assertEqual(after["data"]["policy_version"], 1)
        self.assertEqual(len(self.service.policy_versions(dataset["id"])), 1)
        self.assertEqual(self.service.list_batches(), [])

    def test_batch_retries_only_unfinished_items(self):
        dataset, applications = self._setup()
        # 第一个批处理项提交时写库失败
        self.repo.inject_failure("batch_item", "transient i/o error")
        with self.assertRaises(BatchFailed) as failed:
            self.service.transition(
                Actor("cm", "committee"), dataset["id"], "amend_policy",
                {"access_policy": "controlled-v2",
                 "policy_rules": {"allowed_purposes": ["variant analysis"]},
                 "reason": "tighten"},
            )
        batch_id = failed.exception.batch_id
        # 版本提交已落库（先落库的生效），但级联批处理挂起
        self.assertEqual(self.service.get(dataset["id"])["data"]["policy_version"], 2)
        batch = self.service.get_batch(batch_id)
        self.assertEqual(batch["status"], "failed")
        completed = {item["entity_id"] for item in batch["items"]
                     if item["status"] == "completed"}
        self.assertEqual(completed, set())

        # 重试只补没完成的申请
        summary = self.service.retry_batch(Actor("cm", "committee"), batch_id)
        self.assertEqual(summary["status"], "completed")
        self.assertEqual(
            {item["status"] for item in summary["items"]}, {"completed"}
        )
        for app in applications:
            self.assertEqual(
                self.service.get(app["id"])["data"]["policy_version"], 2
            )


class ReconcileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger_path = Path(self.tmp.name) / "external.json"
        self.repo = SQLiteRepository(Path(self.tmp.name) / "test.db")

    def tearDown(self):
        self.tmp.cleanup()

    def _service(self, rows):
        self.ledger_path.write_text(
            __import__("json").dumps(rows), encoding="utf-8"
        )
        return DomainService(
            self.repo, RuleEngine(), ledger=ExternalLedger(self.ledger_path)
        )

    def test_reconcile_matches_flags_and_records_denial(self):
        service = self._service([])
        actor = Actor("admin", "admin")
        dataset = service.create(
            actor, "dataset", {"name": "C", "access_policy": "controlled"}
        )
        app = service.create(
            Actor("u1", "applicant"), "application",
            {"dataset_id": dataset["id"], "applicant_id": "u1",
             "purpose": "p"},
        )
        service.transition(Actor("u1", "applicant"), app["id"], "submit", {})
        service.transition(
            Actor("cm", "committee"), app["id"], "review",
            {"committee_id": "c"},
        )
        service.transition(
            Actor("cm", "committee"), app["id"], "approve",
            {"approvals": ["a", "b", "c"], "terms": "x",
             "expires_at": "2099-01-01"},
        )
        grant = service.create(
            Actor("cm", "committee"), "grant",
            {"application_id": app["id"], "dataset_id": dataset["id"],
             "recipient": "u1"},
        )
        service.transition(
            Actor("cm", "committee"), grant["id"], "activate",
            {"starts_at": "2026-09-01", "expires_at": "2099-01-01"},
        )
        allowed = service.request_access(Actor("u1", "applicant"), dataset["id"])

        external = [
            # 与本地放行一致
            {"id": allowed["id"], "dataset_id": dataset["id"],
             "actor_id": "u1", "event": "access", "decision": "allow",
             "policy_version": 1},
            # 外部有放行、本地没有：越权取数
            {"id": "ext-rogue", "dataset_id": dataset["id"],
             "actor_id": "u2", "event": "access", "decision": "allow",
             "policy_version": 1},
        ]
        service = self._service(external)
        report = service.reconcile(Actor("aud", "auditor"), dataset["id"])
        statuses = {item["status"] for item in report["items"]}
        self.assertIn("match", statuses)
        self.assertIn("unauthorized_external_access", statuses)
        self.assertEqual(report["unauthorized_external_access"], 1)

        # 越权事件补记一条本地拒绝
        denials = service.list_access_requests(decision="denied")
        self.assertEqual(len(denials), 1)
        self.assertEqual(denials[0]["reason"], "unauthorized_external_access")
        audit = [row for row in service.audit_log(dataset["id"])
                 if row["action"] == "access_denied"]
        self.assertTrue(audit)

    def test_non_auditor_cannot_reconcile(self):
        service = self._service([])
        with self.assertRaises(PermissionDenied):
            service.reconcile(Actor("cm", "committee"))


if __name__ == "__main__":
    unittest.main()
