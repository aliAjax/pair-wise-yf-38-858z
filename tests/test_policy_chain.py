import tempfile
import unittest
from pathlib import Path

from src.domain import Actor, ConflictError, PermissionDenied, ValidationError
from src.repository import SQLiteRepository
from src.rules import RuleEngine
from src.service import DomainService


class PolicyChainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.service = DomainService(self.repo, RuleEngine())
        self.admin = Actor("admin-1", "admin")
        self.committee = Actor("committee-1", "committee")
        self.auditor = Actor("auditor-1", "auditor")
        self.viewer = Actor("viewer-1", "viewer")

    def tearDown(self):
        self.tmp.cleanup()

    def _dataset(self, policy="controlled"):
        return self.service.create(
            self.admin, "dataset", {"name": "D", "access_policy": policy}
        )

    def _application(self, dataset_id, purpose="analysis"):
        return self.service.create(
            self.admin,
            "application",
            {"dataset_id": dataset_id, "applicant_id": "APP-1", "purpose": purpose},
        )

    def _grant(self, application_id, dataset_id):
        return self.service.create(
            self.admin,
            "grant",
            {
                "application_id": application_id,
                "dataset_id": dataset_id,
                "recipient": "researcher-1",
            },
        )

    def _approve(self, app_id):
        self.service.transition(self.admin, app_id, "submit", {})
        self.service.transition(self.admin, app_id, "review", {"committee_id": "c-a"})
        self.service.transition(
            self.admin,
            app_id,
            "approve",
            {"approvals": ["r1", "r2", "r3"], "terms": "t", "expires_at": "2099-01-01"},
        )

    def _activate_grant(self, grant_id):
        self.service.transition(
            self.admin,
            grant_id,
            "activate",
            {"starts_at": "2026-01-01", "expires_at": "2099-01-01"},
        )

    def test_policy_change_records_version_and_timestamp(self):
        ds = self._dataset()
        self.assertEqual(ds["data"]["policy_version"], 1)
        self.assertIn("policy_updated_at", ds["data"])
        updated = self.service.transition(
            self.admin, ds["id"], "update_policy", {"access_policy": "restricted"}
        )
        self.assertEqual(updated["data"]["policy_version"], 2)
        self.assertGreaterEqual(
            updated["data"]["policy_updated_at"], ds["data"]["policy_updated_at"]
        )
        entries = self.service.audit_log(ds["id"])
        self.assertEqual(entries[-1]["action"], "update_policy")
        self.assertEqual(entries[-1]["detail"]["policy_version"], 2)

    def test_cascade_invalidates_pending_reconfirms_approved_recalcs_draft(self):
        ds = self._dataset()
        pending = self._application(ds["id"], "pending work")
        approved = self._application(ds["id"], "approved work")
        draft = self._application(ds["id"], "draft work")
        self._approve(approved["id"])
        grant = self._grant(approved["id"], ds["id"])
        self._activate_grant(grant["id"])
        self.service.transition(self.admin, pending["id"], "submit", {})
        self.service.transition(self.admin, pending["id"], "review", {"committee_id": "c-a"})

        self.service.transition(
            self.admin, ds["id"], "update_policy", {"access_policy": "closed"}
        )

        pending_after = self.service.get(pending["id"])
        self.assertEqual(pending_after["status"], "invalidated")
        self.assertEqual(pending_after["data"]["policy_version"], 2)

        approved_after = self.service.get(approved["id"])
        self.assertEqual(approved_after["status"], "reconfirming")
        self.assertEqual(approved_after["data"]["policy_version"], 2)

        draft_after = self.service.get(draft["id"])
        self.assertEqual(draft_after["status"], "draft")
        self.assertEqual(draft_after["data"]["policy_version"], 2)

        grant_after = self.service.get(grant["id"])
        self.assertEqual(grant_after["status"], "suspended")
        self.assertEqual(grant_after["data"]["policy_version"], 2)

    def test_fetch_on_suspended_grant_denied_with_policy_version(self):
        ds = self._dataset()
        app = self._application(ds["id"])
        self._approve(app["id"])
        grant = self._grant(app["id"], ds["id"])
        self._activate_grant(grant["id"])

        self.service.transition(
            self.admin, ds["id"], "update_policy", {"access_policy": "closed"}
        )
        with self.assertRaises(PermissionDenied):
            self.service.transition(self.admin, grant["id"], "fetch", {})
        external = self.repo.latest_external_ledger(grant["id"])
        self.assertFalse(external["allowed"])
        self.assertEqual(external["policy_version"], 2)

    def test_fetch_on_active_grant_allowed_records_policy_version(self):
        ds = self._dataset()
        app = self._application(ds["id"])
        self._approve(app["id"])
        grant = self._grant(app["id"], ds["id"])
        self._activate_grant(grant["id"])
        result = self.service.transition(self.admin, grant["id"], "fetch", {})
        self.assertEqual(result["decision"], "allowed")
        self.assertEqual(result["policy_version"], 1)
        external = self.repo.latest_external_ledger(grant["id"])
        self.assertTrue(external["allowed"])

    def test_reconfirm_resumes_suspended_grant(self):
        ds = self._dataset()
        app = self._application(ds["id"])
        self._approve(app["id"])
        grant = self._grant(app["id"], ds["id"])
        self._activate_grant(grant["id"])
        self.service.transition(
            self.admin, ds["id"], "update_policy", {"access_policy": "closed"}
        )
        self.assertEqual(self.service.get(grant["id"])["status"], "suspended")

        self.service.transition(self.admin, app["id"], "reconfirm", {})
        self.assertEqual(self.service.get(app["id"])["status"], "approved")
        grant_after = self.service.get(grant["id"])
        self.assertEqual(grant_after["status"], "active")
        self.assertEqual(grant_after["data"]["policy_version"], 2)
        result = self.service.transition(self.admin, grant["id"], "fetch", {})
        self.assertEqual(result["decision"], "allowed")

    def test_concurrent_policy_change_loser_gets_conflict(self):
        ds = self._dataset()
        first = self.service.transition(
            self.admin, ds["id"], "update_policy", {"access_policy": "closed"}
        )
        self.assertEqual(first["data"]["policy_version"], 2)
        with self.assertRaises(ConflictError):
            self.service.transition(
                self.committee,
                ds["id"],
                "update_policy",
                {"access_policy": "open"},
                expected_version=1,
            )

    def test_batch_reconfirm_rejects_invalid_item_whole_batch(self):
        ds = self._dataset()
        app = self._application(ds["id"])
        self._approve(app["id"])
        self.service.transition(
            self.admin, ds["id"], "update_policy", {"access_policy": "closed"}
        )
        draft = self._application(ds["id"], "draft")
        with self.assertRaises(ValidationError):
            self.service.batch_reconfirm(
                self.admin, ds["id"], [app["id"], draft["id"]]
            )
        self.assertEqual(self.service.get(app["id"])["status"], "reconfirming")

    def test_batch_reconfirm_retries_only_unfinished(self):
        ds = self._dataset()
        app1 = self._application(ds["id"], "a1")
        app2 = self._application(ds["id"], "a2")
        self._approve(app1["id"])
        self._approve(app2["id"])
        self.service.transition(
            self.admin, ds["id"], "update_policy", {"access_policy": "closed"}
        )
        result1 = self.service.batch_reconfirm(self.admin, ds["id"], [app1["id"]])
        self.assertEqual(result1["results"][0]["status"], "reconfirmed")
        self.assertEqual(self.service.get(app1["id"])["status"], "approved")

        result2 = self.service.batch_reconfirm(
            self.admin, ds["id"], [app1["id"], app2["id"]]
        )
        statuses = {r["id"]: r["status"] for r in result2["results"]}
        self.assertEqual(statuses[app1["id"]], "reconfirmed")
        self.assertEqual(statuses[app2["id"]], "reconfirmed")

    def test_reconcile_is_idempotent(self):
        ds = self._dataset()
        app = self._application(ds["id"])
        self._approve(app["id"])
        grant = self._grant(app["id"], ds["id"])
        self._activate_grant(grant["id"])
        self.service.transition(
            self.admin, ds["id"], "update_policy", {"access_policy": "closed"}
        )
        self.assertEqual(self.service.get(grant["id"])["status"], "suspended")
        self.service.transition(self.admin, ds["id"], "reconcile", {})
        self.assertEqual(self.service.get(grant["id"])["status"], "suspended")
        self.service.transition(self.admin, app["id"], "reconfirm", {})
        self.assertEqual(self.service.get(grant["id"])["status"], "active")

    def test_audit_reconcile_auditor_only(self):
        ds = self._dataset()
        app = self._application(ds["id"])
        self._approve(app["id"])
        grant = self._grant(app["id"], ds["id"])
        self._activate_grant(grant["id"])
        self.service.transition(self.admin, grant["id"], "fetch", {})

        report = self.service.reconcile_audit(self.auditor)
        self.assertEqual(len(report["matched"]), 1)
        self.assertEqual(len(report["mismatched"]), 0)

        with self.assertRaises(PermissionDenied):
            self.service.reconcile_audit(self.viewer)

    def test_audit_reconcile_detects_mismatch(self):
        ds = self._dataset()
        app = self._application(ds["id"])
        self._approve(app["id"])
        grant = self._grant(app["id"], ds["id"])
        self._activate_grant(grant["id"])
        self.repo.record_external_ledger(grant["id"], "fetch", 99, False)

        report = self.service.reconcile_audit(self.auditor)
        self.assertEqual(len(report["mismatched"]), 1)
        self.assertEqual(report["mismatched"][0]["grant_id"], grant["id"])
        self.assertTrue(report["mismatched"][0]["local_active"])
        self.assertFalse(report["mismatched"][0]["external_allowed"])

    def test_revoke_then_fetch_denied(self):
        ds = self._dataset()
        app = self._application(ds["id"])
        self._approve(app["id"])
        grant = self._grant(app["id"], ds["id"])
        self._activate_grant(grant["id"])
        self.service.transition(self.admin, grant["id"], "revoke", {"reason": "done"})
        with self.assertRaises(PermissionDenied):
            self.service.transition(self.admin, grant["id"], "fetch", {})
        external = self.repo.latest_external_ledger(grant["id"])
        self.assertFalse(external["allowed"])


if __name__ == "__main__":
    unittest.main()
