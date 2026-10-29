import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

import backend.main as app_module


class MultiFormatRouteTests(unittest.TestCase):
    def setUp(self):
        self.old_overrides = dict(app_module.app.dependency_overrides)
        app_module.app.dependency_overrides[app_module.verify_user_and_credits] = lambda: {
            "user_id": "00000000-0000-0000-0000-000000000123",
            "current_tier": "tier_2_83",
            "monthly_credits_used": 0,
            "total_lifetime_jobs": 0,
            "job_credits_remaining": 5,
            "included_job_limit": 300,
            "max_rows": 25000,
        }
        self.client = TestClient(app_module.app)
        self.db = MagicMock()
        self.db.rpc.return_value.execute.return_value.data = {
            "job_id": "00000000-0000-0000-0000-000000000456",
            "job_credits_remaining": 4,
            "monthly_credits_used": 1,
            "total_lifetime_jobs": 1,
        }

    def tearDown(self):
        app_module.app.dependency_overrides.clear()
        app_module.app.dependency_overrides.update(self.old_overrides)

    def test_json_upload_routes_to_processor_and_persists_report(self):
        with patch.object(app_module, "supabase", self.db):
            response = self.client.post(
                "/api/v1/automation/process-file",
                data={"operation": "auto"},
                files={"file": ("errors.json", b'{"error":"failure","count":2}', "application/json")},
            )
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["job_type"], "json_payload_clean")
        self.assertEqual(body["job_credits_remaining"], 4)
        self.db.rpc.assert_called_once()
        args = self.db.rpc.call_args.args
        self.assertEqual(args[0], "complete_automation_job")
        self.assertEqual(args[1]["p_job_type"], "json_payload_clean")
        self.assertEqual(args[1]["p_input_filename"], "errors.json")

    def test_basic_tier_cannot_upload_json(self):
        app_module.app.dependency_overrides[app_module.verify_user_and_credits] = lambda: {
            "user_id": "00000000-0000-0000-0000-000000000123",
            "current_tier": "tier_1_51",
            "monthly_credits_used": 0,
            "total_lifetime_jobs": 0,
            "job_credits_remaining": 5,
            "included_job_limit": 30,
            "max_rows": 2500,
        }
        with patch.object(app_module, "supabase", self.db):
            response = self.client.post(
                "/api/v1/automation/process-file",
                data={"operation": "auto"},
                files={"file": ("errors.json", b'{"error":"failure"}', "application/json")},
            )
        self.assertEqual(response.status_code, 422)
        self.db.rpc.assert_not_called()

    def test_unsupported_extension_is_rejected_without_charging_credit(self):
        with patch.object(app_module, "supabase", self.db):
            response = self.client.post(
                "/api/v1/automation/process-file",
                data={"operation": "auto"},
                files={"file": ("payload.exe", b"binary", "application/octet-stream")},
            )
        self.assertEqual(response.status_code, 400)
        self.db.rpc.assert_not_called()


if __name__ == "__main__":
    unittest.main()
