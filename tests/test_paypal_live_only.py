import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from starlette.responses import Response

import backend.main as app_module


class PayPalLiveOnlyConfigTests(unittest.IsolatedAsyncioTestCase):
    def test_api_host_is_fixed_to_live_and_has_no_sandbox_fallback(self):
        self.assertEqual(app_module.PAYPAL_LIVE_API_BASE, "https://api-m.paypal.com")
        self.assertEqual(app_module.PAYPAL_API_BASE, app_module.PAYPAL_LIVE_API_BASE)
        self.assertEqual(app_module._paypal_mode(), "live")

        source = Path(app_module.__file__).read_text(encoding="utf-8").lower()
        self.assertNotIn("sandbox.paypal.com", source)
        self.assertNotIn('os.getenv("paypal_api_base"', source)

    def test_live_checkout_fails_closed_when_live_flag_is_disabled(self):
        with (
            patch.object(app_module, "PAYPAL_CLIENT_ID", "live-client-id"),
            patch.object(app_module, "PAYPAL_CLIENT_SECRET", "live-client-secret"),
            patch.object(app_module, "PAYPAL_WEBHOOK_ID", "live-webhook-id"),
            patch.object(app_module, "PAYPAL_LIVE_ENABLED", False),
        ):
            with self.assertRaises(HTTPException) as raised:
                app_module._assert_paypal_runtime_ready()
        self.assertEqual(raised.exception.status_code, 503)

    def test_runtime_guard_rejects_invalid_mode(self):
        with patch.object(app_module, "_paypal_mode", return_value="invalid"):
            with self.assertRaises(HTTPException) as raised:
                app_module._assert_paypal_runtime_ready()
        self.assertEqual(raised.exception.status_code, 503)

    async def test_public_config_advertises_live_mode_only(self):
        with (
            patch.object(app_module, "PAYPAL_CLIENT_ID", "live-client-id"),
            patch.object(app_module, "PAYPAL_CLIENT_SECRET", "live-client-secret"),
            patch.object(app_module, "PAYPAL_WEBHOOK_ID", "live-webhook-id"),
            patch.object(app_module, "PAYPAL_LIVE_ENABLED", True),
        ):
            config = await app_module.paypal_public_config(Response())

        self.assertTrue(config["enabled"])
        self.assertEqual(config["mode"], "live")
        self.assertEqual(config["currency"], "USD")


if __name__ == "__main__":
    unittest.main()
