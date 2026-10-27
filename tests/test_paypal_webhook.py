import unittest
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

import backend.main as app_module


def make_request(headers=None):
    raw_headers = [
        (key.lower().encode("latin-1"), value.encode("latin-1"))
        for key, value in (headers or {}).items()
    ]
    return Request({
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/api/v1/payments/paypal-webhook",
        "raw_path": b"/api/v1/payments/paypal-webhook",
        "query_string": b"",
        "headers": raw_headers,
        "server": ("testserver", 443),
        "client": ("127.0.0.1", 12345),
    })


class PayPalWebhookSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def test_verifier_fails_closed_when_credentials_missing(self):
        with (
            patch.object(app_module, "PAYPAL_CLIENT_ID", ""),
            patch.object(app_module, "PAYPAL_CLIENT_SECRET", ""),
            patch.object(app_module, "PAYPAL_WEBHOOK_ID", ""),
        ):
            with self.assertRaises(HTTPException) as raised:
                await app_module.verify_paypal_signature(make_request(), {})
        self.assertEqual(raised.exception.status_code, 503)

    async def test_verifier_rejects_missing_signature_headers(self):
        with (
            patch.object(app_module, "PAYPAL_CLIENT_ID", "configured-client"),
            patch.object(app_module, "PAYPAL_CLIENT_SECRET", "configured-secret"),
            patch.object(app_module, "PAYPAL_WEBHOOK_ID", "WH-configured"),
        ):
            with self.assertRaises(HTTPException) as raised:
                await app_module.verify_paypal_signature(make_request(), {})
        self.assertEqual(raised.exception.status_code, 401)

    async def test_webhook_fails_closed_when_database_is_unavailable(self):
        with patch.object(app_module, "supabase", None):
            with self.assertRaises(HTTPException) as raised:
                await app_module.paypal_webhook(make_request())
        self.assertEqual(raised.exception.status_code, 503)


if __name__ == "__main__":
    unittest.main()
