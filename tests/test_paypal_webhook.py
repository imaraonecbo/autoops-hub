import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import HTTPException
from starlette.requests import Request

import backend.main as app_module


def make_request(headers=None, body=b"{}"):
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
        "receive": receive_body(body),
    })


def receive_body(body):
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


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


    async def test_verified_capture_uses_atomic_database_rpc(self):
        user_id = "00000000-0000-0000-0000-000000000123"
        event = {
            "event_type": "PAYMENT.CAPTURE.COMPLETED",
            "resource": {
                "id": "CAPTURE-TEST-123",
                "amount": {"value": "51.00", "currency_code": "USD"},
                "custom_id": json.dumps({"user_id": user_id}),
            },
        }
        fake_db = MagicMock()
        fake_db.rpc.return_value.execute.return_value.data = {
            "success": True, "duplicate": False, "tier": "tier_1_51"
        }
        with (
            patch.object(app_module, "supabase", fake_db),
            patch.object(app_module, "verify_paypal_signature", new=AsyncMock(return_value=None)),
        ):
            response = await app_module.paypal_webhook(
                make_request(body=json.dumps(event).encode("utf-8"))
            )
        self.assertTrue(response.success)
        self.assertEqual(response.details["tier"], "tier_1_51")
        fake_db.rpc.assert_called_once_with("apply_paypal_capture", {
            "p_user_id": user_id,
            "p_transaction_id": "CAPTURE-TEST-123",
            "p_amount_paid": 51.0,
            "p_assigned_tier": "tier_1_51",
        })

    async def test_unconfigured_payment_amount_is_rejected(self):
        event = {
            "event_type": "PAYMENT.CAPTURE.COMPLETED",
            "resource": {
                "id": "CAPTURE-TEST-INVALID",
                "amount": {"value": "52.00", "currency_code": "USD"},
                "custom_id": json.dumps({"user_id": "00000000-0000-0000-0000-000000000123"}),
            },
        }
        fake_db = MagicMock()
        with (
            patch.object(app_module, "supabase", fake_db),
            patch.object(app_module, "verify_paypal_signature", new=AsyncMock(return_value=None)),
        ):
            with self.assertRaises(HTTPException) as raised:
                await app_module.paypal_webhook(
                    make_request(body=json.dumps(event).encode("utf-8"))
                )
        self.assertEqual(raised.exception.status_code, 400)
        fake_db.rpc.assert_not_called()

    async def test_webhook_fails_closed_when_database_is_unavailable(self):
        with patch.object(app_module, "supabase", None):
            with self.assertRaises(HTTPException) as raised:
                await app_module.paypal_webhook(make_request())
        self.assertEqual(raised.exception.status_code, 503)


if __name__ == "__main__":
    unittest.main()
