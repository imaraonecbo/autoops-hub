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
    }, receive=receive_body(body))


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
    async def test_unsigned_request_is_rejected_before_credential_checks(self):
        # Missing signature headers are an authentication failure even if server
        # credentials are also incomplete; never accept an unsigned delivery.
        with (
            patch.object(app_module, "PAYPAL_CLIENT_ID", ""),
            patch.object(app_module, "PAYPAL_CLIENT_SECRET", ""),
            patch.object(app_module, "PAYPAL_WEBHOOK_ID", ""),
        ):
            with self.assertRaises(HTTPException) as raised:
                await app_module.verify_paypal_signature(make_request(), {})
        self.assertEqual(raised.exception.status_code, 401)

    async def test_verifier_rejects_missing_signature_headers(self):
        with (
            patch.object(app_module, "PAYPAL_CLIENT_ID", "configured-client"),
            patch.object(app_module, "PAYPAL_CLIENT_SECRET", "configured-secret"),
            patch.object(app_module, "PAYPAL_WEBHOOK_ID", "WH-configured"),
        ):
            with self.assertRaises(HTTPException) as raised:
                await app_module.verify_paypal_signature(make_request(), {})
        self.assertEqual(raised.exception.status_code, 401)



    async def test_verifier_uses_paypal_api_and_requires_success(self):
        headers = {
            "PAYPAL-TRANSMISSION-ID": "transmission-id",
            "PAYPAL-TRANSMISSION-TIME": "2026-10-27T09:00:00Z",
            "PAYPAL-TRANSMISSION-SIG": "signature",
            "PAYPAL-CERT-URL": "https://api.paypal.com/cert",
            "PAYPAL-AUTH-ALGO": "SHA256withRSA",
        }
        token_response = MagicMock()
        token_response.json.return_value = {"access_token": "test-access-token"}
        verify_response = MagicMock()
        verify_response.json.return_value = {"verification_status": "SUCCESS"}
        fake_client = MagicMock()
        fake_client.post = AsyncMock(side_effect=[token_response, verify_response])
        fake_client.__aenter__ = AsyncMock(return_value=fake_client)
        fake_client.__aexit__ = AsyncMock(return_value=False)
        with (
            patch.object(app_module, "PAYPAL_CLIENT_ID", "configured-client"),
            patch.object(app_module, "PAYPAL_CLIENT_SECRET", "configured-secret"),
            patch.object(app_module, "PAYPAL_WEBHOOK_ID", "WH-configured"),
            patch.object(app_module, "PAYPAL_LIVE_ENABLED", True),
            patch.object(app_module.httpx, "AsyncClient", return_value=fake_client),
        ):
            await app_module.verify_paypal_signature(make_request(headers=headers), {"id": "EVENT-1"})
        self.assertEqual(fake_client.post.await_count, 2)
        verification_call = fake_client.post.await_args_list[1]
        self.assertTrue(verification_call.args[0].endswith("/v1/notifications/verify-webhook-signature"))
        self.assertEqual(verification_call.kwargs["json"]["webhook_event"], {"id": "EVENT-1"})

    async def test_verified_capture_uses_server_recorded_order_and_atomic_rpc(self):
        user_id = "00000000-0000-0000-0000-000000000123"
        event = {
            "event_type": "PAYMENT.CAPTURE.COMPLETED",
            "resource": {
                "id": "CAPTURE-TEST-123",
                "amount": {"value": "79.00", "currency_code": "USD"},
                "custom_id": user_id,
                "supplementary_data": {"related_ids": {"order_id": "ORDER-TEST-123"}},
            },
        }
        fake_db = MagicMock()
        fake_db.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value.data = [{
            "paypal_order_id": "ORDER-TEST-123",
            "user_id": user_id,
            "tier": "tier_1_51",
            "amount": 79.0,
            "status": "pending",
            "capture_id": None,
        }]
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
            "p_amount_paid": 79.0,
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
