import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from starlette.requests import Request

import backend.main as app_module


def make_post_request(body: dict) -> Request:
    raw = json.dumps(body).encode("utf-8")
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": raw, "more_body": False}

    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/api/v1/payments/paypal-webhook",
            "raw_path": b"/api/v1/payments/paypal-webhook",
            "query_string": b"",
            "headers": [(b"content-type", b"application/json")],
            "server": ("testserver", 443),
            "client": ("127.0.0.1", 12345),
        },
        receive,
    )


class DuplicatePayPalWebhookTests(unittest.IsolatedAsyncioTestCase):
    async def test_already_captured_webhook_does_not_apply_rpc_again(self):
        user_id = "00000000-0000-0000-0000-000000000123"
        capture_id = "CAPTURE-ALREADY-APPLIED"
        order_id = "ORDER-ALREADY-APPLIED"
        event = {
            "id": "WH-EVENT-DUPLICATE-TEST",
            "event_type": "PAYMENT.CAPTURE.COMPLETED",
            "resource": {
                "id": capture_id,
                "amount": {"value": "79.00", "currency_code": "USD"},
                "custom_id": user_id,
                "supplementary_data": {"related_ids": {"order_id": order_id}},
            },
        }

        fake_db = MagicMock()
        fake_db.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value.data = [
            {
                "paypal_order_id": order_id,
                "user_id": user_id,
                "tier": "tier_1_51",
                "amount": 79.0,
                "status": "captured",
                "capture_id": capture_id,
            }
        ]

        with (
            patch.object(app_module, "supabase", fake_db),
            patch.object(app_module, "verify_paypal_signature", new=AsyncMock(return_value=None)),
        ):
            response = await app_module.paypal_webhook(
                make_post_request(event)
            )

        self.assertTrue(response.success)
        self.assertTrue(response.details["duplicate"])
        self.assertEqual(response.details["transaction_id"], capture_id)
        fake_db.rpc.assert_not_called()
        fake_db.table.return_value.update.assert_not_called()


if __name__ == "__main__":
    unittest.main()
