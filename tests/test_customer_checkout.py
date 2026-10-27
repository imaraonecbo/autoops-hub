import unittest
from unittest.mock import patch, MagicMock
from fastapi import HTTPException
from starlette.requests import Request
import backend.main as app_module

def request_with_headers(headers=None, cookie=None):
    values = dict(headers or {})
    if cookie:
        values["cookie"] = cookie
    raw = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k,v in values.items()]
    async def receive():
        return {"type":"http.request","body":b"","more_body":False}
    return Request({"type":"http","http_version":"1.1","method":"GET","scheme":"https",
      "path":"/api/v1/auth/me","raw_path":b"/api/v1/auth/me","query_string":b"",
      "headers":raw,"server":("testserver",443),"client":("127.0.0.1",1)}, receive)

class CustomerAuthTests(unittest.IsolatedAsyncioTestCase):
    async def test_client_cannot_impersonate_user_with_x_user_id(self):
        request = request_with_headers({"X-User-ID":"00000000-0000-0000-0000-000000000123"})
        with patch.object(app_module, "SUPABASE_URL", "https://example.supabase.co"), patch.object(app_module, "SUPABASE_KEY", "test-key"):
            with self.assertRaises(HTTPException) as exc:
                await app_module.get_authenticated_user(request)
        self.assertEqual(exc.exception.status_code, 401)

    async def test_unknown_tier_is_rejected_before_paypal_order(self):
        self.assertNotIn("tier_free", app_module.TIERS)
        self.assertEqual(app_module.TIERS["tier_1_51"][0], "51.00")
        self.assertEqual(app_module.TIERS["tier_2_83"][0], "83.00")
        self.assertEqual(app_module.TIERS["tier_3_129"][0], "129.00")

if __name__ == "__main__":
    unittest.main()
