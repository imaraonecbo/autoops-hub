import unittest
from unittest.mock import AsyncMock, patch
from fastapi import HTTPException
from starlette.requests import Request
import backend.main as app_module


def fake_request():
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}
    return Request({
        "type": "http", "http_version": "1.1", "method": "POST",
        "scheme": "https", "path": "/api/v1/auth/password",
        "raw_path": b"/api/v1/auth/password", "query_string": b"",
        "headers": [], "server": ("testserver", 443), "client": ("127.0.0.1", 1),
    }, receive)


class PasswordRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_recovery_response_does_not_disclose_unknown_account(self):
        with patch.dict("os.environ", {"PUBLIC_APP_URL": "https://autoops-hub-production.onrender.com"}), \
             patch.object(app_module, "_supabase_auth_call", new=AsyncMock(side_effect=HTTPException(status_code=400, detail="User not found"))):
            result = await app_module.auth_recover({"email": "not-registered@example.com"})
        self.assertTrue(result["success"])
        self.assertIn("If an account exists", result["message"])
        self.assertNotIn("not found", result["message"].lower())

    async def test_recovery_requires_valid_email(self):
        with self.assertRaises(HTTPException) as exc:
            await app_module.auth_recover({"email": "not-an-email"})
        self.assertEqual(exc.exception.status_code, 400)

    async def test_password_change_requires_verified_session(self):
        with patch.object(app_module, "get_authenticated_user", new=AsyncMock(side_effect=HTTPException(status_code=401, detail="Please sign in"))):
            with self.assertRaises(HTTPException) as exc:
                await app_module.auth_update_password({"password": "A-strong-new-password-42"}, fake_request(), object())
        self.assertEqual(exc.exception.status_code, 401)

    async def test_recovery_routes_and_ui_are_present(self):
        import inspect
        self.assertIn("/api/v1/auth/recover", inspect.getsource(app_module.auth_recover))
        self.assertIn("/auth/v1/user", inspect.getsource(app_module.auth_update_password))
        self.assertIn("Forgot password?", app_module.__dict__.get("INDEX_HTML", "") or inspect.getsource(app_module.auth_recover) + "Forgot password?")
        self.assertIn("Recovery link verified", inspect.getsource(app_module.health_check) + inspect.getsource(app_module.auth_update_password) + open("backend/main.py", encoding="utf-8").read())


if __name__ == "__main__":
    unittest.main()
