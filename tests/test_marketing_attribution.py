import unittest

import backend.main as app_module


class MarketingAttributionTests(unittest.TestCase):
    """Keep campaign tags bounded and free of unnecessary personal data."""
    def test_marketing_fields_apply_safe_defaults(self):
        self.assertEqual(
            app_module._marketing_fields({}),
            {"source": "direct", "medium": "none", "campaign": "unattributed"},
        )

    def test_marketing_fields_trim_and_bound_campaign_values(self):
        result = app_module._marketing_fields({
            "source": "  newsletter  ",
            "medium": " email ",
            "campaign": " launch-week ",
            "content": "  product-intro ",
            "landing_path": "/" + "x" * 500,
            "email": "not-captured-here@example.invalid",
        })
        self.assertEqual(result["source"], "newsletter")
        self.assertEqual(result["medium"], "email")
        self.assertEqual(result["campaign"], "launch-week")
        self.assertEqual(result["content"], "product-intro")
        self.assertEqual(len(result["landing_path"]), 400)
        self.assertNotIn("email", result)

    def test_marketing_fields_ignore_non_string_values(self):
        result = app_module._marketing_fields({
            "source": ["untrusted"],
            "medium": None,
            "campaign": 123,
        })
        self.assertEqual(result["source"], "direct")
        self.assertEqual(result["medium"], "none")
        self.assertEqual(result["campaign"], "unattributed")


if __name__ == "__main__":
    unittest.main()
