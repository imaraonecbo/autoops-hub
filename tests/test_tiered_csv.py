import unittest
import csv

import backend.main as app_module


class TieredCsvTests(unittest.TestCase):
    SAMPLE = "Customer Name,Age,Note\n Alice ,30, hello \nBob,25,\nBob,25,\n,,\n"

    def test_basic_normalizes_headers_and_whitespace_without_deduplication(self):
        result = app_module.clean_csv_content(self.SAMPLE, "tier_1_51")
        self.assertIn("customer_name,age,note", result["formatted_result"])
        self.assertEqual(result["summary"]["plan"], "Basic")
        self.assertEqual(result["summary"]["rows_output"], 4)
        self.assertEqual(result["summary"]["missing_values_by_column"], {})

    def test_scale_removes_blank_and_duplicate_rows_and_reports_missing_values(self):
        result = app_module.clean_csv_content(self.SAMPLE, "tier_2_83")
        self.assertEqual(result["summary"]["blank_rows_removed"], 1)
        self.assertEqual(result["summary"]["duplicate_rows_removed"], 1)
        self.assertEqual(result["summary"]["rows_output"], 2)
        self.assertIn("age", result["summary"]["missing_values_by_column"])

    def test_ultimate_adds_column_quality_and_quality_flags(self):
        result = app_module.clean_csv_content(self.SAMPLE, "tier_3_129")
        summary = result["summary"]
        self.assertEqual(summary["plan"], "Ultimate")
        self.assertEqual(summary["column_quality"][0]["inferred_type"], "text")
        self.assertTrue(any("note" in flag for flag in summary["quality_flags"]))

    def test_row_limit_is_enforced_per_tier(self):
        rows = "name\n" + "".join(f"person{i}\n" for i in range(1001))
        with self.assertRaisesRegex(ValueError, "up to 1,000"):
            app_module.clean_csv_content(rows, "tier_1_51")

    def test_empty_csv_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "empty"):
            app_module.clean_csv_content("", "tier_1_51")

    def test_unknown_tier_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unknown access tier"):
            app_module.clean_csv_content("name\nAlice\n", "tier_unknown")


if __name__ == "__main__":
    unittest.main()
