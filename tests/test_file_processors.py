import io
import json
import unittest

import openpyxl

from backend import file_processors as fp


class MultiFormatProcessorTests(unittest.TestCase):
    def test_legacy_csv_cleanup_keeps_header_trimming_and_basic_duplicates(self):
        content = b"Customer Name, Note\n Alice  , hello  \nAlice,hello\n"
        result = fp.process_data_file("sample.csv", content, "tier_1_51")
        self.assertEqual(result["job_type"], "csv_clean")
        self.assertIn("customer_name,note", result["formatted_result"])
        self.assertEqual(result["summary"]["rows_output"], 2)

    def test_scale_json_payload_is_pretty_printed_and_normalized(self):
        payload = b'{"Error Detail":"  failure   happened ", "count":2}'
        result = fp.process_data_file("payload.json", payload, "tier_2_83")
        parsed = json.loads(result["formatted_result"])
        self.assertEqual(parsed["error_detail"], "failure happened")
        self.assertEqual(result["summary"]["anomaly_fields_detected"], 1)

    def test_scale_json_anomaly_filter_keeps_only_error_records(self):
        payload = b'[{"event":"ok"},{"event":"failed","error":"timeout"},{"event":"crash","exception":"ValueError"}]'
        result = fp.process_data_file("events.json", payload, "tier_2_83", "json_filter_anomalies")
        rows = json.loads(result["formatted_result"])
        self.assertEqual(len(rows), 2)
        self.assertEqual(result["summary"]["entries_received"], 3)
        self.assertEqual(result["summary"]["entries_filtered_out"], 1)
        self.assertEqual(result["job_type"], "json_anomaly_filter")

    def test_basic_cannot_use_scale_json_processor(self):
        with self.assertRaisesRegex(ValueError, "Scale tier"):
            fp.process_data_file("payload.json", b'{"x":1}', "tier_1_51")

    def test_log_parser_extracts_error_and_indented_stack_trace(self):
        log = b"2026-10-28T10:00:00Z ERROR: request failed\n  Traceback (most recent call last):\n    ValueError: invalid input\nINFO: worker ready\n"
        result = fp.process_data_file("service.log", log, "tier_2_83")
        entries = json.loads(result["formatted_result"])
        self.assertEqual(result["summary"]["anomaly_count"], 1)
        self.assertIn("ValueError", entries[0]["stack_trace"])
        self.assertEqual(result["summary"]["level_counts"]["INFO"], 1)

    def test_xlsx_sheets_align_headers_across_different_column_orders(self):
        workbook = openpyxl.Workbook()
        first = workbook.active
        first.title = "North"
        first.append(["Customer Name", "Price"])
        first.append([" Alice ", 12])
        second = workbook.create_sheet("South")
        second.append(["Price", "Region", "Customer Name"])
        second.append([10, " West ", "Bob"])
        buffer = io.BytesIO()
        workbook.save(buffer)
        result = fp.process_data_file("multi.xlsx", buffer.getvalue(), "tier_2_83")
        self.assertEqual(result["summary"]["sheet_rows"], {"North": 1, "South": 1})
        rows = list(__import__("csv").reader(io.StringIO(result["formatted_result"])))
        self.assertEqual(rows[0], ["customer_name", "price", "region"])
        self.assertEqual(rows[1], ["Alice", "12", ""])
        self.assertEqual(rows[2], ["Bob", "10", "West"])

    def test_ultimate_catalog_normalizes_prices_inventory_and_duplicate_sku(self):
        content = b"sku,name,unit_price,stock\nA-1, Widget ,$12.5,4\nA-1, Widget Updated ,$15.00,7\nB-2,Gadget,invalid,not-a-number\n"
        result = fp.process_data_file("catalog.csv", content, "tier_3_129", "catalog_normalize")
        rows = list(__import__("csv").reader(io.StringIO(result["formatted_result"])))
        header = rows[0]
        sku_idx, name_idx, price_idx, stock_idx = [header.index(key) for key in ("product_sku", "product_name", "price", "inventory_quantity")]
        self.assertEqual(result["summary"]["duplicate_skus_resolved"], 1)
        self.assertEqual(result["summary"]["invalid_prices"], 1)
        self.assertEqual(rows[1][sku_idx], "A-1")
        self.assertEqual(rows[1][name_idx], "Widget Updated")
        self.assertEqual(rows[1][price_idx], "15.00")
        self.assertEqual(rows[1][stock_idx], "7")

    def test_ultimate_order_export_normalizes_money_phone_address_and_currency(self):
        content = b"shipping_address,phone_number,total,currency\n  12 Main   Street ,+1 (555) 123-4567,$1,200.50,usd\n"
        # Quoting is necessary because the amount contains a comma.
        content = b'shipping_address,phone_number,total,currency\n"  12 Main   Street ",+1 (555) 123-4567,"$1,200.50",usd\n'
        result = fp.process_data_file("orders.csv", content, "tier_3_129", "order_normalize")
        rows = list(__import__("csv").reader(io.StringIO(result["formatted_result"])))
        row = dict(zip(rows[0], rows[1]))
        self.assertEqual(row["address"], "12 Main Street")
        self.assertEqual(row["phone"], "+15551234567")
        self.assertEqual(row["total"], "1200.50")
        self.assertEqual(row["currency"], "USD")

    def test_ultimate_identity_export_validates_and_deduplicates_email(self):
        content = b"email_address,display_name\nAna @example.com,Ana old\nana@example.com,Ana new\nnot-an-email,Invalid\n"
        result = fp.process_data_file("users.csv", content, "tier_3_129", "identity_sanitize")
        rows = list(__import__("csv").reader(io.StringIO(result["formatted_result"])))
        self.assertEqual(result["summary"]["duplicate_identities_resolved"], 1)
        self.assertEqual(result["summary"]["invalid_email_rows"], 1)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1][1], "Ana new")

    def test_tier_row_limits_match_requested_packaging(self):
        basic = "name\n" + "".join(f"row{i}\n" for i in range(2501)).encode().decode()
        with self.assertRaisesRegex(ValueError, "up to 2,500"):
            fp.process_data_file("big.csv", basic.encode(), "tier_1_51")

    def test_invalid_json_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "JSON file is invalid"):
            fp.process_data_file("bad.json", b"{broken", "tier_2_83")


if __name__ == "__main__":
    unittest.main()
