"""Additive file processors. The legacy CSV cleanup path stays in backend.main."""
from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter
from decimal import Decimal, InvalidOperation
from typing import Any

import openpyxl
import xlrd

TIER_RANK = {"free": 0, "tier_1_51": 1, "tier_2_83": 2, "tier_3_129": 3}
TIER_MAX_ROWS = {"free": 100, "tier_1_51": 2500, "tier_2_83": 25000, "tier_3_129": 250000}
SUPPORTED_EXTENSIONS = {".csv", ".xlsx", ".xls", ".json", ".log"}
ULTIMATE_OPERATIONS = {"catalog_normalize", "order_normalize", "identity_sanitize"}
HEADER_ALIASES = {
    "sku": "product_sku", "item_sku": "product_sku", "product_id": "product_sku",
    "title": "product_name", "name": "product_name",
    "unit_price": "price", "retail_price": "price", "price_usd": "price",
    "stock": "inventory_quantity", "stock_quantity": "inventory_quantity",
    "quantity_on_hand": "inventory_quantity", "inventory": "inventory_quantity",
    "e_mail": "email", "email_address": "email", "user_email": "email",
    "phone_number": "phone", "mobile": "phone", "telephone": "phone",
    "shipping_address": "address", "street_address": "address",
}

def _require_tier(tier: str, minimum: int, feature: str) -> None:
    if TIER_RANK.get(tier, -1) < minimum:
        required = "Scale" if minimum == 2 else "Ultimate"
        raise ValueError(f"{feature} is available on the {required} tier and above.")

def _check_row_limit(rows: int, tier: str) -> None:
    limit = TIER_MAX_ROWS.get(tier, TIER_MAX_ROWS["free"])
    if rows > limit:
        label = {"free": "Free", "tier_1_51": "Basic", "tier_2_83": "Scale", "tier_3_129": "Ultimate"}.get(tier, tier)
        raise ValueError(f"{label} supports up to {limit:,} data rows or entries per file.")

def _header(value: Any) -> str:
    text = str(value if value is not None else "").strip().lower()
    text = re.sub(r"\s+", "_", text)
    text = re.sub(r"[^a-z0-9_]+", "_", text)
    return re.sub(r"_+", "_", text).strip("_")

def _clean_scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return re.sub(r"\s+", " ", str(value)).strip()

def _dedupe_and_blank(rows: list[list[str]]) -> tuple[list[list[str]], int, int]:
    kept: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
    blank_removed = duplicate_removed = 0
    for row in rows:
        if not any(str(value).strip() for value in row):
            blank_removed += 1
            continue
        key = tuple(row)
        if key in seen:
            duplicate_removed += 1
            continue
        seen.add(key)
        kept.append(row)
    return kept, blank_removed, duplicate_removed

def _csv_output(headers: list[str], rows: list[list[str]]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(headers)
    writer.writerows(rows)
    return stream.getvalue()

def _table_from_csv(content: bytes) -> tuple[list[str], list[list[str]], dict[str, int]]:
    try:
        text = content.decode("utf-8-sig")
        raw = list(csv.reader(io.StringIO(text)))
    except UnicodeDecodeError as exc:
        raise ValueError("CSV must be UTF-8 encoded.") from exc
    except csv.Error as exc:
        raise ValueError("CSV structure is invalid.") from exc
    if not raw:
        raise ValueError("The CSV file is empty.")
    headers = [_header(v) for v in raw[0]]
    if not any(headers):
        raise ValueError("The CSV must contain a header row.")
    rows: list[list[str]] = []
    for rawrow in raw[1:]:
        row = [_clean_scalar(v) for v in rawrow]
        if len(row) < len(headers):
            row += [""] * (len(headers) - len(row))
        elif len(row) > len(headers):
            extra = len(row) - len(headers)
            headers += [f"extra_column_{i}" for i in range(1, extra + 1)]
            for prior in rows:
                prior.extend([""] * extra)
        rows.append(row)
    return headers, rows, {"csv": len(rows)}

def _table_from_excel(filename: str, content: bytes) -> tuple[list[str], list[list[str]], dict[str, int]]:
    ext = "." + filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    sheet_data: list[tuple[str, list[str], list[list[str]]]] = []
    try:
        if ext == ".xlsx":
            workbook = openpyxl.load_workbook(io.BytesIO(content), read_only=True, data_only=True)
            try:
                for sheet in workbook.worksheets:
                    values = list(sheet.iter_rows(values_only=True))
                    if not values:
                        continue
                    headers = [_header(v) for v in values[0]]
                    rows = [[_clean_scalar(v) for v in row] for row in values[1:]]
                    rows = [row + [""] * max(0, len(headers) - len(row)) for row in rows]
                    rows = [row[:len(headers)] for row in rows]
                    sheet_data.append((sheet.title, headers, rows))
            finally:
                workbook.close()
        elif ext == ".xls":
            workbook = xlrd.open_workbook(file_contents=content, on_demand=True)
            try:
                for sheet in workbook.sheets():
                    if sheet.nrows == 0:
                        continue
                    headers = [_header(sheet.cell_value(0, col)) for col in range(sheet.ncols)]
                    rows = [[_clean_scalar(sheet.cell_value(r, col)) for col in range(sheet.ncols)]
                            for r in range(1, sheet.nrows)]
                    sheet_data.append((sheet.name, headers, rows))
            finally:
                workbook.release_resources()
        else:
            raise ValueError("Unsupported workbook extension.")
    except (openpyxl.utils.exceptions.InvalidFileException, xlrd.XLRDError, OSError) as exc:
        raise ValueError("Workbook could not be parsed. Check that the file is a valid .xlsx or .xls workbook.") from exc
    if not sheet_data:
        raise ValueError("Workbook contains no non-empty worksheets.")
    aligned_headers: list[str] = []
    for _, headers, _ in sheet_data:
        for header in headers:
            if header and header not in aligned_headers:
                aligned_headers.append(header)
    if not aligned_headers:
        raise ValueError("Workbook worksheets must contain header rows.")
    aligned_rows: list[list[str]] = []
    counts: dict[str, int] = {}
    for sheet_name, headers, rows in sheet_data:
        counts[sheet_name] = len(rows)
        positions = {header: index for index, header in enumerate(headers) if header}
        for row in rows:
            aligned_rows.append([row[positions[h]] if h in positions and positions[h] < len(row) else ""
                                 for h in aligned_headers])
    return aligned_headers, aligned_rows, counts

def _normalize_table_headers(headers: list[str], rows: list[list[str]]) -> tuple[list[str], list[list[str]]]:
    renamed = [HEADER_ALIASES.get(h, h) for h in headers]
    out = [row + [""] * max(0, len(headers) - len(row)) for row in rows]
    return renamed, [row[:len(headers)] for row in out]

def _money(value: str) -> tuple[str, bool]:
    cleaned = re.sub(r"[$€£¥,\s]", "", value or "")
    cleaned = re.sub(r"(?i)(usd|eur|gbp|kes|ksh)", "", cleaned)
    if not cleaned:
        return "", True
    try:
        amount = Decimal(cleaned)
        if not amount.is_finite():
            return "", False
        return f"{amount:.2f}", True
    except InvalidOperation:
        return value.strip(), False

def _normalize_catalog(headers: list[str], rows: list[list[str]], tier: str, sheet_counts: dict[str, int]) -> dict[str, Any]:
    _require_tier(tier, 3, "Merchant catalog normalization")
    headers, rows = _normalize_table_headers(headers, rows)
    for needed in ("product_sku", "product_name", "price", "inventory_quantity"):
        if needed not in headers:
            headers.append(needed)
            for row in rows:
                row.append("")
    pos = {h: i for i, h in enumerate(headers)}
    invalid_price = invalid_inventory = duplicate_skus = 0
    normalized: list[list[str]] = []
    for raw in rows:
        row = raw + [""] * max(0, len(headers) - len(raw))
        row = row[:len(headers)]
        row[pos["product_sku"]] = _clean_scalar(row[pos["product_sku"]])
        row[pos["product_name"]] = _clean_scalar(row[pos["product_name"]])
        price, valid_price = _money(row[pos["price"]])
        row[pos["price"]] = price
        invalid_price += 0 if valid_price else 1
        inventory = re.sub(r"[,\s]", "", row[pos["inventory_quantity"]])
        try:
            quantity = int(Decimal(inventory)) if inventory else 0
            if quantity < 0:
                raise ValueError
            row[pos["inventory_quantity"]] = str(quantity)
        except (InvalidOperation, ValueError):
            invalid_inventory += 1
            row[pos["inventory_quantity"]] = ""
        normalized.append(row)
    sku_idx = pos["product_sku"]
    last_by_sku: dict[str, list[str]] = {}
    without_sku: list[list[str]] = []
    for row in normalized:
        sku = row[sku_idx].casefold()
        if sku:
            duplicate_skus += 1 if sku in last_by_sku else 0
            last_by_sku[sku] = row
        else:
            without_sku.append(row)
    if duplicate_skus:
        normalized = without_sku + list(last_by_sku.values())
    _check_row_limit(len(rows), tier)
    summary = {
        "operation": "catalog_normalize", "rows_received": len(rows), "rows_output": len(normalized),
        "columns": len(headers), "duplicate_skus_resolved": duplicate_skus,
        "invalid_prices": invalid_price, "invalid_inventory_values": invalid_inventory,
        "sheet_rows": sheet_counts, "sync_status": "normalized_export_ready",
        "note": "This prepares a catalog export for synchronization. No external commerce platform is modified by this file-only operation.",
    }
    summary["quality_flags"] = ([f"{invalid_price} row(s) had unparseable prices"] if invalid_price else []) + ([f"{invalid_inventory} row(s) had invalid inventory values"] if invalid_inventory else [])
    return {"job_type": "merchant_catalog_normalize", "output_format": "csv", "rows_cleaned": len(normalized), "formatted_result": _csv_output(headers, normalized), "summary": summary}

def _normalize_orders(headers: list[str], rows: list[list[str]], tier: str, sheet_counts: dict[str, int]) -> dict[str, Any]:
    _require_tier(tier, 3, "E-commerce order normalization")
    headers, rows = _normalize_table_headers(headers, rows)
    money_headers = {h for h in headers if h in {"price", "unit_price", "amount", "subtotal", "tax", "shipping", "shipping_cost", "total", "order_total", "discount"} or h.endswith("_amount") or h.endswith("_price")}
    addr_headers = {h for h in headers if "address" in h or h in {"city", "state", "province", "postal_code", "country"}}
    phone_headers = {h for h in headers if "phone" in h or h in {"mobile", "telephone"}}
    currency_headers = {h for h in headers if h in {"currency", "currency_code"}}
    pos = {h: i for i, h in enumerate(headers)}
    invalid_money = 0
    normalized: list[list[str]] = []
    for raw in rows:
        row = raw + [""] * max(0, len(headers) - len(raw))
        row = row[:len(headers)]
        for header in addr_headers:
            row[pos[header]] = re.sub(r"\s+", " ", row[pos[header]]).strip()
        for header in phone_headers:
            raw_phone = row[pos[header]].strip()
            prefix = "+" if raw_phone.startswith("+") or raw_phone.startswith("00") else ""
            digits = re.sub(r"\D", "", raw_phone)
            if prefix == "+" and digits.startswith("00"):
                digits = digits[2:]
            row[pos[header]] = (("+" if prefix else "") + digits) if digits else ""
        for header in money_headers:
            value, valid = _money(row[pos[header]])
            row[pos[header]] = value
            invalid_money += 0 if valid else 1
        for header in currency_headers:
            row[pos[header]] = row[pos[header]].strip().upper()
        normalized.append(row)
    _check_row_limit(len(normalized), tier)
    summary = {
        "operation": "order_normalize", "rows_received": len(rows), "rows_output": len(normalized),
        "columns": len(headers), "monetary_fields_normalized": sorted(money_headers),
        "address_fields_scrubbed": sorted(addr_headers), "phone_fields_normalized": sorted(phone_headers),
        "invalid_monetary_values": invalid_money, "sheet_rows": sheet_counts,
    }
    summary["quality_flags"] = [f"{invalid_money} monetary value(s) could not be parsed"] if invalid_money else []
    return {"job_type": "ecommerce_order_normalize", "output_format": "csv", "rows_cleaned": len(normalized), "formatted_result": _csv_output(headers, normalized), "summary": summary}

def _sanitize_identities(headers: list[str], rows: list[list[str]], tier: str, sheet_counts: dict[str, int]) -> dict[str, Any]:
    _require_tier(tier, 3, "User export sanitization")
    headers, rows = _normalize_table_headers(headers, rows)
    if "email" not in headers:
        raise ValueError("Identity sanitization requires an email, email_address, or user_email column.")
    email_idx = headers.index("email")
    email_re = re.compile(r"^[A-Z0-9.!#$%&'*+/=?^_{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$", re.I)
    valid_by_email: dict[str, list[str]] = {}
    invalid_rows: list[list[str]] = []
    duplicate_count = 0
    for raw in rows:
        row = raw + [""] * max(0, len(headers) - len(raw))
        row = row[:len(headers)]
        email = re.sub(r"\s+", "", row[email_idx]).lower()
        row[email_idx] = email
        if not email_re.match(email):
            invalid_rows.append(row)
            continue
        if email in valid_by_email:
            duplicate_count += 1
        valid_by_email[email] = row
    clean_rows = list(valid_by_email.values())
    _check_row_limit(len(rows), tier)
    summary = {
        "operation": "identity_sanitize", "rows_received": len(rows), "rows_output": len(clean_rows),
        "valid_unique_emails": len(clean_rows), "invalid_email_rows": len(invalid_rows),
        "duplicate_identities_resolved": duplicate_count, "sheet_rows": sheet_counts,
        "note": "For duplicate valid emails the last encountered row is retained. Invalid-email rows are excluded from the cleaned export and counted in the report.",
    }
    summary["quality_flags"] = ([f"{len(invalid_rows)} row(s) contained invalid email addresses"] if invalid_rows else [])
    return {"job_type": "identity_export_sanitize", "output_format": "csv", "rows_cleaned": len(clean_rows), "formatted_result": _csv_output(headers, clean_rows), "summary": summary}

def _infer_types(value: Any) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    examples: dict[str, Any] = {}
    def walk(item: Any, path: str = "$") -> None:
        typ = "object" if isinstance(item, dict) else "array" if isinstance(item, list) else "null" if item is None else "boolean" if isinstance(item, bool) else "number" if isinstance(item, (int, float)) else "string"
        counts[typ] += 1
        examples.setdefault(path, {"type": typ, "sample": item if typ not in {"object", "array"} else None})
        if isinstance(item, dict):
            for key, child in item.items():
                walk(child, path + "." + str(key))
        elif isinstance(item, list):
            for index, child in enumerate(item[:25]):
                walk(child, path + f"[{index}]")
    walk(value)
    return {"node_type_counts": dict(counts), "paths": examples}

def _parse_json(content: bytes, tier: str) -> dict[str, Any]:
    _require_tier(tier, 2, "JSON payload formatting")
    try:
        root = json.loads(content.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("JSON file is invalid or is not UTF-8 encoded.") from exc
    def clean(value: Any) -> Any:
        if isinstance(value, dict):
            return {_header(key): clean(child) for key, child in value.items()}
        if isinstance(value, list):
            return [clean(child) for child in value]
        if isinstance(value, str):
            return re.sub(r"[ \t]+", " ", value).strip()
        return value
    cleaned = clean(root)
    entries = len(cleaned) if isinstance(cleaned, list) else 1
    _check_row_limit(entries, tier)
    anomaly_keys = 0
    def scan(value: Any) -> None:
        nonlocal anomaly_keys
        if isinstance(value, dict):
            for key, child in value.items():
                if re.search(r"(error|exception|stack.?trace|fatal)", key, re.I) and child not in (None, "", [], {}):
                    anomaly_keys += 1
                scan(child)
        elif isinstance(value, list):
            for child in value:
                scan(child)
    scan(cleaned)
    summary: dict[str, Any] = {"operation": "json_clean", "entries_processed": entries, "anomaly_fields_detected": anomaly_keys}
    if TIER_RANK.get(tier, 0) >= 3:
        summary["type_summary"] = _infer_types(cleaned)
        summary["quality_flags"] = [f"{anomaly_keys} error/exception/stack-trace field(s) detected"] if anomaly_keys else []
    return {"job_type": "json_payload_clean", "output_format": "json", "rows_cleaned": entries,
            "formatted_result": json.dumps(cleaned, ensure_ascii=False, indent=2), "summary": summary}

def _parse_log(content: bytes, tier: str) -> dict[str, Any]:
    _require_tier(tier, 2, "Server log parsing")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Log files must be UTF-8 encoded.") from exc
    raw_lines = text.splitlines()
    _check_row_limit(len(raw_lines), tier)
    pattern = re.compile(r"^\s*(?:(?P<timestamp>\d{4}-\d{2}-\d{2}[T ][0-9:.+\-Z]+)\s+)?(?:\[(?P<bracketlevel>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)\]|(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL))\s*[:\-]?\s*(?P<message>.*)$", re.I)
    entries: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw_lines, start=1):
        match = pattern.match(line)
        if match:
            level = (match.group("bracketlevel") or match.group("level") or "INFO").upper()
            if level == "WARNING":
                level = "WARN"
            entries.append({"line": line_number, "timestamp": match.group("timestamp"), "level": level, "message": match.group("message").strip(), "stack_trace": ""})
        elif line[:1].isspace() and entries and (line.lstrip().startswith(("at ", "File ", "Traceback", "Caused by:", "...")) or re.search(r"\bException\b|\bError\b", line)):
            entries[-1]["stack_trace"] = (entries[-1]["stack_trace"] + "\n" + line.rstrip()).strip()
        else:
            entries.append({"line": line_number, "timestamp": None, "level": "INFO", "message": line.strip(), "stack_trace": ""})
    _check_row_limit(len(entries), tier)
    errors = [entry for entry in entries if entry["level"] in {"ERROR", "CRITICAL", "FATAL"} or re.search(r"\b(exception|traceback|fatal error)\b", entry["message"], re.I)]
    for entry in errors:
        entry["anomaly_type"] = "exception_or_error"
    summary: dict[str, Any] = {
        "operation": "log_analyze", "lines_processed": len(raw_lines), "entries_parsed": len(entries),
        "level_counts": dict(Counter(entry["level"] for entry in entries)), "anomaly_count": len(errors),
        "anomalies": [{"line": item["line"], "level": item["level"], "message": item["message"], "stack_trace": item["stack_trace"]} for item in errors[:100]],
    }
    if TIER_RANK.get(tier, 0) >= 3:
        summary["quality_flags"] = [f"{len(errors)} error/exception anomaly record(s) found"] if errors else []
    return {"job_type": "server_log_analyze", "output_format": "json", "rows_cleaned": len(entries),
            "formatted_result": json.dumps(entries, ensure_ascii=False, indent=2), "summary": summary}

def process_data_file(filename: str, content: bytes, tier: str, operation: str = "auto") -> dict[str, Any]:
    """Dispatch an uploaded file to a tier-gated processor and return a storable report."""
    ext = "." + filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if ext not in SUPPORTED_EXTENSIONS:
        raise ValueError("Supported file types: .csv, .xlsx, .xls, .json, and .log.")
    allowed_ops = {"auto", "csv_clean", "excel_consolidate", "json_clean", "log_analyze", "catalog_normalize", "order_normalize", "identity_sanitize"}
    if operation not in allowed_ops:
        raise ValueError("Unknown processing operation.")
    if ext == ".json":
        if operation not in {"auto", "json_clean"}:
            raise ValueError("Choose JSON payload formatting for .json files.")
        return _parse_json(content, tier)
    if ext == ".log":
        if operation not in {"auto", "log_analyze"}:
            raise ValueError("Choose server log analysis for .log files.")
        return _parse_log(content, tier)
    if ext == ".csv":
        headers, rows, sheets = _table_from_csv(content)
    elif ext in {".xlsx", ".xls"}:
        _require_tier(tier, 2, "Excel workbook processing")
        if operation not in {"auto", "excel_consolidate", "catalog_normalize", "order_normalize", "identity_sanitize"}:
            raise ValueError("Selected operation is not supported for workbook files.")
        headers, rows, sheets = _table_from_excel(filename, content)
    else:
        raise ValueError("This format is not supported by the selected processor.")
    _check_row_limit(len(rows), tier)
    if operation == "catalog_normalize":
        return _normalize_catalog(headers, rows, tier, sheets)
    if operation == "order_normalize":
        return _normalize_orders(headers, rows, tier, sheets)
    if operation == "identity_sanitize":
        return _sanitize_identities(headers, rows, tier, sheets)
    if operation not in {"auto", "csv_clean", "excel_consolidate"}:
        raise ValueError("Selected operation is not supported for tabular files.")
    if ext in {".xlsx", ".xls"}:
        _require_tier(tier, 2, "Excel consolidation")
    blank_removed = duplicate_removed = 0
    if TIER_RANK.get(tier, 0) >= 2:
        rows, blank_removed, duplicate_removed = _dedupe_and_blank(rows)
    summary: dict[str, Any] = {
        "operation": "excel_consolidate" if ext in {".xlsx", ".xls"} else "csv_clean",
        "rows_received": sum(sheets.values()) if ext in {".xlsx", ".xls"} else len(rows),
        "rows_output": len(rows), "columns": len(headers), "sheet_rows": sheets,
        "blank_rows_removed": blank_removed, "duplicate_rows_removed": duplicate_removed,
        "missing_values_by_column": {header: sum(not row[i].strip() for row in rows) for i, header in enumerate(headers)} if TIER_RANK.get(tier, 0) >= 2 else {},
    }
    if TIER_RANK.get(tier, 0) >= 3:
        summary["type_summary"] = _infer_types([{h: row[i] if i < len(row) else "" for i, h in enumerate(headers)} for row in rows])
        summary["quality_flags"] = [f"{h}: missing values found" for h, count in summary["missing_values_by_column"].items() if count]
    return {"job_type": "excel_consolidate" if ext in {".xlsx", ".xls"} else "csv_clean",
            "output_format": "csv", "rows_cleaned": len(rows), "formatted_result": _csv_output(headers, rows), "summary": summary}
