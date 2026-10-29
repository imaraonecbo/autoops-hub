#!/usr/bin/env python3
"""Free-first AutoOps Hub growth and availability audit. No customer data or secrets are collected."""
from __future__ import annotations

import os
import sys
import time
import json
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

SITE = os.getenv("PUBLIC_SITE_URL", "https://autoops-hub-public.onrender.com").rstrip("/")
APP = os.getenv("PUBLIC_APP_URL", "https://autoops-hub-production.onrender.com").rstrip("/")
PATHS = [
    "/",
    "/csv-cleanup.html",
    "/excel-file-reporting.html",
    "/json-log-processing.html",
    "/robots.txt",
    "/sitemap.xml",
]
failures: list[str] = []
summary: list[str] = []

def fetch(url: str) -> tuple[int, str]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "AutoOpsHub-GrowthAudit/1.0 (+https://github.com/imaraonecbo/autoops-hub)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, response.read(2_000_000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(1000).decode("utf-8", errors="replace")
    except Exception as exc:
        return 0, str(exc)

for path in PATHS:
    code, body = fetch(SITE + path)
    ok = code == 200
    summary.append(f"- {'PASS' if ok else 'FAIL'} {SITE + path} — HTTP {code}")
    if not ok:
        failures.append(f"{path}: HTTP {code}")
    if path.endswith(".html") and ok:
        if "<title>" not in body.lower():
            failures.append(f"{path}: missing title element")
        if 'name="description"' not in body.lower():
            failures.append(f"{path}: missing meta description")
        if 'rel="canonical"' not in body.lower():
            failures.append(f"{path}: missing canonical URL")
    if path == "/robots.txt" and ok and "/sitemap.xml" not in body:
        failures.append("robots.txt does not reference sitemap.xml")
    if path == "/sitemap.xml" and ok:
        try:
            root = ET.fromstring(body)
            locs = [el.text or "" for el in root.iter() if el.tag.endswith("loc")]
            if not locs:
                failures.append("sitemap.xml contains no loc entries")
            for loc in locs:
                if not loc.startswith(SITE + "/") and loc != SITE + "/":
                    failures.append(f"sitemap contains unexpected host: {loc}")
        except ET.ParseError:
            failures.append("sitemap.xml is not valid XML")

health_url = APP + "/api/v1/health"
code, body = fetch(health_url)
summary.append(f"- {'PASS' if code == 200 else 'FAIL'} {health_url} — HTTP {code}")
if code != 200:
    failures.append(f"application health endpoint: HTTP {code}")

print("# AutoOps Hub weekly growth and availability audit\n")
print("## Public checks")
print("\n".join(summary))
print("\n## Result")
if failures:
    print(f"FAIL — {len(failures)} issue(s) need review.")
    for item in failures:
        print(f"- {item}")
    sys.exit(1)
print("PASS — landing pages, crawler files, sitemap and application health responded as expected.")
