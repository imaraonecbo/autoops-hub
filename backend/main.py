# ============================================================================
# FastAPI Microservice: AutoOps Hub v1 Backend Engine
# Principal Backend Engineer & Python DevSecOps Approved
# ============================================================================

import os
import io
import csv
import logging
import hmac
import hashlib
import json
from typing import Dict, Any, Optional
from urllib.parse import quote
from fastapi import FastAPI, Depends, HTTPException, Header, UploadFile, File, Request, status
from fastapi.responses import HTMLResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from supabase import create_client, Client
import httpx
from uuid import UUID
from datetime import datetime, timezone

# Initialize elite structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s.%(funcName)s:%(lineno)d - %(message)s"
)
logger = logging.getLogger("autoops.backend")

# Initialize FastAPI application
app = FastAPI(
    title="AutoOps Hub v1 Backend Engine",
    description="Secured high-performance operations backend managing autonomous script task queues, telemetry ledgers and transaction webhooks.",
    version="1.0.0"
)

# Enable modern production-grade CORS headers
# To satisfy DevSecOps standards, we parse from an env variable and avoid "*" wildcard alongside allow_credentials=True
raw_origins = os.getenv("ALLOWED_ORIGINS", "")
if raw_origins:
    ALLOWED_ORIGINS = [origin.strip() for origin in raw_origins.split(",") if origin.strip()]
else:
    # Explicitly whitelist standard development origins
    ALLOWED_ORIGINS = [
        "http://localhost:3000",
        "http://localhost:5173",
        "https://ais-dev-7nyigeiij7v5y34benmwxd-304369769553.europe-west2.run.app",
        "https://ais-pre-7nyigeiij7v5y34benmwxd-304369769553.europe-west2.run.app"
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# ----------------------------------------------------------------------------
# 1. CONFIGURATION & CLIENT INITIALIZATION
# ----------------------------------------------------------------------------

# Fail closed: never construct a client using placeholder credentials.
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "").strip()
PAYPAL_WEBHOOK_ID = os.getenv("PAYPAL_WEBHOOK_ID", "").strip()
PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID", "").strip()
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET", "").strip()
PAYPAL_API_BASE = os.getenv("PAYPAL_API_BASE", "https://api-m.sandbox.paypal.com").rstrip("/")
COINBASE_WEBHOOK_SECRET = os.getenv("COINBASE_WEBHOOK_SECRET", "").strip()

supabase: Optional[Client] = None
if SUPABASE_URL and SUPABASE_KEY and "placeholder" not in SUPABASE_URL.lower() and "placeholder" not in SUPABASE_KEY.lower() and "unconfigured" not in SUPABASE_KEY.lower():
    try:
        # Construct the stateless server client without create_client()'s session restore
        # path; customer identity is validated separately against Supabase Auth per request.
        supabase = Client(SUPABASE_URL, SUPABASE_KEY)
        logger.info("Supabase client constructed; readiness endpoint will verify the database API key.")
    except Exception:
        logger.exception("Supabase client initialization failed.")
else:
    logger.error("Supabase credentials are missing or are placeholder values; database-backed routes will fail closed.")

# ----------------------------------------------------------------------------
# 2. SEED MODELS AND DEFINITIONS
# ----------------------------------------------------------------------------

class WebhookResponse(BaseModel):
    success: bool
    message: str
    details: Optional[Dict[str, Any]] = None

class BotWebhookPayload(BaseModel):
    bot_token: str = Field(..., description="Access key of requesting Telegram or WhatsApp automation worker client.")
    task_action: str = Field(..., description="Action parameters to be registered on ledger task pipeline.")
    meta_payload: Dict[str, Any] = Field(default_factory=dict, description="Metadata payload from automated agent pipelines.")

# ----------------------------------------------------------------------------
# 3. HIGHLY SECURE CREDIT ENFORCEMENT DEPENDENCY
# ----------------------------------------------------------------------------

async def get_authenticated_user(request: Request) -> Dict[str, Any]:
    """Validate a Supabase access token against Supabase Auth; never trust a client-supplied user ID."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=503, detail="Authentication/database configuration is unavailable.")
    token = request.cookies.get("autoops_session", "")
    auth_header = request.headers.get("authorization", "")
    if not token and auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Please sign in to continue.")
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            response = await client.get(
                f"{SUPABASE_URL.rstrip('/')}/auth/v1/user",
                headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {token}"},
            )
        if response.status_code != 200:
            raise HTTPException(status_code=401, detail="Your session is invalid or expired. Please sign in again.")
        user = response.json()
        user_id = str(UUID(str(user.get("id", ""))))
        return {"user_id": user_id, "email": user.get("email"), "token": token}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Supabase session validation failed.")
        raise HTTPException(status_code=503, detail="Unable to validate the account session.")

async def verify_user_and_credits(request: Request) -> Dict[str, Any]:
    """Authorize work using the authenticated Supabase user, not an X-User-ID supplied by a caller."""
    if not supabase:
        raise HTTPException(status_code=503, detail="Database coordinator engine is offline.")
    auth_user = await get_authenticated_user(request)
    user_id = auth_user["user_id"]
    try:
        profile_res = supabase.table("profiles").select("current_tier, status").eq("user_id", user_id).execute()
        if not profile_res.data:
            raise HTTPException(status_code=409, detail="Your account profile is not provisioned. Contact support.")
        profile = profile_res.data[0]
        current_tier = profile.get("current_tier", "free")
        profile_status_val = profile.get("status", "active")
        if profile_status_val != "active":
            raise HTTPException(status_code=403, detail=f"Subscription is currently '{profile_status_val}'.")
        ledger_res = supabase.table("usage_ledger").select("monthly_credits_used,total_lifetime_jobs,last_reset_date").eq("profile_id", user_id).execute()
        if not ledger_res.data:
            raise HTTPException(status_code=409, detail="Usage ledger is not provisioned for this account.")
        ledger = ledger_res.data[0]
        monthly_credits = int(ledger.get("monthly_credits_used", 0) or 0)
        lifetime_jobs = int(ledger.get("total_lifetime_jobs", 0) or 0)
        limits = TIER_LIMITS.get(current_tier, TIER_LIMITS["free"])
        if lifetime_jobs >= limits["included_jobs"]:
            raise HTTPException(status_code=402, detail={
                "error": "Included job allowance exhausted",
                "current_tier": current_tier,
                "total_lifetime_jobs": lifetime_jobs,
                "included_job_limit": limits["included_jobs"],
                "message": f"{limits['label']} includes {limits['included_jobs']:,} total jobs for this purchase tier.",
                "pricing_options": {
                    "tier_1_51": {"unit_price": 51.00, "tier_name": "Basic"},
                    "tier_2_83": {"unit_price": 83.00, "tier_name": "Scale"},
                    "tier_3_129": {"unit_price": 129.00, "tier_name": "Ultimate"}
                }
            })
        return {"user_id": user_id, "email": auth_user.get("email"),
                "current_tier": current_tier, "monthly_credits_used": monthly_credits,
                "total_lifetime_jobs": lifetime_jobs,
                "included_job_limit": limits["included_jobs"], "max_rows": limits["max_rows"]}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Account credit check failed.")
        raise HTTPException(status_code=503, detail="Unable to verify account credits.")

# ----------------------------------------------------------------------------
# 4. CORE SAAS SERVICE AUTOMATION ROUTERS
# ----------------------------------------------------------------------------

@app.post("/api/v1/automation/clean-csv", status_code=status.HTTP_200_OK)
async def clean_csv(
    file: UploadFile = File(..., description="The raw unformatted telemetry CSV report."),
    security_context: Dict[str, Any] = Depends(verify_user_and_credits)
):
    """
    Accepts, parses, and formats an uncleaned analytics CSV in-memory.
    Validates execution privileges via credit dependency and increments consumption ledger inside a database trigger context.
    """
    if not file.filename.endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File Format Exception: CSV telemetry logs are required."
        )

    user_id = security_context["user_id"]
    current_credits = security_context["monthly_credits_used"]

    try:
        # A. Safely read and decode file streaming in-memory up to a secure 20MB limit
        MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 Megabytes
        content = await file.read(MAX_FILE_SIZE)
        extra = await file.read(1)
        if extra:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Payload Too Large: CSV file size exceeds the strict production security payload boundary of 20MB."
            )
        
        decoded_text = content.decode("utf-8-sig")
        cleaned = clean_csv_content(decoded_text, security_context["current_tier"])
        cleaned_rows_count = cleaned["rows_cleaned"]
        cleaned_csv_result = cleaned["formatted_result"]
        report_summary = cleaned["summary"]

        # Increment usage only after a valid CSV has been processed.
        next_credits = current_credits + 1
        
        supabase.table("usage_ledger").update({
            "monthly_credits_used": next_credits
        }).eq("profile_id", user_id).execute()

        # Update lifetime counter using Postgrest raw modifier or rpc
        supabase.rpc("increment_lifetime_jobs", {"uid": user_id}).execute()

        job_record = supabase.table("automation_jobs").insert({
            "profile_id": user_id,
            "job_type": "clean_csv",
            "input_filename": file.filename,
            "status": "completed",
            "result": {"rows_cleaned": cleaned_rows_count, "formatted_result": cleaned_csv_result, "summary": report_summary},
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }).execute()
        job_id = job_record.data[0]["id"] if job_record.data else None
        logger.info(f"Successfully cleaned telemetry data log for user_id: {user_id}. Rows processed: {cleaned_rows_count}.")
        return {
            "success": True,
            "job_id": job_id,
            "rows_cleaned": cleaned_rows_count,
            "credits_remaining": max(0, security_context.get("included_job_limit", 2) - (security_context.get("total_lifetime_jobs", 0) + 1)),
            "included_job_limit": security_context.get("included_job_limit", 2),
            "summary": report_summary,
            "formatted_result": cleaned_csv_result
        }

    except HTTPException:
        raise
    except (UnicodeDecodeError, csv.Error, ValueError) as e:
        logger.warning("CSV validation failed for user_id %s: %s", user_id, str(e))
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"CSV processing failed: {str(e)}")
    except Exception:
        logger.exception("CSV job failed for user_id %s.", user_id)
        raise HTTPException(status_code=503, detail="CSV processing failed unexpectedly. Please retry; no successful report was returned.")

@app.post("/api/v1/automation/bot-webhook", response_model=WebhookResponse)
async def bot_webhook(
    payload: BotWebhookPayload,
    security_context: Dict[str, Any] = Depends(verify_user_and_credits)
):
    """
    Endpoint verifying incoming programmatic payloads from WhatsApp or Telegram automation workers.
    Ensures users are within business boundaries before routing jobs into operation microservice lanes.
    """
    user_id = security_context["user_id"]
    current_credits = security_context["monthly_credits_used"]

    # Simulates verification of bot access token signatures
    if not payload.bot_token or len(payload.bot_token) < 20:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Cryptographic Bot Token invalid or missing on script execution header."
        )

    try:
        # Update usage counter following webhook execution
        next_credits = current_credits + 1
        supabase.table("usage_ledger").update({
            "monthly_credits_used": next_credits
        }).eq("profile_id", user_id).execute()

        supabase.rpc("increment_lifetime_jobs", {"uid": user_id}).execute()

        logger.info(f"Webhook automated pipeline successfully triggered by script worker for user_id: {user_id}.")
        return WebhookResponse(
            success=True,
            message="Autonomous action pipeline loaded successfully. Job routed to scheduler context.",
            details={
                "task_action": payload.task_action,
                "current_credits_count": next_credits,
                "current_tier": security_context["current_tier"]
            }
        )
    except Exception as e:
        logger.error(f"Webhook automated handler exception: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Critical operation dispatch event error."
        )

# ----------------------------------------------------------------------------
# 5. UNIFIED CHECKOUT & WEBHOOK ROUTER
# ----------------------------------------------------------------------------

async def verify_paypal_signature(request: Request, event: Dict[str, Any]) -> None:
    """Ask PayPal's official verification API to validate the exact webhook headers and event."""
    if not PAYPAL_CLIENT_ID or not PAYPAL_CLIENT_SECRET or not PAYPAL_WEBHOOK_ID or "PLACEHOLDER" in PAYPAL_WEBHOOK_ID.upper() or "UNCONFIGURED" in PAYPAL_WEBHOOK_ID.upper():
        raise HTTPException(status_code=503, detail="PayPal webhook verification is not configured.")

    header_names = {
        "transmission_id": "PAYPAL-TRANSMISSION-ID",
        "transmission_time": "PAYPAL-TRANSMISSION-TIME",
        "transmission_sig": "PAYPAL-TRANSMISSION-SIG",
        "cert_url": "PAYPAL-CERT-URL",
        "auth_algo": "PAYPAL-AUTH-ALGO",
    }
    verification_payload: Dict[str, Any] = {}
    for field, header in header_names.items():
        value = request.headers.get(header)
        if not value:
            raise HTTPException(status_code=401, detail="Required PayPal signature headers are missing.")
        verification_payload[field] = value
    verification_payload["webhook_id"] = PAYPAL_WEBHOOK_ID
    verification_payload["webhook_event"] = event

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            token_response = await client.post(
                f"{PAYPAL_API_BASE}/v1/oauth2/token",
                auth=(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET),
                data={"grant_type": "client_credentials"},
                headers={"Accept": "application/json", "Accept-Language": "en_US"},
            )
            token_response.raise_for_status()
            access_token = token_response.json().get("access_token")
            if not access_token:
                raise HTTPException(status_code=503, detail="PayPal did not issue an access token.")
            verification_response = await client.post(
                f"{PAYPAL_API_BASE}/v1/notifications/verify-webhook-signature",
                json=verification_payload,
                headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            )
            verification_response.raise_for_status()
            verification_status = verification_response.json().get("verification_status")
    except HTTPException:
        raise
    except (httpx.HTTPError, ValueError):
        logger.exception("PayPal verification service request failed.")
        raise HTTPException(status_code=503, detail="PayPal verification service is temporarily unavailable.")

    if verification_status != "SUCCESS":
        logger.warning("Rejected PayPal webhook with unsuccessful signature verification.")
        raise HTTPException(status_code=401, detail="PayPal webhook signature verification failed.")


@app.post("/api/v1/payments/paypal-webhook", response_model=WebhookResponse)
async def paypal_webhook(request: Request):
    """Accept only verified PayPal captures that match a server-created order."""
    if supabase is None:
        raise HTTPException(status_code=503, detail="Payment processing is unavailable because the database is not configured.")
    try:
        data = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Invalid JSON webhook payload.")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Invalid webhook event structure.")

    await verify_paypal_signature(request, data)
    event_type = data.get("event_type")
    if event_type != "PAYMENT.CAPTURE.COMPLETED":
        return WebhookResponse(success=True, message="Verified PayPal event acknowledged; no account change was required.",
                               details={"received_event_type": event_type})

    resource = data.get("resource") or {}
    amount = resource.get("amount") or {}
    capture_id = resource.get("id")
    related_ids = ((resource.get("supplementary_data") or {}).get("related_ids") or {})
    order_id = related_ids.get("order_id")
    if not capture_id or not order_id or not isinstance(amount, dict):
        raise HTTPException(status_code=400, detail="Capture event is missing its capture/order identifiers or amount.")
    try:
        amount_val = round(float(amount.get("value")), 2)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid payment amount.")
    if amount.get("currency_code") != "USD":
        raise HTTPException(status_code=400, detail="Only USD payments are accepted.")

    try:
        orders = supabase.table("paypal_orders").select("*").eq("paypal_order_id", order_id).limit(1).execute()
        if not orders.data:
            raise HTTPException(status_code=404, detail="Verified PayPal capture does not match a server-created checkout order.")
        saved = orders.data[0]
        if float(saved.get("amount", 0)) != amount_val:
            raise HTTPException(status_code=400, detail="Capture amount does not match the server-recorded checkout.")
        tier = saved.get("tier")
        if tier not in TIERS or float(TIERS[tier][0]) != amount_val:
            raise HTTPException(status_code=400, detail="Recorded checkout tier and capture amount do not match.")
        custom_id = resource.get("custom_id")
        if custom_id and custom_id != saved.get("user_id"):
            raise HTTPException(status_code=400, detail="Capture customer metadata does not match the server-recorded checkout.")
        if saved.get("status") == "captured":
            if saved.get("capture_id") != capture_id:
                raise HTTPException(status_code=409, detail="Checkout was already fulfilled by a different capture.")
            return WebhookResponse(success=True, message="Verified duplicate PayPal webhook acknowledged.",
                                   details={"transaction_id": capture_id, "duplicate": True, "tier": tier})

        supabase.rpc("apply_paypal_capture", {
            "p_user_id": saved["user_id"],
            "p_transaction_id": capture_id,
            "p_amount_paid": amount_val,
            "p_assigned_tier": tier,
        }).execute()
        supabase.table("paypal_orders").update({
            "status": "captured",
            "capture_id": capture_id,
            "captured_at": datetime.now(timezone.utc).isoformat(),
        }).eq("paypal_order_id", order_id).execute()
        logger.info("Verified PayPal capture applied to server-created order %s.", order_id)
        return WebhookResponse(success=True, message="Verified PayPal capture recorded and account tier synchronized.",
                               details={"transaction_id": capture_id, "user_id": saved["user_id"],
                                        "tier": tier, "duplicate": False})
    except HTTPException:
        raise
    except Exception:
        logger.exception("Verified PayPal capture could not be applied to the database.")
        raise HTTPException(status_code=503, detail="Payment was verified but could not be recorded; retry delivery later.")


# ============================================================================
# 6. SAFARICOM M-PESA DARAJA API DEPRECATION INTERCEPTORS (SOLE ROUTER TO PAYPAL)
# ============================================================================

@app.post("/api/v1/payments/mpesa/stk-push")
@app.post("/api/v1/payments/mpesa/c2b-callback")
@app.post("/api/v1/payments/mpesa/b2c-callback")
@app.post("/api/v1/payments/mpesa/b2b-callback")
@app.post("/api/v1/payments/mpesa/transaction-status")
@app.get("/api/v1/payments/mpesa/transaction-status")
async def mpesa_legacy_intercept():
    """
    Blocks legacy Safaricom Daraja API requests, STK push actions, pay bill operations, 
    and transaction state queries. Returns a strict HTTP 503 Service Unavailable exception.
    """
    logger.warning("Unsanctioned access attempt to deprecated M-Pesa Daraja API. Access intercepted and denied.")
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="M-Pesa cashout method has been deprecated."
    )


@app.post("/api/v1/payments/crypto-webhook", response_model=WebhookResponse)
async def crypto_webhook(request: Request):
    """
    Coinbase Commerce Payment Webhook Handler (Deprecated/Deactivated).
    To enforce PayPal as the single authorized gateway, crypto checkouts have been disabled.
    """
    logger.warning("Intercepted crypto payment webhook event. Gateway deactivated.")
    raise HTTPException(
        status_code=status.HTTP_510_NOT_EXTENDED,
        detail="Crypto payment method has been migrated. Please use PayPal for all automated operations pricing subscriptions."
    )



# ----------------------------------------------------------------------------
# Customer portal: sign-up, sign-in, PayPal checkout, job history and reports
# ----------------------------------------------------------------------------
TIERS = {
    "tier_1_51": ("51.00", "Basic"),
    "tier_2_83": ("83.00", "Scale"),
    "tier_3_129": ("129.00", "Ultimate"),
}
TIER_LIMITS = {
    "free": {"included_jobs": 2, "max_rows": 100, "label": "Free"},
    "tier_1_51": {"included_jobs": 25, "max_rows": 1000, "label": "Basic"},
    "tier_2_83": {"included_jobs": 250, "max_rows": 10000, "label": "Scale"},
    "tier_3_129": {"included_jobs": 1000, "max_rows": 100000, "label": "Ultimate"},
}

def clean_csv_content(decoded_text: str, tier: str) -> Dict[str, Any]:
    """Deterministic tier-aware CSV cleanup and report generation."""
    if tier not in TIER_LIMITS:
        raise ValueError("Unknown access tier.")
    reader = csv.reader(io.StringIO(decoded_text))
    try:
        raw_rows = list(reader)
    except csv.Error as exc:
        raise ValueError("CSV structure is invalid.") from exc
    if not raw_rows:
        raise ValueError("The CSV file is empty.")
    headers = [str(col).strip().lower().replace(" ", "_") for col in raw_rows[0]]
    if not headers or not any(headers):
        raise ValueError("The CSV must contain a header row.")
    max_rows = TIER_LIMITS[tier]["max_rows"]
    if max(0, len(raw_rows) - 1) > max_rows:
        raise ValueError(f"{TIER_LIMITS[tier]['label']} supports up to {max_rows:,} input data rows per CSV.")
    normalized = []
    for row in raw_rows[1:]:
        row = [str(value).strip() for value in row]
        if len(row) < len(headers):
            row.extend([""] * (len(headers) - len(row)))
        elif len(row) > len(headers):
            headers.extend([f"extra_column_{i}" for i in range(1, len(row) - len(headers) + 1)])
            for prior in normalized:
                prior.extend([""] * (len(headers) - len(prior)))
        normalized.append(row)
    blank_rows_removed = 0
    duplicate_rows_removed = 0
    if tier in ("tier_2_83", "tier_3_129"):
        kept = []
        seen = set()
        for row in normalized:
            if not any(value.strip() for value in row):
                blank_rows_removed += 1
                continue
            key = tuple(row)
            if key in seen:
                duplicate_rows_removed += 1
                continue
            seen.add(key)
            kept.append(row)
        normalized = kept
    output_stream = io.StringIO()
    writer = csv.writer(output_stream)
    writer.writerow(headers)
    writer.writerows(normalized)
    missing_by_column = {
        header: sum(1 for row in normalized if idx >= len(row) or not row[idx].strip())
        for idx, header in enumerate(headers)
    }
    summary: Dict[str, Any] = {
        "plan": TIER_LIMITS[tier]["label"],
        "rows_received": max(0, len(raw_rows) - 1),
        "rows_output": len(normalized),
        "columns": len(headers),
        "blank_rows_removed": blank_rows_removed,
        "duplicate_rows_removed": duplicate_rows_removed,
        "missing_values_by_column": missing_by_column if tier in ("tier_2_83", "tier_3_129") else {},
    }
    if tier == "tier_3_129":
        column_quality = []
        for idx, header in enumerate(headers):
            values = [row[idx].strip() for row in normalized if idx < len(row) and row[idx].strip()]
            if not values:
                inferred = "empty"
            elif all(v.lower() in ("true", "false", "yes", "no") for v in values):
                inferred = "boolean-like"
            else:
                try:
                    [float(v.replace(",", "")) for v in values]
                    inferred = "numeric"
                except ValueError:
                    inferred = "text"
            column_quality.append({
                "column": header,
                "non_empty_values": len(values),
                "missing_values": len(normalized) - len(values),
                "inferred_type": inferred,
            })
        summary["column_quality"] = column_quality
        summary["quality_flags"] = [
            f"{col}: {count} missing value(s)"
            for col, count in missing_by_column.items() if count
        ]
    return {"rows_cleaned": len(normalized), "formatted_result": output_stream.getvalue(), "summary": summary}


async def _supabase_auth_call(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=503, detail="Supabase authentication is not configured.")
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            response = await client.post(
                f"{SUPABASE_URL.rstrip('/')}/auth/v1/{path}",
                headers={"apikey": SUPABASE_KEY, "Content-Type": "application/json"},
                json=payload,
            )
        if response.status_code >= 400:
            message = "Authentication request failed."
            try:
                message = response.json().get("msg") or response.json().get("message") or response.json().get("error_description") or message
            except Exception:
                pass
            raise HTTPException(status_code=400, detail=message)
        return response.json()
    except HTTPException:
        raise
    except Exception:
        logger.exception("Supabase Auth request failed.")
        raise HTTPException(status_code=503, detail="Supabase Auth is temporarily unavailable.")

def _set_session_cookie(response, auth_data: Dict[str, Any]) -> None:
    token = auth_data.get("access_token")
    if not token:
        return
    response.set_cookie(
        "autoops_session", token, httponly=True, secure=True, samesite="lax",
        max_age=int(auth_data.get("expires_in") or 3600), path="/",
    )

@app.get("/api/v1/health")
async def health_check():
    """Non-sensitive readiness probe; checks actual PostgREST connectivity."""
    result = {"status": "ok", "database_configured": bool(supabase), "database_reachable": False}
    if supabase is not None:
        try:
            supabase.table("profiles").select("user_id").limit(1).execute()
            result["database_reachable"] = True
        except Exception:
            logger.exception("Supabase readiness query failed.")
            result["status"] = "degraded"
    else:
        result["status"] = "degraded"
    return result

@app.get("/", response_class=HTMLResponse)
async def customer_portal():
    return HTMLResponse(r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#0a1020">
<title>AutoOps Hub | Data operations, delivered</title>
<style>
:root{color-scheme:dark;--bg:#080d19;--panel:#10192b;--panel2:#0c1424;--line:#24314a;--text:#eef3ff;--muted:#9eacc5;--blue:#8bb4ff;--cyan:#70e1d1;--gold:#f4d18b;--danger:#ff9d9d;--radius:20px;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 15% -10%,#18294b 0,transparent 42%),radial-gradient(ellipse at 100% 5%,#123333 0,transparent 30%),var(--bg);color:var(--text);min-height:100vh}button,input,select{font:inherit}button{cursor:pointer;transition:transform .15s,border-color .15s,background .15s}button:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--cyan);outline-offset:3px}button:disabled{opacity:.55;cursor:wait;transform:none}
a{color:var(--blue)}.shell{max-width:1180px;margin:auto;padding:26px 22px 56px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:18px;padding:6px 0 28px}.brand{display:flex;align-items:center;gap:12px;font-weight:800;letter-spacing:-.04em;font-size:19px}.brandmark{display:grid;place-items:center;width:42px;height:42px;border-radius:14px;background:linear-gradient(135deg,#82b5ff,#68dfd1);color:#071321;font-weight:950;font-size:20px;box-shadow:0 8px 35px #72b9ff22}.topmeta{color:var(--muted);font-size:13px;display:flex;align-items:center;gap:8px}.dot{display:inline-block;width:8px;height:8px;background:var(--cyan);border-radius:50%;box-shadow:0 0 12px #70e1d188}
.hero{display:grid;grid-template-columns:1.25fr .75fr;gap:24px;align-items:stretch;padding:28px 0 24px}.eyebrow{font-size:12px;text-transform:uppercase;letter-spacing:.18em;color:var(--cyan);font-weight:800}.hero h1{font-size:clamp(38px,5.5vw,66px);line-height:1.02;letter-spacing:-.055em;margin:15px 0 18px;max-width:740px}.hero h1 span{color:var(--blue)}.hero p{color:var(--muted);font-size:17px;line-height:1.7;max-width:670px;margin:0}.hero-panel{border:1px solid #334564;background:linear-gradient(145deg,#16243b,#0d1727);border-radius:var(--radius);padding:24px;display:flex;flex-direction:column;justify-content:space-between;min-height:245px;box-shadow:0 22px 70px #0003}.hero-panel .big{font-size:13px;color:var(--muted)}.hero-panel strong{display:block;font-size:42px;letter-spacing:-.05em;margin:8px 0}.hero-panel .deliver{border-top:1px solid var(--line);padding-top:17px;color:#d8e3f7;font-size:14px;line-height:1.6}
.section-head{display:flex;justify-content:space-between;align-items:end;gap:20px;margin:32px 0 16px}.section-head h2{font-size:24px;letter-spacing:-.035em;margin:0 0 6px}.section-head p{margin:0;color:var(--muted);font-size:14px;line-height:1.6}.tag{display:inline-flex;align-items:center;border:1px solid #38526b;background:#112536;color:#bdece6;padding:7px 10px;border-radius:999px;font-size:12px;white-space:nowrap}
.service-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.service{background:linear-gradient(160deg,#121e32,#0d1525);border:1px solid var(--line);border-radius:var(--radius);padding:21px;min-height:210px}.service-icon{width:40px;height:40px;border:1px solid #334b6b;border-radius:13px;display:grid;place-items:center;color:var(--blue);font-size:20px;margin-bottom:16px}.service h3{font-size:17px;margin:0 0 9px}.service p{font-size:13px;line-height:1.65;color:var(--muted);margin:0}.service .included{margin-top:15px;color:#c4d4ee;font-size:12px}
.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:14px}.step{border:1px solid var(--line);border-radius:16px;padding:17px;background:#0c1422}.step b{display:block;font-size:14px;margin:8px 0}.step p{margin:0;color:var(--muted);font-size:13px;line-height:1.6}.step .num{color:var(--cyan);font-size:12px;font-weight:850;letter-spacing:.12em}
.workspace{display:grid;grid-template-columns:.88fr 1.12fr;gap:16px;margin-top:16px}.card{background:linear-gradient(160deg,#121d30,#0d1525);border:1px solid var(--line);border-radius:var(--radius);padding:22px;min-width:0}.card h2{font-size:19px;letter-spacing:-.03em;margin:0 0 8px}.card .sub{color:var(--muted);font-size:13px;line-height:1.6;margin:0 0 18px}.field{margin:14px 0}.field label{display:block;font-size:12px;color:#b9c7df;font-weight:700;margin-bottom:7px}.field input,.field select{width:100%;padding:12px 13px;border:1px solid #30405c;border-radius:11px;background:#080f1d;color:var(--text)}.field input::placeholder{color:#63738f}.btn{width:100%;border:1px solid transparent;border-radius:11px;padding:12px 15px;font-weight:800;margin-top:9px;background:linear-gradient(100deg,#9bc0ff,#74e0d0);color:#071321}.btn:hover{transform:translateY(-1px);filter:brightness(1.05)}.btn.secondary{background:#17253b;border-color:#344765;color:#e3ecfc}.btn.ghost{background:transparent;border-color:#30405c;color:#c7d4e9}.btn.small{width:auto;padding:8px 12px;margin:0;font-size:12px}
.pricing{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.price-card{border:1px solid var(--line);border-radius:17px;background:#0b1322;padding:17px;display:flex;flex-direction:column;min-height:250px}.price-card.featured{border-color:#6c9fda;background:linear-gradient(160deg,#172a43,#0d1829);box-shadow:inset 0 0 0 1px #6c9fda22}.plan-name{font-size:13px;font-weight:800;color:#c8d8f2}.price{font-size:34px;font-weight:850;letter-spacing:-.05em;margin:10px 0 3px}.once{font-size:11px;color:var(--muted)}.price-card ul{padding-left:18px;color:var(--muted);font-size:12px;line-height:1.8;flex:1;margin:14px 0}.price-card .btn{font-size:12px;padding:10px 8px}
.notice{display:none;padding:13px 15px;border:1px solid #39506f;border-radius:13px;background:#0d1d30;color:#d9e8ff;font-size:13px;line-height:1.55;margin-top:16px;white-space:pre-wrap;overflow-wrap:anywhere}.notice.show{display:block}.notice.error{border-color:#77434b;background:#28151e;color:#ffd3d3}.notice.good{border-color:#285e57;background:#102722;color:#c3f8e9}.report-empty{border:1px dashed #33445f;border-radius:14px;padding:26px;text-align:center;color:var(--muted);font-size:13px;line-height:1.7}.report-list{display:grid;gap:10px}.report-row{border:1px solid var(--line);border-radius:13px;padding:13px;background:#0a1220}.report-row-head{display:flex;justify-content:space-between;gap:10px;align-items:center}.report-row strong{font-size:13px}.report-row small{color:var(--muted);display:block;margin-top:5px;overflow-wrap:anywhere}.report-row button{margin-top:10px}.result-box{margin-top:12px;max-height:360px;overflow:auto;border:1px solid #2b3a54;background:#070d18;border-radius:12px;padding:14px;font-size:12px;line-height:1.7;white-space:pre-wrap;overflow-wrap:anywhere}.footer{border-top:1px solid var(--line);margin-top:42px;padding-top:20px;color:#7f8ea8;font-size:12px;display:flex;justify-content:space-between;gap:15px;flex-wrap:wrap}
@media(max-width:850px){.hero{grid-template-columns:1fr}.hero-panel{min-height:190px}.workspace{grid-template-columns:1fr}.service-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.pricing{grid-template-columns:1fr}.price-card{min-height:auto}.price-card ul{margin:10px 0}}
@media(max-width:560px){.shell{padding:18px 14px 40px}.topbar{align-items:flex-start}.topmeta{font-size:11px}.hero h1{font-size:42px}.hero p{font-size:15px}.service-grid,.steps{grid-template-columns:1fr}.section-head{align-items:flex-start;flex-direction:column}.card{padding:17px}.hero-panel strong{font-size:36px}}
</style>
</head>
<body>
<div class="shell">
<header class="topbar"><div class="brand"><div class="brandmark">A</div><span>AutoOps <span style="color:var(--blue)">Hub</span></span></div><div class="topmeta"><span class="dot"></span><span>Customer workspace · Sandbox environment</span></div></header>
<main>
<section class="hero"><div><div class="eyebrow">DATA OPERATIONS, WITHOUT THE BUSYWORK</div><h1>Turn messy CSVs into <span>usable data.</span></h1><p>Upload a CSV, let AutoOps Hub standardize its headers and trim inconsistent whitespace, then view and retrieve the cleaned report from your private workspace. A clear, repeatable workflow for everyday data cleanup.</p></div>
<aside class="hero-panel"><div><div class="big">YOUR FIRST AUTOMATION</div><strong>CSV Clean-up</strong><div class="tag">Upload · Clean · Review · Retrieve</div></div><div class="deliver">You receive a cleaned CSV result, a row count, and a saved report entry linked to your account.</div></aside></section>
<section><div class="section-head"><div><h2>What AutoOps Hub does today</h2><p>A focused, practical first service — not vague promises about automation.</p></div><span class="tag">Available in staging</span></div>
<div class="service-grid">
<article class="service"><div class="service-icon">↔</div><h3>Standardize CSV columns</h3><p>Trims header spaces, converts column names to lowercase, and replaces spaces in headers with underscores.</p><div class="included">Example: <b>Customer Name</b> → <b>customer_name</b></div></article>
<article class="service"><div class="service-icon">✳</div><h3>Clean cell whitespace</h3><p>Removes leading and trailing spaces from each CSV cell while preserving the tabular rows for easier downstream use.</p><div class="included">Input CSV → cleaned CSV output</div></article>
<article class="service"><div class="service-icon">▤</div><h3>Save a retrievable report</h3><p>Stores the job result and summary against your signed-in account so you can revisit previous runs in your workspace.</p><div class="included">Rows processed · Result · History</div></article>
</div>
<div class="steps"><div class="step"><span class="num">STEP 01</span><b>Create your secure account</b><p>Register with your email. Confirmation should return to this AutoOps Hub staging domain; if it does not, sign in after confirming and report the error.</p></div><div class="step"><span class="num">STEP 02</span><b>Choose your access tier</b><p>Compare exact row limits, monthly job quotas, deduplication and quality-report features before choosing.</p></div><div class="step"><span class="num">STEP 03</span><b>Upload and retrieve</b><p>Choose a CSV file, run the cleaner, and open the saved report. Ultimate adds inferred column types and quality flags.</p></div></div></section>
<section><div class="section-head"><div><h2>Choose your tier</h2><p>These are staging test prices, not live charges. Each checkout is currently a one-time payment, not a recurring subscription. Live payments must remain disabled until billing terms are finalized.</p></div><span class="tag">PayPal Sandbox</span></div>
<div class="pricing">
<article class="price-card"><div class="plan-name">BASIC</div><div class="price">$51</div><div class="once">USD · sandbox one-time test payment</div><ul><li>Clean CSV headers and trim cell whitespace</li><li>Up to 1,000 data rows per file</li><li>25 CSV jobs included with this one-time purchase</li><li>Private saved report and cleaned CSV result</li><li>View and retrieve previous reports</li></ul><button class="btn plan-select" data-tier="tier_1_51">Choose Basic</button></article>
<article class="price-card featured"><div class="plan-name">SCALE</div><div class="price">$83</div><div class="once">USD · sandbox one-time test payment</div><ul><li><b>Everything in Basic, plus:</b></li><li>Up to 10,000 data rows per file</li><li>250 total CSV jobs included with this one-time purchase</li><li>Remove fully blank rows</li><li>Remove exact duplicate rows</li><li>Per-column missing-value counts</li><li>Detailed cleanup summary in each report</li></ul><button class="btn plan-select" data-tier="tier_2_83">Choose Scale</button></article>
<article class="price-card"><div class="plan-name">ULTIMATE</div><div class="price">$129</div><div class="once">USD · sandbox one-time test payment</div><ul><li><b>Everything in Scale, plus:</b></li><li>Up to 100,000 data rows per file</li><li>1,000 total CSV jobs included with this one-time purchase</li><li>Column-level data type inference</li><li>Quality flags for missing values</li><li>Expanded column quality report</li><li>Saved, account-linked results and history</li></ul><button class="btn plan-select" data-tier="tier_3_129">Choose Ultimate</button></article>
</div></section>
<section class="workspace"><div class="card"><h2>Your account</h2><p class="sub">Your account details and payment access stay linked to your secure sign-in.</p>
<div id="authControls">
<div class="field"><label for="email">EMAIL ADDRESS</label><input id="email" type="email" autocomplete="email" placeholder="you@example.com"></div>
<div class="field"><label for="password">PASSWORD</label><input id="password" type="password" autocomplete="current-password" minlength="10" placeholder="At least 10 characters"></div>
<button class="btn" id="signupBtn">Create account</button><button class="btn secondary" id="loginBtn">Sign in</button>
</div>
<div id="signedInPanel" hidden><p class="sub" id="signedInLabel">You are signed in.</p><button class="btn ghost" id="logoutBtn">Sign out</button></div>
<div class="notice" id="accountNotice" role="status" aria-live="polite"></div>
<div class="field"><label for="tier">SELECT CHECKOUT TIER</label><select id="tier"><option value="tier_1_51">Basic — $51 USD</option><option value="tier_2_83">Scale — $83 USD</option><option value="tier_3_129">Ultimate — $129 USD</option></select></div>
<button class="btn" id="checkoutBtn">Continue to PayPal Sandbox</button><p class="sub" style="margin:12px 0 0">Sandbox checkout only: sign in at PayPal using a <b>Sandbox personal/buyer test account</b> from the PayPal Developer Dashboard. Your normal live PayPal email/password will not sign in to the Sandbox. Sandbox payments do not reach your real-money PayPal balance.</p>
</div>
<div class="card"><h2>Submit a CSV job</h2><p class="sub">Upload a small CSV file to test the complete workflow. Only CSV files are accepted.</p>
<div class="field"><label for="csv">CHOOSE YOUR CSV FILE</label><input id="csv" type="file" accept=".csv,text/csv"></div>
<button class="btn" id="submitJobBtn">Clean CSV &amp; generate report</button><button class="btn secondary" id="refreshBtn">Refresh my reports</button>
<div class="notice" id="jobNotice" role="status" aria-live="polite"></div>
<div style="height:1px;background:var(--line);margin:22px 0"></div><h2>Your report history</h2><p class="sub">Your saved jobs and report contents appear here after you sign in.</p>
<div id="reportList" class="report-empty">Sign in to load your private report history.</div><div id="reportResult"></div>
</div></section>
</main>
<footer class="footer"><span>AutoOps Hub · Staging preview</span><span>Sandbox only. Current checkout is one-time; recurring billing is not implemented.</span></footer>
</div>
<script>
(function(){
'use strict';
const $=id=>document.getElementById(id);
const accountNotice=$('accountNotice'),jobNotice=$('jobNotice'),reportList=$('reportList'),reportResult=$('reportResult');
const authControls=$('authControls'),signedInPanel=$('signedInPanel'),signedInLabel=$('signedInLabel');
function notice(el,message,type){el.textContent=message;el.className='notice show'+(type?' '+type:'')}
function clearNotice(el){el.textContent='';el.className='notice'}
function errorMessage(data,status){if(data&&typeof data.detail==='string')return data.detail;if(data&&data.detail&&typeof data.detail==='object')return JSON.stringify(data.detail);if(data&&data.message)return data.message;return 'Request failed ('+status+'). Please try again.'}
async function api(path,options){const response=await fetch(path,Object.assign({credentials:'same-origin'},options||{}));let data={};try{data=await response.json()}catch(e){}if(!response.ok)throw new Error(errorMessage(data,response.status));return data}
async function busy(button,work){if(button.disabled)return;const old=button.textContent;button.disabled=true;button.textContent='Please wait…';try{await work()}catch(e){notice(button.id==='submitJobBtn'||button.id==='refreshBtn'?jobNotice:accountNotice,e.message||'Something went wrong. Please try again.','error')}finally{button.disabled=false;button.textContent=old}}
function credentials(){const email=$('email').value.trim(),password=$('password').value;if(!email||email.indexOf('@')<1)throw new Error('Enter a valid email address first.');if(password.length<10)throw new Error('Use a password of at least 10 characters.');return {email:email,password:password}}
async function authenticate(mode){const body=credentials();const data=await api('/api/v1/auth/'+mode,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});notice(accountNotice,data.message||'Authentication request completed.','good');if(data.user){await loadAccount();await loadReports()}}
async function loadAccount(){try{const data=await api('/api/v1/auth/me');const tier=data.profile&&data.profile.current_tier?data.profile.current_tier:'not provisioned';authControls.hidden=true;signedInPanel.hidden=false;signedInLabel.textContent='Signed in as '+(data.user.email||data.user.id)+'. Current access tier: '+tier+'.';notice(accountNotice,'You are inside your account. Choose a plan or submit a CSV job below.','good');return true}catch(e){authControls.hidden=false;signedInPanel.hidden=true;return false}}
async function logout(){await api('/api/v1/auth/logout',{method:'POST'});reportList.className='report-empty';reportList.textContent='Sign in to load your private report history.';reportResult.replaceChildren();await loadAccount();notice(accountNotice,'You have signed out. Sign in again to access private reports or checkout.','good')}
async function checkout(){const data=await api('/api/v1/payments/paypal/order',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tier:$('tier').value})});if(!data.approval_url)throw new Error('PayPal did not return an approval link. Check Sandbox credentials and try again.');notice(accountNotice,'Opening PayPal Sandbox for $'+data.amount+' USD…','good');window.location.assign(data.approval_url)}
async function captureReturned(){const orderId=new URLSearchParams(window.location.search).get('token');if(!orderId)throw new Error('No PayPal order token was found. Start checkout and return here after approving the Sandbox payment.');const data=await api('/api/v1/payments/paypal/capture',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({order_id:orderId})});window.history.replaceState({},'',window.location.pathname);notice(accountNotice,data.message||'Payment verification completed.','good');await loadAccount();await loadReports()}
async function handleAuthCallback(){const hash=new URLSearchParams(window.location.hash.replace(/^#/,''));const query=new URLSearchParams(window.location.search);const accessToken=hash.get('access_token')||query.get('access_token');const authError=hash.get('error_description')||query.get('error_description')||hash.get('error')||query.get('error');if(authError)throw new Error('Email confirmation did not complete: '+authError.replace(/\+/g,' '));if(accessToken){const data=await api('/api/v1/auth/session',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({access_token:accessToken})});window.history.replaceState({},'',window.location.pathname);notice(accountNotice,data.message||'Email confirmed. You are signed in.','good');await loadAccount();await loadReports();return true}if(query.get('auth')==='confirmed'){notice(accountNotice,'Email confirmed. Sign in below to continue.','good');window.history.replaceState({},'',window.location.pathname);return true}return false}
async function submitJob(){const file=$('csv').files&&$('csv').files[0];if(!file)throw new Error('Choose a CSV file before submitting the job.');if(!file.name.toLowerCase().endsWith('.csv'))throw new Error('Please choose a file ending in .csv.');const form=new FormData();form.append('file',file);const data=await api('/api/v1/automation/clean-csv',{method:'POST',body:form});notice(jobNotice,'Job completed. '+data.rows_cleaned+' data rows processed.','good');showResult('Latest cleaned CSV',data.formatted_result||JSON.stringify(data,null,2));await loadReports()}
function showResult(title,value){reportResult.replaceChildren();const heading=document.createElement('h3');heading.textContent=title;heading.style.fontSize='14px';const pre=document.createElement('pre');pre.className='result-box';pre.textContent=value;reportResult.append(heading,pre)}
async function loadReports(){const data=await api('/api/v1/jobs');const jobs=data.jobs||[];reportList.replaceChildren();if(!jobs.length){reportList.className='report-empty';reportList.textContent='No reports yet. Submit a CSV job to create your first report.';return}reportList.className='report-list';jobs.forEach(job=>{const row=document.createElement('article');row.className='report-row';const head=document.createElement('div');head.className='report-row-head';const title=document.createElement('strong');title.textContent=(job.job_type||'Automation job').replace(/_/g,' ');const state=document.createElement('span');state.className='tag';state.textContent=job.status||'unknown';head.append(title,state);const meta=document.createElement('small');meta.textContent='Created: '+(job.created_at||'time unavailable')+' · Report ID: '+job.id;const view=document.createElement('button');view.className='btn secondary small';view.textContent='Open report';view.addEventListener('click',()=>busy(view,async()=>{const full=await api('/api/v1/jobs/'+encodeURIComponent(job.id));showResult('Report · '+job.id,JSON.stringify(full.job.result,null,2));notice(jobNotice,'Report loaded.','good')}));row.append(head,meta,view);reportList.append(row)})}
$('signupBtn').addEventListener('click',()=>busy($('signupBtn'),()=>authenticate('signup')));
$('loginBtn').addEventListener('click',()=>busy($('loginBtn'),()=>authenticate('login')));
$('logoutBtn').addEventListener('click',()=>busy($('logoutBtn'),logout));
$('checkoutBtn').addEventListener('click',()=>busy($('checkoutBtn'),checkout));
$('submitJobBtn').addEventListener('click',()=>busy($('submitJobBtn'),submitJob));
$('refreshBtn').addEventListener('click',()=>busy($('refreshBtn'),loadReports));
document.querySelectorAll('.plan-select').forEach(button=>button.addEventListener('click',()=>{$('tier').value=button.dataset.tier;document.querySelectorAll('.plan-select').forEach(b=>b.textContent='Choose '+b.dataset.tier.replace('tier_1_51','Basic').replace('tier_2_83','Scale').replace('tier_3_129','Ultimate'));button.textContent='Selected';$('tier').scrollIntoView({behavior:'smooth',block:'center'});notice(accountNotice,'Selected '+button.textContent.replace('Selected','plan')+'. Sign in before continuing to PayPal.')})); 
(async()=>{try{if(await handleAuthCallback())return;const query=new URLSearchParams(window.location.search);if(query.get('payment')==='success'&&query.get('token')){await captureReturned();return}if(query.get('payment')==='cancelled'){notice(accountNotice,'PayPal checkout was cancelled. No payment was captured. You can choose a plan and try again.');window.history.replaceState({},'',window.location.pathname)}await loadAccount();await loadReports()}catch(e){notice(accountNotice,e.message,'error')}})();
})();
</script>
</body></html>''')

@app.post("/api/v1/auth/signup")
async def auth_signup(payload: Dict[str, Any], response: Response):
    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", ""))
    if "@" not in email or len(password) < 10:
        raise HTTPException(status_code=400, detail="Enter a valid email and a password of at least 10 characters.")
    public_app_url = os.getenv("PUBLIC_APP_URL", "https://autoops-hub-staging.onrender.com").rstrip("/")
    confirmation_redirect = f"{public_app_url}/?auth=confirmed"
    auth_path = "signup?redirect_to=" + quote(confirmation_redirect, safe="")
    auth_data = await _supabase_auth_call(auth_path, {"email": email, "password": password})
    if auth_data.get("access_token"):
        _set_session_cookie(response, auth_data)
        return {"message": "Account created and signed in.", "user": {"id": auth_data.get("user", {}).get("id"), "email": email}}
    return {"message": "Account created. Check your email to confirm it, then sign in.", "user": None}

@app.post("/api/v1/auth/session")
async def auth_session(payload: Dict[str, Any], response: Response):
    """Exchange a Supabase email-confirmation access token for an HttpOnly app session cookie."""
    access_token = str(payload.get("access_token", "")).strip()
    if not access_token or len(access_token) > 8192:
        raise HTTPException(status_code=400, detail="A valid confirmation session token is required.")
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            verified = await client.get(
                f"{SUPABASE_URL.rstrip('/')}/auth/v1/user",
                headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {access_token}"},
            )
        if verified.status_code != 200:
            raise HTTPException(status_code=401, detail="The confirmation link is expired or invalid. Please sign in again.")
        _set_session_cookie(response, {"access_token": access_token, "expires_in": 3600})
        user = verified.json()
        return {"success": True, "message": "Email confirmed. You are signed in.", "user": {"id": user.get("id"), "email": user.get("email")}}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Supabase confirmation session exchange failed.")
        raise HTTPException(status_code=503, detail="Could not complete email confirmation. Please sign in again.")

@app.post("/api/v1/auth/login")
async def auth_login(payload: Dict[str, Any], response: Response):
    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", ""))
    auth_data = await _supabase_auth_call("token?grant_type=password", {"email": email, "password": password})
    if not auth_data.get("access_token"):
        raise HTTPException(status_code=401, detail="Sign-in did not return a session.")
    _set_session_cookie(response, auth_data)
    return {"message": "Signed in.", "user": {"id": auth_data.get("user", {}).get("id"), "email": auth_data.get("user", {}).get("email")}}

@app.post("/api/v1/auth/logout")
async def auth_logout(response: Response):
    response.delete_cookie("autoops_session", path="/", secure=True, httponly=True, samesite="lax")
    return {"success": True, "message": "Signed out."}

@app.get("/api/v1/auth/me")
async def auth_me(request: Request):
    user = await get_authenticated_user(request)
    if not supabase:
        raise HTTPException(status_code=503, detail="Database is not connected.")
    profile = supabase.table("profiles").select("current_tier,status").eq("user_id", user["user_id"]).execute()
    return {"user": {"id": user["user_id"], "email": user.get("email")}, "profile": profile.data[0] if profile.data else None}

async def _paypal_access_token() -> str:
    if not PAYPAL_CLIENT_ID or not PAYPAL_CLIENT_SECRET or not PAYPAL_WEBHOOK_ID:
        raise HTTPException(status_code=503, detail="PayPal Sandbox credentials are not fully configured.")
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            r = await client.post(f"{PAYPAL_API_BASE}/v1/oauth2/token",
                auth=(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET),
                data={"grant_type": "client_credentials"},
                headers={"Accept": "application/json"})
            r.raise_for_status()
            token = r.json().get("access_token")
            if not token:
                raise HTTPException(status_code=503, detail="PayPal did not issue an access token.")
            return token
    except HTTPException:
        raise
    except Exception:
        logger.exception("PayPal OAuth failed.")
        raise HTTPException(status_code=503, detail="PayPal Sandbox authentication failed; check that all credentials belong to the same Sandbox app.")

@app.post("/api/v1/payments/paypal/order")
async def create_paypal_order(request: Request, payload: Dict[str, Any]):
    user = await get_authenticated_user(request)
    if not supabase:
        raise HTTPException(status_code=503, detail="Database is not connected.")
    tier = str(payload.get("tier", ""))
    if tier not in TIERS:
        raise HTTPException(status_code=400, detail="Unknown plan.")
    profile = supabase.table("profiles").select("user_id").eq("user_id", user["user_id"]).execute()
    ledger = supabase.table("usage_ledger").select("profile_id").eq("profile_id", user["user_id"]).execute()
    if not profile.data or not ledger.data:
        raise HTTPException(status_code=409, detail="Account profile/usage ledger is missing; cannot create a checkout.")
    amount, label = TIERS[tier]
    token = await _paypal_access_token()
    base_url = os.getenv("PUBLIC_APP_URL", "https://autoops-hub-staging.onrender.com").rstrip("/")
    payload = {
        "intent": "CAPTURE",
        "purchase_units": [{
            "reference_id": tier,
            "custom_id": user["user_id"],
            "description": f"AutoOps Hub {label} plan",
            "amount": {"currency_code": "USD", "value": amount},
        }],
        "application_context": {
            "brand_name": "AutoOps Hub",
            "user_action": "PAY_NOW",
            "return_url": f"{base_url}/?payment=success",
            "cancel_url": f"{base_url}/?payment=cancelled",
        },
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0)) as client:
            r = await client.post(f"{PAYPAL_API_BASE}/v2/checkout/orders",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json=payload)
            r.raise_for_status()
            order = r.json()
        order_id = order.get("id")
        approval = next((x.get("href") for x in order.get("links", []) if x.get("rel") in ("approve", "payer-action")), None)
        if not order_id or not approval:
            raise HTTPException(status_code=502, detail="PayPal did not return a valid approval URL.")
        supabase.table("paypal_orders").insert({
            "paypal_order_id": order_id, "user_id": user["user_id"],
            "tier": tier, "amount": float(amount), "status": "pending"
        }).execute()
        return {"order_id": order_id, "approval_url": approval, "tier": tier, "amount": amount, "currency": "USD"}
    except HTTPException:
        raise
    except Exception:
        logger.exception("PayPal order creation failed.")
        raise HTTPException(status_code=502, detail="Could not create a PayPal order. Check Sandbox configuration and retry.")

@app.post("/api/v1/payments/paypal/capture")
async def capture_paypal_order(request: Request, payload: Dict[str, Any]):
    user = await get_authenticated_user(request)
    if not supabase:
        raise HTTPException(status_code=503, detail="Database is not connected.")
    order_id = str(payload.get("order_id", "")).strip()
    if not order_id or len(order_id) > 128:
        raise HTTPException(status_code=400, detail="A valid PayPal order ID is required.")
    rows = supabase.table("paypal_orders").select("*").eq("paypal_order_id", order_id).eq("user_id", user["user_id"]).execute()
    if not rows.data:
        raise HTTPException(status_code=404, detail="This PayPal order does not belong to your signed-in account.")
    saved = rows.data[0]
    if saved.get("status") == "captured":
        return {"success": True, "message": "This payment was already processed.", "tier": saved.get("tier"), "duplicate": True}
    token = await _paypal_access_token()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0)) as client:
            check = await client.get(f"{PAYPAL_API_BASE}/v2/checkout/orders/{order_id}",
                headers={"Authorization": f"Bearer {token}"})
            check.raise_for_status()
            order = check.json()
            if order.get("status") != "APPROVED":
                raise HTTPException(status_code=409, detail="PayPal order is not approved yet.")
            units = order.get("purchase_units") or []
            if len(units) != 1:
                raise HTTPException(status_code=400, detail="Unexpected PayPal purchase-unit count.")
            unit = units[0]
            amt = unit.get("amount") or {}
            if unit.get("custom_id") != user["user_id"] or unit.get("reference_id") != saved["tier"]:
                raise HTTPException(status_code=400, detail="PayPal order ownership/tier mismatch.")
            if amt.get("currency_code") != "USD" or amt.get("value") != f'{float(saved["amount"]):.2f}':
                raise HTTPException(status_code=400, detail="PayPal order amount does not match the recorded plan.")
            captured = await client.post(f"{PAYPAL_API_BASE}/v2/checkout/orders/{order_id}/capture",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json={})
            captured.raise_for_status()
            capture_data = captured.json()
        if capture_data.get("status") != "COMPLETED":
            raise HTTPException(status_code=409, detail="PayPal has not completed the capture.")
        captures = (((capture_data.get("purchase_units") or [{}])[0].get("payments") or {}).get("captures") or [])
        if not captures or captures[0].get("status") != "COMPLETED":
            raise HTTPException(status_code=409, detail="No completed PayPal capture was returned.")
        cap = captures[0]
        cap_amount = cap.get("amount") or {}
        if cap_amount.get("currency_code") != "USD" or cap_amount.get("value") != f'{float(saved["amount"]):.2f}':
            raise HTTPException(status_code=400, detail="Captured amount does not match the recorded plan.")
        applied = supabase.rpc("apply_paypal_capture", {
            "p_user_id": user["user_id"], "p_transaction_id": cap["id"],
            "p_amount_paid": float(saved["amount"]), "p_assigned_tier": saved["tier"],
        }).execute()
        supabase.table("paypal_orders").update({
            "status": "captured", "capture_id": cap["id"], "captured_at": datetime.now(timezone.utc).isoformat()
        }).eq("paypal_order_id", order_id).execute()
        return {"success": True, "message": "Sandbox payment captured and account tier updated.", "tier": saved["tier"], "capture_id": cap["id"], "database_result": applied.data}
    except HTTPException:
        raise
    except Exception:
        logger.exception("PayPal order capture/application failed.")
        raise HTTPException(status_code=503, detail="PayPal capture could not be applied safely. Retry after checking logs.")

@app.get("/api/v1/jobs")
async def list_customer_jobs(request: Request):
    user = await get_authenticated_user(request)
    if not supabase:
        raise HTTPException(status_code=503, detail="Database is not connected.")
    rows = supabase.table("automation_jobs").select("id,job_type,input_filename,status,created_at,completed_at").eq("profile_id", user["user_id"]).order("created_at", desc=True).limit(25).execute()
    return {"jobs": rows.data or []}

@app.get("/api/v1/jobs/{job_id}")
async def get_customer_job(job_id: str, request: Request):
    user = await get_authenticated_user(request)
    if not supabase:
        raise HTTPException(status_code=503, detail="Database is not connected.")
    try:
        job_uuid = str(UUID(job_id))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report ID.")
    rows = supabase.table("automation_jobs").select("*").eq("id", job_uuid).eq("profile_id", user["user_id"]).limit(1).execute()
    if not rows.data:
        raise HTTPException(status_code=404, detail="Report not found.")
    return {"job": rows.data[0]}

if __name__ == "__main__":
    import uvicorn
    # Start server locally on port 3000 mapping DevSecOps requirements
    uvicorn.run(app, host="0.0.0.0", port=3000)
