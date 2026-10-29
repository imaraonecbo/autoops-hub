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
from fastapi import FastAPI, Depends, HTTPException, Header, UploadFile, File, Form, Request, status
from backend import file_processors
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
PAYPAL_SANDBOX_API_BASE = "https://api-m.sandbox.paypal.com"
PAYPAL_LIVE_API_BASE = "https://api-m.paypal.com"
PAYPAL_API_BASE = os.getenv("PAYPAL_API_BASE", PAYPAL_SANDBOX_API_BASE).rstrip("/")
PAYPAL_LIVE_ENABLED = os.getenv("PAYPAL_LIVE_ENABLED", "false").strip().lower() in {"true", "1", "yes"}
COINBASE_WEBHOOK_SECRET = os.getenv("COINBASE_WEBHOOK_SECRET", "").strip()

def _paypal_credentials_configured() -> bool:
    values = (PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, PAYPAL_WEBHOOK_ID)
    return all(value and "placeholder" not in value.lower() and "unconfigured" not in value.lower()
               for value in values)

def _paypal_mode() -> str:
    if PAYPAL_API_BASE == PAYPAL_LIVE_API_BASE:
        return "live"
    if PAYPAL_API_BASE == PAYPAL_SANDBOX_API_BASE:
        return "sandbox"
    return "invalid"

def _assert_paypal_runtime_ready() -> None:
    mode = _paypal_mode()
    if mode == "invalid":
        raise HTTPException(status_code=503, detail="PayPal API host is not an approved Sandbox or Live endpoint.")
    if not _paypal_credentials_configured():
        raise HTTPException(status_code=503, detail="PayPal credentials are not fully configured for this environment.")
    if mode == "live" and not PAYPAL_LIVE_ENABLED:
        raise HTTPException(status_code=503, detail="Live checkout is deliberately disabled until production credentials and merchant configuration are verified.")

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
        ledger_res = supabase.table("usage_ledger").select("monthly_credits_used,total_lifetime_jobs,job_credits_remaining,last_reset_date").eq("profile_id", user_id).execute()
        if not ledger_res.data:
            raise HTTPException(status_code=409, detail="Usage ledger is not provisioned for this account.")
        ledger = ledger_res.data[0]
        monthly_credits = int(ledger.get("monthly_credits_used", 0) or 0)
        lifetime_jobs = int(ledger.get("total_lifetime_jobs", 0) or 0)
        credits_remaining = int(ledger.get("job_credits_remaining", 0) or 0)
        limits = TIER_LIMITS.get(current_tier, TIER_LIMITS["free"])
        if credits_remaining <= 0:
            raise HTTPException(status_code=402, detail={
                "error": "Included job credits exhausted",
                "current_tier": current_tier,
                "total_lifetime_jobs": lifetime_jobs,
                "job_credits_remaining": credits_remaining,
                "message": "There are no remaining job credits on this account. Purchase a tier to add more credits.",
                "pricing_options": {
                    "tier_1_51": {"unit_price": 79.00, "tier_name": "Basic"},
                    "tier_2_83": {"unit_price": 149.00, "tier_name": "Scale"},
                    "tier_3_129": {"unit_price": 299.00, "tier_name": "Ultimate"}
                }
            })
        return {"user_id": user_id, "email": auth_user.get("email"),
                "current_tier": current_tier, "monthly_credits_used": monthly_credits,
                "total_lifetime_jobs": lifetime_jobs, "job_credits_remaining": credits_remaining,
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

        # Record the report and consume a purchased job credit in one DB transaction.
        job_record = supabase.rpc("complete_automation_job", {
            "p_user_id": user_id,
            "p_job_type": "clean_csv",
            "p_input_filename": file.filename,
            "p_result": {"output_format": "csv", "rows_cleaned": cleaned_rows_count, "formatted_result": cleaned_csv_result, "summary": report_summary},
        }).execute()
        job_result = job_record.data if isinstance(job_record.data, dict) else (
            job_record.data[0] if isinstance(job_record.data, list) and job_record.data else {}
        )
        job_id = job_result.get("job_id")
        logger.info(f"Successfully cleaned telemetry data log for user_id: {user_id}. Rows processed: {cleaned_rows_count}.")
        return {
            "success": True,
            "job_id": job_id,
            "rows_cleaned": cleaned_rows_count,
            "credits_remaining": job_result.get("job_credits_remaining", max(0, security_context.get("job_credits_remaining", 0) - 1)),
            "job_credits_remaining": job_result.get("job_credits_remaining", max(0, security_context.get("job_credits_remaining", 0) - 1)),
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
        # Persist the webhook result and consume the packaged job credit atomically.
        saved = supabase.rpc("complete_automation_job", {
            "p_user_id": user_id,
            "p_job_type": "bot_webhook",
            "p_input_filename": "programmatic-webhook",
            "p_result": {
                "task_action": payload.task_action,
                "current_tier": security_context["current_tier"],
                "source": "authenticated_bot_webhook",
            },
        }).execute()
        saved_data = saved.data if isinstance(saved.data, dict) else (
            saved.data[0] if isinstance(saved.data, list) and saved.data else {}
        )
        next_credits = saved_data.get("monthly_credits_used", current_credits + 1)
        logger.info("Webhook job completed for user_id=%s; credits remaining=%s",
                    user_id, saved_data.get("job_credits_remaining"))
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


@app.post("/api/v1/automation/process-file", status_code=status.HTTP_200_OK)
async def process_supported_file(
    file: UploadFile = File(..., description="CSV, Excel, JSON, or server log input."),
    operation: str = Form("auto"),
    security_context: Dict[str, Any] = Depends(verify_user_and_credits),
):
    """Additive format-aware pipeline; the legacy /clean-csv route remains supported."""
    user_id = security_context["user_id"]
    if not file.filename:
        raise HTTPException(status_code=400, detail="A filename is required.")
    extension = "." + file.filename.lower().rsplit(".", 1)[-1] if "." in file.filename else ""
    if extension not in file_processors.SUPPORTED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Supported file types are .csv, .xlsx, .xls, .json, and .log.")
    max_bytes = 20 * 1024 * 1024
    content = await file.read(max_bytes)
    if await file.read(1):
        raise HTTPException(status_code=413, detail="File exceeds the 20 MB upload limit.")
    try:
        # Keep the already-tested CSV algorithm as the canonical CSV path.
        # The new dispatcher handles CSV only when a caller explicitly selects an
        # Ultimate tabular workload such as catalog/order/identity normalization.
        if extension == ".csv" and operation in {"auto", "csv_clean"}:
            try:
                legacy_csv = content.decode("utf-8-sig")
                cleaned_csv = clean_csv_content(legacy_csv, security_context["current_tier"])
            except (UnicodeDecodeError, csv.Error, ValueError) as exc:
                raise HTTPException(status_code=422, detail=f"CSV processing failed: {exc}")
            processed = {
                "job_type": "clean_csv",
                "output_format": "csv",
                "rows_cleaned": cleaned_csv["rows_cleaned"],
                "formatted_result": cleaned_csv["formatted_result"],
                "summary": cleaned_csv["summary"],
            }
        else:
            processed = file_processors.process_data_file(
                filename=file.filename,
                content=content,
                tier=security_context["current_tier"],
                operation=operation,
            )
        stored_result = {
            "output_format": processed.get("output_format", "json"),
            "rows_cleaned": processed.get("rows_cleaned", 0),
            "formatted_result": processed.get("formatted_result", ""),
            "summary": processed.get("summary", {}),
            "operation": operation,
        }
        saved = supabase.rpc("complete_automation_job", {
            "p_user_id": user_id,
            "p_job_type": processed["job_type"],
            "p_input_filename": file.filename,
            "p_result": stored_result,
        }).execute()
        saved_data = saved.data if isinstance(saved.data, dict) else (
            saved.data[0] if isinstance(saved.data, list) and saved.data else {}
        )
        logger.info("Completed file operation=%s extension=%s user_id=%s rows=%s",
                    operation, extension, user_id, processed.get("rows_cleaned", 0))
        return {
            "success": True,
            "job_id": saved_data.get("job_id"),
            "job_type": processed["job_type"],
            "output_format": processed.get("output_format", "json"),
            "rows_cleaned": processed.get("rows_cleaned", 0),
            "summary": processed.get("summary", {}),
            "formatted_result": processed.get("formatted_result", ""),
            "job_credits_remaining": saved_data.get("job_credits_remaining"),
        }
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception:
        logger.exception("Multi-format processing failed for user_id=%s filename=%s", user_id, file.filename)
        raise HTTPException(status_code=503, detail="File processing failed. No successful report was returned.")

# ----------------------------------------------------------------------------
# 5. UNIFIED CHECKOUT & WEBHOOK ROUTER
# ----------------------------------------------------------------------------

async def verify_paypal_signature(request: Request, event: Dict[str, Any]) -> None:
    """Ask PayPal's official verification API to validate the exact webhook headers and event."""
    _assert_paypal_runtime_ready()

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
        _record_marketing_event(
            str(saved["user_id"]), f"purchase:{capture_id}", "purchase_completed",
            value=amount_val, metadata={"tier": tier, "capture_id": capture_id},
        )
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
    "tier_1_51": ("79.00", "Basic"),
    "tier_2_83": ("149.00", "Scale"),
    "tier_3_129": ("299.00", "Ultimate"),
}
TIER_LIMITS = {
    "free": {"included_jobs": 2, "max_rows": 100, "label": "Free"},
    "tier_1_51": {"included_jobs": 30, "max_rows": 2500, "label": "Basic"},
    "tier_2_83": {"included_jobs": 300, "max_rows": 25000, "label": "Scale"},
    "tier_3_129": {"included_jobs": 1500, "max_rows": 250000, "label": "Ultimate"},
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


def _marketing_fields(payload: Dict[str, Any]) -> Dict[str, str]:
    """Normalize non-sensitive campaign tags supplied by the customer-facing page."""
    payload = payload if isinstance(payload, dict) else {}
    allowed = ("source", "medium", "campaign", "content", "term", "landing_path", "referrer_host")
    result: Dict[str, str] = {}
    for key in allowed:
        raw = payload.get(key)
        if not isinstance(raw, str):
            continue
        value = raw.strip()
        if key in ("source", "medium", "campaign"):
            value = value or {"source": "direct", "medium": "none", "campaign": "unattributed"}[key]
        if value:
            result[key] = value[:400 if key == "landing_path" else 160]
    result.setdefault("source", "direct")
    result.setdefault("medium", "none")
    result.setdefault("campaign", "unattributed")
    return result


def _record_marketing_attribution(user_id: str, fields: Dict[str, str]) -> None:
    """Persist first and last campaign touch without storing email or raw referrer URLs."""
    if not supabase or not user_id:
        return
    now = datetime.now(timezone.utc).isoformat()
    source = fields.get("source", "direct")
    medium = fields.get("medium", "none")
    campaign = fields.get("campaign", "unattributed")
    first = {
        "user_id": user_id,
        "first_source": source,
        "first_medium": medium,
        "first_campaign": campaign,
        "first_content": fields.get("content"),
        "first_term": fields.get("term"),
        "first_landing_path": fields.get("landing_path"),
        "first_referrer_host": fields.get("referrer_host"),
        "first_touch_at": now,
        "last_source": source,
        "last_medium": medium,
        "last_campaign": campaign,
        "last_content": fields.get("content"),
        "last_term": fields.get("term"),
        "last_landing_path": fields.get("landing_path"),
        "last_referrer_host": fields.get("referrer_host"),
        "last_touch_at": now,
        "updated_at": now,
    }
    try:
        existing = supabase.table("marketing_attributions").select("user_id").eq("user_id", user_id).limit(1).execute()
        if existing.data:
            # A direct checkout must not overwrite a known campaign touch.
            if source == "direct" and campaign == "unattributed":
                return
            update = {key: value for key, value in first.items() if key.startswith("last_")}
            update["updated_at"] = now
            supabase.table("marketing_attributions").update(update).eq("user_id", user_id).execute()
        else:
            supabase.table("marketing_attributions").insert(first).execute()
    except Exception:
        logger.exception("Marketing attribution could not be recorded for user %s.", user_id)


def _record_marketing_event(
    user_id: Optional[str],
    event_key: str,
    event_name: str,
    fields: Optional[Dict[str, str]] = None,
    value: Optional[float] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Record idempotent conversion events; never let analytics interrupt checkout or signup."""
    if not supabase:
        return
    fields = fields or {}
    try:
        if user_id and (
            not fields or (
                fields.get("source", "direct") == "direct"
                and fields.get("campaign", "unattributed") == "unattributed"
            )
        ):
            saved = supabase.table("marketing_attributions").select(
                "last_source,last_medium,last_campaign"
            ).eq("user_id", user_id).limit(1).execute()
            if saved.data:
                row = saved.data[0]
                fields = {
                    "source": row.get("last_source") or "direct",
                    "medium": row.get("last_medium") or "none",
                    "campaign": row.get("last_campaign") or "unattributed",
                }
        record = {
            "event_key": event_key[:200],
            "event_name": event_name,
            "user_id": user_id,
            "source": fields.get("source", "direct")[:160],
            "medium": fields.get("medium", "none")[:160],
            "campaign": fields.get("campaign", "unattributed")[:160],
            "value": value,
            "currency": "USD",
            "metadata": metadata or {},
        }
        supabase.table("marketing_events").upsert(record, on_conflict="event_key").execute()
    except Exception:
        logger.exception("Marketing event %s could not be recorded.", event_name)


@app.get("/api/v1/health")
async def health_check():
    """Non-sensitive readiness probe; checks actual PostgREST connectivity."""
    mode = _paypal_mode()
    paypal_ready = _paypal_credentials_configured() and mode != "invalid" and (mode != "live" or PAYPAL_LIVE_ENABLED)
    result = {
        "status": "ok",
        "database_configured": bool(supabase),
        "database_reachable": False,
        "payment_mode": mode,
        "paypal_credentials_configured": _paypal_credentials_configured(),
        "paypal_checkout_enabled": paypal_ready,
    }
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
<meta name="theme-color" content="#0b1220">
<title>AutoOps Hub | Operations workspace</title>
<style>
:root{color-scheme:dark;--bg:#080e18;--sidebar:#0b1321;--panel:#101b2b;--panel2:#0d1726;--line:#223249;--line2:#2e425d;--text:#edf3fc;--muted:#94a6bd;--soft:#c4d2e5;--blue:#9fc3ff;--teal:#75e0cc;--gold:#edce8f;--red:#ffabab;--radius:18px;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:radial-gradient(ellipse at 65% -12%,#172b45 0,transparent 34%),var(--bg);color:var(--text);min-height:100vh;font-size:14px}button,input,select{font:inherit}button{cursor:pointer;transition:background .16s,border-color .16s,transform .16s,opacity .16s}button:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--teal);outline-offset:3px}button:disabled{opacity:.6;cursor:wait}a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}.app{display:grid;grid-template-columns:250px minmax(0,1fr);min-height:100vh}.sidebar{background:linear-gradient(180deg,#0c1524,#090f1b);border-right:1px solid #1a2a40;padding:24px 15px 18px;display:flex;flex-direction:column;gap:24px;min-height:100vh;position:sticky;top:0;height:100vh;overflow-y:auto;z-index:20}.brand{display:flex;align-items:center;gap:11px;padding:0 9px}.brandmark{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;background:linear-gradient(140deg,#a8caff,#70e1d0);color:#071320;font-weight:950;font-size:18px;box-shadow:0 8px 30px #71c4ff20}.brandname{font-weight:850;letter-spacing:-.045em;font-size:17px}.brandname span{color:var(--blue)}.brandtag{font-size:10px;color:#7488a3;letter-spacing:.13em;text-transform:uppercase;margin-top:3px}.nav-label{padding:0 12px;color:#71839b;font-size:10px;font-weight:800;letter-spacing:.16em;text-transform:uppercase;margin-bottom:8px}.nav{display:grid;gap:5px}.nav-link{display:flex;align-items:center;gap:12px;width:100%;text-align:left;border:1px solid transparent;border-radius:12px;background:transparent;color:#9fb0c8;padding:12px 13px;font-size:13px;font-weight:650}.nav-link .ico{display:grid;place-items:center;width:20px;height:20px;font-size:16px;color:#8196b2}.nav-link:hover{background:#142238;color:#e5efff}.nav-link.active{background:linear-gradient(100deg,#1b3150,#17273e);border-color:#2c496d;color:#edf5ff;box-shadow:inset 2px 0 0 var(--teal)}.nav-link.active .ico{color:var(--teal)}.sidebar-spacer{flex:1}.side-status{margin:0 4px;padding:14px;border:1px solid #293c52;border-radius:14px;background:#0e1a2a}.status-line{display:flex;align-items:center;gap:8px;font-size:12px;color:#d0def0;font-weight:700}.dot{width:7px;height:7px;background:var(--teal);border-radius:50%;box-shadow:0 0 11px #75e0cc55;flex-shrink:0}.side-status p{font-size:11px;line-height:1.6;color:#8597b0;margin:8px 0 0}.side-foot{padding:0 10px;color:#62748c;font-size:10px;line-height:1.7}.main{min-width:0;padding:0 32px 38px}.topbar{height:76px;border-bottom:1px solid #1c2a3e;display:flex;align-items:center;justify-content:space-between;gap:15px}.breadcrumbs{font-size:12px;color:#8295af}.breadcrumbs strong{color:#e8effa;font-weight:750}.top-actions{display:flex;align-items:center;gap:12px}.env-pill,.status-pill{display:inline-flex;align-items:center;gap:7px;padding:7px 10px;border:1px solid #2b4b58;background:#102720;color:#a8f0df;border-radius:999px;font-size:10px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;white-space:nowrap}.user-chip{display:flex;align-items:center;gap:9px;padding-left:13px;border-left:1px solid var(--line)}.avatar{width:33px;height:33px;border-radius:50%;display:grid;place-items:center;background:#203957;border:1px solid #365579;color:#d4e4ff;font-size:12px;font-weight:850}.user-detail{max-width:185px}.user-detail strong{display:block;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.user-detail small{display:block;font-size:10px;color:var(--muted);margin-top:3px}.mobile-menu{display:none;border:1px solid var(--line2);background:#111f32;color:var(--text);border-radius:10px;padding:8px 11px}.view{display:none;padding:29px 0 16px;animation:appear .18s ease}.view.active{display:block}@keyframes appear{from{opacity:.45;transform:translateY(3px)}to{opacity:1;transform:translateY(0)}}.page-head{display:flex;align-items:flex-end;justify-content:space-between;gap:20px;margin:4px 0 22px}.eyebrow{font-size:10px;font-weight:850;color:var(--teal);letter-spacing:.17em;text-transform:uppercase}.page-head h1{font-size:clamp(27px,3vw,37px);line-height:1.13;letter-spacing:-.05em;margin:9px 0 9px;font-weight:780}.page-head p{color:var(--muted);font-size:13px;line-height:1.7;margin:0;max-width:760px}.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border:1px solid transparent;border-radius:11px;padding:11px 15px;background:linear-gradient(105deg,#a9caff,#70decf);color:#091624;font-size:12px;font-weight:850;white-space:nowrap}.btn:hover{transform:translateY(-1px);filter:brightness(1.05)}.btn.secondary{background:#16253a;color:#dfeaff;border-color:#314663}.btn.ghost{background:transparent;border-color:#2a3c54;color:#bacbe0}.btn.small{padding:8px 11px;font-size:11px}.btn.block{width:100%}.hero{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(240px,.6fr);gap:15px;margin-bottom:18px}.hero-copy{position:relative;overflow:hidden;min-height:250px;border:1px solid #2d4563;border-radius:22px;padding:30px;background:radial-gradient(ellipse at 90% 0%,#254467aa,transparent 45%),linear-gradient(135deg,#14263c,#101a2a)}.hero-copy:after{content:"";position:absolute;width:210px;height:210px;border:1px solid #8cb7ec20;border-radius:50%;right:-70px;bottom:-130px;box-shadow:0 0 0 22px #8cb7ec08,0 0 0 48px #8cb7ec05}.hero-copy h2{max-width:670px;font-size:clamp(29px,3.4vw,45px);line-height:1.06;letter-spacing:-.055em;margin:14px 0 13px;position:relative;z-index:1}.hero-copy h2 span{color:var(--blue)}.hero-copy p{color:#aabbd1;max-width:670px;line-height:1.75;font-size:13px;margin:0;position:relative;z-index:1}.hero-actions{display:flex;flex-wrap:wrap;gap:9px;margin-top:22px;position:relative;z-index:1}.hero-aside{border:1px solid var(--line);border-radius:22px;background:linear-gradient(165deg,#121f31,#0d1624);padding:22px;display:flex;flex-direction:column;justify-content:space-between;min-height:250px}.aside-top{display:flex;align-items:center;justify-content:space-between;gap:12px}.aside-label{font-size:10px;color:#8ca1bc;font-weight:800;text-transform:uppercase;letter-spacing:.13em}.mini-icon{width:37px;height:37px;border:1px solid #33506c;border-radius:12px;display:grid;place-items:center;background:#14273a;color:var(--teal);font-size:18px}.hero-aside h3{font-size:21px;letter-spacing:-.03em;margin:18px 0 8px}.hero-aside p{font-size:12px;line-height:1.7;color:var(--muted);margin:0}.progress-track{height:5px;background:#1e2c40;border-radius:10px;overflow:hidden;margin:18px 0 8px}.progress-track span{display:block;width:0;height:100%;background:linear-gradient(90deg,#9fc3ff,#75e0cc);border-radius:10px}.aside-foot{display:flex;justify-content:space-between;gap:12px;font-size:10px;color:#8296b0}.grid{display:grid;gap:14px}.metrics{grid-template-columns:repeat(4,minmax(0,1fr));margin:0 0 24px}.metric{border:1px solid var(--line);border-radius:15px;background:linear-gradient(155deg,#101c2d,#0d1624);padding:18px;min-width:0}.metric-label{font-size:11px;color:#93a5bc;line-height:1.5}.metric-row{display:flex;align-items:end;justify-content:space-between;gap:10px;margin-top:12px}.metric-value{font-size:27px;font-weight:800;letter-spacing:-.055em;max-width:100%;overflow:hidden;text-overflow:ellipsis}.metric-note{color:#7289a6;font-size:10px;margin-top:5px;line-height:1.5}.metric-symbol{width:31px;height:31px;border-radius:10px;display:grid;place-items:center;background:#192d43;color:var(--blue);font-size:15px;flex-shrink:0}.section-title{display:flex;align-items:end;justify-content:space-between;gap:14px;margin:28px 0 14px}.section-title h2{font-size:18px;letter-spacing:-.03em;margin:0 0 5px}.section-title p{font-size:12px;color:var(--muted);margin:0;line-height:1.6}.card{border:1px solid var(--line);background:linear-gradient(160deg,#111d2d,#0c1523);border-radius:17px;padding:21px;min-width:0}.card h3{font-size:15px;letter-spacing:-.02em;margin:0 0 8px}.card .sub{font-size:12px;line-height:1.7;color:var(--muted);margin:0 0 16px}.service-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.service{padding:20px;border:1px solid var(--line);border-radius:16px;background:#0e1928;min-height:193px}.service .service-icon{width:39px;height:39px;border:1px solid #2e4966;background:#14263a;border-radius:12px;display:grid;place-items:center;color:var(--teal);font-size:18px;margin-bottom:16px}.service h3{font-size:14px;margin:0 0 8px}.service p{color:#94a7bf;font-size:12px;line-height:1.7;margin:0}.service .meta{margin-top:14px;color:#b3c9e5;font-size:10px;font-weight:750}.flow-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.flow-step{padding:18px;border:1px solid var(--line);border-radius:15px;background:#0c1625}.flow-step .number{font-size:10px;letter-spacing:.13em;color:var(--teal);font-weight:850}.flow-step h4{margin:9px 0 7px;font-size:13px}.flow-step p{margin:0;color:var(--muted);font-size:11px;line-height:1.65}.workspace{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:15px}.field{margin:13px 0}.field label{display:block;color:#b8c9de;font-size:10px;letter-spacing:.08em;font-weight:800;margin:0 0 7px}.field input,.field select,.field textarea{width:100%;padding:12px 13px;border:1px solid #2c3f58;border-radius:10px;background:#080f1b;color:var(--text)}.field input::placeholder{color:#6d8099}.field input[type=file]{font-size:12px}.notice{display:none;padding:12px 14px;border:1px solid #334a65;border-radius:11px;background:#102034;color:#d9e7fb;font-size:12px;line-height:1.6;white-space:pre-wrap;overflow-wrap:anywhere;margin-top:13px}.notice.show{display:block}.notice.error{border-color:#77434b;background:#28151e;color:#ffd3d3}.notice.good{border-color:#285e57;background:#102722;color:#c3f8e9}.report-empty{border:1px dashed #30425b;border-radius:13px;padding:25px;text-align:center;color:#8fa2bb;font-size:12px;line-height:1.7}.report-list{display:grid;gap:9px}.report-row{border:1px solid #243750;border-radius:12px;background:#0a1422;padding:13px}.report-row-head{display:flex;justify-content:space-between;align-items:center;gap:10px}.report-row strong{font-size:12px;text-transform:capitalize}.report-row small{display:block;margin-top:6px;color:#869ab4;font-size:10px;overflow-wrap:anywhere}.report-row button{margin-top:10px}.tag{display:inline-flex;align-items:center;padding:5px 8px;border:1px solid #314c65;background:#13283a;border-radius:999px;color:#b5d6ed;font-size:9px;font-weight:850;text-transform:uppercase;letter-spacing:.06em}.result-box{margin-top:12px;max-height:420px;overflow:auto;border:1px solid #293c53;background:#070d16;border-radius:12px;padding:14px;font-size:11px;line-height:1.7;white-space:pre-wrap;overflow-wrap:anywhere}.pricing{grid-template-columns:repeat(3,minmax(0,1fr));align-items:stretch}.price-card{border:1px solid var(--line);border-radius:17px;background:linear-gradient(160deg,#111d2c,#0b1421);padding:19px;display:flex;flex-direction:column;min-width:0}.price-card.featured{border-color:#4c7891;box-shadow:inset 0 0 0 1px #75e0cc17;background:linear-gradient(160deg,#14283a,#0c1624)}.price-card .plan-label{font-size:10px;font-weight:850;letter-spacing:.14em;color:#b8cae1}.price-card .price{font-size:33px;letter-spacing:-.06em;font-weight:850;margin:13px 0 3px}.price-card .once{font-size:10px;color:#8296b0}.price-card ul{padding-left:17px;margin:17px 0;flex:1;font-size:11px;line-height:1.85;color:#a7b7cc}.price-card li{padding-left:1px;margin:1px 0}.price-card .feature-note{font-size:11px;line-height:1.7;color:#91a5bf;margin:13px 0 3px}.price-card .btn{margin-top:13px;width:100%}.selected-plan{outline:2px solid var(--teal);outline-offset:2px}.plan-note{padding:14px 16px;border:1px solid #2e485f;border-radius:13px;background:#0d1d2c;color:#aabed5;font-size:11px;line-height:1.7;margin-bottom:15px}.settings-grid{grid-template-columns:minmax(0,1fr) minmax(0,1fr)}.setting-row{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:15px 0;border-top:1px solid #213148}.setting-row:first-of-type{border-top:0}.setting-row strong{font-size:12px;display:block;margin-bottom:5px}.setting-row p{font-size:11px;color:var(--muted);line-height:1.6;margin:0}.switch{width:43px;height:24px;position:relative;flex-shrink:0}.switch input{opacity:0;width:0;height:0}.switch-track{position:absolute;inset:0;border-radius:20px;background:#263750;border:1px solid #40516a;transition:.15s;cursor:pointer}.switch-track:before{content:"";position:absolute;width:16px;height:16px;left:3px;top:3px;border-radius:50%;background:#a7b8ce;transition:.15s}.switch input:checked+.switch-track{background:#1a6559;border-color:#4ba998}.switch input:checked+.switch-track:before{transform:translateX(18px);background:#d1fff3}.account-big{display:flex;align-items:center;gap:13px;padding:5px 0 18px}.account-big .avatar{width:43px;height:43px;font-size:15px}.account-email{font-size:13px;font-weight:800;overflow-wrap:anywhere}.account-caption{font-size:11px;color:var(--muted);margin-top:5px}.security-list{display:grid;gap:10px}.security-item{display:flex;align-items:flex-start;gap:10px;color:#a8b9ce;font-size:11px;line-height:1.65}.security-check{color:var(--teal);font-size:14px}.footer{display:flex;justify-content:space-between;gap:14px;flex-wrap:wrap;padding-top:20px;margin-top:28px;border-top:1px solid #1a2a40;color:#687d96;font-size:10px;line-height:1.7}.compact .card,.compact .service,.compact .metric{padding:14px}.compact .view{padding-top:20px}.hidden{display:none!important}
@media(max-width:1080px){.app{grid-template-columns:218px minmax(0,1fr)}.main{padding:0 22px 30px}.hero{grid-template-columns:minmax(0,1fr)}.hero-aside{min-height:190px}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.service-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:760px){.app{display:block}.sidebar{position:fixed;left:0;top:0;bottom:0;width:255px;height:100dvh;transform:translateX(-105%);transition:transform .2s;box-shadow:15px 0 50px #0007}.sidebar.open{transform:translateX(0)}.main{padding:0 16px 28px}.topbar{height:66px}.mobile-menu{display:block}.breadcrumbs{display:none}.top-actions{gap:8px}.user-detail{display:none}.user-chip{padding-left:8px}.page-head{align-items:flex-start;flex-direction:column}.page-head .btn{align-self:stretch}.service-grid,.flow-grid,.workspace,.settings-grid,.pricing{grid-template-columns:1fr}.hero-copy{padding:23px;min-height:245px}.hero-copy h2{font-size:34px}.hero-aside{min-height:170px}.metrics{gap:9px}.metric{padding:14px}.metric-value{font-size:23px}.section-title{align-items:flex-start;flex-direction:column}.price-card{min-height:auto}.nav-overlay{display:none;position:fixed;inset:0;background:#02060bbb;z-index:19}.nav-overlay.open{display:block}}
@media(max-width:410px){.main{padding-left:12px;padding-right:12px}.env-pill{font-size:9px;padding:6px 8px}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.hero-copy h2{font-size:30px}.metric-value{font-size:21px}}
</style>
</head>
<body>
<div class="nav-overlay" id="navOverlay"></div>
<div class="app" id="appShell">
<aside class="sidebar" id="sidebar">
<div class="brand"><div class="brandmark">A</div><div><div class="brandname">AutoOps <span>Hub</span></div><div class="brandtag">Operations workspace</div></div></div>
<div><div class="nav-label">Workspace</div><nav class="nav" aria-label="Main navigation">
<button class="nav-link active" data-view="overview"><span class="ico">◫</span>Overview</button>
<button class="nav-link" data-view="jobs"><span class="ico">▤</span>Jobs &amp; Reports</button>
<button class="nav-link" data-view="billing"><span class="ico">◇</span>Billing &amp; Plans</button>
<button class="nav-link" data-view="settings"><span class="ico">⚙</span>Settings</button>
</nav></div>
<div class="sidebar-spacer"></div>
<div class="side-status"><div class="status-line"><span class="dot"></span><span id="sideEnvTitle">Sandbox environment</span></div><p id="sideEnvCopy">Test orders only. Live billing is not enabled for this workspace.</p></div>
<div class="side-foot">AUTOMATION WORKSPACE<br>Secure account · Private reports</div>
</aside>
<main class="main">
<header class="topbar"><div style="display:flex;align-items:center;gap:12px"><button class="mobile-menu" id="menuBtn" aria-label="Open navigation">☰</button><div class="breadcrumbs">AutoOps Hub <span style="color:#506680">/</span> <strong id="crumbTitle">Overview</strong></div></div><div class="top-actions"><span class="env-pill"><span class="dot"></span>Sandbox</span><div class="user-chip"><div class="avatar" id="topAvatar">A</div><div class="user-detail"><strong id="topUserName">Guest workspace</strong><small id="topUserMeta">Sign in to sync reports</small></div></div></div></header>
<section class="view active" id="view-overview" data-page="overview">
<div class="page-head"><div><div class="eyebrow">Workspace overview</div><h1>Good work starts with clean data.</h1><p>Run repeatable CSV cleanup jobs, inspect data-quality results, and keep every report linked to your account. Your workspace gives you one place to process, review, and retrieve the outputs.</p></div><button class="btn" id="overviewStartJob">＋ Create a cleanup job</button></div>
<div class="hero"><div class="hero-copy"><div class="eyebrow">DATA OPERATIONS · MADE PRACTICAL</div><h2>From raw spreadsheets to <span>decision-ready files.</span></h2><p>Standardize headers, normalize cell whitespace, remove blank or duplicate rows on eligible tiers, and produce a saved output with a transparent quality summary. No inflated promises — just a clear workflow and a report you can retrieve.</p><div class="hero-actions"><button class="btn" id="heroJobBtn">Start a CSV job <span>→</span></button><button class="btn secondary" id="heroPlansBtn">Compare plans</button></div></div>
<div class="hero-aside"><div><div class="aside-top"><span class="aside-label">Your operations</span><div class="mini-icon">⌁</div></div><h3 id="welcomeTitle">Your workspace, ready.</h3><p id="welcomeCopy">Sign in to link jobs, billing, and reports to your account. A CSV output is created only when you submit a valid file.</p><div class="progress-track"><span id="activityBar"></span></div><div class="aside-foot"><span>Job history</span><span id="activityLabel">Awaiting first report</span></div></div><button class="btn secondary block" id="heroReportsBtn">View job history →</button></div></div>
<div class="grid metrics">
<article class="metric"><div class="metric-label">Saved jobs</div><div class="metric-row"><div><div class="metric-value" id="metricJobs">—</div><div class="metric-note">Jobs in your report history</div></div><div class="metric-symbol">▤</div></div></article>
<article class="metric"><div class="metric-label">Current access</div><div class="metric-row"><div><div class="metric-value" id="metricTier" style="font-size:20px">Guest</div><div class="metric-note" id="metricTierNote">Sign in to view your tier</div></div><div class="metric-symbol">◇</div></div></article>
<article class="metric"><div class="metric-label">Latest report</div><div class="metric-row"><div><div class="metric-value" id="metricLatest" style="font-size:16px">—</div><div class="metric-note" id="metricLatestNote">No job completed yet</div></div><div class="metric-symbol">↗</div></div></article>
<article class="metric"><div class="metric-label">Payment mode</div><div class="metric-row"><div><div class="metric-value" style="font-size:20px">Sandbox</div><div class="metric-note">No live payments enabled</div></div><div class="metric-symbol">◎</div></div></article>
</div>
<div class="section-title"><div><h2>Capabilities in this workspace</h2><p>Features customers can use in the current CSV cleanup service.</p></div><button class="btn ghost small" data-go="billing">View plan limits</button></div>
<div class="grid service-grid">
<article class="service"><div class="service-icon">↔</div><h3>Normalize headers and values</h3><p>Clean header spacing, lowercase column labels, replace header spaces with underscores, and trim cell whitespace.</p><div class="meta">CORE CSV CLEANUP</div></article>
<article class="service"><div class="service-icon">✳</div><h3>Remove repeated noise</h3><p>Scale and Ultimate also remove fully blank rows and exact duplicate rows, then report per-column missing-value counts.</p><div class="meta">SCALE + ULTIMATE</div></article>
<article class="service"><div class="service-icon">⌕</div><h3>Inspect data quality</h3><p>Ultimate adds basic type inference and quality flags so missing-value patterns are more visible before downstream use.</p><div class="meta">ULTIMATE</div></article>
</div>
<div class="section-title"><div><h2>A transparent process</h2><p>Each step has a clear input and output.</p></div></div>
<div class="grid flow-grid"><article class="flow-step"><div class="number">01 / PREPARE</div><h4>Choose a plan and file</h4><p>Sign in, review row/job limits, and upload a CSV within your selected tier.</p></article><article class="flow-step"><div class="number">02 / PROCESS</div><h4>Run the cleanup</h4><p>The backend normalizes the data and applies the extra cleanup rules included in your tier.</p></article><article class="flow-step"><div class="number">03 / DELIVER</div><h4>Review and retrieve</h4><p>Inspect the output and report summary, then reopen it from your private job history.</p></article></div>
<div class="notice" id="accountNotice" role="status" aria-live="polite"></div>
</section>
<section class="view" id="view-jobs" data-page="jobs">
<div class="page-head"><div><div class="eyebrow">Execution centre</div><h1>Jobs &amp; reports</h1><p>Submit CSVs, Excel workbooks, JSON payloads, server logs, merchant catalogs, order exports, or user identity exports according to your selected tier. Retrieve completed results from your account history.</p></div><span class="tag">Multi-format engine</span></div>
<div class="workspace"><section class="card"><h3>Submit a new job</h3><p class="sub">Choose a supported file and workload. Basic supports CSV cleanup; Scale adds Excel, JSON and logs; Ultimate adds merchant, order and identity workloads.</p><div class="field"><label for="csv">INPUT FILE (.CSV, .XLSX, .XLS, .JSON, .LOG)</label><input id="csv" type="file" accept=".csv,.xlsx,.xls,.json,.log,text/csv,application/json,text/plain,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.ms-excel"></div><div class="field"><label for="operation">PROCESSING WORKLOAD</label><select id="operation"><option value="auto">Auto-detect by file type</option><option value="csv_clean">CSV header and whitespace cleanup</option><option value="excel_consolidate">Excel workbook consolidation (.xlsx/.xls)</option><option value="json_clean">JSON payload formatting and anomaly scan</option><option value="json_filter_anomalies">Filter JSON event arrays to error/anomaly records (Scale+)</option><option value="log_analyze">Server log and stack-trace analysis</option><option value="catalog_normalize">Merchant product catalog normalization (Ultimate)</option><option value="order_normalize">E-commerce order export normalization (Ultimate)</option><option value="identity_sanitize">User export email and duplicate identity sanitization (Ultimate)</option></select></div><button class="btn block" id="submitJobBtn">Process file &amp; generate report →</button><div class="notice" id="jobNotice" role="status" aria-live="polite"></div><div style="height:1px;background:var(--line);margin:20px 0"></div><h3>Supported processing</h3><div class="security-list"><div class="security-item"><span class="security-check">✓</span><span>CSV header and whitespace cleanup remains available.</span></div><div class="security-item"><span class="security-check">✓</span><span>Scale: multi-sheet workbook consolidation, JSON formatting, log parsing, deduplication, and missing-value analysis.</span></div><div class="security-item"><span class="security-check">✓</span><span>Ultimate: catalog, order and user export normalization with quality flags.</span></div></div></section>
<section class="card"><div class="section-title" style="margin:0 0 13px"><div><h3>Report history</h3><p>Only reports belonging to your account are shown.</p></div><button class="btn secondary small" id="refreshBtn">↻ Refresh</button></div><div id="reportList" class="report-empty">Sign in to load your private report history.</div><div id="reportResult"></div></section></div>
</section>
<section class="view" id="view-billing" data-page="billing">
<div class="page-head"><div><div class="eyebrow">Access &amp; billing</div><h1>Plans built around real work.</h1><p>Every plan includes the core CSV cleanup workflow. Higher tiers increase the permitted file size and add distinct cleanup and data-quality capabilities.</p></div><span class="env-pill"><span class="dot"></span>Sandbox checkout</span></div>
<div class="plan-note"><strong>Testing notice:</strong> These are the requested Sandbox one-time prices and job-credit packages, not recurring subscriptions. Sandbox transactions do not pay out real funds. Live billing remains disabled until production credentials and merchant ownership are verified.</div>
<div class="grid pricing">
<article class="price-card" data-price-tier="tier_1_51"><div class="plan-label">BASIC · ESSENTIAL CLEANUP</div><div class="price">$79</div><div class="once">USD · one-time Sandbox test purchase</div><p class="feature-note">For dependable, everyday CSV preparation.</p><ul><li>Standardize CSV headers and trim cell whitespace</li><li>Up to 2,500 data rows per file</li><li>30 jobs included per purchase</li><li>Private saved reports and cleaned CSV output</li><li>Historical report retrieval</li></ul><button class="btn plan-select" data-tier="tier_1_51">Select Basic</button></article>
<article class="price-card featured" data-price-tier="tier_2_83"><div class="plan-label">SCALE · TECHNICAL OPERATIONS</div><div class="price">$149</div><div class="once">USD · one-time Sandbox test purchase</div><p class="feature-note">For teams working with spreadsheets, JSON payloads and operational logs.</p><ul><li><b>Everything in Basic, plus:</b></li><li>Multi-sheet Excel (.xlsx) cleaning and consolidation</li><li>JSON payload formatting and error-field scan</li><li>Filter JSON event arrays to error/exception records</li><li>Server log parsing and structured stack-trace summaries</li><li>Blank-row removal, exact deduplication and missing-value counts</li><li>Up to 25,000 rows or entries per file</li><li>300 jobs included per purchase</li></ul><button class="btn plan-select" data-tier="tier_2_83">Select Scale</button></article>
<article class="price-card" data-price-tier="tier_3_129"><div class="plan-label">ULTIMATE · MERCHANT &amp; ENTERPRISE</div><div class="price">$299</div><div class="once">USD · one-time Sandbox test purchase</div><p class="feature-note">For high-volume catalogs, order exports, and data-quality review.</p><ul><li><b>Everything in Scale, plus:</b></li><li>Catalog SKU, price and inventory standardization for sync-ready exports (external store writes are not enabled)</li><li>Order price, currency, address and phone normalization</li><li>User export email validation and duplicate identity resolution</li><li>Deep type inference, anomaly detection and quality flags</li><li>Enterprise API route and retrievable historical reports</li><li>Up to 250,000 rows or entries per file</li><li>1,500 jobs included per purchase</li></ul><button class="btn plan-select" data-tier="tier_3_129">Select Ultimate</button></article>
</div>
<div class="workspace" style="margin-top:16px"><section class="card"><h3>Complete Sandbox checkout</h3><p class="sub">Sign in to AutoOps Hub first. You will then be redirected to PayPal Sandbox to approve the selected test order.</p><div class="field"><label for="tier">SELECT PLAN</label><select id="tier"><option value="tier_1_51">Basic — $79 USD</option><option value="tier_2_83">Scale — $149 USD</option><option value="tier_3_129">Ultimate — $299 USD</option></select></div><button class="btn block" id="checkoutBtn">Continue to PayPal Sandbox →</button><div class="notice" id="billingNotice" role="status" aria-live="polite"></div></section>
<section class="card"><h3>Billing clarity</h3><p class="sub">The current integration creates a one-time Sandbox order. Automatic renewals, invoices, refunds, tax calculation, and a customer-facing payment management portal are not represented as available features yet.</p><div class="security-list"><div class="security-item"><span class="security-check">✓</span><span>Order is created by the server and associated with the signed-in account.</span></div><div class="security-item"><span class="security-check">✓</span><span>Capture amount and plan are checked before a tier upgrade is applied.</span></div><div class="security-item"><span class="security-check">!</span><span>Live processing remains disabled until a complete end-to-end test and merchant verification.</span></div></div></section></div>
</section>
<section class="view" id="view-settings" data-page="settings">
<div class="page-head"><div><div class="eyebrow">Workspace control</div><h1>Settings</h1><p>Manage your current session and workspace preferences. Payment credentials are intentionally kept on the server rather than exposed in browser settings.</p></div><span class="tag">Account preferences</span></div>
<div class="grid settings-grid">
<section class="card"><h3>Account &amp; session</h3><p class="sub">Your signed-in identity and current access status.</p>
<div id="authControls"><div class="field"><label for="email">EMAIL ADDRESS</label><input id="email" type="email" autocomplete="email" placeholder="you@example.com"></div><div class="field"><label for="password">PASSWORD</label><input id="password" type="password" autocomplete="current-password" minlength="10" placeholder="At least 10 characters"></div><button class="btn block" id="signupBtn">Create account</button><button class="btn secondary block" id="loginBtn" style="margin-top:9px">Sign in</button><div class="sub" style="margin:12px 0 0">Use an email-confirmed account to create orders and save reports.</div></div>
<div id="signedInPanel" hidden><div class="account-big"><div class="avatar" id="settingsAvatar">A</div><div><div class="account-email" id="signedInLabel">Signed in</div><div class="account-caption" id="settingsAccountCaption">Authenticated workspace</div></div></div><button class="btn ghost block" id="logoutBtn">Sign out of this session</button></div>
<div class="notice" id="settingsAccountNotice" role="status" aria-live="polite"></div></section>
<section class="card"><h3>Workspace preferences</h3><p class="sub">These display preferences are saved in this browser; they do not change billing or permissions.</p>
<div class="setting-row"><div><strong>Compact workspace</strong><p>Reduce card spacing so more information fits on screen.</p></div><label class="switch"><input id="compactMode" type="checkbox"><span class="switch-track"></span></label></div>
<div class="setting-row"><div><strong>Show completed job details first</strong><p>Open the latest saved report automatically when loading history.</p></div><label class="switch"><input id="autoOpenLatest" type="checkbox"><span class="switch-track"></span></label></div>
<div class="notice show" id="preferenceNotice">Changes apply immediately and stay in this browser.</div></section>
<section class="card"><h3>Payment environment</h3><p class="sub">This customer workspace is connected to PayPal Sandbox. The dashboard must never store client secrets or merchant credentials in browser-accessible settings.</p><div class="setting-row"><div><strong>Active checkout mode</strong><p>PayPal Sandbox · one-time test orders only</p></div><span class="tag">Sandbox</span></div><div class="setting-row"><div><strong>Merchant receiving account</strong><p>Determined by the PayPal REST app and merchant configuration used by the server. Not verified as live.</p></div><span class="tag">Not verified</span></div><a href="https://dashboard.render.com/web/srv-db7kcpuk1f9s7382q7q0" class="btn secondary block" target="_blank" rel="noopener">Open server configuration in Render ↗</a></section>
<section class="card"><h3>Security &amp; privacy</h3><p class="sub">Controls that protect customer accounts and report history.</p><div class="security-list"><div class="security-item"><span class="security-check">✓</span><span>Account endpoints verify the Supabase session token server-side.</span></div><div class="security-item"><span class="security-check">✓</span><span>Report queries are scoped to the signed-in user's account.</span></div><div class="security-item"><span class="security-check">✓</span><span>PayPal client secrets belong in Render environment variables, never HTML, JavaScript, or public repository files.</span></div></div></section>
</div>
</section>
<footer class="footer"><span>AutoOps Hub · Operations workspace</span><span>Sandbox mode · No real payments are processed in this environment.</span></footer>
</main>
</div>
<script>
(function(){
'use strict';
const $=id=>document.getElementById(id);
const accountNotice=$('accountNotice'),jobNotice=$('jobNotice'),reportList=$('reportList'),reportResult=$('reportResult'),billingNotice=$('billingNotice'),settingsAccountNotice=$('settingsAccountNotice');
const authControls=$('authControls'),signedInPanel=$('signedInPanel'),signedInLabel=$('signedInLabel');
let currentUser=null,currentProfile=null,reportsCache=[],paymentMode='sandbox',paymentsEnabled=false;
async function configurePaymentMode(){
  const pill=document.querySelector('.env-pill');
  try{
    const health=await api('/api/v1/health');
    paymentMode=health.payment_mode||'sandbox';
    paymentsEnabled=health.paypal_checkout_enabled===true;
    if(pill)pill.innerHTML='<span class="dot"></span>'+(paymentMode==='live'?'Live payments':paymentMode==='sandbox'?'Sandbox':'Payment configuration invalid');
    const button=$('checkoutBtn');
    if(button&&!paymentsEnabled){button.title='Checkout is disabled until PayPal and database configuration are verified.';button.setAttribute('aria-disabled','true')}
    if(button&&paymentsEnabled){button.removeAttribute('aria-disabled');button.title='Continue to '+(paymentMode==='live'?'PayPal':'PayPal Sandbox')}
  }catch(e){
    paymentsEnabled=false;
    if(pill)pill.innerHTML='<span class="dot"></span>Payment status unavailable';
  }
}
function notice(el,message,type){if(!el)return;el.textContent=message;el.className='notice show'+(type?' '+type:'')}
function errorMessage(data,status){if(data&&typeof data.detail==='string')return data.detail;if(data&&data.detail&&typeof data.detail==='object')return data.detail.message||JSON.stringify(data.detail);if(data&&data.message)return data.message;return 'Request failed ('+status+'). Please try again.'}
async function api(path,options){const response=await fetch(path,Object.assign({credentials:'same-origin'},options||{}));let data={};try{data=await response.json()}catch(e){}if(!response.ok)throw new Error(errorMessage(data,response.status));return data}
async function busy(button,work){if(!button||button.disabled)return;const old=button.textContent;button.disabled=true;button.textContent='Working…';try{await work()}catch(e){const target=(button.id==='submitJobBtn'||button.id==='refreshBtn')?jobNotice:(button.id==='checkoutBtn'||button.classList.contains('plan-select'))?billingNotice:(button.id==='signupBtn'||button.id==='loginBtn'||button.id==='logoutBtn')?settingsAccountNotice:accountNotice;notice(target,e.message||'Something went wrong. Please try again.','error')}finally{button.disabled=false;button.textContent=old}}
function marketingAttribution(){const q=new URLSearchParams(window.location.search);let referrerHost='';try{referrerHost=window.document.referrer?new URL(window.document.referrer).hostname:''}catch(e){}const get=(key)=>{const v=q.get('utm_'+key);return v?v.slice(0,160):''};return {source:get('source')||'direct',medium:get('medium')||'none',campaign:get('campaign')||'unattributed',content:get('content'),term:get('term'),landing_path:(window.location.pathname||'/').slice(0,400),referrer_host:referrerHost.slice(0,160)}}
function credentials(){const email=$('email').value.trim(),password=$('password').value;if(!email||email.indexOf('@')<1)throw new Error('Enter a valid email address first.');if(password.length<10)throw new Error('Use a password of at least 10 characters.');return {email:email,password:password,marketing:marketingAttribution()}}
function setNavView(view){if(!$( 'view-'+view))view='overview';document.querySelectorAll('.view').forEach(el=>el.classList.toggle('active',el.id==='view-'+view));document.querySelectorAll('.nav-link').forEach(el=>el.classList.toggle('active',el.dataset.view===view));const names={overview:'Overview',jobs:'Jobs & Reports',billing:'Billing & Plans',settings:'Settings'};$('crumbTitle').textContent=names[view]||'Overview';if(window.location.hash!=='#'+view)history.replaceState({},'',window.location.pathname+window.location.search+'#'+view);$('sidebar').classList.remove('open');$('navOverlay').classList.remove('open');window.scrollTo({top:0,behavior:'smooth'})}
document.querySelectorAll('.nav-link').forEach(button=>button.addEventListener('click',()=>setNavView(button.dataset.view)));
document.querySelectorAll('[data-go]').forEach(button=>button.addEventListener('click',()=>setNavView(button.dataset.go)));
$('menuBtn').addEventListener('click',()=>{$('sidebar').classList.toggle('open');$('navOverlay').classList.toggle('open')});
$('navOverlay').addEventListener('click',()=>{$('sidebar').classList.remove('open');$('navOverlay').classList.remove('open')});
$('overviewStartJob').addEventListener('click',()=>setNavView('jobs'));$('heroJobBtn').addEventListener('click',()=>setNavView('jobs'));$('heroReportsBtn').addEventListener('click',()=>setNavView('jobs'));$('heroPlansBtn').addEventListener('click',()=>setNavView('billing'));
function setSignedInUI(data){currentUser=data.user;currentProfile=data.profile||{};const email=(data.user&&data.user.email)||'Signed-in user';const tier=currentProfile.current_tier||'free';const label=({'free':'Free','tier_1_51':'Basic','tier_2_83':'Scale','tier_3_129':'Ultimate'})[tier]||tier;authControls.hidden=true;signedInPanel.hidden=false;signedInLabel.textContent=email;$('settingsAccountCaption').textContent='Current access: '+label;$('settingsAvatar').textContent=(email[0]||'A').toUpperCase();$('topAvatar').textContent=(email[0]||'A').toUpperCase();$('topUserName').textContent=email;$('topUserMeta').textContent='Access tier: '+label;$('metricTier').textContent=label;$('metricTierNote').textContent='Authenticated account';$('welcomeTitle').textContent='Your workspace is connected.';$('welcomeCopy').textContent='Account: '+email+'. You can submit a CSV job, view saved reports, and choose a plan from Billing & Plans.';$('sideEnvTitle').textContent='Sandbox environment';$('sideEnvCopy').textContent='PayPal Sandbox test orders only. Live billing has not been enabled.'}
function setSignedOutUI(){currentUser=null;currentProfile=null;authControls.hidden=false;signedInPanel.hidden=true;$('topAvatar').textContent='A';$('topUserName').textContent='Guest workspace';$('topUserMeta').textContent='Sign in to sync reports';$('metricTier').textContent='Guest';$('metricTierNote').textContent='Sign in to view your tier';$('welcomeTitle').textContent='Your workspace, ready.';$('welcomeCopy').textContent='Sign in to link jobs, billing, and reports to your account. A CSV output is created only when you submit a valid file.'}
async function loadAccount(silent){try{const data=await api('/api/v1/auth/me');setSignedInUI(data);if(!silent)notice(accountNotice,'You are signed in. Choose a plan or run a CSV job.','good');if(settingsAccountNotice)notice(settingsAccountNotice,'Signed in as '+(data.user.email||data.user.id)+'.','good');return true}catch(e){setSignedOutUI();return false}}
async function authenticate(mode){const body=credentials();const data=await api('/api/v1/auth/'+mode,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(data.user){setNavView('overview');await loadAccount(true);await loadReports();notice(accountNotice,data.message||'Signed in successfully.','good')}else{notice(settingsAccountNotice,data.message||'Account created. Check your email to confirm it.','good')}}
async function logout(){await api('/api/v1/auth/logout',{method:'POST'});setSignedOutUI();reportsCache=[];reportList.className='report-empty';reportList.textContent='Sign in to load your private report history.';reportResult.replaceChildren();notice(settingsAccountNotice,'You have signed out. Sign in again to access your private reports or checkout.','good')}
async function checkout(){await configurePaymentMode();if(!paymentsEnabled)throw new Error('Checkout is disabled because payment or database readiness has not been verified. Please try again after the service is configured.');const signedIn=await loadAccount(true);if(!signedIn){setNavView('settings');throw new Error('Please sign in to AutoOps Hub first. The order will be linked to the account that is signed in.')}const data=await api('/api/v1/payments/paypal/order',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tier:$('tier').value,marketing:marketingAttribution()})});if(!data.approval_url)throw new Error('PayPal did not return an approval link. Check the configured credentials and try again.');let approval;try{approval=new URL(data.approval_url)}catch(e){throw new Error('PayPal returned an invalid approval URL. No redirect was attempted.')}const allowedHosts=paymentMode==='live'?['www.paypal.com','paypal.com']:['www.sandbox.paypal.com','sandbox.paypal.com'];if(approval.protocol!=='https:'||!allowedHosts.includes(approval.hostname))throw new Error('PayPal returned an approval URL for the wrong payment environment. No redirect was attempted.');notice(billingNotice,(paymentMode==='live'?'Live':'Sandbox')+' order created for 
async function captureReturned(){const orderId=new URLSearchParams(window.location.search).get('token');if(!orderId)throw new Error('No PayPal order token was found. Start checkout and return here after approving the Sandbox payment.');const data=await api('/api/v1/payments/paypal/capture',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({order_id:orderId})});window.history.replaceState({},'',window.location.pathname+'#billing');notice(billingNotice,data.message||'Payment verification completed.','good');await loadAccount(true);await loadReports()}
async function handleAuthCallback(){const hash=new URLSearchParams(window.location.hash.replace(/^#/,''));const query=new URLSearchParams(window.location.search);const accessToken=hash.get('access_token')||query.get('access_token');const authError=hash.get('error_description')||query.get('error_description')||hash.get('error')||query.get('error');if(authError)throw new Error('Email confirmation did not complete: '+authError.replace(/\+/g,' '));if(accessToken){const data=await api('/api/v1/auth/session',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({access_token:accessToken})});window.history.replaceState({},'',window.location.pathname+'#overview');notice(accountNotice,data.message||'Email confirmed. You are signed in.','good');await loadAccount(true);await loadReports();return true}if(query.get('auth')==='confirmed'){setNavView('settings');notice(settingsAccountNotice,'Email confirmation completed. Sign in below to continue.','good');window.history.replaceState({},'',window.location.pathname+'#settings');return true}return false}
function downloadReport(name,value,format){const ext=(format||'csv').toLowerCase()==='json'?'json':'csv';const blob=new Blob([value],{type:ext==='json'?'application/json;charset=utf-8':'text/csv;charset=utf-8'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=(name||'autoops-report').replace(/[^a-z0-9_.-]/gi,'_')+'.'+ext;document.body.append(a);a.click();a.remove();URL.revokeObjectURL(url)}
function showResult(title,value){reportResult.replaceChildren();const heading=document.createElement('h3');heading.textContent=title;heading.style.margin='16px 0 7px';reportResult.append(heading);let printable=value,download=null,format='csv';if(value&&typeof value==='object'){format=value.output_format||'csv';if(value.formatted_result){download=value.formatted_result;printable=JSON.stringify(value.summary||{rows_cleaned:value.rows_cleaned},null,2)+'\n\n'+value.formatted_result}else printable=JSON.stringify(value,null,2)}const pre=document.createElement('pre');pre.className='result-box';pre.textContent=typeof printable==='string'?printable:JSON.stringify(printable,null,2);reportResult.append(pre);if(download!==null){const button=document.createElement('button');button.className='btn secondary small';button.textContent='Download '+(format==='json'?'JSON result':'cleaned CSV');button.style.marginTop='10px';button.addEventListener('click',()=>downloadReport(title,download,format));reportResult.append(button)}}
async function submitJob(){const file=$('csv').files&&$('csv').files[0];if(!file)throw new Error('Choose a supported file before submitting the job.');const form=new FormData();form.append('file',file);form.append('operation',$('operation').value);const data=await api('/api/v1/automation/process-file',{method:'POST',body:form});notice(jobNotice,'Job completed. '+data.rows_cleaned+' row(s)/entry(ies) processed. Saved report ID: '+(data.job_id||'pending'),'good');showResult('Latest '+data.job_type.replace(/_/g,' ')+' report',data);await loadReports()}
async function loadReports(){if(!currentUser){reportList.className='report-empty';reportList.textContent='Sign in to load your private report history.';$('metricJobs').textContent='—';$('metricLatest').textContent='—';$('metricLatestNote').textContent='Sign in to view your reports';$('activityLabel').textContent='Awaiting account sign-in';$('activityBar').style.width='0%';return}try{const data=await api('/api/v1/jobs');const jobs=data.jobs||[];reportsCache=jobs;$('metricJobs').textContent=String(jobs.length);$('activityLabel').textContent=jobs.length?jobs.length+' saved report'+(jobs.length===1?'':'s'):'Awaiting first report';$('activityBar').style.width=Math.min(100,jobs.length*10)+'%';if(jobs.length){$('metricLatest').textContent=(jobs[0].job_type||'CSV job').replace(/_/g,' ');$('metricLatestNote').textContent=jobs[0].created_at?new Date(jobs[0].created_at).toLocaleDateString():'Latest saved job'}else{$('metricLatest').textContent='—';$('metricLatestNote').textContent='No job completed yet'}reportList.replaceChildren();if(!jobs.length){reportList.className='report-empty';reportList.textContent='No reports yet. Upload a CSV to create the first saved result.';return}reportList.className='report-list';jobs.forEach(job=>{const row=document.createElement('article');row.className='report-row';const head=document.createElement('div');head.className='report-row-head';const title=document.createElement('strong');title.textContent=(job.job_type||'Automation job').replace(/_/g,' ');const state=document.createElement('span');state.className='tag';state.textContent=job.status||'unknown';head.append(title,state);const meta=document.createElement('small');meta.textContent='Created: '+(job.created_at||'time unavailable')+' · Report ID: '+job.id;const view=document.createElement('button');view.className='btn secondary small';view.textContent='Open report';view.addEventListener('click',()=>busy(view,async()=>{const full=await api('/api/v1/jobs/'+encodeURIComponent(job.id));showResult('Report '+job.id,full.job.result);notice(jobNotice,'Saved report loaded.','good')}));row.append(head,meta,view);reportList.append(row)});if($('autoOpenLatest').checked&&jobs.length){const latest=await api('/api/v1/jobs/'+encodeURIComponent(jobs[0].id));showResult('Latest saved report',latest.job.result)}}catch(e){reportList.className='report-empty';reportList.textContent='Unable to load reports. '+e.message}}
function applyPreferences(){document.body.classList.toggle('compact',$('compactMode').checked);try{localStorage.setItem('autoops_compact',String($('compactMode').checked));localStorage.setItem('autoops_auto_latest',String($('autoOpenLatest').checked))}catch(e){}}
try{$('compactMode').checked=localStorage.getItem('autoops_compact')==='true';$('autoOpenLatest').checked=localStorage.getItem('autoops_auto_latest')==='true'}catch(e){}
$('compactMode').addEventListener('change',applyPreferences);$('autoOpenLatest').addEventListener('change',()=>{applyPreferences();if(currentUser)loadReports()});
$('signupBtn').addEventListener('click',()=>busy($('signupBtn'),()=>authenticate('signup')));
$('loginBtn').addEventListener('click',()=>busy($('loginBtn'),()=>authenticate('login')));
$('logoutBtn').addEventListener('click',()=>busy($('logoutBtn'),logout));
$('checkoutBtn').addEventListener('click',()=>busy($('checkoutBtn'),checkout));
$('submitJobBtn').addEventListener('click',()=>busy($('submitJobBtn'),submitJob));
$('refreshBtn').addEventListener('click',()=>busy($('refreshBtn'),loadReports));
document.querySelectorAll('.plan-select').forEach(button=>button.addEventListener('click',()=>{$('tier').value=button.dataset.tier;document.querySelectorAll('.price-card').forEach(card=>card.classList.toggle('selected-plan',card.dataset.priceTier===button.dataset.tier));document.querySelectorAll('.plan-select').forEach(b=>{b.textContent='Select '+({'tier_1_51':'Basic','tier_2_83':'Scale','tier_3_129':'Ultimate'})[b.dataset.tier];});button.textContent='Selected';notice(billingNotice,$('tier').selectedOptions[0].text+' selected. Continue to '+(paymentMode==='live'?'PayPal':'PayPal Sandbox')+' to create an order.','good');$('checkoutBtn').scrollIntoView({behavior:'smooth',block:'center'})}));
(async()=>{applyPreferences();setNavView((window.location.hash||'#overview').slice(1));try{if(await handleAuthCallback())return;const query=new URLSearchParams(window.location.search);if(query.get('payment')==='success'&&query.get('token')){setNavView('billing');await captureReturned();return}if(query.get('payment')==='cancelled'){setNavView('billing');notice(billingNotice,'PayPal checkout was cancelled. No payment was captured. You can choose a plan and try again.','error');window.history.replaceState({},'',window.location.pathname+'#billing')}const signed=await loadAccount(true);if(signed)await loadReports();else await loadReports()}catch(e){notice(accountNotice,e.message,'error')}})();
})();
</script>
</body>
</html>''')

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
    user_id = (auth_data.get("user") or {}).get("id")
    marketing = _marketing_fields(payload.get("marketing") or {})
    if user_id:
        _record_marketing_attribution(str(user_id), marketing)
        _record_marketing_event(str(user_id), f"signup:{user_id}", "signup_completed", marketing, metadata={"method": "email"})
    if auth_data.get("access_token"):
        _set_session_cookie(response, auth_data)
        return {"message": "Account created and signed in.", "user": {"id": user_id, "email": email}}
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


@app.get("/api/v1/marketing/report")
async def marketing_report(request: Request):
    """Return aggregate acquisition metrics only to the explicitly configured owner account."""
    user = await get_authenticated_user(request)
    admin_email = os.getenv("MARKETING_REPORT_ADMIN_EMAIL", "").strip().lower()
    if not admin_email:
        raise HTTPException(status_code=503, detail="Marketing reporting is not enabled until the owner email is configured.")
    if str(user.get("email", "")).strip().lower() != admin_email:
        raise HTTPException(status_code=403, detail="Marketing report access is restricted to the configured owner.")
    if not supabase:
        raise HTTPException(status_code=503, detail="Database is not connected.")
    try:
        result = supabase.table("marketing_events").select(
            "event_name,source,medium,campaign,value,currency,occurred_at"
        ).order("occurred_at", desc=True).limit(10000).execute()
        rows = result.data or []
        by_event: Dict[str, int] = {}
        by_channel: Dict[str, Dict[str, Any]] = {}
        revenue = 0.0
        for row in rows:
            event_name = str(row.get("event_name") or "unknown")
            by_event[event_name] = by_event.get(event_name, 0) + 1
            key = "|".join([
                str(row.get("source") or "direct"),
                str(row.get("medium") or "none"),
                str(row.get("campaign") or "unattributed"),
            ])
            channel = by_channel.setdefault(key, {
                "source": row.get("source") or "direct",
                "medium": row.get("medium") or "none",
                "campaign": row.get("campaign") or "unattributed",
                "signups": 0,
                "checkouts": 0,
                "purchases": 0,
                "revenue_usd": 0.0,
            })
            if event_name == "signup_completed":
                channel["signups"] += 1
            elif event_name == "checkout_started":
                channel["checkouts"] += 1
            elif event_name == "purchase_completed":
                channel["purchases"] += 1
                revenue += float(row.get("value") or 0)
                channel["revenue_usd"] += float(row.get("value") or 0)
        for channel in by_channel.values():
            channel["revenue_usd"] = round(channel["revenue_usd"], 2)
        return {
            "events_scanned": len(rows),
            "truncated": len(rows) == 10000,
            "events_by_name": by_event,
            "revenue_usd": round(revenue, 2),
            "channels": sorted(by_channel.values(), key=lambda item: (item["purchases"], item["signups"]), reverse=True),
            "note": "Counts include events recorded after attribution tracking was deployed; this is not retroactive and does not include social-platform impressions.",
        }
    except HTTPException:
        raise
    except Exception:
        logger.exception("Owner marketing report query failed.")
        raise HTTPException(status_code=503, detail="Marketing report data is temporarily unavailable.")


async def _paypal_access_token() -> str:
    _assert_paypal_runtime_ready()
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
        raise HTTPException(status_code=503, detail="PayPal authentication failed; verify the credentials belong to the selected environment and REST app.")

@app.post("/api/v1/payments/paypal/order")
async def create_paypal_order(request: Request, payload: Dict[str, Any]):
    user = await get_authenticated_user(request)
    if not supabase:
        raise HTTPException(status_code=503, detail="Database is not connected.")
    tier = str(payload.get("tier", ""))
    marketing = _marketing_fields(payload.get("marketing") or {})
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
        _record_marketing_attribution(str(user["user_id"]), marketing)
        _record_marketing_event(
            str(user["user_id"]), f"checkout:{order_id}", "checkout_started",
            marketing, value=float(amount), metadata={"tier": tier},
        )
        return {"order_id": order_id, "approval_url": approval, "tier": tier, "amount": amount, "currency": "USD"}
    except HTTPException:
        raise
    except Exception:
        logger.exception("PayPal order creation failed.")
        raise HTTPException(status_code=502, detail="Could not create a PayPal order. Check the configured PayPal environment and credentials, then retry.")

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
        _record_marketing_event(
            str(user["user_id"]), f"purchase:{cap['id']}", "purchase_completed",
            value=float(saved["amount"]), metadata={"tier": saved["tier"], "capture_id": cap["id"]},
        )
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
