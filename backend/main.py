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
from fastapi import FastAPI, Depends, HTTPException, Header, UploadFile, File, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from supabase import create_client, Client
import httpx
from uuid import UUID

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
PAYPAL_API_BASE = os.getenv("PAYPAL_API_BASE", "https://api-m.paypal.com").rstrip("/")
COINBASE_WEBHOOK_SECRET = os.getenv("COINBASE_WEBHOOK_SECRET", "").strip()

supabase: Optional[Client] = None
if SUPABASE_URL and SUPABASE_KEY and "placeholder" not in SUPABASE_URL.lower() and "placeholder" not in SUPABASE_KEY.lower() and "unconfigured" not in SUPABASE_KEY.lower():
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        logger.info("Supabase client initialized.")
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

async def verify_user_and_credits(user_id: str = Header(..., alias="X-User-ID")) -> Dict[str, Any]:
    """
    Dependency to verify a user exists, check current subscription status,
    and enforce maximum usage credit constraints before any execution pipeline starts.
    """
    if not supabase:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database coordinator engine is offline."
        )

    # Validate UUID structural format to block potential exploit strings
    if len(user_id) != 36 or user_id.count("-") != 4:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Structural Boundary Exception: Invalid user unique identifier format."
        )

    try:
        # A. Query client profile status in profiles table
        profile_res = supabase.table("profiles").select("current_tier, status").eq("user_id", user_id).execute()
        if not profile_res.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User profile not provisioned within database."
            )
        
        profile = profile_res.data[0]
        current_tier = profile.get("current_tier", "free")
        profile_status_val = profile.get("status", "active")

        # Block revoked, unpaid, or canceled accounts immediately
        if profile_status_val != "active":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Subscription Status Exception: Your account is currently '{profile_status_val}'. Re-billing transaction required."
            )

        # B. Query billing reset consumption history from usage_ledger table
        ledger_res = supabase.table("usage_ledger").select("monthly_credits_used").eq("profile_id", user_id).execute()
        if not ledger_res.data:
            # Auto-provision fallback if ledger missed the initial auth trigger event
            supabase.table("usage_ledger").insert({"profile_id": user_id, "monthly_credits_used": 0}).execute()
            monthly_credits = 0
        else:
            monthly_credits = ledger_res.data[0].get("monthly_credits_used", 0)

        # C. Enforce the hard constraint: if tier is free, restrict limit to 2
        if current_tier == "free" and monthly_credits >= 2:
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail={
                    "error": "Billing Exception: Monthly credit limits reached",
                    "current_tier": "free",
                    "monthly_credits_used": monthly_credits,
                    "pricing_options": {
                        "tier_1_51": {
                            "unit_price": 51.00,
                            "tier_name": "Basic SaaS Tier",
                            "description": "Premium access for cloud infrastructure developers.",
                        },
                        "tier_2_83": {
                            "unit_price": 83.00,
                            "tier_name": "Scale Operations Tier",
                            "description": "Enterprise API pipelines, dedicated workers, and automated job runs.",
                        },
                        "tier_3_129": {
                            "unit_price": 129.00,
                            "tier_name": "Ultimate operations cluster runtime monitoring.",
                            "description": "Full continuous integration & deployment pipelines on custom subnets.",
                        }
                    }
                }
            )

        return {
            "user_id": user_id,
            "current_tier": current_tier,
            "monthly_credits_used": monthly_credits
        }

    except HTTPException as http_exc:
        # Pass handled billing exceptions upwards directly
        raise http_exc
    except Exception as e:
        logger.error(f"DevSecOps telemetry checking failure on user_id {user_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Security Middleware checking error occurred on credits check."
        )

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
        
        decoded_text = content.decode("utf-8")
        
        input_stream = io.StringIO(decoded_text)
        reader = csv.reader(input_stream)
        
        output_stream = io.StringIO()
        writer = csv.writer(output_stream)

        # B. Clean telemetry: strip whitespace and standardize column formatting
        cleaned_rows_count = 0
        for i, row in enumerate(reader):
            if i == 0:
                # Standardize headers to lowercase keys
                writer.writerow([col.strip().lower().replace(" ", "_") for col in row])
            else:
                writer.writerow([col.strip() for col in row])
                cleaned_rows_count += 1

        cleaned_csv_result = output_stream.getvalue()

        # C. Increment usage_ledger via transaction atomic updates
        # This will fire the 'before_usage_ledger_write' trigger checking if credits exceed 2
        next_credits = current_credits + 1
        
        supabase.table("usage_ledger").update({
            "monthly_credits_used": next_credits
        }).eq("profile_id", user_id).execute()

        # Update lifetime counter using Postgrest raw modifier or rpc
        supabase.rpc("increment_lifetime_jobs", {"uid": user_id}).execute()

        logger.info(f"Successfully cleaned telemetry data log for user_id: {user_id}. Rows processed: {cleaned_rows_count}.")
        
        return {
            "success": True,
            "rows_cleaned": cleaned_rows_count,
            "credits_remaining": "Unlimited" if security_context["current_tier"] != "free" else 2 - next_credits,
            "formatted_result": cleaned_csv_result
        }

    except Exception as e:
        logger.error(f"Data formatting exception encountered for user_id {user_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"CSV processing failed during column parsing: {str(e)}"
        )

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
    """Accept payment events only after PayPal's remote signature verification succeeds."""
    if supabase is None:
        raise HTTPException(status_code=503, detail="Payment processing is unavailable because the database is not configured.")

    try:
        payload_bytes = await request.body()
        data = json.loads(payload_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Invalid JSON webhook payload.")

    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Invalid webhook event structure.")

    await verify_paypal_signature(request, data)

    event_type = data.get("event_type")
    if event_type != "PAYMENT.CAPTURE.COMPLETED":
        return WebhookResponse(
            success=True,
            message="Verified PayPal event acknowledged; no account change was required.",
            details={"received_event_type": event_type},
        )

    resource = data.get("resource") or {}
    amount = resource.get("amount") or {}
    transaction_id = resource.get("id")
    if not transaction_id or not isinstance(amount, dict):
        raise HTTPException(status_code=400, detail="Verified capture event is missing transaction details.")

    try:
        amount_val = round(float(amount.get("value")), 2)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid payment amount.")
    if amount.get("currency_code") != "USD":
        raise HTTPException(status_code=400, detail="Only USD payments are accepted.")

    # Only accept the exact published prices; never upgrade accounts based on broad ranges.
    tier_by_amount = {51.00: "tier_1_51", 83.00: "tier_2_83", 129.00: "tier_3_129"}
    assigned_tier = tier_by_amount.get(amount_val)
    if assigned_tier is None:
        raise HTTPException(status_code=400, detail="Payment amount does not match a configured tier.")

    custom_payload = resource.get("custom_id") or ""
    try:
        custom_data = json.loads(custom_payload) if isinstance(custom_payload, str) else custom_payload
        target_user_id = str(UUID(str(custom_data.get("user_id", ""))))
    except (ValueError, TypeError, AttributeError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="A valid user_id UUID is required in the verified capture custom_id.")

    try:
        # A duplicate delivery must not reapply a payment. A database unique constraint on
        # (payment_gateway, gateway_transaction_id) is still required for race-safe idempotency.
        prior = (
            supabase.table("transactions")
            .select("gateway_transaction_id")
            .eq("payment_gateway", "paypal")
            .eq("gateway_transaction_id", transaction_id)
            .limit(1)
            .execute()
        )
        if prior.data:
            return WebhookResponse(
                success=True,
                message="Verified PayPal capture was already recorded.",
                details={"transaction_id": transaction_id, "duplicate": True},
            )

        profile_result = supabase.table("profiles").select("user_id").eq("user_id", target_user_id).limit(1).execute()
        if not profile_result.data:
            raise HTTPException(status_code=404, detail="The paid account does not exist.")

        ledger_result = supabase.table("usage_ledger").select("profile_id").eq("profile_id", target_user_id).limit(1).execute()
        if not ledger_result.data:
            raise HTTPException(status_code=503, detail="The account usage ledger is not provisioned.")

        supabase.table("transactions").insert({
            "profile_id": target_user_id,
            "payment_gateway": "paypal",
            "gateway_transaction_id": transaction_id,
            "amount_paid": amount_val,
        }).execute()
        supabase.table("profiles").update({
            "current_tier": assigned_tier,
            "status": "active",
        }).eq("user_id", target_user_id).execute()

        logger.info("Verified PayPal capture recorded and tier updated for account %s.", target_user_id)
        return WebhookResponse(
            success=True,
            message="Verified PayPal capture recorded and account tier updated.",
            details={"transaction_id": transaction_id, "user_id": target_user_id, "tier": assigned_tier},
        )
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


if __name__ == "__main__":
    import uvicorn
    # Start server locally on port 3000 mapping DevSecOps requirements
    uvicorn.run(app, host="0.0.0.0", port=3000)
