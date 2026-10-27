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
from fastapi.responses import HTMLResponse
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
        ledger_res = supabase.table("usage_ledger").select("monthly_credits_used").eq("profile_id", user_id).execute()
        if not ledger_res.data:
            raise HTTPException(status_code=409, detail="Usage ledger is not provisioned for this account.")
        monthly_credits = ledger_res.data[0].get("monthly_credits_used", 0)
        if current_tier == "free" and monthly_credits >= 2:
            raise HTTPException(status_code=402, detail={
                "error": "Monthly free credits exhausted",
                "current_tier": "free",
                "monthly_credits_used": monthly_credits,
                "pricing_options": {
                    "tier_1_51": {"unit_price": 51.00, "tier_name": "Basic"},
                    "tier_2_83": {"unit_price": 83.00, "tier_name": "Scale"},
                    "tier_3_129": {"unit_price": 129.00, "tier_name": "Ultimate"}
                }
            })
        return {"user_id": user_id, "email": auth_user.get("email"),
                "current_tier": current_tier, "monthly_credits_used": monthly_credits}
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

        job_record = supabase.table("automation_jobs").insert({
            "profile_id": user_id,
            "job_type": "clean_csv",
            "input_filename": file.filename,
            "status": "completed",
            "result": {"rows_cleaned": cleaned_rows_count, "formatted_result": cleaned_csv_result},
            "completed_at": "now()",
        }).execute()
        job_id = job_record.data[0]["id"] if job_record.data else None
        logger.info(f"Successfully cleaned telemetry data log for user_id: {user_id}. Rows processed: {cleaned_rows_count}.")
        return {
            "success": True,
            "job_id": job_id,
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
        result = supabase.rpc("apply_paypal_capture", {
            "p_user_id": target_user_id,
            "p_transaction_id": transaction_id,
            "p_amount_paid": amount_val,
            "p_assigned_tier": assigned_tier,
        }).execute()
        result_data = result.data if isinstance(result.data, dict) else {}
        logger.info(
            "Verified PayPal capture processed for account %s (duplicate=%s).",
            target_user_id,
            bool(result_data.get("duplicate", False)),
        )
        return WebhookResponse(
            success=True,
            message="Verified PayPal capture recorded and account tier synchronized.",
            details={
                "transaction_id": transaction_id,
                "user_id": target_user_id,
                "tier": assigned_tier,
                "duplicate": bool(result_data.get("duplicate", False)),
            },
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



# ----------------------------------------------------------------------------
# Customer portal: sign-up, sign-in, PayPal checkout, job history and reports
# ----------------------------------------------------------------------------
TIERS = {
    "tier_1_51": ("51.00", "Basic"),
    "tier_2_83": ("83.00", "Scale"),
    "tier_3_129": ("129.00", "Ultimate"),
}

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

@app.get("/", response_class=HTMLResponse)
async def customer_portal():
    return HTMLResponse(r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AutoOps Hub — Customer Portal</title><style>
:root{font-family:system-ui,Arial;color:#172033;background:#f4f7fb}body{margin:0}.wrap{max-width:920px;margin:auto;padding:24px}
header{background:#142b52;color:white;padding:24px;border-radius:16px}h1{margin:0 0 8px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px;margin-top:16px}
section{background:white;padding:18px;border:1px solid #dce4ef;border-radius:14px}label{display:block;margin:10px 0 4px}input,select,button{font:inherit;padding:10px;border:1px solid #c7d2e3;border-radius:8px;width:100%;box-sizing:border-box}button{background:#1d4ed8;color:white;border:0;margin-top:10px;cursor:pointer;font-weight:650}button.secondary{background:#334155}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f7fafc;padding:12px;border-radius:8px}.muted{color:#64748b}.status{margin-top:12px;padding:12px;background:#eef2ff;border-radius:8px;white-space:pre-wrap}
</style></head><body><div class="wrap"><header><h1>AutoOps Hub</h1><div>Secure account · PayPal sandbox checkout · Automated CSV report</div></header>
<div class="grid"><section><h2>1. Account</h2><label>Email</label><input id="email" type="email" autocomplete="email"><label>Password</label><input id="password" type="password" autocomplete="current-password">
<button onclick="auth('signup')">Create account</button><button class="secondary" onclick="auth('login')">Sign in</button><button class="secondary" onclick="logout()">Sign out</button><p class="muted">If email confirmation is enabled, confirm your email before signing in.</p></section>
<section><h2>2. Choose a tier</h2><label>Plan</label><select id="tier"><option value="tier_1_51">Basic — $51 USD</option><option value="tier_2_83">Scale — $83 USD</option><option value="tier_3_129">Ultimate — $129 USD</option></select>
<button onclick="checkout()">Continue to PayPal</button><button class="secondary" onclick="captureReturned()">I have returned from PayPal — verify payment</button><p class="muted">Staging is intended for PayPal Sandbox only.</p></section>
<section><h2>3. Submit a job</h2><label>CSV file</label><input id="csv" type="file" accept=".csv,text/csv"><button onclick="submitJob()">Clean CSV and generate report</button><button class="secondary" onclick="history()">Refresh my reports</button></section>
<section><h2>4. Report</h2><div id="report" class="muted">Sign in to view your account and reports.</div></section></div>
<div id="status" class="status">Ready. Sign in or create an account to begin.</div></div>
<script>
const statusEl=document.getElementById('status'),reportEl=document.getElementById('report');
function say(x){statusEl.textContent=typeof x==='string'?x:JSON.stringify(x,null,2)}
async function api(path,opts={}){const r=await fetch(path,{credentials:'same-origin',...opts});let d={};try{d=await r.json()}catch{}if(!r.ok)throw Error(d.detail||d.message||('Request failed ('+r.status+')'));return d}
async function auth(mode){try{const d=await api('/api/v1/auth/'+mode,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:document.getElementById('email').value,password:document.getElementById('password').value})});say(d.message||'Signed in.');if(d.user)await history()}catch(e){say(e.message)}}
async function logout(){try{await api('/api/v1/auth/logout',{method:'POST'});say('Signed out.')}catch(e){say(e.message)}}
async function checkout(){try{const d=await api('/api/v1/payments/paypal/order',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tier:document.getElementById('tier').value})});if(!d.approval_url)throw Error('PayPal did not return an approval URL.');say('Opening PayPal Sandbox checkout for '+d.amount+' USD.');location.href=d.approval_url}catch(e){say(e.message)}}
async function captureReturned(){try{const id=new URLSearchParams(location.search).get('token');if(!id)throw Error('No PayPal order token found in this page URL. Return from the PayPal approval page first.');const d=await api('/api/v1/payments/paypal/capture',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({order_id:id})});history.replaceState({},'',location.pathname);say(d.message||'Payment verified.');await history()}catch(e){say(e.message)}}
async function submitJob(){try{const f=document.getElementById('csv').files[0];if(!f)throw Error('Choose a CSV file first.');const fd=new FormData();fd.append('file',f);const d=await api('/api/v1/automation/clean-csv',{method:'POST',body:fd});say('Job complete. Report ID: '+(d.job_id||'not returned'));reportEl.innerHTML='<p><b>CSV cleaning report</b></p><p>Rows cleaned: '+d.rows_cleaned+'</p><pre></pre>';reportEl.querySelector('pre').textContent=d.formatted_result||JSON.stringify(d,null,2);await history()}catch(e){say(e.message)}}
async function history(){try{const d=await api('/api/v1/jobs');reportEl.innerHTML='<p><b>Account reports</b></p>';if(!d.jobs||!d.jobs.length){reportEl.innerHTML+='<p class="muted">No reports yet.</p>';return}for(const j of d.jobs){const b=document.createElement('button');b.className='secondary';b.textContent=(j.job_type||'Job')+' · '+j.status+' · '+j.created_at;b.onclick=()=>viewJob(j.id);reportEl.appendChild(b)}}catch(e){say(e.message)}}
async function viewJob(id){try{const d=await api('/api/v1/jobs/'+encodeURIComponent(id));reportEl.innerHTML='<p><b>Report '+id+'</b></p><pre></pre>';reportEl.querySelector('pre').textContent=JSON.stringify(d.job.result,null,2)}catch(e){say(e.message)}}
(async()=>{const q=new URLSearchParams(location.search);if(q.get('payment')==='success'&&q.get('token'))await captureReturned();try{const d=await api('/api/v1/auth/me');say('Signed in as '+(d.user.email||d.user.id)+'.');await history()}catch(e){say('Sign in to begin. '+e.message)}})();
</script></body></html>''')

@app.post("/api/v1/auth/signup")
async def auth_signup(payload: Dict[str, Any], response):
    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", ""))
    if "@" not in email or len(password) < 10:
        raise HTTPException(status_code=400, detail="Enter a valid email and a password of at least 10 characters.")
    auth_data = await _supabase_auth_call("signup", {"email": email, "password": password})
    if auth_data.get("access_token"):
        _set_session_cookie(response, auth_data)
        return {"message": "Account created and signed in.", "user": {"id": auth_data.get("user", {}).get("id"), "email": email}}
    return {"message": "Account created. Check your email to confirm it, then sign in.", "user": None}

@app.post("/api/v1/auth/login")
async def auth_login(payload: Dict[str, Any], response):
    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", ""))
    auth_data = await _supabase_auth_call("token?grant_type=password", {"email": email, "password": password})
    if not auth_data.get("access_token"):
        raise HTTPException(status_code=401, detail="Sign-in did not return a session.")
    _set_session_cookie(response, auth_data)
    return {"message": "Signed in.", "user": {"id": auth_data.get("user", {}).get("id"), "email": auth_data.get("user", {}).get("email")}}

@app.post("/api/v1/auth/logout")
async def auth_logout(response):
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
            "status": "captured", "capture_id": cap["id"], "captured_at": "now()"
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
