"""
Garmin connect microservice — NOT DEPLOYED YET. See README.md before running
this anywhere real users can reach it.

Exists because Supabase Edge Functions run Deno/TypeScript and can't run
python-garminconnect, which is what actually knows how to log into Garmin
(there's no public Garmin OAuth API to call directly). This service is the
only thing that ever sees a user's Garmin password, and only in memory,
only for the duration of the login call — see garmin_client.py's docstring
for the two-path design (fresh login vs. token-bundle refresh) that keeps
those separate.

Auth: every request must carry `X-Internal-Secret` matching INTERNAL_API_SECRET.
This is a private service meant to be called only by the Supabase Edge
Function, never by a browser directly.
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Optional

import garminconnect
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from garmin_client import (
    RateLimited,
    ReauthRequired,
    dump_bundle,
    pull_data,
    resume_login_mfa,
    start_login,
)

app = FastAPI(title="garmin-connect-service")

INTERNAL_API_SECRET = os.environ.get("INTERNAL_API_SECRET")

# session_id -> (live Garmin client object, created_at). The pending MFA
# state lives ON that object in memory (garminconnect's own design, not
# ours) — it cannot be serialized or resumed from a different process. This
# means: single worker process only. Do not deploy this behind more than
# one instance/replica without moving to a shared session store first, or
# a friend's "enter MFA code" request may land on a process that never saw
# their /login call.
PENDING_LOGINS: dict[str, tuple[garminconnect.Garmin, float]] = {}
PENDING_TTL_SECONDS = 5 * 60


def _sweep_expired_pending() -> None:
    now = time.time()
    for sid in [s for s, (_, ts) in PENDING_LOGINS.items() if now - ts > PENDING_TTL_SECONDS]:
        PENDING_LOGINS.pop(sid, None)


def verify_secret(x_internal_secret: Optional[str] = Header(default=None)) -> None:
    if not INTERNAL_API_SECRET:
        raise HTTPException(500, "INTERNAL_API_SECRET is not configured on this service")
    if x_internal_secret != INTERNAL_API_SECRET:
        raise HTTPException(401, "invalid or missing X-Internal-Secret")


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    status: str  # "connected" | "mfa_required"
    session_id: Optional[str] = None
    token_bundle: Optional[str] = None


class MfaRequest(BaseModel):
    session_id: str
    code: str


class SyncRequest(BaseModel):
    token_bundle: str
    days: int = 7


class SyncResponse(BaseModel):
    status: str  # "ok" | "reauth_required"
    updated_token_bundle: Optional[str] = None
    wellness: Optional[list] = None
    activities: Optional[list] = None


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/login", response_model=LoginResponse)
def login(req: LoginRequest, _=Depends(verify_secret)):
    _sweep_expired_pending()
    try:
        status, client = start_login(req.email, req.password)
    except RateLimited:
        raise HTTPException(429, "Garmin is rate-limiting login attempts right now — wait a few minutes and try again.")
    except garminconnect.GarminConnectAuthenticationError as e:
        raise HTTPException(401, f"Garmin rejected the email/password: {e}")
    except garminconnect.GarminConnectConnectionError as e:
        raise HTTPException(502, f"Could not reach Garmin: {e}")

    if status == "mfa_required":
        session_id = str(uuid.uuid4())
        PENDING_LOGINS[session_id] = (client, time.time())
        return LoginResponse(status="mfa_required", session_id=session_id)

    return LoginResponse(status="connected", token_bundle=dump_bundle(client))


@app.post("/login/mfa", response_model=LoginResponse)
def submit_mfa(req: MfaRequest, _=Depends(verify_secret)):
    entry = PENDING_LOGINS.pop(req.session_id, None)
    if not entry:
        raise HTTPException(404, "This connect session has expired or doesn't exist — start over from Connect Garmin.")
    client, _started_at = entry
    try:
        resume_login_mfa(client, req.code)
    except RateLimited:
        raise HTTPException(429, "Garmin is rate-limiting login attempts right now — wait a few minutes and try again.")
    except Exception as e:
        raise HTTPException(401, f"MFA code rejected or expired: {e}")

    return LoginResponse(status="connected", token_bundle=dump_bundle(client))


@app.post("/sync", response_model=SyncResponse)
def sync(req: SyncRequest, _=Depends(verify_secret)):
    try:
        result = pull_data(req.token_bundle, days=req.days)
    except ReauthRequired:
        return SyncResponse(status="reauth_required")
    except RateLimited:
        raise HTTPException(429, "Garmin is rate-limiting requests right now — try again shortly.")

    return SyncResponse(
        status="ok",
        updated_token_bundle=result["updated_token_bundle"],
        wellness=result["wellness"],
        activities=result["activities"],
    )
