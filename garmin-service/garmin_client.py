"""
Thin wrapper around python-garminconnect for the Garmin connect microservice.

Two structurally separate code paths, by design:
  - `start_login()` / `resume_login_mfa()` — fresh SSO login. Needs email +
    password (used only in-memory, never persisted) and possibly an MFA
    code. This is the path documented as at-risk upstream (see README) —
    it depends on Garmin's undocumented internal auth flow.
  - `pull_data()` — takes an existing token bundle (from `Garmin.login()`'s
    internal `client.dumps()`, persisted by the caller) and restores it via
    `Garmin(...).login(tokenstore=<json string>)`. This never touches
    email/password/MFA — it only holds an oauth1 token, which
    python-garminconnect refreshes automatically via a plain HTTP call when
    it's about to expire. So this path keeps working for an
    already-connected friend even if start_login() breaks later upstream.

Verified 2026-09 against the actually-installed garminconnect==0.3.11:
Garmin wraps its own client at `.client` (not `.garth` — that attribute
name from older code/examples no longer applies), and that inner client
exposes `.dumps()`/`.loads()`. `python-garminconnect` itself now runs a
5-strategy cascading login (including curl_cffi-based strategies) — visible
evidence it has already adapted to the Garmin auth changes that deprecated
the standalone `garth` package. Still worth re-verifying against whatever
version is installed if this starts failing (see README).
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from typing import Any

import garminconnect
from garminconnect import (
    GarminConnectAuthenticationError,
    GarminConnectConnectionError,
    GarminConnectTooManyRequestsError,
)

GARMIN_TYPE_TO_SPORT = {
    "running": "Run", "treadmill_running": "Run", "trail_running": "Run",
    "track_running": "Run", "indoor_running": "Run", "street_running": "Run",
    "cycling": "Bike", "road_biking": "Bike", "indoor_cycling": "Bike",
    "virtual_ride": "Bike", "mountain_biking": "Bike", "gravel_cycling": "Bike",
    "cyclocross": "Bike", "track_cycling": "Bike",
    "lap_swimming": "Swim", "open_water_swimming": "Swim", "pool_swim": "Swim",
    "strength_training": "Strength",
    "walking": "Recovery", "hiking": "Recovery",
}


class RateLimited(Exception):
    """Garmin's SSO endpoint is rate-limiting login attempts. Confirmed to
    happen in practice (not hypothetical) — surface this distinctly so the
    frontend can say "try again in a few minutes" instead of a generic
    failure."""


class ReauthRequired(Exception):
    """The stored token bundle is no longer usable (oauth1 token itself
    expired/revoked, or the API tier rejected it) — only a fresh login
    fixes this. Distinct from a transient failure: the caller should
    prompt the user to reconnect via the full login flow, not just retry."""


def start_login(email: str, password: str) -> tuple[str, garminconnect.Garmin | None]:
    """
    Begins a fresh SSO login. Returns (status, client):
      - ("connected", None) is never returned here — caller reads the bundle
        via client.client.dumps() when status == "connected".
      - status == "connected": login finished, client holds the session.
      - status == "mfa_required": caller must hold on to `client` (in
        memory, keyed by a session id) and call resume_login_mfa(client, code).
    """
    client = garminconnect.Garmin(email=email, password=password, return_on_mfa=True)
    try:
        mfa_status, _ = client.login()
    except GarminConnectTooManyRequestsError as e:
        raise RateLimited(str(e)) from e
    except GarminConnectAuthenticationError:
        raise
    except GarminConnectConnectionError:
        raise

    if mfa_status == "needs_mfa":
        return "mfa_required", client
    return "connected", client


def resume_login_mfa(client: garminconnect.Garmin, code: str) -> None:
    """
    Completes a login that returned "mfa_required" from start_login(). Must
    be called on the SAME `client` object start_login() returned — the
    pending MFA state lives on that object in memory, it is not a portable
    token you can hand to a different process. Raises on a wrong/expired
    code or if Garmin rate-limits the attempt.
    """
    try:
        client.resume_login(None, code)
    except GarminConnectTooManyRequestsError as e:
        raise RateLimited(str(e)) from e


def dump_bundle(client: garminconnect.Garmin) -> str:
    return client.client.dumps()


def pull_data(token_bundle: str, days: int = 7) -> dict:
    """
    Pulls the last `days` of wellness + activity data using an existing
    token bundle. Never performs a fresh login — no email/password/MFA
    involved at all. Returns the (possibly rotated, since
    python-garminconnect refreshes the session as needed) bundle alongside
    the data, so the caller can re-save it.
    """
    client = garminconnect.Garmin()  # no email/password: a poisoned/rejected
    # token here raises straight through instead of silently trying a
    # password-based re-login, which is exactly what we want in this path.
    try:
        client.login(tokenstore=token_bundle)
    except GarminConnectAuthenticationError as e:
        raise ReauthRequired(f"stored token rejected by Garmin: {e}") from e
    except GarminConnectTooManyRequestsError as e:
        raise RateLimited(str(e)) from e

    end = date.today()
    start = end - timedelta(days=days - 1)

    wellness = _pull_wellness(client, start, end)
    activities = _pull_activities(client, start, end)

    return {
        "updated_token_bundle": dump_bundle(client),
        "wellness": wellness,
        "activities": activities,
    }


def _pull_wellness(client: garminconnect.Garmin, start: date, end: date) -> list[dict]:
    records = []
    d = start
    while d <= end:
        iso = d.isoformat()
        record: dict[str, Any] = {"date": iso}
        try:
            summary = client.get_user_summary(iso)
            record["resting_hr"] = summary.get("restingHeartRate")
            record["steps"] = summary.get("totalSteps")
            record["stress_avg"] = summary.get("averageStressLevel")
        except Exception:
            pass
        records.append(record)
        d += timedelta(days=1)
    return records


def _pull_activities(client: garminconnect.Garmin, start: date, end: date) -> list[dict]:
    raw = client.get_activities_by_date(start.isoformat(), end.isoformat()) or []
    out = []
    for a in raw:
        sport = GARMIN_TYPE_TO_SPORT.get((a.get("activityType") or {}).get("typeKey"))
        if not sport:
            continue
        distance_m = a.get("distance") or 0
        out.append({
            "activityId": a.get("activityId"),
            "date": (a.get("startTimeLocal") or "")[:10],
            "sport": sport,
            "duration": round((a.get("duration") or 0) / 60, 1),
            "distance": round(distance_m / 1609.34, 2) if distance_m else None,
            "notes": a.get("activityName"),
        })
    return out
