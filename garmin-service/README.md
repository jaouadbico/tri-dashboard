# garmin-connect-service

**Status: scaffolded, not deployed.** Nothing here is reachable by anyone
yet. This is Option 2 from the Strava/WHOOP/Garmin connect-page design
discussion: a small private Python service that does Garmin login/sync,
called by a Supabase Edge Function that can't run Python itself.

## Why this exists

Garmin has no public OAuth API. `garminconnect`/`garth` work by driving
Garmin's own internal mobile-app login flow, which isn't documented and
isn't stable. Supabase Edge Functions run Deno/TypeScript, which can't run
this Python library — so instead of reimplementing Garmin's undocumented
login flow from scratch in TypeScript, this service wraps the existing,
working Python code and exposes it over a small private HTTP API.

## Security model

- **The password is never persisted, anywhere.** It's used in-memory,
  only inside `/login`, only for the duration of that one call. What gets
  stored (in Supabase, via Vault — see `../supabase/schema.sql`) is the
  resulting **token bundle** (`garminconnect`'s internal session state,
  refreshable for a long time without the password), the same category of
  thing as a Strava/WHOOP OAuth token, not a raw credential.
- **Two structurally separate code paths** (see `garmin_client.py`'s
  docstring for the full reasoning):
  - `start_login()`/`resume_login_mfa()` — fresh login. Needs email +
    password (+ possibly an MFA code). This is the path at risk if Garmin
    changes their auth flow again.
  - `pull_data()` — takes an already-stored token bundle, never touches
    email/password/MFA at all. `garminconnect` refreshes the session
    automatically as needed using only the stored token. **This path is
    designed to keep working for already-connected users even if
    `start_login()` breaks upstream later** — they're independent code
    paths, not just independently tested.
- **This service is not public-facing.** Every request must carry
  `X-Internal-Secret` matching `INTERNAL_API_SECRET` — only the Supabase
  Edge Function is meant to ever call it, never a browser directly.

## ⚠️ Upstream breakage risk — read this before relying on it

The standalone `garth` library (which `garminconnect` used to depend on
directly) is **officially deprecated** as of this writing. Per the
maintainer's own deprecation notice: Garmin recently changed their auth
flow in a way that broke the mobile-login approach garth relied on, and
the maintainer doesn't have capacity to adapt it. No official replacement
exists; community workarounds include browser User-Agent spoofing,
Playwright-driven headless-browser login, and TLS-fingerprint
impersonation via `curl_cffi`.

**What this means for this service, concretely:**

- The `pull_data()` / refresh path is not affected by this — it doesn't
  do a fresh login, so it isn't exposed to whatever in the SSO flow broke.
- The `start_login()` path (new users connecting for the first time) is
  exactly the code path this breakage would hit.

**Reassuring evidence, not just theory:**

1. The installed `garminconnect==0.3.11` (verified 2026-09-16) already
   runs a **5-strategy cascading login chain** internally
   (`mobile+cffi`, `mobile+requests`, `widget+cffi`, `portal+cffi`,
   `portal+requests`) — the `+cffi` strategies use `curl_cffi` for TLS
   fingerprint impersonation, i.e. exactly one of the community
   workarounds the garth deprecation notice points to. This library has
   already adapted, independent of garth.
2. **Empirically tested** on 2026-09-16: a real fresh login (existing
   cached token deliberately removed first) succeeded, including an MFA
   challenge, after first hitting Garmin's rate limiter (HTTP 429) —
   confirming both that fresh login currently works, and that repeated
   login attempts get rate-limited by Garmin. Don't build retry logic
   that hammers `/login`; surface the 429 to the user and back off.

**Action item if this ever breaks**: check `garminconnect`'s GitHub repo
for a newer release before assuming a from-scratch fix is needed — the
maintainer has already shown they patch around Garmin's changes.

## Known limitation: single process only

The in-progress MFA state (`PENDING_LOGINS` in `main.py`) is a **live
Python object held in memory**, not a serializable token — that's how
`garminconnect`'s own `resume_login()` API works, not a shortcut taken
here. A friend's "here's my MFA code" request must land on the same
process instance that handled their `/login` call. Fine for personal-scale
deployment (a single Fly.io/Render instance, no autoscaling); would need a
shared session store (e.g. Redis) before ever running more than one
worker/replica.

## API

All endpoints require header `X-Internal-Secret: <INTERNAL_API_SECRET>`.

- `POST /login` — `{email, password}` → `{status: "connected", token_bundle}`
  or `{status: "mfa_required", session_id}`
- `POST /login/mfa` — `{session_id, code}` → same shape as `/login`'s success
- `POST /sync` — `{token_bundle, days?}` → `{status: "ok", updated_token_bundle, wellness, activities}`
  or `{status: "reauth_required"}` (token no longer valid — caller must
  prompt the user through `/login` again, from scratch)
- `GET /health`

## Running locally

```bash
cd garmin-service
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in INTERNAL_API_SECRET
export $(cat .env | xargs)
uvicorn main:app --reload
```

## Not done yet

- Not deployed anywhere (Fly.io/Render, per the earlier options discussion).
- No rate-limiting/backoff on our own `/login` beyond surfacing Garmin's 429.
- No persistence check for `PENDING_LOGINS` growing unbounded beyond the
  5-minute sweep (fine at this scale, revisit if that ever changes).
- **TODO — don't forget**: the Garmin card on the Connect page needs a
  small disclosure note before a friend enters their password — this is
  an unofficial, community-maintained integration (not a Garmin-sanctioned
  one), and they should know that before connecting. Flagged here now per
  request; not written yet since the Connect page itself doesn't exist yet.
