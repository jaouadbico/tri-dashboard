#!/usr/bin/env bash
# One command for schema + function deploys. Requires the CLI already
# linked to the project (see README/onboarding notes for the one-time
# `supabase login` / `supabase link` commands).
set -euo pipefail
cd "$(dirname "$0")"

echo "==> Pushing schema migrations..."
supabase db push

echo "==> Deploying strava-callback (no JWT verification — public OAuth redirect)..."
supabase functions deploy strava-callback --no-verify-jwt

echo "==> Deploying strava-sync (JWT-verified)..."
supabase functions deploy strava-sync

echo "==> Done."
