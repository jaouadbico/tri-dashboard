// Strava OAuth callback — Strava redirects here after the user approves
// (or denies) access, with ?code=...&state=... in the query string.
//
// NOT YET RUN OR DEPLOYED. Written against Supabase's documented Edge
// Function conventions and Strava's documented OAuth token-exchange API,
// but unlike the Python service, this hasn't been executed anywhere —
// there's no Deno runtime available to test it locally in this session.
// Deploy with `supabase functions deploy strava-callback` and test against
// a real Connect Strava click before trusting it.
//
// Flow:
//   1. Verify `state` against oauth_states (one-time use — deleted here
//      regardless of what happens after, so it can never be replayed).
//   2. Exchange `code` for tokens via Strava's token endpoint, server-side
//      only — this is the step that needs the client secret.
//   3. Store the tokens via upsert_connection() (Vault-backed, service-role
//      only — see supabase/schema.sql).
//   4. Redirect the browser back to the Connect page with a status.
//
// Required secrets (`supabase secrets set ...`): STRAVA_CLIENT_ID,
// STRAVA_CLIENT_SECRET. SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are
// injected automatically into every Edge Function — no need to set those.
// Optional: APP_REDIRECT_URL (defaults to the tri-dashboard connect page).

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const STRAVA_CLIENT_ID = Deno.env.get("STRAVA_CLIENT_ID")!;
const STRAVA_CLIENT_SECRET = Deno.env.get("STRAVA_CLIENT_SECRET")!;
const APP_REDIRECT_URL = Deno.env.get("APP_REDIRECT_URL") ??
  "https://jaouadbico.github.io/connect.html";

// How long a pending oauth_states row is trusted. Generous, since it only
// bounds "how long between clicking Connect and finishing Strava's consent
// screen" — not a security-critical window (the state is single-use and
// tied to a specific user regardless of age).
const STATE_MAX_AGE_MS = 10 * 60 * 1000;

const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

function redirectTo(status: "connected" | "error", extra?: Record<string, string>) {
  const url = new URL(APP_REDIRECT_URL);
  url.searchParams.set("provider", "strava");
  url.searchParams.set("status", status);
  if (extra) {
    for (const [k, v] of Object.entries(extra)) url.searchParams.set(k, v);
  }
  return Response.redirect(url.toString(), 302);
}

Deno.serve(async (req: Request) => {
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const stravaError = url.searchParams.get("error");

  // User clicked "Cancel" on Strava's consent screen.
  if (stravaError) {
    return redirectTo("error", { reason: "denied" });
  }
  if (!code || !state) {
    return redirectTo("error", { reason: "missing_params" });
  }

  const { data: stateRow, error: stateErr } = await admin
    .from("oauth_states")
    .select("user_id, created_at")
    .eq("state", state)
    .eq("provider", "strava")
    .maybeSingle();

  if (stateErr || !stateRow) {
    return redirectTo("error", { reason: "invalid_state" });
  }

  // Consume it immediately — one-time use, regardless of what happens next.
  await admin.from("oauth_states").delete().eq("state", state);

  const ageMs = Date.now() - new Date(stateRow.created_at as string).getTime();
  if (ageMs > STATE_MAX_AGE_MS) {
    return redirectTo("error", { reason: "state_expired" });
  }

  let tokenData: {
    access_token: string;
    refresh_token: string;
    expires_at: number;
    athlete?: { id?: number };
  };
  try {
    const tokenResp = await fetch("https://www.strava.com/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: STRAVA_CLIENT_ID,
        client_secret: STRAVA_CLIENT_SECRET,
        code,
        grant_type: "authorization_code",
      }),
    });
    if (!tokenResp.ok) {
      console.error("Strava token exchange failed:", tokenResp.status, await tokenResp.text());
      return redirectTo("error", { reason: "token_exchange_failed" });
    }
    tokenData = await tokenResp.json();
  } catch (e) {
    console.error("Strava token exchange threw:", e);
    return redirectTo("error", { reason: "token_exchange_failed" });
  }

  const { error: upsertErr } = await admin.rpc("upsert_connection", {
    p_user_id: stateRow.user_id,
    p_provider: "strava",
    p_access_token: tokenData.access_token,
    p_refresh_token: tokenData.refresh_token,
    p_expires_at: new Date(tokenData.expires_at * 1000).toISOString(),
    p_scope: url.searchParams.get("scope"),
    p_provider_athlete_id: tokenData.athlete?.id != null ? String(tokenData.athlete.id) : null,
  });

  if (upsertErr) {
    console.error("upsert_connection failed:", upsertErr);
    return redirectTo("error", { reason: "storage_failed" });
  }

  return redirectTo("connected");
});
