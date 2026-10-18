// Strava OAuth callback — Strava redirects here after the user approves
// (or denies) access, with ?code=...&state=... in the query string.
//
// NOT YET RUN OR DEPLOYED. Written against Supabase's documented Edge
// Function conventions and Strava's documented OAuth token-exchange API,
// but unlike the Python service, this hasn't been executed anywhere —
// there's no Deno runtime available to test it locally in this session.
// Deploy with `supabase functions deploy strava-callback --no-verify-jwt`
// and test against a real flow before trusting it.
//
// Two modes, branched on whether the matched oauth_states row has a
// user_id:
//   - CONNECT (user_id present): an already-signed-in user linking their
//     Strava account. Unchanged from before — exchange code, upsert the
//     connection, redirect with a plain status query param.
//   - LOGIN (user_id is NULL): "Continue with Strava" — no signed-in user
//     yet. After the token exchange, the Strava athlete id must be on the
//     allowed_athletes allowlist (invite-only); find-or-create a Supabase
//     user for that athlete, upsert the connection, mint a real session
//     server-side (generateLink + verifyOtp — there's no direct "create a
//     session for user X" admin call), and redirect with the session
//     tokens in the URL FRAGMENT, never a query string (fragments are
//     never sent to or logged by any server, including GitHub Pages).
//     Full-page redirect only for now — popup/postMessage mode comes later.
//
// Required secrets (`supabase secrets set ...`): STRAVA_CLIENT_ID,
// STRAVA_CLIENT_SECRET. SUPABASE_URL, SUPABASE_ANON_KEY, and
// SUPABASE_SERVICE_ROLE_KEY are injected automatically into every Edge
// Function — no need to set those. Optional: APP_REDIRECT_URL (defaults
// to the tri-dashboard connect page).

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const STRAVA_CLIENT_ID = Deno.env.get("STRAVA_CLIENT_ID")!;
const STRAVA_CLIENT_SECRET = Deno.env.get("STRAVA_CLIENT_SECRET")!;
const APP_REDIRECT_URL = Deno.env.get("APP_REDIRECT_URL") ??
  "https://jaouadbico.github.io/connect.html";

// How long a pending oauth_states row is trusted. Generous, since it only
// bounds "how long between clicking Connect/Continue and finishing
// Strava's consent screen" — not a security-critical window (the state is
// single-use regardless of age).
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

// Login success only: tokens (and, for first-time sign-ins, the athlete's
// name for onboarding prefill) travel in the fragment, never the query
// string — never sent to, or logged by, any server.
function redirectWithSession(
  accessToken: string,
  refreshToken: string,
  firstName: string,
  lastName: string,
) {
  const url = new URL(APP_REDIRECT_URL);
  const parts = [
    `access_token=${encodeURIComponent(accessToken)}`,
    `refresh_token=${encodeURIComponent(refreshToken)}`,
  ];
  if (firstName) parts.push(`strava_first_name=${encodeURIComponent(firstName)}`);
  if (lastName) parts.push(`strava_last_name=${encodeURIComponent(lastName)}`);
  url.hash = parts.join("&");
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

  const isLogin = stateRow.user_id === null;

  let tokenData: {
    access_token: string;
    refresh_token: string;
    expires_at: number;
    athlete?: { id?: number; firstname?: string; lastname?: string };
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

  const athleteId = tokenData.athlete?.id != null ? String(tokenData.athlete.id) : null;

  // --- CONNECT mode ---
  if (!isLogin) {
    const { error: upsertErr } = await admin.rpc("upsert_connection", {
      p_user_id: stateRow.user_id,
      p_provider: "strava",
      p_access_token: tokenData.access_token,
      p_refresh_token: tokenData.refresh_token,
      p_expires_at: new Date(tokenData.expires_at * 1000).toISOString(),
      p_scope: url.searchParams.get("scope"),
      p_provider_athlete_id: athleteId,
    });
    if (upsertErr) {
      console.error("upsert_connection failed:", upsertErr);
      // 23505 = unique_violation on connections(provider, provider_athlete_id)
      // — this Strava athlete is already linked to a DIFFERENT Supabase user
      // (upsert_connection only looks up by user_id+provider, so it can't
      // detect this itself before inserting). A clear, specific reason
      // instead of the generic one.
      if (upsertErr.code === "23505") {
        return redirectTo("error", { reason: "athlete_already_linked" });
      }
      return redirectTo("error", { reason: "storage_failed" });
    }
    return redirectTo("connected");
  }

  // --- LOGIN mode: "Continue with Strava" ---
  if (!athleteId) {
    return redirectTo("error", { reason: "no_athlete_id" });
  }

  const { data: allowedRow, error: allowedErr } = await admin
    .from("allowed_athletes")
    .select("provider_athlete_id")
    .eq("provider_athlete_id", athleteId)
    .maybeSingle();
  if (allowedErr) {
    console.error("allowed_athletes check failed:", allowedErr);
    return redirectTo("error", { reason: "internal_error" });
  }
  if (!allowedRow) {
    // Clear, specific reason — connect.html should show this as "not
    // invited", not a generic failure.
    return redirectTo("error", { reason: "not_invited" });
  }

  // Find-or-create: an athlete who already has a connections row (e.g.
  // previously signed in, or an owner who connected before login mode
  // existed) resolves to that same user — never a new one.
  const { data: existingConn, error: existingErr } = await admin
    .from("connections")
    .select("user_id")
    .eq("provider", "strava")
    .eq("provider_athlete_id", athleteId)
    .maybeSingle();
  if (existingErr) {
    console.error("connections lookup failed:", existingErr);
    return redirectTo("error", { reason: "internal_error" });
  }

  let userId: string;
  let userEmail: string;

  if (existingConn) {
    userId = existingConn.user_id;
    const { data: userResp, error: getUserErr } = await admin.auth.admin.getUserById(userId);
    if (getUserErr || !userResp?.user?.email) {
      console.error("getUserById failed:", getUserErr);
      return redirectTo("error", { reason: "internal_error" });
    }
    userEmail = userResp.user.email;
  } else {
    userEmail = `strava-${athleteId}@users.invalid`;
    const { data: created, error: createErr } = await admin.auth.admin.createUser({
      email: userEmail,
      email_confirm: true,
    });
    if (createErr || !created?.user) {
      console.error("createUser failed:", createErr);
      return redirectTo("error", { reason: "user_create_failed" });
    }
    userId = created.user.id;
  }

  const { error: upsertErr } = await admin.rpc("upsert_connection", {
    p_user_id: userId,
    p_provider: "strava",
    p_access_token: tokenData.access_token,
    p_refresh_token: tokenData.refresh_token,
    p_expires_at: new Date(tokenData.expires_at * 1000).toISOString(),
    p_scope: url.searchParams.get("scope"),
    p_provider_athlete_id: athleteId,
  });
  if (upsertErr) {
    console.error("upsert_connection failed:", upsertErr);
    return redirectTo("error", { reason: "storage_failed" });
  }

  // Mint a session server-side: no direct "create a session for user X"
  // admin call exists, so this is the documented workaround — generate a
  // magic-link token via the admin API, then redeem it immediately via a
  // plain (non-admin) client to get back a real access/refresh token pair.
  const { data: linkData, error: linkErr } = await admin.auth.admin.generateLink({
    type: "magiclink",
    email: userEmail,
  });
  if (linkErr || !linkData) {
    console.error("generateLink failed:", linkErr);
    return redirectTo("error", { reason: "session_mint_failed" });
  }

  const plainClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
  const { data: otpData, error: otpErr } = await plainClient.auth.verifyOtp({
    type: "magiclink",
    token_hash: linkData.properties.hashed_token,
  });
  if (otpErr || !otpData.session) {
    console.error("verifyOtp failed:", otpErr);
    return redirectTo("error", { reason: "session_mint_failed" });
  }

  // First/last name travel in the fragment alongside the session tokens,
  // same reasoning as the tokens themselves — never a query string, never
  // logged or sent to any server. Used once by onboarding.html to prefill
  // the display name; nothing new is stored server-side for this.
  const firstName = tokenData.athlete?.firstname ?? "";
  const lastName = tokenData.athlete?.lastname ?? "";

  return redirectWithSession(
    otpData.session.access_token,
    otpData.session.refresh_token,
    firstName,
    lastName,
  );
});
