// Pulls recent activities from Strava for the signed-in caller and stores
// them in the activities table. Called directly by the Connect page (a
// "Sync now" button), not by a third-party redirect — so unlike
// strava-callback, this function is deployed WITH normal JWT verification
// on (no --no-verify-jwt), and additionally verifies the caller explicitly
// below.
//
// NOT YET DEPLOYED — written for review before that happens, same as
// strava-callback was. Requires the upsert_connection coalesce fix in
// supabase/schema.sql (scope/provider_athlete_id must not be wiped on a
// token-only refresh) to be applied before this is used for real.
//
// Required secrets: STRAVA_CLIENT_ID, STRAVA_CLIENT_SECRET (already set).
// SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY are injected
// automatically into every Edge Function — nothing new to set for those.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const STRAVA_CLIENT_ID = Deno.env.get("STRAVA_CLIENT_ID")!;
const STRAVA_CLIENT_SECRET = Deno.env.get("STRAVA_CLIENT_SECRET")!;

const DEFAULT_LOOKBACK_DAYS = 30;
const MAX_LOOKBACK_DAYS = 90;
const PER_PAGE = 200;
const MAX_PAGES = 10; // safety cap: 2000 activities, far beyond any real 90-day window

const STRAVA_TYPE_TO_SPORT: Record<string, string> = {
  Run: "Run", TrailRun: "Run", VirtualRun: "Run",
  Ride: "Bike", VirtualRide: "Bike", MountainBikeRide: "Bike", GravelRide: "Bike", EBikeRide: "Bike",
  Swim: "Swim",
  WeightTraining: "Strength", Workout: "Strength", Crossfit: "Strength",
  Walk: "Recovery", Hike: "Recovery",
};

// Origin locked to the actual Connect page, not "*" — this function
// requires a real caller JWT regardless, but there's no reason to accept
// cross-origin calls from anywhere else either.
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "https://jaouadbico.github.io",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

type RefreshResult =
  | { ok: true; accessToken: string; refreshToken: string; expiresAt: number }
  | { ok: false; status: number };

async function refreshStravaToken(refreshToken: string): Promise<RefreshResult> {
  const resp = await fetch("https://www.strava.com/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: STRAVA_CLIENT_ID,
      client_secret: STRAVA_CLIENT_SECRET,
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    }),
  });
  if (resp.status === 429) {
    console.error("Strava token refresh rate-limited");
    return { ok: false, status: 429 };
  }
  if (!resp.ok) {
    console.error("Strava token refresh failed:", resp.status, await resp.text());
    return { ok: false, status: resp.status };
  }
  const data = await resp.json();
  return {
    ok: true,
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresAt: data.expires_at,
  };
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: CORS_HEADERS });
  }

  // --- Verify the caller's JWT ---
  // This function is deployed WITHOUT --no-verify-jwt, so Supabase's own
  // platform gateway already rejects any request with a missing or invalid
  // Authorization header before this code ever runs (the opposite of
  // strava-callback, which Strava calls with no auth header at all and is
  // deployed with --no-verify-jwt for exactly that reason). That platform
  // check confirms the token is valid but doesn't hand us the user — to
  // actually identify (and independently re-verify) the caller, the token
  // is extracted explicitly and passed straight to getUser(token), rather
  // than relying on a client configured with a global Authorization header
  // (which would silently use whatever ambient header state the client
  // happened to carry). Every exit on this path is fail-closed: a missing
  // header, a non-Bearer header, an empty token, a rejected token, or any
  // unexpected exception all return 401 the same way.
  const authHeader = req.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return json({ error: "missing_authorization" }, 401);
  }
  const token = authHeader.slice("Bearer ".length).trim();
  if (!token) {
    return json({ error: "missing_authorization" }, 401);
  }

  let userId: string;
  try {
    const callerClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
    const { data, error: userErr } = await callerClient.auth.getUser(token);
    if (userErr || !data.user) {
      return json({ error: "invalid_token" }, 401);
    }
    // userId has exactly one source — never a client-supplied body/query
    // param — so a caller can only ever sync their own data.
    userId = data.user.id;
  } catch (e) {
    console.error("getUser threw unexpectedly:", e);
    return json({ error: "invalid_token" }, 401);
  }

  let days = DEFAULT_LOOKBACK_DAYS;
  try {
    const body = await req.json();
    if (typeof body?.days === "number" && body.days > 0) days = body.days;
  } catch {
    // no/empty body is fine — use the default
  }
  days = Math.min(Math.max(Math.round(days), 1), MAX_LOOKBACK_DAYS);

  // --- Load the stored connection ---
  const { data: tokenRows, error: tokenErr } = await admin.rpc("get_decrypted_tokens", {
    p_user_id: userId,
    p_provider: "strava",
  });
  if (tokenErr) {
    console.error("get_decrypted_tokens failed:", tokenErr);
    return json({ status: "error", reason: "internal_error" }, 500);
  }
  const tokenRow = tokenRows?.[0];
  if (!tokenRow?.access_token) {
    return json({ status: "not_connected" }, 404);
  }

  let accessToken: string = tokenRow.access_token;
  const expiresAtMs = tokenRow.expires_at ? new Date(tokenRow.expires_at).getTime() : 0;
  const isExpired = Date.now() >= expiresAtMs;

  if (isExpired) {
    if (!tokenRow.refresh_token) {
      // Expired and nothing to refresh with — only a full reconnect fixes
      // this. Do not touch last_synced_at: nothing was synced.
      return json({ status: "reconnect_needed", reason: "no_refresh_token" });
    }

    const refreshResult = await refreshStravaToken(tokenRow.refresh_token);
    if (!refreshResult.ok) {
      if (refreshResult.status === 400 || refreshResult.status === 401) {
        // Strava rejected the refresh token itself — the connection is
        // dead; only a fresh OAuth consent (full reconnect) can fix it.
        // Explicitly NOT touching last_synced_at: nothing was synced, and
        // updating it would hide that this connection is broken.
        return json({ status: "reconnect_needed", reason: "refresh_rejected" });
      }
      if (refreshResult.status === 429) {
        return json({ status: "error", reason: "rate_limited" }, 429);
      }
      // Anything else (network error, Strava 5xx) is transient, not a
      // dead connection — distinct from reconnect_needed so the UI
      // doesn't wrongly tell the user their credentials are bad.
      return json({ status: "error", reason: "refresh_failed" }, 502);
    }

    accessToken = refreshResult.accessToken;

    // Persist BOTH rotated tokens immediately, before attempting the
    // activity pull — Strava refresh tokens can rotate on use, so if the
    // pull below failed first, we'd risk losing the only valid refresh
    // token we have.
    const { error: upsertErr } = await admin.rpc("upsert_connection", {
      p_user_id: userId,
      p_provider: "strava",
      p_access_token: refreshResult.accessToken,
      p_refresh_token: refreshResult.refreshToken,
      p_expires_at: new Date(refreshResult.expiresAt * 1000).toISOString(),
      p_scope: null,              // preserved via coalesce in upsert_connection
      p_provider_athlete_id: null, // preserved via coalesce in upsert_connection
    });
    if (upsertErr) {
      console.error("upsert_connection (token rotation) failed:", upsertErr);
      return json({ status: "error", reason: "storage_failed" }, 500);
    }
  }

  // --- Pull activities, paginated, bounded to MAX_LOOKBACK_DAYS ---
  const afterEpochSeconds = Math.floor((Date.now() - days * 24 * 60 * 60 * 1000) / 1000);
  const allActivities: Record<string, unknown>[] = [];
  let rateLimitedMidway = false;

  for (let page = 1; page <= MAX_PAGES; page++) {
    const resp = await fetch(
      `https://www.strava.com/api/v3/athlete/activities?after=${afterEpochSeconds}&per_page=${PER_PAGE}&page=${page}`,
      { headers: { Authorization: `Bearer ${accessToken}` } },
    );

    // Strava reports real usage on every response, success or not — format
    // is "15-min,daily" for both. Logged so a backfill's actual rate-limit
    // consumption can be checked afterward via `supabase functions logs
    // strava-sync`, instead of guessing from request counts.
    const rlLimit = resp.headers.get("X-RateLimit-Limit");
    const rlUsage = resp.headers.get("X-RateLimit-Usage");
    if (rlLimit || rlUsage) {
      console.log(`Strava rate limit — limit: ${rlLimit}, usage: ${rlUsage} (page ${page})`);
    }

    if (resp.status === 429) {
      console.error("Strava activities fetch rate-limited on page", page);
      rateLimitedMidway = true;
      break; // keep whatever pages we already fetched rather than discard them
    }
    if (!resp.ok) {
      if (resp.status === 401) {
        return json({ status: "reconnect_needed", reason: "access_token_rejected" });
      }
      console.error("Strava activities fetch failed:", resp.status, await resp.text());
      return json({ status: "error", reason: "activities_fetch_failed" }, 502);
    }

    const pageActivities: Record<string, unknown>[] = await resp.json();
    allActivities.push(...pageActivities);
    if (pageActivities.length < PER_PAGE) break; // last page reached
  }

  const rows = [];
  for (const a of allActivities) {
    // Anything not explicitly mapped falls through to Cross rather than
    // being dropped — matches this app's existing vocabulary elsewhere
    // (Cross = "Cross-training, soccer, etc."), and means a sync can never
    // silently lose an activity just because its Strava type isn't one
    // we've named yet.
    const sport = STRAVA_TYPE_TO_SPORT[a.type as string] ?? "Cross";
    const distanceM = (a.distance as number) || 0;
    rows.push({
      user_id: userId,
      provider: "strava",
      provider_activity_id: String(a.id),
      date: String(a.start_date_local ?? a.start_date ?? "").slice(0, 10),
      sport,
      // elapsed_time, not moving_time — matches the existing convention
      // (Garmin's "duration" field elsewhere in this app is total elapsed
      // time including pauses, not moving-only time).
      duration: a.elapsed_time != null ? Math.round(((a.elapsed_time as number) / 60) * 10) / 10 : null,
      distance: distanceM ? Math.round((distanceM / 1609.34) * 100) / 100 : null,
      notes: a.name ?? null,
      raw_payload: a,
    });
  }

  if (rows.length > 0) {
    const { error: activitiesUpsertErr } = await admin
      .from("activities")
      .upsert(rows, { onConflict: "user_id,provider,provider_activity_id" });
    if (activitiesUpsertErr) {
      console.error("activities upsert failed:", activitiesUpsertErr);
      return json({ status: "error", reason: "activities_storage_failed" }, 500);
    }
  }

  // Only now, after a genuinely successful pull (even zero new activities
  // counts as a completed sync, not a failure), do we touch last_synced_at.
  // A mid-pagination rate limit still counts as completed: the unique
  // constraint on provider_activity_id makes re-fetching the same fixed
  // window next time a harmless no-op for whatever was already saved.
  const { error: touchErr } = await admin
    .from("connections")
    .update({ last_synced_at: new Date().toISOString() })
    .eq("user_id", userId)
    .eq("provider", "strava");
  if (touchErr) {
    console.error("last_synced_at update failed:", touchErr);
    return json({ status: "ok", activities_synced: rows.length, warning: "last_synced_at_not_updated" });
  }

  return json({
    status: "ok",
    activities_synced: rows.length,
    ...(rateLimitedMidway ? { warning: "rate_limited_partial_sync" } : {}),
  });
});
