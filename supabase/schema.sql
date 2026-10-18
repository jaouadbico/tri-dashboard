-- Tri Dashboard — Connect Your Accounts foundation
-- Run this once in the Supabase SQL editor (Project → SQL Editor → New query)
-- after creating your project. Safe to re-run (uses IF NOT EXISTS / OR REPLACE).
--
-- OAuth tokens are stored via Supabase Vault (pgsodium-backed), not as plain
-- columns. `connections` holds only a reference (uuid) into vault.secrets —
-- the actual token text never sits in a plain, dashboard-browsable column.
-- If `create extension supabase_vault` below fails with a permission error,
-- enable it instead via Database → Extensions in the dashboard, then re-run
-- the rest of this script.

create extension if not exists pgcrypto;
create extension if not exists supabase_vault;

-- Postgres grants EXECUTE on every new function to PUBLIC by default, and
-- Supabase's own project setup separately grants it to
-- anon/authenticated/service_role on every new function in this schema —
-- both fire automatically at creation time. This is exactly how
-- upsert_connection and get_decrypted_tokens ended up callable by
-- anonymous requests despite an explicit per-function revoke sitting in
-- this file: the file was correct, but the live database had never been
-- re-run against it since that fix was added.
--
-- Both statements below are required, not redundant: per Postgres's own
-- docs, a schema-scoped ALTER DEFAULT PRIVILEGES only adds to the global
-- default — it cannot override or narrow it. The first (global, no IN
-- SCHEMA) removes the PUBLIC-on-every-function baseline; the second
-- (schema-scoped) additionally removes Supabase's own
-- anon/authenticated grant for this schema. Neither is retroactive — they
-- only affect functions created after this runs, which is why the
-- explicit per-function revokes elsewhere in this file still matter for
-- the functions that already exist.
alter default privileges revoke execute on functions from public;
alter default privileges in schema public revoke execute on functions from anon, authenticated;

-- One row per (user, provider) OAuth connection. access_token_id /
-- refresh_token_id point into vault.secrets; the plaintext tokens are never
-- stored on this table. RLS below means the frontend can't read this table
-- at all regardless — Vault is a second, independent layer on top of that.
create table if not exists connections (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  provider text not null check (provider in ('strava', 'whoop')),
  access_token_id uuid not null references vault.secrets(id),
  refresh_token_id uuid references vault.secrets(id),
  expires_at timestamptz,
  scope text,
  provider_athlete_id text,
  connected_at timestamptz not null default now(),
  last_synced_at timestamptz,
  -- Set by strava-sync when a refresh/access-token attempt is rejected by
  -- the provider — only a fresh OAuth consent (reconnect) fixes it. Cleared
  -- by upsert_connection on any successful connect/token-rotation, and by
  -- strava-sync on any successful pull.
  needs_reconnect boolean not null default false,
  unique (user_id, provider)
);

-- For a database where `connections` already existed before needs_reconnect
-- was added above — create table if not exists is a no-op there, so the
-- column has to be added explicitly for anyone upgrading in place.
alter table connections add column if not exists needs_reconnect boolean not null default false;

alter table connections enable row level security;

-- Intentionally NO row-level policies on `connections`. With RLS enabled and
-- zero policies, the `anon` and `authenticated` client roles get zero access
-- to this table — no SELECT, INSERT, UPDATE, or DELETE, from any frontend
-- request, no matter whose row it is. Edge Functions use the service_role
-- key, which ignores RLS entirely, so they're unaffected by this.

-- Defense in depth: explicitly deny the client roles access to Vault's own
-- tables/views too, so nothing here relies solely on Supabase's defaults.
revoke all on vault.secrets from anon, authenticated;
revoke all on vault.decrypted_secrets from anon, authenticated;

-- When a connection row is deleted (via disconnect_provider, or cascaded
-- from a deleted auth.users row), delete its Vault secrets too — otherwise
-- encrypted tokens for a disconnected/deleted account linger forever with
-- no owning row.
create or replace function cleanup_connection_secrets()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  delete from vault.secrets where id = old.access_token_id;
  if old.refresh_token_id is not null then
    delete from vault.secrets where id = old.refresh_token_id;
  end if;
  return old;
end;
$$;

-- AFTER, not BEFORE: a BEFORE DELETE trigger tries to delete the
-- vault.secrets row while the connections row referencing it (via
-- access_token_id/refresh_token_id, both FKs into vault.secrets) still
-- exists — Postgres correctly refuses that as a foreign-key violation,
-- blocking the connections delete entirely. AFTER DELETE fires once the
-- connections row is actually gone, so the now-orphaned secret can be
-- removed without violating anything. Found via a real delete that
-- wouldn't go through.
drop trigger if exists connections_cleanup_secrets on connections;
create trigger connections_cleanup_secrets
  after delete on connections
  for each row
  execute function cleanup_connection_secrets();

-- Safe, read-only status the Connect page IS allowed to see: which
-- providers are connected and when — never the tokens themselves.
-- Postgres refuses `create or replace` across a return-type change (it
-- errors with "cannot change return type of existing function"), so an
-- upgrade from the earlier 3-column version needs an explicit drop first.
drop function if exists get_my_connections();
create or replace function get_my_connections()
returns table (provider text, connected_at timestamptz, last_synced_at timestamptz, needs_reconnect boolean)
language sql
security definer
set search_path = public
as $$
  select provider, connected_at, last_synced_at, needs_reconnect
  from connections
  where user_id = auth.uid();
$$;

-- NOTE: Supabase projects auto-grant EXECUTE on every new public-schema
-- function directly to `anon` and `authenticated` (an ALTER DEFAULT
-- PRIVILEGES rule set up at project creation) — separate from, and not
-- removed by, revoking from PUBLIC. Anon must be revoked explicitly.
revoke execute on function get_my_connections() from public, anon;
grant execute on function get_my_connections() to authenticated;

-- Lets a signed-in user disconnect their own provider. Safe to expose
-- directly — it only ever deletes the caller's own row (auth.uid()), and
-- the trigger above cleans up the associated Vault secrets automatically.
create or replace function disconnect_provider(p_provider text)
returns void
language sql
security definer
set search_path = public
as $$
  delete from connections
  where user_id = auth.uid() and provider = p_provider;
$$;

revoke execute on function disconnect_provider(text) from public, anon;
grant execute on function disconnect_provider(text) to authenticated;

-- ---------------------------------------------------------------------
-- Edge-Function-only functions below. These take an explicit p_user_id
-- (rather than relying on auth.uid()) because the Edge Function acts on
-- behalf of whichever user's OAuth callback it's handling — so they must
-- NEVER be callable by anon/authenticated (a malicious caller could pass
-- someone else's user_id). Only the service_role key can call these, since
-- service_role bypasses grants entirely. The explicit revoke below MUST
-- name anon/authenticated directly, not just PUBLIC — Supabase projects
-- auto-grant EXECUTE on every new public-schema function straight to
-- anon/authenticated/service_role via an ALTER DEFAULT PRIVILEGES rule set
-- at project creation, and revoking from PUBLIC alone does not touch that
-- separate, direct grant.
-- ---------------------------------------------------------------------

-- Creates or updates a user's connection for a provider, storing tokens in
-- Vault (rotating the existing secret in place on update, rather than
-- leaving the old one orphaned).
create or replace function upsert_connection(
  p_user_id uuid,
  p_provider text,
  p_access_token text,
  p_refresh_token text,
  p_expires_at timestamptz,
  p_scope text,
  p_provider_athlete_id text
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  existing connections%rowtype;
  v_access_id uuid;
  v_refresh_id uuid;
begin
  select * into existing from connections
    where user_id = p_user_id and provider = p_provider;

  if found then
    perform vault.update_secret(existing.access_token_id, p_access_token);
    v_access_id := existing.access_token_id;

    if p_refresh_token is not null then
      if existing.refresh_token_id is not null then
        perform vault.update_secret(existing.refresh_token_id, p_refresh_token);
        v_refresh_id := existing.refresh_token_id;
      else
        v_refresh_id := vault.create_secret(p_refresh_token);
      end if;
    else
      v_refresh_id := existing.refresh_token_id;
    end if;

    -- last_synced_at is deliberately untouched here — this function is
    -- about token lifecycle (store/rotate credentials), not data freshness.
    -- Only the sync function itself sets last_synced_at, once a pull of
    -- actual activity data succeeds.
    -- coalesce, not a plain overwrite: a token-refresh call has no scope
    -- or athlete id to report (Strava's refresh response includes neither,
    -- only the original authorize exchange does) — passing null here must
    -- not erase what a successful connect already recorded.
    update connections set
      access_token_id = v_access_id,
      refresh_token_id = v_refresh_id,
      expires_at = p_expires_at,
      scope = coalesce(p_scope, existing.scope),
      provider_athlete_id = coalesce(p_provider_athlete_id, existing.provider_athlete_id),
      -- A successful connect or token rotation is itself proof the
      -- credentials work again — clear any earlier reconnect flag.
      needs_reconnect = false
    where id = existing.id;
  else
    v_access_id := vault.create_secret(p_access_token);
    v_refresh_id := case when p_refresh_token is not null
      then vault.create_secret(p_refresh_token) else null end;

    -- last_synced_at stays NULL until a real sync happens — connecting
    -- an account is not the same as having pulled any data from it yet.
    insert into connections (
      user_id, provider, access_token_id, refresh_token_id,
      expires_at, scope, provider_athlete_id, connected_at
    ) values (
      p_user_id, p_provider, v_access_id, v_refresh_id,
      p_expires_at, p_scope, p_provider_athlete_id, now()
    );
  end if;
end;
$$;

revoke execute on function
  upsert_connection(uuid, text, text, text, timestamptz, text, text)
  from public, anon, authenticated;

-- Returns decrypted tokens for a given user+provider — for the Edge
-- Function's own use when it needs to call Strava/WHOOP on the user's
-- behalf (syncing data, refreshing an expired token). Never exposed to
-- anon/authenticated.
create or replace function get_decrypted_tokens(p_user_id uuid, p_provider text)
returns table (access_token text, refresh_token text, expires_at timestamptz)
language sql
security definer
set search_path = public
as $$
  select
    (select decrypted_secret from vault.decrypted_secrets where id = c.access_token_id),
    (select decrypted_secret from vault.decrypted_secrets where id = c.refresh_token_id),
    c.expires_at
  from connections c
  where c.user_id = p_user_id and c.provider = p_provider;
$$;

revoke execute on function get_decrypted_tokens(uuid, text) from public, anon, authenticated;

-- Prevents pending OAuth handshakes from being hijacked or replayed. A row
-- is inserted right before redirecting to Strava/WHOOP, and consumed
-- (checked + deleted) by the Edge Function when the provider redirects back.
create table if not exists oauth_states (
  state text primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  provider text not null check (provider in ('strava', 'whoop')),
  created_at timestamptz not null default now()
);

alter table oauth_states enable row level security;
-- No row-level policies here — the frontend never reads or writes this
-- table directly. It creates a pending state only via create_oauth_state()
-- below (which inserts a row scoped to the caller's own auth.uid(), not
-- an arbitrary user), and only the Edge Function (service_role, which
-- bypasses RLS) reads/deletes it when the provider redirects back.

-- Called by the Connect page right before redirecting to Strava/WHOOP's
-- authorize URL. Generates a fresh random state, tied to the caller's own
-- id, and clears any of the caller's previous pending state for that
-- provider first (bounds each user to one in-flight attempt per provider
-- and self-cleans abandoned attempts — someone who closes the tab mid-flow
-- doesn't leave a row behind forever).
create or replace function create_oauth_state(p_provider text)
returns text
language plpgsql
security definer
-- pgcrypto (gen_random_bytes) may live in `extensions` rather than `public`
-- on newer Supabase projects — check both rather than assume.
set search_path = public, extensions
as $$
declare
  v_state text;
begin
  if p_provider not in ('strava', 'whoop') then
    raise exception 'invalid provider: %', p_provider;
  end if;

  delete from oauth_states where user_id = auth.uid() and provider = p_provider;

  v_state := encode(gen_random_bytes(32), 'hex');
  insert into oauth_states (state, user_id, provider) values (v_state, auth.uid(), p_provider);

  return v_state;
end;
$$;

revoke execute on function create_oauth_state(text) from public, anon;
grant execute on function create_oauth_state(text) to authenticated;

-- Sign-in via Strava ("Continue with Strava"): the caller has no session
-- at all yet, so there's no auth.uid() to tie a state to — unlike
-- create_oauth_state above (authenticated-only), this is anon-callable
-- and inserts user_id = NULL. strava-callback branches on whether the
-- matched oauth_states row has a user_id: present -> existing "connect"
-- flow (unchanged); NULL -> "login" flow (find-or-create user, mint a
-- session). Self-cleaning: sweeps rows older than 10 minutes on every
-- call, so abandoned login attempts don't accumulate.
alter table oauth_states alter column user_id drop not null;

create or replace function create_oauth_login_state(p_provider text)
returns text
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_state text;
begin
  if p_provider not in ('strava', 'whoop') then
    raise exception 'invalid provider: %', p_provider;
  end if;
  delete from oauth_states where created_at < now() - interval '10 minutes';
  v_state := encode(gen_random_bytes(32), 'hex');
  insert into oauth_states (state, user_id, provider) values (v_state, null, p_provider);
  return v_state;
end;
$$;

-- No explicit revoke needed: the ALTER DEFAULT PRIVILEGES statements
-- above already lock new functions down to nobody by default (verified
-- empirically, not just by reading the docs) — this grant is the only
-- permission this function actually needs.
grant execute on function create_oauth_login_state(text) to anon;

-- One Strava athlete can only ever map to one Supabase user — enforced at
-- the database level, not just by application logic, now that the
-- duplicate test-user rows are cleaned up.
create unique index if not exists connections_provider_athlete_unique on connections(provider, provider_athlete_id);

-- Invite-only sign-in: only athlete ids in this table can create an
-- account via "Continue with Strava". Checked server-side (service_role)
-- in strava-callback; no client access needed, so same zero-policy
-- lockdown as connections/oauth_states.
create table if not exists allowed_athletes (
  provider_athlete_id text primary key,
  added_at timestamptz not null default now()
);

alter table allowed_athletes enable row level security;

insert into allowed_athletes (provider_athlete_id) values ('174546304') on conflict (provider_athlete_id) do nothing;

-- ---------------------------------------------------------------------
-- Synced activity data. Unlike `connections`, this is not sensitive —
-- it's the actual training data a user wants to see, so a normal RLS
-- SELECT policy (read your own rows) is the right call here, not a
-- zero-policy lockdown. Writes are a different story: only the sync
-- Edge Function (service_role) should ever insert/update rows, so
-- there are deliberately no insert/update/delete policies for the
-- client — a user can't forge or tamper with their own activity history
-- by writing directly to this table.
-- ---------------------------------------------------------------------
create table if not exists activities (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  provider text not null check (provider in ('strava', 'whoop', 'garmin')),
  provider_activity_id text not null,
  date date not null,
  sport text not null check (sport in ('Run', 'Bike', 'Swim', 'Strength', 'Recovery', 'Cross')),
  duration numeric,   -- minutes, matching the convention already used by
                       -- garmin_activities.json / workouts.json elsewhere
                       -- in this app
  distance numeric,   -- miles, same convention
  notes text,
  raw_payload jsonb,  -- full original API response for this activity — lets
                      -- us improve sport-mapping or pull new fields later
                      -- without re-fetching, which may not even be possible
                      -- for older activities depending on provider retention
  synced_at timestamptz not null default now(),
  unique (user_id, provider, provider_activity_id)
);

create index if not exists activities_user_date_idx on activities (user_id, date);

alter table activities enable row level security;

drop policy if exists "users can view own activities" on activities;
create policy "users can view own activities"
  on activities for select
  using (auth.uid() = user_id);

-- One-time onboarding profile. A user with no row here is sent to
-- onboarding.html after sign-in; once this row exists, they go straight to
-- the dashboard. No delete policy at all — RLS default-denies delete from
-- the client regardless of auth.uid(), same pattern as connections/activities.
create table if not exists profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null,
  age integer,
  sex text check (sex in ('male', 'female', 'prefer_not_to_say')),
  height_cm numeric,
  weight_kg numeric,
  goal text not null check (goal in (
    'sprint_triathlon', 'olympic_triathlon', '70.3', 'ironman',
    'marathon', 'half_marathon', 'get_fitter', 'other'
  )),
  goal_other text,
  target_race_date date,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table profiles enable row level security;

drop policy if exists "users can view own profile" on profiles;
create policy "users can view own profile"
  on profiles for select
  using (auth.uid() = user_id);

drop policy if exists "users can insert own profile" on profiles;
create policy "users can insert own profile"
  on profiles for insert
  with check (auth.uid() = user_id);

drop policy if exists "users can update own profile" on profiles;
create policy "users can update own profile"
  on profiles for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);
