-- Adds a persisted "needs reconnect" flag to connections, surfaced through
-- get_my_connections() so connect.html can show it without running a sync
-- first. Set by strava-sync on any reconnect-needed path; cleared by
-- upsert_connection on any successful connect/token-rotation and by
-- strava-sync on any successful pull. See supabase/schema.sql for the
-- full, current schema — this file applies just the incremental change.

alter table connections add column if not exists needs_reconnect boolean not null default false;

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

revoke execute on function get_my_connections() from public, anon;
grant execute on function get_my_connections() to authenticated;

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

    update connections set
      access_token_id = v_access_id,
      refresh_token_id = v_refresh_id,
      expires_at = p_expires_at,
      scope = coalesce(p_scope, existing.scope),
      provider_athlete_id = coalesce(p_provider_athlete_id, existing.provider_athlete_id),
      needs_reconnect = false
    where id = existing.id;
  else
    v_access_id := vault.create_secret(p_access_token);
    v_refresh_id := case when p_refresh_token is not null
      then vault.create_secret(p_refresh_token) else null end;

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
