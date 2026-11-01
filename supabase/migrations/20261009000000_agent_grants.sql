-- Scoped, revocable AI-agent access to user data.
--
-- Flow (OAuth 2.0 authorization code + PKCE, implemented as Postgres RPCs):
--   1. Agent sends the user to the consent screen with client_id, scope,
--      redirect_uri, state and a PKCE code_challenge.
--   2. User approves (optionally narrowing scopes / note folders):
--      authorize_agent() creates an agent_grant and a one-time code.
--   3. Agent calls exchange_agent_code() with the code + code_verifier and
--      receives an opaque bearer token. Only its SHA-256 hash is stored.
--   4. Agent calls the Data API with the anon key plus `x-agent-token: <token>`.
--      RLS policies on the `anon` role resolve the token to its grant and only
--      expose rows the grant covers.
--   5. User revokes the grant. The PostgREST pre-request hook then rejects every
--      request carrying that token with HTTP 401 `agent_grant_revoked`.

create extension if not exists pgcrypto with schema extensions;

create schema if not exists private;
-- RLS policies and the pre-request hook run as the request role, so it needs
-- to resolve functions here. The schema is not exposed through the Data API.
grant usage on schema private to anon, authenticated;

-- ---------------------------------------------------------------------------
-- User data
-- ---------------------------------------------------------------------------

create type public.note_folder as enum ('work', 'personal', 'health', 'finance');

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  folder public.note_folder not null,
  title text not null,
  body text not null default '',
  created_at timestamptz not null default now()
);
create index notes_owner_folder_idx on public.notes (owner_id, folder);

create table public.tasks (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  title text not null,
  status text not null default 'todo' check (status in ('todo', 'doing', 'done')),
  due_date date,
  created_at timestamptz not null default now()
);
create index tasks_owner_idx on public.tasks (owner_id);

-- ---------------------------------------------------------------------------
-- Agent registry, grants and authorization codes
-- ---------------------------------------------------------------------------

create table public.agent_clients (
  id text primary key,
  name text not null,
  description text not null default '',
  redirect_uris text[] not null,
  allowed_scopes text[] not null,
  created_at timestamptz not null default now()
);

create table public.agent_grants (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  client_id text not null references public.agent_clients (id) on delete cascade,
  scopes text[] not null,
  -- Only meaningful with notes:read. null means every folder.
  note_folders public.note_folder[],
  -- SHA-256 of the bearer token. null until the auth code is exchanged.
  token_hash text unique,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '30 days',
  revoked_at timestamptz,
  last_used_at timestamptz
);
create index agent_grants_user_idx on public.agent_grants (user_id);

create table public.agent_auth_codes (
  code_hash text primary key,
  grant_id uuid not null references public.agent_grants (id) on delete cascade,
  code_challenge text not null,
  redirect_uri text not null,
  expires_at timestamptz not null default now() + interval '5 minutes',
  used_at timestamptz
);

alter table public.notes enable row level security;
alter table public.tasks enable row level security;
alter table public.agent_clients enable row level security;
alter table public.agent_grants enable row level security;
alter table public.agent_auth_codes enable row level security;

-- Grant bookkeeping is only reachable through the security-definer RPCs below.
revoke all on public.agent_clients, public.agent_grants, public.agent_auth_codes from anon, authenticated;

-- Agents (anon + token) may only read; signed-in owners have full CRUD.
revoke all on public.notes, public.tasks from anon;
grant select on public.notes, public.tasks to anon;
grant select, insert, update, delete on public.notes, public.tasks to authenticated;

-- ---------------------------------------------------------------------------
-- Private helpers
-- ---------------------------------------------------------------------------

create function private.hash_secret(p_secret text)
returns text
language sql
immutable
set search_path = ''
as $$
  select encode(extensions.digest(p_secret, 'sha256'), 'hex')
$$;

-- base64url(sha256(verifier)) without padding, per RFC 7636 (S256).
create function private.pkce_s256(p_verifier text)
returns text
language sql
immutable
set search_path = ''
as $$
  select rtrim(translate(encode(extensions.digest(p_verifier, 'sha256'), 'base64'), '+/', '-_'), '=')
$$;

-- The bearer token from the `x-agent-token` request header, if any.
create function private.request_agent_token()
returns text
language sql
stable
set search_path = ''
as $$
  select nullif(nullif(current_setting('request.headers', true), '')::json ->> 'x-agent-token', '')
$$;

-- Owner of the active grant behind the request's token, if that grant
-- includes p_scope. null otherwise (no token, unknown, revoked, expired,
-- or scope not granted).
create function private.agent_user_id(p_scope text)
returns uuid
language sql
stable
security definer
set search_path = ''
as $$
  select g.user_id
  from public.agent_grants g
  where g.token_hash = private.hash_secret(private.request_agent_token())
    and g.revoked_at is null
    and g.expires_at > now()
    and p_scope = any (g.scopes)
$$;

-- Note folders the active grant covers. null means all folders.
create function private.agent_note_folders()
returns public.note_folder[]
language sql
stable
security definer
set search_path = ''
as $$
  select g.note_folders
  from public.agent_grants g
  where g.token_hash = private.hash_secret(private.request_agent_token())
    and g.revoked_at is null
    and g.expires_at > now()
$$;

-- Resolve a token to its grant or raise a 401 that PostgREST passes through
-- as the HTTP status (sqlstate PTxyz => HTTP xyz).
create function private.assert_agent_grant(p_token text)
returns public.agent_grants
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_grant public.agent_grants;
begin
  select * into v_grant
  from public.agent_grants g
  where g.token_hash = private.hash_secret(p_token);

  if not found then
    raise sqlstate 'PT401' using
      message = 'invalid_agent_token',
      hint = 'Reconnect the agent to request a new grant.';
  elsif v_grant.revoked_at is not null then
    raise sqlstate 'PT401' using
      message = 'agent_grant_revoked',
      detail = format('The user revoked this grant at %s.', v_grant.revoked_at),
      hint = 'Ask the user to reconnect the agent.';
  elsif v_grant.expires_at <= now() then
    raise sqlstate 'PT401' using
      message = 'agent_grant_expired',
      detail = format('This grant expired at %s.', v_grant.expires_at),
      hint = 'Ask the user to reconnect the agent.';
  end if;

  return v_grant;
end;
$$;

-- PostgREST runs this before every request. Requests without an agent token
-- pass through untouched; requests with a bad token fail fast with a 401
-- instead of quietly returning zero rows.
create function private.agent_pre_request()
returns void
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_token text := private.request_agent_token();
begin
  if v_token is not null then
    perform private.assert_agent_grant(v_token);
  end if;
end;
$$;

revoke all on all functions in schema private from public;
grant execute on function
  private.request_agent_token(),
  private.agent_user_id(text),
  private.agent_note_folders(),
  private.agent_pre_request()
to anon, authenticated;

alter role authenticator set pgrst.db_pre_request = 'private.agent_pre_request';
notify pgrst, 'reload config';

-- ---------------------------------------------------------------------------
-- RLS policies
-- ---------------------------------------------------------------------------
-- Helpers are wrapped in (select ...) so Postgres evaluates them once per
-- statement rather than once per row.

create policy "owners manage their notes" on public.notes
  for all to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));

create policy "agents read notes their grant covers" on public.notes
  for select to anon
  using (
    owner_id = (select private.agent_user_id('notes:read'))
    and (
      (select private.agent_note_folders()) is null
      -- The cast keeps ANY in array mode rather than subquery mode.
      or folder = any ((select private.agent_note_folders())::public.note_folder[])
    )
  );

create policy "owners manage their tasks" on public.tasks
  for all to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));

create policy "agents read tasks their grant covers" on public.tasks
  for select to anon
  using (owner_id = (select private.agent_user_id('tasks:read')));

-- ---------------------------------------------------------------------------
-- RPCs: consent screen + dashboard (authenticated user)
-- ---------------------------------------------------------------------------

create function public.get_agent_client(p_client_id text)
returns table (id text, name text, description text, allowed_scopes text[], redirect_uris text[])
language sql
stable
security definer
set search_path = ''
as $$
  select c.id, c.name, c.description, c.allowed_scopes, c.redirect_uris
  from public.agent_clients c
  where c.id = p_client_id
$$;

create function public.authorize_agent(
  p_client_id text,
  p_redirect_uri text,
  p_scopes text[],
  p_note_folders public.note_folder[],
  p_code_challenge text,
  p_code_challenge_method text default 'S256'
)
returns text
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_client public.agent_clients;
  v_scopes text[];
  v_grant_id uuid;
  v_code text;
begin
  if v_user is null then
    raise sqlstate 'PT401' using message = 'not_authenticated';
  end if;

  select * into v_client from public.agent_clients c where c.id = p_client_id;
  if not found then
    raise sqlstate 'PT400' using message = 'unknown_client';
  end if;
  if not (p_redirect_uri = any (v_client.redirect_uris)) then
    raise sqlstate 'PT400' using message = 'invalid_redirect_uri';
  end if;
  if p_code_challenge_method is distinct from 'S256'
     or p_code_challenge !~ '^[A-Za-z0-9_-]{43}$' then
    raise sqlstate 'PT400' using message = 'invalid_code_challenge',
      hint = 'Use PKCE with code_challenge_method=S256.';
  end if;

  select array_agg(distinct s order by s) into v_scopes from unnest(p_scopes) s;
  if v_scopes is null or not (v_scopes <@ v_client.allowed_scopes) then
    raise sqlstate 'PT400' using message = 'invalid_scope';
  end if;
  if p_note_folders is not null and cardinality(p_note_folders) = 0 then
    raise sqlstate 'PT400' using message = 'invalid_note_folders',
      hint = 'Pass null for all folders, or drop notes:read.';
  end if;

  -- Re-consenting replaces any earlier grant this user gave this client.
  update public.agent_grants g
  set revoked_at = now()
  where g.user_id = v_user and g.client_id = p_client_id and g.revoked_at is null;

  insert into public.agent_grants (user_id, client_id, scopes, note_folders)
  values (
    v_user,
    p_client_id,
    v_scopes,
    case when 'notes:read' = any (v_scopes) then p_note_folders end
  )
  returning id into v_grant_id;

  v_code := encode(extensions.gen_random_bytes(32), 'hex');
  insert into public.agent_auth_codes (code_hash, grant_id, code_challenge, redirect_uri)
  values (private.hash_secret(v_code), v_grant_id, p_code_challenge, p_redirect_uri);

  return v_code;
end;
$$;

create function public.list_my_agent_grants()
returns table (
  id uuid,
  client_id text,
  client_name text,
  scopes text[],
  note_folders public.note_folder[],
  status text,
  created_at timestamptz,
  expires_at timestamptz,
  revoked_at timestamptz,
  last_used_at timestamptz
)
language sql
stable
security definer
set search_path = ''
as $$
  select
    g.id,
    g.client_id,
    c.name,
    g.scopes,
    g.note_folders,
    case
      when g.revoked_at is not null then 'revoked'
      when g.expires_at <= now() then 'expired'
      else 'active'
    end,
    g.created_at,
    g.expires_at,
    g.revoked_at,
    g.last_used_at
  from public.agent_grants g
  join public.agent_clients c on c.id = g.client_id
  where g.user_id = auth.uid()
    and g.token_hash is not null
  order by g.created_at desc
$$;

create function public.revoke_agent_grant(p_grant_id uuid)
returns boolean
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  update public.agent_grants g
  set revoked_at = now()
  where g.id = p_grant_id
    and g.user_id = auth.uid()
    and g.revoked_at is null;
  return found;
end;
$$;

create function public.load_sample_data()
returns void
language sql
volatile
security invoker
set search_path = ''
as $$
  insert into public.notes (folder, title, body) values
    ('work', 'Q4 planning', 'Ship the consent screen by Nov 1. Hiring: one backend engineer.'),
    ('work', 'Launch checklist', 'Docs, changelog, status page, rollback plan.'),
    ('personal', 'Gift ideas', 'Mum: pottery class. Sam: trail running shoes.'),
    ('health', 'Allergist follow-up', 'Results due Oct 20. Ask about the nut panel.'),
    ('finance', 'Budget', 'Rent 1,850. Savings target 600/month. Card ends 4412.');
  insert into public.tasks (title, status, due_date) values
    ('Draft Q4 roadmap', 'doing', current_date + 3),
    ('Book allergist follow-up', 'todo', current_date + 10),
    ('Renew passport', 'todo', current_date + 30),
    ('File expense report', 'done', current_date - 2);
$$;

-- ---------------------------------------------------------------------------
-- RPCs: agent side (anon key, no user session)
-- ---------------------------------------------------------------------------

-- Token endpoint. Returns an OAuth-style JSON body (access_token, or error +
-- error_description) instead of raising, so the code-replay revocation below
-- commits.
create function public.exchange_agent_code(
  p_client_id text,
  p_code text,
  p_code_verifier text,
  p_redirect_uri text
)
returns json
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_code public.agent_auth_codes;
  v_grant public.agent_grants;
  v_token text;
begin
  select * into v_code
  from public.agent_auth_codes ac
  where ac.code_hash = private.hash_secret(p_code)
  for update;

  if not found or v_code.expires_at <= now() then
    return json_build_object('error', 'invalid_grant', 'error_description', 'Authorization code is invalid or expired.');
  end if;

  select * into v_grant from public.agent_grants g where g.id = v_code.grant_id for update;

  if v_code.used_at is not null then
    -- A replayed code means it leaked: kill whatever it was used to issue.
    update public.agent_grants g set revoked_at = coalesce(g.revoked_at, now()) where g.id = v_grant.id;
    return json_build_object('error', 'invalid_grant', 'error_description', 'Authorization code was already used; the grant has been revoked.');
  end if;

  if v_grant.client_id <> p_client_id or v_code.redirect_uri <> p_redirect_uri then
    return json_build_object('error', 'invalid_grant', 'error_description', 'client_id or redirect_uri does not match the authorization request.');
  end if;

  if p_code_verifier !~ '^[A-Za-z0-9._~-]{43,128}$'
     or private.pkce_s256(p_code_verifier) <> v_code.code_challenge then
    return json_build_object('error', 'invalid_grant', 'error_description', 'PKCE verification failed.');
  end if;

  if v_grant.revoked_at is not null then
    return json_build_object('error', 'access_denied', 'error_description', 'The grant was revoked before the code was exchanged.');
  end if;

  update public.agent_auth_codes ac set used_at = now() where ac.code_hash = v_code.code_hash;

  v_token := 'agt_' || encode(extensions.gen_random_bytes(32), 'hex');
  update public.agent_grants g set token_hash = private.hash_secret(v_token) where g.id = v_grant.id;

  return json_build_object(
    'access_token', v_token,
    'token_type', 'agent',
    'grant_id', v_grant.id,
    'scopes', v_grant.scopes,
    'note_folders', v_grant.note_folders,
    'expires_at', v_grant.expires_at
  );
end;
$$;

-- Lets the agent check its grant up front. Also records last use.
create function public.agent_whoami()
returns json
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_token text := private.request_agent_token();
  v_grant public.agent_grants;
begin
  if v_token is null then
    raise sqlstate 'PT401' using message = 'missing_agent_token';
  end if;

  v_grant := private.assert_agent_grant(v_token);

  update public.agent_grants g set last_used_at = now() where g.id = v_grant.id;

  return json_build_object(
    'grant_id', v_grant.id,
    'client_id', v_grant.client_id,
    'scopes', v_grant.scopes,
    'note_folders', v_grant.note_folders,
    'expires_at', v_grant.expires_at
  );
end;
$$;

revoke all on function
  public.get_agent_client(text),
  public.authorize_agent(text, text, text[], public.note_folder[], text, text),
  public.list_my_agent_grants(),
  public.revoke_agent_grant(uuid),
  public.load_sample_data(),
  public.exchange_agent_code(text, text, text, text),
  public.agent_whoami()
from public, anon, authenticated;

grant execute on function
  public.get_agent_client(text),
  public.authorize_agent(text, text, text[], public.note_folder[], text, text),
  public.list_my_agent_grants(),
  public.revoke_agent_grant(uuid),
  public.load_sample_data()
to authenticated;

grant execute on function
  public.exchange_agent_code(text, text, text, text),
  public.agent_whoami()
to anon;

-- ---------------------------------------------------------------------------
-- Registered agent
-- ---------------------------------------------------------------------------

insert into public.agent_clients (id, name, description, redirect_uris, allowed_scopes)
values (
  'claude-assistant',
  'Claude Assistant',
  'A Claude-powered assistant that answers questions about your notes and tasks.',
  array['http://localhost:8787/callback'],
  array['notes:read', 'tasks:read']
);
