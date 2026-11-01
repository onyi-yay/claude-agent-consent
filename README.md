# Claude Agent Consent

A user grants a Claude-powered agent scoped, read-only access to their Supabase data through an OAuth-style consent screen. Row Level Security enforces the grant on every query. When the user revokes access, the agent's next request fails with `401 agent_grant_revoked`.

```
 Agent (CLI)                    Consent screen (browser)            Supabase (Postgres + PostgREST)
 ───────────                    ────────────────────────            ───────────────────────────────
 agent:connect
   PKCE verifier + challenge ──► /consent.html?client_id&scope
                                 &redirect_uri&state&code_challenge
                                 user signs in, picks scopes  ──────► authorize_agent()  → grant + one-time code
   localhost:8787/callback ◄──── redirect ?code&state
   exchange_agent_code(code, verifier) ─────────────────────────────► checks PKCE → returns opaque token
                                                                     (only sha256(token) is stored)
 agent:ask "…"
   Claude (tool runner) ── list_tasks / search_notes ──────────────► GET /rest/v1/notes
                                      x-agent-token: agt_…           pre-request hook: token valid?
                                                                     RLS (role anon): owner = grant.user
                                                                       AND scope granted AND folder allowed
                              dashboard: Revoke ────────────────────► revoke_agent_grant()
   next call ──────────────────────────────────────────────────────► 401 agent_grant_revoked
```

## How access is enforced

- **The token is opaque, not a JWT.** The agent sends the project's anon key plus `x-agent-token: agt_…`. Only the SHA-256 hash of the token is stored in `agent_grants`.
- **RLS does the scoping.** The `anon` role has `SELECT` only. Its policies on `notes` and `tasks` resolve the request's token to an active grant. They only match rows that belong to the user who granted access, in a scope that was granted (`notes:read`, `tasks:read`) and, for notes, in a folder that was granted. Without a valid token, `anon` sees nothing.
- **Revocation takes effect on the next request.** The grant is checked inside every query, so nothing is cached and no token has to expire first. A PostgREST [pre-request hook](https://docs.postgrest.org/en/stable/references/transactions.html#pre-request) (`private.agent_pre_request`) turns a revoked, expired or unknown token into an explicit HTTP 401 with a reason, instead of an empty result. If the hook isn't configured, RLS still returns zero rows.
- **The agent only gets tools for scopes it holds.** `agent:ask` fetches its grant from the server (`agent_whoami`) before calling Claude. It registers `list_tasks` only with `tasks:read`, and `search_notes` only with `notes:read`, limited to the granted folders. If access is revoked during a run, the next tool call gets a 401, the run stops, and the CLI exits with code 2.
- **The OAuth hardening:**
  - PKCE (S256) is required.
  - `redirect_uri` must exactly match a registered URI. The consent screen never redirects to an unverified one.
  - Authorization codes are single-use and expire after 5 minutes. Replaying a code revokes the grant it issued.
  - Consenting again replaces the earlier grant.
  - The consent page can't be framed (protection against clickjacking).

## Project layout

```
supabase/migrations/20261009000000_agent_grants.sql   schema, RLS, RPCs, pre-request hook, registered agent
web/server.ts, web/public/                           consent screen + "Connected agents" dashboard
agent/connect.ts                                     consent flow + code exchange
agent/ask.ts                                         Claude agent (claude-opus-5-5, tool runner)
agent/data-api.ts                                    the agent's only route to data
tests/rls.test.ts                                    runs the migration in PGlite; 15 tests
```

## Setup

1. **Create a Supabase project** at [supabase.com](https://supabase.com). The free tier is enough.

2. **Apply the migration.** Pick one of these:
   - **SQL Editor:** paste `supabase/migrations/20261009000000_agent_grants.sql` and run it.
   - **Supabase CLI:** run these from this folder:
     ```sh
     npx supabase init
     npx supabase link --project-ref <ref>
     npx supabase db push
     ```

3. **Auth:** email/password sign-in is used. For a quick local demo, turn off **Confirm email** under Authentication → Sign In / Providers. Otherwise, confirm your account from the email before signing in.

4. **Configure:**
   ```sh
   cp .env.example .env   # fill in SUPABASE_URL, SUPABASE_ANON_KEY, ANTHROPIC_API_KEY
   npm install
   ```

## Demo

```sh
npm run web                     # terminal 1: http://localhost:3000
```

1. Open http://localhost:3000, create an account, and click **Load sample notes and tasks**.

2. Connect the agent:
   ```sh
   npm run agent:connect           # terminal 2: opens the consent screen
   ```
   On the consent screen, keep **Read your tasks**, keep **Read your notes**, and untick the **health** and **finance** folders. Then click **Allow access**.

3. Ask a question that touches both allowed and blocked data:
   ```sh
   npm run agent:ask -- "What's on my plate, and what does my budget note say?"
   ```
   Claude answers from the tasks and the work/personal notes. It says it can't see the budget note: RLS never returned the finance folder.

4. Click **Revoke** on the dashboard, then ask again:
   ```sh
   npm run agent:ask -- "List my tasks"
   ```
   ```
   Access denied: The user revoked this agent's access.
   The user revoked this grant at 2026-10-09 18:42:10+00.
   No data was read. Run `npm run agent:connect` to ask the user for access again.
   ```
   The command exits with code 2 and makes no Claude API call. `npm run agent:status` shows the grant state as the server sees it.

No Anthropic key? `npm run agent:peek` prints exactly what the agent can see, and `npm run agent:view` opens it as a live page at http://localhost:8788. Both use the agent's own token, and neither calls Claude. Refresh the view after revoking to see the refusal.

## Tests

```sh
npm test
```

These tests run the real migration in [PGlite](https://pglite.dev) (Postgres in WASM), with small stand-ins for Supabase's `auth` schema and API roles. They simulate PostgREST requests and cover:

- scope and folder filtering
- cross-user isolation
- read-only enforcement
- the 401 on revocation, plus the fallback when the hook isn't configured
- owner-only revoke
- PKCE failure
- code replay
- unregistered scopes and redirect URIs

They need no Supabase project or API key.

## Production notes

- **Registering agents.** The migration registers one agent, `claude-assistant`, with a localhost redirect URI. To register real agents, insert rows into `agent_clients` with HTTPS redirect URIs. A confidential agent should also authenticate at the token exchange with a client secret. This demo uses a public client (PKCE only), which is right for CLIs.
- **Token lifetime.** Grants last 30 days, with no refresh tokens. Shorten `expires_at`, or add a refresh flow, if you need tighter rotation.
- **Prompt injection.** Note contents are untrusted input to the model. The system prompt tells Claude to treat them as data. The agent is also read-only, by grant and by role privileges.
- **Model fallback.** `agent/ask.ts` uses `claude-opus-5-5` with server-side refusal fallback enabled (`fallbacks: "default"`). Remove those two lines if you don't want it.

## License

[MIT](LICENSE) © 2026 Onyinyechi Iwuchukwu
