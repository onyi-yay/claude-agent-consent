// Runs the real migration against PGlite (Postgres compiled to WASM) with
// small stand-ins for the pieces Supabase provides (auth schema, API roles),
// then plays PostgREST: set the request role/headers, run the pre-request
// hook, run the query.
import { before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { PGlite } from "@electric-sql/pglite";
import { pgcrypto } from "@electric-sql/pglite/contrib/pgcrypto";
import { createPkcePair } from "../agent/pkce.ts";

const MIGRATION = readFileSync(
  new URL("../supabase/migrations/20261009000000_agent_grants.sql", import.meta.url),
  "utf8",
);
const REDIRECT = "http://localhost:8787/callback";
const CLIENT = "claude-assistant";
const ALICE = "00000000-0000-0000-0000-00000000000a";
const BOB = "00000000-0000-0000-0000-00000000000b";

const SUPABASE_STUBS = `
  create role anon nologin;
  create role authenticated nologin;
  create role authenticator noinherit login;
  create schema extensions;
  create schema auth;
  create table auth.users (id uuid primary key);
  create function auth.uid() returns uuid language sql stable as $$
    select nullif(nullif(current_setting('request.jwt.claims', true), '')::json ->> 'sub', '')::uuid
  $$;
  grant usage on schema auth to anon, authenticated;
  grant usage on schema public to anon, authenticated;
  insert into auth.users values ('${ALICE}'), ('${BOB}');
`;

let db: PGlite;

type Req = { userId?: string; agentToken?: string; preRequest?: boolean };

// Executes `sql` the way PostgREST would for one HTTP request.
async function request<T = Record<string, unknown>>(req: Req, sql: string, params: unknown[] = []) {
  const role = req.userId ? "authenticated" : "anon";
  const claims = JSON.stringify(req.userId ? { sub: req.userId, role } : { role });
  const headers = JSON.stringify(req.agentToken ? { "x-agent-token": req.agentToken } : {});
  return db.transaction(async (tx) => {
    await tx.query(`select set_config('request.jwt.claims', $1, true), set_config('request.headers', $2, true)`, [claims, headers]);
    await tx.exec(`set local role ${role}`);
    if (req.preRequest !== false) await tx.query(`select private.agent_pre_request()`);
    return (await tx.query<T>(sql, params)).rows;
  });
}

async function connectAgent(userId: string, scopes: string[], folders: string[] | null) {
  const { verifier, challenge } = createPkcePair();
  const [{ code }] = await request<{ code: string }>(
    { userId },
    `select public.authorize_agent($1, $2, $3, $4::text[]::public.note_folder[], $5) as code`,
    [CLIENT, REDIRECT, scopes, folders, challenge],
  );
  const [{ body }] = await request<{ body: any }>(
    {},
    `select public.exchange_agent_code($1, $2, $3, $4) as body`,
    [CLIENT, code, verifier, REDIRECT],
  );
  assert.ok(body.access_token, JSON.stringify(body));
  return { code, verifier, token: body.access_token as string, grantId: body.grant_id as string };
}

const rejection = (message: string) => (err: any) => err.code === "PT401" && err.message === message;

before(async () => {
  db = await PGlite.create({ extensions: { pgcrypto } });
  await db.exec(SUPABASE_STUBS);
  await db.exec(MIGRATION);
  await request({ userId: ALICE }, `select public.load_sample_data()`);
  await request({ userId: BOB }, `select public.load_sample_data()`);
});

describe("scoped reads", () => {
  it("only returns the granting user's rows in the granted folders", async () => {
    const { token } = await connectAgent(ALICE, ["notes:read", "tasks:read"], ["work", "personal"]);
    const notes = await request<{ owner_id: string; folder: string }>({ agentToken: token }, `select owner_id, folder from public.notes`);
    assert.equal(notes.length, 3);
    assert.ok(notes.every((n) => n.owner_id === ALICE && ["work", "personal"].includes(n.folder)));

    const tasks = await request<{ owner_id: string }>({ agentToken: token }, `select owner_id from public.tasks`);
    assert.equal(tasks.length, 4);
    assert.ok(tasks.every((t) => t.owner_id === ALICE));
  });

  it("hides tables whose scope was not granted", async () => {
    const { token } = await connectAgent(BOB, ["notes:read"], null);
    assert.equal((await request({ agentToken: token }, `select 1 from public.notes`)).length, 5);
    assert.equal((await request({ agentToken: token }, `select 1 from public.tasks`)).length, 0);
  });

  it("cannot write, even to rows it can read", async () => {
    const { token } = await connectAgent(ALICE, ["notes:read", "tasks:read"], null);
    await assert.rejects(
      request({ agentToken: token }, `insert into public.tasks (owner_id, title) values ($1, 'x')`, [ALICE]),
      /permission denied/,
    );
    await assert.rejects(request({ agentToken: token }, `delete from public.notes`), /permission denied/);
  });

  it("anon without a token sees nothing and is not rejected", async () => {
    assert.equal((await request({}, `select 1 from public.notes`)).length, 0);
  });

  it("cannot reach grant bookkeeping directly", async () => {
    const { token } = await connectAgent(ALICE, ["tasks:read"], null);
    await assert.rejects(request({ agentToken: token }, `select * from public.agent_grants`), /permission denied/);
  });
});

describe("revocation", () => {
  it("makes the next call fail with 401 agent_grant_revoked", async () => {
    const { token, grantId } = await connectAgent(ALICE, ["notes:read", "tasks:read"], null);
    assert.equal((await request({ agentToken: token }, `select 1 from public.tasks`)).length, 4);

    const [{ ok }] = await request<{ ok: boolean }>({ userId: ALICE }, `select public.revoke_agent_grant($1) as ok`, [grantId]);
    assert.equal(ok, true);

    await assert.rejects(request({ agentToken: token }, `select 1 from public.tasks`), rejection("agent_grant_revoked"));
    await assert.rejects(request({ agentToken: token }, `select public.agent_whoami()`), rejection("agent_grant_revoked"));
  });

  it("still exposes zero rows if the pre-request hook is not configured", async () => {
    const { token, grantId } = await connectAgent(ALICE, ["notes:read"], null);
    await request({ userId: ALICE }, `select public.revoke_agent_grant($1)`, [grantId]);
    const rows = await request({ agentToken: token, preRequest: false }, `select 1 from public.notes`);
    assert.equal(rows.length, 0);
  });

  it("only lets the owner revoke a grant", async () => {
    const { token, grantId } = await connectAgent(ALICE, ["tasks:read"], null);
    const [{ ok }] = await request<{ ok: boolean }>({ userId: BOB }, `select public.revoke_agent_grant($1) as ok`, [grantId]);
    assert.equal(ok, false);
    assert.equal((await request({ agentToken: token }, `select 1 from public.tasks`)).length, 4);
  });

  it("re-consenting replaces the previous grant", async () => {
    const first = await connectAgent(BOB, ["tasks:read"], null);
    await connectAgent(BOB, ["tasks:read"], null);
    await assert.rejects(request({ agentToken: first.token }, `select 1 from public.tasks`), rejection("agent_grant_revoked"));
  });

  it("rejects unknown tokens", async () => {
    await assert.rejects(request({ agentToken: "agt_nope" }, `select 1 from public.notes`), rejection("invalid_agent_token"));
  });
});

describe("token exchange", () => {
  it("rejects a wrong PKCE verifier", async () => {
    const { challenge } = createPkcePair();
    const [{ code }] = await request<{ code: string }>(
      { userId: ALICE },
      `select public.authorize_agent($1, $2, $3, null, $4) as code`,
      [CLIENT, REDIRECT, ["tasks:read"], challenge],
    );
    const [{ body }] = await request<{ body: any }>({}, `select public.exchange_agent_code($1, $2, $3, $4) as body`, [
      CLIENT, code, createPkcePair().verifier, REDIRECT,
    ]);
    assert.equal(body.error, "invalid_grant");
    assert.match(body.error_description, /PKCE/);
  });

  it("revokes the grant when a code is replayed", async () => {
    const { code, verifier, token } = await connectAgent(ALICE, ["tasks:read"], null);
    const [{ body }] = await request<{ body: any }>({}, `select public.exchange_agent_code($1, $2, $3, $4) as body`, [
      CLIENT, code, verifier, REDIRECT,
    ]);
    assert.equal(body.error, "invalid_grant");
    await assert.rejects(request({ agentToken: token }, `select 1 from public.tasks`), rejection("agent_grant_revoked"));
  });

  it("refuses scopes and redirect URIs the client did not register", async () => {
    const { challenge } = createPkcePair();
    await assert.rejects(
      request({ userId: ALICE }, `select public.authorize_agent($1, $2, $3, null, $4)`, [CLIENT, REDIRECT, ["finance:write"], challenge]),
      /invalid_scope/,
    );
    await assert.rejects(
      request({ userId: ALICE }, `select public.authorize_agent($1, $2, $3, null, $4)`, [CLIENT, "https://evil.example/cb", ["tasks:read"], challenge]),
      /invalid_redirect_uri/,
    );
  });

  it("requires a signed-in user to authorize", async () => {
    const { challenge } = createPkcePair();
    await assert.rejects(
      request({}, `select public.authorize_agent($1, $2, $3, null, $4)`, [CLIENT, REDIRECT, ["tasks:read"], challenge]),
      /permission denied/,
    );
  });
});

describe("dashboard", () => {
  it("lists the user's grants and records last use", async () => {
    const { token, grantId } = await connectAgent(BOB, ["notes:read"], ["health"]);
    await request({ agentToken: token }, `select public.agent_whoami()`);
    const rows = await request<{ id: string; status: string; last_used_at: Date | null; note_folders: string }>(
      { userId: BOB },
      `select * from public.list_my_agent_grants()`,
    );
    const row = rows.find((r) => r.id === grantId)!;
    assert.equal(row.status, "active");
    assert.ok(row.last_used_at);
    assert.ok(rows.every((r) => r.id !== undefined));
    const aliceRows = await request<{ id: string }>({ userId: ALICE }, `select id from public.list_my_agent_grants()`);
    assert.ok(!aliceRows.some((r) => r.id === grantId));
  });
});
