// Runs the consent flow: opens the consent screen, waits for the redirect on
// localhost, exchanges the code (with the PKCE verifier) for a grant token.
import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import { exec } from "node:child_process";
import { createClient } from "@supabase/supabase-js";
import { config, saveGrant, type StoredGrant } from "./config.ts";
import { createPkcePair } from "./pkce.ts";

const { verifier, challenge } = createPkcePair();
const state = randomBytes(16).toString("base64url");

const consentUrl = new URL("/consent.html", config.webUrl);
consentUrl.search = new URLSearchParams({
  client_id: config.clientId,
  redirect_uri: config.redirectUri,
  scope: config.requestedScopes.join(" "),
  state,
  code_challenge: challenge,
  code_challenge_method: "S256",
}).toString();

const anon = createClient(config.supabaseUrl, config.supabaseAnonKey, {
  auth: { persistSession: false, autoRefreshToken: false },
});

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", config.redirectUri);
  if (url.pathname !== "/callback") {
    res.writeHead(404).end();
    return;
  }

  const finish = (status: number, message: string, exitCode: number) => {
    res.writeHead(status, { "content-type": "text/html; charset=utf-8" });
    res.end(`<!doctype html><title>Claude Assistant</title><body style="font-family:system-ui;padding:3rem">
      <h1>${message}</h1><p>You can close this tab and return to the terminal.</p></body>`);
    server.close();
    setTimeout(() => process.exit(exitCode), 50);
  };

  if (url.searchParams.get("state") !== state) {
    console.error("State mismatch: ignoring this callback.");
    return finish(400, "Something went wrong (state mismatch).", 1);
  }
  const denied = url.searchParams.get("error");
  if (denied) {
    console.error(`Access was not granted (${denied}).`);
    return finish(200, "Access was not granted.", 1);
  }

  const code = url.searchParams.get("code");
  const { data, error } = await anon.rpc("exchange_agent_code", {
    p_client_id: config.clientId,
    p_code: code,
    p_code_verifier: verifier,
    p_redirect_uri: config.redirectUri,
  });
  if (error || data?.error) {
    console.error("Token exchange failed:", error?.message ?? `${data.error}: ${data.error_description}`);
    return finish(400, "Token exchange failed.", 1);
  }

  const grant = data as StoredGrant;
  saveGrant(grant);
  console.log("\nConnected. Grant scopes:", grant.scopes.join(", "));
  if (grant.scopes.includes("notes:read")) {
    console.log("Note folders:", grant.note_folders?.join(", ") ?? "all");
  }
  console.log(`Expires: ${new Date(grant.expires_at).toLocaleString()}`);
  console.log('\nTry: npm run agent:ask -- "What is on my plate this week?"');
  finish(200, "Claude Assistant is connected.", 0);
});

server.listen(config.callbackPort, () => {
  console.log("Open this URL to review and approve access:\n");
  console.log(consentUrl.toString(), "\n");
  const opener = process.platform === "win32" ? 'start ""' : process.platform === "darwin" ? "open" : "xdg-open";
  exec(`${opener} "${consentUrl.toString()}"`);
  console.log(`Waiting for the redirect on ${config.redirectUri} ...`);
});
