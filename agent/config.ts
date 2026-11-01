import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";

try {
  process.loadEnvFile(new URL("../.env", import.meta.url));
} catch {
  // No .env file; rely on the real environment.
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    console.error(`Missing ${name}. Copy .env.example to .env and fill it in.`);
    process.exit(1);
  }
  return value;
}

export const config = {
  supabaseUrl: required("SUPABASE_URL"),
  supabaseAnonKey: required("SUPABASE_ANON_KEY"),
  webUrl: process.env.WEB_URL ?? "http://localhost:3000",
  clientId: "claude-assistant",
  callbackPort: 8787,
  get redirectUri() {
    return `http://localhost:${this.callbackPort}/callback`;
  },
  requestedScopes: ["notes:read", "tasks:read"],
};

export type StoredGrant = {
  access_token: string;
  grant_id: string;
  scopes: string[];
  note_folders: string[] | null;
  expires_at: string;
};

const TOKEN_FILE = new URL("./.agent-token.json", import.meta.url);

export function saveGrant(grant: StoredGrant) {
  writeFileSync(TOKEN_FILE, JSON.stringify(grant, null, 2));
  try {
    chmodSync(TOKEN_FILE, 0o600);
  } catch {
    // chmod is a no-op on Windows.
  }
}

export function loadGrant(): StoredGrant | null {
  if (!existsSync(TOKEN_FILE)) return null;
  return JSON.parse(readFileSync(TOKEN_FILE, "utf8"));
}
