// Shows whether the agent's grant is still valid, as the server sees it.
import { loadGrant } from "./config.ts";
import { AgentAccessError, createDataApi } from "./data-api.ts";

// Returns the exit code; see the note in ask.ts on avoiding process.exit().
async function main(): Promise<number> {
  const stored = loadGrant();
  if (!stored) {
    console.log("Not connected. Run `npm run agent:connect`.");
    return 2;
  }

  try {
    const grant = await createDataApi(stored.access_token).whoami();
    console.log("Active grant", grant.grant_id);
    console.log("  scopes:      ", grant.scopes.join(", "));
    if (grant.scopes.includes("notes:read")) {
      console.log("  note folders:", grant.note_folders?.join(", ") ?? "all");
    }
    console.log("  expires:     ", new Date(grant.expires_at).toLocaleString());
    return 0;
  } catch (err) {
    if (!(err instanceof AgentAccessError)) throw err;
    console.log(`No access: ${err.reason}`);
    if (err.detail) console.log(err.detail);
    return 2;
  }
}

process.exitCode = await main();
