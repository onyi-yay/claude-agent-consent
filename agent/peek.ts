// Shows exactly what the agent can see with its current grant, without
// calling Claude. Same token, same Data API, same RLS as agent:ask.
import { loadGrant } from "./config.ts";
import { AgentAccessError, createDataApi } from "./data-api.ts";

// Returns the exit code; see the note in ask.ts on avoiding process.exit().
async function main(): Promise<number> {
  const stored = loadGrant();
  if (!stored) {
    console.error("Not connected. Run `npm run agent:connect` first.");
    return 2;
  }

  const api = createDataApi(stored.access_token);

  try {
    const grant = await api.whoami();
    console.log(`Grant scopes: ${grant.scopes.join(", ")}`);
    if (grant.scopes.includes("notes:read")) {
      console.log(`Note folders: ${grant.note_folders?.join(", ") ?? "all"}`);
    }

    const tasks = await api.listTasks();
    console.log(`\nTasks the agent can see (${tasks.length}):`);
    console.table(tasks.map(({ title, status, due_date }) => ({ title, status, due_date })));

    const notes = await api.searchNotes();
    console.log(`\nNotes the agent can see (${notes.length}):`);
    console.table(notes.map(({ folder, title }) => ({ folder, title })));
    return 0;
  } catch (err) {
    if (!(err instanceof AgentAccessError)) throw err;
    console.error(`\nAccess denied: ${err.reason}`);
    if (err.detail) console.error(err.detail);
    console.error("No data was read.");
    return 2;
  }
}

process.exitCode = await main();
