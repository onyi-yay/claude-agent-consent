// A browser view of exactly what the agent can see. Every page load reads the
// data with the agent's own token (same Data API, same RLS as agent:ask), so
// after the user revokes, a refresh shows the refusal.
import { createServer } from "node:http";
import { exec } from "node:child_process";
import { config, loadGrant } from "./config.ts";
import { AgentAccessError, createDataApi } from "./data-api.ts";

const PORT = 8788;

const REASONS: Record<string, string> = {
  agent_grant_revoked: "The user revoked this agent's access.",
  agent_grant_expired: "This agent's access has expired.",
  invalid_agent_token: "This agent's access key is not recognised.",
};

const escapeHtml = (value: unknown) =>
  String(value ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function page(body: string) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Agent View</title>
  <link rel="stylesheet" href="${config.webUrl}/styles.css">
  <style>
    .agent-banner { display: flex; gap: 12px; align-items: center; }
    .denied { border-color: var(--danger); }
    .denied h2 { color: var(--danger); font-size: 1.4rem; }
  </style>
</head>
<body>
<main>
  <div class="agent-banner">
    <div class="agent-mark" aria-hidden="true">C</div>
    <div>
      <h1>What Claude Assistant can see</h1>
      <p class="muted">Read with the agent's own access key, not yours. Refresh to check again.</p>
    </div>
  </div>
  ${body}
</main>
</body>
</html>`;
}

async function render(): Promise<string> {
  const stored = loadGrant();
  if (!stored) {
    return page(`<section class="card denied"><h2>Not connected</h2>
      <p>Run <code>npm run agent:connect</code> and approve access first.</p></section>`);
  }

  const api = createDataApi(stored.access_token);
  try {
    const grant = await api.whoami();
    const [tasks, notes] = await Promise.all([api.listTasks(), api.searchNotes()]);
    const access = [
      grant.scopes.includes("tasks:read") ? "Tasks" : null,
      grant.scopes.includes("notes:read") ? `Notes in: ${grant.note_folders?.join(", ") ?? "all folders"}` : null,
    ].filter(Boolean);

    return page(`
      <section class="card">
        <span class="pill active">access active</span>
        <p>Allowed by the user: <strong>${escapeHtml(access.join(" · "))}</strong></p>
      </section>
      <section class="card">
        <h2>Notes (${notes.length})</h2>
        ${notes.length === 0 ? `<p class="muted">No notes visible.</p>` : `
        <table>
          <thead><tr><th>Note</th><th>Folder</th></tr></thead>
          <tbody>${notes.map((n) => `<tr><td>${escapeHtml(n.title)}</td><td>${escapeHtml(n.folder)}</td></tr>`).join("")}</tbody>
        </table>`}
      </section>
      <section class="card">
        <h2>Tasks (${tasks.length})</h2>
        ${tasks.length === 0 ? `<p class="muted">No tasks visible.</p>` : `
        <table>
          <thead><tr><th>Task</th><th>Status</th><th>Due</th></tr></thead>
          <tbody>${tasks.map((t) => `<tr><td>${escapeHtml(t.title)}</td><td>${escapeHtml(t.status)}</td><td>${escapeHtml(t.due_date ?? "—")}</td></tr>`).join("")}</tbody>
        </table>`}
      </section>`);
  } catch (err) {
    if (!(err instanceof AgentAccessError)) throw err;
    return page(`
      <section class="card denied stack">
        <span class="pill revoked">access refused</span>
        <h2>Access denied</h2>
        <p>${escapeHtml(REASONS[err.reason] ?? err.reason)}</p>
        ${err.detail ? `<p class="muted">${escapeHtml(err.detail)}</p>` : ""}
        <p><strong>No data was read.</strong></p>
      </section>`);
  }
}

createServer(async (req, res) => {
  if (new URL(req.url ?? "/", "http://localhost").pathname !== "/") {
    res.writeHead(404).end();
    return;
  }
  try {
    const html = await render();
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    res.end(html);
  } catch (err) {
    res.writeHead(500, { "content-type": "text/plain" }).end(`Error: ${(err as Error).message}`);
  }
}).listen(PORT, () => {
  const url = `http://localhost:${PORT}`;
  console.log(`Agent view: ${url}  (Ctrl+C to stop)`);
  exec(process.platform === "win32" ? `start "" "${url}"` : `open "${url}"`);
});
