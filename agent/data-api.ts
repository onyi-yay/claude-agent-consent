// The agent's only path to user data: the Supabase Data API with the anon key
// plus its grant token. Every row it gets back has passed RLS for that grant.
import { createClient, type PostgrestError } from "@supabase/supabase-js";
import { config } from "./config.ts";

const ACCESS_ERRORS = new Set([
  "agent_grant_revoked",
  "agent_grant_expired",
  "invalid_agent_token",
  "missing_agent_token",
]);

/** The user revoked the grant, it expired, or the token is unknown. */
export class AgentAccessError extends Error {
  constructor(
    readonly reason: string,
    readonly detail: string | null,
  ) {
    super(detail ? `${reason}: ${detail}` : reason);
  }
}

export type Whoami = {
  grant_id: string;
  client_id: string;
  scopes: string[];
  note_folders: string[] | null;
  expires_at: string;
};

export function createDataApi(token: string) {
  const db = createClient(config.supabaseUrl, config.supabaseAnonKey, {
    global: { headers: { "x-agent-token": token } },
    auth: { persistSession: false, autoRefreshToken: false },
  });

  function unwrap<T>(result: { data: T | null; error: PostgrestError | null; status: number }): T {
    if (result.error) {
      if (result.status === 401 && ACCESS_ERRORS.has(result.error.message)) {
        throw new AgentAccessError(result.error.message, result.error.details || null);
      }
      throw new Error(`Data API error ${result.status}: ${result.error.message}`);
    }
    return result.data as T;
  }

  return {
    async whoami(): Promise<Whoami> {
      return unwrap(await db.rpc("agent_whoami"));
    },

    async listTasks(status?: "todo" | "doing" | "done") {
      let query = db.from("tasks").select("id, title, status, due_date").order("due_date", { nullsFirst: false });
      if (status) query = query.eq("status", status);
      return unwrap(await query.limit(100));
    },

    async searchNotes(text?: string, folder?: string) {
      let query = db.from("notes").select("id, folder, title, body, created_at").order("created_at", { ascending: false });
      if (folder) query = query.eq("folder", folder);
      // Strip PostgREST filter syntax characters from model-supplied text.
      const term = text?.replace(/[,()*%\\.:"]/g, " ").trim();
      if (term) query = query.or(`title.ilike.*${term}*,body.ilike.*${term}*`);
      return unwrap(await query.limit(50));
    },
  };
}

export type DataApi = ReturnType<typeof createDataApi>;
