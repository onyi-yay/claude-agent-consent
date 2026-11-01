import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.45.4/+esm";

const { supabaseUrl, supabaseAnonKey } = window.APP_CONFIG;
export const supabase = createClient(supabaseUrl, supabaseAnonKey);

export const SCOPE_LABELS = {
  "notes:read": "Read your notes",
  "tasks:read": "Read your tasks",
};
export const NOTE_FOLDERS = ["work", "personal", "health", "finance"];

export const $ = (selector) => document.querySelector(selector);

export function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

// Renders a sign-in / sign-up form into `container`; resolves with the session.
export async function requireSession(container) {
  const { data } = await supabase.auth.getSession();
  if (data.session) return data.session;

  container.innerHTML = `
    <form class="card stack" id="auth-form">
      <h2>Sign in</h2>
      <label>Email <input name="email" type="email" required autocomplete="email"></label>
      <label>Password <input name="password" type="password" required minlength="6" autocomplete="current-password"></label>
      <div class="row">
        <button type="submit" name="mode" value="signin">Sign in</button>
        <button type="submit" name="mode" value="signup" class="secondary">Create account</button>
      </div>
      <p class="muted" id="auth-message" role="status"></p>
    </form>`;

  return new Promise((resolve) => {
    const form = container.querySelector("#auth-form");
    const message = container.querySelector("#auth-message");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const mode = event.submitter?.value ?? "signin";
      const credentials = { email: form.email.value, password: form.password.value };
      message.textContent = "Working…";
      const { data, error } =
        mode === "signup"
          ? await supabase.auth.signUp(credentials)
          : await supabase.auth.signInWithPassword(credentials);
      if (error) {
        message.textContent = error.message;
      } else if (!data.session) {
        message.textContent = "Check your email to confirm your account, then sign in.";
      } else {
        resolve(data.session);
      }
    });
  });
}
