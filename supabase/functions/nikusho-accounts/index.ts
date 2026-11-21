import { createClient } from "npm:@supabase/supabase-js@2.95.3";

const headers = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Cache-Control": "no-store",
  "Content-Type": "application/json",
};
const reply = (body: object, status = 200) =>
  new Response(JSON.stringify(body), { status, headers });

async function loginAddress(code: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(code));
  const hex = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  return hex + "@login.shift-app.invalid";
}

function validPassword(password: unknown): password is string {
  return typeof password === "string" && /^[0-9]{4}$/.test(password);
}

// Supabase Auth needs a longer credential. Derive it inside the Edge
// Function so the browser only handles the four digits entered by the user.
async function authPassword(code: string, pin: string) {
  const secret = Deno.env.get("NIKUSHO_PIN_SECRET");
  if (!secret || secret.length < 32) throw new Error("PIN secret is not configured");
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const bytes = await crypto.subtle.sign("HMAC", key, encoder.encode(JSON.stringify([code, pin])));
  const digest = Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, "0")).join("");
  return "N1!" + digest;
}

Deno.serve(async (request) => {
  if (request.method === "OPTIONS") return new Response(null, { headers });
  if (request.method !== "POST") return reply({ error: "method" }, 405);
  let input;
  try { input = await request.json(); } catch { return reply({ error: "invalid_input" }, 400); }
  if (!input || typeof input !== "object") return reply({ error: "invalid_input" }, 400);
  const { action } = input;
  const url = Deno.env.get("SUPABASE_URL")!;
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
  const auth = { persistSession: false, autoRefreshToken: false };
  const service = () => createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth });

  if (action === "login") {
    const code = typeof input.code === "string" ? input.code.trim() : "";
    if (!/^[0-9]{1,10}$/.test(code) || !validPassword(input.password)) {
      return reply({ error: "invalid_credentials" }, 401);
    }
    const identity = createClient(url, anonKey, { auth });
    const { data, error } = await identity.auth.signInWithPassword({
      email: await loginAddress(code), password: await authPassword(code, input.password)
    });
    if (error || !data.session) return reply({ error: "invalid_credentials" }, 401);
    return reply({ access_token: data.session.access_token, refresh_token: data.session.refresh_token });
  }

  if (action === "activate") {
    const code = typeof input.code === "string" ? input.code.trim() : "";
    if (!/^[0-9]{1,10}$/.test(code) || !validPassword(input.password)) {
      return reply({ error: "invalid_input" }, 400);
    }
    const password = await authPassword(code, input.password);
    const db = service();
    const { data: account, error } = await db.rpc("nikusho_claim_password_setup", { staff_code: code });
    if (error) return reply({ error: "setup_unavailable" }, 502);
    if (account?.rate_limited) return reply({ error: "rate_limited" }, 429);
    if (!account) return reply({ error: "setup_unavailable" }, 403);
    const userId = account.auth_user_id;
    if (userId) {
      const { error } = await db.auth.admin.updateUserById(userId, { password });
      if (error) return reply({ error: "setup_unavailable" }, 502);
    } else {
      const email = await loginAddress(String(account.code));
      const { data, error } = await db.auth.admin.createUser({ email, password, email_confirm: true });
      if (error || !data.user) return reply({ error: "setup_unavailable" }, 502);
      account.auth_user_id = data.user.id;
    }
    const { data: finished, error: finishError } = await db.rpc("nikusho_finish_password_change", {
      target_staff_id: account.id,
      target_auth_user_id: account.auth_user_id,
    });
    if (finishError || !finished) return reply({ error: "setup_unavailable" }, 502);
    return reply({ ok: true });
  }

  const authorization = request.headers.get("Authorization");
  if (!authorization?.startsWith("Bearer ")) return reply({ error: "unauthorized" }, 401);
  const caller = createClient(url, anonKey, { auth, global: { headers: { Authorization: authorization } } });
  const { data: member, error: sessionError } = await caller.rpc("nikusho_current_account");
  if (sessionError || !member) return reply({ error: "unauthorized" }, 401);
  if (member.password_setup_required || (action !== "change" && !member.is_admin)) {
    return reply({ error: "forbidden" }, 403);
  }
  if (!["register", "reset", "change", "delete"].includes(action)) return reply({ error: "invalid_action" }, 400);
  const db = service();
  let target = action === "change" ? String(member.id) : input.staffId;
  if (action === "register") {
    const name = typeof input.name === "string" ? input.name.trim() : "";
    const code = typeof input.code === "string" ? input.code.trim() : "";
    if (!name || name.length > 100 || !/^[0-9]{1,10}$/.test(code)) return reply({ error: "invalid_staff" }, 400);
    const { data, error } = await db.from("staff").insert({
      name, code, is_admin: false, is_external_viewer: false
    }).select("id").single();
    if (error) return reply({ error: "staff_registration_failed" }, 409);
    target = String(data.id);
  }
  if (typeof target !== "string" || !target || (action !== "change" && target === String(member.id))) {
    return reply({ error: "invalid_staff" }, 400);
  }

  const { data: account, error: lookupError } = await db.from("staff")
    .select("id,code,auth_user_id,password_reset_at").eq("id", target).maybeSingle();
  if (lookupError || !account) return reply({ error: "staff_not_found" }, 404);
  if (action === "register") return reply({ staffCode: String(account.code) });
  if (action === "reset") {
    const { data: reset, error } = await db.rpc("nikusho_reset_password_setup", { target_staff_id: target });
    if (error || !reset) return reply({ error: "setup_unavailable" }, 409);
    return reply({ staffCode: String(account.code) });
  }
  if (action === "change") {
    if (!validPassword(input.password) || !validPassword(input.currentPassword)
      || input.currentPassword === input.password) {
      return reply({ error: "invalid_password" }, 400);
    }
    const email = await loginAddress(String(account.code));
    const identity = createClient(url, anonKey, { auth });
    const { data, error } = await identity.auth.signInWithPassword({ email, password: await authPassword(String(account.code), input.currentPassword) });
    if (error || !data.user || data.user.id !== account.auth_user_id) return reply({ error: "invalid_credentials" }, 401);
    await identity.auth.signOut({ scope: "local" });
  }
  // Serialize credential changes and prevent existing sessions from accessing
  // application data while Auth and the staff record are being updated.
  let lock = db.from("staff").update({ account_locked: true }).eq("id", target).eq("account_locked", false);
  lock = account.password_reset_at
    ? lock.eq("password_reset_at", account.password_reset_at)
    : lock.is("password_reset_at", null);
  const { data: locked, error: lockError } = await lock.select("id").maybeSingle();
  if (lockError || !locked) return reply({ error: "account_locked" }, 409);

  const userId = account.auth_user_id;
  if (action === "delete") {
    const { error } = await db.from("staff").delete().eq("id", target);
    if (error) {
      await db.from("staff").update({ account_locked: false }).eq("id", target);
      return reply({ error: "staff_delete_failed" }, 409);
    }
    if (userId) {
      const { error: authDeleteError } = await db.auth.admin.deleteUser(userId);
      if (authDeleteError) return reply({ error: "identity_delete_failed" }, 502);
    }
    return reply({ ok: true });
  }
  const { error } = await db.auth.admin.updateUserById(userId, {
    password: await authPassword(String(account.code), input.password)
  });
  if (error) return reply({ error: "password_update_failed" }, 502);
  const { data: finished, error: finishError } = await db.rpc("nikusho_finish_password_change", {
    target_staff_id: target,
    target_auth_user_id: userId,
  });
  if (finishError || !finished) return reply({ error: "account_link_failed" }, 502);
  return reply({ ok: true });
});
