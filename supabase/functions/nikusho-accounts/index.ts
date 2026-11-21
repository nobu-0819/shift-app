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

Deno.serve(async (request) => {
  if (request.method === "OPTIONS") return new Response(null, { headers });
  if (request.method !== "POST") return reply({ error: "method" }, 405);
  const authorization = request.headers.get("Authorization");
  if (!authorization?.startsWith("Bearer ")) return reply({ error: "unauthorized" }, 401);
  const url = Deno.env.get("SUPABASE_URL")!;
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
  const auth = { persistSession: false, autoRefreshToken: false };
  const caller = createClient(url, anonKey, { auth, global: { headers: { Authorization: authorization } } });
  const { data: member, error: sessionError } = await caller.rpc("nikusho_current_account");
  if (sessionError || !member) return reply({ error: "unauthorized" }, 401);

  let input;
  try { input = await request.json(); } catch { return reply({ error: "invalid_input" }, 400); }
  if (!input || typeof input !== "object") return reply({ error: "invalid_input" }, 400);
  const { action } = input;
  if (action !== "change" && (!member.is_admin || member.password_setup_required)) {
    return reply({ error: "forbidden" }, 403);
  }
  if (!["register", "reset", "change", "delete"].includes(action)) return reply({ error: "invalid_action" }, 400);

  const db = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth });
  let target = action === "change" ? String(member.id) : input.staffId;
  if (action === "register") {
    const name = typeof input.name === "string" ? input.name.trim() : "";
    const code = typeof input.code === "string" ? input.code.trim() : "";
    if (!name || name.length > 100 || !/^[0-9]{1,10}$/.test(code)) return reply({ error: "invalid_staff" }, 400);
    const { data, error } = await db.from("staff").insert({ name, code }).select("id").single();
    if (error) return reply({ error: "staff_registration_failed" }, 409);
    target = String(data.id);
  }
  if (typeof target !== "string" || !target || (action !== "change" && target === String(member.id))) {
    return reply({ error: "invalid_staff" }, 400);
  }

  const { data: account, error: lookupError } = await db.from("staff")
    .select("id,code,auth_user_id,password_reset_at").eq("id", target).maybeSingle();
  if (lookupError || !account) return reply({ error: "staff_not_found" }, 404);
  const email = await loginAddress(String(account.code));
  let password = crypto.randomUUID();
  if (action === "change") {
    if (typeof input.password !== "string" || input.password.length < 10 || new TextEncoder().encode(input.password).length > 72
      || typeof input.currentPassword !== "string" || input.currentPassword === input.password) {
      return reply({ error: "invalid_password" }, 400);
    }
    const identity = createClient(url, anonKey, { auth });
    const { data, error } = await identity.auth.signInWithPassword({ email, password: input.currentPassword });
    if (error || data.user?.id !== account.auth_user_id) return reply({ error: "invalid_credentials" }, 401);
    await identity.auth.signOut({ scope: "local" });
    password = input.password;
  }
  // Serialize credential changes and prevent existing sessions from accessing
  // application data while Auth and the staff record are being updated.
  let lock = db.from("staff").update({ account_locked: true }).eq("id", target).eq("account_locked", false);
  lock = account.password_reset_at
    ? lock.eq("password_reset_at", account.password_reset_at)
    : lock.is("password_reset_at", null);
  const { data: locked, error: lockError } = await lock.select("id").maybeSingle();
  if (lockError || !locked) return reply({ error: "account_locked" }, 409);

  let userId = account.auth_user_id;
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
  if (userId) {
    const { error } = await db.auth.admin.updateUserById(userId, { password });
    if (error) return reply({ error: "password_update_failed" }, 502);
  } else {
    const { data, error } = await db.auth.admin.createUser({ email, password, email_confirm: true });
    if (error || !data.user) return reply({ error: "account_creation_failed" }, 502);
    userId = data.user.id;
  }

  const { data: finished, error: finishError } = await db.rpc("nikusho_finish_password_change", {
    target_staff_id: target,
    target_auth_user_id: userId,
    setup_required: action !== "change",
  });
  if (finishError || !finished) return reply({ error: "account_link_failed" }, 502);
  return action === "change" ? reply({ ok: true }) : reply({ temporaryPassword: password, staffCode: String(account.code) });
});
