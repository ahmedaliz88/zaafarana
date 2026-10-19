// Cloudflare Worker: a small, safe bridge between the Zaafarana app and the Claude API.
// The API key never reaches the browser. Only signed-in owner / accountant users of the app may call it.
// Secret to add in Cloudflare: ANTHROPIC_API_KEY
const PROJECT = "contractor-d4e31";
const ORIGINS = ["https://ahmedaliz88.github.io"];
const MODEL = "claude-sonnet-5-5";
const MAX_TOKENS = 3000;
const FS = `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/`;
const seen = new Map(); // token -> {ok, until}

function cors(origin) {
  const o = ORIGINS.includes(origin) ? origin : ORIGINS[0];
  return { "Access-Control-Allow-Origin": o, "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization", "Access-Control-Max-Age": "86400", "Vary": "Origin" };
}
function json(obj, status, origin) { return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json; charset=utf-8", ...cors(origin) } }); }
function uidOf(token) { try { const p = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))); return p.user_id || p.sub || ""; } catch (e) { return ""; } }

// Firestore checks the token for us: if this user can read master/main he is a member;
// his roles doc (or its absence for the owner) tells whether he is the owner or an accountant.
async function allowed(token) {
  const c = seen.get(token); if (c && c.until > Date.now()) return c.ok;
  const uid = uidOf(token); if (!uid) return false;
  const H = { Authorization: "Bearer " + token };
  let ok = false;
  const m = await fetch(FS + "master/main?mask.fieldPaths=start", { headers: H });
  if (m.ok) {
    const r = await fetch(FS + "roles/" + uid, { headers: H });
    if (r.status === 404) ok = true; // the owner has no roles doc
    else if (r.ok) { const d = await r.json(); const f = d.fields || {}; const role = f.role && f.role.stringValue; const act = !(f.active && f.active.booleanValue === false); ok = act && (role === "accountant" || role === "owner"); }
  }
  seen.set(token, { ok, until: Date.now() + 5 * 60 * 1000 });
  if (seen.size > 500) seen.clear();
  return ok;
}

export default {
  async fetch(req, env) {
    const origin = req.headers.get("Origin") || "";
    if (req.method === "OPTIONS") return new Response(null, { headers: cors(origin) });
    if (req.method !== "POST") return json({ error: "POST only" }, 405, origin);
    if (!ORIGINS.includes(origin)) return json({ error: "origin" }, 403, origin);
    if (!env.ANTHROPIC_API_KEY) return json({ error: "no_key", message: "أضف ANTHROPIC_API_KEY فى إعدادات الـ Worker" }, 500, origin);
    const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
    if (!token || !(await allowed(token))) return json({ error: "auth", message: "غير مسموح – سجّل دخولك كمالك أو محاسب" }, 403, origin);
    let body; try { body = await req.json(); } catch (e) { return json({ error: "bad_json" }, 400, origin); }
    if (body && body.ping) return json({ ok: true, model: MODEL }, 200, origin);
    const messages = Array.isArray(body.messages) ? body.messages.slice(-60) : null;
    if (!messages || !messages.length) return json({ error: "no_messages" }, 400, origin);
    const payload = { model: MODEL, max_tokens: Math.min(Number(body.max_tokens) || MAX_TOKENS, MAX_TOKENS), messages };
    if (typeof body.system === "string") payload.system = body.system.slice(0, 40000);
    if (Array.isArray(body.tools)) payload.tools = body.tools.slice(0, 30);
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    const text = await r.text();
    return new Response(text, { status: r.status, headers: { "Content-Type": "application/json; charset=utf-8", ...cors(origin) } });
  },
};
