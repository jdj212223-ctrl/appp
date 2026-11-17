// The RealismPhoneOS App Store on Cloudflare Workers.
//   GET  /                        the store (clean apps)
//   GET  /upload, POST /upload    upload a phone .appp (manifest.json + app.json + optional icon.png)
//   GET  /apps/:id                an app's page (or why it was rejected)
//   GET  /apps/:id/download       the stamped .appp (clean apps only)
//   GET  /apps/:id/icon.png
//   GET  /api/phone/apps          clean apps (what the phone's App Store app lists)
//   GET  /api/phone/apps/:id      one app's manifest + app.json (what the phone installs)
//   GET  /stamp-key               the public key stamps are signed with
// Same API as the Rust appp server, so Realism's appStoreUrl can point at either.

import { unzipSync, zipSync } from "fflate";
import { scan, MAX_APP_BYTES } from "./scan.js";
import { makeStamp, publicKey } from "./stamp.js";

const MAX_UPLOAD = 1024 * 1024; // phone apps are tiny

const esc = (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const validId = (id) => /^[0-9a-f]{12}$/.test(id);
const newId = () => [...crypto.getRandomValues(new Uint8Array(6))].map((b) => b.toString(16).padStart(2, "0")).join("");
const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json; charset=utf-8", "access-control-allow-origin": "*" } });

const STYLE = `<style>
:root{--bg:#0e1013;--card:#171a1f;--line:#262a31;--fg:#e9ecef;--dim:#9aa3ad;--acc:#4f8cff;--ok:#36c26b;--bad:#ff5d5d;--warn:#f0b23e}
@media(prefers-color-scheme:light){:root{--bg:#f6f7f9;--card:#fff;--line:#e2e5ea;--fg:#15181c;--dim:#5b6470}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,"Segoe UI",system-ui,sans-serif}
header{display:flex;align-items:center;gap:16px;padding:14px 24px;border-bottom:1px solid var(--line)}
header b{font-size:18px}header b span{color:var(--acc)}header nav{margin-left:auto;display:flex;gap:10px}
a{color:var(--acc);text-decoration:none}.btn{background:var(--acc);color:#fff;padding:8px 14px;border-radius:9px;font-weight:600;border:0;cursor:pointer;font:inherit}
.btn.ghost{background:var(--card);color:var(--fg);border:1px solid var(--line)}
main{max-width:980px;margin:0 auto;padding:28px 20px}
.hero{background:linear-gradient(135deg,#1d2b4f,#0f1626);color:#fff;border-radius:18px;padding:26px;margin-bottom:22px}
.hero h1{margin:0 0 6px}.hero p{margin:0;color:#c9d4ea}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px}
.app{display:flex;flex-direction:column;gap:6px;color:var(--fg)}.app:hover{border-color:var(--acc)}
.icon{width:56px;height:56px;border-radius:14px;background:#2a3550 center/cover;display:grid;place-items:center;font-size:26px}
.dim{color:var(--dim)}.small{font-size:13px}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:700}
.clean{background:#173a25;color:var(--ok)}.rejected{background:#3d1717;color:var(--bad)}
.perm{background:#2b2f3a;color:#c8d2e8;margin-right:4px}
ul.rep{margin:6px 0 0;padding-left:20px}ul.rep li{margin:3px 0}.bad{color:var(--bad)}.warn{color:var(--warn)}
input,textarea{width:100%;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:9px;padding:10px;font:inherit}
label{display:block;margin:14px 0 6px;font-weight:600}
.phone{width:160px;border:6px solid #222;border-radius:22px;background:#0b0f19;color:#ddd;padding:8px;font:12px monospace}
.phone .t{background:#0f1626;text-align:center;padding:3px;margin:-2px -2px 6px;border-radius:6px;color:#fff}
.phone .b{border:1px solid #3a4560;border-radius:5px;padding:3px;margin-top:5px;text-align:center;background:#1b2338}
code{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:1px 6px}
@media(max-width:600px){header{flex-wrap:wrap;padding:12px 16px}main{padding:18px 16px}}
</style>`;

const page = (title, body) => new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · RealismPhoneOS App Store</title>${STYLE}</head><body>
<header><a href="/"><b>app<span>p</span></b></a><span class="dim small">the RealismPhoneOS App Store</span>
<nav><a class="btn ghost" href="/">Apps</a><a class="btn" href="/upload">Upload</a></nav></header><main>${body}</main></body></html>`,
  { headers: { "content-type": "text/html; charset=utf-8" } });

const perms = (row) => { try { return JSON.parse(row.permissions || "[]"); } catch { return []; } };
const icon = (row) => `<div class="icon" style="background-image:url(/apps/${row.id}/icon.png)">📱</div>`;

async function storePage(env) {
  const { results } = await env.DB.prepare("SELECT * FROM apps WHERE status='clean' ORDER BY uploaded_at DESC LIMIT 200").all();
  const cards = results.map((r) => `<a class="card app" href="/apps/${r.id}">${icon(r)}<b>${esc(r.name)}</b>
<span class="dim small">${esc(r.version)} · ${esc(r.author || "unknown author")}</span>
<span class="small">${esc(String(r.description || "").slice(0, 90))}</span>
<span>${perms(r).map((p) => `<span class="pill perm">${esc(p)}</span>`).join("")}</span></a>`).join("");
  return page("Apps", `<div class="hero"><h1>📲 RealismPhoneOS App Store</h1>
<p>Apps for the phone in the Realism Minecraft mod. Every app here was scanned: no <b>brickers</b> (apps that delete realboot, realkernel or realism-launchd), no <b>spyware</b>, no <b>adware</b>.
In game: open your phone → Apps → App Store.</p></div>
<div class="grid">${cards || '<p class="dim">No apps yet. <a href="/upload">Upload the first one.</a></p>'}</div>`);
}

function uploadPage() {
  return page("Upload", `<h1>Upload a phone app</h1>
<p class="dim">A <b>.appp</b> for RealismPhoneOS: a zip with <code>manifest.json</code> (name, version, author, description, permissions) and
<code>app.json</code> (screens with buttons and actions), plus an optional <code>icon.png</code>. It's scanned first: apps that would brick the phone,
spy on you or show background ads are rejected, and only clean ones get a page. Make one with <code>appp pack my-app/</code>.</p>
<form class="card" method="post" action="/upload" enctype="multipart/form-data">
<label>File (.appp)</label><input type="file" name="file" accept=".appp,.zip" required>
<label>Author <span class="dim">(optional, replaces the manifest's)</span></label><input name="author" maxlength="80">
<label>Description <span class="dim">(optional)</span></label><textarea name="description" rows="3" maxlength="600"></textarea>
<p><button class="btn" type="submit">Upload and scan</button></p></form>`);
}

async function upload(req, env) {
  const form = await req.formData();
  const file = form.get("file");
  if (!file || typeof file === "string") return new Response("no file", { status: 400 });
  if (file.size > MAX_UPLOAD) return new Response("phone apps must be under 1 MB", { status: 413 });
  const id = newId();
  const author = String(form.get("author") || "").slice(0, 80), description = String(form.get("description") || "").slice(0, 600);
  let manifest = null, app = null, appBytes = 0, iconBytes = null, report;
  try {
    // Only the three files a phone app has; anything else in the zip is ignored (and never served).
    const files = unzipSync(new Uint8Array(await file.arrayBuffer()), { filter: (f) => ["manifest.json", "app.json", "icon.png"].includes(f.name) && f.originalSize <= MAX_APP_BYTES * 8 });
    if (files["app.json"]) { appBytes = files["app.json"].length; app = JSON.parse(new TextDecoder().decode(files["app.json"])); }
    if (files["manifest.json"]) manifest = JSON.parse(new TextDecoder().decode(files["manifest.json"]));
    if (files["icon.png"] && files["icon.png"].length < 256 * 1024) iconBytes = files["icon.png"];
    if (!app) throw new Error("no app.json: this isn't a RealismPhoneOS app");
    if (manifest && author) manifest.author = author;
    if (manifest && description) manifest.description = description;
    report = scan(manifest, app, appBytes);
  } catch (e) {
    report = { verdict: "rejected", kind: "broken", problems: [`broken: ${e.message}`], warnings: [], notes: [] };
  }
  const now = Math.floor(Date.now() / 1000);
  let size = 0;
  if (report.verdict === "clean") {
    const enc = (o) => new TextEncoder().encode(JSON.stringify(o, null, 2));
    const parts = { "manifest.json": enc(manifest), "app.json": enc(app) };
    if (iconBytes) parts["icon.png"] = iconBytes;
    const stamp = await makeStamp(env, parts, report.warnings);
    const zipped = zipSync({ ...parts, "stamp.json": enc(stamp) });
    size = zipped.length;
    await env.FILES.put(`apps/${id}.appp`, zipped, { httpMetadata: { contentType: "application/vnd.appp+zip" } });
    await env.FILES.put(`apps/${id}/app.json`, JSON.stringify({ id, manifest, app }), { httpMetadata: { contentType: "application/json" } });
    if (iconBytes) await env.FILES.put(`icons/${id}.png`, iconBytes, { httpMetadata: { contentType: "image/png" } });
  }
  await env.DB.prepare("INSERT INTO apps (id,status,name,version,author,description,permissions,report,uploaded_at,size) VALUES (?,?,?,?,?,?,?,?,?,?)")
    .bind(id, report.verdict, String(manifest?.name ?? file.name).slice(0, 40), String(manifest?.version ?? ""), String(manifest?.author ?? author),
      String(manifest?.description ?? description), JSON.stringify(Array.isArray(manifest?.permissions) ? manifest.permissions : []), JSON.stringify(report), now, size).run();
  return Response.redirect(new URL(`/apps/${id}`, req.url).toString(), 303);
}

/** A little phone mock-up of the app's start screen. */
function preview(app) {
  const sc = app?.screens?.[app.start ?? "main"];
  if (!sc) return "";
  const lines = (sc.text ?? []).map((l) => `<div>${esc(l)}</div>`).join("");
  const buttons = (sc.buttons ?? []).map((b) => `<div class="b">${esc(b.label)}</div>`).join("");
  return `<div class="phone"><div class="t">${esc(sc.title)}</div>${lines}${buttons}</div>`;
}

async function appPage(env, id) {
  const r = await env.DB.prepare("SELECT * FROM apps WHERE id=?").bind(id).first();
  if (!r) return new Response("not found", { status: 404 });
  const rep = JSON.parse(r.report || "{}");
  const list = (items, cls) => (items ?? []).map((x) => `<li class="${cls}">${esc(x)}</li>`).join("");
  let details = "";
  if (rep.problems?.length) details += `<h3 class="bad">Why it was rejected (${esc(rep.kind)})</h3><ul class="rep">${list(rep.problems, "bad")}</ul>`;
  if (rep.warnings?.length) details += `<h3 class="warn">Good to know</h3><ul class="rep">${list(rep.warnings, "warn")}</ul>`;
  if (rep.notes?.length) details += `<h3>Checks</h3><ul class="rep dim">${list(rep.notes, "")}</ul>`;
  let shot = "";
  if (r.status === "clean") {
    const obj = await env.FILES.get(`apps/${id}/app.json`);
    if (obj) shot = preview((await obj.json()).app);
  }
  const status = r.status === "clean"
    ? `<span class="pill clean">Scanned clean ✓</span> <a class="btn" style="margin-left:10px" href="/apps/${id}/download">Download .appp</a>`
    : `<span class="pill rejected">Rejected</span> <span class="dim small">no download</span>`;
  return page(r.name, `<div class="card" style="display:flex;gap:18px;align-items:center;flex-wrap:wrap">${icon(r)}
<div><h1 style="margin:0">${esc(r.name)}</h1><div class="dim">📱 RealismPhoneOS app · ${esc(r.version)} · ${esc(r.author || "unknown author")}</div>
<p style="margin:10px 0 0">${status}</p></div></div>
<div class="card" style="margin-top:14px;display:flex;gap:22px;flex-wrap:wrap"><div style="flex:1;min-width:240px"><p>${esc(r.description)}</p>
<p>${perms(r).map((p) => `<span class="pill perm">${esc(p)}</span>`).join("") || '<span class="dim small">no permissions</span>'}</p>${details}
${r.status === "clean" ? `<p class="dim small">In game: phone → Apps → App Store → ${esc(r.name)}. Or download the .appp and sideload it.</p>` : ""}</div>${shot}</div>`);
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const parts = url.pathname.split("/").filter(Boolean);
    try {
      if (req.method === "POST" && url.pathname === "/upload") return await upload(req, env);
      if (req.method !== "GET" && req.method !== "HEAD") return new Response("method not allowed", { status: 405 });
      if (url.pathname === "/") return await storePage(env);
      if (url.pathname === "/upload") return uploadPage();
      if (url.pathname === "/stamp-key") return new Response(await publicKey(env));
      if (url.pathname === "/api/phone/apps") {
        const { results } = await env.DB.prepare("SELECT * FROM apps WHERE status='clean' ORDER BY uploaded_at DESC LIMIT 200").all();
        return json(results.map((r) => ({ id: r.id, name: r.name, version: r.version, author: r.author, description: r.description,
          permissions: perms(r), warnings: JSON.parse(r.report || "{}").warnings ?? [] })));
      }
      if (parts[0] === "api" && parts[1] === "phone" && parts[2] === "apps" && validId(parts[3] ?? "")) {
        const row = await env.DB.prepare("SELECT status FROM apps WHERE id=?").bind(parts[3]).first();
        const obj = row?.status === "clean" ? await env.FILES.get(`apps/${parts[3]}/app.json`) : null;
        return obj ? json(await obj.json()) : json({ error: "not found" }, 404);
      }
      if (parts[0] === "apps" && validId(parts[1] ?? "")) {
        const id = parts[1];
        if (parts.length === 2) return await appPage(env, id);
        if (parts[2] === "download") {
          const row = await env.DB.prepare("SELECT name,version,status FROM apps WHERE id=?").bind(id).first();
          const obj = row?.status === "clean" ? await env.FILES.get(`apps/${id}.appp`) : null;
          if (!obj) return new Response("not found", { status: 404 });
          const fname = `${row.name}-${row.version}`.replace(/[^A-Za-z0-9.-]/g, "_") + ".appp";
          return new Response(obj.body, { headers: { "content-type": "application/vnd.appp+zip", "content-disposition": `attachment; filename="${fname}"` } });
        }
        if (parts[2] === "icon.png") {
          const obj = await env.FILES.get(`icons/${id}.png`);
          return obj ? new Response(obj.body, { headers: { "content-type": "image/png", "cache-control": "public, max-age=86400" } }) : new Response("", { status: 404 });
        }
      }
      return new Response("not found", { status: 404 });
    } catch (e) {
      return new Response(`server error: ${e.message}`, { status: 500 });
    }
  },
};
