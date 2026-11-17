//! The upload server (axum + SQLite). Uploads land in data/incoming, get unpacked into a throwaway folder, checked,
//! scanned, and only clean ones become a stamped .appp in data/apps with a public page. Rejected uploads go to
//! data/quarantine and never get a download link.

use crate::package::{self, Manifest};
use crate::{scan, stamp};
use axum::extract::{DefaultBodyLimit, Multipart, Path as UrlPath, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub struct App {
    pub data: PathBuf,
    pub db: Mutex<Connection>,
    pub key: SigningKey,
    pub name: String,
}

type S = State<Arc<App>>;

pub async fn serve(data: PathBuf, addr: String, name: String) {
    for d in ["incoming", "work", "apps", "quarantine", "icons"] {
        fs::create_dir_all(data.join(d)).expect("can't create data folders");
    }
    let db = Connection::open(data.join("appp.db")).expect("can't open the database");
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS apps (
            id TEXT PRIMARY KEY, status TEXT NOT NULL, name TEXT, version TEXT, bundle_id TEXT, author TEXT,
            description TEXT, uploaded_at INTEGER, size INTEGER, report TEXT);",
    )
    .unwrap();
    let key = stamp::load_or_create_key(&data);
    let state = Arc::new(App { data, db: Mutex::new(db), key, name });
    let app = Router::new()
        .route("/", get(index))
        .route("/upload", get(upload_page).post(upload))
        .route("/apps/{id}", get(app_page))
        .route("/apps/{id}/download", get(download))
        .route("/apps/{id}/icon.png", get(icon))
        .route("/api/apps", get(api_apps))
        .route("/api/apps/{id}", get(api_app))
        .route("/stamp-key", get(stamp_key))
        .layer(DefaultBodyLimit::max(1024 * 1024 * 1024))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("can't listen on that address");
    println!("appp server on http://{addr}  (data in {})", listener.local_addr().map(|a| a.to_string()).unwrap_or_default());
    axum::serve(listener, app).await.unwrap();
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn new_id() -> String {
    let mut b = [0u8; 6];
    let _ = getrandom::fill(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn valid_id(id: &str) -> bool {
    id.len() == 12 && id.chars().all(|c| c.is_ascii_hexdigit())
}

#[derive(serde::Serialize)]
struct Row {
    id: String,
    status: String,
    name: String,
    version: String,
    bundle_id: String,
    author: String,
    description: String,
    uploaded_at: i64,
    size: i64,
    report: serde_json::Value,
}

fn rows(app: &App, where_sql: &str, p: &[&dyn rusqlite::ToSql]) -> Vec<Row> {
    let db = app.db.lock().unwrap();
    let mut st = db
        .prepare(&format!(
            "SELECT id,status,IFNULL(name,''),IFNULL(version,''),IFNULL(bundle_id,''),IFNULL(author,''),IFNULL(description,''),
             IFNULL(uploaded_at,0),IFNULL(size,0),IFNULL(report,'{{}}') FROM apps {where_sql} ORDER BY uploaded_at DESC"
        ))
        .unwrap();
    st.query_map(p, |r| {
        Ok(Row {
            id: r.get(0)?,
            status: r.get(1)?,
            name: r.get(2)?,
            version: r.get(3)?,
            bundle_id: r.get(4)?,
            author: r.get(5)?,
            description: r.get(6)?,
            uploaded_at: r.get(7)?,
            size: r.get(8)?,
            report: serde_json::from_str(&r.get::<_, String>(9)?).unwrap_or_default(),
        })
    })
    .unwrap()
    .filter_map(Result::ok)
    .collect()
}

const STYLE: &str = r#"<style>
:root{--bg:#0e1013;--card:#171a1f;--line:#262a31;--fg:#e9ecef;--dim:#9aa3ad;--acc:#4f8cff;--ok:#36c26b;--bad:#ff5d5d;--warn:#f0b23e}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,"Segoe UI",system-ui,sans-serif}
header{display:flex;align-items:center;gap:16px;padding:14px 24px;border-bottom:1px solid var(--line)}
header b{font-size:18px}header b span{color:var(--acc)}header nav{margin-left:auto;display:flex;gap:10px}
a{color:var(--acc);text-decoration:none}.btn{background:var(--acc);color:#fff;padding:8px 14px;border-radius:9px;font-weight:600;border:0;cursor:pointer;font:inherit}
.btn.ghost{background:var(--card);color:var(--fg);border:1px solid var(--line)}
main{max-width:980px;margin:0 auto;padding:28px 20px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px}
.app{display:flex;flex-direction:column;gap:8px;color:var(--fg)}.app:hover{border-color:var(--acc)}
.icon{width:64px;height:64px;border-radius:15px;background:#222 center/cover}
.dim{color:var(--dim)}.small{font-size:13px}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:700}
.clean{background:#173a25;color:var(--ok)}.rejected{background:#3d1717;color:var(--bad)}.scanning{background:#3a3017;color:var(--warn)}
ul.rep{margin:6px 0 0;padding-left:20px}ul.rep li{margin:3px 0}
.bad{color:var(--bad)}.warn{color:var(--warn)}
input,textarea{width:100%;background:#0b0d10;color:var(--fg);border:1px solid var(--line);border-radius:9px;padding:10px;font:inherit}
label{display:block;margin:14px 0 6px;font-weight:600}
@media(max-width:600px){header{flex-wrap:wrap}main{padding:18px 16px}}
</style>"#;

fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{t} · appp</title>{STYLE}</head>
<body><header><a href="/"><b>app<span>p</span></b></a><span class="dim small">apps scanned before they're shared</span>
<nav><a class="btn ghost" href="/">Apps</a><a class="btn" href="/upload">Upload</a></nav></header><main>{body}</main></body></html>"#,
        t = esc(title)
    ))
}

async fn index(State(app): S) -> Html<String> {
    let list = rows(&app, "WHERE status='clean'", &[]);
    let mut cards = String::new();
    for r in &list {
        cards += &format!(
            r#"<a class="card app" href="/apps/{id}"><div class="icon" style="background-image:url(/apps/{id}/icon.png)"></div>
<b>{n}</b><span class="dim small">{v} · {a}</span><span class="small">{d}</span></a>"#,
            id = r.id,
            n = esc(&r.name),
            v = esc(&r.version),
            a = esc(if r.author.is_empty() { "unknown author" } else { &r.author }),
            d = esc(&r.description.chars().take(90).collect::<String>())
        );
    }
    if list.is_empty() {
        cards = r#"<p class="dim">No apps yet. <a href="/upload">Upload the first one.</a></p>"#.into();
    }
    page("Apps", &format!(r#"<h1>Apps</h1><p class="dim">Every app here passed the malware and bricker scan and carries a signed “scanned clean” stamp.</p><div class="grid">{cards}</div>"#))
}

async fn upload_page() -> Html<String> {
    page(
        "Upload",
        r#"<h1>Upload an app</h1>
<p class="dim">A <b>.appp</b> package, or a <b>zipped .app</b> (Finder: right-click the app → Compress). It's scanned before anyone can download it:
known malware, anything that could brick a device (deleting launchd, the kernel or boot files, wiping disks, turning off SIP), and the code signature.</p>
<form class="card" method="post" action="/upload" enctype="multipart/form-data">
<label>File</label><input type="file" name="file" accept=".appp,.zip" required>
<label>Author <span class="dim">(optional)</span></label><input name="author" maxlength="80">
<label>Description <span class="dim">(optional)</span></label><textarea name="description" rows="3" maxlength="600"></textarea>
<p><button class="btn" type="submit">Upload and scan</button></p></form>"#,
    )
}

async fn upload(State(app): S, mut mp: Multipart) -> Response {
    let id = new_id();
    let incoming = app.data.join("incoming").join(format!("{id}.zip"));
    let (mut author, mut description, mut got) = (String::new(), String::new(), false);
    while let Ok(Some(mut field)) = mp.next_field().await {
        match field.name().unwrap_or("") {
            "file" => {
                let mut f = match tokio::fs::File::create(&incoming).await {
                    Ok(f) => f,
                    Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "can't save the upload").into_response(),
                };
                use tokio::io::AsyncWriteExt;
                while let Ok(Some(chunk)) = field.chunk().await {
                    if f.write_all(&chunk).await.is_err() {
                        return (StatusCode::INTERNAL_SERVER_ERROR, "can't save the upload").into_response();
                    }
                    got = true;
                }
            }
            "author" => author = field.text().await.unwrap_or_default().chars().take(80).collect(),
            "description" => description = field.text().await.unwrap_or_default().chars().take(600).collect(),
            _ => {}
        }
    }
    if !got {
        return (StatusCode::BAD_REQUEST, "no file").into_response();
    }
    {
        let db = app.db.lock().unwrap();
        db.execute(
            "INSERT INTO apps (id,status,author,description,uploaded_at,size) VALUES (?1,'scanning',?2,?3,?4,?5)",
            params![id, author, description, now(), fs::metadata(&incoming).map(|m| m.len() as i64).unwrap_or(0)],
        )
        .unwrap();
    }
    let a = app.clone();
    let id2 = id.clone();
    tokio::task::spawn_blocking(move || process(&a, &id2, &incoming, author, description));
    Redirect::to(&format!("/apps/{id}")).into_response()
}

/// Unpack → normalise into a package folder → inspect → scan → stamp (clean) or quarantine (rejected).
fn process(app: &App, id: &str, incoming: &Path, author: String, description: String) {
    let work = app.data.join("work").join(id);
    let pkg = work.join("pkg");
    let raw = work.join("raw");
    let result = (|| -> Result<(Manifest, scan::Report), (String, scan::Report)> {
        let fail = |m: String| (m, scan::Report::default());
        package::unzip(incoming, &raw).map_err(fail)?;
        // An uploaded .appp brings its manifest (and maybe old extras); a zipped .app gets one made for it.
        let up_manifest: Option<Manifest> = fs::read(raw.join("manifest.json")).ok().and_then(|b| serde_json::from_slice(&b).ok());
        let app_dir = up_manifest
            .as_ref()
            .map(|m| raw.join(&m.app_path))
            .filter(|p| !p.as_os_str().is_empty() && p.is_dir() && p.starts_with(&raw))
            .or_else(|| package::find_app(&raw))
            .ok_or_else(|| fail("no .app bundle inside".into()))?;
        let info = package::inspect_app(&app_dir).map_err(fail)?;
        // Name the upload right away, so even a rejected one shows what it was.
        let _ = app.db.lock().unwrap().execute(
            "UPDATE apps SET name=?2,version=?3,bundle_id=?4 WHERE id=?1",
            params![id, info.name, info.version, info.bundle_id],
        );
        let app_name = app_dir.file_name().unwrap().to_string_lossy().to_string();
        fs::create_dir_all(pkg.join("app")).map_err(|e| fail(e.to_string()))?;
        fs::rename(&app_dir, pkg.join("app").join(&app_name)).map_err(|e| fail(e.to_string()))?;
        for extra in ["icon.png", "screenshots"] {
            if raw.join(extra).exists() {
                let _ = fs::rename(raw.join(extra), pkg.join(extra));
            }
        }
        let m = Manifest {
            name: info.name.clone(),
            version: info.version.clone(),
            bundle_id: info.bundle_id.clone(),
            author: if author.is_empty() { up_manifest.as_ref().map(|m| m.author.clone()).unwrap_or_default() } else { author.clone() },
            description: if description.is_empty() { up_manifest.as_ref().map(|m| m.description.clone()).unwrap_or_default() } else { description.clone() },
            app_path: format!("app/{app_name}"),
        };
        fs::write(pkg.join("manifest.json"), serde_json::to_vec_pretty(&m).unwrap()).map_err(|e| fail(e.to_string()))?;
        // Scan everything that will be shipped (not leftovers in the raw upload, which are dropped).
        let bad = bad_hashes(&app.data);
        let mut report = scan::scan(&pkg, &bad);
        // Don't show the server's own folders in reports.
        let prefix = format!("{}/", pkg.display());
        for v in [&mut report.problems, &mut report.warnings, &mut report.notes] {
            for x in v.iter_mut() {
                *x = x.replace(&prefix, "");
            }
        }
        if report.verdict != "clean" {
            return Err(("rejected by the scan".into(), report));
        }
        make_icon(&pkg.join("app").join(&app_name), &app.data.join("icons").join(format!("{id}.png")));
        Ok((m, report))
    })();
    let db = app.db.lock().unwrap();
    match result {
        Ok((m, report)) => {
            let out = app.data.join("apps").join(format!("{id}.appp"));
            let stamped = stamp::make(&pkg, &app.key, &app.name, report.warnings.clone())
                .and_then(|s| package::zip_dir(&pkg, &out, &[("stamp.json", serde_json::to_vec_pretty(&s).unwrap())]));
            match stamped {
                Ok(()) => {
                    db.execute(
                        "UPDATE apps SET status='clean',name=?2,version=?3,bundle_id=?4,author=?5,description=?6,report=?7,size=?8 WHERE id=?1",
                        params![id, m.name, m.version, m.bundle_id, m.author, m.description, serde_json::to_string(&report).unwrap(),
                            fs::metadata(&out).map(|x| x.len() as i64).unwrap_or(0)],
                    )
                    .unwrap();
                    let _ = fs::remove_file(incoming);
                }
                Err(e) => {
                    let r = scan::Report { verdict: "rejected".into(), problems: vec![format!("couldn't build the package: {e}")], ..Default::default() };
                    db.execute("UPDATE apps SET status='rejected',report=?2 WHERE id=?1", params![id, serde_json::to_string(&r).unwrap()]).unwrap();
                }
            }
        }
        Err((why, mut report)) => {
            report.verdict = "rejected".into();
            if report.problems.is_empty() {
                report.problems.push(why);
            }
            let _ = fs::rename(incoming, app.data.join("quarantine").join(format!("{id}.zip")));
            db.execute("UPDATE apps SET status='rejected',report=?2 WHERE id=?1", params![id, serde_json::to_string(&report).unwrap()]).unwrap();
        }
    }
    let _ = fs::remove_dir_all(&work);
}

fn bad_hashes(data: &Path) -> HashSet<String> {
    fs::read_to_string(data.join("bad-hashes.txt"))
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().to_lowercase())
        .filter(|l| l.len() == 64)
        .collect()
}

/// The app's own icon as a PNG for the web page (macOS `sips` converts the .icns).
fn make_icon(app: &Path, out: &Path) {
    let Ok(v) = plist::from_file::<_, plist::Value>(app.join("Contents/Info.plist")) else { return };
    let Some(name) = v.as_dictionary().and_then(|d| d.get("CFBundleIconFile")).and_then(|x| x.as_string()) else { return };
    let mut icns = app.join("Contents/Resources").join(name);
    if icns.extension().is_none() {
        icns.set_extension("icns");
    }
    if icns.is_file() {
        let _ = std::process::Command::new("sips").args(["-s", "format", "png", "-Z", "256"]).arg(&icns).arg("--out").arg(out).output();
    }
}

fn list(items: &[serde_json::Value], class: &str) -> String {
    items.iter().filter_map(|x| x.as_str()).map(|x| format!(r#"<li class="{class}">{}</li>"#, esc(x))).collect()
}

async fn app_page(State(app): S, UrlPath(id): UrlPath<String>) -> Response {
    if !valid_id(&id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(r) = rows(&app, "WHERE id=?1", &[&id]).into_iter().next() else { return StatusCode::NOT_FOUND.into_response() };
    let rep = &r.report;
    let arr = |k: &str| rep.get(k).and_then(|x| x.as_array()).cloned().unwrap_or_default();
    let (problems, warnings, notes) = (arr("problems"), arr("warnings"), arr("notes"));
    let status = match r.status.as_str() {
        "scanning" => r#"<span class="pill scanning">Scanning…</span> <span class="dim small">this page refreshes by itself</span>
<script>setTimeout(()=>location.reload(),1500)</script>"#.to_string(),
        "clean" => format!(r#"<span class="pill clean">Scanned clean ✓</span> <a class="btn" style="margin-left:10px" href="/apps/{}/download">Download .appp</a>"#, r.id),
        _ => r#"<span class="pill rejected">Rejected</span> <span class="dim small">no download: it stays in quarantine</span>"#.to_string(),
    };
    let mut details = String::new();
    if !problems.is_empty() {
        details += &format!(r#"<h3 class="bad">Why it was rejected</h3><ul class="rep">{}</ul>"#, list(&problems, "bad"));
    }
    if !warnings.is_empty() {
        details += &format!(r#"<h3 class="warn">Warnings</h3><ul class="rep">{}</ul>"#, list(&warnings, "warn"));
    }
    if !notes.is_empty() {
        details += &format!(r#"<h3>Checks</h3><ul class="rep dim">{}</ul>"#, list(&notes, ""));
    }
    let files = rep.get("files").and_then(|x| x.as_u64()).unwrap_or(0);
    let body = format!(
        r#"<div class="card" style="display:flex;gap:18px;align-items:center"><div class="icon" style="width:96px;height:96px;border-radius:22px;background-image:url(/apps/{id}/icon.png)"></div>
<div><h1 style="margin:0">{n}</h1><div class="dim">{v} · {b} · {a}</div><p style="margin:10px 0 0">{status}</p></div></div>
<div class="card" style="margin-top:14px"><p>{d}</p><div class="dim small">{files} files · {kb} KB</div>{details}</div>"#,
        id = r.id,
        n = esc(if r.name.is_empty() { "Upload" } else { &r.name }),
        v = esc(&r.version),
        b = esc(&r.bundle_id),
        a = esc(if r.author.is_empty() { "unknown author" } else { &r.author }),
        d = esc(&r.description),
        kb = r.size / 1024,
    );
    page(&r.name, &body).into_response()
}

async fn download(State(app): S, UrlPath(id): UrlPath<String>) -> Response {
    if !valid_id(&id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(r) = rows(&app, "WHERE id=?1 AND status='clean'", &[&id]).into_iter().next() else { return StatusCode::NOT_FOUND.into_response() };
    let Ok(bytes) = tokio::fs::read(app.data.join("apps").join(format!("{id}.appp"))).await else { return StatusCode::NOT_FOUND.into_response() };
    let file = format!("{}-{}.appp", r.name.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-', "_"), r.version.replace(|c: char| !c.is_ascii_alphanumeric() && c != '.', "_"));
    ([(header::CONTENT_TYPE, "application/vnd.appp+zip".to_string()), (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{file}\""))], bytes).into_response()
}

async fn icon(State(app): S, UrlPath(id): UrlPath<String>) -> Response {
    if !valid_id(&id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match tokio::fs::read(app.data.join("icons").join(format!("{id}.png"))).await {
        Ok(b) => ([(header::CONTENT_TYPE, "image/png")], b).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn api_apps(State(app): S) -> Json<Vec<Row>> {
    Json(rows(&app, "WHERE status='clean'", &[]))
}

async fn api_app(State(app): S, UrlPath(id): UrlPath<String>) -> Response {
    match rows(&app, "WHERE id=?1", &[&id]).into_iter().next() {
        Some(r) => Json(r).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn stamp_key(State(app): S) -> String {
    stamp::public_hex(&app.key)
}
