//! The `.appp` package: a zip holding
//!   manifest.json        name, version, bundle id, author, description (made from Info.plist when missing)
//!   app/<Name>.app/...   the macOS app bundle itself
//!   icon.png, screenshots/*.png (optional extras)
//!   stamp.json           added by the server after a clean scan (see stamp.rs)
//! Uploads can also be a plain zipped .app; the server wraps it into a .appp.

use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

/// Unpacking limits, so a "zip bomb" can't fill the disk.
const MAX_FILES: usize = 50_000;
const MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    pub bundle_id: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub description: String,
    /// Path of the .app inside the package, e.g. "app/Scarlet.app".
    #[serde(default)]
    pub app_path: String,
}

/// What we learn from the app bundle itself.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AppInfo {
    pub app_dir: PathBuf,
    pub name: String,
    pub version: String,
    pub bundle_id: String,
    pub executable: String,
}

/// Unzips safely: rejects entries that escape the folder ("../"), absolute paths and symlinks pointing outside, and
/// stops at the size/file limits. Keeps the executable bit.
pub fn unzip(zip_path: &Path, dest: &Path) -> Result<(), String> {
    let f = File::open(zip_path).map_err(|e| format!("can't open upload: {e}"))?;
    let mut z = zip::ZipArchive::new(f).map_err(|_| "not a zip file (a .appp or a zipped .app is expected)".to_string())?;
    if z.len() > MAX_FILES {
        return Err(format!("too many files ({} > {MAX_FILES})", z.len()));
    }
    let mut total = 0u64;
    for i in 0..z.len() {
        let mut e = z.by_index(i).map_err(|e| format!("broken zip entry: {e}"))?;
        let Some(rel) = e.enclosed_name() else { return Err(format!("unsafe path in zip: {}", e.name())) };
        if rel.components().any(|c| matches!(c, Component::ParentDir | Component::RootDir | Component::Prefix(_))) {
            return Err(format!("unsafe path in zip: {}", e.name()));
        }
        // Skip macOS zip clutter.
        if rel.starts_with("__MACOSX") || rel.file_name().is_some_and(|n| n == ".DS_Store") {
            continue;
        }
        let out = dest.join(&rel);
        total += e.size();
        if total > MAX_BYTES {
            return Err("unpacked size is over 2 GB".into());
        }
        if e.is_dir() {
            fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            continue;
        }
        if let Some(p) = out.parent() {
            fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        let mode = e.unix_mode().unwrap_or(0o644);
        // A symlink entry: its "content" is the target. Only allow targets that stay inside the package.
        if mode & 0o170000 == 0o120000 {
            let mut target = String::new();
            e.read_to_string(&mut target).map_err(|e| e.to_string())?;
            let resolved = out.parent().unwrap_or(dest).join(&target);
            if Path::new(&target).is_absolute() || !normalize(&resolved).starts_with(normalize(dest)) {
                return Err(format!("symlink points outside the app: {} -> {target}", rel.display()));
            }
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, &out).map_err(|e| e.to_string())?;
            continue;
        }
        let mut w = File::create(&out).map_err(|e| e.to_string())?;
        io::copy(&mut e, &mut w).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&out, fs::Permissions::from_mode(mode & 0o777));
        }
    }
    Ok(())
}

fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            c => out.push(c),
        }
    }
    out
}

/// Finds the first `.app` bundle (shallowest) under `root`.
pub fn find_app(root: &Path) -> Option<PathBuf> {
    WalkDir::new(root)
        .max_depth(4)
        .sort_by_key(|e| e.depth())
        .into_iter()
        .filter_map(Result::ok)
        .find(|e| e.file_type().is_dir() && e.path().extension().is_some_and(|x| x == "app"))
        .map(|e| e.into_path())
}

/// Checks it's a real app bundle: Contents/Info.plist and Contents/MacOS/<CFBundleExecutable>.
pub fn inspect_app(app: &Path) -> Result<AppInfo, String> {
    let plist_path = app.join("Contents/Info.plist");
    let v: plist::Value = plist::from_file(&plist_path).map_err(|_| "no readable Contents/Info.plist, so this isn't a real .app".to_string())?;
    let d = v.as_dictionary().ok_or("Info.plist isn't a dictionary")?;
    let s = |k: &str| d.get(k).and_then(|x| x.as_string()).unwrap_or("").to_string();
    let executable = s("CFBundleExecutable");
    if executable.is_empty() {
        return Err("Info.plist has no CFBundleExecutable".into());
    }
    if !app.join("Contents/MacOS").join(&executable).is_file() {
        return Err(format!("the executable Contents/MacOS/{executable} is missing"));
    }
    let file_name = app.file_stem().map(|x| x.to_string_lossy().to_string()).unwrap_or_default();
    let name = [s("CFBundleDisplayName"), s("CFBundleName"), file_name].into_iter().find(|x| !x.is_empty()).unwrap_or_default();
    let version = [s("CFBundleShortVersionString"), s("CFBundleVersion")].into_iter().find(|x| !x.is_empty()).unwrap_or("0".into());
    Ok(AppInfo { app_dir: app.to_path_buf(), name, version, bundle_id: s("CFBundleIdentifier"), executable })
}

/// Zips `files` (paths relative to `root`) into `out`, keeping permissions and symlinks. Sorted, so the same content
/// always makes the same file list.
pub fn zip_dir(root: &Path, out: &Path, extra: &[(&str, Vec<u8>)]) -> Result<(), String> {
    let f = File::create(out).map_err(|e| e.to_string())?;
    let mut z = zip::ZipWriter::new(f);
    let base = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    let mut entries: Vec<_> = WalkDir::new(root).min_depth(1).sort_by_file_name().into_iter().filter_map(Result::ok).collect();
    entries.sort_by(|a, b| a.path().cmp(b.path()));
    for e in entries {
        let rel = e.path().strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
        if extra.iter().any(|(n, _)| *n == rel) {
            continue; // replaced by the extra version below
        }
        let meta = fs::symlink_metadata(e.path()).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        let mode = { use std::os::unix::fs::PermissionsExt; meta.permissions().mode() };
        #[cfg(not(unix))]
        let mode = 0o644u32;
        if meta.file_type().is_symlink() {
            let target = fs::read_link(e.path()).map_err(|e| e.to_string())?;
            z.add_symlink(rel, target.to_string_lossy(), base).map_err(|e| e.to_string())?;
        } else if meta.is_dir() {
            z.add_directory(rel, base.unix_permissions(mode & 0o777)).map_err(|e| e.to_string())?;
        } else {
            z.start_file(rel, base.unix_permissions(mode & 0o777)).map_err(|e| e.to_string())?;
            let mut r = File::open(e.path()).map_err(|e| e.to_string())?;
            io::copy(&mut r, &mut z).map_err(|e| e.to_string())?;
        }
    }
    for (name, data) in extra {
        z.start_file(*name, base.unix_permissions(0o644)).map_err(|e| e.to_string())?;
        z.write_all(data).map_err(|e| e.to_string())?;
    }
    z.finish().map_err(|e| e.to_string())?;
    Ok(())
}

/// `appp pack Foo.app [--author X] [--description Y]` → Foo.appp next to it (no stamp: the server adds that).
pub fn pack(app: &Path, author: &str, description: &str) -> Result<PathBuf, String> {
    let info = inspect_app(app)?;
    let tmp = std::env::temp_dir().join(format!("appp-pack-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let app_name = app.file_name().unwrap().to_string_lossy().to_string();
    fs::create_dir_all(tmp.join("app")).map_err(|e| e.to_string())?;
    copy_tree(app, &tmp.join("app").join(&app_name))?;
    let m = Manifest {
        name: info.name.clone(),
        version: info.version,
        bundle_id: info.bundle_id,
        author: author.into(),
        description: description.into(),
        app_path: format!("app/{app_name}"),
    };
    let out = app.with_extension("appp");
    zip_dir(&tmp, &out, &[("manifest.json", serde_json::to_vec_pretty(&m).unwrap())])?;
    let _ = fs::remove_dir_all(&tmp);
    Ok(out)
}

pub fn copy_tree(from: &Path, to: &Path) -> Result<(), String> {
    for e in WalkDir::new(from).into_iter().filter_map(Result::ok) {
        let rel = e.path().strip_prefix(from).unwrap();
        let dst = to.join(rel);
        let ft = e.path().symlink_metadata().map_err(|e| e.to_string())?.file_type();
        if ft.is_symlink() {
            #[cfg(unix)]
            std::os::unix::fs::symlink(fs::read_link(e.path()).map_err(|e| e.to_string())?, &dst).map_err(|e| e.to_string())?;
        } else if ft.is_dir() {
            fs::create_dir_all(&dst).map_err(|e| e.to_string())?;
        } else {
            fs::copy(e.path(), &dst).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
