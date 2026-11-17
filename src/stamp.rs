//! The "scanned clean" stamp. After a clean scan the server lists every file in the package with its SHA-256, adds
//! the verdict and time, and signs that with its Ed25519 key. `appp verify` re-hashes the files and checks the
//! signature, so swapping or adding a single file after the scan breaks the stamp.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Serialize, Deserialize, Clone)]
pub struct Stamp {
    pub format: String,
    pub server: String,
    pub scanned_at: u64,
    pub verdict: String,
    pub warnings: Vec<String>,
    /// path → sha256 (or "link:<target>" for symlinks), every file except stamp.json itself.
    pub files: BTreeMap<String, String>,
    pub public_key: String,
    #[serde(default)]
    pub signature: String,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Option<Vec<u8>> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// The server's signing key: data/stamp.key (made on first run). Never leaves the server.
pub fn load_or_create_key(dir: &Path) -> SigningKey {
    let p = dir.join("stamp.key");
    if let Ok(b) = fs::read(&p) {
        if let Ok(arr) = <[u8; 32]>::try_from(b.as_slice()) {
            return SigningKey::from_bytes(&arr);
        }
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("no randomness available");
    let _ = fs::create_dir_all(dir);
    fs::write(&p, seed).expect("can't save the stamp key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o600));
    }
    SigningKey::from_bytes(&seed)
}

pub fn public_hex(key: &SigningKey) -> String {
    hex(key.verifying_key().as_bytes())
}

pub fn hash_tree(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut files = BTreeMap::new();
    for e in WalkDir::new(root).min_depth(1).into_iter().filter_map(Result::ok) {
        let rel = e.path().strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
        if rel == "stamp.json" {
            continue;
        }
        let ft = e.path().symlink_metadata().map_err(|e| e.to_string())?.file_type();
        if ft.is_symlink() {
            files.insert(rel, format!("link:{}", fs::read_link(e.path()).map_err(|e| e.to_string())?.display()));
        } else if ft.is_file() {
            files.insert(rel, crate::scan::sha256_file(e.path()).map_err(|e| e.to_string())?);
        }
    }
    Ok(files)
}

fn signed_bytes(s: &Stamp) -> Vec<u8> {
    let mut c = s.clone();
    c.signature = String::new();
    serde_json::to_vec(&c).unwrap()
}

pub fn make(root: &Path, key: &SigningKey, server: &str, warnings: Vec<String>) -> Result<Stamp, String> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut s = Stamp {
        format: "appp-stamp-1".into(),
        server: server.into(),
        scanned_at: now,
        verdict: "clean".into(),
        warnings,
        files: hash_tree(root)?,
        public_key: public_hex(key),
        signature: String::new(),
    };
    s.signature = hex(&key.sign(&signed_bytes(&s)).to_bytes());
    Ok(s)
}

/// Checks an unpacked package against its stamp.json. `trusted` = the server key you expect (optional).
pub fn verify(root: &Path, trusted: Option<&str>) -> Result<Stamp, String> {
    let s: Stamp = serde_json::from_slice(&fs::read(root.join("stamp.json")).map_err(|_| "no stamp.json: this package was never scanned")?)
        .map_err(|_| "stamp.json is unreadable")?;
    if let Some(t) = trusted {
        if t != s.public_key {
            return Err("stamped by a different server than the one you trust".into());
        }
    }
    let pk = unhex(&s.public_key).and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or("bad public key")?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| "bad public key")?;
    let sig = unhex(&s.signature).and_then(|b| <[u8; 64]>::try_from(b).ok()).ok_or("bad signature")?;
    vk.verify(&signed_bytes(&s), &Signature::from_bytes(&sig)).map_err(|_| "the stamp's signature is wrong (stamp.json was edited)")?;
    let now = hash_tree(root)?;
    for (path, h) in &s.files {
        match now.get(path) {
            None => return Err(format!("{path} was removed after the scan")),
            Some(x) if x != h => return Err(format!("{path} was changed after the scan")),
            _ => {}
        }
    }
    if let Some(extra) = now.keys().find(|p| !s.files.contains_key(*p)) {
        return Err(format!("{extra} was added after the scan"));
    }
    Ok(s)
}
