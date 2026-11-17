//! The scan an upload must pass before it gets a public page:
//! - known-bad file hashes (data/bad-hashes.txt, one SHA-256 per line)
//! - the "bricker" check: anything that deletes, moves or overwrites the files a device can't boot without
//!   (launchd, the kernel / kernelcache, boot.efi), or wipes the disk / turns off System Integrity Protection
//! - other red flags (warnings): download-and-run, admin-password shell scripts, LaunchDaemon persistence
//! - code signature and notarization (macOS `codesign` / `spctl`; warnings, since free apps are often unsigned)
//! - ClamAV, when `clamscan` is installed
//!
//! Verdict: "clean" (maybe with warnings) or "rejected" with the reasons.

use regex::bytes::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::Command;
use walkdir::WalkDir;

#[derive(Serialize, Clone, Debug, Default)]
pub struct Report {
    pub verdict: String, // "clean" | "rejected"
    pub problems: Vec<String>,
    pub warnings: Vec<String>,
    pub notes: Vec<String>,
    pub files: usize,
    pub bytes: u64,
}

/// Files a Mac or iPhone can't start without. Touching them destructively = "could brick a device".
const CRITICAL: &str = r"(/sbin/launchd|/System/Library/Kernels/kernel|/System/Library/KernelCollections|/System/Library/PrelinkedKernels|kernelcache|/System/Library/CoreServices/boot\.efi|/usr/standalone/i386/boot\.efi|/System/Library/CoreServices/SystemVersion\.plist)";
/// Destructive actions, within a few hundred bytes of a critical path.
const DESTRUCTIVE: &str = r"(\brm\b|\bmv\b|\bdd\b|\bunlink\b|\btruncate\b|\bshred\b|removeItem|moveItem|removeFile|DeleteFile|\bchflags\b|>\s*/|of=)";

fn rules() -> Vec<(&'static str, Regex, bool)> {
    // (message, pattern, rejects?)
    let r = |s: &str| Regex::new(s).unwrap();
    vec![
        ("could brick a device: changes a file the system needs to boot (launchd, kernel or boot.efi)",
            r(&format!(r"(?s){DESTRUCTIVE}.{{0,200}}{CRITICAL}|{CRITICAL}.{{0,200}}{DESTRUCTIVE}")), true),
        ("could brick a device: turns off System Integrity Protection (csrutil disable)", r(r"csrutil\s+(disable|authenticated-root\s+disable)"), true),
        ("could brick a device: erases or repartitions disks", r(r"diskutil\s+(eraseDisk|eraseVolume|zeroDisk|secureErase|partitionDisk|apfs\s+deleteContainer)|\bnewfs_\w+\s+/dev/disk"), true),
        ("could brick a device: writes raw data to a disk device", r(r"\bdd\b[^\n]{0,80}of=/dev/(r?disk|sd)"), true),
        ("could brick a device: deletes the whole system", r(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(--no-preserve-root\s+)?/(\s|$|\*|System|usr|bin|sbin|Library\b)"), true),
        ("changes the startup disk or firmware settings (bless / nvram)", r(r"\bbless\s+--(mount|device|setBoot)|\bnvram\s+[\w-]+="), true),
        ("downloads a script and runs it straight away (curl/wget | sh)", r(r"(curl|wget)[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b"), false),
        ("asks for the admin password to run shell commands", r(r"with administrator privileges"), false),
        ("installs itself to start with the system (LaunchDaemons)", r(r"/Library/LaunchDaemons/"), false),
        ("hides the Terminal / quarantine flag (xattr -d com.apple.quarantine)", r(r"xattr\s+(-[a-z]*d[a-z]*\s+)?com\.apple\.quarantine"), false),
    ]
}

pub fn sha256_file(p: &Path) -> std::io::Result<String> {
    let mut h = Sha256::new();
    let mut f = fs::File::open(p)?;
    std::io::copy(&mut f, &mut h)?;
    Ok(format!("{:x}", h.finalize()))
}

pub fn scan(root: &Path, bad_hashes: &HashSet<String>) -> Report {
    let mut r = Report::default();
    let rules = rules();
    let mut hit: HashSet<String> = HashSet::new();
    for e in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if !e.file_type().is_file() {
            continue;
        }
        r.files += 1;
        let len = e.metadata().map(|m| m.len()).unwrap_or(0);
        r.bytes += len;
        let rel = e.path().strip_prefix(root).unwrap_or(e.path()).display().to_string();
        if let Ok(h) = sha256_file(e.path()) {
            if bad_hashes.contains(&h) {
                r.problems.push(format!("known malware (hash match): {rel}"));
            }
        }
        // Read up to 64 MB of each file; binaries are searched too (their strings hold the paths and commands).
        let Ok(data) = read_capped(e.path(), 64 * 1024 * 1024) else { continue };
        for (msg, re, rejects) in &rules {
            if re.is_match(&data) && hit.insert(format!("{msg}|{rel}")) {
                let line = format!("{msg} ({rel})");
                if *rejects { r.problems.push(line) } else { r.warnings.push(line) }
            }
        }
    }
    signature_checks(root, &mut r);
    clamav(root, &mut r);
    r.verdict = if r.problems.is_empty() { "clean".into() } else { "rejected".into() };
    r
}

fn read_capped(p: &Path, cap: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut v = Vec::new();
    fs::File::open(p)?.take(cap).read_to_end(&mut v)?;
    Ok(v)
}

fn signature_checks(root: &Path, r: &mut Report) {
    if !cfg!(target_os = "macos") {
        r.notes.push("code signature not checked (the server isn't running on macOS)".into());
        return;
    }
    let Some(app) = crate::package::find_app(root) else { return };
    match Command::new("codesign").args(["--verify", "--deep", "--strict"]).arg(&app).output() {
        Ok(o) if o.status.success() => r.notes.push("code signature valid".into()),
        Ok(o) => {
            let why = String::from_utf8_lossy(&o.stderr).lines().last().unwrap_or("").to_string();
            r.warnings.push(format!("not signed, or the signature is broken: {why}"));
        }
        Err(_) => r.notes.push("codesign not available".into()),
    }
    match Command::new("spctl").args(["--assess", "--type", "execute", "-vv"]).arg(&app).output() {
        Ok(o) if o.status.success() => r.notes.push("accepted by Gatekeeper (notarized)".into()),
        Ok(_) => r.warnings.push("not notarized by Apple: Gatekeeper will warn when it's opened".into()),
        Err(_) => {}
    }
}

fn clamav(root: &Path, r: &mut Report) {
    match Command::new("clamscan").args(["-r", "--infected", "--no-summary"]).arg(root).output() {
        Err(_) => r.notes.push("ClamAV not installed, so only the built-in rules and hash list were used (brew install clamav)".into()),
        Ok(o) => match o.status.code() {
            Some(0) => r.notes.push("ClamAV: nothing found".into()),
            Some(1) => {
                for l in String::from_utf8_lossy(&o.stdout).lines() {
                    r.problems.push(format!("ClamAV: {}", l.replace(&root.display().to_string(), "")));
                }
            }
            _ => r.notes.push("ClamAV couldn't run (is its database downloaded? run freshclam)".into()),
        },
    }
}
