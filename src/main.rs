//! appp: our own app upload server and `.appp` package format.
//!
//!   appp serve [--data DIR] [--addr 127.0.0.1:8787] [--name NAME]   run the upload server
//!   appp pack  Foo.app [--author NAME] [--description TEXT]           make Foo.appp (unstamped)
//!   appp verify Foo.appp [--key HEX]                                  check its "scanned clean" stamp
//!   appp scan  Foo.app|Foo.appp|folder                                run the scan locally and print the report

mod package;
mod scan;
mod server;
mod stamp;

use std::path::{Path, PathBuf};

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn usage() -> ! {
    eprintln!(
        "appp: app upload server with malware + bricker scans\n\n  appp serve [--data DIR] [--addr 127.0.0.1:8787] [--name NAME]\n  appp pack Foo.app [--author NAME] [--description TEXT]\n  appp verify Foo.appp [--key HEX]\n  appp scan Foo.app | Foo.appp | folder"
    );
    std::process::exit(2)
}

fn unpack_tmp(file: &Path) -> PathBuf {
    let tmp = std::env::temp_dir().join(format!("appp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    if let Err(e) = package::unzip(file, &tmp) {
        eprintln!("✗ {e}");
        std::process::exit(1);
    }
    tmp
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => {
            let data = flag(&args, "--data").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("data"));
            let addr = flag(&args, "--addr").unwrap_or_else(|| "127.0.0.1:8787".into());
            let name = flag(&args, "--name").unwrap_or_else(|| "appp-local".into());
            server::serve(data, addr, name).await;
        }
        Some("pack") => {
            let Some(app) = args.get(1) else { usage() };
            match package::pack(Path::new(app), &flag(&args, "--author").unwrap_or_default(), &flag(&args, "--description").unwrap_or_default()) {
                Ok(p) => println!("✓ made {}", p.display()),
                Err(e) => {
                    eprintln!("✗ {e}");
                    std::process::exit(1)
                }
            }
        }
        Some("verify") => {
            let Some(file) = args.get(1) else { usage() };
            let tmp = unpack_tmp(Path::new(file));
            let res = stamp::verify(&tmp, flag(&args, "--key").as_deref());
            let _ = std::fs::remove_dir_all(&tmp);
            match res {
                Ok(s) => {
                    println!("✓ stamp OK: scanned clean by {} ({} files unchanged)", s.server, s.files.len());
                    for w in s.warnings {
                        println!("  ! {w}");
                    }
                }
                Err(e) => {
                    eprintln!("✗ {e}");
                    std::process::exit(1)
                }
            }
        }
        Some("scan") => {
            let Some(target) = args.get(1) else { usage() };
            let p = Path::new(target);
            let (root, tmp) = if p.is_dir() { (p.to_path_buf(), None) } else { let t = unpack_tmp(p); (t.clone(), Some(t)) };
            let r = scan::scan(&root, &Default::default());
            if let Some(t) = tmp {
                let _ = std::fs::remove_dir_all(t);
            }
            println!("{}", serde_json::to_string_pretty(&r).unwrap());
            if r.verdict != "clean" {
                std::process::exit(1)
            }
        }
        _ => usage(),
    }
}
