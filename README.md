# appp

Our own app upload server and the **`.appp`** package format: people upload Mac apps, the server scans them, and only
clean ones get a public page and a download link, with a signed "scanned clean" stamp inside.

## The `.appp` format
A zip with:
```
manifest.json        name, version, bundle id, author, description, where the app is
app/<Name>.app/...   the macOS app bundle
icon.png, screenshots/   (optional)
stamp.json           added by the server after a clean scan
```
`stamp.json` lists every file with its SHA-256, plus the verdict and time, signed with the server's Ed25519 key. Change,
add or remove a single file after the scan and `appp verify` says so.

## The scan (before anything is public)
- **Bricker check (rejects):** deleting, moving or overwriting the files a Mac/iPhone can't boot without (`/sbin/launchd`,
  the kernel / kernelcache, `boot.efi`), turning off SIP (`csrutil disable`), erasing or repartitioning disks, writing
  raw data to `/dev/disk*`, `rm -rf /`, changing the startup disk / NVRAM. Message: **"could brick a device"**.
- **Known malware:** SHA-256 list in `data/bad-hashes.txt` (one per line), plus **ClamAV** when it's installed
  (`brew install clamav && freshclam`).
- **Warnings (still allowed):** download-and-run scripts (`curl … | sh`), admin-password shell scripts, LaunchDaemon
  persistence, removing the quarantine flag, unsigned or not-notarized apps (`codesign`, `spctl`).
- **Safe unpacking:** no `../` paths, no symlinks out of the app, 50,000-file and 2 GB limits (zip bombs).
- Rejected uploads go to `data/quarantine/` and never get a download link.

## Use it
```
cargo build --release
./target/release/appp serve                 # http://127.0.0.1:8787, data in ./data
./target/release/appp pack MyApp.app --author me --description "What it does"   # → MyApp.appp
./target/release/appp verify MyApp.appp      # check a downloaded package's stamp
./target/release/appp scan MyApp.app         # run the scan locally
```
Upload a `.appp`, or a zipped `.app` (Finder → Compress), on the Upload page. `GET /api/apps` lists clean apps as JSON,
`GET /stamp-key` gives the server's public key (`appp verify --key <hex>` to require that server).

Built with axum, SQLite (rusqlite), zip, ed25519-dalek.

## Later
- Run the scan in a throwaway VM/container instead of on the server itself
- Accounts, versions/updates, PostgreSQL + S3/R2 storage for a public deployment
