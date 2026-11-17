# appp on Cloudflare Workers: the RealismPhoneOS App Store website

The public version of the appp server, for phone apps (`manifest.json` + `app.json`). Same scan rules (bricker,
spyware, adware, broken), same "scanned clean" stamp (Rust `appp verify` checks it), same API, so Realism's
`appStoreUrl` can point here.

- **Worker** (`src/index.js`): store page, upload, app pages with a phone preview, downloads, `/api/phone/apps`.
- **D1** (`schema.sql`): the app list. **R2**: the stamped `.appp` files and icons.
- **Secret `STAMP_KEY`**: the Ed25519 key that signs stamps (`node scripts/genkey.mjs`).

## Try it locally (no Cloudflare account needed)
```
npm install
node scripts/genkey.mjs > .dev.vars
npm run db:local
npm run dev            # http://127.0.0.1:8787 (or --port 8788)
npm test               # the scan agrees with ../examples
```

## Put it on the internet
```
npx wrangler login                        # opens Cloudflare's sign-in page
npx wrangler d1 create appp               # copy the database_id into wrangler.toml
npx wrangler r2 bucket create appp-files
npm run db:remote
node scripts/genkey.mjs | cut -d= -f2- | npx wrangler secret put STAMP_KEY
npm run deploy                            # → https://appp-store.<your-subdomain>.workers.dev
```
Then set `appStoreUrl` in the Realism server config (`realism-server.toml`) to that address.
