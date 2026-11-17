// The "scanned clean" stamp, byte-for-byte the same format as the Rust server's (src/stamp.rs), so
// `appp verify file.appp --key <hex>` checks packages from this website too.
// Signed bytes = the stamp as JSON with signature "" and keys in this order:
//   format, server, scanned_at, verdict, warnings, files (sorted paths), public_key, signature

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export async function sha256(bytes) {
  return hex(await crypto.subtle.digest("SHA-256", bytes));
}

async function keys(env) {
  if (!env.STAMP_KEY) throw new Error("STAMP_KEY secret is missing (node scripts/genkey.mjs)");
  const priv = await crypto.subtle.importKey("pkcs8", b64(env.STAMP_KEY), { name: "Ed25519" }, true, ["sign"]);
  // The public key is the last 32 bytes of the JWK "x" (base64url) of the private key.
  const jwk = await crypto.subtle.exportKey("jwk", priv);
  const pub = Uint8Array.from(atob(jwk.x.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (jwk.x.length % 4)) % 4)), (c) => c.charCodeAt(0));
  return { priv, pubHex: hex(pub) };
}

export async function publicKey(env) {
  return (await keys(env)).pubHex;
}

function signedJson(s) {
  const files = {};
  for (const k of Object.keys(s.files).sort()) files[k] = s.files[k];
  return JSON.stringify({ format: s.format, server: s.server, scanned_at: s.scanned_at, verdict: s.verdict, warnings: s.warnings, files, public_key: s.public_key, signature: "" });
}

/** files: { path: Uint8Array } (everything except stamp.json). Returns the stamp object. */
export async function makeStamp(env, files, warnings) {
  const { priv, pubHex } = await keys(env);
  const hashes = {};
  for (const [path, bytes] of Object.entries(files)) hashes[path] = await sha256(bytes);
  const s = { format: "appp-stamp-1", server: env.STORE_NAME || "appp", scanned_at: Math.floor(Date.now() / 1000), verdict: "clean", warnings, files: hashes, public_key: pubHex, signature: "" };
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, priv, new TextEncoder().encode(signedJson(s)));
  s.signature = hex(sig);
  const ordered = {};
  for (const k of Object.keys(s.files).sort()) ordered[k] = s.files[k];
  s.files = ordered;
  return s;
}
