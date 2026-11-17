// Makes a new Ed25519 key for signing stamps. Prints STAMP_KEY=<base64 pkcs8> (keep it secret) and the public key.
const k = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const priv = Buffer.from(await crypto.subtle.exportKey("pkcs8", k.privateKey)).toString("base64");
const pub = Buffer.from(await crypto.subtle.exportKey("raw", k.publicKey)).toString("hex");
console.log(`STAMP_KEY=${priv}`);
console.error(`public key (what appp verify --key checks): ${pub}`);
