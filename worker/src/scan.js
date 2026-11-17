// The RealismPhoneOS app scan: the same rules as the Rust server (src/phone.rs) and the phone itself
// (Realism's PhoneApps.java). Rejects brickers, spyware, adware and broken apps.

export const BOOT_CHAIN = ["/boot/realboot", "/System/realkernel", "/sbin/realism-launchd"];
export const PERMISSIONS = ["location", "files", "drones"];
const SOUNDS = ["ding", "chime", "pling", "bell"];
const LIMITS = { screens: 20, buttons: 8, lines: 10, actions: 10, text: 120 };
export const MAX_APP_BYTES = 16 * 1024;

export const validName = (n) => typeof n === "string" && n.trim().length > 0 && n.trim().length <= 24 && /^[\p{L}\p{N} _!-]+$/u.test(n.trim());

export function scan(manifest, app, appBytes) {
  const r = { verdict: "clean", kind: "clean", problems: [], warnings: [], notes: [] };
  const bad = (m) => r.problems.push(m);
  if (appBytes > MAX_APP_BYTES) bad(`broken: app.json is over ${MAX_APP_BYTES / 1024} KB`);
  if (!manifest || typeof manifest !== "object") { bad("broken: no readable manifest.json"); return finish(r); }
  if (!validName(manifest.name)) bad("broken: manifest name must be 1-24 letters, numbers, spaces, - _ !");
  if (!manifest.version) bad("broken: manifest has no version");
  const perms = Array.isArray(manifest.permissions) ? manifest.permissions.map(String) : [];
  for (const p of perms) if (!PERMISSIONS.includes(p)) bad(`broken: unknown permission "${p}"`);
  const has = (p) => perms.includes(p);
  const screens = app && typeof app.screens === "object" && !Array.isArray(app.screens) ? app.screens : null;
  if (!screens) { bad("broken: app.json has no screens"); return finish(r); }
  const start = app.start ?? "main";
  if (!(start in screens)) bad(`broken: start screen "${start}" doesn't exist`);
  if (Object.keys(screens).length > LIMITS.screens) bad(`broken: more than ${LIMITS.screens} screens`);

  const check = (where, list, background) => {
    if (!Array.isArray(list)) return;
    if (list.length > LIMITS.actions) bad(`broken: ${where} has more than ${LIMITS.actions} actions`);
    for (const raw of list) {
      const a = String(raw), i = a.indexOf(" ");
      const verb = i < 0 ? a : a.slice(0, i), arg = i < 0 ? "" : a.slice(i + 1).trim();
      switch (verb) {
        case "say": case "toast": if (arg.length > LIMITS.text) bad(`broken: text over ${LIMITS.text} characters in ${where}`); break;
        case "sound": if (!SOUNDS.includes(arg)) bad(`broken: unknown sound "${arg}" (ding, chime, pling, bell)`); break;
        case "open": if (!(arg in screens)) bad(`broken: ${where} opens a screen that doesn't exist ("${arg}")`); break;
        case "fun": break;
        case "rth": case "drone_status": if (!has("drones")) bad(`broken: ${where} uses drones without the "drones" permission`); break;
        case "location": if (!has("location")) bad(`spyware: ${where} reads your location without asking ("location" permission)`); break;
        case "share_location":
          if (!has("location")) bad(`spyware: ${where} sends your location to other players without asking`);
          else if (background) bad("spyware: shares your location in the background, without you pressing anything");
          else r.warnings.push(`shares your location with other players when you press it (${where})`);
          break;
        case "ad":
          if (background) bad("adware: shows pop-up ads in the background");
          else r.warnings.push(`shows an ad when you press it (${where})`);
          break;
        case "delete":
          if (BOOT_CHAIN.includes(arg) || arg.startsWith("/boot")) bad(`bricker: deletes ${arg}, which the phone needs to start (it would brick the phone)`);
          else if (arg.startsWith("/System") || arg.startsWith("/sbin")) bad(`bricker: deletes the system file ${arg}, which breaks the phone`);
          else if (!has("files")) bad(`broken: ${where} deletes files without the "files" permission`);
          else if (arg.startsWith("/Apps/")) r.warnings.push(`can delete the app ${arg}`);
          else bad(`broken: ${where} deletes an unknown path ${arg}`);
          break;
        default: bad(`broken: unknown action "${verb}" in ${where}`);
      }
    }
  };
  for (const [name, sc] of Object.entries(screens)) {
    if (String(sc?.title ?? "").length > 40) bad(`broken: screen "${name}" title is over 40 characters`);
    if ((sc?.text ?? []).length > LIMITS.lines) bad(`broken: screen "${name}" has more than ${LIMITS.lines} lines`);
    const buttons = Array.isArray(sc?.buttons) ? sc.buttons : [];
    if (buttons.length > LIMITS.buttons) bad(`broken: screen "${name}" has more than ${LIMITS.buttons} buttons`);
    buttons.forEach((b, i) => {
      const label = String(b?.label ?? "");
      if (!label || label.length > 24) bad(`broken: button ${i + 1} on "${name}" needs a label of 1-24 characters`);
      check(`button "${label}" on "${name}"`, b?.do, false);
    });
  }
  if (app.background) {
    if (!(Number(app.background.every) >= 30)) bad('broken: background "every" must be at least 30 seconds');
    check("the background timer", app.background.do, true);
  }
  r.notes.push(`${Object.keys(screens).length} screens, permissions: ${perms.length ? perms.join(", ") : "none"}`);
  return finish(r);
}

function finish(r) {
  r.problems = [...new Set(r.problems)];
  r.verdict = r.problems.length ? "rejected" : "clean";
  const first = r.problems.map((p) => p.split(":")[0]);
  r.kind = r.verdict === "clean" ? "clean" : ["bricker", "spyware", "adware"].find((k) => first.includes(k)) ?? "broken";
  return r;
}
