//! RealismPhoneOS apps: the in-game phone in the Realism Minecraft mod runs `.appp` apps.
//!
//! A phone `.appp` is a zip with:
//!   manifest.json  { "name", "version", "author", "description", "permissions": ["location", "files", "drones"] }
//!   app.json       { "start": "main",
//!                    "screens": { "main": { "title": "...", "text": ["..."], "buttons": [{ "label": "...", "do": ["say hi", "open more"] }] } },
//!                    "background": { "every": 60, "do": ["toast ..."] } }   (optional)
//!   icon.png       (optional)
//!
//! Actions: say <text> · toast <text> · sound ding|chime|pling|bell · open <screen> · fun · rth (drones come home,
//! needs "drones") · drone_status (battery, distance and props of your drones, needs "drones") · location (shows YOU your coordinates, needs "location") · share_location (tells every player where
//! you are, needs "location") · delete <path> (needs "files") · ad <text> (a pop-up ad).
//!
//! The scan (here in the App Store, and the same rules in the in-game sideload scanner) rejects:
//!   bricker  - deletes the boot chain (/boot/realboot, /System/realkernel, /sbin/realism-launchd) or system daemons
//!   spyware  - share_location without asking for the "location" permission, or doing it in the background
//!   adware   - ads in the background
//!   broken   - unknown actions, missing screens, over the size limits

use crate::scan::Report;
use serde_json::Value;

pub const BOOT_CHAIN: [&str; 3] = ["/boot/realboot", "/System/realkernel", "/sbin/realism-launchd"];
pub const PERMISSIONS: [&str; 3] = ["location", "files", "drones"];
const SOUNDS: [&str; 4] = ["ding", "chime", "pling", "bell"];
const MAX_SCREENS: usize = 20;
const MAX_BUTTONS: usize = 8;
const MAX_LINES: usize = 10;
const MAX_ACTIONS: usize = 10;
const MAX_TEXT: usize = 120;
pub const MAX_APP_BYTES: usize = 16 * 1024;

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

/// Name rules: shown on the phone and used as /Apps/<name>, so no path or list separators.
pub fn clean_name(n: &str) -> Option<String> {
    let n = n.trim();
    (!n.is_empty() && n.len() <= 24 && n.chars().all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_' || c == '!')).then(|| n.to_string())
}

/// Validates and scans a phone app. Returns the report (verdict "clean" or "rejected").
pub fn scan(manifest: &Value, app: &Value, app_bytes: usize) -> Report {
    let mut r = Report::default();
    let mut bad = |m: String| r.problems.push(m);
    if app_bytes > MAX_APP_BYTES {
        bad(format!("broken: app.json is over {} KB", MAX_APP_BYTES / 1024));
    }
    if clean_name(&s(manifest, "name")).is_none() {
        bad("broken: manifest name must be 1-24 letters, numbers, spaces, - _ !".into());
    }
    if s(manifest, "version").is_empty() {
        bad("broken: manifest has no version".into());
    }
    let perms: Vec<String> = manifest.get("permissions").and_then(|p| p.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    for p in &perms {
        if !PERMISSIONS.contains(&p.as_str()) {
            bad(format!("broken: unknown permission \"{p}\""));
        }
    }
    let has = |p: &str| perms.iter().any(|x| x == p);
    let Some(screens) = app.get("screens").and_then(|x| x.as_object()) else {
        r.problems.push("broken: app.json has no screens".into());
        r.verdict = "rejected".into();
        return r;
    };
    let start = app.get("start").and_then(|x| x.as_str()).unwrap_or("main");
    if !screens.contains_key(start) {
        r.problems.push(format!("broken: start screen \"{start}\" doesn't exist"));
    }
    if screens.len() > MAX_SCREENS {
        r.problems.push(format!("broken: more than {MAX_SCREENS} screens"));
    }
    let check = |where_: &str, list: Option<&Value>, background: bool, r: &mut Report| {
        let Some(list) = list.and_then(|x| x.as_array()) else { return };
        if list.len() > MAX_ACTIONS {
            r.problems.push(format!("broken: {where_} has more than {MAX_ACTIONS} actions"));
        }
        for a in list {
            let a = a.as_str().unwrap_or("");
            let (verb, arg) = a.split_once(' ').map(|(v, x)| (v, x.trim())).unwrap_or((a, ""));
            match verb {
                "say" | "toast" if arg.len() <= MAX_TEXT => {}
                "say" | "toast" => r.problems.push(format!("broken: text over {MAX_TEXT} characters in {where_}")),
                "sound" if SOUNDS.contains(&arg) => {}
                "open" if screens.contains_key(arg) => {}
                "open" => r.problems.push(format!("broken: {where_} opens a screen that doesn't exist (\"{arg}\")")),
                "fun" => {}
                "rth" | "drone_status" if has("drones") => {}
                "drone_status" => r.problems.push(format!("broken: {where_} reads your drones without the \"drones\" permission")),
                "rth" => r.problems.push(format!("broken: {where_} controls drones without the \"drones\" permission")),
                "location" if has("location") => {}
                "location" => r.problems.push(format!("spyware: {where_} reads your location without asking (\"location\" permission)")),
                "share_location" if !has("location") => r.problems.push(format!("spyware: {where_} sends your location to other players without asking")),
                "share_location" if background => r.problems.push("spyware: shares your location in the background, without you pressing anything".into()),
                "share_location" => r.warnings.push(format!("shares your location with other players when you press it ({where_})")),
                "ad" if background => r.problems.push("adware: shows pop-up ads in the background".into()),
                "ad" => r.warnings.push(format!("shows an ad when you press it ({where_})")),
                "delete" if BOOT_CHAIN.contains(&arg) || arg.starts_with("/boot") => {
                    r.problems.push(format!("bricker: deletes {arg}, which the phone needs to start (it would brick the phone)"))
                }
                "delete" if arg.starts_with("/System") || arg.starts_with("/sbin") => {
                    r.problems.push(format!("bricker: deletes the system file {arg}, which breaks the phone"))
                }
                "delete" if !has("files") => r.problems.push(format!("broken: {where_} deletes files without the \"files\" permission")),
                "delete" if arg.starts_with("/Apps/") => r.warnings.push(format!("can delete the app {arg}")),
                "delete" => r.problems.push(format!("broken: {where_} deletes an unknown path {arg}")),
                "sound" => r.problems.push(format!("broken: unknown sound \"{arg}\" (ding, chime, pling, bell)")),
                _ => r.problems.push(format!("broken: unknown action \"{verb}\" in {where_}")),
            }
        }
    };
    for (name, sc) in screens {
        if s(sc, "title").len() > 40 {
            r.problems.push(format!("broken: screen \"{name}\" title is over 40 characters"));
        }
        let lines = sc.get("text").and_then(|x| x.as_array()).map(|a| a.len()).unwrap_or(0);
        if lines > MAX_LINES {
            r.problems.push(format!("broken: screen \"{name}\" has more than {MAX_LINES} lines"));
        }
        let buttons = sc.get("buttons").and_then(|x| x.as_array()).cloned().unwrap_or_default();
        if buttons.len() > MAX_BUTTONS {
            r.problems.push(format!("broken: screen \"{name}\" has more than {MAX_BUTTONS} buttons"));
        }
        for (i, b) in buttons.iter().enumerate() {
            let label = s(b, "label");
            if label.is_empty() || label.len() > 24 {
                r.problems.push(format!("broken: button {} on \"{name}\" needs a label of 1-24 characters", i + 1));
            }
            check(&format!("button \"{label}\" on \"{name}\""), b.get("do"), false, &mut r);
        }
    }
    if let Some(bg) = app.get("background") {
        let every = bg.get("every").and_then(|x| x.as_u64()).unwrap_or(0);
        if every < 30 {
            r.problems.push("broken: background \"every\" must be at least 30 seconds".into());
        }
        check("the background timer", bg.get("do"), true, &mut r);
    }
    r.problems.dedup();
    r.notes.push(format!("{} screens, permissions: {}", screens.len(), if perms.is_empty() { "none".into() } else { perms.join(", ") }));
    r.verdict = if r.problems.is_empty() { "clean".into() } else { "rejected".into() };
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn verdict(m: Value, a: Value) -> Report {
        scan(&m, &a, 100)
    }

    #[test]
    fn fine_app_passes() {
        let r = verdict(
            json!({"name": "Cookie Tap", "version": "1.0"}),
            json!({"screens": {"main": {"title": "Cookies", "text": ["Tap!"], "buttons": [{"label": "Tap", "do": ["fun", "sound pling", "open win"]}]},
                               "win": {"title": "Yum", "buttons": [{"label": "Back", "do": ["open main"]}]}}}),
        );
        assert_eq!(r.verdict, "clean", "{:?}", r.problems);
    }

    #[test]
    fn bricker_is_rejected() {
        let r = verdict(
            json!({"name": "SuperBoost", "version": "9.9", "permissions": ["files"]}),
            json!({"screens": {"main": {"title": "Boost!", "buttons": [{"label": "Boost", "do": ["delete /sbin/realism-launchd"]}]}}}),
        );
        assert_eq!(r.verdict, "rejected");
        assert!(r.problems.iter().any(|p| p.starts_with("bricker")));
    }

    #[test]
    fn spyware_and_adware_are_rejected() {
        let spy = verdict(
            json!({"name": "FlashlightPro", "version": "1"}),
            json!({"screens": {"main": {"title": "Light", "buttons": [{"label": "On", "do": ["share_location"]}]}}}),
        );
        assert!(spy.problems.iter().any(|p| p.starts_with("spyware")));
        let ads = verdict(
            json!({"name": "FreeDiamonds", "version": "1"}),
            json!({"screens": {"main": {"title": "Free!"}}, "background": {"every": 60, "do": ["ad BUY NOW"]}}),
        );
        assert!(ads.problems.iter().any(|p| p.starts_with("adware")));
    }

    #[test]
    fn honest_location_sharing_is_allowed_with_a_warning() {
        let r = verdict(
            json!({"name": "Meet Up", "version": "1", "permissions": ["location"]}),
            json!({"screens": {"main": {"title": "Meet", "buttons": [{"label": "Share where I am", "do": ["share_location"]}]}}}),
        );
        assert_eq!(r.verdict, "clean");
        assert!(!r.warnings.is_empty());
    }
}
