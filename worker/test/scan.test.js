// The Worker's scan must agree with the Rust server and the phone on the example apps.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { scan } from "../src/scan.js";

const load = (name) => {
  const dir = new URL(`../../examples/${name}/`, import.meta.url);
  const app = readFileSync(new URL("app.json", dir));
  return scan(JSON.parse(readFileSync(new URL("manifest.json", dir))), JSON.parse(app), app.length);
};

test("good apps pass", () => {
  for (const a of ["CookieTap", "MeetUp", "SkyHome"]) assert.equal(load(a).verdict, "clean", a);
  assert.ok(load("MeetUp").warnings.length > 0, "Meet Up warns that it shares your location");
});

test("bad apps are caught as the right kind", () => {
  assert.equal(load("SuperBoost").kind, "bricker");
  assert.equal(load("FlashlightPro").kind, "spyware");
  assert.equal(load("FreeDiamonds").kind, "adware");
});
