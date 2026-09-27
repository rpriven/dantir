#!/usr/bin/env bun
// Rebuild tools/map/dantir-map.standalone.html and refresh its .gitleaksignore fingerprints.
//
//   bun tools/map/rebuild-standalone.ts
//
// The standalone page inlines Leaflet's marker PNGs as base64. Their tails
// (…AAAASUVORK5CYII=, the PNG IEND chunk) match gitleaks' wireguard-private-key
// rule, and the fingerprints pin line numbers that move whenever the page
// changes. This script:
//   1. runs build-map.ts --standalone into the tracked file;
//   2. scans that file with gitleaks and REFUSES to continue if any finding is
//      not a base64 PNG tail on the wireguard rule (a real secret never gets
//      allowlisted by this script);
//   3. rewrites only the standalone-file lines of .gitleaksignore, keeping every
//      other line as it was;
//   4. re-scans with the ignore file and fails unless the result is clean.
// Running it twice in a row changes nothing the second time.
//
// The wireguard rule that flags those tails is not in gitleaks' default ruleset;
// it comes from the maintainer's config. Config resolution mirrors the
// pre-commit hook: ./.gitleaks.toml, then ~/.config/gitleaks/gitleaks.toml.
// With neither present the default rules flag nothing, so the ignore file is
// left exactly as it is rather than emptied.

import { existsSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from "fs";
import { join, resolve } from "path";
import { homedir, tmpdir } from "os";

const REPO = resolve(import.meta.dir, "..", "..");
const TARGET = "tools/map/dantir-map.standalone.html";   // repo-relative: gitleaks fingerprints use this spelling
const IGNORE = join(REPO, ".gitleaksignore");
const PNG_TAIL = /ORK5CYII=?$/;                          // base64 of the PNG IEND chunk
const CONFIG = [join(REPO, ".gitleaks.toml"), join(homedir(), ".config", "gitleaks", "gitleaks.toml")].find(p => existsSync(p));
const CONFIG_ARGS = CONFIG ? ["-c", CONFIG] : [];

function run(cmd: string[], okCodes = [0]): { code: number; out: string } {
  const p = Bun.spawnSync(cmd, { cwd: REPO, stdout: "pipe", stderr: "pipe" });
  const out = p.stdout.toString() + p.stderr.toString();
  if (!okCodes.includes(p.exitCode ?? -1)) {
    console.error(`FAILED (${p.exitCode}): ${cmd.join(" ")}\n${out}`);
    process.exit(1);
  }
  return { code: p.exitCode ?? -1, out };
}

if (!Bun.which("gitleaks")) { console.error("gitleaks is not on PATH; install it first"); process.exit(1); }

// 1. rebuild
run(["bun", join(REPO, "tools/map/build-map.ts"), "--standalone", "-o", join(REPO, TARGET)]);

// 2. scan without the ignore file (exit 1 = findings, expected)
type Finding = { RuleID: string; File: string; StartLine: number; Match: string; Fingerprint: string };
const tmp = mkdtempSync(join(tmpdir(), "dantir-gl-"));
let findings: Finding[] = [];
try {
  const report = join(tmp, "gl.json");
  run(["gitleaks", "detect", "--no-git", "--no-banner", "--source", TARGET,
       ...CONFIG_ARGS, "--gitleaks-ignore-path", join(tmp, "none"), "--report-format", "json", "--report-path", report], [0, 1]);
  findings = JSON.parse(readFileSync(report, "utf8")) as Finding[];
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
// A finding is only a known false positive when ALL of these hold: it is the
// wireguard rule, its match ends in the PNG IEND trailer, and the match sits
// inside a base64 PNG data URL on its own line. The suffix alone is not enough
// (cross-vendor review, 2026-09-27): a real key that happened to end in those
// characters would otherwise be allowlisted by this script.
const pageLines = readFileSync(join(REPO, TARGET), "utf8").split("\n");
const inPngDataUrl = (f: Finding) => {
  const line = pageLines[f.StartLine - 1] ?? "";
  const m = f.Match.trim();
  const at = line.indexOf(m);
  if (at < 0) return false;
  const start = line.lastIndexOf("data:image/png;base64,", at);
  return start >= 0 && /^[A-Za-z0-9+/=]*$/.test(line.slice(start + "data:image/png;base64,".length, at));
};
const bad = findings.filter(f => f.RuleID !== "wireguard-private-key" || !PNG_TAIL.test(f.Match.trim()) || !inPngDataUrl(f));
if (bad.length) {
  console.error("gitleaks found something that is not an inlined Leaflet PNG. Not allowlisting it:");
  for (const f of bad) console.error(`  ${f.RuleID} line ${f.StartLine}: ${f.Match.slice(0, 80)}`);
  process.exit(1);
}
const fps = [...new Set(findings.map(f => `${TARGET}:${f.RuleID}:${f.StartLine}`))].sort((a, b) =>
  Number(a.split(":").pop()) - Number(b.split(":").pop()));

// 3. rewrite only this file's fingerprint lines, in place of the old ones
const before = readFileSync(IGNORE, "utf8");
if (!CONFIG) console.log("No .gitleaks.toml or ~/.config/gitleaks/gitleaks.toml: default rules only, .gitleaksignore left as is");
const lines = before.split("\n");
const firstOld = lines.findIndex(l => l.startsWith(TARGET + ":"));
const kept = lines.filter(l => !l.startsWith(TARGET + ":"));
const at = firstOld === -1 ? (kept[kept.length - 1] === "" ? kept.length - 1 : kept.length) : firstOld;
kept.splice(at, 0, ...fps);
const after = kept.join("\n");
if (CONFIG && after !== before) writeFileSync(IGNORE, after);

// 4. prove the landing: with the ignore file the scan must be clean
const verify = run(["gitleaks", "detect", "--no-git", "--no-banner", "--source", TARGET,
                    ...CONFIG_ARGS, "--gitleaks-ignore-path", IGNORE], [0, 1]);
if (verify.code !== 0) { console.error("gitleaks still reports findings with the refreshed ignore file:\n" + verify.out); process.exit(1); }

console.log(`Rebuilt ${TARGET}; ${fps.length} PNG-tail fingerprint(s): ${fps.map(f => f.split(":").pop()).join(", ")}`);
console.log(!CONFIG || after === before ? ".gitleaksignore unchanged" : ".gitleaksignore updated");
if (CONFIG) console.log(`gitleaks config: ${CONFIG.startsWith(homedir()) ? "~" + CONFIG.slice(homedir().length) : CONFIG}`);
console.log("gitleaks with .gitleaksignore: clean");
