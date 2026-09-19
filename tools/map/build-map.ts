#!/usr/bin/env bun
// Bake Dantir session exports into ONE self-contained HTML map.
//
//   bun tools/map/build-map.ts <file-or-dir> [more...] [-o out.html]
//   bun tools/map/build-map.ts --standalone [-o out.html]     # no data: one-file drop-in page
//
// Walks the given files/directories for Dantir JSON exports (arrays of
// detections with a `mac` field), embeds them into a copy of dantir-map.html
// with Leaflet inlined, and writes a single portable file. Nothing is uploaded;
// the output only contacts the basemap provider the viewer picks ("None" = no
// requests at all). Session dates come from the filename (dantir_YYYY-MM-DD_…),
// falling back to the file's mtime.
//
// Output is data-bearing: it holds your MACs and coordinates. Keep it out of
// any repo (this repo's .gitignore already refuses *.html under tools/map/out/).

import { readdirSync, readFileSync, statSync, writeFileSync, mkdirSync } from "fs";
import { join, dirname, basename, resolve } from "path";

const HERE = import.meta.dir;
const args = process.argv.slice(2);
let out = join(HERE, "out", "dantir-map.html");
let standalone = false;
const inputs: string[] = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--standalone") { standalone = true; continue; }
  if (args[i] === "-o" || args[i] === "--out") {
    if (!args[i + 1]) { console.error("-o needs a path"); usage(); process.exit(2); }
    out = resolve(args[++i]); continue;
  }
  if (args[i] === "-h" || args[i] === "--help") { usage(); process.exit(0); }
  if (args[i].startsWith("-")) { console.error(`Unknown flag ${args[i]}`); usage(); process.exit(2); }
  inputs.push(resolve(args[i]));
}
if (!inputs.length && !standalone) { usage(); process.exit(2); }

function usage() {
  console.log("usage: bun build-map.ts <file-or-dir> [more...] [-o out.html]");
  console.log("       bun build-map.ts --standalone [-o out.html]   (drop-in page as ONE file, no data)");
}

type Session = { name: string; date: string; detections: unknown[] };

function isDetectionArray(v: unknown): v is { mac: string }[] {
  return Array.isArray(v) && v.length > 0 && typeof v[0] === "object" && v[0] !== null && "mac" in (v[0] as object);
}

function collect(path: string, acc: Session[]) {
  const st = statSync(path);
  if (st.isDirectory()) {
    for (const e of readdirSync(path)) {
      if (e.startsWith(".") || e === "node_modules") continue;
      collect(join(path, e), acc);
    }
    return;
  }
  if (!path.endsWith(".json")) return;
  // Skip our own outputs: a master/merged file re-ingested would double-count every session in it.
  if (/master|merged/i.test(basename(path))) return;
  let data: unknown;
  try { data = JSON.parse(readFileSync(path, "utf8")); } catch { return; }
  const arr = isDetectionArray(data) ? data
    : (data && typeof data === "object" && isDetectionArray((data as { detections?: unknown }).detections)) ? (data as { detections: { mac: string }[] }).detections
    : null;
  if (!arr) return;
  // Same rule as the page: the date comes from the FILE name, never a dated parent directory.
  const m = basename(path).match(/(\d{4}-\d{2}-\d{2})/);
  const date = m ? m[1] : st.mtime.toISOString().slice(0, 10);
  acc.push({ name: basename(path), date, detections: arr });
}

const sessions: Session[] = [];
for (const p of inputs) collect(p, sessions);
sessions.sort((a, b) => a.date.localeCompare(b.date));
if (!standalone) {
  if (!sessions.length) { console.error("No Dantir JSON exports found under: " + inputs.join(", ")); process.exit(1); }
  console.log(`Found ${sessions.length} session file(s):`);
  for (const s of sessions) console.log(`  ${s.date}  ${s.name}  (${s.detections.length} detections)`);
}

// Inline the vendored Leaflet so the output is one file.
const page = readFileSync(join(HERE, "dantir-map.html"), "utf8");
const css = readFileSync(join(HERE, "vendor", "leaflet", "leaflet.css"), "utf8")
  .replace(/url\(images\/([^)]+)\)/g, (_m, f) => `url(data:image/png;base64,${readFileSync(join(HERE, "vendor", "leaflet", "images", f)).toString("base64")})`);
const js = readFileSync(join(HERE, "vendor", "leaflet", "leaflet.js"), "utf8");
const vendorBlock = /<!-- DANTIR-VENDOR-START -->[\s\S]*?<!-- DANTIR-VENDOR-END -->/;
if (!vendorBlock.test(page)) { console.error("dantir-map.html is missing the vendor markers"); process.exit(1); }
// Device names are attacker-controlled (BLE advertisements). Inside a <script>, "</script>" and "<!--"
// change how the browser parses the block, so every "<" in the embedded JSON becomes \u003c.
const dataJson = JSON.stringify(sessions).replace(/</g, "\\u003c");
const dataTag = standalone ? "" : `\n<script>window.DANTIR_DATA=${dataJson};</script>`;
const html = page.replace(vendorBlock,
  `<style>\n${css}\n</style>\n<script>\n${js}\n</script>${dataTag}`);

mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, html);
const total = sessions.reduce((n, s) => n + s.detections.length, 0);
if (standalone) console.log(`Wrote ${out} (${(html.length / 1024).toFixed(0)} KB, standalone drop-in page, no data)`);
else console.log(`Wrote ${out} (${(html.length / 1024).toFixed(0)} KB, ${total} detections across ${sessions.length} files)`);
console.log("Open it in a browser. Basemap picker is top-right; choose None for zero network requests.");
