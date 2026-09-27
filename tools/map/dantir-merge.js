// ───────────────────────── Dantir merge core ─────────────────────────
// The ONE copy of the session-merge logic: per-MAC merge, confidence, name
// categories, false-positive names, and the fixed-install persistence test.
//
// Used by both entry points so they cannot drift:
//   - dantir-map.html loads it with <script src="dantir-merge.js"> (plain
//     browser script, no build step) and reads window.DantirMerge;
//   - build-map.ts require()s it to report fixed installs at bake time, and
//     inlines this same file into the page it writes (and into the standalone).
//
// Plain JavaScript on purpose: a browser can load it straight from disk.
(function (root) {
"use strict";

const FALSE_POSITIVE_NAMES = [  // name substring (lower-case) → reason. Only applied to mac_prefix matches.
  ["hue", "Philips Hue lamp (OUI collision)"],
  ["bluedriv", "BlueDriver OBD-II scanner (OUI collision)"],
  ["wyze lock", "Wyze Lock (OUI collision)"],
  ["ooler", "OOLER bed-cooling unit (Espressif OUI collision)"],
  ["square reader", "Square payment reader (Espressif OUI collision)"],
];
// KML and CSV exports carry no category; infer one from the advertised name so those sessions
// are not all "unknown". JSON exports keep the firmware's category. Order matters: first hit wins.
// Categories match what the firmware emits (Ray-Ban Meta is "glasses", Quest is "vr_headset").
const NAME_CATEGORY = [
  [/^penguin-/i, "flock"], [/^flock/i, "flock"], [/^ring\b|^ring-/i, "ring"], [/^blink/i, "ring"],
  [/wyze/i, "camera"], [/^eufy/i, "camera"], [/^arlo/i, "camera"], [/^nest ?cam/i, "camera"],
  [/^quest\b|^pico\b/i, "vr_headset"], [/ray-?ban|meta glasses/i, "glasses"],
  [/^tile\b|airtag|smarttag/i, "tracker"], [/^axon\b/i, "axon"],
];
function categoryFromName(name) {
  if (!name) return null;
  for (const [re, cat] of NAME_CATEGORY) if (re.test(name)) return cat;
  return null;
}
const FIXED_RADIUS_M = 150;   // seen in 2+ sessions within this radius → fixed install
const SPLIT_FIXED_MOBILE = new Set(["axon", "lawenf"]);  // categories whose fixed/mobile distinction matters

// Confidence mirrors the firmware's fyConfidence(): a device's own name, its
// manufacturer ID, a GATT service UUID or a SoftAP SSID identify a PRODUCT; a
// MAC prefix only identifies a MODULE VENDOR (Liteon, Silicon Labs, Samsung)
// and is a lead, not an ID. Exports written before 2026-09-20 carry no "conf"
// field, so it is derived from the method here — otherwise every historical
// session would vanish behind the default filter.
const HIGH_CONF_METHODS = new Set(["device_name","ble_mfr_id","raven_uuid","flock_uuid","wifi_ssid"]);
function confOf(d) {
  if (d.conf === "high" || d.conf === "low") return d.conf;
  return HIGH_CONF_METHODS.has(d.method) ? "high" : "low";
}

function haversineM(a, b) {
  const R = 6371000, toR = x => x * Math.PI / 180;
  const dLat = toR(b.lat - a.lat), dLon = toR(b.lon - a.lon);
  const s = Math.sin(dLat / 2) ** 2 + Math.cos(toR(a.lat)) * Math.cos(toR(b.lat)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(s));
}
function falsePositive(name, method) {
  if (!name || method !== "mac_prefix") return null;
  const n = name.toLowerCase();
  for (const [pat, reason] of FALSE_POSITIVE_NAMES) if (n.includes(pat)) return reason;
  return null;
}
function merge(sessions) {  // sessions: [{date, name, detections}]
  const byMac = new Map();
  let noGps = 0;
  for (const s of sessions) {
    for (const d of s.detections) {
      const mac = String(d.mac).toLowerCase();
      const gps = d.best_gps || d.gps;
      const rssi = Number(d.best_rssi ?? d.rssi ?? -100);
      const count = Number(d.count) || 1;
      let m = byMac.get(mac);
      if (!m) {
        m = { mac, names: [], conf: "low", cat: d.cat && d.cat !== "unknown" ? d.cat : "unknown", method: d.method || "unknown",
          best_rssi: -999, total_count: 0, sessions: [], fixes: [], lat: null, lon: null, fp_reason: falsePositive(d.name, d.method) };
        byMac.set(mac, m);
      }
      if (confOf(d) === "high") m.conf = "high";
      if (d.name && !m.names.includes(d.name)) m.names.push(d.name);
      if (d.cat && d.cat !== "unknown" && m.cat === "unknown") m.cat = d.cat;
      if (m.cat === "unknown" && !m.fp_reason) { const nc = categoryFromName(d.name); if (nc) m.cat = nc; }
      if (!m.sessions.includes(s.date)) m.sessions.push(s.date);
      m.total_count += count;
      if (!gps) { noGps++; continue; }
      m.fixes.push({ date: s.date, lat: gps.lat, lon: gps.lon, rssi });
      if (rssi > m.best_rssi) { m.best_rssi = rssi; m.lat = gps.lat; m.lon = gps.lon; }
    }
  }
  const merged = [];
  for (const m of byMac.values()) {
    m.sessions.sort();
    const datesWithFix = new Set(m.fixes.map(f => f.date));
    if (datesWithFix.size >= 2 && m.lat !== null) {
      const anchor = { lat: m.lat, lon: m.lon };
      const spread = Math.max(...m.fixes.map(f => haversineM(anchor, f)));
      m.fixed = spread <= FIXED_RADIUS_M; m.spread_m = Math.round(spread);
    } else { m.fixed = null; }
    // Persistence IS evidence in a way a module vendor never was: the same MAC
    // on 2+ separate dates inside FIXED_RADIUS_M is an installation, not a
    // passer-by. That earns a low-confidence OUI hit its way into the default
    // view, and it is the only promotion path that does not require guessing.
    if (m.conf === "low" && m.fixed === true) { m.conf = "high"; m.promoted = true; }
    if (SPLIT_FIXED_MOBILE.has(m.cat) && m.fixed !== null) m.cat = m.cat + (m.fixed ? "_fixed" : "_mobile");
    m.display_cat = m.fp_reason ? "false_positive" : m.cat;
    merged.push(m);
  }
  merged.sort((a, b) => b.total_count - a.total_count);
  return { merged, noGps };
}

// One record of the "export merged JSON" file. build-map.ts --merged writes the same shape.
function exportRecord(m) {
  return { mac: m.mac, names: m.names, cat: m.cat, method: m.method, lat: m.lat, lon: m.lon,
    best_rssi: m.best_rssi, total_count: m.total_count, sessions_seen: m.sessions, fixed_install: m.fixed, spread_m: m.spread_m ?? null, false_positive_reason: m.fp_reason };
}

const api = { merge, exportRecord, confOf, categoryFromName, falsePositive, haversineM, FIXED_RADIUS_M, SPLIT_FIXED_MOBILE, HIGH_CONF_METHODS };
if (typeof module === "object" && module && module.exports) module.exports = api;
if (root) root.DantirMerge = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
