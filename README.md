# Dantir — Surveillance Counter-Watcher

> *Sindarin:* **dan** (against / back) + **tir** (to watch) = *"counter-watcher."*

Dantir is a pocket-sized **BLE + WiFi surveillance-detection device** for the
Seeed XIAO ESP32-S3. It passively listens for the radio signatures of
surveillance hardware around you — Flock Safety ALPR cameras, Ring/Amazon
cameras, recording smart glasses, Bluetooth trackers, gunshot-detector nodes,
and law-enforcement gear — then alerts you with audio, light, and a live web
dashboard with a proximity radar.

It only **detects and documents**. It does not jam, spoof, or interfere with
anything. Awareness is the point: you can't push back against what you can't
see.

---

## Credits & Lineage

Dantir stands on the shoulders of others' work. Full respect and thanks to:

- **[Colonel Panic](https://colonelpanic.tech/) — [OUI Spy Unified Blue](https://github.com/colonelpanichacks/oui-spy-unified-blue)**
  Dantir is a fork of OUI Spy Unified Blue's *Flock-You* mode. The detection
  engine, session persistence, GPS handling, export pipeline, and dashboard
  foundations all originate there. If you want a polished, pre-built detector,
  buy one from Colonel Panic — support the upstream project.
- **[wgreenberg / flock-you](https://github.com/wgreenberg/flock-you)** — BLE
  detection research and signature work that informs how Flock devices are
  identified.
- **[deflock.me](https://deflock.me/)** — community-sourced surveillance device
  signatures.

Dantir's changes over upstream: standalone single-mode firmware (no BOOT-button
mode dance), added WiFi promiscuous detection (Ring/Blink), expanded BLE
manufacturer-ID and category coverage, Morse-code category alerts, a proximity
radar dashboard, and peak-RSSI GPS tracking.

---

## What it detects

Dantir uses **seven detection methods** across BLE and WiFi:

| Method | Radio | How it matches |
|--------|-------|----------------|
| `mac_prefix` | BLE | MAC OUI against the Flock Safety prefix set (lowest confidence — see note) |
| `device_name` | BLE | Advertised name patterns (Flock, Penguin, Pigvision, Ring, Ray-Ban…) |
| `ble_mfr_id` | BLE | Bluetooth manufacturer company IDs |
| `raven_uuid` | BLE | Raven gunshot-detector service UUIDs (+ firmware-version estimate) |
| `wifi_probe` | WiFi | Probe-request source MAC OUI (promiscuous mode) |
| `wifi_beacon` | WiFi | Beacon-frame source MAC OUI (promiscuous mode) |

Detections are grouped into **ten categories**, each with its own Morse-code
audio signature on the buzzer:

| Category | Morse | What it covers |
|----------|:-----:|----------------|
| `flock`      | ··-· (F) | Flock Safety / ALPR cameras, Penguin, Pigvision |
| `axon`       | ·- (A)   | Axon ALPR cameras (the vendor replacing Flock in some cities) |
| `glasses`    | --· (G)  | Camera-equipped smart glasses (Ray-Ban Meta, Oakley, Snap) |
| `vr_headset` | · (E)    | VR headsets (Quest/Oculus) — benign; logged with a quiet blip, not a threat alert |
| `tracker`    | - (T)    | Bluetooth trackers (Tile, etc.) |
| `lawenf`     | ·-·· (L) | Law-enforcement gear (TASER/Axon body-cams, Motorola Solutions) |
| `ring`       | ·-· (R)  | Ring / Blink / Amazon cameras |
| `camera`     | ··· (S)  | Other surveillance cameras (Hikvision, Arlo, Wyze) |
| `raven`      | ···- (V) | Raven gunshot-detector nodes |
| `wifi`       | ·-- (W)  | Generic WiFi-side detections |

> **Detection is signature-based, not proof.** Many OUIs are shared across a
> chipset vendor's entire catalog, so a bare `mac_prefix` match is the
> lowest-confidence signal. Treat `device_name`, `ble_mfr_id`, and `raven_uuid`
> hits as higher confidence, and confirm visually before drawing conclusions.
> Known shared-OUI false-positive sources — e.g. a Silicon Labs prefix that also
> covers Wyze locks and OBD-II dongles, and the Raspberry Pi prefix — have been
> pulled from the Flock list; real Flock-on-RPi now relies on name (Penguin /
> Pigvision) and manufacturer ID, not a bare OUI.

---

## Features

- **Dual-radio scanning** — BLE active scan + WiFi promiscuous capture running
  alongside the dashboard access point.
- **Morse-code alerts** — each category beeps its letter, so you can ID a hit
  by ear without looking.
- **Foxhunter / proximity mode** — once a device is in range, a heartbeat beep
  every 10 s helps you locate it; clears after 30 s with no new sightings.
- **NeoPixel feedback** — purple breathing when idle, red/pink flash on
  detection, dim heartbeat glow while a device is nearby.
- **Live web dashboard** — proximity radar, live detection cards, stats, and
  three themes (Purple, Tactical, Ithildin).
- **GPS tagging** — hardware GNSS (Seeed L76K) with phone-browser geolocation
  fallback; tracks both first-seen and **peak-RSSI (closest-approach)** position.
- **Exports** — download a session as JSON, CSV, or KML (Google Earth).
- **Session persistence** — detections survive reboots; the prior session is
  auto-backed up to onboard flash.
- **Optional battery monitoring** — LiPo percentage via a voltage divider, or
  uptime display if the ADC is disabled.

---

## Hardware

### Bill of materials (per unit)

| Part | Notes | Approx. |
|------|-------|---------|
| Seeed XIAO ESP32-S3 (N8R8) | Main board; needs PSRAM variant | ~$9 |
| Passive buzzer | Audio + Morse alerts | ~$1 |
| WS2812 / NeoPixel | Status LED | ~$1 |
| Seeed L76K GNSS module | *Optional* — GPS tagging | ~$10 |
| U.FL→SMA pigtail + 2.4 GHz antenna | *Optional* — extends range | ~$6 |

> For external antenna use, the XIAO's RF switch 0-ohm resistor must be moved to
> the U.FL pad. The onboard PCB antenna works fine for getting started.

### Pin map

| Function | GPIO | XIAO pin |
|----------|:----:|:--------:|
| Buzzer | 3 | — |
| NeoPixel | 4 | — |
| GPS RX | 44 | D7 |
| GPS TX | 43 | D6 |
| Battery ADC *(optional, `-1` = off)* | 1 | A0 / D0 |

---

## Build & flash

Dantir is a [PlatformIO](https://platformio.org/) project (no Arduino IDE
sketch juggling required).

```bash
git clone https://github.com/rpriven/dantir.git
cd dantir

# Build
pio run

# Flash + open serial monitor (auto-detects the XIAO on USB)
pio run --target upload
pio device monitor
```

Target environment: `seeed_xiao_esp32s3` (defined in `platformio.ini`).
Libraries are pulled automatically: NimBLE-Arduino, ESP Async WebServer,
Adafruit NeoPixel, ArduinoJson, and TinyGPSPlus.

If `pio` isn't installed: `pip install platformio` (or use the PlatformIO IDE
extension for VS Code).

---

## Usage

1. **Power on.** Dantir plays a boot "crow call" and starts scanning
   immediately — no mode selection needed.
2. **Connect to the dashboard.** Join the WiFi access point:
   - **SSID:** `dantir`  •  **Password:** `dantir123`
   - Open **`http://192.168.4.1`** in a browser.

   > ⚠️ **Change the defaults before any real use.** The stock AP credentials
   > (`dantir` / `dantir123`) are published here and in the source — anyone
   > within WiFi range of a device on stock firmware can open your live
   > detection feed and GPS position. Edit `FY_AP_SSID` / `FY_AP_PASS` in
   > `src/main.cpp` and re-flash before you take it out.
3. **(Optional) share phone GPS.** The dashboard can push your phone's
   geolocation to the device as a fallback when no hardware GNSS fix is present.
   Hardware GPS always takes priority when available.
4. **Walk.** Watch the radar and detection cards populate. Listen for the
   Morse-letter beeps to ID categories by ear.
5. **Export.** Download the session as JSON / CSV / KML, or clear it to start
   fresh (the cleared session is backed up automatically).

### Web API

The onboard server (port 80) exposes a small JSON API used by the dashboard:

| Endpoint | Purpose |
|----------|---------|
| `GET /` | Dashboard UI |
| `GET /api/detections` | Live detection list |
| `GET /api/stats` | Counts, GPS status, battery/uptime |
| `GET /api/gps?lat=&lon=&acc=` | Push phone GPS to the device |
| `GET /api/patterns` | Full signature database (MACs, names, MFR IDs, UUIDs) |
| `GET /api/export/{json,csv,kml}` | Download current session |
| `GET /api/history` · `/api/history/{json,kml}` | Prior session |
| `GET /api/clear` | Clear detections (backs up first) |

---

## Data & exports

Each detection records MAC, name, RSSI, detection method, category, first/last
seen, re-sighting count, Raven flag + firmware estimate, and **two** GPS fixes:
first-seen and peak-RSSI (closest approach). Exports:

- **JSON** — full structured record incl. `gps` and `best_gps` objects.
- **CSV** — flat table for spreadsheets/analysis.
- **KML** — placemarks for Google Earth; uses the peak-RSSI position when
  available for the most accurate location.

Sessions auto-save to onboard flash (SPIFFS) every ~15 s and are restored on
boot, so a power cycle won't lose your data.

---

## Key configuration

Tunable `#define`s at the top of `src/main.cpp`:

| Setting | Default | Meaning |
|---------|:-------:|---------|
| `BLE_SCAN_DURATION` / `BLE_SCAN_INTERVAL` | 2 s / 3000 ms | BLE scan timing |
| `MAX_DETECTIONS` | 200 | Stored-detection capacity |
| `BATTERY_ADC_PIN` | `-1` | Set to a GPIO to enable battery monitoring |
| `BATTERY_FULL_V` / `BATTERY_EMPTY_V` | 4.2 V / 3.0 V | LiPo range |
| `FY_AP_SSID` / `FY_AP_PASS` | `dantir` / `dantir123` | Dashboard AP credentials |
| `FY_SAVE_INTERVAL` | 15000 ms | Session auto-save interval |

---

## Responsible use

Dantir is a **defensive, educational, passive** tool. It receives radio signals
that devices already broadcast publicly — the same advertisements your phone
sees — and matches them against known signatures. It transmits nothing at the
targets and interferes with nothing.

You are responsible for using it lawfully in your jurisdiction. Detect, learn,
document — don't harass, stalk, or disrupt. The goal is to make an invisible
surveillance landscape visible, not to interfere with it.

**A note on the tracker category.** Detecting Bluetooth trackers (Tile,
AirTag-class devices) is a defensive, anti-stalking use — it helps someone find
a tracker another person has planted on their car or belongings. Dantir
identifies *device classes* by their public radio signatures; it is not built
to locate or follow a specific person, and we ask that you don't try to.

---

## License

[MIT](LICENSE) — Copyright (c) 2026 rpriven.
Based on **OUI Spy Unified Blue** by
[colonelpanichacks](https://github.com/colonelpanichacks/oui-spy-unified-blue).
