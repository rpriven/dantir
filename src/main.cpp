// ============================================================================
// DANTIR: Surveillance Counter-Watcher
// ============================================================================
// "Go flock yourself."
// Sindarin: dan (against/back) + tir (to watch) = counter-watcher
//
// Forked from OUI Spy Unified Blue — Flock-You mode
// Original: https://github.com/colonelpanichacks/oui-spy-unified-blue
// BLE detection research: https://github.com/wgreenberg/flock-you
//
// Detection methods:
//   BLE:
//     1. MAC prefix matching (Flock Safety, Ring, Amazon OUIs)
//     2. Device name pattern matching (case-insensitive substring)
//     3. Manufacturer company ID matching (0x09C8 XUNTONG, 0x0171 Amazon)
//     4. Raven gunshot detector service UUID matching
//     5. Raven firmware version estimation from service UUID patterns
//   WiFi (promiscuous mode):
//     6. Probe request source MAC OUI matching (Ring, Blink, Amazon)
//     7. Beacon frame source MAC OUI matching
//
// WiFi AP "dantir" / "dantir123" serves web dashboard at 192.168.4.1
// All detections stored in memory + SPIFFS, exportable as JSON, CSV, KML
// ============================================================================

#include <Arduino.h>
#include <WiFi.h>
#include <NimBLEDevice.h>
#include <NimBLEScan.h>
#include <NimBLEAdvertisedDevice.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <SPIFFS.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include "esp_wifi.h"
#include <TinyGPS++.h>
#include <Adafruit_NeoPixel.h>
#include <ESPAsyncWebServer.h>

// ============================================================================
// CONFIGURATION
// ============================================================================

#define BUZZER_PIN 3

// Hardware GPS (Seeed L76K GNSS module)
#define GPS_RX_PIN 44      // D7 — ESP32 RX <- GPS TX
#define GPS_TX_PIN 43      // D6 — ESP32 TX -> GPS RX
#define GPS_BAUD   9600
#define GPS_HDOP_SCALE 5.0f  // HDOP * scale ≈ accuracy in meters

// Audio
#define LOW_FREQ 200
#define HIGH_FREQ 800
#define DETECT_FREQ 1000
#define HEARTBEAT_FREQ 600
#define BOOT_BEEP_DURATION 300
#define DETECT_BEEP_DURATION 150
#define HEARTBEAT_DURATION 100

// NeoPixel
#define FY_NEOPIXEL_PIN 4
#define FY_NEOPIXEL_BRIGHTNESS 50
#define FY_NEOPIXEL_DETECTION_BRIGHTNESS 200

// Battery monitoring
// XIAO ESP32-S3 has no dedicated battery ADC pin. To enable battery monitoring:
//   1. Wire a voltage divider (2x 200K resistors) from BAT+ to an ADC pin
//   2. Set BATTERY_ADC_PIN to that GPIO number (e.g. 1 for A0/D0)
//   3. The code reads voltage, applies divider ratio, maps to 0-100%
// Set to -1 to disable (no hardware voltage divider connected)
#define BATTERY_ADC_PIN -1       // -1 = disabled, set to GPIO with voltage divider
#define BATTERY_SAMPLES 16       // ADC samples to average (noise reduction)
#define BATTERY_FULL_V 4.2f      // LiPo full charge voltage
#define BATTERY_EMPTY_V 3.0f     // LiPo cutoff voltage
#define BATTERY_DIVIDER 2.0f     // Voltage divider ratio (2x 200K = /2)

// BLE scanning
#define BLE_SCAN_DURATION 2      // seconds per scan
#define BLE_SCAN_INTERVAL 3000   // ms between scans

// Detection storage
#define MAX_DETECTIONS 200

// WiFi AP credentials
#define FY_AP_SSID "dantir"
#define FY_AP_PASS "dantir123"

// ============================================================================
// DETECTION PATTERNS — BLE
// ============================================================================

// Known Flock Safety MAC address prefixes (OUIs) — matched during BLE scan
static const char* ble_mac_prefixes[] = {
    // Flock Safety — FS Ext Battery devices
    "58:8e:81", "cc:cc:cc", "ec:1b:bd", "90:35:ea",
    "f0:82:c0", "1c:34:f1", "38:5b:44", "94:34:69", "b4:e3:f9",
    // Flock Safety — WiFi-enabled devices
    "70:c9:4e", "3c:91:80", "d8:f3:bc", "80:30:49", "14:5a:fc",
    "74:4c:a1", "9c:2f:9d", "94:08:53", "e4:aa:ea",
    // --- Cherry-picked from upstream colonelpanichacks/flock-you, 2026-09-20 ---
    // Flock Safety's OWN IEEE MA-L assignment (Atlanta HQ). Confirmed in the
    // 2026-09-16 firmware dump (Qualcomm MSM8953 + QCA9377, Android 8.1).
    // Highest-confidence prefix in this table: it is their corporate OUI.
    "b4:1e:52",
    // Community OUI set (NitekryDPaul). Checked against the IEEE MA-L registry
    // on 2026-09-20 before adopting; SEVEN of the 20 upstream prefixes were
    // rejected and are listed below with the reason. These remaining ones are
    // Liteon / Samsung / USI module-vendor blocks — the same class as the
    // pre-existing table above, and the same LOW confidence. A mac_prefix hit
    // is a lead, never a positive ID; device_name, ble_mfr_id and the UUID
    // vectors are what promote it.
    "c0:35:32", "f4:6a:dd", "e0:0a:f6", "00:f4:8d", "d0:39:57",
    "e8:d0:fc", "e0:4f:43", "b8:1e:a4", "70:08:94", "58:00:e3",
    "5c:93:a2", "64:6e:69", "48:27:ea"
    //
    // REJECTED from the upstream set, 2026-09-20, each verified against
    // /usr/share/ieee-data/oui.txt:
    //   "3c:71:bf", "a4:cf:12" — ESPRESSIF. This firmware runs on an Espressif
    //     part. Adopting them makes Dantir flag other Dantirs, Heltec boards,
    //     Meshtastic nodes and every Tasmota plug on the street as Flock. A
    //     detector that reports its own hardware vendor as the threat is worse
    //     than no detector.
    //   "b8:35:32", "24:b2:b9", "14:b5:cd" — not assigned in MA-L, MA-M or
    //     MA-S. An unregistered prefix cannot be attributed to anyone.
    //   "82:6b:f2" — locally-administered bit set, i.e. a randomized address.
    //     Matches by coincidence on address rotation; never a stable identifier.
    //   "00:03:7f" — Qualcomm Atheros; covers every Atheros radio ever made.
    //     The firmware dump names two EXACT MACs and only those are actionable:
    //       00:03:7f:50:00:01  (bdwlan30.bin / fakeboar.bin)
    //       00:03:7f:4f:00:16  (otp30.bin)
    //     Add as full-MAC matches if/when full-MAC matching exists.
    // REMOVED 2026-06-23 (false-positive sources — see signatures/ audit):
    //   "04:0d:84" — Silicon Labs OUI (Wyze Lock / BlueDriver / Philips Hue), NOT Flock
    //   "08:3a:88" — Raspberry Pi Foundation OUI (millions of hobby RPis), too ambiguous
    // Both produced false "flock" tags. Real Flock-on-RPi now relies on name
    // (Penguin/Pigvision) + mfr ID 0x09C8, not these shared OUIs.
};

// firmware-todo #5 (add Raven OUI ec:62:60) was CLOSED WITHOUT ADOPTING IT,
// 2026-09-20. The IEEE MA-L registry assigns ec:62:60 to ESPRESSIF INC — the
// vendor of the ESP32-S3 this firmware runs on. As the sole identifier for the
// raven category it would have tagged every other Dantir, every Heltec board
// and every Meshtastic node in range as a Flock gunshot detector. The source
// that reported it as Raven was a single field observation of one device, which
// is consistent with a Raven using an Espressif module and says nothing about
// the prefix. raven_service_uuids[] remains the reliable Raven vector.

// Known NON-surveillance devices that share an OUI with something in the
// tables above. An OUI match is weak evidence; a device NAME is strong, so a
// name hit here overrides the prefix and the detection is filed
// "false_positive" rather than silently inflating the flock count.
// Field evidence: Hue Go (34 hits / 3 sessions), BlueDriver OBD-II (8), Wyze
// Lock (3), all previously tagged flock. firmware-todo #3, added 2026-09-20.
static const char* known_false_positives[] = {
    "hue", "bluedriv", "wyze", "philips", "obdii", "obd-ii"
};

// Locally field-cleared devices: physically searched for and not found to be
// surveillance. Counted, never categorized as a threat.
// LEAVE THIS EMPTY IN THE PUBLIC REPO. A MAC here is a specific device at a
// specific place, so filling it in upstream would publish the maintainer's
// neighbourhood. Populate it in your own working copy and do not commit it.
// firmware-todo #4, added 2026-09-20.
static const char* known_benign_macs[] = { };

// ============================================================================
// DETECTION CATEGORIES
// ============================================================================
// Each detection is tagged with a category for differentiated alerts.
// Categories map to Morse code letters for buzzer/haptic patterns:
//   F (··-·) = Flock/ALPR    G (--·)  = Glasses/recording
//   T (-)    = Tracker        L (·-··) = Law enforcement
//   R (·-·)  = Ring/consumer  S (···)  = Surveillance cameras
//   V (···-) = Raven          W (·--)  = WiFi detection

// BLE device name patterns (matched case-insensitive substring)
struct NameEntry {
    const char* pattern;
    const char* category;
};

static const NameEntry device_name_entries[] = {
    // Flock Safety
    {"FS Ext Battery", "flock"},
    {"Penguin",        "flock"},
    {"Flock",          "flock"},
    {"Pigvision",      "flock"},
    // Ring / consumer cameras
    {"Ring",           "ring"},
    // Smart glasses / recording devices
    {"rayban",         "glasses"},
    {"ray-ban",        "glasses"},
    {"ray ban",        "glasses"},
};

// BLE Manufacturer Company IDs (from Bluetooth SIG assigned numbers)
struct MfrEntry {
    uint16_t id;
    const char* category;
};

static const MfrEntry ble_manufacturer_entries[] = {
    // Flock Safety / ALPR
    {0x09C8, "flock"},     // XUNTONG — Flock Safety cameras
    // Consumer surveillance (Amazon ecosystem)
    {0x0171, "ring"},      // Amazon — Ring doorbells, Echo, Blink
    // Smart glasses / recording devices
    {0x01AB, "glasses"},   // Meta Platforms — Ray-Ban Meta
    {0x058E, "glasses"},   // Meta Platforms Technologies — Ray-Ban Meta
    {0x0D53, "glasses"},   // Luxottica/EssilorLuxottica — Oakley smart glasses
    {0x03C2, "glasses"},   // Snapchat — Spectacles
    // Law enforcement equipment
    {0x034D, "lawenf"},    // TASER International / Axon — body cameras
    {0x04EC, "lawenf"},    // Motorola Solutions — police radios/cameras
    // Tracking devices
    {0x067C, "tracker"},   // Tile — BLE trackers
    // Surveillance cameras
    {0x0E25, "camera"},    // Hangzhou Hikvision — surveillance cameras
    {0x0C19, "camera"},    // Arlo Technologies — security cameras
    {0x0870, "camera"},    // Wyze Labs — security cameras
};

// ============================================================================
// DETECTION PATTERNS — WiFi (promiscuous mode)
// ============================================================================
// These OUIs are checked against source MACs in WiFi management frames
// (probe requests, beacon frames) captured via promiscuous callback.

// WiFi-side surveillance OUI prefixes (matched in promiscuous mode). Each carries its
// own category so matches aren't all assumed Ring (mirrors the shared signatures/ library).
struct WifiPrefixEntry { const char* prefix; const char* category; };
static const WifiPrefixEntry wifi_mac_prefixes[] = {
    // Ring LLC
    {"00:b4:63","ring"}, {"18:7f:88","ring"}, {"24:2b:d6","ring"}, {"34:3e:a4","ring"},
    {"54:e0:19","ring"}, {"5c:47:5e","ring"}, {"64:9a:63","ring"}, {"90:48:6c","ring"},
    {"9c:76:13","ring"}, {"ac:9f:c3","ring"}, {"c4:db:ad","ring"}, {"cc:3b:fb","ring"},
    // Blink by Amazon (Ring's sister brand)
    {"70:ad:43","ring"},
    // Axon ALPR — catches Lightpost's 2.4GHz radio / Outpost in setup mode.
    // (Deployed Outpost is LTE-only/RF-silent; Lightpost's 5GHz is invisible to ESP32.)
    {"00:25:df","axon"},
    // Flock Safety's own IEEE MA-L (firmware dump 2026-09-16, Qualcomm QCA9377
    // radio). The cameras probe-request roughly every 125 ms while channel-
    // hopping, from Qualcomm's LOWI geolocation stack, so they are noisy on
    // WiFi. Without this row a Flock camera's WiFi traffic was invisible here;
    // the prefix only lived in the BLE table. Added 2026-09-20.
    {"b4:1e:52","flock"},
};

// ============================================================================
// WIFI PROMISCUOUS MODE — frame subtypes
// ============================================================================
#define WIFI_MGMT_PROBE_REQ  0x04
#define WIFI_MGMT_BEACON     0x08

// ============================================================================
// RAVEN SURVEILLANCE DEVICE UUID PATTERNS
// ============================================================================

#define RAVEN_DEVICE_INFO_SERVICE   "0000180a-0000-1000-8000-00805f9b34fb"
#define RAVEN_GPS_SERVICE           "00003100-0000-1000-8000-00805f9b34fb"
#define RAVEN_POWER_SERVICE         "00003200-0000-1000-8000-00805f9b34fb"
#define RAVEN_NETWORK_SERVICE       "00003300-0000-1000-8000-00805f9b34fb"
#define RAVEN_UPLOAD_SERVICE        "00003400-0000-1000-8000-00805f9b34fb"
#define RAVEN_ERROR_SERVICE         "00003500-0000-1000-8000-00805f9b34fb"
#define RAVEN_OLD_HEALTH_SERVICE    "00001809-0000-1000-8000-00805f9b34fb"
#define RAVEN_OLD_LOCATION_SERVICE  "00001819-0000-1000-8000-00805f9b34fb"

// Flock accessory GATT service, from the same firmware dump. Deliberately NOT
// in raven_service_uuids[]: a hit here is a Flock accessory, not a Raven
// gunshot detector, and folding them would mis-tag the category and the
// isRaven flag. Added 2026-09-20.
#define FLOCK_ACCESSORY_SERVICE "e8ccbb38-9532-46a8-9fe5-1814df172e6f"
static const char* flock_service_uuids[] = { FLOCK_ACCESSORY_SERVICE };

static const char* raven_service_uuids[] = {
    RAVEN_DEVICE_INFO_SERVICE,
    RAVEN_GPS_SERVICE,
    RAVEN_POWER_SERVICE,
    RAVEN_NETWORK_SERVICE,
    RAVEN_UPLOAD_SERVICE,
    RAVEN_ERROR_SERVICE,
    RAVEN_OLD_HEALTH_SERVICE,
    RAVEN_OLD_LOCATION_SERVICE
};

// ============================================================================
// DETECTION STORAGE
// ============================================================================

// Widest category string plus NUL. The field was 12 bytes until 2026-09-20,
// when "flock_candidate" (15), "false_positive" (14) and "known_benign" (12)
// landed and strncpy silently stored "flock_candi", "false_posit" and
// "known_benig": every strcmp consumer (the geo-minimization gate, the
// per-category alert table, the dashboard CSS) then missed them. Update this
// and the static_assert below together when a longer category is added.
#define FY_CATEGORY_LEN 16
#define FY_LONGEST_CATEGORY "flock_candidate"

struct FYDetection {
    char mac[18];
    char name[48];
    int rssi;
    char method[24];
    char category[FY_CATEGORY_LEN];    // flock, glasses, tracker, lawenf, ring, camera, raven, axon, vr_headset, flock_candidate, false_positive, known_benign, unknown
    unsigned long firstSeen;
    unsigned long lastSeen;
    int count;
    bool isRaven;
    char ravenFW[16];
    // GPS from phone (wardriving) — first detection position
    double gpsLat;
    double gpsLon;
    float gpsAcc;
    bool hasGPS;
    bool gpsInterp;       // coords are a carried-forward fix, not a live one
    char confidence[6];   // "high" | "low" — derived from method, see fyConfidence()
    // Peak-RSSI GPS — position at strongest signal (closest approach to device)
    int bestRSSI;         // Strongest (least negative) RSSI seen
    double bestGPSLat;
    double bestGPSLon;
    float bestGPSAcc;
    bool hasBestGPS;
};

static FYDetection fyDet[MAX_DETECTIONS];
static int fyDetCount = 0;
static SemaphoreHandle_t fyMutex = NULL;

// ============================================================================
// GLOBALS
// ============================================================================

static bool fyBuzzerOn = true;
static Adafruit_NeoPixel fyPixel(1, FY_NEOPIXEL_PIN, NEO_GRB + NEO_KHZ800);
static bool fyPixelAlertMode = false;
static unsigned long fyPixelAlertStart = 0;
static unsigned long fyLastBleScan = 0;
static volatile bool fyWifiAlertPending = false;  // Deferred from promiscuous CB
// The promiscuous callback cannot buzz (it runs on the WiFi task), so the alert
// is deferred to the main loop. These carry WHAT was seen across that gap. The
// alert used to hardcode "ring" with the comment "WiFi OUIs are all Ring/Blink",
// which stopped being true on 2026-09-20 when Flock's own b4:1e:52 went into
// wifi_mac_prefixes: a Flock camera on WiFi would have buzzed as a doorbell.
static volatile const char* fyWifiAlertCat  = "ring";
static volatile const char* fyWifiAlertConf = "low";
static int fyWifiDetCount = 0;
static bool fyDeviceInRange = false;
static unsigned long fyLastDetTime = 0;
static unsigned long fyLastHB = 0;

// Per-category alert tracking — each category beeps once, then heartbeat takes over
#define FY_MAX_ALERTED_CATS 8
static char fyAlertedCats[FY_MAX_ALERTED_CATS][FY_CATEGORY_LEN] = {};
static_assert(sizeof(FY_LONGEST_CATEGORY) <= FY_CATEGORY_LEN,
              "FY_CATEGORY_LEN is too small for the longest category string");
static_assert(sizeof(((FYDetection*)0)->category) == FY_CATEGORY_LEN,
              "FYDetection.category and fyAlertedCats must share FY_CATEGORY_LEN");
static int fyAlertedCatCount = 0;

static bool fyCategoryAlerted(const char* cat) {
    if (!cat) return false;
    for (int i = 0; i < fyAlertedCatCount; i++) {
        if (strcmp(fyAlertedCats[i], cat) == 0) return true;
    }
    return false;
}

static void fyMarkCategoryAlerted(const char* cat) {
    if (!cat || fyCategoryAlerted(cat)) return;
    if (fyAlertedCatCount < FY_MAX_ALERTED_CATS) {
        strlcpy(fyAlertedCats[fyAlertedCatCount], cat, sizeof(fyAlertedCats[0]));
        fyAlertedCatCount++;
    }
}

static void fyClearAlertedCategories() {
    fyAlertedCatCount = 0;
    memset(fyAlertedCats, 0, sizeof(fyAlertedCats));
}
static NimBLEScan* fyBLEScan = NULL;
static AsyncWebServer fyServer(80);

// Phone GPS state (updated via browser Geolocation API -> /api/gps)
static double fyGPSLat = 0;
static double fyGPSLon = 0;
static float  fyGPSAcc = 0;
static bool   fyGPSValid = false;
static unsigned long fyGPSLastUpdate = 0;
#define GPS_STALE_MS 30000  // GPS considered stale after 30s without update
// Orphan-detection GPS fallback (firmware-todo #2). Past GPS_STALE_MS a fix is
// no longer "where we are", but for up to GPS_INTERP_MS it is still a far better
// answer than nothing: at driving speed two minutes is coarse, at walking speed
// it is close. Such coords are flagged gps_interp so downstream can render them
// differently and never mistake them for a live fix.
#define GPS_INTERP_MS 120000

// Hardware GPS state (Seeed L76K GNSS module on UART1)
static TinyGPSPlus fyGPS;
static HardwareSerial fyGPSSerial(1);
static bool fyHWGPSDetected = false;     // Any NMEA received = module present
static bool fyHWGPSFix = false;          // Valid position fix
static int  fyHWGPSSats = 0;             // Satellite count
static unsigned long fyHWGPSLastChar = 0;
static bool fyGPSIsHardware = false;     // Current GPS source is hardware
#define GPS_HW_TIMEOUT_MS 5000

// Session persistence (SPIFFS)
#define FY_SESSION_FILE  "/session.json"
#define FY_PREV_FILE     "/prev_session.json"
#define FY_SAVE_INTERVAL 15000  // Auto-save every 15 seconds (prevent data loss on quick power-cycle)
static unsigned long fyLastSave = 0;
static int fyLastSaveCount = 0;  // Track changes to avoid unnecessary writes
static bool fySpiffsReady = false;

// Battery monitoring
static int fyBatteryPercent = -1;    // -1 = no ADC available
static float fyBatteryVoltage = 0;
static unsigned long fyLastBattRead = 0;
#define BATTERY_READ_INTERVAL 10000  // Read every 10 seconds

static void fyReadBattery() {
#if BATTERY_ADC_PIN >= 0
    if (millis() - fyLastBattRead < BATTERY_READ_INTERVAL && fyLastBattRead > 0) return;
    fyLastBattRead = millis();
    uint32_t raw = 0;
    for (int i = 0; i < BATTERY_SAMPLES; i++) {
        raw += analogReadMilliVolts(BATTERY_ADC_PIN);
    }
    float mv = (float)raw / BATTERY_SAMPLES;
    fyBatteryVoltage = mv * BATTERY_DIVIDER / 1000.0f;
    int pct = (int)((fyBatteryVoltage - BATTERY_EMPTY_V) / (BATTERY_FULL_V - BATTERY_EMPTY_V) * 100.0f);
    if (pct > 100) pct = 100;
    if (pct < 0) pct = 0;
    fyBatteryPercent = pct;
#else
    fyBatteryPercent = -1;
#endif
}

// ============================================================================
// AUDIO SYSTEM
// ============================================================================

static void fyBeep(int freq, int dur) {
    if (!fyBuzzerOn) return;
    tone(BUZZER_PIN, freq, dur);
    delay(dur + 50);
}

// Crow caw: harsh descending sweep with warble texture
static void fyCaw(int startFreq, int endFreq, int durationMs, int warbleHz) {
    if (!fyBuzzerOn) return;
    int steps = durationMs / 8;  // 8ms per step
    float fStep = (float)(endFreq - startFreq) / steps;
    for (int i = 0; i < steps; i++) {
        int f = startFreq + (int)(fStep * i);
        // Add warble: oscillate frequency +/- for raspy texture
        if (warbleHz > 0 && (i % 3 == 0)) {
            f += ((i % 6 < 3) ? warbleHz : -warbleHz);
        }
        if (f < 100) f = 100;
        tone(BUZZER_PIN, f, 10);
        delay(8);
    }
    noTone(BUZZER_PIN);
}

static void fyBootBeep() {
    printf("[DANTIR] Boot sound (buzzer %s)\n", fyBuzzerOn ? "ON" : "OFF");
    if (!fyBuzzerOn) return;

    // === CROW CALL SEQUENCE ===
    // Caw 1: sharp descending caw
    fyCaw(850, 380, 180, 40);
    delay(100);

    // Caw 2: slightly lower, shorter
    fyCaw(780, 350, 150, 50);
    delay(100);

    // Caw 3: longer trailing caw with more rasp
    fyCaw(820, 280, 220, 60);
    delay(80);

    // Quick staccato ending "kk-kk"
    tone(BUZZER_PIN, 600, 25); delay(40);
    tone(BUZZER_PIN, 550, 25); delay(40);
    noTone(BUZZER_PIN);

    printf("[DANTIR] *caw caw caw*\n");
}

// ============================================================================
// MORSE CODE ALERT SYSTEM
// ============================================================================
// Each detection category plays its Morse code letter on the buzzer.
// This serves dual purpose: identify device type + learn Morse code.
//
// Morse patterns (. = dit, - = dah):
//   F ··-·  = Flock/ALPR       G --·   = Glasses/recording
//   T -     = Tracker           L ·-··  = Law enforcement
//   R ·-·   = Ring/consumer     S ···   = Surveillance cameras
//   V ···-  = Raven             W ·--   = WiFi detection

#define MORSE_FREQ     800    // Hz — clean, distinct tone
#define MORSE_DIT_MS   80     // dit duration
#define MORSE_DAH_MS   240    // dah = 3x dit
#define MORSE_GAP_MS   80     // inter-element gap = 1x dit
#define MORSE_LEAD_MS  30     // tiny pre-delay for audio clarity

// Play a Morse code element (dit or dah)
static void fyMorseDit() {
    tone(BUZZER_PIN, MORSE_FREQ, MORSE_DIT_MS);
    delay(MORSE_DIT_MS + MORSE_GAP_MS);
}

static void fyMorseDah() {
    tone(BUZZER_PIN, MORSE_FREQ, MORSE_DAH_MS);
    delay(MORSE_DAH_MS + MORSE_GAP_MS);
}

// Play Morse pattern for a detection category
static void fyMorseCategory(const char* category, const char* confidence) {
    if (!fyBuzzerOn || !category) return;
    delay(MORSE_LEAD_MS);

    // A vendor-OUI hit gets one dit, whatever the category guess is. Before
    // this, a Liteon module got the full four-symbol Flock alert, which trains
    // you to ignore the buzzer — and an alert you ignore is not an alert.
    if (confidence && strcmp(confidence, "low") == 0) {
        fyMorseDit();
        return;
    }

    if (strcmp(category, "flock") == 0) {
        // F: ··-·
        fyMorseDit(); fyMorseDit(); fyMorseDah(); fyMorseDit();
    } else if (strcmp(category, "glasses") == 0) {
        // G: --·
        fyMorseDah(); fyMorseDah(); fyMorseDit();
    } else if (strcmp(category, "tracker") == 0) {
        // T: -
        fyMorseDah();
    } else if (strcmp(category, "lawenf") == 0) {
        // L: ·-··
        fyMorseDit(); fyMorseDah(); fyMorseDit(); fyMorseDit();
    } else if (strcmp(category, "ring") == 0) {
        // R: ·-·
        fyMorseDit(); fyMorseDah(); fyMorseDit();
    } else if (strcmp(category, "camera") == 0) {
        // S: ···
        fyMorseDit(); fyMorseDit(); fyMorseDit();
    } else if (strcmp(category, "raven") == 0) {
        // V: ···-
        fyMorseDit(); fyMorseDit(); fyMorseDit(); fyMorseDah();
    } else if (strcmp(category, "axon") == 0) {
        // A: ·-  (Axon ALPR — Flock's municipal replacement)
        fyMorseDit(); fyMorseDah();
    } else if (strcmp(category, "false_positive") == 0 ||
               strcmp(category, "known_benign") == 0) {
        // I: ··  Two quick dits. These mean "identified, and it is NOT a threat".
        // Without this case they fell through to the else below, which is two
        // dahs — the loudest pattern in the table. The device was shouting
        // hardest at the things we had positively cleared.
        fyMorseDit(); fyMorseDit();
    } else if (strcmp(category, "flock_candidate") == 0) {
        // Q: --·-  Distinct from F (confirmed flock) on purpose: a candidate is
        // a lead to go investigate, not a positive identification.
        fyMorseDah(); fyMorseDah(); fyMorseDit(); fyMorseDah();
    } else if (strcmp(category, "vr_headset") == 0) {
        // E: ·  (single dit — VR headset, benign; quiet acknowledgement, not a threat)
        fyMorseDit();
    } else {
        // Unknown: single long beep
        fyMorseDah(); fyMorseDah();
    }
    noTone(BUZZER_PIN);
}

static void fyDetectBeep(const char* category = nullptr,
                         const char* confidence = "high") {
    printf("[DANTIR] Detection alert! [%s/%s]\n", category ? category : "?",
           confidence ? confidence : "?");
    fyPixelAlertMode = true;
    fyPixelAlertStart = millis();
    if (!fyBuzzerOn) return;
    if (category) {
        fyMorseCategory(category, confidence);
    } else {
        // Fallback: original crow caw for uncategorized
        fyCaw(400, 900, 100, 30);
        delay(60);
        fyCaw(450, 950, 100, 30);
        delay(60);
        fyCaw(900, 350, 200, 50);
    }
}

static void fyHeartbeat() {
    if (!fyBuzzerOn) return;
    // Soft double coo - like a distant crow
    fyCaw(500, 400, 80, 20);
    delay(120);
    fyCaw(480, 380, 80, 20);
}

// ============================================================================
// NEOPIXEL FUNCTIONS
// ============================================================================

static uint32_t fyHsvToRgb(uint16_t h, uint8_t s, uint8_t v) {
    uint8_t r, g, b;
    if (s == 0) {
        r = g = b = v;
    } else {
        uint8_t region = h / 43;
        uint8_t remainder = (h - (region * 43)) * 6;
        uint8_t p = (v * (255 - s)) >> 8;
        uint8_t q = (v * (255 - ((s * remainder) >> 8))) >> 8;
        uint8_t t = (v * (255 - ((s * (255 - remainder)) >> 8))) >> 8;
        switch (region) {
            case 0: r = v; g = t; b = p; break;
            case 1: r = q; g = v; b = p; break;
            case 2: r = p; g = v; b = t; break;
            case 3: r = p; g = q; b = v; break;
            case 4: r = t; g = p; b = v; break;
            default: r = v; g = p; b = q; break;
        }
    }
    return fyPixel.Color(r, g, b);
}

// Idle: slow purple breathing (hue 270)
static void fyPixelBreathing() {
    static unsigned long lastUpdate = 0;
    static float brightness = 0.0;
    static bool increasing = true;
    if (millis() - lastUpdate < 20) return;
    lastUpdate = millis();
    if (increasing) {
        brightness += 0.02;
        if (brightness >= 1.0) { brightness = 1.0; increasing = false; }
    } else {
        brightness -= 0.02;
        if (brightness <= 0.1) { brightness = 0.1; increasing = true; }
    }
    uint32_t color = fyHsvToRgb(270, 255, (uint8_t)(FY_NEOPIXEL_BRIGHTNESS * brightness));
    fyPixel.setPixelColor(0, color);
    fyPixel.show();
}

// Detection: 3 rapid flashes red->pink->red (~750ms total)
static void fyPixelDetection() {
    unsigned long elapsed = millis() - fyPixelAlertStart;
    int flashIdx = elapsed / 250;
    if (flashIdx >= 3) {
        fyPixelAlertMode = false;
        return;
    }
    uint16_t hue = (flashIdx == 1) ? 300 : 0; // pink middle, red bookends
    bool bright = ((elapsed % 250) < 150);
    uint8_t val = bright ? FY_NEOPIXEL_DETECTION_BRIGHTNESS : (FY_NEOPIXEL_BRIGHTNESS / 4);
    fyPixel.setPixelColor(0, fyHsvToRgb(hue, 255, val));
    fyPixel.show();
}

// Device in range: dim steady pink glow (hue 300)
static void fyPixelHeartbeat() {
    fyPixel.setPixelColor(0, fyHsvToRgb(300, 255, 30));
    fyPixel.show();
}

// Dispatcher: called each loop iteration
static void fyUpdatePixel() {
    if (fyPixelAlertMode) {
        fyPixelDetection();
    } else if (fyDeviceInRange) {
        fyPixelHeartbeat();
    } else {
        fyPixelBreathing();
    }
}

// ============================================================================
// DETECTION HELPERS
// ============================================================================

static bool checkBLEMACPrefix(const uint8_t* mac) {
    char mac_str[9];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x", mac[0], mac[1], mac[2]);
    for (size_t i = 0; i < sizeof(ble_mac_prefixes)/sizeof(ble_mac_prefixes[0]); i++) {
        if (strncasecmp(mac_str, ble_mac_prefixes[i], 8) == 0) return true;
    }
    return false;
}

// Returns the category for a matching WiFi OUI, or nullptr if no match.
static const char* checkWiFiMACPrefix(const uint8_t* mac) {
    char mac_str[9];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x", mac[0], mac[1], mac[2]);
    for (size_t i = 0; i < sizeof(wifi_mac_prefixes)/sizeof(wifi_mac_prefixes[0]); i++) {
        if (strncasecmp(mac_str, wifi_mac_prefixes[i].prefix, 8) == 0) return wifi_mac_prefixes[i].category;
    }
    return nullptr;
}

// ============================================================================
// WIFI PROMISCUOUS CALLBACK
// ============================================================================
// Forward declarations for functions called by WiFi promiscuous callback
static bool fyGPSIsFresh();
static int fyAddDetection(const char* mac, const char* name, int rssi,
                          const char* method, const char* category = "unknown",
                          bool isRaven = false, const char* ravenFW = "");
static const char* fyConfidence(const char* method);
static const char* fyApplyDowngrades(const char*, const char*, const char*, const char*, bool*);

// Called by the WiFi driver for every frame on the AP's channel.
// Probe requests from devices scanning (on ANY channel) are caught because
// WiFi devices sweep all channels when probing. Beacons only on AP channel.
// NOTE: Runs on the WiFi task — do NOT call delay()/tone() here.
// Audio/LED alerts are deferred to the main loop via fyWifiAlertPending.

static void fyWifiPromiscuousCB(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;

    // Minimum 802.11 management header: 24 bytes
    // (FC:2 + Duration:2 + Addr1:6 + Addr2:6 + Addr3:6 + SeqCtrl:2)
    if (len < 24) return;

    // Frame Control byte 0: bits[3:2]=type, bits[7:4]=subtype
    uint8_t fc0 = frame[0];
    uint8_t frame_type = (fc0 >> 2) & 0x03;
    uint8_t subtype = (fc0 >> 4) & 0x0F;

    if (frame_type != 0) return;  // Not a management frame
    if (subtype != WIFI_MGMT_PROBE_REQ && subtype != WIFI_MGMT_BEACON) return;

    // Address 2 (source/transmitter MAC) at offset 10
    const uint8_t *src_mac = &frame[10];

    const char *wcat = checkWiFiMACPrefix(src_mac);

    // SSID check (added 2026-09-20, firmware dump 2026-09-16). The camera's
    // SoftAP name is built in WifiApService.java as the literal "Flock-" plus
    // the last 6 characters of its WiFi MAC. Provisioned units have also been
    // seen broadcasting a bare "Flock". An SSID hit stands on its own — it does not need an OUI
    // match, which is the point, since it catches hardware revisions whose
    // prefix is not in any list yet.
    char ssid[33] = {0};
    bool ssidFlock = false;
    if (subtype == WIFI_MGMT_BEACON && len >= 38) {
        // 24B management header + 12B fixed params (timestamp 8, interval 2,
        // capability 2), then tagged IEs. Tag 0 is the SSID.
        uint8_t ssid_len = frame[37];
        if (frame[36] == 0 && ssid_len > 0 && ssid_len <= 32 && 38 + (int)ssid_len <= len) {
            memcpy(ssid, &frame[38], ssid_len);
            ssid[ssid_len] = '\0';
            if (strncasecmp(ssid, "Flock-", 6) == 0 || strcasecmp(ssid, "Flock") == 0) {
                ssidFlock = true;
            }
        }
    }

    if (!wcat && !ssidFlock) return;
    if (ssidFlock) wcat = "flock";

    // Match! Build MAC string and register detection
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             src_mac[0], src_mac[1], src_mac[2],
             src_mac[3], src_mac[4], src_mac[5]);

    const char *method = ssidFlock ? "wifi_ssid"
                       : (subtype == WIFI_MGMT_PROBE_REQ) ? "wifi_probe" : "wifi_beacon";
    int rssi = pkt->rx_ctrl.rssi;

    int idx = fyAddDetection(mac_str, ssid, rssi, method, wcat);
    // Everything below reports and alerts on the POST-downgrade category, the
    // same one fyAddDetection stored. fyApplyDowngrades returns string
    // literals, so wcat stays a stable pointer for the deferred alert in the
    // main loop (fyWifiAlertCat); reading fyDet[idx].category there would
    // point into a slot that a session clear can zero underneath it.
    wcat = fyApplyDowngrades(mac_str, ssid, method, wcat, nullptr);
    if (idx >= 0) {
        if (fyDet[idx].count == 1) {
            // First sighting — new WiFi surveillance device
            fyWifiDetCount++;
            printf("[DANTIR] WiFi DETECTED [%s]: %s RSSI:%d [%s]\n", wcat, mac_str, rssi, method);

            // JSON serial output
            char gpsBuf[80] = "";
            if (fyGPSIsFresh()) {
                snprintf(gpsBuf, sizeof(gpsBuf),
                    ",\"gps\":{\"latitude\":%.8f,\"longitude\":%.8f,\"accuracy\":%.1f}",
                    fyGPSLat, fyGPSLon, fyGPSAcc);
            }
            printf("{\"detection_method\":\"%s\",\"category\":\"%s\",\"protocol\":\"wifi\","
                   "\"mac_address\":\"%s\",\"rssi\":%d%s}\n",
                   method, wcat, mac_str, rssi, gpsBuf);
        }

        // Defer buzzer/LED alert to main loop (can't call delay() here)
        fyDeviceInRange = true;
        fyLastDetTime = millis();
        fyWifiAlertCat  = wcat;
        fyWifiAlertConf = fyConfidence(method);
        fyWifiAlertPending = true;
    }
}

// ============================================================================
// DETECTION HELPERS — NAME & MANUFACTURER
// ============================================================================

// Returns category string if name matches, or nullptr
static const char* checkDeviceName(const char* name) {
    if (!name || !name[0]) return nullptr;
    for (size_t i = 0; i < sizeof(device_name_entries)/sizeof(device_name_entries[0]); i++) {
        if (strcasestr(name, device_name_entries[i].pattern)) return device_name_entries[i].category;
    }
    return nullptr;
}

// Returns category string if manufacturer ID matches, or nullptr
static const char* checkManufacturerID(uint16_t id) {
    for (size_t i = 0; i < sizeof(ble_manufacturer_entries)/sizeof(ble_manufacturer_entries[0]); i++) {
        if (ble_manufacturer_entries[i].id == id) return ble_manufacturer_entries[i].category;
    }
    return nullptr;
}

// ============================================================================
// RAVEN UUID DETECTION
// ============================================================================

static bool checkRavenUUID(NimBLEAdvertisedDevice* device, char* out_uuid = nullptr) {
    if (!device || !device->haveServiceUUID()) return false;
    int count = device->getServiceUUIDCount();
    if (count == 0) return false;
    for (int i = 0; i < count; i++) {
        NimBLEUUID svc = device->getServiceUUID(i);
        std::string str = svc.toString();
        for (size_t j = 0; j < sizeof(raven_service_uuids)/sizeof(raven_service_uuids[0]); j++) {
            if (strcasecmp(str.c_str(), raven_service_uuids[j]) == 0) {
                if (out_uuid) strncpy(out_uuid, str.c_str(), 40);
                return true;
            }
        }
    }
    return false;
}

static bool checkFlockUUID(NimBLEAdvertisedDevice* device, char* out_uuid = nullptr) {
    if (!device || !device->haveServiceUUID()) return false;
    int count = device->getServiceUUIDCount();
    for (int i = 0; i < count; i++) {
        std::string str = device->getServiceUUID(i).toString();
        for (size_t j = 0; j < sizeof(flock_service_uuids)/sizeof(flock_service_uuids[0]); j++) {
            if (strcasecmp(str.c_str(), flock_service_uuids[j]) == 0) {
                if (out_uuid) strncpy(out_uuid, str.c_str(), 40);
                return true;
            }
        }
    }
    return false;
}

static const char* estimateRavenFW(NimBLEAdvertisedDevice* device) {
    if (!device || !device->haveServiceUUID()) return "?";
    bool has_new_gps = false, has_old_loc = false, has_power = false;
    int count = device->getServiceUUIDCount();
    for (int i = 0; i < count; i++) {
        std::string u = device->getServiceUUID(i).toString();
        if (strcasecmp(u.c_str(), RAVEN_GPS_SERVICE) == 0)          has_new_gps = true;
        if (strcasecmp(u.c_str(), RAVEN_OLD_LOCATION_SERVICE) == 0) has_old_loc = true;
        if (strcasecmp(u.c_str(), RAVEN_POWER_SERVICE) == 0)        has_power = true;
    }
    if (has_old_loc && !has_new_gps) return "1.1.x";
    if (has_new_gps && !has_power)   return "1.2.x";
    if (has_new_gps && has_power)    return "1.3.x";
    return "?";
}

// ============================================================================
// GPS HELPERS
// ============================================================================

static bool fyGPSIsFresh() {
    return fyGPSValid && (millis() - fyGPSLastUpdate < GPS_STALE_MS);
}

// GPS data-minimization gate (firmware-todo #10, raised 2026-06-23).
// A detection we cannot name, or one we have positively identified as NOT
// surveillance, is counted but never geo-logged. Recording precise coordinates
// to track a neighbour's VR headset or an unidentified radio is a self-inflicted
// doxx surface with no analytic payoff, and it is the bulk of what a leaked
// export would reveal. Surveillance categories are unaffected.
static bool fyCategoryMayGeoLog(const char* cat) {
    if (!cat || !cat[0]) return false;
    // "flock_candidate" is deliberately NOT here: it is a genuine unknown that
    // may be surveillance, and its coordinates are what the fixed-install
    // persistence test needs in order to resolve it either way.
    static const char* denied[] = {
        "unknown", "vr_headset", "false_positive", "known_benign"
    };
    for (size_t i = 0; i < sizeof(denied)/sizeof(denied[0]); i++) {
        if (strcasecmp(cat, denied[i]) == 0) return false;
    }
    return true;
}

static void fyAttachGPS(FYDetection& d) {
    if (!fyCategoryMayGeoLog(d.category)) return;
    if (fyGPSIsFresh()) {
        d.hasGPS = true;
        d.gpsInterp = false;
        d.gpsLat = fyGPSLat;
        d.gpsLon = fyGPSLon;
        d.gpsAcc = fyGPSAcc;
        return;
    }
    // Stale but recent: carry the last known fix forward, flagged. Never let an
    // interpolated fix overwrite a live one already attached to this detection.
    if (fyGPSValid && !(d.hasGPS && !d.gpsInterp) &&
        (millis() - fyGPSLastUpdate) < GPS_INTERP_MS) {
        d.hasGPS = true;
        d.gpsInterp = true;
        d.gpsLat = fyGPSLat;
        d.gpsLon = fyGPSLon;
        d.gpsAcc = fyGPSAcc;
    }
}

// ============================================================================
// HARDWARE GPS PROCESSING
// ============================================================================

static void fyProcessHardwareGPS() {
    // Read all available UART bytes into TinyGPSPlus parser
    while (fyGPSSerial.available()) {
        char c = fyGPSSerial.read();
        fyGPS.encode(c);
        fyHWGPSLastChar = millis();
        if (!fyHWGPSDetected) {
            fyHWGPSDetected = true;
            printf("[DANTIR] Hardware GPS module detected (NMEA data received)\n");
        }
    }

    // Timeout: no NMEA data for 5s → module disconnected or absent
    if (fyHWGPSDetected && (millis() - fyHWGPSLastChar > GPS_HW_TIMEOUT_MS)) {
        if (fyGPSIsHardware) {
            printf("[DANTIR] Hardware GPS timeout — falling back to phone GPS\n");
        }
        fyHWGPSDetected = false;
        fyHWGPSFix = false;
        fyHWGPSSats = 0;
        fyGPSIsHardware = false;
    }

    // Update satellite count whenever available
    if (fyGPS.satellites.isUpdated()) {
        fyHWGPSSats = fyGPS.satellites.value();
    }

    // Update position when valid fix is available
    if (fyGPS.location.isUpdated() && fyGPS.location.isValid()) {
        if (!fyHWGPSFix) {
            printf("[DANTIR] First GPS fix acquired! Sats:%d Lat:%.6f Lon:%.6f\n",
                   fyHWGPSSats, fyGPS.location.lat(), fyGPS.location.lng());
        }
        fyHWGPSFix = true;
        fyGPSIsHardware = true;
        fyGPSLat = fyGPS.location.lat();
        fyGPSLon = fyGPS.location.lng();
        fyGPSAcc = fyGPS.hdop.isValid() ? (float)(fyGPS.hdop.hdop() * GPS_HDOP_SCALE) : 10.0f;
        fyGPSValid = true;
        fyGPSLastUpdate = millis();
    } else if (fyHWGPSFix && fyGPS.location.isValid()) {
        // Keep updating timestamp while fix is held
        fyGPSLastUpdate = millis();
    }
}

// ============================================================================
// DETECTION MANAGEMENT
// ============================================================================

// Case-insensitive substring test against a name table.
static bool fyNameMatchesAny(const char* name, const char* const* table, size_t n) {
    if (!name || !name[0]) return false;
    char low[64];
    size_t i = 0;
    for (; i < sizeof(low) - 1 && name[i]; i++) low[i] = (char)tolower((unsigned char)name[i]);
    low[i] = '\0';
    for (size_t j = 0; j < n; j++) if (strstr(low, table[j])) return true;
    return false;
}

static bool fyIsKnownFalsePositive(const char* name) {
    return fyNameMatchesAny(name, known_false_positives,
                            sizeof(known_false_positives)/sizeof(known_false_positives[0]));
}

static bool fyIsKnownBenignMAC(const char* mac) {
    for (size_t j = 0; j < sizeof(known_benign_macs)/sizeof(known_benign_macs[0]); j++) {
        if (strcasecmp(mac, known_benign_macs[j]) == 0) return true;
    }
    return false;
}

// True when the ONLY thing that identified this device was a vendor OUI. Every
// prefix table in this firmware is a module-vendor block (Liteon, Silicon Labs,
// Samsung), not a Flock-specific assignment, so a prefix hit is a lead and a
// device's own name outranks it. Covers the WiFi paths too: the promiscuous
// callback matches on OUI exactly like the BLE scan does, and an earlier
// version of this check guarded on method=="mac_prefix" alone, which silently
// exempted every WiFi detection from the downgrades.
static bool fyMethodIsPrefixOnly(const char* m) {
    return m && (strcmp(m, "mac_prefix") == 0 ||
                 strcmp(m, "wifi_probe") == 0 ||
                 strcmp(m, "wifi_beacon") == 0);
}

// Confidence is a SEPARATE axis from category. Category says what we think the
// device is; confidence says how we know. Every prefix table in this firmware
// is a module-vendor block (Liteon, Silicon Labs, Samsung), never a
// Flock-specific IEEE assignment, so an OUI hit is a lead and nothing more.
// A device's own name, its manufacturer ID, a GATT service UUID or a SoftAP
// SSID are specific to the product and are treated as identification.
//
// Keeping these two axes separate is what lets the vendor prefixes stay in the
// table honestly: the uncertainty lives in the data instead of in a comment.
static const char* fyConfidence(const char* method) {
    if (!method) return "low";
    if (strcmp(method, "device_name") == 0 ||
        strcmp(method, "ble_mfr_id")  == 0 ||
        strcmp(method, "raven_uuid")  == 0 ||
        strcmp(method, "flock_uuid")  == 0 ||
        strcmp(method, "wifi_ssid")   == 0) return "high";
    // mac_prefix, wifi_probe, wifi_beacon, name_pattern
    return "low";
}

// Names come off the radio (a BLE local name, a WiFi SSID) and are printed
// with printf into JSON, the session file, CSV (quoted) and a KML CDATA block
// that Google Earth renders as HTML. One sanitizer, applied on first sight AND
// on every re-sighting: quotes and backslashes for JSON/CSV, angle brackets
// and ampersand for HTML/XML (and the CDATA terminator "]]>"), control bytes
// for the line-based writers. Replaced with '_' so the name stays readable.
// Before 2026-09-20 only the first-sighting path stripped quotes, so one
// beacon with a newline in its SSID made /api/detections invalid JSON and
// the saved session unparseable on reboot.
static void fySanitizeName(char* dst, size_t dstSize, const char* src) {
    size_t j = 0;
    if (src) {
        for (; j + 1 < dstSize && src[j]; j++) {
            unsigned char c = (unsigned char)src[j];
            dst[j] = (c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' ||
                      c < 0x20 || c == 0x7f) ? '_' : (char)c;
        }
    }
    dst[j] = '\0';
}

// Applied on BOTH detection paths, at the single point they converge.
static const char* fyApplyDowngrades(const char* mac, const char* name,
                                     const char* method, const char* category,
                                     bool* isRaven) {
    if (fyIsKnownBenignMAC(mac)) {
        if (isRaven) *isRaven = false;
        return "known_benign";
    }
    if (fyMethodIsPrefixOnly(method) && fyIsKnownFalsePositive(name)) {
        if (isRaven) *isRaven = false;
        return "false_positive";
    }
    return category;
}

static int fyAddDetection(const char* mac, const char* name, int rssi,
                          const char* method, const char* category,
                          bool isRaven, const char* ravenFW) {
    category = fyApplyDowngrades(mac, name, method, category, &isRaven);
    if (!fyMutex || xSemaphoreTake(fyMutex, pdMS_TO_TICKS(100)) != pdTRUE) return -1;

    // Update existing by MAC
    for (int i = 0; i < fyDetCount; i++) {
        if (strcasecmp(fyDet[i].mac, mac) == 0) {
            fyDet[i].count++;
            fyDet[i].lastSeen = millis();
            fyDet[i].rssi = rssi;
            if (name && name[0]) {
                fySanitizeName(fyDet[i].name, sizeof(fyDet[i].name), name);
            }
            // Refresh the category. The caller recomputes it from scratch on
            // every advertisement, so a device first seen nameless as "glasses"
            // becomes "vr_headset" once its name resolves. Without this the
            // stale category persisted and fyCategoryMayGeoLog kept geo-logging
            // a device we had already identified as benign. "unknown" never
            // overwrites something more specific.
            //
            // Sticky categories (2026-09-20): a clearance (false_positive,
            // known_benign) or an identification that needed the name
            // (vr_headset) is not undone by a later advertisement that carries
            // no name and only has the OUI to go on. Before this rule a Hue Go
            // on a Flock prefix was cleared on its first, named sighting and
            // flipped back to "flock" on the next nameless one, and that same
            // call geo-logged it. Only known_benign may replace a sticky value.
            if (category && category[0] && strcmp(category, "unknown") != 0 &&
                strcmp(category, fyDet[i].category) != 0) {
                const bool stickyStored = strcmp(fyDet[i].category, "false_positive") == 0 ||
                                          strcmp(fyDet[i].category, "known_benign") == 0 ||
                                          strcmp(fyDet[i].category, "vr_headset") == 0;
                if (!stickyStored || strcmp(category, "known_benign") == 0) {
                    strncpy(fyDet[i].category, category, sizeof(fyDet[i].category) - 1);
                    fyDet[i].category[sizeof(fyDet[i].category) - 1] = '\0';
                }
            }
            // Confidence only ever ratchets UP. A device identified by name
            // once stays identified even if the next advertisement carries no
            // name and falls back to the OUI.
            if (strcmp(fyConfidence(method), "high") == 0 &&
                strcmp(fyDet[i].confidence, "high") != 0) {
                strncpy(fyDet[i].confidence, "high", sizeof(fyDet[i].confidence) - 1);
                strncpy(fyDet[i].method, method, sizeof(fyDet[i].method) - 1);
            }
            // Update GPS on every re-sighting (captures movement)
            fyAttachGPS(fyDet[i]);
            // Track peak RSSI — strongest signal = closest approach to device
            if (rssi > fyDet[i].bestRSSI && fyGPSIsFresh() &&
                fyCategoryMayGeoLog(fyDet[i].category)) {
                fyDet[i].bestRSSI = rssi;
                fyDet[i].bestGPSLat = fyGPSLat;
                fyDet[i].bestGPSLon = fyGPSLon;
                fyDet[i].bestGPSAcc = fyGPSAcc;
                fyDet[i].hasBestGPS = true;
            }
            xSemaphoreGive(fyMutex);
            return i;
        }
    }

    // Add new
    if (fyDetCount < MAX_DETECTIONS) {
        FYDetection& d = fyDet[fyDetCount];
        memset(&d, 0, sizeof(d));
        strncpy(d.mac, mac, sizeof(d.mac) - 1);
        fySanitizeName(d.name, sizeof(d.name), name);
        d.rssi = rssi;
        d.bestRSSI = rssi;  // First sighting = initial best
        strncpy(d.method, method, sizeof(d.method) - 1);
        strncpy(d.confidence, fyConfidence(method), sizeof(d.confidence) - 1);
        strncpy(d.category, category ? category : "unknown", sizeof(d.category) - 1);
        d.firstSeen = millis();
        d.lastSeen = millis();
        d.count = 1;
        d.isRaven = isRaven;
        strncpy(d.ravenFW, ravenFW ? ravenFW : "", sizeof(d.ravenFW) - 1);
        // Attach GPS from phone (first-seen position)
        fyAttachGPS(d);
        // Initialize best GPS to first-seen GPS. Never seed it from an
        // interpolated fix: best_gps is the peak-RSSI position and the map pins
        // on it in preference to gps, so a carried-forward coord here would
        // silently become the plotted location of the device.
        if (d.hasGPS && !d.gpsInterp) {
            d.bestGPSLat = d.gpsLat;
            d.bestGPSLon = d.gpsLon;
            d.bestGPSAcc = d.gpsAcc;
            d.hasBestGPS = true;
        }
        int idx = fyDetCount++;
        xSemaphoreGive(fyMutex);
        return idx;
    }

    xSemaphoreGive(fyMutex);
    return -1;
}

// ============================================================================
// BLE SCANNING
// ============================================================================

// A DBC350-style hostname on a device we cannot otherwise identify. Flock has
// shipped camera generations built on Raspberry Pi Compute Modules, so this
// pattern is suggestive and nothing more — it is filed "flock_candidate", never
// "flock". The RPi OUI itself (08:3a:88) stays OUT of the prefix table: it
// covers millions of hobby boards and produced false flock tags before it was
// removed on 2026-06-23. Promotion to flock requires a second, specific vector
// (mfr ID 0x09C8 or a known Flock device name), which the ordering below gives
// for free since those checks run first. firmware-todo #4.
static bool fyIsFlockCandidateName(const char* name) {
    static const char* pats[] = { "dbc350" };
    return fyNameMatchesAny(name, pats, sizeof(pats)/sizeof(pats[0]));
}

class FYBLECallbacks : public NimBLEAdvertisedDeviceCallbacks {
    void onResult(NimBLEAdvertisedDevice* dev) override {
        NimBLEAddress addr = dev->getAddress();
        std::string addrStr = addr.toString();

        // Safe MAC byte extraction
        unsigned int m[6];
        sscanf(addrStr.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
        uint8_t mac[6] = {(uint8_t)m[0], (uint8_t)m[1], (uint8_t)m[2],
                          (uint8_t)m[3], (uint8_t)m[4], (uint8_t)m[5]};

        int rssi = dev->getRSSI();
        std::string name = dev->haveName() ? dev->getName() : "";

        bool detected = false;
        const char* method = "";
        bool isRaven = false;
        const char* ravenFW = "";

        const char* cat = nullptr;

        // 1. Check MAC prefix against known surveillance device OUIs (BLE)
        if (checkBLEMACPrefix(mac)) {
            detected = true;
            method = "mac_prefix";
            cat = "flock";  // MAC prefixes are all Flock Safety OUIs
        }

        // 2. Check BLE device name patterns (returns category or nullptr)
        if (!detected && !name.empty()) {
            cat = checkDeviceName(name.c_str());
            if (cat) {
                detected = true;
                method = "device_name";
            }
        }

        // 3. Check BLE manufacturer company IDs (returns category or nullptr)
        if (!detected) {
            for (int i = 0; i < (int)dev->getManufacturerDataCount(); i++) {
                std::string data = dev->getManufacturerData(i);
                if (data.size() >= 2) {
                    uint16_t code = ((uint16_t)(uint8_t)data[1] << 8) |
                                     (uint16_t)(uint8_t)data[0];
                    cat = checkManufacturerID(code);
                    if (cat) {
                        detected = true;
                        method = "ble_mfr_id";
                        break;
                    }
                }
            }
        }

        // 4. Check Raven gunshot detector service UUIDs
        if (!detected) {
            char detUUID[41] = {0};
            if (checkRavenUUID(dev, detUUID)) {
                detected = true;
                method = "raven_uuid";
                cat = "raven";
                isRaven = true;
                ravenFW = estimateRavenFW(dev);
            }
        }

        // 4b. Flock accessory GATT service (firmware-derived). Category flock,
        //     and isRaven stays false on purpose.
        if (!detected) {
            char flockUUID[41] = {0};
            if (checkFlockUUID(dev, flockUUID)) {
                detected = true;
                method = "flock_uuid";
                cat = "flock";
            }
        }

        // 4c. Downgrades and overrides, applied last so they can veto every
        //     check above. Order matters: a benign clearance beats a false-
        //     positive name, which beats a bare OUI match.
        // The benign-MAC and false-positive-name downgrades now live in
        // fyAddDetection (fyApplyDowngrades), which both detection paths go
        // through. Only the BLE-specific promotion stays here.
        if (!detected && fyIsFlockCandidateName(name.c_str())) {
            // Nothing specific matched, but the hostname fits the RPi-based
            // camera pattern. Suggestive only. firmware-todo #4.
            detected = true;
            method = "name_pattern";
            cat = "flock_candidate";
        }

        // 5. Refine glasses: Meta's mfr ID covers BOTH Ray-Ban Meta (camera/surveillance
        //    glasses) and Quest/Oculus (VR headsets) — split by device name (different
        //    threat models). Mirrors firmware-todo #6 / shared signatures library.
        if (cat && strcmp(cat, "glasses") == 0 && !name.empty()) {
            std::string lname = name;
            for (auto& c : lname) c = (char)tolower((unsigned char)c);
            if (lname.find("quest") != std::string::npos ||
                lname.find("oculus") != std::string::npos) {
                cat = "vr_headset";
            }
        }

        if (detected) {
            int idx = fyAddDetection(addrStr.c_str(), name.c_str(), rssi,
                                     method, cat ? cat : "unknown",
                                     isRaven, ravenFW);

            // Log, serial JSON and the alert all use the category AFTER
            // fyApplyDowngrades ran inside fyAddDetection. Until 2026-09-20 they
            // used the caller's pre-downgrade `cat`, so a known_benign or
            // false_positive device still buzzed its original threat pattern and
            // printed category: flock on serial, and the "identified, not a
            // threat" Morse case was unreachable.
            const char* catStr = (idx >= 0) ? fyDet[idx].category : (cat ? cat : "unknown");
            printf("[DANTIR] DETECTED [%s]: %s %s RSSI:%d [%s] count:%d\n",
                   catStr, addrStr.c_str(), name.c_str(), rssi, method,
                   idx >= 0 ? fyDet[idx].count : 0);

            // JSON serial output (Flask-compatible format for live ingestion)
            // Build GPS fragment if available
            char gpsBuf[80] = "";
            if (fyGPSIsFresh()) {
                snprintf(gpsBuf, sizeof(gpsBuf),
                    ",\"gps\":{\"latitude\":%.8f,\"longitude\":%.8f,\"accuracy\":%.1f}",
                    fyGPSLat, fyGPSLon, fyGPSAcc);
            }
            const bool ravenNow = (idx >= 0) ? fyDet[idx].isRaven : isRaven;
            if (ravenNow) {
                printf("{\"detection_method\":\"%s\",\"category\":\"%s\",\"protocol\":\"bluetooth_le\","
                       "\"mac_address\":\"%s\",\"device_name\":\"%s\","
                       "\"rssi\":%d,\"is_raven\":true,\"raven_fw\":\"%s\"%s}\n",
                       method, catStr, addrStr.c_str(), name.c_str(), rssi, ravenFW, gpsBuf);
            } else {
                printf("{\"detection_method\":\"%s\",\"category\":\"%s\",\"protocol\":\"bluetooth_le\","
                       "\"mac_address\":\"%s\",\"device_name\":\"%s\","
                       "\"rssi\":%d%s}\n",
                       method, catStr, addrStr.c_str(), name.c_str(), rssi, gpsBuf);
            }

            if (!fyCategoryAlerted(catStr)) {
                fyMarkCategoryAlerted(catStr);
                fyDetectBeep(catStr, fyConfidence(method));
                fyLastHB = millis();  // Start heartbeat countdown AFTER the alert beep
            }
            fyDeviceInRange = true;
            fyLastDetTime = millis();
        }
    }
};

// ============================================================================
// JSON HELPER
// ============================================================================

static void writeDetectionsJSON(AsyncResponseStream *resp) {
    resp->print("[");
    if (fyMutex && xSemaphoreTake(fyMutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        for (int i = 0; i < fyDetCount; i++) {
            if (i > 0) resp->print(",");
            resp->printf(
                "{\"mac\":\"%s\",\"name\":\"%s\",\"rssi\":%d,\"method\":\"%s\","
                "\"cat\":\"%s\","
                "\"first\":%lu,\"last\":%lu,\"count\":%d,"
                "\"raven\":%s,\"fw\":\"%s\",\"conf\":\"%s\"",
                fyDet[i].mac, fyDet[i].name, fyDet[i].rssi, fyDet[i].method,
                fyDet[i].category,
                fyDet[i].firstSeen, fyDet[i].lastSeen, fyDet[i].count,
                fyDet[i].isRaven ? "true" : "false", fyDet[i].ravenFW,
                fyDet[i].confidence);
            // Append GPS if present (first-seen position)
            if (fyDet[i].hasGPS) {
                resp->printf(",\"gps\":{\"lat\":%.8f,\"lon\":%.8f,\"acc\":%.1f}%s",
                    fyDet[i].gpsLat, fyDet[i].gpsLon, fyDet[i].gpsAcc,
                    fyDet[i].gpsInterp ? ",\"gps_interp\":true" : "");
            }
            // Append best GPS (peak-RSSI = closest approach position)
            if (fyDet[i].hasBestGPS) {
                resp->printf(",\"best_rssi\":%d,\"best_gps\":{\"lat\":%.8f,\"lon\":%.8f,\"acc\":%.1f}",
                    fyDet[i].bestRSSI,
                    fyDet[i].bestGPSLat, fyDet[i].bestGPSLon, fyDet[i].bestGPSAcc);
            }
            resp->print("}");
        }
        xSemaphoreGive(fyMutex);
    }
    resp->print("]");
}

// ============================================================================
// SESSION PERSISTENCE (SPIFFS)
// ============================================================================

static void fySaveSession() {
    if (!fySpiffsReady || !fyMutex) return;
    if (xSemaphoreTake(fyMutex, pdMS_TO_TICKS(300)) != pdTRUE) return;

    File f = SPIFFS.open(FY_SESSION_FILE, "w");
    if (!f) { xSemaphoreGive(fyMutex); return; }

    f.print("[");
    for (int i = 0; i < fyDetCount; i++) {
        if (i > 0) f.print(",");
        FYDetection& d = fyDet[i];
        f.printf("{\"mac\":\"%s\",\"name\":\"%s\",\"rssi\":%d,\"method\":\"%s\","
                 "\"cat\":\"%s\","
                 "\"first\":%lu,\"last\":%lu,\"count\":%d,"
                 "\"raven\":%s,\"fw\":\"%s\",\"conf\":\"%s\"",
                 d.mac, d.name, d.rssi, d.method,
                 d.category,
                 d.firstSeen, d.lastSeen, d.count,
                 d.isRaven ? "true" : "false", d.ravenFW, d.confidence);
        if (d.hasGPS) {
            f.printf(",\"gps\":{\"lat\":%.8f,\"lon\":%.8f,\"acc\":%.1f}%s",
                d.gpsLat, d.gpsLon, d.gpsAcc, d.gpsInterp ? ",\"gps_interp\":true" : "");
        }
        if (d.hasBestGPS) {
            f.printf(",\"best_rssi\":%d,\"best_gps\":{\"lat\":%.8f,\"lon\":%.8f,\"acc\":%.1f}",
                d.bestRSSI, d.bestGPSLat, d.bestGPSLon, d.bestGPSAcc);
        }
        f.print("}");
    }
    f.print("]");
    f.close();
    fyLastSaveCount = fyDetCount;
    printf("[DANTIR] Session saved: %d detections\n", fyDetCount);
    xSemaphoreGive(fyMutex);
}

static void fyPromotePrevSession() {
    // Copy current session to prev_session on boot, then delete original
    // NOTE: SPIFFS.rename() is unreliable on ESP32 — use copy+delete instead
    if (!fySpiffsReady) return;
    if (!SPIFFS.exists(FY_SESSION_FILE)) {
        printf("[DANTIR] No prior session file to promote\n");
        return;
    }

    File src = SPIFFS.open(FY_SESSION_FILE, "r");
    if (!src) {
        printf("[DANTIR] Failed to open session file for promotion\n");
        return;
    }
    String data = src.readString();
    src.close();

    if (data.length() == 0) {
        printf("[DANTIR] Session file empty, skipping promotion\n");
        SPIFFS.remove(FY_SESSION_FILE);
        return;
    }

    // Write to prev_session (overwrite any existing)
    File dst = SPIFFS.open(FY_PREV_FILE, "w");
    if (!dst) {
        printf("[DANTIR] Failed to create prev_session file\n");
        return;
    }
    dst.print(data);
    dst.close();

    // Delete the old session file so it doesn't get re-promoted next boot
    SPIFFS.remove(FY_SESSION_FILE);
    printf("[DANTIR] Prior session promoted: %d bytes\n", data.length());
}

// Restore detections from prev_session into live array (append mode)
// Called after promotion — loads prev_session data so dashboard survives reboots
static void fyRestoreSession() {
    if (!fySpiffsReady || !SPIFFS.exists(FY_PREV_FILE)) {
        printf("[DANTIR] No prev_session to restore\n");
        return;
    }

    File f = SPIFFS.open(FY_PREV_FILE, "r");
    if (!f) {
        printf("[DANTIR] Failed to open prev_session for restore\n");
        return;
    }
    String data = f.readString();
    f.close();

    if (data.length() == 0) {
        printf("[DANTIR] prev_session empty, nothing to restore\n");
        return;
    }

    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, data);
    if (err || !doc.is<JsonArray>()) {
        printf("[DANTIR] prev_session JSON parse failed: %s\n", err.c_str());
        return;
    }

    int restored = 0;
    for (JsonObject d : doc.as<JsonArray>()) {
        if (fyDetCount >= MAX_DETECTIONS) break;

        FYDetection& det = fyDet[fyDetCount];
        memset(&det, 0, sizeof(FYDetection));

        strlcpy(det.mac, d["mac"] | "", sizeof(det.mac));
        // Sanitized again on the way back in: a session file written by a
        // build before fySanitizeName covered the re-sighting path can carry
        // a raw name, and every writer downstream trusts fyDet.
        fySanitizeName(det.name, sizeof(det.name), d["name"] | "");
        det.rssi = d["rssi"] | 0;
        strlcpy(det.method, d["method"] | "", sizeof(det.method));
        strlcpy(det.category, d["cat"] | "unknown", sizeof(det.category));
        // Confidence rides outside the gps block: a detection saved without a
        // fix still has one. Until 2026-09-20 it was restored only alongside
        // gps, so every GPS-less detection came back with an empty string,
        // which the Morse table reads as "high". Session files written before
        // the field existed carry no "conf"; derive it from the method the
        // same way fyAddDetection does on first sight.
        strlcpy(det.confidence, d["conf"] | fyConfidence(det.method), sizeof(det.confidence));
        det.firstSeen = d["first"] | 0UL;
        det.lastSeen = d["last"] | 0UL;
        det.count = d["count"] | 1;
        det.isRaven = d["raven"] | false;
        strlcpy(det.ravenFW, d["fw"] | "", sizeof(det.ravenFW));

        JsonObject gps = d["gps"];
        if (gps && gps["lat"]) {
            det.gpsLat = gps["lat"] | 0.0;
            det.gpsLon = gps["lon"] | 0.0;
            det.gpsAcc = gps["acc"] | 0.0f;
            det.hasGPS = true;
            // Round-trip the interpolation flag. Without this a reboot launders
            // a carried-forward coordinate into an apparently-live fix, and the
            // next export publishes it unflagged — up to 120 s of travel away.
            det.gpsInterp = d["gps_interp"] | false;
        }

        if (d["best_rssi"].is<int>()) {
            det.bestRSSI = d["best_rssi"] | 0;
            JsonObject bgps = d["best_gps"];
            if (bgps && bgps["lat"]) {
                det.bestGPSLat = bgps["lat"] | 0.0;
                det.bestGPSLon = bgps["lon"] | 0.0;
                det.bestGPSAcc = bgps["acc"] | 0.0f;
                det.hasBestGPS = true;
            }
        }

        fyDetCount++;
        restored++;
    }

    // Mark as already saved so we don't immediately re-write the same data
    fyLastSaveCount = fyDetCount;
    printf("[DANTIR] Restored %d detections from prev_session\n", restored);
}

// ============================================================================
// KML EXPORT
// ============================================================================

static void writeDetectionsKML(AsyncResponseStream *resp) {
    resp->print("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                "<kml xmlns=\"http://www.opengis.net/kml/2.2\">\n<Document>\n"
                "<name>Dantir Detections</name>\n"
                "<description>Surveillance device detections with GPS</description>\n");

    // Detection pin style
    resp->print("<Style id=\"det\"><IconStyle><color>ff4489ec</color>"
                "<scale>1.0</scale></IconStyle></Style>\n"
                "<Style id=\"raven\"><IconStyle><color>ff4444ef</color>"
                "<scale>1.2</scale></IconStyle></Style>\n"
                "<Style id=\"interp\"><IconStyle><color>8044aaaa</color>"
                "<scale>0.8</scale></IconStyle></Style>\n");

    if (fyMutex && xSemaphoreTake(fyMutex, pdMS_TO_TICKS(300)) == pdTRUE) {
        for (int i = 0; i < fyDetCount; i++) {
            FYDetection& d = fyDet[i];
            if (!d.hasGPS && !d.hasBestGPS) continue;  // Skip detections without any GPS
            // Use best GPS (closest approach) if available, else first-seen GPS
            double pinLat = d.hasBestGPS ? d.bestGPSLat : d.gpsLat;
            double pinLon = d.hasBestGPS ? d.bestGPSLon : d.gpsLon;
            float pinAcc = d.hasBestGPS ? d.bestGPSAcc : d.gpsAcc;
            resp->print("<Placemark>\n");
            resp->printf("<name>%s</name>\n", d.mac);
            const bool pinIsInterp = (!d.hasBestGPS && d.gpsInterp);
            resp->printf("<styleUrl>#%s</styleUrl>\n",
                         pinIsInterp ? "interp" : (d.isRaven ? "raven" : "det"));
            resp->print("<description><![CDATA[");
            if (d.name[0]) resp->printf("<b>Name:</b> %s<br/>", d.name);
            resp->printf("<b>Method:</b> %s<br/>"
                         "<b>RSSI:</b> %d dBm<br/>"
                         "<b>Best RSSI:</b> %d dBm<br/>"
                         "<b>Count:</b> %d<br/>",
                         d.method, d.rssi, d.hasBestGPS ? d.bestRSSI : d.rssi, d.count);
            resp->printf("<b>Confidence:</b> %s<br/>", d.confidence);
            if (d.isRaven) resp->printf("<b>Raven FW:</b> %s<br/>", d.ravenFW);
            // pinAcc is the GPS receiver's accuracy for a LIVE fix. When the
            // pin falls back to an interpolated gps (which is exactly the
            // !hasBestGPS case now), that number describes the fix's precision
            // at the moment it was taken, not how far the device has travelled
            // since. Printing it bare labelled a possibly-kilometres-stale pin
            // "Accuracy: 5.0 m".
            if (!d.hasBestGPS && d.gpsInterp) {
                resp->printf("<b>Accuracy:</b> %.1f m at time of fix "
                             "<b>(INTERPOLATED — carried forward up to %d s, "
                             "true position may differ)</b>",
                             pinAcc, GPS_INTERP_MS / 1000);
            } else {
                resp->printf("<b>Accuracy:</b> %.1f m", pinAcc);
            }
            resp->print("]]></description>\n");
            resp->printf("<Point><coordinates>%.8f,%.8f,0</coordinates></Point>\n",
                         pinLon, pinLat);
            resp->print("</Placemark>\n");
        }
        xSemaphoreGive(fyMutex);
    }
    resp->print("</Document>\n</kml>");
}

// ============================================================================
// DASHBOARD HTML
// ============================================================================

static const char FY_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>DANTIR</title>
<style>
:root{
--bg-body:#0a0012;--bg-hdr:#1a0033;--bg-card:linear-gradient(135deg,rgba(45,27,105,.5),rgba(30,15,80,.3));
--bg-stats:rgba(139,92,246,.08);--bg-tag:rgba(139,92,246,.15);
--a1:#ec4899;--a2:#8b5cf6;--a3:#c084fc;
--b1:#ec4899;--b2:rgba(139,92,246,.25);--b3:rgba(139,92,246,.19);
--t1:#e0e0e0;--t2:rgba(139,92,246,.5);
--grid:rgba(236,72,153,.02);
--rr:rgba(139,92,246,.2);--rs:rgba(236,72,153,.4);
--bl-flock:#ef4444;--bl-ring:#60a5fa;--bl-raven:#f59e0b;--bl-other:#6b7280;
--btn-bg:#8b5cf6;--btn-act:#ec4899;
}
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;overflow:hidden}
body{font-family:'Courier New',monospace;background:var(--bg-body);color:var(--t1);display:flex;flex-direction:column}
body::before{content:"";position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:0;
background-image:linear-gradient(var(--grid) 1px,transparent 1px),linear-gradient(90deg,var(--grid) 1px,transparent 1px);background-size:50px 50px}
.hd{background:var(--bg-hdr);padding:10px 14px;border-bottom:2px solid var(--b1);flex-shrink:0;position:relative;z-index:1;
display:flex;justify-content:space-between;align-items:center}
.hd::after{content:'';position:absolute;bottom:-2px;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--a1),transparent);opacity:.3}
.hd-l h1{font-size:22px;color:var(--a1);letter-spacing:4px;text-shadow:0 0 8px var(--a1)}
.hd-l .sub{font-size:11px;color:var(--a2);margin-top:2px}
#thm{background:rgba(0,0,0,.3);color:var(--a1);border:1px solid var(--b2);border-radius:4px;padding:4px 8px;
font-family:inherit;font-size:11px;font-weight:bold;letter-spacing:1px;cursor:pointer}
.st{display:flex;gap:8px;padding:8px 12px;background:var(--bg-stats);border-bottom:1px solid var(--b3);flex-shrink:0;position:relative;z-index:1}
.sc{flex:1;text-align:center;padding:6px;border:1px solid var(--b2);border-radius:5px}
.sc .n{font-size:22px;font-weight:bold;color:var(--a1)}
.sc .l{font-size:10px;color:var(--a2);margin-top:2px}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.pulse{display:inline-block;width:6px;height:6px;border-radius:50%;background:#22c55e;animation:pulse 2s ease-in-out infinite;vertical-align:middle;margin-right:4px}
.tb{display:flex;border-bottom:1px solid var(--a2);flex-shrink:0;position:relative;z-index:1}
.tb button{flex:1;padding:9px;text-align:center;cursor:pointer;color:var(--a2);border:none;background:none;font-family:inherit;font-size:13px;font-weight:bold;letter-spacing:1px}
.tb button.a{color:var(--a1);border-bottom:2px solid var(--a1);background:rgba(236,72,153,.08)}
.cn{flex:1;overflow-y:auto;padding:10px;position:relative;z-index:1}
.pn{display:none}.pn.a{display:block}
.det{background:var(--bg-card);border:1px solid var(--b2);border-radius:7px;padding:10px;margin-bottom:8px;border-left:3px solid var(--a2)}
.det.t-flock{border-left-color:var(--bl-flock)}.det.t-ring{border-left-color:var(--bl-ring)}
.det.t-raven{border-left-color:var(--bl-raven)}.det.t-wifi{border-left-color:#22c55e}
.det.t-glasses{border-left-color:#e879f9}.det.t-lawenf{border-left-color:#f43f5e}
.det.t-tracker{border-left-color:#fb923c}.det.t-camera{border-left-color:#94a3b8}
.det.t-unknown{border-left-color:#6b7280}
/* Cleared and candidate categories, added 2026-09-20. Muted green reads as
   "handled, not a threat"; amber-dashed reads as "lead, go look". Without
   these rules all three fell through to the default border and were visually
   indistinguishable from a confirmed detection. */
.det.t-false_positive{border-left-color:#4ade80;opacity:.6}
.det.t-known_benign{border-left-color:#4ade80;opacity:.5}
.det.t-flock_candidate{border-left-color:#fbbf24;border-left-style:dashed}
/* axon and vr_headset were added 2026-06-23 and never given a rule, so both
   rendered as generic grey "other" — axon being Flock's municipal replacement
   and the most important new vendor on the board. Found 2026-09-20 by the
   category-coverage probe, not by looking. */
.det.t-axon{border-left-color:#a855f7}
.det.t-vr_headset{border-left-color:#4ade80;opacity:.6}
.det .mac{color:var(--a1);font-weight:bold;font-size:14px}
.det .nm{color:var(--a3);font-size:13px;margin-left:4px}
.det .inf{display:flex;flex-wrap:wrap;gap:5px;margin-top:5px;font-size:12px}
.det .inf span{background:var(--bg-tag);padding:3px 6px;border-radius:4px}
.det .rv{background:rgba(239,68,68,.15)!important;color:#ef4444;font-weight:bold}
.rp{background:var(--bg-card);border:1px solid var(--b2);border-radius:7px;margin-bottom:10px}
.rp-h{padding:10px;cursor:pointer;color:var(--a1);font-weight:bold;font-size:13px;display:flex;justify-content:space-between;align-items:center}
.rp-h .arr{display:inline-block;transition:transform .2s;font-size:10px}
.rp-h.open .arr{transform:rotate(90deg)}
.rp-ct{font-size:11px;color:var(--a2)}
.rp-b{display:none;padding:0 10px 10px;text-align:center}
.rp-b.open{display:block}
#rC{max-width:100%;border-radius:7px}
.rp-lg{margin-top:8px;font-size:11px;display:flex;justify-content:center;gap:12px;color:var(--t1)}
.ch{background:var(--bg-card);border:1px solid var(--b2);border-radius:7px;margin-bottom:10px;overflow:hidden;max-height:160px}
.ch canvas{width:100%;display:block;max-height:150px}
.pg{margin-bottom:12px}
.pg h3{color:var(--a1);font-size:14px;margin-bottom:4px;border-bottom:1px solid var(--b3);padding-bottom:4px}
.pg .it{display:flex;flex-wrap:wrap;gap:4px;font-size:12px}
.pg .it span{background:var(--bg-tag);padding:3px 6px;border-radius:4px;border:1px solid var(--b3)}
.btn{display:block;width:100%;padding:10px;margin-bottom:8px;background:var(--btn-bg);color:#fff;border:none;border-radius:5px;cursor:pointer;font-family:inherit;font-size:14px;font-weight:bold}
.btn:active{background:var(--btn-act)}
.btn.dng{background:#ef4444}
.empty{text-align:center;color:var(--t2);padding:28px;font-size:14px}
.sep{border:none;border-top:1px solid var(--b3);margin:12px 0}
h4{color:var(--a1);font-size:14px;margin-bottom:8px}
</style></head><body>
<div class="hd">
<div class="hd-l"><h1>DANTIR</h1><div class="sub" id="tagline"></div></div>
<select id="thm" onchange="setTheme(this.value)">
<option value="purple">PURPLE</option>
<option value="tactical">TACTICAL</option>
<option value="ithildin">ITHILDIN</option>
</select>
</div>
<div class="st">
<div class="sc"><div class="n" id="sT">0</div><div class="l"><span class="pulse"></span>DETECTED</div></div>
<div class="sc"><div class="n" id="sR">0</div><div class="l">RAVEN</div></div>
<div class="sc"><div class="n" id="sB">ON</div><div class="l">BLE+WiFi</div></div>
<div class="sc" onclick="reqGPS()" style="cursor:pointer"><div class="n" id="sG" style="font-size:14px">TAP</div><div class="l" id="sGL">GPS</div></div>
<div class="sc"><div class="n" id="sBat" style="font-size:12px">--</div><div class="l" id="sBatL">UPTIME</div></div>
</div>
<div class="tb">
<button class="a" onclick="tab(0,this)">LIVE</button>
<button onclick="tab(1,this)">PREV</button>
<button onclick="tab(2,this)">DB</button>
<button onclick="tab(3,this)">TOOLS</button>
</div>
<div class="cn">
<div class="pn a" id="p0">
<div class="rp">
<div class="rp-h" onclick="togRadar()"><div><span class="arr" id="rArr">&#9654;</span> PROXIMITY RADAR</div><span class="rp-ct" id="rCt">0 devices</span></div>
<div class="rp-b" id="rB"><canvas id="rC" width="280" height="280"></canvas>
<div class="rp-lg"><span style="color:var(--bl-flock)">&#9679;</span>Flock <span style="color:var(--bl-ring)">&#9679;</span>Ring <span style="color:var(--bl-raven)">&#9679;</span>Raven <span style="color:#22c55e">&#9679;</span>WiFi <span style="color:#e879f9">&#9679;</span>Glasses <span style="color:#f43f5e">&#9679;</span>LawEnf <span style="color:#fb923c">&#9679;</span>Tracker <span style="color:#a855f7">&#9679;</span>Axon <span style="color:#fbbf24">&#9679;</span>Candidate <span style="color:#4ade80">&#9679;</span>Cleared <span style="color:var(--bl-other)">&#9679;</span>Other</div></div>
</div>
<div class="ch" id="chP" style="display:none"><canvas id="chC" height="60"></canvas></div>
<div id="dL"><div class="empty">Scanning for surveillance devices...<br>BLE + WiFi promiscuous active</div></div>
</div>
<div class="pn" id="p1"><div id="hL"><div class="empty">Loading prior session...</div></div></div>
<div class="pn" id="p2"><div id="pC">Loading patterns...</div></div>
<div class="pn" id="p3">
<h4>EXPORT DETECTIONS</h4>
<p style="font-size:10px;color:var(--a2);margin-bottom:8px">Download current session data</p>
<button class="btn" onclick="dlTS('/api/export/json','dantir','json')">DOWNLOAD JSON</button>
<button class="btn" onclick="dlTS('/api/export/csv','dantir','csv')">DOWNLOAD CSV</button>
<button class="btn" onclick="dlTS('/api/export/kml','dantir','kml')" style="background:#22c55e">DOWNLOAD KML (GPS MAP)</button>
<hr class="sep">
<h4>PRIOR SESSION</h4>
<button class="btn" onclick="dlTS('/api/history/json','dantir_prev','json')" style="background:#6366f1">DOWNLOAD PREV JSON</button>
<button class="btn" onclick="dlTS('/api/history/kml','dantir_prev','kml')" style="background:#22c55e">DOWNLOAD PREV KML</button>
<hr class="sep">
<button class="btn dng" onclick="if(confirm('Clear all detections?'))fetch('/api/clear').then(()=>refresh())">CLEAR ALL DETECTIONS</button>
</div>
</div>
<script>
// === THEMES ===
const TH={
purple:{
'--bg-body':'#0a0012','--bg-hdr':'#1a0033',
'--bg-card':'linear-gradient(135deg,rgba(45,27,105,.5),rgba(30,15,80,.3))',
'--bg-stats':'rgba(139,92,246,.08)','--bg-tag':'rgba(139,92,246,.15)',
'--a1':'#ec4899','--a2':'#8b5cf6','--a3':'#c084fc',
'--b1':'#ec4899','--b2':'rgba(139,92,246,.25)','--b3':'rgba(139,92,246,.19)',
'--t1':'#e0e0e0','--t2':'rgba(139,92,246,.5)',
'--grid':'rgba(236,72,153,.02)',
'--rr':'rgba(139,92,246,.2)','--rs':'rgba(236,72,153,.4)',
'--bl-flock':'#ef4444','--bl-ring':'#60a5fa','--bl-raven':'#f59e0b','--bl-other':'#6b7280',
'--btn-bg':'#8b5cf6','--btn-act':'#ec4899'},
tactical:{
'--bg-body':'#0a0f0a','--bg-hdr':'#0f1a0f',
'--bg-card':'linear-gradient(135deg,rgba(20,40,20,.6),rgba(15,30,15,.3))',
'--bg-stats':'rgba(34,197,94,.05)','--bg-tag':'rgba(34,197,94,.15)',
'--a1':'#22c55e','--a2':'#facc15','--a3':'#84cc16',
'--b1':'#22c55e','--b2':'rgba(34,197,94,.3)','--b3':'rgba(34,197,94,.15)',
'--t1':'#d4f4dd','--t2':'rgba(34,197,94,.4)',
'--grid':'rgba(34,197,94,.03)',
'--rr':'rgba(34,197,94,.25)','--rs':'rgba(250,204,21,.4)',
'--bl-flock':'#ef4444','--bl-ring':'#3b82f6','--bl-raven':'#f59e0b','--bl-other':'#a3a3a3',
'--btn-bg':'#16a34a','--btn-act':'#facc15'},
ithildin:{
'--bg-body':'#080811','--bg-hdr':'#0f0f1f',
'--bg-card':'linear-gradient(135deg,rgba(30,41,59,.5),rgba(20,30,48,.3))',
'--bg-stats':'rgba(148,163,184,.06)','--bg-tag':'rgba(148,163,184,.12)',
'--a1':'#cbd5e1','--a2':'#60a5fa','--a3':'#93c5fd',
'--b1':'#94a3b8','--b2':'rgba(148,163,184,.3)','--b3':'rgba(148,163,184,.12)',
'--t1':'#f1f5f9','--t2':'rgba(148,163,184,.4)',
'--grid':'rgba(96,165,250,.02)',
'--rr':'rgba(148,163,184,.2)','--rs':'rgba(96,165,250,.35)',
'--bl-flock':'#ef4444','--bl-ring':'#60a5fa','--bl-raven':'#f59e0b','--bl-other':'#94a3b8',
'--btn-bg':'#3b82f6','--btn-act':'#60a5fa'}
};
function setTheme(n){const t=TH[n];if(!t)return;const r=document.documentElement;
for(const[k,v]of Object.entries(t))r.style.setProperty(k,v);
try{localStorage.setItem('dantir_theme',n)}catch(e){}}
// === TAGLINES ===
const TAGS=['Surveillance Counter-Watcher &bull; Go Flock Yourself',
'Surveillance Counter-Watcher &bull; Privacy is a Right',
'Surveillance Counter-Watcher &bull; BLE + WiFi + GPS',
'Surveillance Counter-Watcher &bull; dan (against) + tir (to watch)'];
// === STATE ===
let D=[],H=[],_dGPS=null,_rO=false,_rA=0;
// === TABS ===
function tab(i,el){document.querySelectorAll('.tb button').forEach(b=>b.classList.remove('a'));
document.querySelectorAll('.pn').forEach(p=>p.classList.remove('a'));
el.classList.add('a');document.getElementById('p'+i).classList.add('a');
if(i===1&&!window._hL)loadHistory();if(i===2&&!window._pL)loadPat();}
// === TIMESTAMPED DOWNLOAD ===
function dlTS(url,prefix,ext){const d=new Date();const ts=d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0')+'_'+String(d.getHours()).padStart(2,'0')+String(d.getMinutes()).padStart(2,'0')+String(d.getSeconds()).padStart(2,'0');fetch(url).then(r=>r.blob()).then(b=>{const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=prefix+'_'+ts+'.'+ext;a.click();URL.revokeObjectURL(a.href);});}
// === REFRESH ===
function refresh(){fetch('/api/detections').then(r=>r.json()).then(d=>{D=d;render();stats();drawChart();}).catch(()=>{});}
// === DETECT TYPE ===
function dtype(d){return d.cat||'unknown';}
// === RENDER LIST ===
function render(){const el=document.getElementById('dL');
if(!D.length){el.innerHTML='<div class="empty">Scanning for surveillance devices...<br>BLE + WiFi promiscuous active</div>';return;}
D.sort((a,b)=>b.last-a.last);el.innerHTML=D.map(card).join('');
document.getElementById('rCt').textContent=D.length+' device'+(D.length!==1?'s':'');}
function card(d){const t=dtype(d);
return '<div class="det t-'+t+'"><div class="mac">'+d.mac+(d.name?'<span class="nm">'+esc(d.name)+'</span>':'')+'</div><div class="inf">'
+'<span>RSSI: '+d.rssi+'</span><span>'+d.method+'</span>'
+'<span style="color:var(--a1);font-weight:bold">&times;'+d.count+'</span>'
+(d.raven?'<span class="rv">RAVEN '+d.fw+'</span>':'')
+(d.best_gps?'<span style="color:#22c55e" title="Peak RSSI: '+d.best_rssi+'dBm">&#9673; '+d.best_gps.lat.toFixed(5)+','+d.best_gps.lon.toFixed(5)+'</span>':d.gps?'<span style="color:#a3e635">&#9673; '+d.gps.lat.toFixed(5)+','+d.gps.lon.toFixed(5)+'</span>':'<span style="color:#666">no gps</span>')
+'</div></div>';}
// Device names and SSIDs are attacker-controlled bytes off the radio. They are
// concatenated into innerHTML below, so they are escaped here rather than
// trusted. Added 2026-09-20 after the SSID capture path made this reachable
// from any laptop in monitor mode, with no BLE stack and no pairing.
function esc(t){return String(t==null?'':t).replace(/[&<>"']/g,function(c){
return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
// === STATS ===
function stats(){document.getElementById('sT').textContent=D.length;
document.getElementById('sR').textContent=D.filter(d=>d.raven).length;
fetch('/api/stats').then(r=>r.json()).then(s=>{
let g=document.getElementById('sG'),gl=document.getElementById('sGL');
if(s.gps_src==='hw'){g.textContent=s.gps_sats+'sat';g.style.color='#22c55e';gl.textContent='HW GPS';}
else if(s.gps_src==='phone'){g.textContent=s.gps_tagged+'/'+s.total;g.style.color='#22c55e';gl.textContent='PHONE';}
else if(s.gps_hw_detected){g.textContent=s.gps_sats+'sat';g.style.color='#facc15';gl.textContent='NO FIX';}
else if(_gErr){g.textContent=_gErrTxt;g.style.color=_gErr===3?'#facc15':'#ef4444';gl.textContent='GPS E'+_gErr;}
else if(_gW!==null){g.textContent='...';g.style.color='#facc15';gl.textContent='ACQUIRING';}
else{g.textContent='TAP';g.style.color='#ef4444';gl.textContent='GPS';}
if(s.device_lat&&s.device_lon)_dGPS={lat:s.device_lat,lon:s.device_lon};else _dGPS=null;
let bt=document.getElementById('sBat'),bl=document.getElementById('sBatL');
if(s.batt_pct>=0){bt.textContent=s.batt_pct+'%';bl.textContent=s.batt_v.toFixed(1)+'V';
bt.style.color=s.batt_pct>20?'#22c55e':s.batt_pct>10?'#facc15':'#ef4444';}
else{bt.textContent=s.uptime;bl.textContent='UPTIME';}
}).catch(()=>{});}
// === RADAR ===
function togRadar(){_rO=!_rO;
document.getElementById('rB').classList.toggle('open',_rO);
document.querySelector('.rp-h').classList.toggle('open',_rO);
document.getElementById('rArr').innerHTML=_rO?'&#9660;':'&#9654;';}
function macHash(m){let h=0;for(let i=0;i<m.length;i++){h=((h<<5)-h)+m.charCodeAt(i);h|=0;}return Math.abs(h);}
function bearing(la1,lo1,la2,lo2){const r=Math.PI/180,dL=(lo2-lo1)*r;
const y=Math.sin(dL)*Math.cos(la2*r);
const x=Math.cos(la1*r)*Math.sin(la2*r)-Math.sin(la1*r)*Math.cos(la2*r)*Math.cos(dL);
return Math.atan2(y,x);}
function drawRadar(){if(!_rO)return;const c=document.getElementById('rC');if(!c)return;
const ctx=c.getContext('2d'),w=c.width,h=c.height,cx=w/2,cy=h/2,mR=Math.min(w,h)/2-20;
const cs=getComputedStyle(document.documentElement);
ctx.clearRect(0,0,w,h);
// rings
ctx.strokeStyle=cs.getPropertyValue('--rr').trim();ctx.lineWidth=1;
[.25,.5,.75,1].forEach(r=>{ctx.beginPath();ctx.arc(cx,cy,mR*r,0,Math.PI*2);ctx.stroke();});
// crosshairs
ctx.beginPath();ctx.moveTo(cx,cy-mR);ctx.lineTo(cx,cy+mR);ctx.moveTo(cx-mR,cy);ctx.lineTo(cx+mR,cy);ctx.stroke();
// RSSI labels
ctx.fillStyle=cs.getPropertyValue('--t2').trim();ctx.font='9px monospace';ctx.textAlign='center';
ctx.fillText('-30',cx+12,cy-mR*.25+3);ctx.fillText('-50',cx+12,cy-mR*.5+3);
ctx.fillText('-70',cx+12,cy-mR*.75+3);ctx.fillText('-90',cx+12,cy-mR+3);
// sweep
ctx.strokeStyle=cs.getPropertyValue('--rs').trim();ctx.lineWidth=2;ctx.beginPath();ctx.moveTo(cx,cy);
ctx.lineTo(cx+mR*Math.cos(_rA),cy+mR*Math.sin(_rA));ctx.stroke();
// sweep trail
const grd=ctx.createConicGradient(_rA-0.5,cx,cy);
grd.addColorStop(0,'transparent');grd.addColorStop(0.08,cs.getPropertyValue('--rs').trim());
grd.addColorStop(0.1,'transparent');
ctx.fillStyle=grd;ctx.beginPath();ctx.arc(cx,cy,mR,0,Math.PI*2);ctx.fill();
// blips
D.forEach(det=>{
const rssi=Math.abs(det.rssi),dist=Math.max(0,Math.min(1,(rssi-30)/60))*mR;
let ang;const dg=det.best_gps||det.gps;
if(_dGPS&&dg)ang=bearing(_dGPS.lat,_dGPS.lon,dg.lat,dg.lon);
else ang=(macHash(det.mac)%628)/100;
const bx=cx+dist*Math.cos(ang),by=cy+dist*Math.sin(ang);
const t=dtype(det);let col=cs.getPropertyValue('--bl-other').trim();
if(t==='raven')col=cs.getPropertyValue('--bl-raven').trim();
else if(t==='ring')col=cs.getPropertyValue('--bl-ring').trim();
else if(t==='flock')col=cs.getPropertyValue('--bl-flock').trim();
else if(t==='flock_candidate')col='#fbbf24';
else if(t==='axon')col='#a855f7';
else if(t==='false_positive'||t==='known_benign'||t==='vr_headset')col='#4ade80';
else if(t==='wifi')col='#22c55e';
else if(t==='glasses')col='#e879f9';
else if(t==='lawenf')col='#f43f5e';
else if(t==='tracker')col='#fb923c';
else if(t==='camera')col='#94a3b8';
else if(t==='wifi')col='#22c55e';
ctx.fillStyle=col;ctx.globalAlpha=1;ctx.beginPath();ctx.arc(bx,by,4,0,Math.PI*2);ctx.fill();
// glow for high count
if(det.count>5){ctx.strokeStyle=col;ctx.lineWidth=1.5;ctx.globalAlpha=.35;
ctx.beginPath();ctx.arc(bx,by,7,0,Math.PI*2);ctx.stroke();ctx.globalAlpha=1;}
});
_rA+=0.03;if(_rA>Math.PI*2)_rA=0;}
// === CHART ===
function drawChart(){const cp=document.getElementById('chP'),cc=document.getElementById('chC');
if(!D.length){cp.style.display='none';return;}
cp.style.display='block';
const sorted=[...D].sort((a,b)=>b.rssi-a.rssi);const n=Math.min(sorted.length,8);
const cs=getComputedStyle(document.documentElement);
cc.width=cp.offsetWidth||300;cc.height=Math.max(60,n*18+10);
const ctx=cc.getContext('2d'),w=cc.width,h=cc.height,bh=12,gap=4,lw=90;
for(let i=0;i<n;i++){
const d=sorted[i],y=i*(bh+gap)+5;
const rssi=Math.abs(d.rssi),pct=Math.max(0,Math.min(1,(90-rssi)/60));
const bw=pct*(w-lw-10);
const t=dtype(d);let col=cs.getPropertyValue('--bl-other').trim();
if(t==='raven')col=cs.getPropertyValue('--bl-raven').trim();
else if(t==='ring')col=cs.getPropertyValue('--bl-ring').trim();
else if(t==='flock')col=cs.getPropertyValue('--bl-flock').trim();
else if(t==='flock_candidate')col='#fbbf24';
else if(t==='axon')col='#a855f7';
else if(t==='false_positive'||t==='known_benign'||t==='vr_headset')col='#4ade80';
else if(t==='wifi')col='#22c55e';
else if(t==='glasses')col='#e879f9';
else if(t==='lawenf')col='#f43f5e';
else if(t==='tracker')col='#fb923c';
else if(t==='camera')col='#94a3b8';
// label
ctx.fillStyle=cs.getPropertyValue('--t1').trim();ctx.font='10px monospace';ctx.textAlign='right';
const lbl=d.name?d.name.substring(0,10):d.mac.substring(9);
ctx.fillText(lbl,lw-4,y+bh-2);
// bar
ctx.fillStyle=col;ctx.globalAlpha=.8;
ctx.fillRect(lw,y,bw,bh);ctx.globalAlpha=1;
// rssi label
ctx.fillStyle=cs.getPropertyValue('--t2').trim();ctx.textAlign='left';ctx.font='9px monospace';
ctx.fillText(d.rssi+'dBm',lw+bw+4,y+bh-2);
}}
// === HISTORY ===
function loadHistory(){fetch('/api/history').then(r=>r.json()).then(d=>{H=d;let el=document.getElementById('hL');
if(!H.length){el.innerHTML='<div class="empty">No prior session data</div>';return;}
H.sort((a,b)=>b.last-a.last);el.innerHTML='<div style="font-size:11px;color:var(--a2);margin-bottom:8px">'+H.length+' detections from prior session</div>'+H.map(card).join('');
window._hL=1;}).catch(()=>{document.getElementById('hL').innerHTML='<div class="empty">No prior session data</div>';});}
// === PATTERNS ===
function loadPat(){fetch('/api/patterns').then(r=>r.json()).then(p=>{let h='';
h+='<div class="pg"><h3>BLE MAC Prefixes ('+p.ble_macs.length+')</h3><div class="it">'+p.ble_macs.map(m=>'<span>'+m+'</span>').join('')+'</div></div>';
h+='<div class="pg"><h3>WiFi MAC Prefixes ('+p.wifi_macs.length+')</h3><div class="it">'+p.wifi_macs.map(m=>'<span>'+m+'</span>').join('')+'</div></div>';
h+='<div class="pg"><h3>BLE Device Names ('+p.names.length+')</h3><div class="it">'+p.names.map(n=>'<span>'+n+'</span>').join('')+'</div></div>';
h+='<div class="pg"><h3>BLE Manufacturer IDs ('+p.mfr.length+')</h3><div class="it">'+p.mfr.map(m=>'<span>0x'+m.toString(16).toUpperCase().padStart(4,'0')+'</span>').join('')+'</div></div>';
h+='<div class="pg"><h3>Raven UUIDs ('+p.raven.length+')</h3><div class="it">'+p.raven.map(u=>'<span style="font-size:8px">'+u+'</span>').join('')+'</div></div>';
document.getElementById('pC').innerHTML=h;window._pL=1;}).catch(()=>{});}
// === GPS ===
let _gW=null,_gOk=false,_gTried=false,_gErr=0,_gErrTxt='';
// Screen Wake Lock — keep the screen on during GPS capture. Phone screen-sleep suspends the
// page and stops geolocation (the #1 cause of GPS-less detections while walking). Re-acquire
// when the page returns to the foreground. Needs a secure context (same flag GPS already needs).
let _wl=null;
async function acquireWake(){try{if('wakeLock' in navigator){_wl=await navigator.wakeLock.request('screen');_wl.addEventListener('release',function(){_wl=null;});}}catch(e){}}
document.addEventListener('visibilitychange',function(){if(document.visibilityState!=='visible')return;if(_gW!==null&&_wl===null){acquireWake();}if(_gTried&&!_gOk){startGPS();}});
// A restored tab (session restore or bfcache) comes back with a dead geolocation watch: the
// callbacks never fire and the only symptom is a code-3 TIMEOUT. Re-arm on restore.
window.addEventListener('pageshow',function(ev){if(ev.persisted&&_gTried){startGPS();}});
function sendGPS(p){_gOk=true;_gErr=0;_gErrTxt='';let g=document.getElementById('sG');g.textContent='OK';g.style.color='#22c55e';
fetch('/api/gps?lat='+p.coords.latitude+'&lon='+p.coords.longitude+'&acc='+(p.coords.accuracy||0)).catch(()=>{});}
function gpsErr(e){_gOk=false;_gErr=e.code;let g=document.getElementById('sG');
var msg='ERR';if(e.code===1){msg='DENIED';g.style.color='#ef4444';alert('GPS permission denied. On iPhone, GPS requires HTTPS which this device cannot provide. On Android Chrome, tap the lock/info icon in the address bar and allow Location.');}
else if(e.code===2){msg='N/A';g.style.color='#ef4444';}
else if(e.code===3){msg='WAIT';g.style.color='#facc15';}
_gErrTxt=msg;g.textContent=msg;document.getElementById('sGL').textContent='GPS E'+e.code;}
function startGPS(){if(!navigator.geolocation){return false;}
if(_gW!==null){navigator.geolocation.clearWatch(_gW);_gW=null;}
_gErr=0;_gErrTxt='';let g=document.getElementById('sG');g.textContent='...';g.style.color='#facc15';document.getElementById('sGL').textContent='ACQUIRING';
// 60s, not 15s: on an AP with no internet there is no A-GPS assist, so a cold satellite fix
// routinely takes longer than 15s and reports a misleading TIMEOUT.
_gW=navigator.geolocation.watchPosition(sendGPS,gpsErr,{enableHighAccuracy:true,maximumAge:5000,timeout:60000});acquireWake();return true;}
function reqGPS(){if(!navigator.geolocation){alert('GPS not available in this browser.');return;}
if(!window.isSecureContext){alert('GPS requires a secure context (HTTPS). This HTTP page may not get GPS permission.\\n\\nAndroid Chrome: try chrome://flags and enable "Insecure origins treated as secure", add http://192.168.4.1\\n\\niPhone: GPS will not work over HTTP.');}
startGPS();_gTried=true;}
// === INIT ===
document.getElementById('tagline').innerHTML=TAGS[Math.floor(Math.random()*TAGS.length)];
// Apply unconditionally. The old form was if(s!=='purple')setTheme(s), which
// silently assumed the baked :root block stays byte-identical to TH.purple.
// They match today, so this was latent, not live — but the two are edited
// independently and the day they drift, purple stops applying while the
// selector still reads PURPLE, with nothing to point at. Fixed 2026-09-20.
(function(){const s=localStorage.getItem('dantir_theme')||'purple';document.getElementById('thm').value=s;setTheme(s);})();
refresh();setInterval(refresh,2500);
function rLoop(){drawRadar();requestAnimationFrame(rLoop);}rLoop();
</script></body></html>
)rawliteral";

// ============================================================================
// WEB SERVER SETUP
// ============================================================================

static void fySetupServer() {
    // Dashboard
    fyServer.on("/", HTTP_GET, [](AsyncWebServerRequest *r) {
        r->send(200, "text/html", FY_HTML);
    });

    // API: Detection list
    fyServer.on("/api/detections", HTTP_GET, [](AsyncWebServerRequest *r) {
        AsyncResponseStream *resp = r->beginResponseStream("application/json");
        writeDetectionsJSON(resp);
        r->send(resp);
    });

    // API: Stats (includes GPS status)
    fyServer.on("/api/stats", HTTP_GET, [](AsyncWebServerRequest *r) {
        int raven = 0, withGPS = 0;
        if (fyMutex && xSemaphoreTake(fyMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
            for (int i = 0; i < fyDetCount; i++) {
                if (fyDet[i].isRaven) raven++;
                if (fyDet[i].hasGPS) withGPS++;
            }
            xSemaphoreGive(fyMutex);
        }
        const char* gpsSrc = "none";
        if (fyGPSIsHardware && fyHWGPSFix) gpsSrc = "hw";
        else if (fyGPSIsFresh()) gpsSrc = "phone";
        unsigned long upSec = millis() / 1000;
        int upH = upSec / 3600, upM = (upSec % 3600) / 60;
        char buf[512];
        snprintf(buf, sizeof(buf),
            "{\"total\":%d,\"raven\":%d,\"ble\":\"active\",\"wifi\":\"active\","
            "\"wifi_det\":%d,"
            "\"gps_valid\":%s,\"gps_age\":%lu,\"gps_tagged\":%d,"
            "\"gps_src\":\"%s\",\"gps_sats\":%d,\"gps_hw_detected\":%s,"
            "\"device_lat\":%.8f,\"device_lon\":%.8f,"
            "\"batt_pct\":%d,\"batt_v\":%.2f,"
            "\"uptime\":\"%dh%02dm\"}",
            fyDetCount, raven, fyWifiDetCount,
            fyGPSIsFresh() ? "true" : "false",
            fyGPSValid ? (millis() - fyGPSLastUpdate) : 0UL,
            withGPS,
            gpsSrc, fyHWGPSSats,
            fyHWGPSDetected ? "true" : "false",
            fyGPSLat, fyGPSLon,
            fyBatteryPercent, fyBatteryVoltage,
            upH, upM);
        r->send(200, "application/json", buf);
    });

    // API: Receive GPS from phone browser (ignored when hardware GPS has fix)
    fyServer.on("/api/gps", HTTP_GET, [](AsyncWebServerRequest *r) {
        if (fyHWGPSFix) {
            r->send(200, "application/json", "{\"status\":\"ignored\",\"reason\":\"hw_gps_active\"}");
            return;
        }
        if (r->hasParam("lat") && r->hasParam("lon")) {
            fyGPSLat = r->getParam("lat")->value().toDouble();
            fyGPSLon = r->getParam("lon")->value().toDouble();
            fyGPSAcc = r->hasParam("acc") ? r->getParam("acc")->value().toFloat() : 0;
            fyGPSValid = true;
            fyGPSLastUpdate = millis();
            fyGPSIsHardware = false;
            r->send(200, "application/json", "{\"status\":\"ok\"}");
        } else {
            r->send(400, "application/json", "{\"error\":\"lat,lon required\"}");
        }
    });

    // API: Pattern database
    fyServer.on("/api/patterns", HTTP_GET, [](AsyncWebServerRequest *r) {
        AsyncResponseStream *resp = r->beginResponseStream("application/json");
        resp->print("{\"ble_macs\":[");
        for (size_t i = 0; i < sizeof(ble_mac_prefixes)/sizeof(ble_mac_prefixes[0]); i++) {
            if (i > 0) resp->print(",");
            resp->printf("\"%s\"", ble_mac_prefixes[i]);
        }
        resp->print("],\"wifi_macs\":[");
        for (size_t i = 0; i < sizeof(wifi_mac_prefixes)/sizeof(wifi_mac_prefixes[0]); i++) {
            if (i > 0) resp->print(",");
            resp->printf("{\"p\":\"%s\",\"c\":\"%s\"}", wifi_mac_prefixes[i].prefix, wifi_mac_prefixes[i].category);
        }
        resp->print("],\"names\":[");
        for (size_t i = 0; i < sizeof(device_name_entries)/sizeof(device_name_entries[0]); i++) {
            if (i > 0) resp->print(",");
            resp->printf("{\"p\":\"%s\",\"c\":\"%s\"}", device_name_entries[i].pattern, device_name_entries[i].category);
        }
        resp->print("],\"mfr\":[");
        for (size_t i = 0; i < sizeof(ble_manufacturer_entries)/sizeof(ble_manufacturer_entries[0]); i++) {
            if (i > 0) resp->print(",");
            resp->printf("{\"id\":%u,\"c\":\"%s\"}", ble_manufacturer_entries[i].id, ble_manufacturer_entries[i].category);
        }
        resp->print("],\"raven\":[");
        for (size_t i = 0; i < sizeof(raven_service_uuids)/sizeof(raven_service_uuids[0]); i++) {
            if (i > 0) resp->print(",");
            resp->printf("\"%s\"", raven_service_uuids[i]);
        }
        resp->print("]}");
        r->send(resp);
    });

    // API: Export JSON (downloadable file)
    fyServer.on("/api/export/json", HTTP_GET, [](AsyncWebServerRequest *r) {
        AsyncResponseStream *resp = r->beginResponseStream("application/json");
        resp->addHeader("Content-Disposition", "attachment; filename=\"dantir_detections.json\"");
        writeDetectionsJSON(resp);
        r->send(resp);
    });

    // API: Export CSV (downloadable file, includes GPS)
    fyServer.on("/api/export/csv", HTTP_GET, [](AsyncWebServerRequest *r) {
        AsyncResponseStream *resp = r->beginResponseStream("text/csv");
        resp->addHeader("Content-Disposition", "attachment; filename=\"dantir_detections.csv\"");
        resp->println("mac,name,rssi,method,first_seen_ms,last_seen_ms,count,is_raven,raven_fw,latitude,longitude,gps_accuracy,best_rssi,best_latitude,best_longitude,best_gps_accuracy,gps_interp,confidence");
        if (fyMutex && xSemaphoreTake(fyMutex, pdMS_TO_TICKS(200)) == pdTRUE) {
            for (int i = 0; i < fyDetCount; i++) {
                FYDetection& d = fyDet[i];
                // Spreadsheets evaluate a quoted cell that starts with = + - @
                // as a formula. A radio name is attacker-chosen, so prefix
                // those with an apostrophe; quotes, backslashes and control
                // bytes are already gone via fySanitizeName.
                const char c0 = d.name[0];
                const char* csvGuard = (c0 == '=' || c0 == '+' || c0 == '-' || c0 == '@') ? "'" : "";
                resp->printf("\"%s\",\"%s%s\",%d,\"%s\",%lu,%lu,%d,%s,\"%s\"",
                    d.mac, csvGuard, d.name, d.rssi, d.method,
                    d.firstSeen, d.lastSeen, d.count,
                    d.isRaven ? "true" : "false", d.ravenFW);
                if (d.hasGPS) {
                    resp->printf(",%.8f,%.8f,%.1f", d.gpsLat, d.gpsLon, d.gpsAcc);
                } else {
                    resp->print(",,,");
                }
                if (d.hasBestGPS) {
                    resp->printf(",%d,%.8f,%.8f,%.1f", d.bestRSSI, d.bestGPSLat, d.bestGPSLon, d.bestGPSAcc);
                } else {
                    resp->print(",,,,");   // 4 empty: best_rssi + 3 best_gps cols
                }
                resp->printf(",%s,%s\n", (d.hasGPS && d.gpsInterp) ? "true" : "false",
                             d.confidence);
            }
            xSemaphoreGive(fyMutex);
        }
        r->send(resp);
    });

    // API: Export KML (GPS-tagged detections for Google Earth)
    fyServer.on("/api/export/kml", HTTP_GET, [](AsyncWebServerRequest *r) {
        AsyncResponseStream *resp = r->beginResponseStream("application/vnd.google-earth.kml+xml");
        resp->addHeader("Content-Disposition", "attachment; filename=\"dantir_detections.kml\"");
        writeDetectionsKML(resp);
        r->send(resp);
    });

    // API: Prior session history (JSON)
    fyServer.on("/api/history", HTTP_GET, [](AsyncWebServerRequest *r) {
        if (fySpiffsReady && SPIFFS.exists(FY_PREV_FILE)) {
            r->send(SPIFFS, FY_PREV_FILE, "application/json");
        } else {
            r->send(200, "application/json", "[]");
        }
    });

    // API: Download prior session as JSON file
    fyServer.on("/api/history/json", HTTP_GET, [](AsyncWebServerRequest *r) {
        if (fySpiffsReady && SPIFFS.exists(FY_PREV_FILE)) {
            AsyncWebServerResponse *resp = r->beginResponse(SPIFFS, FY_PREV_FILE, "application/json");
            resp->addHeader("Content-Disposition", "attachment; filename=\"dantir_prev_session.json\"");
            r->send(resp);
        } else {
            r->send(404, "application/json", "{\"error\":\"no prior session\"}");
        }
    });

    // API: Download prior session as KML (reads JSON from SPIFFS, converts)
    fyServer.on("/api/history/kml", HTTP_GET, [](AsyncWebServerRequest *r) {
        if (!fySpiffsReady || !SPIFFS.exists(FY_PREV_FILE)) {
            r->send(404, "application/json", "{\"error\":\"no prior session\"}");
            return;
        }
        File f = SPIFFS.open(FY_PREV_FILE, "r");
        if (!f) { r->send(500, "text/plain", "read error"); return; }
        String content = f.readString();
        f.close();
        if (content.length() == 0) {
            r->send(404, "application/json", "{\"error\":\"prior session empty\"}");
            return;
        }
        AsyncResponseStream *resp = r->beginResponseStream("application/vnd.google-earth.kml+xml");
        resp->addHeader("Content-Disposition", "attachment; filename=\"dantir_prev_session.kml\"");
        resp->print("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    "<kml xmlns=\"http://www.opengis.net/kml/2.2\">\n<Document>\n"
                    "<name>Dantir Prior Session</name>\n"
                    "<description>Surveillance device detections from prior session</description>\n"
                    "<Style id=\"det\"><IconStyle><color>ff4489ec</color>"
                    "<scale>1.0</scale></IconStyle></Style>\n"
                    "<Style id=\"raven\"><IconStyle><color>ff4444ef</color>"
                    "<scale>1.2</scale></IconStyle></Style>\n");
        // Parse JSON array and emit placemarks
        JsonDocument doc;
        DeserializationError err = deserializeJson(doc, content);
        if (!err && doc.is<JsonArray>()) {
            int placed = 0;
            for (JsonObject d : doc.as<JsonArray>()) {
                // Prefer best_gps (peak RSSI = closest approach), fall back to first-seen gps
                JsonObject bgps = d["best_gps"];
                JsonObject gps = d["gps"];
                JsonObject pinGPS = (bgps && bgps["lat"]) ? bgps : gps;
                if (!pinGPS || !pinGPS["lat"]) continue;
                bool isRaven = d["raven"] | false;
                resp->printf("<Placemark><name>%s</name>\n", d["mac"] | "?");
                resp->printf("<styleUrl>#%s</styleUrl>\n", isRaven ? "raven" : "det");
                resp->print("<description><![CDATA[");
                if (d["name"].is<const char*>() && strlen(d["name"] | "") > 0) {
                    // This writer reads the saved file directly, not fyDet, so
                    // it sanitizes for itself: the description is a CDATA block
                    // Google Earth renders as HTML.
                    char safeName[48];
                    fySanitizeName(safeName, sizeof(safeName), d["name"] | "");
                    resp->printf("<b>Name:</b> %s<br/>", safeName);
                }
                resp->printf("<b>Method:</b> %s<br/><b>RSSI:</b> %d<br/>",
                    d["method"] | "?", d["rssi"] | 0);
                if (d["best_rssi"])
                    resp->printf("<b>Best RSSI:</b> %d<br/>", d["best_rssi"] | 0);
                resp->printf("<b>Count:</b> %d", d["count"] | 1);
                if (isRaven && d["fw"].is<const char*>())
                    resp->printf("<br/><b>Raven FW:</b> %s", d["fw"] | "");
                resp->print("]]></description>\n");
                resp->printf("<Point><coordinates>%.8f,%.8f,0</coordinates></Point>\n",
                    (double)(pinGPS["lon"] | 0.0), (double)(pinGPS["lat"] | 0.0));
                resp->print("</Placemark>\n");
                placed++;
            }
            printf("[DANTIR] Prior session KML: %d placemarks\n", placed);
        } else {
            printf("[DANTIR] Prior session KML: JSON parse failed\n");
        }
        resp->print("</Document>\n</kml>");
        r->send(resp);
    });

    // API: Clear all detections (saves current session first)
    fyServer.on("/api/clear", HTTP_GET, [](AsyncWebServerRequest *r) {
        fySaveSession();  // Persist before clearing
        if (fyMutex && xSemaphoreTake(fyMutex, pdMS_TO_TICKS(200)) == pdTRUE) {
            fyDetCount = 0;
            memset(fyDet, 0, sizeof(fyDet));
            fyClearAlertedCategories();
            fyDeviceInRange = false;
            xSemaphoreGive(fyMutex);
        }
        r->send(200, "application/json", "{\"status\":\"cleared\"}");
        printf("[DANTIR] All detections cleared (session saved)\n");
    });

    fyServer.begin();
    printf("[DANTIR] Web server started on port 80\n");
}

// ============================================================================
// MAIN FUNCTIONS
// ============================================================================

void setup() {
    Serial.begin(115200);
    delay(500);

    // Read buzzer setting from OUI-SPY NVS
    Preferences bzP;
    bzP.begin("ouispy-bz", true);
    fyBuzzerOn = bzP.getBool("on", true);
    bzP.end();

    pinMode(BUZZER_PIN, OUTPUT);
    digitalWrite(BUZZER_PIN, LOW);

    // Init NeoPixel
    fyPixel.begin();
    fyPixel.setBrightness(FY_NEOPIXEL_BRIGHTNESS);
    fyPixel.clear();
    fyPixel.show();
    // Test flash: pink -> purple
    fyPixel.setPixelColor(0, fyPixel.Color(236, 72, 153));  // pink #ec4899
    fyPixel.show();
    delay(500);
    fyPixel.setPixelColor(0, fyPixel.Color(139, 92, 246));  // purple #8b5cf6
    fyPixel.show();
    delay(500);
    fyPixel.clear();
    fyPixel.show();

    fyMutex = xSemaphoreCreateMutex();

    // Init hardware GPS UART (Seeed L76K on D6/D7)
    fyGPSSerial.begin(GPS_BAUD, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);

    // Init SPIFFS for session persistence
    if (SPIFFS.begin(true)) {
        fySpiffsReady = true;
        printf("[DANTIR] SPIFFS ready\n");
        // Promote last session to prev_session (backup), then restore into live array
        // This means: prev_session always has a backup, AND dashboard keeps all detections
        fyPromotePrevSession();
        fyRestoreSession();
    } else {
        printf("[DANTIR] SPIFFS init failed - no persistence\n");
    }

    // Initialize battery monitoring
    fyReadBattery();

    printf("\n========================================\n");
    printf("  DANTIR Surveillance Counter-Watcher\n");
    printf("  Buzzer: %s\n", fyBuzzerOn ? "ON" : "OFF");
    printf("  GPS: auto-detect (L76K on D6/D7)\n");
    printf("  Battery ADC: %s\n", BATTERY_ADC_PIN >= 0 ? "enabled" : "disabled (no voltage divider)");
    printf("========================================\n");

    // Init BLE scanner FIRST -- start scanning immediately
    NimBLEDevice::init("");
    fyBLEScan = NimBLEDevice::getScan();
    fyBLEScan->setAdvertisedDeviceCallbacks(new FYBLECallbacks());
    fyBLEScan->setActiveScan(true);
    fyBLEScan->setInterval(100);
    fyBLEScan->setWindow(99);

    // Kick off the first scan right away
    fyBLEScan->start(BLE_SCAN_DURATION, false);
    fyLastBleScan = millis();
    printf("[DANTIR] BLE scanning ACTIVE\n");

    // Crow calls play WHILE BLE is already scanning
    fyBootBeep();

    // Start WiFi AP (no need to connect to anything -- AP only)
    WiFi.mode(WIFI_AP);
    delay(100);
    WiFi.softAP(FY_AP_SSID, FY_AP_PASS);
    printf("[DANTIR] AP: %s / %s\n", FY_AP_SSID, FY_AP_PASS);
    printf("[DANTIR] IP: %s\n", WiFi.softAPIP().toString().c_str());

    // Enable WiFi promiscuous mode — captures management frames on AP channel
    // Probe requests from devices scanning other channels are still caught
    // because WiFi devices sweep all channels during active scanning
    esp_wifi_set_promiscuous_rx_cb(fyWifiPromiscuousCB);
    esp_wifi_set_promiscuous(true);
    printf("[DANTIR] WiFi promiscuous mode ACTIVE (ch %d)\n", WiFi.channel());

    // Start web dashboard
    fySetupServer();

    printf("[DANTIR] BLE: %d OUI prefixes, %d name patterns, %d mfr IDs, %d Raven UUIDs\n",
        (int)(sizeof(ble_mac_prefixes)/sizeof(ble_mac_prefixes[0])),
        (int)(sizeof(device_name_entries)/sizeof(device_name_entries[0])),
        (int)(sizeof(ble_manufacturer_entries)/sizeof(ble_manufacturer_entries[0])),
        (int)(sizeof(raven_service_uuids)/sizeof(raven_service_uuids[0])));
    printf("[DANTIR] WiFi: %d OUI prefixes (promiscuous mode ACTIVE)\n",
        (int)(sizeof(wifi_mac_prefixes)/sizeof(wifi_mac_prefixes[0])));
    printf("[DANTIR] Dashboard: http://192.168.4.1\n");
    printf("[DANTIR] Ready - BLE scanning + WiFi promiscuous + AP dashboard\n\n");
}

void loop() {
    fyProcessHardwareGPS();
    fyUpdatePixel();
    fyReadBattery();

    // BLE scanning cycle
    if (millis() - fyLastBleScan >= BLE_SCAN_INTERVAL && !fyBLEScan->isScanning()) {
        fyBLEScan->start(BLE_SCAN_DURATION, false);
        fyLastBleScan = millis();
    }

    if (!fyBLEScan->isScanning() && millis() - fyLastBleScan > BLE_SCAN_DURATION * 1000) {
        fyBLEScan->clearResults();
    }

    // WiFi detection alert (deferred from promiscuous callback — can't buzz there)
    if (fyWifiAlertPending) {
        fyWifiAlertPending = false;
        const char* wc = (const char*)fyWifiAlertCat;
        if (!fyCategoryAlerted(wc)) {
            fyMarkCategoryAlerted(wc);
            fyDetectBeep(wc, (const char*)fyWifiAlertConf);
            fyLastHB = millis();
        }
    }

    // Heartbeat tracking — runs on clean 10s cadence, independent of re-detections
    if (fyDeviceInRange) {
        if (millis() - fyLastHB >= 10000) {
            fyHeartbeat();
            fyLastHB = millis();
        }
        if (millis() - fyLastDetTime >= 30000) {
            printf("[DANTIR] Device out of range - stopping heartbeat\n");
            fyDeviceInRange = false;
            fyClearAlertedCategories();
        }
    }

    // Auto-save session to SPIFFS every 15s if detections changed
    // Also triggers an early save 5s after first detection to minimize loss on power-cycle
    if (fySpiffsReady && millis() - fyLastSave >= FY_SAVE_INTERVAL) {
        if (fyDetCount > 0 && fyDetCount != fyLastSaveCount) {
            fySaveSession();
        }
        fyLastSave = millis();
    } else if (fySpiffsReady && fyDetCount > 0 && fyLastSaveCount == 0 &&
               millis() - fyLastSave >= 5000) {
        // Quick first-save: persist within 5s of first detection
        fySaveSession();
        fyLastSave = millis();
    }

    delay(100);
}
