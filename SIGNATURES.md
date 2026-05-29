# Signature Provenance

Dantir detects devices by matching publicly broadcast radio signatures —
Bluetooth MAC OUI prefixes, advertised device-name patterns, BLE manufacturer
company IDs, service UUIDs, and WiFi management-frame source OUIs. None of this
data is proprietary; it comes from public registries and open community
research.

## Sources & credit

- **[OUI Spy Unified Blue](https://github.com/colonelpanichacks/oui-spy-unified-blue)**
  by **colonelpanichacks** ([colonelpanic.tech](https://colonelpanic.tech/)) —
  the upstream project Dantir is forked from, and the origin of the core
  detection engine and much of the BLE signature set.
- **[flock-you](https://github.com/wgreenberg/flock-you)** by **wgreenberg** —
  BLE detection research on Flock Safety hardware.
- **[deflock.me](https://deflock.me/)** — community-maintained, crowd-sourced
  catalog of surveillance-device signatures (ALPR cameras and related gear).
- **IEEE MA-L (OUI) registry** — public assignments mapping MAC prefixes to
  manufacturers.
- **Bluetooth SIG company identifiers** — manufacturer company IDs carried in
  BLE advertisements, published by the Bluetooth SIG.

## Nature of the data

These signatures describe what publicly observable radio emissions *look like* —
facts about how devices identify themselves over the air, compiled for
interoperability and security-research purposes. A detection indicates only
that a matching broadcast was observed nearby. It is **not** proof of the
presence, ownership, or operation of any specific device or party.
