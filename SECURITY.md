# Security Policy

## What Dantir is (and isn't)

Dantir is a **passive radio receiver**. It listens for Bluetooth Low Energy
advertisements and WiFi management frames (beacons and probe requests) that
devices already broadcast openly to anyone in range — the same packets your
phone's Bluetooth and WiFi scanners receive — and matches those public
signatures against known surveillance-device patterns.

Dantir does **not**:

- transmit anything at the devices it detects;
- connect to, authenticate against, or query any third-party device;
- jam, spoof, deauthenticate, or otherwise interfere with any radio signal;
- capture the *content* of any communication — only broadcast metadata
  (MAC address, advertised name, manufacturer ID, service UUID).

The device runs its own local WiFi access point solely to serve its dashboard.

## Reporting a vulnerability

If you find a security issue in the firmware or dashboard, please report it
privately rather than opening a public issue:

- Open a **GitHub security advisory** on this repository, or
- Contact the maintainer via the profile linked on the repository.

Please include reproduction steps and the firmware version/commit. We aim to
acknowledge reports promptly and will credit reporters who wish to be named.

## Operating it responsibly

- Change the default dashboard credentials (`FY_AP_SSID` / `FY_AP_PASS`) before
  any real-world use — the defaults are public.
- Detection is signature-based and is **not proof** of any specific device.
- Use it lawfully in your jurisdiction. Detect and document — never interfere.
