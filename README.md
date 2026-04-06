# Aegis Nexus Pro — Smart Hotspot Controller

> A Flutter-based Android application that turns your phone into an intelligent, manageable Wi-Fi gateway — with real-time monitoring, per-client bandwidth throttling, data quotas, and domain-level firewall controls. No root required.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Key Concepts Explained](#key-concepts-explained)
- [Features](#features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation & Setup](#installation--setup)
- [How to Use](#how-to-use)
- [Testing Protocol](#testing-protocol)
- [Suggested Improvements](#suggested-improvements)
- [Known Limitations](#known-limitations)
- [Dependencies](#dependencies)

---

## Overview

**Aegis Nexus Pro** is a smart hotspot management app for Android. When your phone shares its mobile data as a Wi-Fi hotspot, connected devices (laptops, tablets, other phones) typically get unrestricted access. This app changes that by inserting a **proxy server** between those client devices and the internet — letting you see exactly who is using what, and enforce rules in real time.

The app works without root access by leveraging an HTTP/HTTPS forwarding proxy server written entirely in pure Dart.

---

## Architecture

```
[Client Device]
      │
      │  (Manual proxy: 192.168.43.1:8080)
      ▼
[ProxyServer — Dart TCP Socket, port 8080]
      │
      ├── SecurityRulesManager  ←  Domain blocklist check (DPI)
      ├── ClientManager          ←  Per-client stats & control state
      ├── AllocationEngine       ←  Auto bandwidth distribution
      │
      ▼
[Real Internet — Cell Tower]
```

All traffic from a client device is forced through the Flutter app's Dart runtime before it reaches the internet. This is what enables monitoring, throttling, and blocking — entirely in user-space, with no kernel modifications.

---

## Key Concepts Explained

### Why a Proxy Server Instead of VpnService?
Android's `VpnService` API intercepts only traffic originating from the device itself. It **cannot** intercept traffic from other devices tethered to the hotspot without root access and `iptables` rules. This app solves that by running an HTTP/TCP forwarding proxy on port `8080`. Client devices are manually configured to route all traffic through this proxy, giving the app full visibility.

### HTTP CONNECT Tunneling (HTTPS Support)
When a client browser tries to open an HTTPS site, it first sends an unencrypted `CONNECT facebook.com:443 HTTP/1.1` header to the proxy. The proxy reads this plaintext header to learn the destination host, checks it against the blocklist, and either:
- **Destroys the connection** (if blocked), or
- **Replies with `200 Connection Established`** and sets up a transparent TCP tunnel between the client and the real server.

The actual TLS/SSL encrypted data passes through the tunnel without being decrypted — the proxy only sees the destination hostname.

### Deep Packet Inspection (DPI) for Domain Blocking
Despite the name, this is a lightweight form of DPI. The proxy inspects the first unencrypted bytes of each connection to extract the destination hostname from the `Host:` header (HTTP) or the `CONNECT` line (HTTPS). It never decrypts TLS traffic. The domain is checked against a `Set<String>` in `SecurityRulesManager`, and the connection is killed before the TLS handshake completes if there is a match.

### Bandwidth Throttling via Artificial Delay
The throttle system works by introducing calculated delays into the socket pipe. When a chunk of data arrives for a throttled client:

1. The size of the data chunk (in bytes) is known.
2. The configured limit (e.g., 1024 Kbps = 128,000 bytes/sec) is known.
3. The engine calculates: `delay_ms = (chunk_bytes * 1000) / (limit_bytes_per_sec)`
4. `Future.delayed()` pauses the socket writer for exactly that duration before forwarding the chunk.

This is a **token bucket** approximation — it does not drop packets; it slows the stream down proportionally, which causes the client's browser or video player to buffer naturally.

### Data Quota / Kill-Switch
Each `ClientDevice` tracks cumulative `bytesDownloaded` and `bytesUploaded`. On every data chunk, the proxy checks `client.isLimitExceeded()`. Once the quota is hit, all subsequent socket pipes for that client are destroyed — effectively cutting their internet access until the quota is reset manually.

### AllocationEngine (Auto Mode)
Runs on a 10-second timer. When auto mode is enabled, it divides the configured `maxBandwidthKbps` (default: 10,000 Kbps / 10 Mbps) equally among all active, unblocked, non-quota-exceeded clients — but only for clients that do not already have a manual limit set.

### ClientManager (State Management)
A `ChangeNotifier` that acts as the single source of truth for all client state. It uses a debounced notify mechanism (`_scheduleNotify` with an 800ms timer) to avoid excessive UI rebuilds during high-traffic periods where stats update many times per second.

### Provider Pattern
The app uses the `provider` package. `ClientManager` is injected at the root via `ChangeNotifierProvider` and consumed anywhere in the widget tree via `Provider.of<ClientManager>(context)`. This means the `DashboardScreen` reactively rebuilds when client data changes.

---

## Features

| Feature | Description |
|---|---|
| **Live Throughput Graph** | Real-time KB/s line chart updated every second using `fl_chart` |
| **Traffic Distribution Pie Chart** | Visual breakdown of bandwidth usage per connected client |
| **Per-Client Stats** | Individual download and upload totals per device IP |
| **Block / Unblock Client** | Instantly cuts or restores a specific device's internet access |
| **Bandwidth Throttle** | Limits a client to 1 Mbps download and upload |
| **Data Quota** | Sets a 50 MB total data cap; access is killed when exceeded |
| **Domain Firewall** | Blocks any domain network-wide via hostname inspection |
| **Gateway Setup Card** | Displays the host IP and port for easy client configuration |
| **Dark Theme UI** | Polished dark UI with a deep navy/slate color palette |

---

## Project Structure

```
lib/
├── main.dart                  # App entry point, UI, DashboardScreen widget
├── models/
│   └── client_device.dart     # Data model for a connected device
├── providers/
│   └── client_manager.dart    # State management (ChangeNotifier)
└── services/
    ├── proxy_server.dart      # TCP proxy server (HTTP + CONNECT tunneling)
    ├── allocation_engine.dart # Auto bandwidth distribution scheduler
    └── security_rules.dart    # Domain blocklist manager

android/
└── app/src/main/
    └── AndroidManifest.xml    # INTERNET, WIFI, FOREGROUND_SERVICE permissions
```

---

## Prerequisites

- **Flutter SDK** `^3.9.2` (or compatible)
- **Dart SDK** `^3.9.2`
- An **Android** device (physical hardware required — the proxy binds to a real network interface)
- **USB Debugging** enabled on the Android device

> iOS is not supported. The proxy server depends on Android's hotspot network interface.

---

## Installation & Setup

### 1. Enable USB Debugging on your Android phone

1. Go to **Settings → About Phone**
2. Tap **Build Number** 7 times until "You are now a developer!" appears
3. Go to **Settings → System → Developer Options**
4. Enable **USB Debugging**
5. Connect your phone via USB and tap **Allow** on the prompt

### 2. Clone and run

```bash
git clone https://github.com/your-username/smart_hotspot_flutter.git
cd smart_hotspot_flutter
flutter pub get
flutter run --release
```

> Use `--release` for best performance. Debug builds can cause noticeable latency in the proxy pipe.

### 3. Enable Mobile Hotspot on the phone

Go to **Settings → Network → Hotspot** and turn it on before starting the proxy.

---

## How to Use

### On the Host Phone (the phone running the app)

1. Open the **Aegis Nexus Pro** app
2. Tap the **START** button (top-right) — it turns red and shows **STOP**
3. A **Gateway Setup** card appears showing the IP (e.g., `192.168.43.1`) and port `8080`

### On the Client Device (phone, laptop, tablet connecting to the hotspot)

1. Connect to the host phone's Wi-Fi hotspot
2. Open advanced Wi-Fi settings for that network connection
3. Set **Proxy → Manual**
4. Enter **Proxy hostname**: the IP shown in the app (typically `192.168.43.1`)
5. Enter **Proxy port**: `8080`
6. Save

### Controlling clients

Once a client device browses the internet, it appears in the **Current Subscriptions** list. Expand any client tile to:

- **STOP / FREE** — Block or unblock the client entirely
- **THROTTLE / UNLIMIT** — Restrict to 1 Mbps or restore full speed
- **50MB / RESET** — Set a 50 MB data quota or clear it

To block a domain across all clients, tap the **shield icon** in the **Live Throughput** header and enter a domain (e.g., `facebook.com`).

---

## Testing Protocol

**Phase 1 — Host Gateway:** Start the app, confirm START button activates and Gateway Setup card appears.

**Phase 2 — Client Bridge:** Connect a second device to the hotspot and configure the manual proxy.

**Phase 3 — Real-Time Monitoring:** Browse on the client device and confirm the throughput graph spikes, the pie chart updates, and the client tile appears.

**Phase 4 — Throttle:** Tap THROTTLE on a client and confirm videos buffer; tap UNLIMIT and confirm speed restores.

**Phase 5 — Firewall:** Block `facebook.com` via the shield icon and confirm Facebook fails to load on the client while other sites work.

**Phase 6 — Data Quota:** Set a 50 MB quota and confirm the client's internet stops after reaching the cap; tap RESET to restore.

---

## Suggested Improvements

### Critical / Functional

1. **Foreground Service for proxy persistence** — Currently the proxy server runs on the main Flutter isolate. Android will kill it when the app is backgrounded. Wrapping it in a `ForegroundService` (with a persistent notification) via a native Android plugin or `flutter_foreground_task` is essential for real-world use.

2. **Configurable throttle value** — The throttle is hardcoded to 1024 Kbps. A slider or text input per client would make this far more useful.

3. **Configurable data quota** — The quota is hardcoded to 50 MB. It should be user-settable.

4. **Persist blocked domains** — The `SecurityRulesManager` uses an in-memory `Set`. All blocked domains are lost when the app restarts. Use `shared_preferences` to persist them.

5. **Show blocked domains list** — There is currently no UI to view or remove blocked domains once added.

6. **Auto-detect hotspot IP more reliably** — The IP detection logic returns the first non-loopback IPv4 address. On some devices the hotspot interface (e.g., `ap0`) may not always be the first result. Filtering by interface name or checking for the `192.168.43.x` subnet would be more reliable.

### UX / UI

7. **Device name resolution** — Clients are shown by raw IP (e.g., `192.168.43.x`). Attempting mDNS/DNS reverse lookup or allowing the user to assign friendly names would greatly improve readability.

8. **AllocationEngine auto mode toggle** — The `AllocationEngine` supports auto mode (`toggleAutoMode`) but there is no UI switch exposed for it. Adding a toggle in settings would complete this feature.

9. **Session history / logging** — No data is persisted between proxy sessions. A simple log of session totals per IP would be valuable.

10. **Onboarding flow** — First-time users need to know to configure the proxy on client devices. A one-time guided setup dialog would reduce friction significantly.

### Code Quality

11. **Split `main.dart`** — At ~450 lines, `main.dart` contains the entire UI. Extracting widgets like `_buildClientExpandableTile`, `_buildLineChartCard`, and `_buildDistributionPieChart` into separate files under `lib/widgets/` would improve maintainability.

12. **Replace `print()` with a proper logger** — The proxy server uses `print()` for error logging. Using the `logging` package or `flutter/foundation.dart`'s `debugPrint` and a structured logger would be better practice.

13. **Add unit tests for core logic** — `AllocationEngine`, `SecurityRulesManager`, and `ClientDevice.isLimitExceeded()` are all pure Dart and straightforward to unit test. The existing `widget_test.dart` is the default Flutter placeholder.

14. **Handle IPv6** — The proxy server binds on `0.0.0.0` (IPv4 only). While Android hotspots typically assign IPv4, adding IPv6 support (`InternetAddress.anyIPv6`) would be more robust.

---

## Known Limitations

- **Android only** — iOS does not expose network interfaces in the same way and does not support this proxy approach.
- **Manual proxy configuration required** — There is no way to force connected clients to use the proxy automatically without root access or a DHCP-based approach. Clients must set it manually.
- **HTTPS domain blocking only** — Blocking works by reading the `CONNECT` header or `Host:` header. Traffic that bypasses the proxy (e.g., using a different DNS resolver or VPN on the client) cannot be blocked.
- **No HTTPS inspection** — The proxy tunnels encrypted TLS traffic transparently. It cannot inspect the content of HTTPS sessions.
- **App backgrounding kills the proxy** — Without a Foreground Service, Android may kill the proxy process when the screen turns off.

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `flutter` | SDK | UI framework |
| `provider` | `^6.1.5` | State management (ChangeNotifier pattern) |
| `fl_chart` | `^1.2.0` | Line chart and pie chart rendering |
| `cupertino_icons` | `^1.0.8` | iOS-style icon set |

---

## License

This project is private and not published to pub.dev (`publish_to: none`). Add a `LICENSE` file if you intend to open-source it.
