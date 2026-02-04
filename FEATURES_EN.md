# dlp_agent — Feature Overview (English)

## Executive Summary
`dlp_agent` is a Windows endpoint DLP (Data Loss Prevention) agent written in modern C++. It provides a modular foundation for collecting endpoint events, enforcing basic device controls, and forwarding telemetry to a central service. The project is designed as a scaffold that can be hardened for enterprise use.

## Core Capabilities
### 1) USB Device Monitoring
- Enumerates logical drives and removable devices.
- Captures basic volume identifiers (including serial information) and device events.
- Enforces a serial allowlist via `config.json`.

### 2) File Activity Monitoring
- Uses `ReadDirectoryChangesW` to watch `C:\Users` and removable drives.
- Emits create/write/delete/rename events.
- Filters by `extension_filter` from `config.json` (case-insensitive).
- Ignores common temporary files and Office lock files (prefix `~$`).

### 3) Event Pipeline & Storage
- Normalizes events and stores them in SQLite (`dlp_agent.db`).
- Dual logging: file-based logs (`dlp_agent.log`) plus a `logs` table in SQLite.

### 4) API Client
- Sends batched JSON POST requests (heartbeat) to `server_url` using libcurl.
- Logs retryable failures locally and includes a scaffolded retry queue table in SQLite.

### 5) Cryptographic Hashing
- Implements SHA-256 via Windows CNG (`bcrypt`).

## Configuration Surface
The agent behavior is primarily controlled via `config.json`:
- `server_url` — API endpoint for event batches.
- `extension_filter` — array of file extensions to monitor (e.g., [".txt", ".docx"]).
- `size_threshold` — numeric size filter (bytes).
- `usb_allow_serials` — allowlisted USB serial strings.

## Operational Notes & Limitations
- This repository is a foundation. Production deployment should add service installation, strict permissions, robust WMI parsing, stronger error handling, secure transport (TLS pinning / mTLS), and backpressure-safe batching.
- Avoid running as SYSTEM without additional hardening and auditing.

## Where to Customize
- `config.json` for policy filters and server endpoints.
- `src/file_watch.cpp` and `src/usb_scan.cpp` for watcher/enumerator logic.
