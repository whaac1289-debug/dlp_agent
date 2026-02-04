# dlp_agent — Feature Overview (English)

## Executive summary
`dlp_agent` is a Windows endpoint DLP (Data Loss Prevention) agent scaffold written in modern C++. It provides a clean, modular base for collecting endpoint events, applying policy checks, and forwarding telemetry to a central service. The codebase is intentionally compact, making it suitable as a starting point for enterprise hardening.

## Core capabilities
### 1) USB device monitoring
- Enumerates logical drives and removable devices.
- Captures volume identifiers (including serial information) and device events.
- Enforces a USB serial allowlist via `config.json`.

### 2) File activity monitoring
- Uses `ReadDirectoryChangesW` to watch `C:\Users` and removable drives.
- Emits create/write/delete/rename events.
- Filters by `extension_filter` from `config.json` (case-insensitive).
- Ignores common temporary files and Office lock files (prefix `~$`).

### 3) Policy checks
- Size thresholds and removable-drive alerting.
- Content keyword scanning with configurable byte limits.
- Optional SHA-256 hashing for small files.

### 4) Rule engine + PII detection
- Regex/keyword/hash rule types for flexible policy enforcement.
- PII detectors for email, phone, passport/ID, credit card, IBAN, and configurable national IDs.

### 5) Event pipeline & storage
- Normalizes file/device events into SQLite (`dlp_agent.db`).
- Dual logging to `dlp_agent.log` and a SQLite `logs` table.
- Stores structured events in `events_v2` and `device_events` tables.

### 6) Telemetry
- Sends secure telemetry batches to `telemetry_endpoint` via libcurl.
- Logs retryable failures locally for troubleshooting.

## Configuration surface
The agent behavior is primarily controlled via `config.json`:
- `telemetry_endpoint` — API endpoint for secure telemetry batches.
- `extension_filter` — array of file extensions to monitor (e.g., [".txt", ".docx"]).
- `size_threshold` — numeric size filter (bytes).
- `usb_allow_serials` — allowlisted USB serial strings.
- `content_keywords`, `max_scan_bytes`, `hash_max_bytes` — content scanning and hashing limits.
- `block_on_match`, `alert_on_removable` — policy decision controls.
- `rules_config`, `national_id_patterns` — rule engine and national ID patterns.

## Operational notes & limitations
- This repository is a foundation. Production deployment should add service installation, strict permissions, robust WMI parsing, stronger error handling, secure transport (TLS pinning/mTLS), and backpressure-safe batching.
- Avoid running as SYSTEM without additional hardening and auditing.

## Where to customize
- `config.json` for policy filters and server endpoints.
- `src/file_watch.cpp` and `src/usb_scan.cpp` for watcher/enumerator logic.
- `rules.json` for example policy rules.
