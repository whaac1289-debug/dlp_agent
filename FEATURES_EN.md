# dlp_agent — Features (English)

Overview
- Long-running Windows endpoint agent (service-style loop) written in modern C++.
- Designed as a modular scaffold to demonstrate core DLP responsibilities.

Core capabilities
- USB Device Monitoring
  - Enumerates logical drives and removable devices.
  - Extracts basic volume serial information and records device events.
  - Policy allowlist by serial via `config.json`.

- File Activity Monitoring
  - Watches `C:\Users` and removable drives using `ReadDirectoryChangesW`.
  - Emits events for create/write/delete/rename operations.
  - Filters events by `extension_filter` in `config.json` (case-insensitive).
  - Ignores temporary files and Office lockfiles (starts with `~$`).

- Event Pipeline & Storage
  - Simple event emitter that normalizes and stores events in SQLite (`dlp_agent.db`).
  - Dual logging: writes to `dlp_agent.log` and the `logs` table in SQLite.

- API Client
  - Sends JSON POST batches (heartbeat) to `server_url` using libcurl.
  - Retries/errors logged locally; a retry queue table is scaffolded in SQLite.

- Hashing
  - SHA-256 implemented using Windows CNG (`bcrypt`).

Configuration
- `config.json` keys:
  - `server_url` — API endpoint for event batches
  - `extension_filter` — array of file extensions (e.g., [".txt", ".docx"]) to monitor
  - `size_threshold` — numeric size filter (bytes)
  - `usb_allow_serials` — array of allowed USB serial strings

Limitations and Notes
- This project is a scaffold: production hardening, service installation, permissions management, robust WMI parsing, batching, and secure transport should be added before deployment.
- Avoid running as SYSTEM until you add proper security and error handling.

Where to change behavior
- `config.json` to change filters and server URL.
- `src/file_watch.cpp` and `src/usb_scan.cpp` contain the watcher and enumerator implementations.
