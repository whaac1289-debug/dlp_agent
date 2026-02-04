# dlp_agent

A minimal Windows DLP (Data Loss Prevention) endpoint agent scaffold written in modern C++ (MSYS2 UCRT64). It provides a compact, compilable foundation for endpoint telemetry, device control, and policy decisions that can be hardened for enterprise use.

## Feature highlights
- **USB device monitoring**: Enumerates logical drives/removable devices, captures volume identifiers, and supports USB serial allowlists.
- **File activity monitoring**: Watches `C:\Users` and removable drives via `ReadDirectoryChangesW` and captures create/write/delete/rename events.
- **Policy checks**: Extension filters, size thresholds, removable-drive alerting, keyword scanning, and optional SHA-256 hashing.
- **Rule engine + PII detection**: Regex/keyword/hash rules plus PII detectors (email, phone, passport/ID, credit card, IBAN, configurable national IDs).
- **Event storage**: Structured events written to SQLite (`dlp_agent.db`) and logs (`dlp_agent.log`).
- **Telemetry**: Periodic heartbeat POSTs to a configurable server URL using libcurl.

## Repository map
- [config.json](config.json) — runtime configuration (server_url, extension_filter, size_threshold, usb_allow_serials, content_keywords, max_scan_bytes, hash_max_bytes, block_on_match, alert_on_removable, rules_config, national_id_patterns).
- [rules.json](rules.json) — example rule pack for the rule engine (regex/keyword/hash rules).
- [src/main.cpp](src/main.cpp) — program entry and worker threads startup.
- [src/file_watch.cpp](src/file_watch.cpp) — file watcher implementation using ReadDirectoryChangesW.
- [src/usb_scan.cpp](src/usb_scan.cpp) — USB / drive enumerator.
- [src/api.cpp](src/api.cpp) — libcurl-based API sender (heartbeat).
- [src/log.cpp](src/log.cpp), [src/sqlite_store.cpp](src/sqlite_store.cpp) — logging + SQLite storage.
- [load.py](load.py) — helper to inspect `dlp_agent.db` (list tables, show recent rows, export CSV).

## Build (MSYS2 UCRT64)

1. Open MSYS2 UCRT64 shell.
2. Install required packages if missing:

```bash
pacman -Syu
pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-make \
    mingw-w64-ucrt-x86_64-libcurl mingw-w64-ucrt-x86_64-sqlite3 \
    mingw-w64-ucrt-x86_64-wbemidl mingw-w64-ucrt-x86_64-crypt32
```

3. Build:

```bash
cd /d/proj/dlp_agent
make clean
make -j1
```

## Run

PowerShell (interactive):

```powershell
.\dlp_agent.exe
# press 'q' then Enter to quit
```

PowerShell (redirect output):

```powershell
.\dlp_agent.exe *> run_all.txt
Get-Content run_all.txt -Wait
```

## Configuration notes
Edit [config.json](config.json) to change `server_url`, `extension_filter`, `size_threshold`, or the USB allowlist. Additional DLP controls:

- `content_keywords`: case-insensitive keywords scanned from the first `max_scan_bytes` of matching files.
- `max_scan_bytes`: maximum bytes to scan for keywords.
- `hash_max_bytes`: maximum file size to hash (SHA-256).
- `block_on_match`: if `true`, keyword hits are marked as `BLOCK` (otherwise `ALERT`).
- `alert_on_removable`: if `true`, file events on removable drives are flagged.
- `rules_config`: path to a JSON/YAML rule file for the rule engine.
- `national_id_patterns`: regex patterns for national IDs (used by PII detector).

## Operational notes
- This repository is a scaffold intended for extension: service installation, robust error handling, secure transport (TLS pinning/mTLS), batching/backpressure, and stronger WMI parsing should be added for production.
- Avoid running as SYSTEM without additional hardening and auditing.
