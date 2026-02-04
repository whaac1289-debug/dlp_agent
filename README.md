# dlp_agent

A minimal Windows DLP (Data Loss Prevention) endpoint agent scaffold written in modern C++ (MSYS2 UCRT64). It provides a compact, compilable foundation for endpoint telemetry, device control, and policy decisions that can be hardened for enterprise use.

## Feature highlights
- **USB device monitoring**: Enumerates logical drives/removable devices, captures volume identifiers, and supports USB serial allowlists.
- **File activity monitoring**: Watches `C:\Users` and removable drives via `ReadDirectoryChangesW` and captures create/write/delete/rename events.
- **Enterprise DLP pipeline**: Driver/file events normalized, attributed, extracted, evaluated in RuleEngineV2, enforced, and recorded.
- **Rule engine + PII detection**: Regex/keyword/hash rules plus PII detectors (email, phone, passport/ID, credit card, IBAN, configurable national IDs).
- **Event storage**: Structured events written to SQLite (`dlp_agent.db`) and logs (`dlp_agent.log`) with rule metadata and content flags.
- **Secure telemetry**: Batched, backoff-retrying telemetry with spool fallback and TLS pinning/mTLS hooks using libcurl.

## Repository map
- [config.json](config.json) — runtime configuration (extension_filter, size_threshold, usb_allow_serials, content_keywords, max_scan_bytes, hash_max_bytes, block_on_match, alert_on_removable, rules_config, national_id_patterns, telemetry_* and policy_* fields).
- [rules.json](rules.json) — example rule pack for the rule engine (regex/keyword/hash rules).
- [src/main.cpp](src/main.cpp) — program entry and worker threads startup.
- [src/file_watch.cpp](src/file_watch.cpp) — file watcher implementation using ReadDirectoryChangesW.
- [src/usb_scan.cpp](src/usb_scan.cpp) — USB / drive enumerator.
- [src/api.cpp](src/api.cpp) — secure telemetry sender/flush loop (no legacy heartbeat-only path).
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

> Note: driver communication relies on the Filter Manager client library (`fltlib`), which is provided by the Windows SDK.

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
Edit [config.json](config.json) to change `extension_filter`, `size_threshold`, or the USB allowlist. Additional DLP controls:

- `content_keywords`: case-insensitive keywords scanned from the first `max_scan_bytes` of matching files.
- `max_scan_bytes`: maximum bytes to scan for keywords.
- `hash_max_bytes`: maximum file size to hash (SHA-256).
- `block_on_match`: if `true`, keyword hits are marked as `BLOCK` (otherwise `ALERT`).
- `alert_on_removable`: if `true`, file events on removable drives are flagged.
- `rules_config`: path to a JSON/YAML rule file for the rule engine.
- `national_id_patterns`: regex patterns for national IDs (used by PII detector).
- `telemetry_*`: secure telemetry endpoint and mTLS/TLS pinning configuration.
- `policy_*`: policy fetch configuration and signature verification fields.
- `quarantine_dir`, `shadow_copy_dir`: enforcement output locations.
- `enable_shadow_copy`, `enable_quarantine`: enforcement toggles.

## Architecture (enterprise pipeline)

```
Driver/File Event
   ↓
Event Normalizer
   ↓
Process Attribution
   ↓
Content Extraction
   ↓
RuleEngineV2
   ↓
Policy Decision
   ↓
Enforcement (driver/user-mode)
   ↓
SecureTelemetry
   ↓
SQLite Storage
```

### Execution flow description
1. Minifilter or user-mode watcher emits a file event.
2. Event normalizer standardizes action, path, and device context.
3. Process attribution enriches with PID/PPID/command line and SID.
4. Content extraction pulls text and metadata; hashes/fingerprints are computed.
5. RuleEngineV2 evaluates rule matches and context conditions.
6. Policy decision resolves enforcement action and final decision.
7. Enforcement occurs in driver (block-on-deny) or user-mode (shadow copy/quarantine/delete).
8. SecureTelemetry batches and retries events, with disk spool fallback.
9. SQLite stores normalized events, rules, and content flags.

### Replaced legacy modules
- Legacy rule engine usage → RuleEngineV2 pipeline integration.
- Heartbeat-only telemetry path → SecureTelemetry batching/backoff/spool path.
- Raw file scanning logic → content extraction pipeline with structured flags.

### Integrated enterprise modules
- `enterprise/driver` minifilter communication port integration.
- `enterprise/process_attribution` for PID/PPID/SID enrichment.
- `enterprise/extraction` content extractor hooks.
- `enterprise/rules` RuleEngineV2 runtime.
- `enterprise/policy` policy fetch + version manager for hot reload.
- `enterprise/telemetry` SecureTelemetry with TLS pinning/mTLS hooks.
- `enterprise/anti_tamper` startup checks + watchdog + periodic self-check.

### Remaining TODO security gaps
- Real signature verification (PKI/HMAC) for policies beyond placeholder hashing.
- Full extraction for PDF/DOCX/XLSX (currently stubs).
- Signed driver package distribution and kernel-mode enforcement hardening.

## Operational notes
- This repository is a scaffold intended for extension: service installation, enterprise signing, and full content extraction should be added for production.
- Avoid running as SYSTEM without additional hardening and auditing.
