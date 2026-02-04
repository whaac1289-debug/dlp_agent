# dlp_agent — Enterprise-capable DLP Agent

`dlp_agent` is an enterprise-capable Windows DLP (Data Loss Prevention) agent scaffold written in modern C++. It ships both a compact core agent and enterprise modules for kernel minifilter enforcement, secure telemetry, policy hot reload with signature verification, Rule Engine v2, anti-tamper protection, document content extraction, process attribution, and an enterprise test suite—so the full production pipeline is visible in-repo.

**See detailed enterprise modules → [ENTERPRISE_AUGMENTATIONS.md](ENTERPRISE_AUGMENTATIONS.md)**

## Architecture overview

```
Kernel Minifilter / User-mode Watchers
               ↓
        Event Normalizer
               ↓
      Process Attribution
               ↓
      Content Extraction
               ↓
        Rule Engine V2
               ↓
        Policy Decision
               ↓
  Enforcement (kernel + user)
               ↓
        Secure Telemetry
               ↓
          SQLite Store
```

## Core features
- **USB device monitoring**: enumerates logical drives/removable devices and supports a USB serial allowlist.
- **File activity monitoring**: watches `C:\Users` and removable drives via `ReadDirectoryChangesW` for create/write/delete/rename events.
- **Policy checks**: size thresholds, removable-drive alerting, keyword scanning, and optional hashing.
- **Rule engine + PII detection**: regex/keyword/hash rules and PII detectors (email, phone, passport/ID, credit card, IBAN, configurable national IDs).
- **Event storage**: structured events written to SQLite (`dlp_agent.db`) and logs (`dlp_agent.log`).
- **Telemetry**: batched telemetry sender with retry logging via libcurl.

## Enterprise features
Enterprise modules live under `src/enterprise/` and are documented in detail in [ENTERPRISE_AUGMENTATIONS.md](ENTERPRISE_AUGMENTATIONS.md).

- **Kernel minifilter enforcement driver** (`src/enterprise/driver/`)
- **Enterprise telemetry security** with mTLS/TLS pinning and spool fallback (`src/enterprise/telemetry/`)
- **Policy hot reload + signature verification** (`src/enterprise/policy/`)
- **Rule Engine v2** (`src/enterprise/rules/`)
- **Anti-tamper protection** (`src/enterprise/anti_tamper/`)
- **Document content extraction** (`src/enterprise/extraction/`)
- **Process attribution** (`src/enterprise/process_attribution.*`)
- **Enterprise test suite** (`tests/`)

## Enforcement model (kernel + user-mode flow)
1. **Kernel mode**: the minifilter driver intercepts file operations and queries user-mode for policy decisions.
2. **User mode**: the agent evaluates rules and policy, then returns allow/deny and performs user-mode enforcement (shadow copy/quarantine/delete) when configured.

## Module layout / project structure

### Module table
| Area | Path | Description |
| --- | --- | --- |
| Core agent entry | `src/main.cpp` | Startup, worker threads, and service loop integration. |
| File monitoring | `src/file_watch.*` | `ReadDirectoryChangesW` watcher and event capture. |
| USB monitoring | `src/usb_scan.*` | Drive and device enumeration, allowlist support. |
| Policy evaluation | `src/rule_engine.*` | Core rule engine and matching logic. |
| PII detection | `src/pii_detector.*` | PII pattern scanning for common identifiers. |
| Event pipeline | `src/event_bus.*`, `src/filter.*`, `src/fingerprint.*`, `src/hash.*` | Normalization, filtering, hashing/fingerprint helpers. |
| Storage & logging | `src/sqlite_store.*`, `src/log.*` | SQLite events storage and log output. |
| Core telemetry | `src/api.*` | Baseline telemetry sender using libcurl. |
| Enterprise driver | `src/enterprise/driver/` | Kernel minifilter driver project and INF. |
| Enterprise telemetry | `src/enterprise/telemetry/` | Secure telemetry with mTLS/TLS pinning + spool. |
| Enterprise policy | `src/enterprise/policy/` | Policy fetch, signature verification, and hot reload. |
| Enterprise rules | `src/enterprise/rules/` | Rule Engine v2 implementation. |
| Enterprise anti-tamper | `src/enterprise/anti_tamper/` | Integrity checks and watchdog hooks. |
| Enterprise extraction | `src/enterprise/extraction/` | Content extractor stubs and extension routing. |
| Enterprise attribution | `src/enterprise/process_attribution.*` | PID/PPID/SID enrichment. |
| Enterprise tests | `tests/` | Test suite for policy reload, rules, telemetry, and enforcement. |
| Config & rules | `config.json`, `rules.json` | Runtime config and example rule pack. |

### Feature matrix (Core vs Enterprise)
| Capability | Core | Enterprise |
| --- | --- | --- |
| USB monitoring | ✅ | ✅ |
| File activity monitoring | ✅ | ✅ |
| Keyword scanning / hashing | ✅ | ✅ |
| PII detection | ✅ | ✅ |
| Rule engine | ✅ (v1) | ✅ (v2) |
| Secure telemetry (mTLS/TLS pinning, spool) | ❌ | ✅ |
| Policy hot reload + signature verification | ❌ | ✅ |
| Kernel minifilter enforcement | ❌ | ✅ |
| Anti-tamper protection | ❌ | ✅ |
| Document content extraction | ❌ (baseline only) | ✅ |
| Process attribution | ❌ | ✅ |
| Enterprise test suite | ❌ | ✅ |

## Build instructions

### Core agent (MSYS2 UCRT64)
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

### Enterprise minifilter driver (Visual Studio + WDK)
- Open `src/enterprise/driver/dlp_minifilter.vcxproj` in Visual Studio.
- Install the Windows Driver Kit (WDK).
- Build `Release | x64` to produce `dlp_minifilter.sys`, then install via `dlp_minifilter.inf`.

## Security model
- **Policy integrity**: enterprise policy modules support signature verification for policy hot reload.
- **Telemetry security**: enterprise telemetry module supports mTLS and TLS pinning with spool fallback.
- **Anti-tamper**: enterprise module provides integrity checks and watchdog hooks for agent survivability.
- **Least privilege**: run with the minimum privileges needed; avoid SYSTEM without additional hardening.

## Limitations
- Enterprise modules are included but require integration and production hardening.
- Full PDF/DOCX/XLSX parsers are not bundled; content extraction is extensible but requires external libraries.
- Kernel enforcement requires driver signing and deployment steps outside the MSYS2 build.

## Roadmap
- Integrate Rule Engine v2 and enterprise policy hot reload into the core service loop.
- Complete production-grade signature verification and key management for policy updates.
- Expand content extraction and PII detection coverage for additional document formats.
