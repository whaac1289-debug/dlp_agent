# Enterprise Augmentations

## 1) Kernel Enforcement Minifilter Driver

**Project structure**
```
src/enterprise/driver/
  dlp_minifilter.c
  dlp_minifilter.h
  dlp_minifilter.inf
  dlp_minifilter.vcxproj
```

**Key workflow**
- Register minifilter and create communication port.
- Intercept IRP_MJ_CREATE, IRP_MJ_WRITE, IRP_MJ_SET_INFORMATION.
- Build policy query, send to user-mode agent, block on deny.

**Integration points**
- User-mode agent should connect to `\\DlpMinifilterPort` and answer policy decisions.
- Map `DLP_POLICY_QUERY` fields to rule engine/context and respond with `DLP_POLICY_DECISION`.

**Build instructions (Visual Studio / MSVC)**
- Open `src/enterprise/driver/dlp_minifilter.vcxproj` in Visual Studio.
- Install WDK and set configuration to `Release | x64`.
- Build to produce `dlp_minifilter.sys`, then install via `dlp_minifilter.inf`.

## 2) Secure Telemetry Module

**Project structure**
```
src/enterprise/telemetry/
  secure_telemetry.h
  secure_telemetry.cpp
```

**Key workflow**
- Queue events in memory; on flush build batches.
- Upload via mTLS + TLS pinning; on failure spool to disk.
- Retry with exponential backoff and jitter.

**Integration points**
- Replace existing telemetry sender with `dlp::telemetry::SecureTelemetry`.
- Use libcurl in `SecureHttpClient::PostJson` for real HTTP/mTLS.

**Build instructions (Visual Studio / MSVC)**
- Add new files to the agent project.
- Link against libcurl and OpenSSL (or SChannel for native TLS).

## 3) Policy Pull & Hot Reload

**Project structure**
```
src/enterprise/policy/
  policy_fetcher.h
  policy_fetcher.cpp
  policy_version_manager.h
  policy_version_manager.cpp
```

**Key workflow**
- Fetch policy JSON and signature.
- Verify signature (HMAC or RSA).
- Apply policy via callback; persist last good; rollback if apply fails.

**Integration points**
- Schedule fetch with a timer in the service loop.
- Connect apply callback to policy engine reload and rule store updates.

**Build instructions (Visual Studio / MSVC)**
- Add files to the agent project.
- Use crypto library for HMAC/RSA validation (CNG / OpenSSL).

## 4) Process Attribution

**Project structure**
```
src/enterprise/
  process_attribution.h
  process_attribution.cpp
```

**Key workflow**
- Capture PID/PPID, process name, command line, token SID and privileges.
- Enrich event schema before storing or sending telemetry.

**Integration points**
- Inject into SQLite event schema and telemetry payloads.

**Build instructions (Visual Studio / MSVC)**
- Add files to the agent project.
- Link with `Advapi32.lib` for token queries.

## 5) Advanced Rule Engine

**Project structure**
```
src/enterprise/rules/
  rule_engine_v2.h
  rule_engine_v2.cpp
```

**Key workflow**
- Parse JSON rules into `Rule` objects.
- Sort by priority and evaluate conditions against `RuleContext`.
- Return action, severity, and rule id.

**Integration points**
- Replace legacy rule evaluation path with `RuleEngineV2`.
- Map policy fields into `RuleContext` attributes.

**Build instructions (Visual Studio / MSVC)**
- Add files to the agent project.
- Use `nlohmann::json` for JSON parsing or equivalent.

## 6) Anti-Tamper Protection

**Project structure**
```
src/enterprise/anti_tamper/
  anti_tamper.h
  anti_tamper.cpp
```

**Key workflow**
- Verify agent binary hash and config signature.
- Detect debugger and enforce watchdog for service restarts.

**Integration points**
- Invoke at service startup and on configuration load.

**Build instructions (Visual Studio / MSVC)**
- Add files to the agent project.
- Use `Dbghelp`/`WinTrust` for integrity checks.

## 7) Document Content Extraction

**Project structure**
```
src/enterprise/extraction/
  content_extractor.h
  content_extractor.cpp
```

**Key workflow**
- Select extractor by extension; extract text for scanners and rule engine.

**Integration points**
- Call from file scan pipeline prior to PII/regex detection.

**Build instructions (Visual Studio / MSVC)**
- Add files to the agent project.
- Integrate with PDF/DOCX/XLSX parsers (PDFium, OpenXML).

## 8) Test Suite

**Project structure**
```
tests/
  test_policy_reload.cpp
  test_rule_engine_v2.cpp
  test_pii_detector.cpp
  test_driver_enforcement.cpp
  test_telemetry_resilience.cpp
```

**Key workflow**
- Unit tests for rule evaluation and PII detection.
- Integration tests for policy reload, driver enforcement, telemetry retry.

**Build instructions (Visual Studio / MSVC)**
- Compile with `DLP_ENABLE_TESTS` to enable the test entry points.

## Removed enterprise artifacts

```
src/enterprise/rules/rule_schema_v2.json
src/enterprise/service/service_installer_manifest.xml
```
