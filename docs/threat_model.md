# Threat Model

## Assets
- Endpoint telemetry and file metadata.
- Policy definitions and rule packs.
- Tenant data and investigation artifacts.
- Agent shared secrets and signing keys.

## Threats
- **Replay attacks** against agent ingestion endpoints.
- **Credential stuffing** against admin portals.
- **Tampering** with agent config and binaries.
- **Data exfiltration** via misconfigured SIEM exports.
- **Cross-tenant access** attempts.

## Mitigations
- Replay protection with nonce + timestamp validation.
- HMAC signing for agent payloads; JWT-based auth.
- Anti-tamper validation of agent binaries and config signature.
- RBAC enforcement and tenant scoping on all data access.
- TLS termination at Nginx and secure syslog transport where possible.

## Residual risk
- Insider misuse is mitigated with audit logging and least-privilege roles.
- Offline agent replay remains limited to the configured skew window.
