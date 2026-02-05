# Security Policy

## Reporting a Vulnerability

Please report vulnerabilities privately to the security team and avoid opening public issues containing exploit details.

Include:
- Affected component and version.
- Reproduction steps / proof-of-concept.
- Impact and suggested remediation.

## Supported Versions

Security fixes are prioritized for the default branch and latest tagged release.

## Hardening Baseline

- Use strong secrets (24+ chars) for all `DLP_*SECRET` values.
- Run production with HTTPS-only origins.
- Do not run with wildcard CORS origins.
- Rotate enrollment and JWT secrets regularly.
- Restrict agent enrollment token TTL and monitor audit logs.
