# Hardening Guide

## Runtime
- Enforce TLS termination at ingress.
- Set secure random secrets in environment variables.
- Limit database user permissions to required schemas.
- Run containers as non-root users.

## API Security
- Keep JWT secrets rotated and unique by environment.
- Use short-lived access tokens and monitor refresh token usage.
- Enforce origin allow-list; avoid `*` and plaintext origins in production.

## Agent Trust
- Require signed requests (`X-Signature`, `X-Timestamp`, `X-Nonce`).
- Enable replay protection with Redis and low skew window.
- Rotate agent `shared_secret` on re-enrollment.

## CI/CD
- Use immutable actions where feasible.
- Avoid `|| true` on security/test stages.
- Keep `permissions` least-privilege (`contents: read` by default).
