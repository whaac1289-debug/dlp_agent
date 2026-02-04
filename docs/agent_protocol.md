# Agent Protocol Specification

## Overview
All agent-to-server API calls are authenticated with:
- A JWT access token (agent token) in `Authorization: Bearer <token>`.
- A request signature in `X-Signature` using the agent shared secret.
- A per-request nonce in `X-Nonce` and Unix timestamp in `X-Timestamp`.
- A protocol version header `X-Agent-Protocol-Version`.

## Required headers
| Header | Description |
| --- | --- |
| `Authorization` | `Bearer <agent_jwt>` |
| `X-Signature` | HMAC SHA-256 of the canonical payload |
| `X-Nonce` | Unique per-request nonce (UUID recommended) |
| `X-Timestamp` | Unix epoch seconds |
| `X-Agent-Protocol-Version` | Supported protocol version (e.g. `1.0`) |

## Signature material
Canonical payload is constructed as:
```
<HTTP_METHOD>\n
<PATH>\n
<X-Timestamp>\n
<X-Nonce>\n
<RAW_BODY_BYTES>
```

Signature is:
```
hex(hmac_sha256(shared_secret, canonical_payload))
```

## Replay protection
- Nonce + timestamp are stored in a replay cache.
- Skew window is ±60 seconds.
- Reuse of `X-Nonce` within the window returns `409`.

## Protocol versioning
- `X-Agent-Protocol-Version` must match one of `DLP_AGENT_PROTOCOL_VERSIONS`.
- Unsupported versions are rejected with `400`.

## Idempotency
Each event must include `event_id` (UUID). Duplicate event IDs are ignored.

## Enrollment
Agent registration requires **one** of:
- `enrollment_token` (one-time use, stored server-side).
- `enrollment_package` + `enrollment_signature` (HMAC-signed JSON payload).
