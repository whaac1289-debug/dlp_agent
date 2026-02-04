# C++ Agent Integration Guide

## Registration
1. Call `POST /api/v1/agent/register` with JSON payload:
   ```json
   {
     "agent_uuid": "<uuid>",
     "fingerprint": "<machine fingerprint>",
     "hostname": "<hostname>",
     "ip_address": "<ip>",
     "version": "<agent version>",
     "tenant": "default"
   }
   ```
2. Store the returned `jwt` and `agent_id`. The server generates a `shared_secret` internally; request the secret via secure provisioning or embed it during registration flow (recommended: update registration to return it out-of-band).

## Heartbeat
- `POST /api/v1/agent/heartbeat`
- Headers: `X-Request-Id`, `X-Timestamp`
- Body:
  ```json
  {"agent_uuid":"<uuid>","timestamp":"2024-09-13T00:00:00Z","status":"online"}
  ```

## Event Ingestion
- `POST /api/v1/agent/events`
- Headers:
  - `Authorization: Bearer <jwt>`
  - `X-Request-Id`: unique UUID per request
  - `X-Timestamp`: unix timestamp
  - `X-Signature`: HMAC-SHA256 of the raw JSON body with agent shared secret
- Body:
  ```json
  {
    "agent_uuid": "<uuid>",
    "event_type": "file_copy",
    "file_path": "C:\\secret.txt",
    "file_hash": "<sha256>",
    "file_size": 1024,
    "metadata": {"usb_copy": true, "content": "redacted"},
    "user_context": {"user": "DOMAIN\\user"},
    "timestamp": "2024-09-13T00:00:00Z"
  }
  ```

## Policy Fetch
- `GET /api/v1/agent/policy` with `Authorization: Bearer <jwt>`.

## Config Fetch
- `GET /api/v1/agent/config` with `Authorization: Bearer <jwt>`.
