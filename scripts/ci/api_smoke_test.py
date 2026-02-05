#!/usr/bin/env python3
import json
import sys
import time
import urllib.error
import urllib.request


def request(method: str, url: str, data: dict | None = None, headers: dict | None = None):
    body = None
    req_headers = headers or {}
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        req_headers = {**req_headers, "Content-Type": "application/json"}
    req = urllib.request.Request(url=url, method=method, data=body, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, raw
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def main() -> int:
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"

    for _ in range(30):
        code, _ = request("GET", f"{base_url}/api/v1/health/live")
        if code == 200:
            break
        time.sleep(1)
    else:
        print("Server never became ready for smoke tests", file=sys.stderr)
        return 1

    checks = [
        ("live", "GET", f"{base_url}/api/v1/health/live", None, None, 200),
        ("ready", "GET", f"{base_url}/api/v1/health/ready", None, None, 200),
        (
            "invalid-payload",
            "POST",
            f"{base_url}/api/v1/agent/register",
            {},
            None,
            422,
        ),
        (
            "unauthorized",
            "GET",
            f"{base_url}/api/v1/admin/alerts",
            None,
            None,
            401,
        ),
    ]

    failures = []
    for name, method, url, data, headers, expected in checks:
        status, body = request(method, url, data=data, headers=headers)
        if status != expected:
            failures.append((name, expected, status, body))

    if failures:
        for name, expected, got, body in failures:
            print(f"[FAIL] {name}: expected {expected}, got {got} body={body}", file=sys.stderr)
        return 1

    print("API smoke tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
