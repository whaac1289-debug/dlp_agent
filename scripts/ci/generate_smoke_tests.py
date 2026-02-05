#!/usr/bin/env python3
from pathlib import Path


SMOKE_TEST = '''import importlib\n\n\ndef test_application_imports():\n    module = importlib.import_module("server.main")\n    assert hasattr(module, "app")\n'''


def main() -> int:
    out = Path("server/tests/test_generated_smoke.py")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(SMOKE_TEST)
    print(f"Generated {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
