#!/usr/bin/env bash
set -euo pipefail

PYTHONPATH=. alembic -c server/alembic.ini upgrade head
