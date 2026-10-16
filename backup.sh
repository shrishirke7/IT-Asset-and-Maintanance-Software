#!/usr/bin/env bash
set -euo pipefail
KIND="${1:-manual}"
case "$KIND" in daily|weekly|monthly|manual) ;; *) echo "Usage: $0 [daily|weekly|monthly|manual]" >&2; exit 2;; esac
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR"
docker compose exec -T app python backup.py "$KIND"
