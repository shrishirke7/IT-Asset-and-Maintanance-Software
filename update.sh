#!/usr/bin/env bash
set -euo pipefail
if [[ "$(id -u)" -ne 0 ]]; then echo "Run with: sudo bash update.sh" >&2; exit 1; fi
SOURCE_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
INSTALL_DIR="/opt/northstar-it"
[[ -f "$INSTALL_DIR/.env" ]] || { echo "No installed Northstar configuration was found." >&2; exit 1; }
if [[ "$SOURCE_DIR" != "$INSTALL_DIR" ]]; then
  tar -C "$SOURCE_DIR" --exclude='./.git' --exclude='./.env' --exclude='./secrets' --exclude='./uploads' --exclude='./backups' --exclude='./caddy-root.crt' --exclude='./__pycache__' -cf - . | tar -C "$INSTALL_DIR" -xf -
fi
cd "$INSTALL_DIR"
./backup.sh manual
docker compose build app scanner
docker compose up -d
echo "Update complete. Existing .env, database, uploads, and backups were preserved."
