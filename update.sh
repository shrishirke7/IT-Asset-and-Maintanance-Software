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
set -a
. "$INSTALL_DIR/.env"
set +a
if [[ ! -s "$INSTALL_DIR/secrets/nginx.crt" || ! -s "$INSTALL_DIR/secrets/nginx.key" ]]; then
  SERVER_IP="$(hostname -I | awk '{print $1}')"
  openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
    -keyout "$INSTALL_DIR/secrets/nginx.key" -out "$INSTALL_DIR/secrets/nginx.crt" \
    -subj "/CN=$APP_FQDN" \
    -addext "subjectAltName=DNS:$APP_FQDN,IP:$SERVER_IP" \
    -addext "basicConstraints=critical,CA:TRUE"
  chmod 600 "$INSTALL_DIR/secrets/nginx.key"
  chmod 644 "$INSTALL_DIR/secrets/nginx.crt"
fi
docker compose build app scanner
docker compose pull web
docker compose up -d --force-recreate web
echo "Update complete. Existing .env, database, uploads, and backups were preserved."
