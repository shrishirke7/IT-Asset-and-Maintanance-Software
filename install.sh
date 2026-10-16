#!/usr/bin/env bash
set -euo pipefail
if [[ "$(id -u)" -ne 0 ]]; then echo "Run once with: sudo bash install.sh" >&2; exit 1; fi
. /etc/os-release
if [[ "${ID:-}" != ubuntu || "${VERSION_ID%%.*}" -lt 22 ]]; then echo "This installer targets Ubuntu Server 22.04 or newer." >&2; exit 1; fi
SOURCE_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
INSTALL_DIR="/opt/northstar-it"
if [[ -f "$INSTALL_DIR/.env" ]]; then echo "Existing install found. Use sudo bash update.sh to update it." >&2; exit 1; fi
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-v2 ca-certificates curl openssl python3
fi
systemctl enable --now docker
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/uploads" "$INSTALL_DIR/backups" "$INSTALL_DIR/secrets"
if [[ "$SOURCE_DIR" != "$INSTALL_DIR" ]]; then
  tar -C "$SOURCE_DIR" --exclude='./.git' --exclude='./.env' --exclude='./secrets' --exclude='./uploads' --exclude='./backups' --exclude='./__pycache__' -cf - . | tar -C "$INSTALL_DIR" -xf -
fi
SERVER_IP="$(hostname -I | awk '{print $1}')"
APP_FQDN="${APP_FQDN:-$SERVER_IP}"
HTTP_PORT="${HTTP_PORT:-8898}"
HTTPS_PORT="${HTTPS_PORT:-8899}"
DB_PASSWORD="$(openssl rand -hex 32)"
APP_SECRET="$(openssl rand -hex 48)"
export APP_FQDN HTTP_PORT HTTPS_PORT DB_PASSWORD APP_SECRET
python3 - "$INSTALL_DIR/.env" <<'PYENV'
import os,sys
keys=("APP_FQDN","HTTP_PORT","HTTPS_PORT","DB_PASSWORD","APP_SECRET")
def q(v): return "'"+v.replace("\\","\\\\").replace("'","\\'")+"'"
with open(sys.argv[1],"w",encoding="utf-8") as f:
    for k in keys: f.write(f"{k}={q(os.environ[k])}\n")
    f.write("COOKIE_SECURE='true'\nBACKUP_DIR='/backups'\nUPLOAD_DIR='/app/uploads'\nTZ='Asia/Kolkata'\n")
PYENV
chmod 600 "$INSTALL_DIR/.env"
chown -R 10001:10001 "$INSTALL_DIR/uploads" "$INSTALL_DIR/backups"
chmod 700 "$INSTALL_DIR/uploads" "$INSTALL_DIR/backups" "$INSTALL_DIR/secrets"
if [[ ! -s "$INSTALL_DIR/secrets/nginx.crt" || ! -s "$INSTALL_DIR/secrets/nginx.key" ]]; then
  openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
    -keyout "$INSTALL_DIR/secrets/nginx.key" -out "$INSTALL_DIR/secrets/nginx.crt" \
    -subj "/CN=$APP_FQDN" \
    -addext "subjectAltName=DNS:$APP_FQDN,IP:$SERVER_IP" \
    -addext "basicConstraints=critical,CA:TRUE"
fi
chmod 600 "$INSTALL_DIR/secrets/nginx.key"
chmod 644 "$INSTALL_DIR/secrets/nginx.crt"
chmod +x "$INSTALL_DIR/backup.sh" "$INSTALL_DIR/restore.sh"
cd "$INSTALL_DIR"
docker compose build app scanner
docker compose up -d
install -m 0644 "$INSTALL_DIR/systemd/northstar-backup@.service" /etc/systemd/system/northstar-backup@.service
for kind in daily weekly monthly; do install -m 0644 "$INSTALL_DIR/systemd/northstar-backup-$kind.timer" "/etc/systemd/system/northstar-backup-$kind.timer"; done
systemctl daemon-reload
systemctl enable --now northstar-backup-daily.timer northstar-backup-weekly.timer northstar-backup-monthly.timer
echo
echo "Northstar is starting at https://$APP_FQDN:$HTTPS_PORT"
echo "Open that address in your browser and complete the first-run company and administrator setup."
echo "This installer creates no default username or password."
echo "Backups: daily, weekly, and monthly. Manual backup: sudo $INSTALL_DIR/backup.sh manual"
echo "Check startup: cd $INSTALL_DIR && docker compose ps"
