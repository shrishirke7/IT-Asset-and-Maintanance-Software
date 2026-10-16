#!/usr/bin/env bash
set -euo pipefail
if [[ "$(id -u)" -ne 0 ]]; then echo "Run once with: sudo bash install.sh" >&2; exit 1; fi
. /etc/os-release
if [[ "${ID:-}" != ubuntu || "${VERSION_ID%%.*}" -lt 22 ]]; then echo "This installer currently targets Ubuntu Server 22.04 or newer." >&2; exit 1; fi
SOURCE_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
INSTALL_DIR="/opt/northstar-it"
echo "== Northstar IT Inventory installer (Ubuntu Server) =="
if [[ -f "$INSTALL_DIR/.env" ]]; then
  echo "An installation already has secrets at $INSTALL_DIR/.env. This first-install script will not rotate them. Use the update instructions in README.md." >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-v2 ca-certificates curl openssl python3
fi
systemctl enable --now docker
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/uploads" "$INSTALL_DIR/backups" "$INSTALL_DIR/secrets"
if [[ "$SOURCE_DIR" != "$INSTALL_DIR" ]]; then
  tar -C "$SOURCE_DIR" --exclude='./.git' --exclude='./.env' --exclude='./secrets' --exclude='./uploads' --exclude='./backups' --exclude='./caddy-root.crt' --exclude='./__pycache__' -cf - . | tar -C "$INSTALL_DIR" -xf -
fi
mkdir -p "$INSTALL_DIR/secrets"
[[ -f "$INSTALL_DIR/secrets/ad-ca.pem" ]] || : > "$INSTALL_DIR/secrets/ad-ca.pem"
read -r -p "Inventory site FQDN (example: it-inventory.office.local): " APP_FQDN
read -r -p "Samba AD / DNS server IP: " LDAP_DNS_SERVER
read -r -p "LDAP URL (ldaps://dc.office.local:636 or ldap://dc.office.local:389): " LDAP_URL
read -r -p "AD base DN (example: DC=office,DC=local): " LDAP_BASE_DN
read -r -p "AD user UPN suffix (example: office.local): " LDAP_UPN_SUFFIX
read -r -p "Read-only sync account DN or UPN: " LDAP_BIND_USER
read -r -s -p "Read-only sync account password: " LDAP_BIND_PASSWORD
echo
read -r -p "AD group DN for inventory administrators: " AD_ADMIN_GROUP_DNS
read -r -p "AD attribute holding ARG/ARB/ARC/ARF (default physicalDeliveryOfficeName): " LDAP_SITE_ATTRIBUTE
LDAP_SITE_ATTRIBUTE="${LDAP_SITE_ATTRIBUTE:-physicalDeliveryOfficeName}"
read -r -p "Path to AD CA certificate PEM (Enter if trusted by system): " LDAP_CA_SOURCE
read -r -p "HTTPS port (default 443): " HTTPS_PORT
HTTPS_PORT="${HTTPS_PORT:-443}"
read -r -p "HTTP redirect port (default 80): " HTTP_PORT
HTTP_PORT="${HTTP_PORT:-80}"
[[ -n "$APP_FQDN" && -n "$LDAP_DNS_SERVER" && -n "$LDAP_BASE_DN" && -n "$LDAP_BIND_USER" && -n "$AD_ADMIN_GROUP_DNS" ]] || { echo "FQDN, AD DNS, base DN, service account and admin group are required." >&2; exit 2; }
[[ "$LDAP_URL" == ldaps://* || "$LDAP_URL" == ldap://* ]] || { echo "LDAP URL must start with ldaps:// or ldap://" >&2; exit 2; }
if [[ "$LDAP_URL" == ldap://* ]]; then echo "StartTLS is required and will be enforced for ldap:// URLs."; fi
if [[ -n "$LDAP_CA_SOURCE" ]]; then install -m 0644 "$LDAP_CA_SOURCE" "$INSTALL_DIR/secrets/ad-ca.pem"; fi
DB_PASSWORD="$(openssl rand -hex 32)"
APP_SECRET="$(openssl rand -hex 48)"
LDAP_BIND_PASSWORD_B64="$(printf '%s' "$LDAP_BIND_PASSWORD" | base64 -w0)"
unset LDAP_BIND_PASSWORD
export APP_FQDN LDAP_DNS_SERVER LDAP_URL LDAP_BASE_DN LDAP_UPN_SUFFIX LDAP_BIND_USER LDAP_BIND_PASSWORD_B64 AD_ADMIN_GROUP_DNS LDAP_SITE_ATTRIBUTE DB_PASSWORD APP_SECRET HTTP_PORT HTTPS_PORT
python3 - "$INSTALL_DIR/.env" <<'PY'
import os, sys
keys = ("APP_FQDN", "LDAP_DNS_SERVER", "LDAP_URL", "LDAP_BASE_DN", "LDAP_UPN_SUFFIX", "LDAP_BIND_USER", "LDAP_BIND_PASSWORD_B64", "AD_ADMIN_GROUP_DNS", "LDAP_SITE_ATTRIBUTE", "DB_PASSWORD", "APP_SECRET", "HTTP_PORT", "HTTPS_PORT")
def q(value):
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"
with open(sys.argv[1], "w", encoding="utf-8") as f:
    for key in keys:
        f.write(f"{key}={q(os.environ[key])}\n")
    f.write("LDAP_STARTTLS='true'\nLDAP_CA_FILE='/run/secrets/ad-ca.pem'\nCOOKIE_SECURE='true'\nBACKUP_DIR='/backups'\nUPLOAD_DIR='/app/uploads'\nTZ='Asia/Kolkata'\n")
PY
chmod 600 "$INSTALL_DIR/.env"
chown -R 10001:10001 "$INSTALL_DIR/uploads" "$INSTALL_DIR/backups"
chmod 700 "$INSTALL_DIR/uploads" "$INSTALL_DIR/backups" "$INSTALL_DIR/secrets"
SERVER_IP="$(hostname -I | awk '{print $1}')"
openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
  -keyout "$INSTALL_DIR/secrets/nginx.key" -out "$INSTALL_DIR/secrets/nginx.crt" \
  -subj "/CN=$APP_FQDN" \
  -addext "subjectAltName=DNS:$APP_FQDN,IP:$SERVER_IP" \
  -addext "basicConstraints=critical,CA:TRUE"
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
echo "Northstar is starting. Add this DNS A record: $APP_FQDN -> $SERVER_IP"
echo "Open: https://$APP_FQDN:$HTTPS_PORT"
echo "First local administrator (fresh database only): administrator1 / Admin@123 — change this starter password in Settings after signing in."
echo "Backups: daily 01:30, weekly Sunday 02:30, monthly on day 1 at 03:30 (server local time)."
echo "Nginx TLS certificate: $INSTALL_DIR/secrets/nginx.crt (trust this certificate on managed workstations to remove browser warnings)."
echo "Manual backup: sudo $INSTALL_DIR/backup.sh manual"
echo "Restore: sudo $INSTALL_DIR/restore.sh /opt/northstar-it/backups/<backup-file>"
echo "Check startup: cd $INSTALL_DIR && docker compose ps && docker compose logs -f app"
