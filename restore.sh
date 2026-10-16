#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 1 || ! -f "$1" ]]; then echo "Usage: sudo $0 /path/to/northstar-backup.tar.gz" >&2; exit 2; fi
ARCHIVE="$(realpath -- "$1")"
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR"
echo "This replaces the current database and uploaded ticket attachments."
read -r -p "Type RESTORE to create a safety backup and continue: " CONFIRM
[[ "$CONFIRM" == "RESTORE" ]] || { echo "Restore cancelled."; exit 1; }
./backup.sh manual
TMP="$(mktemp -d)"
STOPPED=0
cleanup() {
  if [[ "$STOPPED" == "1" ]]; then docker compose start app web >/dev/null || true; fi
  rm -rf -- "$TMP"
}
trap cleanup EXIT
python3 restore_archive.py "$ARCHIVE" "$TMP"
docker compose stop app web
STOPPED=1
docker compose exec -T db pg_restore --clean --if-exists --no-owner -U northstar -d northstar - < "$TMP/database.dump"
mkdir -p uploads
find uploads -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
cp -a "$TMP/uploads/." uploads/
chown -R 10001:10001 uploads
docker compose start app web
STOPPED=0
echo "Restore complete. Review application and ticket attachment access."
