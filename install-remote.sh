#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/install-remote.sh | sudo bash -s -- OWNER/REPO [branch]" >&2
  exit 1
fi

REPOSITORY="${1:-}"
BRANCH="${2:-main}"
if [[ ! "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "Usage: install-remote.sh OWNER/REPO [branch]" >&2
  exit 2
fi
if [[ ! "$BRANCH" =~ ^[A-Za-z0-9_.-]+$ ]]; then
  echo "Branch may contain only letters, digits, dots, underscores, and hyphens." >&2
  exit 2
fi

command -v git >/dev/null 2>&1 || {
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y git ca-certificates
}
TMP_DIR="$(mktemp -d /tmp/northstar-install.XXXXXX)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT
git clone --depth 1 --branch "$BRANCH" "https://github.com/$REPOSITORY.git" "$TMP_DIR/source"
bash "$TMP_DIR/source/install.sh"
