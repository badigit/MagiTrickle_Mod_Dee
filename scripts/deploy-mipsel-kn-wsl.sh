#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_ALIAS="root@192.168.5.1"
SSH_PORT="222"
REMOTE_TMP_DIR="/opt/root/tmp"

shopt -s nullglob
candidates=("$ROOT_DIR"/.build/magitrickle_*_entware_mipsel-3.4_kn.ipk)
shopt -u nullglob

if [[ ${#candidates[@]} -eq 0 ]]; then
  echo "No mipsel-3.4_kn package found in \"$ROOT_DIR/.build\"." >&2
  exit 1
fi

PACKAGE_PATH="$(ls -1t "${candidates[@]}" | head -n1)"

PACKAGE_NAME="$(basename "$PACKAGE_PATH")"
REMOTE_PACKAGE_PATH="$REMOTE_TMP_DIR/$PACKAGE_NAME"

echo "Using package: $PACKAGE_PATH"
echo "Uploading to $HOST_ALIAS:$REMOTE_PACKAGE_PATH"

ssh -p "$SSH_PORT" "$HOST_ALIAS" "mkdir -p \"$REMOTE_TMP_DIR\""
scp -O -P "$SSH_PORT" "$PACKAGE_PATH" "$HOST_ALIAS:$REMOTE_TMP_DIR/"

echo "Installing package on $HOST_ALIAS"
ssh -p "$SSH_PORT" "$HOST_ALIAS" "opkg install --force-reinstall \"$REMOTE_PACKAGE_PATH\" && /opt/etc/init.d/S99magitrickle restart"
