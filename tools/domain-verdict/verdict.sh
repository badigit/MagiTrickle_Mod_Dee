#!/usr/bin/env bash
# verdict.sh — обёртка: гонит tools/domain-verdict/domain-verdict.sh на роутере
# через ssh stdin (ничего не копируя на роутер — всегда свежая версия из репо).
#
# Использование:
#   bash tools/domain-verdict/verdict.sh <домен|URL> [--host <ssh-алиас>] [--ref <хост>]
#
# По умолчанию хост — <ROUTER_SSH> (алиас несёт порт и пользователя в ~/.ssh/config).
# Для офисного роутера: --host <ROUTER_SSH_OFFICE>
set -euo pipefail

# Git Bash иначе перепишет /opt/bin/sh в C:/Program Files/... — путь уедет в Windows
export MSYS_NO_PATHCONV=1
# /bin/sh на Keenetic — это ndmsh (CLI роутера), он не понимает `-s`; нужен busybox из Entware
REMOTE_SH="/opt/bin/sh"

TARGET=""
SSH_HOST="${ROUTER_SSH:-<ROUTER_SSH>}"
DV_REF=""

while [ $# -gt 0 ]; do
  case "$1" in
    --host) SSH_HOST="$2"; shift 2 ;;
    --ref) DV_REF="$2"; shift 2 ;;
    -h|--help)
      echo "использование: verdict.sh <домен|URL> [--host <ssh-алиас>] [--ref <хост>]"; exit 0 ;;
    *) TARGET="$1"; shift ;;
  esac
done

if [ -z "$TARGET" ]; then
  echo "нужен домен или URL. пример: verdict.sh https://example.com/path" >&2
  exit 2
fi

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
SCRIPT="$ROOT/tools/domain-verdict/domain-verdict.sh"
[ -r "$SCRIPT" ] || { echo "не найден $SCRIPT" >&2; exit 1; }

# LF-нормализация на лету: CRLF в heredoc роняет busybox sh
tr -d '\r' < "$SCRIPT" | ssh -o ConnectTimeout=10 "$SSH_HOST" "DV_TARGET='$TARGET' DV_REF='$DV_REF' $REMOTE_SH -s"
