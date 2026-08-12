#!/usr/bin/env bash
# verdict.sh — обёртка: гонит tools/domain-verdict/domain-verdict.sh на роутере
# через ssh stdin (ничего не копируя на роутер — всегда свежая версия из репо).
#
# Использование:
#   bash tools/domain-verdict/verdict.sh <домен|URL> [--host <ssh-цель>] [--ref <хост>]
#
# Куда идти, задаётся снаружи и никаких личных хостов в репозитории не держит:
#   --host <цель>            ssh-алиас из ~/.ssh/config или user@адрес
#   ROUTER_SSH=<цель>        то же переменной окружения
#   ROUTER_PORT=<порт>       если цель без алиаса и порт нестандартный
# По умолчанию — root@<ROUTER_IP> из ROUTER_IP/ROUTER_PORT, как в scripts/speedtest.sh.
set -euo pipefail

# Git Bash иначе перепишет /opt/bin/sh в C:/Program Files/... — путь уедет в Windows
export MSYS_NO_PATHCONV=1
# /bin/sh на Keenetic — это ndmsh (CLI роутера), он не понимает `-s`; нужен busybox из Entware
REMOTE_SH="/opt/bin/sh"

TARGET=""
SSH_HOST="${ROUTER_SSH:-}"
DV_REF=""

while [ $# -gt 0 ]; do
  case "$1" in
    --host) SSH_HOST="$2"; shift 2 ;;
    --ref) DV_REF="$2"; shift 2 ;;
    -h|--help)
      echo "использование: verdict.sh <домен|URL> [--host <ssh-цель>] [--ref <хост>]"
      echo "цель роутера: --host, либо ROUTER_SSH, либо ROUTER_IP (+ROUTER_PORT)"; exit 0 ;;
    *) TARGET="$1"; shift ;;
  esac
done

# ssh-цель: явный алиас перекрывает всё; иначе собираем из ROUTER_IP/ROUTER_PORT
SSH_OPTS="-o ConnectTimeout=10"
if [ -z "$SSH_HOST" ]; then
  SSH_HOST="root@${ROUTER_IP:-<ROUTER_IP>}"
  SSH_OPTS="$SSH_OPTS -p ${ROUTER_PORT:-222}"
elif [ -n "${ROUTER_PORT:-}" ]; then
  SSH_OPTS="$SSH_OPTS -p $ROUTER_PORT"
fi

if [ -z "$TARGET" ]; then
  echo "нужен домен или URL. пример: verdict.sh https://example.com/path" >&2
  exit 2
fi

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
SCRIPT="$ROOT/tools/domain-verdict/domain-verdict.sh"
[ -r "$SCRIPT" ] || { echo "не найден $SCRIPT" >&2; exit 1; }

# LF-нормализация на лету: CRLF в heredoc роняет busybox sh
tr -d '\r' < "$SCRIPT" | ssh $SSH_OPTS "$SSH_HOST" "DV_TARGET='$TARGET' DV_REF='$DV_REF' $REMOTE_SH -s"
