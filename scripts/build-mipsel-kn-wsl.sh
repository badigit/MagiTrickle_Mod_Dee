#!/usr/bin/env bash
set -euo pipefail

# Если запущено из Git Bash (MSYS2/MinGW) — перезапуск через WSL,
# где есть make и Linux-окружение для кросс-компиляции.
if [[ "${MSYSTEM:-}" == MINGW* ]]; then
  ROOT_WIN="$(cygpath -w "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)")"
  SCRIPT_REL="scripts/$(basename "${BASH_SOURCE[0]}")"
  echo "[wrapper] Re-launching under WSL: $SCRIPT_REL"
  exec wsl --cd "$ROOT_WIN" -- bash "$SCRIPT_REL" "$@"
fi

# fnm (node version manager) — нужен node >=20 для vite 7
# Стандартная установка: бинарник в ~/.local/bin/fnm, данные в ~/.local/share/fnm/.
FNM_BIN_DIR="${HOME}/.local/bin"
if [ -x "$FNM_BIN_DIR/fnm" ]; then
  export PATH="$FNM_BIN_DIR:$PATH"
  eval "$(fnm env --shell bash)"
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="$ROOT_DIR/config/entware/mipsel-3.4_kn.config"
BUILD_DIR="$ROOT_DIR/.build/entware_mipsel-3.4_kn"

cd "$ROOT_DIR"

while IFS='=' read -r key value; do
  [[ -n "${key}" ]] || continue
  export "${key}=${value}"
done < <(tr -d '\r' < "$CONFIG_FILE")

NODE_MAJOR=$(node -v 2>/dev/null | sed 's/v\([0-9]*\).*/\1/')
if [ -z "$NODE_MAJOR" ] || [ "$NODE_MAJOR" -lt 20 ]; then
  echo "ERROR: node >= 20 required (got $(node -v 2>/dev/null || echo 'none')). Install via: fnm install 24" >&2
  exit 1
fi

rm -rf "$BUILD_DIR"

pushd "$ROOT_DIR/src/frontend" >/dev/null
npm install
npm run build
popd >/dev/null

make build_backend \
  PLATFORM="${PLATFORM}" \
  TARGET="${TARGET}" \
  GOOS="${GOOS}" \
  GOARCH="${GOARCH}" \
  GOMIPS="${GOMIPS}" \
  GOARM= \
  GO386=

make -o build prepare_files \
  PLATFORM="${PLATFORM}" \
  TARGET="${TARGET}" \
  GOOS="${GOOS}" \
  GOARCH="${GOARCH}" \
  GOMIPS="${GOMIPS}" \
  GOARM= \
  GO386=

make -o build -o prepare_files package \
  PLATFORM="${PLATFORM}" \
  TARGET="${TARGET}" \
  GOOS="${GOOS}" \
  GOARCH="${GOARCH}" \
  GOMIPS="${GOMIPS}" \
  GOARM= \
  GO386=
