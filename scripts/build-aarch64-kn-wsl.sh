#!/usr/bin/env bash
set -euo pipefail

# fnm (node version manager) — нужен node >=20 для vite 7
FNM_PATH="${HOME}/.local/share/fnm"
if [ -d "$FNM_PATH" ]; then
  export PATH="$FNM_PATH:$PATH"
  eval "$(fnm env --shell bash)"
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="$ROOT_DIR/config/entware/aarch64-3.10_kn.config"
BUILD_DIR="$ROOT_DIR/.build/entware_aarch64-3.10_kn"

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
  GOMIPS= \
  GOARM= \
  GO386=

make -o build prepare_files \
  PLATFORM="${PLATFORM}" \
  TARGET="${TARGET}" \
  GOOS="${GOOS}" \
  GOARCH="${GOARCH}" \
  GOMIPS= \
  GOARM= \
  GO386=

make -o build -o prepare_files package \
  PLATFORM="${PLATFORM}" \
  TARGET="${TARGET}" \
  GOOS="${GOOS}" \
  GOARCH="${GOARCH}" \
  GOMIPS= \
  GOARM= \
  GO386=
