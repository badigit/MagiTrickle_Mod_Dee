#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="$ROOT_DIR/config/entware/mipsel-3.4_kn.config"
BUILD_DIR="$ROOT_DIR/.build/entware_mipsel-3.4_kn"
SKIN_DIR="$BUILD_DIR/data/opt/usr/share/magitrickle/skins/default"
NODE24=(npx -y -p node@24.12.0 node)
NPM_CLI="/usr/share/nodejs/npm/bin/npm-cli.js"

cd "$ROOT_DIR"

while IFS='=' read -r key value; do
  [[ -n "${key}" ]] || continue
  export "${key}=${value}"
done < <(tr -d '\r' < "$CONFIG_FILE")

rm -rf "$BUILD_DIR"

pushd "$ROOT_DIR/src/frontend" >/dev/null
"${NODE24[@]}" "$NPM_CLI" install
"${NODE24[@]}" "$NPM_CLI" run build
popd >/dev/null

make build_backend \
  PLATFORM="${PLATFORM}" \
  TARGET="${TARGET}" \
  GOOS="${GOOS}" \
  GOARCH="${GOARCH}" \
  GOMIPS="${GOMIPS}" \
  GOARM= \
  GO386=

# Помечаем фронтенд как собранный, чтобы make package не пересобирал
# через системный node (который слишком старый для vite 7)
mkdir -p "$ROOT_DIR/.build/.stamps"
touch "$ROOT_DIR/.build/.stamps/build-frontend" \
      "$ROOT_DIR/.build/.stamps/download-frontend" \
      "$ROOT_DIR/.build/.stamps/build-properties-frontend"

make package \
  PLATFORM="${PLATFORM}" \
  TARGET="${TARGET}" \
  GOOS="${GOOS}" \
  GOARCH="${GOARCH}" \
  GOMIPS="${GOMIPS}" \
  GOARM= \
  GO386=
