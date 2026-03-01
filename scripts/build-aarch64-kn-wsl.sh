#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="$ROOT_DIR/config/entware/aarch64-3.10_kn.config"
BUILD_DIR="$ROOT_DIR/.build/entware_aarch64-3.10_kn"
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
  GOMIPS= \
  GOARM= \
  GO386=

mkdir -p "$SKIN_DIR"
cp -r "$ROOT_DIR/src/frontend/dist/"* "$SKIN_DIR/"

make package \
  PLATFORM="${PLATFORM}" \
  TARGET="${TARGET}" \
  GOOS="${GOOS}" \
  GOARCH="${GOARCH}" \
  GOMIPS= \
  GOARM= \
  GO386=
