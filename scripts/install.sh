#!/bin/sh
set -e

# MagiTrickle (badigit fork) — universal install/update script
# Supports: Entware (Keenetic), OpenWrt (opkg), OpenWrt 25+ (apk)
#
# Usage:
#   wget -qO- https://raw.githubusercontent.com/badigit/MagiTrickle_mod_badigit/mod_badigit/scripts/install.sh | sh
#   or:
#   curl -fsSL https://raw.githubusercontent.com/badigit/MagiTrickle_mod_badigit/mod_badigit/scripts/install.sh | sh

REPO="badigit/MagiTrickle_mod_badigit"
API_URL="https://api.github.com/repos/${REPO}/releases/latest"
TMP_DIR="/tmp"

echo "=== MagiTrickle (badigit) installer ==="

# --- Download helper (wget / curl / uclient-fetch) ---

download() {
  local url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -Lf --retry 3 --retry-delay 2 -o "$dest" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$dest" "$url"
  elif command -v uclient-fetch >/dev/null 2>&1; then
    uclient-fetch -qO "$dest" "$url"
  else
    echo "Error: no download tool found (curl, wget, uclient-fetch)" >&2
    exit 1
  fi
}

download_stdout() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "$url"
  elif command -v uclient-fetch >/dev/null 2>&1; then
    uclient-fetch -qO- "$url"
  else
    echo "Error: no download tool found (curl, wget, uclient-fetch)" >&2
    exit 1
  fi
}

# --- Detect platform and architecture ---

PLATFORM=""
ARCH=""
PKG_EXT=""

if [ -f /opt/etc/entware_release ]; then
  # Entware (Keenetic and others)
  PLATFORM="entware"
  PKG_EXT="ipk"
  for a in $(/opt/bin/opkg print-architecture | awk '{print $2}'); do
    case "$a" in
      aarch64-3.10_kn) ARCH="aarch64-3.10_kn"; break ;;
      mipsel-3.4_kn)   ARCH="mipsel-3.4_kn";   break ;;
      mips-3.4_kn)     ARCH="mips-3.4_kn";      break ;;
      aarch64-3.10)    ARCH="aarch64-3.10_kn"  ;;
      mipsel-3.4)      ARCH="mipsel-3.4_kn"    ;;
      mips-3.4)        ARCH="mips-3.4_kn"      ;;
    esac
  done

elif [ -f /etc/openwrt_release ]; then
  # OpenWrt
  ARCH=$(. /etc/os-release 2>/dev/null && echo "$OPENWRT_ARCH" || grep "OPENWRT_ARCH" /etc/os-release 2>/dev/null | cut -d'"' -f2)

  if command -v apk >/dev/null 2>&1; then
    PLATFORM="openwrt_apk"
    PKG_EXT="apk"
  else
    PLATFORM="openwrt_opkg"
    PKG_EXT="ipk"
  fi

else
  echo "Error: unsupported platform (neither Entware nor OpenWrt found)" >&2
  exit 1
fi

if [ -z "$ARCH" ]; then
  echo "Error: could not detect architecture" >&2
  exit 1
fi

echo "Platform: ${PLATFORM}"
echo "Architecture: ${ARCH}"

# --- Fetch latest release from GitHub API ---

echo "Fetching latest release..."
RELEASE_JSON=$(download_stdout "$API_URL") || {
  echo "Error: failed to fetch release info from GitHub" >&2
  exit 1
}

# --- Find download URL ---

case "$PLATFORM" in
  entware)
    # Match: *_entware_${ARCH}.ipk
    DL_URL=$(echo "$RELEASE_JSON" | grep -o "\"browser_download_url\"[[:space:]]*:[[:space:]]*\"[^\"]*_entware_${ARCH}\.ipk\"" | head -1 | grep -o 'https://[^"]*')
    ;;
  openwrt_apk)
    # Match: *_openwrt_${ARCH}.apk
    DL_URL=$(echo "$RELEASE_JSON" | grep -o "\"browser_download_url\"[[:space:]]*:[[:space:]]*\"[^\"]*_openwrt_${ARCH}\.apk\"" | head -1 | grep -o 'https://[^"]*')
    ;;
  openwrt_opkg)
    # Match: *_openwrt_${ARCH}.ipk
    DL_URL=$(echo "$RELEASE_JSON" | grep -o "\"browser_download_url\"[[:space:]]*:[[:space:]]*\"[^\"]*_openwrt_${ARCH}\.ipk\"" | head -1 | grep -o 'https://[^"]*')
    ;;
esac

if [ -z "$DL_URL" ]; then
  echo "Error: no package found for ${PLATFORM}/${ARCH} in latest release" >&2
  echo "Check: https://github.com/${REPO}/releases/latest" >&2
  exit 1
fi

FILENAME=$(basename "$DL_URL")
echo "Package: ${FILENAME}"

# --- Download ---

PKG_PATH="${TMP_DIR}/${FILENAME}"
echo "Downloading..."
download "$DL_URL" "$PKG_PATH" || {
  echo "Error: download failed" >&2
  exit 1
}

# --- Install ---

echo "Installing..."
case "$PLATFORM" in
  entware)
    /opt/bin/opkg install --force-reinstall "$PKG_PATH"
    ;;
  openwrt_apk)
    apk add --allow-untrusted "$PKG_PATH"
    ;;
  openwrt_opkg)
    opkg install --force-reinstall "$PKG_PATH"
    ;;
esac

# --- Restart service ---

if [ -x /opt/etc/init.d/S99magitrickle ]; then
  /opt/etc/init.d/S99magitrickle restart 2>/dev/null || /opt/etc/init.d/S99magitrickle start
elif [ -x /etc/init.d/magitrickle ]; then
  /etc/init.d/magitrickle restart 2>/dev/null || /etc/init.d/magitrickle start
fi

# --- Cleanup ---

rm -f "$PKG_PATH"

echo ""
echo "=== Done! ==="
echo "Web UI: http://$(hostname -i 2>/dev/null || echo '<router-ip>'):8080"
