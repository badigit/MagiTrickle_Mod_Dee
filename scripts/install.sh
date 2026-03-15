#!/bin/sh
set -e

# MagiTrickle (badigit fork) — install/update script
# Usage:
#   opkg update && opkg install wget-ssl ca-certificates
#   wget -qO- https://raw.githubusercontent.com/badigit/MagiTrickle_mod_badigit/mod_badigit/scripts/install.sh | sh

REPO="badigit/MagiTrickle_mod_badigit"
API_URL="https://api.github.com/repos/${REPO}/releases/latest"
TMP_DIR="/opt/root/tmp"

echo "=== MagiTrickle (badigit) installer ==="

# Detect platform
if [ ! -f /opt/etc/entware_release ]; then
  echo "Error: Entware not found." >&2
  exit 1
fi

# Check wget-ssl
if ! wget --help 2>&1 | grep -qi 'https'; then
  echo "Error: wget-ssl required. Run first:" >&2
  echo "  opkg update && opkg install wget-ssl ca-certificates" >&2
  exit 1
fi

# Detect architecture
ARCH=""
for a in $(/opt/bin/opkg print-architecture | awk '{print $2}'); do
  case "$a" in
    aarch64-3.10_kn) ARCH="aarch64-3.10_kn"; break ;;
    mipsel-3.4_kn)   ARCH="mipsel-3.4_kn";   break ;;
    aarch64-3.10)     ARCH="aarch64-3.10_kn"  ;;
    mipsel-3.4)       ARCH="mipsel-3.4_kn"    ;;
  esac
done

if [ -z "$ARCH" ]; then
  echo "Error: unsupported architecture" >&2
  /opt/bin/opkg print-architecture >&2
  exit 1
fi

echo "Architecture: ${ARCH}"

# Get latest release info
echo "Fetching latest release..."
RELEASE_JSON=$(wget -qO- "$API_URL") || {
  echo "Error: failed to fetch release info from GitHub" >&2
  exit 1
}

# Parse download URL for our architecture
DL_URL=$(echo "$RELEASE_JSON" | grep -o "\"browser_download_url\"[[:space:]]*:[[:space:]]*\"[^\"]*${ARCH}[^\"]*\.ipk\"" | head -1 | grep -o 'https://[^"]*')

if [ -z "$DL_URL" ]; then
  echo "Error: no ipk found for ${ARCH} in latest release" >&2
  echo "Check: https://github.com/${REPO}/releases/latest" >&2
  exit 1
fi

FILENAME=$(basename "$DL_URL")
echo "Package: ${FILENAME}"

# Download
mkdir -p "$TMP_DIR"
IPK_PATH="${TMP_DIR}/${FILENAME}"
echo "Downloading..."
wget -qO "$IPK_PATH" "$DL_URL" || {
  echo "Error: download failed" >&2
  exit 1
}

# Install
echo "Installing..."
/opt/bin/opkg install --force-reinstall "$IPK_PATH"

# Restart
if [ -x /opt/etc/init.d/S99magitrickle ]; then
  /opt/etc/init.d/S99magitrickle restart 2>/dev/null || /opt/etc/init.d/S99magitrickle start
fi

# Cleanup
rm -f "$IPK_PATH"

echo ""
echo "=== Done! ==="
