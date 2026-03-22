#!/bin/sh
export PKG_UPGRADE=1
[ "${IPKG_NO_SCRIPT}" = "1" ] && exit 0
[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. ${IPKG_INSTROOT}/lib/functions.sh
export root="${IPKG_INSTROOT}"
export pkgname="magitrickle"
add_group_and_user
default_postinst

# Optional: install TPROXY dependencies (best-effort)
if command -v apk >/dev/null 2>&1; then
  apk add kmod-nft-tproxy kmod-nft-socket iptables-mod-tproxy iptables-mod-socket 2>/dev/null || true
fi
