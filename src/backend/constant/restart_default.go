//go:build !entware && !openwrt

package constant

// RestartCommand returns shell command (sh -c) that restarts magitrickle service.
// Default: systemd.
const RestartCommand = "systemctl restart magitrickle"
