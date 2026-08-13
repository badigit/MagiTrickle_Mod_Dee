//go:build linux || darwin
// +build linux darwin

package main

import "testing"

// Регрессия: после atomic replace бинарника (именно так opkg ставит пакет
// поверх ещё живого процесса) ядро меняет /proc/<pid>/exe у старого процесса
// на "<путь> (deleted)", хотя это тот же самый запущенный бинарник. Проверено
// живым экспериментом на проде (2026-07-26): cp+mv поверх
// работающего magitrickled -> readlink /proc/$PID/exe стал показывать суффикс
// " (deleted)" при байт-в-байт идентичном содержимом файла.
func TestSameBinary(t *testing.T) {
	cases := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{"identical paths", "/opt/bin/magitrickled", "/opt/bin/magitrickled", true},
		{"old process after opkg replaced binary", "/opt/bin/magitrickled (deleted)", "/opt/bin/magitrickled", true},
		{"both deleted", "/opt/bin/magitrickled (deleted)", "/opt/bin/magitrickled (deleted)", true},
		{"different binaries", "/opt/bin/magitrickled", "/opt/bin/other-daemon", false},
		{"different binary, one deleted", "/opt/bin/magitrickled (deleted)", "/opt/bin/other-daemon", false},
		{"empty vs real (failed readlink)", "", "/opt/bin/magitrickled", false},
		{"both empty", "", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameBinary(tc.a, tc.b); got != tc.want {
				t.Errorf("sameBinary(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
