package updater

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want int // знак ожидаемого результата: -1, 0, +1
	}{
		{"clean newer patch", "0.5.2-badigit.15", "0.5.2-badigit.14", 1},
		{"clean older patch", "0.5.2-badigit.14", "0.5.2-badigit.15", -1},
		{"clean equal", "0.5.2-badigit.15", "0.5.2-badigit.15", 0},

		// Ключевой кейс: чистый релиз .15 против dev-сборки .15~git на роутере.
		// Числа равны -> pre-release (dev) ниже -> релиз предлагается как новее.
		{"clean beats same-number dev build",
			"0.5.2-badigit.15", "0.5.2-badigit.15~git20260628165258.24c54eb-1", 1},
		{"dev build is older than clean of same number",
			"0.5.2-badigit.15~git20260628165258.24c54eb-1", "0.5.2-badigit.15", -1},

		// Следующий чистый релиз новее dev-сборки предыдущего номера.
		{"next clean beats dev of prev", "0.5.2-badigit.16", "0.5.2-badigit.15~gitabcdef", 1},

		// Хвост git-хеша больше не протекает в числа как лишний компонент.
		{"dev vs dev same base equal", "0.5.2-badigit.15~gitAAA", "0.5.2-badigit.15~gitBBB", 0},

		{"v-prefix tolerated", "v0.5.2-badigit.15", "0.5.2-badigit.14", 1},
		{"badigit build newer than plain base", "0.5.2-badigit.2", "0.5.2", 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := compareVersions(tc.a, tc.b)
			sign := func(n int) int {
				switch {
				case n > 0:
					return 1
				case n < 0:
					return -1
				default:
					return 0
				}
			}
			if sign(got) != tc.want {
				t.Errorf("compareVersions(%q, %q) = %d (знак %d), ожидали знак %d",
					tc.a, tc.b, got, sign(got), tc.want)
			}
		})
	}
}
