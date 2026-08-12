package magitrickle

import (
	"testing"

	"magitrickle/constant"
	"magitrickle/models"
)

// TestNormalizeDirectPriority — незнакомый режим арбитража direct не должен
// молча менять маршрутизацию: любое значение вне известных падает в absolute
// (дефолт, при котором direct перебивает все группы). Кейс реальный: опечатка
// в YAML руками или конфиг, приехавший от более новой версии.
func TestNormalizeDirectPriority(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{models.DirectPriorityAbsolute, models.DirectPriorityAbsolute},
		{models.DirectPriorityByOrder, models.DirectPriorityByOrder},
		{"", models.DirectPriorityAbsolute},
		{"byorder", models.DirectPriorityAbsolute},  // регистр значим
		{"by-order", models.DirectPriorityAbsolute}, // другой разделитель
		{"мусор", models.DirectPriorityAbsolute},
	}
	for _, c := range cases {
		if got := normalizeDirectPriority(c.in); got != c.want {
			t.Errorf("normalizeDirectPriority(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestDefaultDirectPriorityIsAbsolute — дефолт обязан сохранять поведение
// с .15: без настройки в конфиге direct остаётся абсолютным приоритетом.
// Иначе обновление демона молча поменяло бы маршрутизацию на всех роутерах.
func TestDefaultDirectPriorityIsAbsolute(t *testing.T) {
	if got := constant.DefaultAppConfig.Netfilter.DirectPriority; got != models.DirectPriorityAbsolute {
		t.Errorf("default DirectPriority = %q, want %q", got, models.DirectPriorityAbsolute)
	}
}
