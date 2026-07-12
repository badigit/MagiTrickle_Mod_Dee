package magitrickle

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
)

// TestMain глушит zerolog ниже Warn на время тест-бинаря пакета. Без этого
// debug-строки RebuildTrie ("trie rebuilt") сыпались в stdout и перемешивались
// с выводом бенчмарков (selectUpstream), портя строки результатов. Warn/Error
// остаются видимыми — реальные проблемы в тестах не прячем.
func TestMain(m *testing.M) {
	zerolog.SetGlobalLevel(zerolog.WarnLevel)
	os.Exit(m.Run())
}
