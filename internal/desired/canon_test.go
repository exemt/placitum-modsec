/*
 * Канон config_hash профилей: инспектор и контроллер обязаны получить из
 * одного дерева один hex.
 *
 * Пара к нему -- controller/src/convergence/canon.test.ts. Оба читают одну
 * фикстуру и сверяются с одним прибитым числом. Это то место, где реализации
 * расходятся молча -- на экранировании < и &, на BOM, на CRLF, -- и такое
 * расхождение нигде не падает: оно просто навсегда оставляет флот в drift.
 */

package desired

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// canonFixture лежит в корне репозитория намеренно: файл один на обе
// реализации, и копия у каждой означала бы, что расходиться они начнут с
// копий, а не с канона.
const canonFixture = "../../../../tests/fixtures/profiles-canon.json"

type canonDoc struct {
	Expect   string             `json:"expect"`
	Profiles map[string]Profile `json:"profiles"`
}

/*
 * readCanon читает фикстуру. Её не оказалось рядом — пропуск, а не падение:
 * модуль собирается образом со своим контекстом (deploy/Dockerfile), корня
 * репозитория в нём нет, и падать здесь значило бы, что образ инспектора
 * нельзя собрать из-за файла, которого в нём и не должно быть.
 *
 * Проверка от этого не исчезает. Пара к ней —
 * controller/src/convergence/canon.test.ts — читает ту же фикстуру и пропуска
 * не знает: пропадёт файл из репозитория, упадёт там, громко. Здесь же пропуск
 * узкий, только на «файла нет»: любая другая беда чтения — по-прежнему отказ,
 * потому что она означает испорченный, а не отсутствующий канон.
 */
func readCanon(t *testing.T) canonDoc {
	t.Helper()

	body, err := os.ReadFile(filepath.FromSlash(canonFixture))
	if errors.Is(err, fs.ErrNotExist) {
		t.Skipf("канон не проверяется: прогон вне корня репозитория, нет %s", canonFixture)
	}

	if err != nil {
		t.Fatalf("фикстура канона не читается: %v", err)
	}

	var doc canonDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("фикстура канона не разбирается: %v", err)
	}

	if doc.Expect == "" {
		t.Fatal("в фикстуре не прибит ожидаемый хеш")
	}

	return doc
}

func TestCanonMatchesController(t *testing.T) {
	doc := readCanon(t)

	if got := Hash(doc.Profiles); got != doc.Expect {
		t.Fatalf("канон разъехался с контроллером:\n  инспектор  %s\n  контроллер %s", got, doc.Expect)
	}
}

func TestCanonIgnoresProfileOrder(t *testing.T) {
	// В Go порядок ключей карты не определён вовсе, поэтому сортировка имён --
	// не украшение: без неё хеш плавал бы от запуска к запуску.
	doc := readCanon(t)

	for i := 0; i < 8; i++ {
		if got := Hash(doc.Profiles); got != doc.Expect {
			t.Fatalf("хеш поплыл на проходе %d: %s", i, got)
		}
	}
}

func TestCanonSeesFileOrder(t *testing.T) {
	// Порядок Include в SecLang значим, и канон обязан это видеть.
	doc := readCanon(t)

	profile := doc.Profiles["default"]
	if len(profile.Files) < 2 {
		t.Fatal("фикстура обмельчала: в default нужно минимум два файла")
	}

	swapped := make([]File, len(profile.Files))
	for i, file := range profile.Files {
		swapped[len(profile.Files)-1-i] = file
	}

	mixed := map[string]Profile{}
	for name, row := range doc.Profiles {
		mixed[name] = row
	}
	mixed["default"] = Profile{Files: swapped}

	if got := Hash(mixed); got == doc.Expect {
		t.Fatal("перестановка файлов не изменила хеш")
	}
}
