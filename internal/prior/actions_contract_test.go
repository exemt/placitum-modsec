/*
 * Наш словарь действий против схемы провода, по образцу такого же теста у
 * капчи. Расходятся такие копии не в момент правки, а через два месяца после
 * неё: словарь расширят в модуле и в схеме, а здесь забудут, и правило с новым
 * глаголом перестанет грузиться без единой ошибки.
 *
 * Схема лежит в дереве репозитория, а не в модуле Go. Прогон из распакованного
 * контейнера, где смонтирован только inspectors/modsec, её не увидит -- тогда
 * тест честно пропускается.
 */

package prior

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/exemt/placitum-modsec/internal/protocol"
)

type wireAction struct {
	Properties struct {
		Do    struct{ Enum []string } `json:"do"`
		Apply struct{ Enum []string } `json:"apply"`
	} `json:"properties"`

	AllOf []struct {
		If struct {
			Properties struct {
				Do struct {
					Const string `json:"const"`
				} `json:"do"`
			} `json:"properties"`
		} `json:"if"`

		Then struct {
			Properties struct {
				Apply struct {
					Const string   `json:"const"`
					Enum  []string `json:"enum"`
				} `json:"apply"`
			} `json:"properties"`
		} `json:"then"`
	} `json:"allOf"`
}

// wire находит контракт, поднимаясь от пакета к корню дерева.
func wire(t *testing.T) wireAction {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 8; i++ {
		path := filepath.Join(dir, "docs", "messages", "inspector.schema.json")

		raw, err := os.ReadFile(path)
		if err == nil {
			var doc struct {
				Defs struct {
					Action wireAction `json:"action"`
				} `json:"$defs"`
			}

			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("%s: %v", path, err)
			}

			return doc.Defs.Action
		}

		up := filepath.Dir(dir)
		if up == dir {
			break
		}

		dir = up
	}

	t.Skip("docs/messages/inspector.schema.json недоступна: контракта в этом дереве нет")

	return wireAction{}
}

// Наши константы -- ровно те слова, что принимает провод: и применяемые нами
// threshold со skip, и остальные, которыми называются чужие просьбы в аудите.
func TestVerbsAndAxesMatchTheWire(t *testing.T) {
	action := wire(t)

	ours := []string{
		protocol.DoChallenge, protocol.DoThreshold,
		protocol.DoSkip, protocol.DoReauth, protocol.DoNote,
		protocol.DoMutate,
		protocol.DoActive, protocol.DoPassive, protocol.DoOff, protocol.DoVote,
		protocol.DoAudit, protocol.DoArchive, protocol.DoMark,
		protocol.DoScore, protocol.DoBan,
	}

	assertSameSet(t, "глаголы", ours, action.Properties.Do.Enum)

	axes := []string{
		protocol.ApplyRequest, protocol.ApplyIP,
		protocol.ApplyASN, protocol.ApplySession,
		protocol.ApplyConn, protocol.ApplyResponse,
	}

	assertSameSet(t, "оси", axes, action.Properties.Apply.Enum)
}

// У обоих наших глаголов провод обещает единственную ось -- этот запрос.
// Валидация правила стоит ровно на этом обещании: появись у threshold другая
// ось, правило с ней перестало бы грузиться не потому, что оно неверное, а
// потому, что здесь забыли строчку.
func TestOurVerbsAreRequestOnly(t *testing.T) {
	action := wire(t)

	for _, verb := range []string{protocol.DoThreshold, protocol.DoSkip} {
		found := false

		for _, block := range action.AllOf {
			if block.If.Properties.Do.Const != verb {
				continue
			}

			found = true

			want := block.Then.Properties.Apply.Enum
			if c := block.Then.Properties.Apply.Const; c != "" {
				want = []string{c}
			}

			assertSameSet(t, "оси "+verb, []string{protocol.ApplyRequest}, want)
		}

		if !found {
			t.Errorf("провод не ограничивает оси %q -- матрица разъехалась", verb)
		}
	}
}

func assertSameSet(t *testing.T, what string, got, want []string) {
	t.Helper()

	a := append([]string(nil), got...)
	b := append([]string(nil), want...)

	sort.Strings(a)
	sort.Strings(b)

	if len(a) != len(b) {
		t.Fatalf("%s: у нас %v, на проводе %v", what, a, b)
	}

	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("%s: у нас %v, на проводе %v", what, a, b)
		}
	}
}
