package prior

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/exemt/placitum-modsec/internal/protocol"
)

func policyWith(t *testing.T, body string) (Policy, error) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, FileName)

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return Load(path)
}

func TestOutcomeAccepts(t *testing.T) {
	cases := map[string]string{
		"ask over the threshold": "outcomes:\n  - {on: score, at: 30, to: captcha, do: challenge}\n",
		"ask under it":           "outcomes:\n  - {on: score, at: 5, below: true, to: vlai, do: skip}\n",
		"ask on allow":           "outcomes:\n  - {on: allow, to: vlai, do: threshold, delta: -50}\n",
		"note with axis": "outcomes:\n  - {on: score, at: 20, to: captcha, do: note, " +
			"apply: asn, value: 25}\n",
		"list the address": "outcomes:\n  - {on: deny, list: hot, write: addr, ttl: 1h}\n",
		"list the prefix":  "outcomes:\n  - {on: deny, list: hot, write: net, ttl: 15m}\n",
		"list the system":  "outcomes:\n  - {on: deny, list: hot, write: asn, ttl: 1d}\n",
		"write defaults to addr": "outcomes:\n  - {on: score, at: 50, list: hot, ttl: 1h, " +
			"code: MODSEC_HOT}\n",
		"both sides of the channel": "prior:\n  - {from: ip, accept: [threshold]}\n" +
			"outcomes:\n  - {on: allow, to: captcha, do: challenge}\n",
		"ask on overload": "outcomes:\n  - {on: overload, to: counter, do: note, apply: ip, value: 20}\n",
		// Переключить группу модификаторов у rewrite: группа и сторона обе.
		"mutate group":     "outcomes:\n  - {on: score, at: 40, to: rewrite, do: mutate, group: mask, set: on}\n",
		"list on overload": "outcomes:\n  - {on: overload, list: hot, write: addr, ttl: 10m}\n",
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := policyWith(t, body); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}

func TestOutcomeRejects(t *testing.T) {
	cases := map[string]string{
		// Триггер и его порог.
		"unknown on":           "outcomes:\n  - {on: sneeze, list: x, ttl: 1h}\n",
		"mutate without group": "outcomes:\n  - {on: allow, to: rewrite, do: mutate, set: on}\n",
		"mutate without set":   "outcomes:\n  - {on: allow, to: rewrite, do: mutate, group: mask}\n",
		"group on skip":        "outcomes:\n  - {on: allow, to: vlai, do: skip, group: mask}\n",
		"score without at":     "outcomes:\n  - {on: score, list: x, ttl: 1h}\n",
		"at without score":     "outcomes:\n  - {on: allow, at: 30, list: x, ttl: 1h}\n",
		"negative at":          "outcomes:\n  - {on: score, at: -1, list: x, ttl: 1h}\n",
		"below on deny":        "outcomes:\n  - {on: deny, below: true, list: x, ttl: 1h}\n",
		"at on overload":       "outcomes:\n  - {on: overload, at: 30, list: x, ttl: 1h}\n",

		// Действие: ровно одно, и оно осмысленное.
		"neither do nor list": "outcomes:\n  - {on: allow}\n",
		"both do and list": "outcomes:\n  - {on: allow, to: captcha, do: challenge, list: x, " +
			"ttl: 1h}\n",
		"list without ttl":        "outcomes:\n  - {on: allow, list: x}\n",
		"unknown write":           "outcomes:\n  - {on: allow, list: x, ttl: 1h, write: soul}\n",
		"unknown verb":            "outcomes:\n  - {on: allow, to: captcha, do: nuke}\n",
		"bad axis":                "outcomes:\n  - {on: allow, to: captcha, do: challenge, apply: asn}\n",
		"note without axis":       "outcomes:\n  - {on: allow, to: captcha, do: note, value: 10}\n",
		"threshold without delta": "outcomes:\n  - {on: allow, to: vlai, do: threshold}\n",
		"threshold zero delta":    "outcomes:\n  - {on: allow, to: vlai, do: threshold, delta: 0}\n",
		"delta out of range":      "outcomes:\n  - {on: allow, to: vlai, do: threshold, delta: 1000}\n",
		"bad code":                "outcomes:\n  - {on: allow, list: x, ttl: 1h, code: \"плохо\"}\n",

		// Просьба на отказе: deny обрывает фазу, доехать ей некуда.
		"ask on deny": "outcomes:\n  - {on: deny, to: captcha, do: challenge}\n",
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := policyWith(t, body); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// Ошибка называет строку, которую правил оператор.
func TestOutcomeErrorNamesTheRow(t *testing.T) {
	_, err := policyWith(t, "outcomes:\n  - {on: allow, list: x}\n")
	if err == nil {
		t.Fatal("accepted")
	}

	if !strings.Contains(err.Error(), "outcomes[0]") {
		t.Fatalf("error does not name the row: %v", err)
	}
}

// Прежнее имя файла читается одно поколение: файлы с ним лежат на нодах.
func TestLoadDirReadsLegacyName(t *testing.T) {
	dir := t.TempDir()
	body := "prior:\n  - {from: ip, accept: [skip]}\n"

	if err := os.WriteFile(filepath.Join(dir, LegacyFileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	var warned string

	policy, err := LoadDir(dir, func(file string) { warned = file })
	if err != nil {
		t.Fatal(err)
	}

	if len(policy.Rules) != 1 || warned != LegacyFileName {
		t.Fatalf("policy = %+v, warned = %q", policy, warned)
	}
}

// Новое имя выигрывает: рядом лежащий старый файл не подмешивается.
func TestLoadDirPrefersNewName(t *testing.T) {
	dir := t.TempDir()

	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write(FileName, "outcomes:\n  - {on: deny, list: new, write: addr, ttl: 1h}\n")
	write(LegacyFileName, "outcomes:\n  - {on: deny, list: old, write: addr, ttl: 1h}\n")

	policy, err := LoadDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(policy.Outcomes) != 1 || policy.Outcomes[0].List != "new" {
		t.Fatalf("outcomes = %+v", policy.Outcomes)
	}
}

func TestOutcomeMatches(t *testing.T) {
	at := 30
	over := Outcome{On: OnScore, At: &at}
	under := Outcome{On: OnScore, At: &at, Below: true}

	cases := []struct {
		name    string
		outcome Outcome
		verdict string
		score   int
		want    bool
	}{
		{"at the threshold", over, protocol.VerdictScore, 30, true},
		{"above it", over, protocol.VerdictScore, 90, true},
		{"below it", over, protocol.VerdictScore, 29, false},
		{"under matches", under, protocol.VerdictScore, 29, true},
		{"under ignores equal", under, protocol.VerdictScore, 30, false},
		{"score rule ignores allow", over, protocol.VerdictAllow, 90, false},
		{"deny matches deny", Outcome{On: OnDeny}, protocol.VerdictDeny, 0, true},
		// Редирект -- тоже вмешательство движка: фаза кончилась отказом.
		{"deny matches redirect", Outcome{On: OnDeny}, protocol.VerdictRedirect, 0, true},
		{"allow matches allow", Outcome{On: OnAllow}, protocol.VerdictAllow, 0, true},
		{"allow ignores score", Outcome{On: OnAllow}, protocol.VerdictScore, 5, false},
		// Перегрузка -- строка триггера, а не вердикт: снятие с allow-ответом
		// не дёргает on: allow, и наоборот.
		{"overload matches the trigger", Outcome{On: OnOverload}, OnOverload, 0, true},
		{"overload ignores allow", Outcome{On: OnOverload}, protocol.VerdictAllow, 0, false},
		{"allow ignores overload", Outcome{On: OnAllow}, OnOverload, 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.outcome.Matches(tc.verdict, tc.score); got != tc.want {
				t.Fatalf("matches = %v, want %v", got, tc.want)
			}
		})
	}
}

// clientIP -- адрес запроса: подсеть и систему по нему разворачивает
// обработчик у кодера, Fire называет только охват.
const clientIP = "203.0.113.7"

func TestFireAsk(t *testing.T) {
	policy, err := policyWith(t,
		"outcomes:\n  - {on: score, at: 30, to: captcha, do: challenge}\n")
	if err != nil {
		t.Fatal(err)
	}

	fired := Fire(policy.Outcomes, protocol.VerdictScore, 45, clientIP, "CRS_ANOMALY")

	if len(fired.Actions) != 1 || len(fired.Bans) != 0 {
		t.Fatalf("fired = %+v", fired)
	}

	got := fired.Actions[0]

	if got.To != "captcha" || got.Do != protocol.DoChallenge || got.Apply != protocol.ApplyRequest {
		t.Fatalf("action = %+v", got)
	}

	// Повод свой не назван -- едет код решения: иначе по записи не понять, на
	// чём инициатор сработал.
	if got.Code != "CRS_ANOMALY" {
		t.Fatalf("code = %q", got.Code)
	}
}

// Кого писать в набор -- решает строка: адрес меняется дешевле всего, анонс
// уже нет, а система целиком -- решение другого масштаба. Разворачивает их
// обработчик у кодера; Fire называет охват и адрес.
func TestFireWritesSubject(t *testing.T) {
	for _, write := range []string{WriteAddr, WriteNet, WriteNetAll, WriteASN} {
		t.Run("write "+write, func(t *testing.T) {
			policy, err := policyWith(t,
				"outcomes:\n  - {on: deny, list: hot, write: "+write+", ttl: 1h}\n")
			if err != nil {
				t.Fatal(err)
			}

			fired := Fire(policy.Outcomes, protocol.VerdictDeny, 0, clientIP, "MODSEC_DENY")

			if len(fired.Bans) != 1 {
				t.Fatalf("bans = %+v", fired.Bans)
			}

			ban := fired.Bans[0]

			if ban.Write != write || ban.Addr != clientIP || ban.TTL != 3600 {
				t.Fatalf("ban = %+v, want write %q for %s", ban, write, clientIP)
			}
		})
	}
}

// Без адреса писать некого -- ни сам адрес, ни его подсеть: сообщение пробы.
func TestFireWithoutAddress(t *testing.T) {
	policy, err := policyWith(t, "outcomes:\n"+
		"  - {on: deny, list: net, write: net_all, ttl: 1h}\n"+
		"  - {on: deny, list: addr, write: addr, ttl: 1h}\n")
	if err != nil {
		t.Fatal(err)
	}

	if fired := Fire(policy.Outcomes, protocol.VerdictDeny, 0, "", "MODSEC_DENY"); len(fired.Bans) != 0 {
		t.Fatalf("bans = %+v: без адреса писать некого", fired.Bans)
	}
}

// На перегрузке срабатывают только строки on: overload: снятый запрос -- не
// решённый allow, и чужие триггеры молчат.
func TestFireOnOverload(t *testing.T) {
	policy, err := policyWith(t, "outcomes:\n"+
		"  - {on: overload, list: hot, write: addr, ttl: 10m}\n"+
		"  - {on: overload, to: counter, do: note, apply: ip, value: 20}\n"+
		"  - {on: allow, to: captcha, do: challenge}\n")
	if err != nil {
		t.Fatal(err)
	}

	fired := Fire(policy.Outcomes, OnOverload, 0, clientIP, "MODSEC_QUEUE_LIMIT")

	if len(fired.Bans) != 1 || len(fired.Actions) != 1 {
		t.Fatalf("fired = %+v", fired)
	}

	if fired.Bans[0].Addr != clientIP || fired.Bans[0].Write != WriteAddr ||
		fired.Bans[0].Reason != "MODSEC_QUEUE_LIMIT" {
		t.Fatalf("ban = %+v", fired.Bans[0])
	}

	if fired.Actions[0].Do != protocol.DoNote || fired.Actions[0].Code != "MODSEC_QUEUE_LIMIT" {
		t.Fatalf("action = %+v", fired.Actions[0])
	}
}

// Охваты -- те же слова, что у капчи: net_all загрузчик пропускает, чужое
// слово -- нет, иначе строка молча писала бы адрес вместо подсети.
func TestValidateWrite(t *testing.T) {
	for _, write := range []string{WriteAddr, WriteNet, WriteNetAll, WriteASN} {
		if _, err := policyWith(t,
			"outcomes:\n  - {on: deny, list: hot, write: "+write+", ttl: 1h}\n"); err != nil {
			t.Fatalf("write %s: %v", write, err)
		}
	}

	if _, err := policyWith(t,
		"outcomes:\n  - {on: deny, list: hot, write: country, ttl: 1h}\n"); err == nil {
		t.Fatal("write: country must not load")
	}
}
