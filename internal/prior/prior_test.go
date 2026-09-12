/*
 * Правила приёма и их применение. Валидация проверяется таблицей: каждое
 * ограничение загрузчика -- строка, и исчезновение любого из них должно падать
 * здесь, а не обнаруживаться обходом защиты на живом трафике.
 */

package prior

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/exemt/placitum-modsec/internal/protocol"
)

func TestValidateTable(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
		ok   bool
	}{
		{"threshold с именем",
			Rule{From: "ip", Accept: []string{"threshold"}}, true},
		{"skip с именем",
			Rule{From: "ip", Accept: []string{"skip"}}, true},
		{"оба глагола разом",
			Rule{From: "action", Accept: []string{"threshold", "skip"}}, true},
		{"мёртвый потолок читается и не значит ничего",
			Rule{From: "ip", Accept: []string{"threshold"}, MaxPercent: 5000}, true},
		{"ось request разрешена явно",
			Rule{From: "ip", Accept: []string{"skip"}, Apply: []string{"request"}}, true},
		{"поводы фильтруют, но не проверяются на словарь",
			Rule{From: "ip", Accept: []string{"skip"}, Codes: []string{"IP_ALLOWLIST"}}, true},

		{"пустой from", Rule{Accept: []string{"skip"}}, false},
		{"пустой accept", Rule{From: "ip"}, false},
		{"незнакомый глагол",
			Rule{From: "ip", Accept: []string{"block"}}, false},
		{"чужой глагол challenge",
			Rule{From: "ip", Accept: []string{"challenge"}}, false},
		{"чужой глагол reauth",
			Rule{From: "ip", Accept: []string{"reauth"}}, false},
		{"чужой глагол note",
			Rule{From: "ip", Accept: []string{"note"}}, false},
		{"ось не для этих глаголов",
			Rule{From: "ip", Accept: []string{"skip"}, Apply: []string{"ip"}}, false},
		{"незнакомая ось",
			Rule{From: "ip", Accept: []string{"skip"}, Apply: []string{"path"}}, false},
		{"широковещательный skip",
			Rule{From: AnyInspector, Accept: []string{"skip"}}, false},
		{"широковещательный threshold",
			Rule{From: AnyInspector, Accept: []string{"threshold"}}, false},
	}

	for _, c := range cases {
		err := validate(0, c.rule)

		if c.ok && err != nil {
			t.Errorf("%s: неожиданный отказ: %v", c.name, err)
		}

		if !c.ok && err == nil {
			t.Errorf("%s: правило принято, а не должно", c.name)
		}
	}
}

func entry(from string, actions ...protocol.Action) protocol.PriorVerdict {
	return protocol.PriorVerdict{
		Phase:     protocol.PhaseRequest,
		Inspector: from,
		Verdict:   protocol.VerdictAllow,
		Actions:   actions,
	}
}

func TestThresholdApplied(t *testing.T) {
	rules := []Rule{{From: "ip", Accept: []string{"threshold"}}}

	ask := Evaluate([]protocol.PriorVerdict{entry("ip", protocol.Action{
		Do: "threshold", Apply: "request", Delta: 30, Code: "IP_ALLOWLIST",
	})}, rules)

	if ask.Percent != 30 || ask.Skip {
		t.Fatalf("ask = %+v, want percent 30 without skip", ask)
	}

	if len(ask.Outcomes) != 1 {
		t.Fatalf("outcomes = %+v", ask.Outcomes)
	}

	out := ask.Outcomes[0]
	if out.Outcome != OutcomeApplied || out.Took != 30 || out.From != "ip" {
		t.Fatalf("outcome = %+v, want applied with took 30", out)
	}
}

// Потолков у правил нет: просьба берётся целиком, числа держит загрузчик
// отправителя. Прижимается только сумма -- к границам коэффициента.
func TestThresholdTakenWhole(t *testing.T) {
	rules := []Rule{{From: "ip", Accept: []string{"threshold"}}}

	ask := Evaluate([]protocol.PriorVerdict{entry("ip", protocol.Action{
		Do: "threshold", Apply: "request", Delta: 500,
	})}, rules)

	if ask.Percent != 500 {
		t.Fatalf("percent = %d, want 500 taken whole", ask.Percent)
	}

	if ask.Outcomes[0].Outcome != OutcomeApplied || ask.Outcomes[0].Took != 500 {
		t.Fatalf("outcome = %+v, want applied with took 500", ask.Outcomes[0])
	}
}

// Знак сохраняется: минусовая дельта -- скидка, и -100 гасит измерение в ноль.
func TestThresholdNegative(t *testing.T) {
	rules := []Rule{{From: "ip", Accept: []string{"threshold"}}}

	ask := Evaluate([]protocol.PriorVerdict{entry("ip", protocol.Action{
		Do: "threshold", Apply: "request", Delta: -100,
	})}, rules)

	if ask.Percent != -100 || ask.Outcomes[0].Outcome != OutcomeApplied {
		t.Fatalf("ask = %+v, want -100 applied", ask)
	}
}

// Без правила просьба не значит ничего, но исход пишется: молчание в ответ на
// просьбу и есть тот случай, который потом разбирают.
func TestNoRuleIsAnOutcome(t *testing.T) {
	ask := Evaluate([]protocol.PriorVerdict{entry("ip", protocol.Action{
		Do: "skip", Apply: "request", Code: "IP_ALLOWLIST",
	})}, nil)

	if ask.Skip {
		t.Fatal("skip прошёл без единого правила")
	}

	if len(ask.Outcomes) != 1 || ask.Outcomes[0].Outcome != OutcomeNoRule {
		t.Fatalf("outcomes = %+v, want a single no_rule", ask.Outcomes)
	}
}

// Правило с именем слушает только это имя; фильтры оси и повода отсекают
// частично совпавшие просьбы тем же исходом no_rule.
func TestRuleFilters(t *testing.T) {
	rules := []Rule{{
		From: "ip", Accept: []string{"skip"}, Codes: []string{"IP_ALLOWLIST"},
	}}

	ask := Evaluate([]protocol.PriorVerdict{
		entry("repu", protocol.Action{Do: "skip", Apply: "request", Code: "IP_ALLOWLIST"}),
		entry("ip", protocol.Action{Do: "skip", Apply: "request", Code: "IP_TOR"}),
		entry("ip", protocol.Action{Do: "skip", Apply: "request", Code: "IP_ALLOWLIST"}),
	}, rules)

	if !ask.Skip {
		t.Fatal("подошедшая просьба не применилась")
	}

	want := []string{OutcomeNoRule, OutcomeNoRule, OutcomeApplied}

	if len(ask.Outcomes) != len(want) {
		t.Fatalf("outcomes = %+v", ask.Outcomes)
	}

	for i, w := range want {
		if ask.Outcomes[i].Outcome != w {
			t.Errorf("outcome[%d] = %q, want %q", i, ask.Outcomes[i].Outcome, w)
		}
	}
}

// Проценты складываются: два принятых threshold дают сумму, каждый со своим
// исходом.
func TestPercentsAccumulate(t *testing.T) {
	rules := []Rule{
		{From: "ip", Accept: []string{"threshold"}},
		{From: "action", Accept: []string{"threshold"}},
	}

	ask := Evaluate([]protocol.PriorVerdict{
		entry("ip", protocol.Action{Do: "threshold", Apply: "request", Delta: 30}),
		entry("action", protocol.Action{Do: "threshold", Apply: "request", Delta: 10}),
	}, rules)

	if ask.Percent != 40 {
		t.Fatalf("percent = %d, want 30 + 10", ask.Percent)
	}
}

// Сумма скидок прижимается к −100: измерение не бывает меньше нуля, и две
// щедрые скидки не должны складываться в бессмыслицу.
func TestPercentSumIsFloored(t *testing.T) {
	rules := []Rule{
		{From: "ip", Accept: []string{"threshold"}},
		{From: "action", Accept: []string{"threshold"}},
	}

	ask := Evaluate([]protocol.PriorVerdict{
		entry("ip", protocol.Action{Do: "threshold", Apply: "request", Delta: -80}),
		entry("action", protocol.Action{Do: "threshold", Apply: "request", Delta: -80}),
	}, rules)

	if ask.Percent != PercentMin {
		t.Fatalf("percent = %d, want the floor %d", ask.Percent, PercentMin)
	}
}

// Мёртвые ключи потолка -- оба имени -- читаются одно поколение и не значат
// ничего: policy.yaml, напечатанный до отмены потолков, не должен ронять
// набор на ноде, а просьба по такому правилу берётся целиком.
func TestDeadCeilingKeysStillLoad(t *testing.T) {
	path := write(t, `
prior:
  - from: ip
    accept: [threshold]
    max_delta: 50
  - from: action
    accept: [threshold]
    max_percent: 10
`)

	policy, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	ask := Evaluate([]protocol.PriorVerdict{entry("ip", protocol.Action{
		Do: "threshold", Apply: "request", Delta: 300,
	})}, policy.Rules)

	if ask.Percent != 300 || ask.Outcomes[0].Outcome != OutcomeApplied {
		t.Fatalf("ask = %+v, want 300 taken whole despite the dead key", ask)
	}
}

// Пустая ось -- сообщение старого образца, читается как request.
func TestEmptyAxisMeansRequest(t *testing.T) {
	rules := []Rule{{From: "ip", Accept: []string{"skip"}, Apply: []string{"request"}}}

	ask := Evaluate([]protocol.PriorVerdict{entry("ip", protocol.Action{Do: "skip"})}, rules)

	if !ask.Skip || ask.Outcomes[0].Apply != protocol.ApplyRequest {
		t.Fatalf("ask = %+v, want skip on the request axis", ask)
	}
}

/* --- загрузка файла --------------------------------------------------------- */

func write(t *testing.T, text string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), FileName)

	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestLoadMissingFileIsSilence(t *testing.T) {
	policy, err := Load(filepath.Join(t.TempDir(), FileName))
	if err != nil || policy.Rules != nil || policy.Outcomes != nil {
		t.Fatalf("policy = %+v, err = %v; want empty, nil", policy, err)
	}
}

func TestLoadParsesRules(t *testing.T) {
	path := write(t, `
prior:
  - from: ip
    accept: [threshold]
    codes: [IP_ALLOWLIST]
  - from: action
    accept: [skip]
`)

	policy, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	rules := policy.Rules

	if len(rules) != 2 || rules[0].Codes[0] != "IP_ALLOWLIST" || rules[1].From != "action" {
		t.Fatalf("rules = %+v", rules)
	}
}

// Незнакомое поле -- ошибка загрузки: файл с опечаткой обязан быть отвергнут
// целиком, а не молча пропустить трафик мимо правила.
func TestLoadRejectsUnknownField(t *testing.T) {
	path := write(t, `
prior:
  - from: ip
    accepts: [skip]
`)

	if _, err := Load(path); err == nil {
		t.Fatal("опечатка в имени поля принята")
	}
}

func TestLoadRejectsInvalidRule(t *testing.T) {
	path := write(t, `
prior:
  - from: "*"
    accept: [threshold]
`)

	if _, err := Load(path); err == nil {
		t.Fatal("широковещательный threshold принят")
	}
}
