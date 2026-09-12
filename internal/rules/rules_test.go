/*
 * Профили из образа обязаны компилироваться. Без этого теста опечатка в SecLang
 * ловится только стартом процесса на стенде, то есть после сборки образа и
 * выкатки: движок собирает набор целиком и отказывается весь, а не частично.
 */

package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildShippedProfiles(t *testing.T) {
	set, err := build(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	for _, name := range []string{"default", "strict", "allow", "deny"} {
		if _, ok := set.profiles[name]; !ok {
			t.Errorf("request profile %q is missing", name)
		}
	}

	// Набор один на обе стороны: правила ответа лежат в тех же профилях.
}

/*
 * Поставляемый профиль обязан покрывать обе стороны транзакции. Липкая
 * транзакция иначе доигрывала бы фазы 3-4 вхолостую -- ни одного правила
 * ответа, ни одной находки и никакого признака ошибки.
 */
func TestShippedProfileCoversBothSides(t *testing.T) {
	set, err := build(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if set.profiles[DefaultProfile].engine.RuleCount() == 0 {
		t.Fatal("the default profile has no rules")
	}
}

/*
 * Дерево профилей на диске: минимальный набор, который компилируется, но не
 * тянет CRS. Тесты ниже про раскладку каталога, а не про правила.
 */
func tree(t *testing.T, trees map[string][]string) string {
	t.Helper()

	dir := t.TempDir()

	for name, profiles := range trees {
		for _, profile := range profiles {
			sub := filepath.Join(dir, name, profile)

			if err := os.MkdirAll(sub, 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}

			conf := "SecRuleEngine DetectionOnly\nSecAuditEngine Off\n"

			if err := os.WriteFile(filepath.Join(sub, "00-engine.conf"),
				[]byte(conf), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
	}

	return dir
}

/*
 * Раскладка каталога: profiles/http/<name>. Уровень один, потому что раздача
 * конфигурации подменяет его целиком -- переименованием каталога, а не по
 * файлу.
 */
func TestBuildReadsTheTree(t *testing.T) {
	dir := tree(t, map[string][]string{TreeDir: {"default", "strict"}})

	set, err := build(dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	r := &Registry{}
	r.current.Store(set)

	eng, sel := r.Select("strict")
	if eng == nil {
		t.Fatal("Select(strict) found nothing")
	}

	if sel.Profile != "strict" || sel.Unknown {
		t.Errorf("selection = %+v, want the named profile", sel)
	}
}

// Каталога с этим именем нет -- отказ сборки, а не пустой набор: инспектор без
// правил отвечает allow на всё и при этом выглядит работающим.
func TestBuildWithoutTree(t *testing.T) {
	dir := tree(t, map[string][]string{"response": {"default"}})

	if _, err := build(dir); err == nil {
		t.Fatal("a tree of the wrong name was accepted")
	}
}

/*
 * Неизвестное имя не подменяется профилем default: чужой набор правил -- это
 * проверка не того, и ответ по нему выдавал бы её за проверку маршрута. Движка
 * нет, вызывающий отвечает error, а расхождение считается: тег из nginx и
 * загруженные профили живут в двух разных репозиториях конфигурации.
 */
func TestSelectDoesNotFallBack(t *testing.T) {
	dir := tree(t, map[string][]string{TreeDir: {"default"}})

	set, err := build(dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	r := &Registry{unknown: map[string]int64{}}
	r.current.Store(set)

	eng, sel := r.Select("strict")
	if eng != nil {
		t.Fatal("an unknown profile was answered with someone else's rules")
	}

	if sel.Profile != "strict" || !sel.Unknown {
		t.Fatalf("selection = %+v, want the requested name marked unknown", sel)
	}

	if r.UnknownCounts()["strict"] != 1 {
		t.Errorf("the mismatch was not counted: %v", r.UnknownCounts())
	}

	// Правила приёма и инициаторы чужого профиля тоже не подставляются.
	if got := r.PriorRules("strict"); got != nil {
		t.Errorf("prior rules = %+v, want none", got)
	}

	if got := r.Outcomes("strict"); got != nil {
		t.Errorf("outcomes = %+v, want none", got)
	}
}

func TestBuildWithoutDefaultProfile(t *testing.T) {
	dir := tree(t, map[string][]string{TreeDir: {"strict"}})

	if _, err := build(dir); err == nil {
		t.Fatal("a request phase without its default was accepted")
	}
}

/*
 * prior.yaml живёт в каталоге профиля и грузится вместе с ним. Отсутствие
 * файла -- профиль никого не слушает; опечатка роняет сборку целиком, как
 * опечатка в SecLang: правило, которое молча не грузится, -- это дыра, а не
 * умолчание.
 */
func TestBuildLoadsPriorRules(t *testing.T) {
	dir := tree(t, map[string][]string{TreeDir: {"default", "strict"}})

	rulesYAML := "prior:\n  - from: ip\n    accept: [threshold]\n"

	if err := os.WriteFile(filepath.Join(dir, TreeDir, "strict", "prior.yaml"),
		[]byte(rulesYAML), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	set, err := build(dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	r := &Registry{}
	r.current.Store(set)

	if got := r.PriorRules("strict"); len(got) != 1 || got[0].From != "ip" {
		t.Fatalf("PriorRules(strict) = %+v, want the loaded rule", got)
	}

	if got := r.PriorRules("default"); got != nil {
		t.Fatalf("PriorRules(default) = %+v, want none", got)
	}

	// Неизвестный профиль слушает то же, что default, -- тем же откатом, что
	// у Select.
	if got := r.PriorRules("missing"); got != nil {
		t.Fatalf("PriorRules(missing) = %+v, want the default fallback", got)
	}
}

func TestBuildRejectsBrokenPriorRules(t *testing.T) {
	dir := tree(t, map[string][]string{TreeDir: {"default"}})

	broken := "prior:\n  - from: '*'\n    accept: [threshold]\n"

	if err := os.WriteFile(filepath.Join(dir, TreeDir, "default", "prior.yaml"),
		[]byte(broken), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := build(dir); err == nil {
		t.Fatal("a broadcast threshold was accepted")
	}
}
