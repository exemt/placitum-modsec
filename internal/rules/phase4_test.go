/*
 * Фаза 4 против настоящего движка: правило, которое смотрит в тело ответа, и
 * только в него.
 *
 * Профиль canary для этого и заведён -- одно своё правило, без CRS. Вопрос
 * «исполняются ли правила ответной стороны» иначе проверяется набором, который
 * меняется с каждой версией CRS: правило переименуют, вес поменяют, уровень
 * паранойи поднимут, и тест начнёт падать не от того, что сломалась фаза.
 *
 * Здесь же ответ однозначен: канарейка в теле -- находка фазы 4; та же строка
 * в заголовке ответа или в запросе -- ничего.
 */

package rules

import (
	"testing"

	"github.com/exemt/placitum-modsec/internal/engine"
)

const canaryRule = 1000901

// Канарейка в теле ответа: единственный случай, когда правило обязано найтись.
func TestCanaryFiresInResponseBody(t *testing.T) {
	set := shipped(t)

	out := canaryRun(t, set, &engine.ResponseInput{
		Status:  200,
		Headers: [][2]string{{"content-type", "text/html"}},
		Body:    []byte("<html><body>token WAF-CANARY-0badc0de leaked</body></html>"),
	}, requestSide())

	m := findRule(out.Matched, canaryRule)
	if m == nil {
		t.Fatalf("the canary rule did not fire, matched %v", ids(out.Matched))
	}

	if m.Phase != 4 {
		t.Fatalf("rule %d reported phase %d, want 4: the response body exists "+
			"in no other phase", m.ID, m.Phase)
	}

	/*
	 * Счёт исходящей стороны -- то, что уезжает модулю как score. Ноль при
	 * сработавшем правиле означал бы, что находка есть, а веса у неё нет, и
	 * маршрут с waf_score_deny response ничего не заметит.
	 */
	if out.AnomalyScore < 5 || out.Threshold != 4 {
		t.Fatalf("outbound %d/%d, want at least 5 over a threshold of 4",
			out.AnomalyScore, out.Threshold)
	}
}

/*
 * Та же строка в заголовке ответа. Фаза 3 видит заголовки, но правило написано
 * на RESPONSE_BODY -- значит не находит. Без этой проверки предыдущий тест
 * доказывал бы только то, что движок где-то нашёл подстроку.
 */
func TestCanaryIgnoresResponseHeader(t *testing.T) {
	set := shipped(t)

	out := canaryRun(t, set, &engine.ResponseInput{
		Status: 200,
		Headers: [][2]string{
			{"content-type", "text/html"},
			{"x-debug-token", "WAF-CANARY-0badc0de"},
		},
		Body: []byte("<html><body>ok</body></html>"),
	}, requestSide())

	if m := findRule(out.Matched, canaryRule); m != nil {
		t.Fatalf("the canary rule fired on a header, phase %d", m.Phase)
	}

	if out.AnomalyScore != 0 {
		t.Errorf("outbound score = %d on a clean body", out.AnomalyScore)
	}
}

// И в запросе: фазы 1-2 к телу ответа отношения не имеют.
func TestCanaryIgnoresRequestSide(t *testing.T) {
	set := shipped(t)

	in := requestSide()
	in.Args = "token=WAF-CANARY-0badc0de"

	out := canaryRun(t, set, &engine.ResponseInput{
		Status:  200,
		Headers: [][2]string{{"content-type", "text/html"}},
		Body:    []byte("<html><body>ok</body></html>"),
	}, in)

	if m := findRule(out.Matched, canaryRule); m != nil {
		t.Fatalf("the canary rule fired on the request side, phase %d", m.Phase)
	}
}

/*
 * Тело ответа приезжает усечённым, когда маршрут снимает меньше, чем отдал
 * апстрим. Движку об этом говорит ProcessPartial: без него он вернул бы ошибку
 * разбора вместо находки, а с ним ищет в том, что дали.
 */
func TestCanaryFiresInTruncatedBody(t *testing.T) {
	set := shipped(t)

	out := canaryRun(t, set, &engine.ResponseInput{
		Status:        200,
		Headers:       [][2]string{{"content-type", "text/html"}},
		Body:          []byte("<html><body>token WAF-CANARY-0badc0de"),
		BodyTruncated: true,
	}, requestSide())

	if findRule(out.Matched, canaryRule) == nil {
		t.Fatalf("the canary was not found in a truncated body, matched %v",
			ids(out.Matched))
	}
}

/*
 * Прогон обоими путями сразу: продолжение живой транзакции и её переигровка.
 * Правило фазы 4 не зависит от контекста запроса, поэтому оба обязаны дать
 * одинаковый результат -- и это тот случай, когда откат ничего не теряет.
 */
func canaryRun(t *testing.T, set *Set, rsp *engine.ResponseInput,
	in *engine.Input) *engine.Outcome {

	t.Helper()

	eng := set.profiles["canary"].engine
	if eng == nil {
		t.Fatal("profile canary is missing")
	}

	_, live, err := engine.ApplyKeep(eng, in)
	if err != nil {
		t.Fatalf("apply keep: %v", err)
	}

	kept, err := live.Resume(rsp)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}

	replayed, err := engine.ApplyResponse(eng, in, rsp)
	if err != nil {
		t.Fatalf("apply response: %v", err)
	}

	if len(ids(kept.Matched)) != len(ids(replayed.Matched)) ||
		kept.AnomalyScore != replayed.AnomalyScore {
		t.Fatalf("sticky and replay disagree: %v %d vs %v %d",
			ids(kept.Matched), kept.AnomalyScore,
			ids(replayed.Matched), replayed.AnomalyScore)
	}

	return kept
}

func findRule(matched []engine.MatchedRule, id int) *engine.MatchedRule {
	for i := range matched {
		if matched[i].ID == id {
			return &matched[i]
		}
	}

	return nil
}
