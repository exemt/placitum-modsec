/*
 * Поставляемый профиль против настоящего движка: собранный CRS и фазы 3-4 --
 * и на продолжении живой транзакции, и на её переигровке.
 *
 * internal/engine проверяет порядок вызовов на фейке -- здесь проверяется, что
 * за этими вызовами действительно срабатывают правила ответной стороны и что
 * счёт считается по исходящей шкале.
 */

package rules

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/exemt/placitum-modsec/internal/engine"
)

func shipped(t *testing.T) *Set {
	t.Helper()

	set, err := build(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	return set
}

func requestSide() *engine.Input {
	return &engine.Input{
		RID:        "3f2a9c1e00000017",
		ClientIP:   "203.0.113.42",
		ClientPort: 51544,
		Method:     "GET",
		URI:        "/api/orders",
		Args:       "id=1",
		Version:    "HTTP/1.1",
		Host:       "shop.example.com",
		Headers: [][2]string{
			{"host", "shop.example.com"},
			{"user-agent", "curl/8.5.0"},
			{"accept", "*/*"},
		},
	}
}

func ids(matched []engine.MatchedRule) []int {
	out := make([]int, 0, len(matched))

	for _, m := range matched {
		out = append(out, m.ID)
	}

	return out
}

/*
 * Утечка ошибки СУБД в теле ответа -- фаза 4. Ровно тот случай, ради которого
 * фаза ответа и заводится: запрос был безобидным, отвечает приложение.
 */
func TestResponsePhaseCatchesSQLLeakInBody(t *testing.T) {
	set := shipped(t)

	out, err := engine.ApplyResponse(set.profiles[DefaultProfile].engine, requestSide(),
		&engine.ResponseInput{
			Status: 500,
			Headers: [][2]string{
				{"content-type", "text/html; charset=utf-8"},
				{"content-length", "84"},
			},
			Body: []byte("<html><body>" +
				"You have an error in your SQL syntax; check the manual " +
				"that corresponds to your MySQL server version" +
				"</body></html>"),
		})
	if err != nil {
		t.Fatalf("apply response: %v", err)
	}

	// Маркеры и служебные правила CRS в аудит не едут (internal/verdict), но в
	// диагностике теста полезны именно находки с текстом.
	for _, m := range out.Matched {
		if m.Message != "" {
			t.Logf("rule %d phase %d: %s", m.ID, m.Phase, m.Message)
		}
	}

	if len(out.Matched) == 0 {
		t.Fatal("the response profile found nothing in a leaking body")
	}

	var body bool

	for _, m := range out.Matched {
		if m.Phase < 3 {
			t.Errorf("rule %d of phase %d leaked into the response findings",
				m.ID, m.Phase)
		}

		if m.Phase == 4 {
			body = true
		}
	}

	if !body {
		t.Fatalf("no phase 4 rule fired, matched %v: the body was not "+
			"inspected -- check SecResponseBodyAccess and "+
			"SecResponseBodyMimeType", ids(out.Matched))
	}

	/*
	 * Счёт исходящей стороны -- то, что уезжает модулю как score. Ноль при
	 * сработавших правилах означает ровно одно: в профиле нет инициализации
	 * CRS, и каждое правило прибавляет нераскрытый макрос вместо веса.
	 */
	if out.AnomalyScore <= 0 {
		t.Fatalf("outbound anomaly score = %d, want a positive one: rules "+
			"fired but RESPONSE-959-BLOCKING-EVALUATION did not sum them",
			out.AnomalyScore)
	}

	if out.Threshold <= 0 {
		t.Errorf("outbound threshold = %d, want the profile value",
			out.Threshold)
	}

	t.Logf("phase 3-4 rules %v, outbound %d/%d",
		ids(out.Matched), out.AnomalyScore, out.Threshold)
}

/*
 * Чистый ответ не находит ничего и не блокирует ничего. Проверяется вместе с
 * предыдущим: профиль, который срабатывает на всём, бесполезен так же, как
 * профиль, который не срабатывает ни на чём.
 */
func TestResponsePhaseIsQuietOnCleanResponse(t *testing.T) {
	set := shipped(t)

	out, err := engine.ApplyResponse(set.profiles[DefaultProfile].engine, requestSide(),
		&engine.ResponseInput{
			Status: 200,
			Headers: [][2]string{
				{"content-type", "application/json"},
				{"content-length", "27"},
			},
			Body: []byte(`{"id":1,"status":"created"}`),
		})
	if err != nil {
		t.Fatalf("apply response: %v", err)
	}

	if out.Intervention != nil {
		t.Errorf("intervention on a clean response: %+v", out.Intervention)
	}

	if out.AnomalyScore != 0 {
		t.Errorf("outbound anomaly score = %d on a clean response, matched %v",
			out.AnomalyScore, ids(out.Matched))
	}
}

/*
 * Тело JSON инспектируется. Рекомендованный набор разбирает три типа, и без
 * своей строки SecResponseBodyMimeType ровно тот ответ, который чаще всего и
 * течёт, проходил бы мимо правил.
 */
func TestResponsePhaseInspectsJSONBody(t *testing.T) {
	set := shipped(t)

	out, err := engine.ApplyResponse(set.profiles[DefaultProfile].engine, requestSide(),
		&engine.ResponseInput{
			Status:  500,
			Headers: [][2]string{{"content-type", "application/json"}},
			Body: []byte(`{"error":"You have an error in your SQL syntax; ` +
				`check the manual that corresponds to your MySQL server version"}`),
		})
	if err != nil {
		t.Fatalf("apply response: %v", err)
	}

	var body bool

	for _, m := range out.Matched {
		if m.Phase == 4 {
			body = true
		}
	}

	if !body {
		t.Fatalf("JSON body was not inspected, matched %v", ids(out.Matched))
	}
}

/*
 * Вердикт фазы ответа не считает находки запроса. Набор один на обе стороны, и
 * при переигровке правила REQUEST-* срабатывают заново -- но уезжает наружу
 * исходящий счёт и находки фаз 3-4, а входящие уже посчитаны вердиктом своей
 * фазы. Иначе запрос, осознанно пропущенный на фазе запроса, отказывался бы на
 * ответе за те же самые срабатывания.
 */
func TestResponsePhaseIgnoresRequestSideAttack(t *testing.T) {
	set := shipped(t)

	in := requestSide()
	in.Args = "id=1' OR 1=1-- "
	in.URI = "/api/orders"

	out, err := engine.ApplyResponse(set.profiles[DefaultProfile].engine, in,
		&engine.ResponseInput{
			Status:  200,
			Headers: [][2]string{{"content-type", "application/json"}},
			Body:    []byte(`{"id":1}`),
		})
	if err != nil {
		t.Fatalf("apply response: %v", err)
	}

	for _, m := range out.Matched {
		if m.Phase < 3 {
			t.Errorf("request-side rule %d reported by the response phase",
				m.ID)
		}
	}

	if out.Intervention != nil {
		t.Fatalf("the response phase blocked over a request-side finding: %+v",
			out.Intervention)
	}

	if out.AnomalyScore != 0 {
		t.Errorf("outbound score = %d on a clean response of a dirty request",
			out.AnomalyScore)
	}
}

/*
 * Тот же запрос на своей фазе: он обязан находить атаку, которую вердикт фазы
 * ответа игнорирует. Иначе предыдущий тест доказывал бы только то, что правил
 * нет вовсе.
 */
func TestRequestPhaseStillCatchesTheSameAttack(t *testing.T) {
	set := shipped(t)

	in := requestSide()
	in.Args = "id=1' OR 1=1-- "

	out, err := engine.Apply(set.profiles[DefaultProfile].engine, in)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	if out.AnomalyScore <= 0 {
		t.Fatalf("the request profile found nothing in %q, matched %v",
			in.Args, ids(out.Matched))
	}
}

// Заголовки ответа -- фаза 3. Утечка версии сервера приложения видна ещё до
// тела, и удерживать ради неё тело незачем.
func TestResponsePhaseSeesHeaders(t *testing.T) {
	set := shipped(t)

	out, err := engine.ApplyResponse(set.profiles[DefaultProfile].engine, requestSide(),
		&engine.ResponseInput{
			Status: 200,
			Headers: [][2]string{
				{"content-type", "text/html"},
				{"x-powered-by", "PHP/5.4.45"},
			},
			Body: []byte("<html>ok</html>"),
		})
	if err != nil {
		t.Fatalf("apply response: %v", err)
	}

	for _, m := range out.Matched {
		if m.Phase == 3 {
			t.Logf("phase 3 rule %d: %s", m.ID, strings.TrimSpace(m.Message))
			return
		}
	}

	t.Fatalf("no phase 3 rule fired on a leaking header, matched %v",
		ids(out.Matched))
}

/*
 * Липкий путь: одна транзакция на обе стороны.
 *
 * Это и есть основной путь фазы ответа. Проверяется то, ради чего он заведён:
 * фазы 3-4 идут поверх состояния фаз 1-2 -- у правил ответа есть настоящий
 * контекст запроса, входящий счёт посчитан один раз своей фазой, а наружу от
 * продолжения уезжают только находки фаз 3-4.
 */
func TestKeptTransactionCarriesRequestContextIntoPhase4(t *testing.T) {
	set := shipped(t)

	in := requestSide()
	in.Args = "id=1' OR 1=1-- "

	req, live, err := engine.ApplyKeep(set.profiles[DefaultProfile].engine, in)
	if err != nil {
		t.Fatalf("apply keep: %v", err)
	}

	if req.AnomalyScore <= 0 {
		t.Fatalf("the request phases found nothing in %q, matched %v",
			in.Args, ids(req.Matched))
	}

	out, err := live.Resume(&engine.ResponseInput{
		Status:  500,
		Headers: [][2]string{{"content-type", "text/html"}},
		Body: []byte("<html><body>" +
			"You have an error in your SQL syntax; check the manual " +
			"that corresponds to your MySQL server version" +
			"</body></html>"),
	})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}

	var body bool

	for _, m := range out.Matched {
		if m.Phase < 3 || m.Phase > 4 {
			t.Errorf("rule %d of phase %d leaked into the response findings",
				m.ID, m.Phase)
		}

		if m.Phase == 4 {
			body = true
		}
	}

	if !body {
		t.Fatalf("no phase 4 rule fired on a leaking body, matched %v",
			ids(out.Matched))
	}

	if out.AnomalyScore <= 0 {
		t.Fatalf("outbound score = %d after phase 4 rules fired: %v",
			out.AnomalyScore, ids(out.Matched))
	}

	t.Logf("inbound %d, outbound %d/%d, phase 3-4 rules %v",
		req.AnomalyScore, out.AnomalyScore, out.Threshold, ids(out.Matched))
}

/*
 * Цена отката, названная числом: переигранная транзакция не видит тела
 * запроса. Тест не требует конкретного правила -- он фиксирует само различие,
 * чтобы «продолжение и переигровка одинаковы» не стало молчаливым допущением.
 */
func TestReplayLosesRequestBody(t *testing.T) {
	set := shipped(t)

	in := requestSide()
	in.Method = "POST"
	in.Args = ""
	in.Headers = append(in.Headers,
		[2]string{"content-type", "application/x-www-form-urlencoded"})
	in.Body = []byte("id=1' OR 1=1-- ")

	kept, live, err := engine.ApplyKeep(set.profiles[DefaultProfile].engine, in)
	if err != nil {
		t.Fatalf("apply keep: %v", err)
	}

	live.Discard()

	replayed := *in
	replayed.Body = nil

	out, err := engine.Apply(set.profiles[DefaultProfile].engine, &replayed)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	if kept.AnomalyScore <= out.AnomalyScore {
		t.Fatalf("inbound score with body %d, without body %d: the request "+
			"body must add findings, otherwise the replay path costs nothing "+
			"and this whole mechanism is pointless",
			kept.AnomalyScore, out.AnomalyScore)
	}
}
