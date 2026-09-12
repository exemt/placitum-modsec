/*
 * Отображение сообщения на вызовы движка -- таблица, а не догадка, и проверять
 * её надо без движка: фейковая транзакция записывает порядок вызовов и то, что
 * ей передали.
 *
 * Главное, что здесь проверяется, -- разница между фазами. На фазе ответа фазы
 * 1-2 прогоняются заново ради переменных запроса, но их вмешательства и их
 * находки принадлежат уже вынесенному вердикту фазы запроса, и попасть в ответ
 * второй раз не должны.
 */

package engine

import (
	"errors"
	"testing"
)

type fakeTx struct {
	calls []string

	reqHeaders  [][2]string
	rspHeaders  [][2]string
	reqBody     []byte
	rspBody     []byte
	uri         string
	method      string
	version     string
	serverName  string
	rspStatus   int
	rspProto    string
	closed      bool
	logged      bool
	writeRspErr error

	onRequestHeaders  *Intervention
	onRequestBody     *Intervention
	onResponseHeaders *Intervention
	onResponseBody    *Intervention

	matched  []MatchedRule
	inbound  [2]int
	outbound [2]int
}

func (t *fakeTx) note(name string) { t.calls = append(t.calls, name) }

func (t *fakeTx) ProcessConnection(clientIP string, clientPort int, serverIP string,
	serverPort int) {
	t.note("connection")
}

func (t *fakeTx) ProcessURI(uri, method, httpVersion string) {
	t.note("uri")
	t.uri, t.method, t.version = uri, method, httpVersion
}

func (t *fakeTx) SetServerName(name string) {
	t.note("server_name")
	t.serverName = name
}

func (t *fakeTx) AddRequestHeader(name, value string) {
	t.note("req_header")
	t.reqHeaders = append(t.reqHeaders, [2]string{name, value})
}

func (t *fakeTx) ProcessRequestHeaders() *Intervention {
	t.note("phase1")
	return t.onRequestHeaders
}

func (t *fakeTx) WriteRequestBody(b []byte) error {
	t.note("req_body")
	t.reqBody = append(t.reqBody, b...)
	return nil
}

func (t *fakeTx) ProcessRequestBody() (*Intervention, error) {
	t.note("phase2")
	return t.onRequestBody, nil
}

func (t *fakeTx) AddResponseHeader(name, value string) {
	t.note("rsp_header")
	t.rspHeaders = append(t.rspHeaders, [2]string{name, value})
}

func (t *fakeTx) ProcessResponseHeaders(status int, proto string) *Intervention {
	t.note("phase3")
	t.rspStatus, t.rspProto = status, proto
	return t.onResponseHeaders
}

func (t *fakeTx) WriteResponseBody(b []byte) error {
	t.note("rsp_body")

	if t.writeRspErr != nil {
		return t.writeRspErr
	}

	t.rspBody = append(t.rspBody, b...)

	return nil
}

func (t *fakeTx) ProcessResponseBody() (*Intervention, error) {
	t.note("phase4")
	return t.onResponseBody, nil
}

func (t *fakeTx) Matched() []MatchedRule { return t.matched }

func (t *fakeTx) Anomaly() (int, int) { return t.inbound[0], t.inbound[1] }

func (t *fakeTx) AnomalyOutbound() (int, int) { return t.outbound[0], t.outbound[1] }

func (t *fakeTx) ProcessLogging() {
	t.note("logging")
	t.logged = true
}

func (t *fakeTx) Close() error {
	t.closed = true
	return nil
}

type fakeEngine struct {
	tx  *fakeTx
	err error
	rid string
	// made -- сколько транзакций попросили. Продолжение обязано обойтись
	// одной: вторая означала бы потерянное состояние.
	made int
}

func (e *fakeEngine) NewTransaction(rid string) (Transaction, error) {
	e.rid = rid
	e.made++

	if e.err != nil {
		return nil, e.err
	}

	return e.tx, nil
}

func (e *fakeEngine) RuleCount() int { return 1 }

func input() *Input {
	return &Input{
		RID:      "3f2a9c1e00000017",
		ClientIP: "203.0.113.42",
		Method:   "POST",
		URI:      "/api/orders",
		Args:     "id=1",
		Version:  "HTTP/1.1",
		Host:     "shop.example.com:443",
		Headers:  [][2]string{{"content-type", "application/json"}},
	}
}

func has(calls []string, name string) bool {
	for _, c := range calls {
		if c == name {
			return true
		}
	}

	return false
}

func index(t *testing.T, calls []string, name string) int {
	t.Helper()

	for i, c := range calls {
		if c == name {
			return i
		}
	}

	t.Fatalf("call %q never happened in %v", name, calls)

	return -1
}

func TestApplyRunsRequestPhasesOnly(t *testing.T) {
	tx := &fakeTx{inbound: [2]int{15, 5}, outbound: [2]int{99, 4}}
	eng := &fakeEngine{tx: tx}

	in := input()
	in.Body = []byte(`{"a":1}`)

	out, err := Apply(eng, in)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	if has(tx.calls, "phase3") || has(tx.calls, "phase4") {
		t.Errorf("request phase touched response phases: %v", tx.calls)
	}

	if !tx.logged || !tx.closed {
		t.Errorf("transaction not finished: logged=%v closed=%v", tx.logged, tx.closed)
	}

	// Счёт фазы запроса -- входящий. Исходящий у той же транзакции есть, и
	// подставить его сюда значило бы отдать модулю чужую сторону.
	if out.AnomalyScore != 15 || out.Threshold != 5 {
		t.Errorf("anomaly = %d/%d, want 15/5", out.AnomalyScore, out.Threshold)
	}

	if tx.uri != "/api/orders?id=1" {
		t.Errorf("uri = %q, want the query glued back on", tx.uri)
	}

	if tx.version != "1.1" {
		t.Errorf("version = %q, want 1.1 without the HTTP/ prefix", tx.version)
	}

	if tx.serverName != "shop.example.com" {
		t.Errorf("server name = %q, want the host without the port", tx.serverName)
	}
}

func TestApplyResponseOrderAndPhases(t *testing.T) {
	tx := &fakeTx{outbound: [2]int{8, 4}}
	eng := &fakeEngine{tx: tx}

	out, err := ApplyResponse(eng, input(), &ResponseInput{
		Status:  503,
		Headers: [][2]string{{"content-type", "text/html"}},
		Body:    []byte("<html>ORA-00933</html>"),
	})
	if err != nil {
		t.Fatalf("apply response: %v", err)
	}

	calls := tx.calls

	for _, name := range []string{"connection", "uri", "phase1", "phase2",
		"phase3", "phase4", "logging"} {
		if !has(calls, name) {
			t.Fatalf("call %q never happened: %v", name, calls)
		}
	}

	if index(t, calls, "phase2") > index(t, calls, "phase3") {
		t.Errorf("request phases must run before the response ones: %v", calls)
	}

	if index(t, calls, "rsp_header") > index(t, calls, "phase3") {
		t.Errorf("response headers must be added before phase 3: %v", calls)
	}

	if index(t, calls, "rsp_body") > index(t, calls, "phase4") {
		t.Errorf("response body must be written before phase 4: %v", calls)
	}

	if tx.rspStatus != 503 {
		t.Errorf("status = %d, want 503", tx.rspStatus)
	}

	if string(tx.rspBody) != "<html>ORA-00933</html>" {
		t.Errorf("response body = %q", tx.rspBody)
	}

	// Исходящая сторона: свой счёт и свой порог.
	if out.AnomalyScore != 8 || out.Threshold != 4 {
		t.Errorf("anomaly = %d/%d, want the outbound 8/4",
			out.AnomalyScore, out.Threshold)
	}

	if !tx.closed {
		t.Error("transaction left open")
	}
}

// Тела запроса в сообщении фазы ответа обычно нет, но фаза 2 вызывается всё
// равно: в ней набор правил сводит счёт, и пропуск вызова оставил бы его
// нулевым при любых срабатываниях фазы 1.
func TestApplyResponseRunsPhaseTwoWithoutBody(t *testing.T) {
	tx := &fakeTx{}
	eng := &fakeEngine{tx: tx}

	if _, err := ApplyResponse(eng, input(), &ResponseInput{}); err != nil {
		t.Fatalf("apply response: %v", err)
	}

	if has(tx.calls, "req_body") {
		t.Errorf("wrote a request body that was not given: %v", tx.calls)
	}

	if !has(tx.calls, "phase2") {
		t.Errorf("phase 2 skipped: %v", tx.calls)
	}
}

func TestApplyResponseDropsRequestPhaseIntervention(t *testing.T) {
	tx := &fakeTx{
		onRequestHeaders: &Intervention{Status: 403, Action: "deny", RuleID: 942100},
		onRequestBody:    &Intervention{Status: 403, Action: "deny", RuleID: 949110},
		onResponseBody:   &Intervention{Status: 500, Action: "deny", RuleID: 951220},
	}
	eng := &fakeEngine{tx: tx}

	out, err := ApplyResponse(eng, input(), &ResponseInput{})
	if err != nil {
		t.Fatalf("apply response: %v", err)
	}

	if out.Intervention == nil {
		t.Fatal("response phase intervention lost")
	}

	if out.Intervention.RuleID != 951220 {
		t.Errorf("intervention from rule %d, want the response one (951220): "+
			"the request phases must not decide here", out.Intervention.RuleID)
	}
}

// Фаза 3 решает раньше фазы 4: первое вмешательство ответной стороны и
// побеждает.
func TestApplyResponseKeepsFirstResponseIntervention(t *testing.T) {
	tx := &fakeTx{
		onResponseHeaders: &Intervention{Status: 500, Action: "deny", RuleID: 950100},
		onResponseBody:    &Intervention{Status: 500, Action: "deny", RuleID: 951220},
	}
	eng := &fakeEngine{tx: tx}

	out, err := ApplyResponse(eng, input(), &ResponseInput{})
	if err != nil {
		t.Fatalf("apply response: %v", err)
	}

	if out.Intervention.RuleID != 950100 {
		t.Errorf("intervention from rule %d, want 950100 from phase 3",
			out.Intervention.RuleID)
	}
}

func TestApplyResponseReportsRulesFromPhaseThree(t *testing.T) {
	tx := &fakeTx{matched: []MatchedRule{
		{ID: 942100, Phase: 2, Message: "sqli in args"},
		{ID: 949110, Phase: 2, Message: "inbound anomaly"},
		{ID: 951220, Phase: 4, Message: "sql error leak"},
		{ID: 950100, Phase: 3, Message: "app error status"},
	}}
	eng := &fakeEngine{tx: tx}

	out, err := ApplyResponse(eng, input(), &ResponseInput{})
	if err != nil {
		t.Fatalf("apply response: %v", err)
	}

	if len(out.Matched) != 2 {
		t.Fatalf("matched = %v, want only the phase 3 and 4 rules", out.Matched)
	}

	for _, m := range out.Matched {
		if m.Phase < 3 {
			t.Errorf("rule %d of phase %d leaked into the response findings",
				m.ID, m.Phase)
		}
	}
}

/*
 * Продолжение: фазы 3-4 идут на той же транзакции, что фазы 1-2. Проверяется
 * именно это -- второй NewTransaction означал бы, что состояние потеряно, а
 * значит потеряны REQUEST_HEADERS, ARGS и входящий счёт.
 */
func TestApplyKeepResumesTheSameTransaction(t *testing.T) {
	tx := &fakeTx{}
	eng := &fakeEngine{tx: tx}

	out, live, err := ApplyKeep(eng, input())
	if err != nil {
		t.Fatalf("apply keep: %v", err)
	}

	if live == nil {
		t.Fatal("transaction was not kept")
	}

	if out == nil {
		t.Fatal("request phases produced no outcome")
	}

	if tx.closed {
		t.Fatal("transaction closed before the response phase")
	}

	// Фаза 5 сводит счёт обеих сторон: позвать её после фаз 1-2 значило бы
	// закрыть транзакцию раньше, чем пришёл ответ.
	if has(tx.calls, "logging") {
		t.Fatalf("logging ran before the response phase: %v", tx.calls)
	}

	if _, err := live.Resume(&ResponseInput{Status: 500}); err != nil {
		t.Fatalf("resume: %v", err)
	}

	if eng.made != 1 {
		t.Fatalf("transactions created = %d, want 1: the response phases must "+
			"continue the request one", eng.made)
	}

	if !has(tx.calls, "logging") {
		t.Fatalf("logging did not run after the response phases: %v", tx.calls)
	}

	if !tx.closed {
		t.Fatal("transaction stayed open after resume")
	}
}

// Брошенное продолжение закрывает транзакцию: реестр держит её память, и
// невостребованная она обязана освободиться, а не дожить до конца процесса.
func TestLiveDiscardClosesTransaction(t *testing.T) {
	tx := &fakeTx{}
	eng := &fakeEngine{tx: tx}

	_, live, err := ApplyKeep(eng, input())
	if err != nil {
		t.Fatalf("apply keep: %v", err)
	}

	live.Discard()

	if !tx.closed {
		t.Fatal("discarded transaction was not closed")
	}
}

/*
 * Отчёт продолжения -- только фазы 3-4. Находки фаз 1-2 уехали в вердикте
 * запроса, и повторить их значило бы посчитать одну находку дважды; фаза 5 не
 * находки, а сводка того, что уже посчитано.
 */
func TestResumeReportsResponsePhasesOnly(t *testing.T) {
	tx := &fakeTx{matched: []MatchedRule{
		{ID: 942100, Phase: 2, Message: "sqli in args"},
		{ID: 951220, Phase: 4, Message: "sql error leak"},
		{ID: 980170, Phase: 5, Message: "correlated attack"},
	}}
	eng := &fakeEngine{tx: tx}

	_, live, err := ApplyKeep(eng, input())
	if err != nil {
		t.Fatalf("apply keep: %v", err)
	}

	out, err := live.Resume(&ResponseInput{Status: 500})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}

	if len(out.Matched) != 1 || out.Matched[0].ID != 951220 {
		t.Fatalf("matched = %+v, want only the phase 4 rule", out.Matched)
	}
}

// То же требование к фазе запроса: сводка фазы 5 -- не находка.
func TestApplyReportsRequestPhasesOnly(t *testing.T) {
	tx := &fakeTx{matched: []MatchedRule{
		{ID: 942100, Phase: 2, Message: "sqli in args"},
		{ID: 980170, Phase: 5, Message: "correlated attack"},
	}}
	eng := &fakeEngine{tx: tx}

	out, err := Apply(eng, input())
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	if len(out.Matched) != 1 || out.Matched[0].ID != 942100 {
		t.Fatalf("matched = %+v, want only the phase 2 rule", out.Matched)
	}
}

func TestApplyResponsePropagatesEngineErrors(t *testing.T) {
	want := errors.New("write failed")
	tx := &fakeTx{writeRspErr: want}
	eng := &fakeEngine{tx: tx}

	_, err := ApplyResponse(eng, input(), &ResponseInput{
		Body: []byte("x"),
	})
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}
