package coraza

import (
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/exemt/placitum-modsec/internal/engine"
)

type Engine struct {
	waf   coraza.WAF
	rules int
}

func New(root fs.FS, files []string) (*Engine, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("no rule files given")
	}

	cfg := coraza.NewWAFConfig().
		WithRootFS(root).
		WithDebugLogger(debuglog.Noop())

	for _, f := range files {
		cfg = cfg.WithDirectivesFromFile(f)
	}

	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		return nil, err
	}

	e := &Engine{waf: waf}

	if c, ok := waf.(interface{ RulesCount() int }); ok {
		e.rules = c.RulesCount()
	}

	return e, nil
}

func (e *Engine) RuleCount() int { return e.rules }

func (e *Engine) NewTransaction(rid string) (engine.Transaction, error) {
	return &transaction{tx: e.waf.NewTransactionWithID(rid)}, nil
}

type transaction struct {
	tx types.Transaction
}

func (t *transaction) ProcessConnection(clientIP string, clientPort int, serverIP string, serverPort int) {
	t.tx.ProcessConnection(clientIP, clientPort, serverIP, serverPort)
}

func (t *transaction) ProcessURI(uri, method, httpVersion string) {
	t.tx.ProcessURI(uri, method, httpVersion)
}

func (t *transaction) SetServerName(name string) { t.tx.SetServerName(name) }

func (t *transaction) AddRequestHeader(name, value string) {
	t.tx.AddRequestHeader(name, value)
}

func (t *transaction) ProcessRequestHeaders() *engine.Intervention {
	return convert(t.tx.ProcessRequestHeaders())
}

func (t *transaction) WriteRequestBody(b []byte) error {
	_, _, err := t.tx.WriteRequestBody(b)
	return err
}

func (t *transaction) ProcessRequestBody() (*engine.Intervention, error) {
	it, err := t.tx.ProcessRequestBody()
	return convert(it), err
}

func (t *transaction) AddResponseHeader(name, value string) {
	t.tx.AddResponseHeader(name, value)
}

func (t *transaction) ProcessResponseHeaders(status int, proto string) *engine.Intervention {
	return convert(t.tx.ProcessResponseHeaders(status, proto))
}

func (t *transaction) WriteResponseBody(b []byte) error {
	_, _, err := t.tx.WriteResponseBody(b)
	return err
}

func (t *transaction) ProcessResponseBody() (*engine.Intervention, error) {
	it, err := t.tx.ProcessResponseBody()
	return convert(it), err
}

func (t *transaction) ProcessLogging() { t.tx.ProcessLogging() }

func (t *transaction) Close() error { return t.tx.Close() }

func (t *transaction) Matched() []engine.MatchedRule {
	src := t.tx.MatchedRules()
	if len(src) == 0 {
		return nil
	}

	out := make([]engine.MatchedRule, 0, len(src))

	for _, m := range src {
		r := m.Rule()

		out = append(out, engine.MatchedRule{
			ID:       r.ID(),
			Phase:    int(r.Phase()),
			Severity: r.Severity().String(),
			Tags:     r.Tags(),
			Message:  m.Message(),
			Data:     m.Data(),
			Target:   target(m.MatchedDatas()),
		})
	}

	return out
}

func target(datas []types.MatchData) string {
	for _, d := range datas {
		name := d.Variable().Name()
		key := strings.ToLower(d.Key())

		switch name {
		case "REQUEST_HEADERS", "REQUEST_HEADERS_NAMES":
			if key == "" {
				return ""
			}

			return "header:" + key

		case "REQUEST_COOKIES", "REQUEST_COOKIES_NAMES":
			if key == "" {
				return ""
			}

			return "cookie:" + key

		case "ARGS", "ARGS_GET", "ARGS_GET_NAMES", "ARGS_NAMES", "QUERY_STRING":
			return "args"

		case "ARGS_POST", "ARGS_POST_NAMES", "REQUEST_BODY", "FILES",
			"FILES_NAMES", "MULTIPART_PART_HEADERS", "JSON", "XML":
			return "body"

		case "REQUEST_URI", "REQUEST_URI_RAW", "REQUEST_FILENAME",
			"REQUEST_BASENAME", "REQUEST_LINE":
			return "uri"
		}
	}

	return ""
}

var anomalyVars = []string{
	"blocking_inbound_anomaly_score",
	"inbound_anomaly_score",
	"detection_inbound_anomaly_score",
}

var anomalyOutVars = []string{
	"blocking_outbound_anomaly_score",
	"outbound_anomaly_score",
	"detection_outbound_anomaly_score",
}

func (t *transaction) Anomaly() (int, int) {
	return t.anomaly(anomalyVars, "inbound_anomaly_score_threshold")
}

func (t *transaction) AnomalyOutbound() (int, int) {
	return t.anomaly(anomalyOutVars, "outbound_anomaly_score_threshold")
}

func (t *transaction) anomaly(names []string, threshold string) (int, int) {
	state, ok := t.tx.(plugintypes.TransactionState)
	if !ok {
		return 0, 0
	}

	tx := state.Variables().TX()

	var score int

	for _, name := range names {
		if v, ok := firstInt(tx.Get(name)); ok {
			score = v
			break
		}
	}

	limit, _ := firstInt(tx.Get(threshold))

	return score, limit
}

func firstInt(values []string) (int, bool) {
	if len(values) == 0 {
		return 0, false
	}

	v, err := strconv.Atoi(values[0])
	if err != nil {
		return 0, false
	}

	return v, true
}

func convert(it *types.Interruption) *engine.Intervention {
	if it == nil {
		return nil
	}

	iv := &engine.Intervention{
		Status:     it.Status,
		Action:     it.Action,
		RuleID:     it.RuleID,
		Disruptive: it.Action != "" && it.Action != "pass" && it.Action != "allow",
	}

	if it.Action == "redirect" {
		iv.URL = it.Data
	}

	return iv
}
