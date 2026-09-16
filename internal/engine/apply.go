package engine

import (
	"strings"
	"time"
)

type Input struct {
	RID string

	ClientIP   string
	ClientPort int
	ServerIP   string
	ServerPort int

	Method  string
	URI     string
	Args    string
	Version string
	Host    string
	Headers [][2]string

	Body          []byte
	BodyTruncated bool
}

type ResponseInput struct {
	Status  int
	Proto   string
	Headers [][2]string

	Body          []byte
	BodyTruncated bool
}

type Outcome struct {
	Intervention *Intervention
	Matched      []MatchedRule
	AnomalyScore int
	Threshold    int
	EngineMS     float64
}

type Live struct {
	tx    Transaction
	proto string
}

func Apply(eng Engine, in *Input) (*Outcome, error) {
	started := time.Now()

	tx, it, err := begin(eng, in)
	if err != nil {
		return nil, err
	}

	defer tx.Close()

	tx.ProcessLogging()

	return outcome(tx, it, 1, 2, tx.Anomaly, started), nil
}

func ApplyKeep(eng Engine, in *Input) (*Outcome, *Live, error) {
	started := time.Now()

	tx, it, err := begin(eng, in)
	if err != nil {
		return nil, nil, err
	}

	return outcome(tx, it, 1, 2, tx.Anomaly, started),
		&Live{tx: tx, proto: protocolVersion(in.Version)}, nil
}

func (l *Live) Resume(rsp *ResponseInput) (*Outcome, error) {
	started := time.Now()

	defer l.tx.Close()

	return finish(l.tx, rsp, l.proto, started)
}

func (l *Live) Discard() {
	l.tx.Close()
}

func ApplyResponse(eng Engine, in *Input, rsp *ResponseInput) (*Outcome, error) {
	started := time.Now()

	tx, _, err := begin(eng, in)
	if err != nil {
		return nil, err
	}

	defer tx.Close()

	return finish(tx, rsp, protocolVersion(in.Version), started)
}

func begin(eng Engine, in *Input) (Transaction, *Intervention, error) {
	tx, err := eng.NewTransaction(in.RID)
	if err != nil {
		return nil, nil, err
	}

	var it *Intervention

	tx.ProcessConnection(in.ClientIP, in.ClientPort, in.ServerIP, in.ServerPort)

	tx.ProcessURI(requestTarget(in.URI, in.Args), in.Method, protocolVersion(in.Version))

	if in.Host != "" {
		tx.SetServerName(hostname(in.Host))
	}

	for _, h := range in.Headers {
		tx.AddRequestHeader(h[0], h[1])
	}

	if v := tx.ProcessRequestHeaders(); v != nil {
		it = v
	}

	if len(in.Body) > 0 {
		if err := tx.WriteRequestBody(in.Body); err != nil {
			tx.Close()
			return nil, nil, err
		}
	}

	v, err := tx.ProcessRequestBody()
	if err != nil {
		tx.Close()
		return nil, nil, err
	}

	if v != nil && it == nil {
		it = v
	}

	return tx, it, nil
}

func finish(tx Transaction, rsp *ResponseInput, proto string,
	started time.Time) (*Outcome, error) {

	var it *Intervention

	for _, h := range rsp.Headers {
		tx.AddResponseHeader(h[0], h[1])
	}

	if v := tx.ProcessResponseHeaders(rsp.Status, proto); v != nil {
		it = v
	}

	if len(rsp.Body) > 0 {
		if err := tx.WriteResponseBody(rsp.Body); err != nil {
			return nil, err
		}
	}

	v, err := tx.ProcessResponseBody()
	if err != nil {
		return nil, err
	}

	if v != nil && it == nil {
		it = v
	}

	tx.ProcessLogging()

	return outcome(tx, it, 3, 4, tx.AnomalyOutbound, started), nil
}

func outcome(tx Transaction, it *Intervention, lo, hi int,
	score func() (int, int), started time.Time) *Outcome {

	out := &Outcome{Intervention: it}

	out.Matched = matchedPhases(tx, lo, hi)
	out.AnomalyScore, out.Threshold = score()
	out.EngineMS = float64(time.Since(started).Microseconds()) / 1000

	return out
}

func matchedPhases(tx Transaction, lo, hi int) []MatchedRule {
	all := tx.Matched()

	out := make([]MatchedRule, 0, len(all))

	for _, m := range all {
		if m.Phase >= lo && m.Phase <= hi {
			out = append(out, m)
		}
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

func requestTarget(uri, args string) string {
	if args == "" {
		return uri
	}

	return uri + "?" + args
}

func protocolVersion(v string) string {
	if v == "" {
		return "1.1"
	}

	return strings.TrimPrefix(v, "HTTP/")
}

func hostname(host string) string {
	if i := strings.LastIndex(host, ":"); i != -1 && !strings.Contains(host[i:], "]") {
		return host[:i]
	}

	return host
}
