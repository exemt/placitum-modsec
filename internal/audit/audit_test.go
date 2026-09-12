package audit

import (
	"encoding/json"
	"testing"

	"github.com/exemt/placitum-modsec/internal/protocol"
)

func TestBuildJoinsRequestAndReply(t *testing.T) {
	score := 80
	req := &protocol.Request{
		RID:       "3f2a9c1e00000017",
		Ray:       "7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03",
		Node:      "edge-01",
		Phase:     protocol.PhaseRequest,
		Inspector: "modsec",
		Route:     protocol.Route{Profile: "strict"},
	}
	reply := &protocol.Reply{
		V:         protocol.Version,
		RID:       req.RID,
		Inspector: "modsec",
		Verdict:   protocol.VerdictScore,
		Score:     &score,
		Reason:    &protocol.Reason{Code: "CRS_ANOMALY"},
	}

	ev := Build(req, reply, Details{
		EngineMS: 1.5,
		Findings: []Finding{{
			Code:     "crs-942100",
			Severity: SeverityHigh,
			Target:   "args",
			Rule:     "942100",
		}},
		Engine: map[string]any{"crs_anomaly_score": 15},
	})

	if ev.V != Version || ev.Kind != Kind {
		t.Fatalf("envelope: %+v", ev)
	}

	// Склейка -- по ray: rid адресует слот воркера и переиспользуется, поэтому
	// в событии его нет вовсе.
	if ev.Ray != req.Ray || ev.Node != "edge-01" || ev.Phase != "request" {
		t.Fatalf("ids: %+v", ev)
	}

	if ev.Profile != "strict" {
		t.Fatalf("profile: %q", ev.Profile)
	}

	// Инвариант склейки: score события совпадает со score ответа, иначе связь
	// по ray проверить нечем.
	if ev.Score == nil || *ev.Score != score {
		t.Fatalf("score: %v", ev.Score)
	}

	if len(ev.Findings) != 1 || ev.Findings[0].Rule != "942100" {
		t.Fatalf("findings: %+v", ev.Findings)
	}

	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}

	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}

	if back["kind"] != Kind || back["node"] != "edge-01" {
		t.Fatalf("json: %s", raw)
	}

	// Ни rid, ни reason: первое адресует слот, второе уже уехало модулю.
	if _, ok := back["rid"]; ok {
		t.Fatalf("rid must not travel to audit: %s", raw)
	}
}

// Пустой массив, а не пропущенное поле: "отработал и не нашёл ничего" -- это
// результат, и выглядеть он должен как результат.
func TestBuildEmptyFindings(t *testing.T) {
	ev := Build(&protocol.Request{Inspector: "modsec"},
		protocol.FallbackReply("abc", "modsec", "MODSEC_MALFORMED_REQUEST"), Details{})

	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}

	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}

	list, ok := back["findings"].([]any)
	if !ok || len(list) != 0 {
		t.Fatalf("findings: %s", raw)
	}
}
