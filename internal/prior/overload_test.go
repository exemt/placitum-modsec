package prior

import "testing"

func TestOverloadRowsLoad(t *testing.T) {
	if _, err := policyWith(t, "outcomes:\n  - {on: overload, at: 60, list: hot, ttl: 1h}\n"); err != nil {
		t.Fatalf("at 60: %v", err)
	}

	for name, body := range map[string]string{
		"under the scale": "outcomes:\n  - {on: overload, at: 10, list: hot, ttl: 1h}\n",
		"over the scale":  "outcomes:\n  - {on: overload, at: 101, list: hot, ttl: 1h}\n",
		"below":           "outcomes:\n  - {on: overload, at: 60, below: true, list: hot, ttl: 1h}\n",
	} {
		if _, err := policyWith(t, body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFireOverloadThreshold(t *testing.T) {
	at := 60
	rows := []Outcome{
		{On: OnOverload, At: &at, To: "captcha", Do: "challenge"},
		{On: OnOverload, List: "hot", TTL: "1h"},
		{On: OnDeny, List: "deny", TTL: "1h"},
	}

	if got := FireOverload(rows, 59, false, "203.0.113.7", "MODSEC_QUEUE_LIMIT"); len(got.Names) != 0 {
		t.Fatalf("below the threshold fired %v", got.Names)
	}

	// От порога -- строка с порогом; строка без порога это край и молчит.
	got := FireOverload(rows, 60, false, "203.0.113.7", "MODSEC_QUEUE_LIMIT")
	if len(got.Actions) != 1 || len(got.Bans) != 0 {
		t.Fatalf("at 60%%: %d asks and %d lists, want the ask alone", len(got.Actions), len(got.Bans))
	}

	// Сброс: обе строки перегрузки, deny молчит; повод -- код сброса.
	shed := FireOverload(rows, 100, true, "203.0.113.7", "MODSEC_QUEUE_LIMIT")
	if len(shed.Actions) != 1 || len(shed.Bans) != 1 || shed.Bans[0].Dataset != "hot" {
		t.Fatalf("shed: %d asks and %d lists", len(shed.Actions), len(shed.Bans))
	}

	if shed.Bans[0].Reason != "MODSEC_QUEUE_LIMIT" {
		t.Fatalf("reason %q", shed.Bans[0].Reason)
	}
}
