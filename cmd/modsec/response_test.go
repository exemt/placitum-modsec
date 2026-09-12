/*
 * Ветка фазы ответа: разбор того, что приехало, до движка.
 *
 * Здесь проверяется не инспекция, а перевод сообщения в вход движка -- место,
 * где ошибка выглядит как "правила почему-то ничего не находят", а не как
 * падение.
 */

package main

import (
	"testing"

	"github.com/exemt/placitum-modsec/internal/protocol"
)

func TestResponseStatusFallsBackTo200(t *testing.T) {
	cases := map[string]struct {
		req  *protocol.Request
		want int
	}{
		"no section":  {&protocol.Request{}, 200},
		"zero status": {&protocol.Request{Response: &protocol.Response{}}, 200},
		"real status": {&protocol.Request{Response: &protocol.Response{Status: 502}}, 502},
	}

	for name, c := range cases {
		if got := responseStatus(c.req); got != c.want {
			t.Errorf("%s: status = %d, want %d", name, got, c.want)
		}
	}
}

func TestPairsKeepsOrderAndDuplicates(t *testing.T) {
	hdr := []protocol.Header{
		{"set-cookie", "a=1"},
		{"set-cookie", "b=2"},
		{"content-type", "application/json"},
	}

	got := pairs(hdr)

	if len(got) != 3 {
		t.Fatalf("pairs = %v, want all three: duplicates of set-cookie are "+
			"the whole reason the wire carries pairs", got)
	}

	if got[0] != [2]string{"set-cookie", "a=1"} || got[1][1] != "b=2" {
		t.Errorf("order lost: %v", got)
	}
}

// Фаза, которой у инспектора нет, отвергается ещё в потоке приёма. Обе стороны
// транзакции HTTP он умеет всегда -- набор правил у них один, -- а кадр
// подаётся движку синтетической транзакцией (frame.go).
func TestSupportsPhases(t *testing.T) {
	h := &handler{registry: nil}

	if !h.supports(protocol.PhaseRequest) {
		t.Error("the request phase must always be supported")
	}

	if !h.supports(protocol.PhaseFrame) {
		t.Error("frames are inspected as synthetic transactions")
	}

	if h.supports("nonsense") {
		t.Error("an unknown phase was accepted")
	}
}
