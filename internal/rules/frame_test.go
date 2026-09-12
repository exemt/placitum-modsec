/*
 * Поставляемый профиль против кадра WebSocket в той форме, в какой его подаёт
 * движку cmd/modsec/frame.go: POST на адрес рукопожатия, один аргумент формы.
 *
 * Два утверждения, и оба про калибровку: безобидное сообщение чата не набирает
 * ни очка (иначе каждый кадр маршрута шёл бы в счёт), а инъекция в том же
 * аргументе набирает порог CRS -- score 50 по калибровке инспектора, то есть
 * ровно то, на что рассчитан waf_score_deny frame:c2s 50 стенда.
 */

package rules

import (
	"net/url"
	"strconv"
	"testing"

	"github.com/exemt/placitum-modsec/internal/engine"
)

func frameSide(payload string) *engine.Input {
	body := "frame=" + url.QueryEscape(payload)

	return &engine.Input{
		RID:        "01",
		ClientIP:   "203.0.113.42",
		ClientPort: 51544,
		Method:     "POST",
		URI:        "/ws/chat",
		Version:    "HTTP/1.1",
		Host:       "app.example.com",
		Headers: [][2]string{
			{"Host", "app.example.com"},
			{"Content-Type", "application/x-www-form-urlencoded"},
			{"Content-Length", strconv.Itoa(len(body))},
		},
		Body: []byte(body),
	}
}

func TestFrameBenignMessageScoresNothing(t *testing.T) {
	set := shipped(t)

	out, err := engine.Apply(set.profiles[DefaultProfile].engine,
		frameSide(`{"type":"msg","text":"привет"}`))
	if err != nil {
		t.Fatal(err)
	}

	if out.AnomalyScore != 0 {
		t.Errorf("anomaly = %d on a chat message, matched %v", out.AnomalyScore, ids(out.Matched))
	}
}

func TestFrameInjectionReachesThreshold(t *testing.T) {
	set := shipped(t)

	out, err := engine.Apply(set.profiles[DefaultProfile].engine,
		frameSide(`{"q":"1' OR 1=1-- "}`))
	if err != nil {
		t.Fatal(err)
	}

	if out.AnomalyScore < out.Threshold {
		t.Errorf("anomaly = %d below threshold %d, matched %v",
			out.AnomalyScore, out.Threshold, ids(out.Matched))
	}

	found := false

	for _, id := range ids(out.Matched) {
		if id >= 942000 && id < 943000 {
			found = true
		}
	}

	if !found {
		t.Errorf("no SQLi rule fired on ARGS_POST:frame, matched %v", ids(out.Matched))
	}
}
