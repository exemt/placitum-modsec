/*
 * Коэффициент к отдаваемому счёту по просьбе threshold. Пороги -- и CRS, и
 * waf_score_deny -- не двигаются вовсе: меняется цена поведения клиента, то
 * есть число, которое инспектор отдаёт модулю.
 */

package verdict

import (
	"testing"

	"github.com/exemt/placitum-modsec/internal/engine"
	"github.com/exemt/placitum-modsec/internal/protocol"
)

func TestScaleScore(t *testing.T) {
	cases := []struct {
		score, percent, want int
	}{
		{50, 0, 50},
		{50, -50, 25},  // скидка вдвое: намерял 50, отдал 25
		{50, 100, 100}, // вдвое дороже
		{40, 50, 60},   // +50%: 40 -> 60
		{50, -100, 0},  // измерение в ноль
		{20, 900, 100}, // x10 упирается в потолок score
		{0, 900, 0},    // нечего масштабировать
	}

	for _, c := range cases {
		if got := ScaleScore(c.score, c.percent); got != c.want {
			t.Errorf("ScaleScore(%d, %d) = %d, want %d",
				c.score, c.percent, got, c.want)
		}
	}
}

// Скидка уменьшает то, что уедет модулю, наценка увеличивает; собственный
// порог калибровки остаётся нетронутым знаменателем.
func TestFromWithScalePercent(t *testing.T) {
	req := &protocol.Request{V: 2, RID: "1", Inspector: "modsec"}
	out := &engine.Outcome{AnomalyScore: 5, Threshold: 5}

	plain := From(req, out, Options{})
	if plain.Score == nil || *plain.Score != 50 {
		t.Fatalf("score without scale = %+v, want 50", plain.Score)
	}

	soft := From(req, out, Options{ScalePercent: -50})
	if soft.Score == nil || *soft.Score != 25 {
		t.Fatalf("score with -50%% = %+v, want 25", soft.Score)
	}

	hard := From(req, out, Options{ScalePercent: 100})
	if hard.Score == nil || *hard.Score != 100 {
		t.Fatalf("score with +100%% = %+v, want 100", hard.Score)
	}

	zero := From(req, out, Options{ScalePercent: -100})
	if zero.Score == nil || *zero.Score != 0 {
		t.Fatalf("score with -100%% = %+v, want 0", zero.Score)
	}
}
