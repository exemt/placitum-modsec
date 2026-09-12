/*
 * Освобождение продолжения: сообщение, которое приезжает вместо инспекции.
 *
 * Разбирается оно тем же Parse и по тем же правилам конверта -- имя и фаза
 * проверяются там же, где у обычного сообщения, -- но дальше не идёт: ни http,
 * ни обменника, ни вердикта в ответ.
 */

package protocol

import "testing"

const releaseMsg = `{
  "v": 2,
  "rid": "3f2a9c1e00000017",
  "inspector": "modsec",
  "phase": "response",
  "release": { "token": "MHDxOEwOEFDoHDwXbXQ0lS", "reason": "deny" }
}`

func TestParseRelease(t *testing.T) {
	req, err := Parse([]byte(releaseMsg))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if req.Release == nil {
		t.Fatal("release section was lost")
	}

	if req.Release.Token != "MHDxOEwOEFDoHDwXbXQ0lS" {
		t.Errorf("token = %q", req.Release.Token)
	}

	if req.Release.Reason != "deny" {
		t.Errorf("reason = %q", req.Release.Reason)
	}
}

/*
 * Секции http у освобождения нет, и требовать её -- значит отвергать
 * сообщение, у которого её и не может быть: инспектировать нечего, запрос
 * закончился.
 */
func TestParseReleaseNeedsNoHTTP(t *testing.T) {
	if _, err := Parse([]byte(releaseMsg)); err != nil {
		t.Fatalf("release was rejected for a missing http section: %v", err)
	}

	// А обычное сообщение без http по-прежнему отвергается.
	const noHTTP = `{"v":2,"rid":"3f2a9c1e00000017","inspector":"modsec","phase":"request"}`

	if _, err := Parse([]byte(noHTTP)); err == nil {
		t.Fatal("an inspection message without http was accepted")
	}
}

// Ключ обязателен: без него бросать нечего, а молча ничего не делать -- значит
// оставить состояние жить до срока и не сказать об этом.
func TestParseReleaseWithoutToken(t *testing.T) {
	const noToken = `{
      "v": 2, "rid": "3f2a9c1e00000017", "inspector": "modsec",
      "phase": "response", "release": {"reason": "skip"}
    }`

	if _, err := Parse([]byte(noToken)); err == nil {
		t.Fatal("a release without a token was accepted")
	}
}

// Конверт проверяется как у всех: освобождение от чужого имени или на
// несуществующей фазе -- такая же ошибка, как чужой вердикт.
func TestParseReleaseKeepsEnvelopeRules(t *testing.T) {
	const badPhase = `{
      "v": 2, "rid": "3f2a9c1e00000017", "inspector": "modsec",
      "phase": "trailers", "release": {"token": "x"}
    }`

	if _, err := Parse([]byte(badPhase)); err == nil {
		t.Fatal("a release on an unknown phase was accepted")
	}
}
