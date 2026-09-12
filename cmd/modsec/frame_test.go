/*
 * Ветка фазы кадров: перевод кадра во вход движка. Ошибка здесь выглядит как
 * "CRS на кадрах ничего не находит", а не как падение, -- поэтому проверяется
 * именно форма транзакции: метод, тип тела, аргумент и заголовки рукопожатия.
 */

package main

import (
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/exemt/placitum-modsec/internal/body"
	"github.com/exemt/placitum-modsec/internal/protocol"
)

func TestFrameInputIsFormPostOnHandshakeURI(t *testing.T) {
	req := &protocol.Request{
		RID:   "01",
		Phase: protocol.PhaseFrame,
		HTTP:  protocol.HTTP{Method: "GET", URI: "/ws/chat", Host: "app.example.com", Version: "HTTP/1.1"},
		Conn:  protocol.Conn{ClientIP: "203.0.113.42", ClientPort: 51544},
	}

	hdr := []protocol.Header{
		{"Host", "app.example.com"},
		{"Cookie", "sid=abc"},
		{"Content-Length", "0"},
		{"Upgrade", "websocket"},
	}

	payload := `{"q":"1' OR 1=1-- "}`

	in := frameInput(req, hdr, body.Body{Data: []byte(payload)})

	if in.Method != "POST" {
		t.Errorf("method = %q, want POST", in.Method)
	}

	if in.URI != "/ws/chat" || in.Host != "app.example.com" {
		t.Errorf("uri/host = %q/%q, want handshake values", in.URI, in.Host)
	}

	if in.Args != "" {
		t.Errorf("args = %q, want none: the frame carries no query string", in.Args)
	}

	// Тело -- один аргумент формы, декодируемый обратно в исходные байты.
	got, err := url.ParseQuery(string(in.Body))
	if err != nil {
		t.Fatalf("body is not urlencoded: %v", err)
	}

	if got.Get(frameArg) != payload {
		t.Errorf("ARGS_POST:%s = %q, want the payload verbatim", frameArg, got.Get(frameArg))
	}

	var ct, cl, cookie, upgrade string
	contentLength := 0

	for _, h := range in.Headers {
		switch strings.ToLower(h[0]) {
		case "content-type":
			ct = h[1]
		case "content-length":
			cl = h[1]
			contentLength++
		case "cookie":
			cookie = h[1]
		case "upgrade":
			upgrade = h[1]
		}
	}

	if ct != "application/x-www-form-urlencoded" {
		t.Errorf("content-type = %q, want urlencoded so ARGS_POST is filled", ct)
	}

	if contentLength != 1 || cl != strconv.Itoa(len(in.Body)) {
		t.Errorf("content-length = %q (x%d), want the frame body length once", cl, contentLength)
	}

	if cookie != "sid=abc" || upgrade != "websocket" {
		t.Errorf("handshake headers lost: cookie %q, upgrade %q", cookie, upgrade)
	}
}

func TestFrameInputWithoutHandshakeHeaders(t *testing.T) {
	req := &protocol.Request{HTTP: protocol.HTTP{URI: "/ws", Host: "app.example.com"}}

	in := frameInput(req, nil, body.Body{Data: []byte("ping me")})

	if in.Version != "HTTP/1.1" {
		t.Errorf("version = %q, want HTTP/1.1 fallback", in.Version)
	}

	// Host из секции http: без него CRS 920280 даёт критические 5 очков
	// на каждом кадре маршрута, который заголовки рукопожатия не снимает.
	if len(in.Headers) != 3 || in.Headers[0] != [2]string{"Host", "app.example.com"} {
		t.Errorf("headers = %v, want host, content-type and content-length", in.Headers)
	}

	if string(in.Body) != "frame=ping+me" {
		t.Errorf("body = %q", in.Body)
	}
}

func TestFrameEngineCarriesFraming(t *testing.T) {
	req := &protocol.Request{
		ConnID: "conn-1", Seq: 7,
		Stream: &protocol.Stream{Direction: "c2s", Opcode: "text", Fin: true, Subprotocol: "chat.v2"},
	}

	e := frameEngine(req)

	if e["phase"] != protocol.PhaseFrame || e["conn"] != "conn-1" || e["seq"] != uint64(7) {
		t.Errorf("identity lost: %v", e)
	}

	if e["opcode"] != "text" || e["direction"] != "c2s" || e["subprotocol"] != "chat.v2" {
		t.Errorf("framing lost: %v", e)
	}

	if frameOpcode(&protocol.Request{}) != "unknown" {
		t.Errorf("opcode without stream should read unknown")
	}
}
