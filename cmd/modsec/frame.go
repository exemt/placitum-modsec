package main

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/exemt/placitum-modsec/internal/audit"
	"github.com/exemt/placitum-modsec/internal/body"
	"github.com/exemt/placitum-modsec/internal/engine"
	"github.com/exemt/placitum-modsec/internal/prior"
	"github.com/exemt/placitum-modsec/internal/protocol"
	"github.com/exemt/placitum-modsec/internal/verdict"
)

const frameArg = "frame"

const codeFrameBinary = "MODSEC_FRAME_BINARY"

var frameDropHeaders = map[string]struct{}{
	"content-type":      {},
	"content-length":    {},
	"transfer-encoding": {},
}

func (h *handler) inspectFrame(req *protocol.Request, budget time.Duration) (
	*protocol.Reply, audit.Details) {

	eng, sel := h.registry.Select(req.Route.Profile)

	if eng == nil {
		h.log.Warn("unknown frame profile", "rid", req.RID, "profile", sel.Profile)

		return protocol.ErrorReply(req, codeUnknownProfile),
			audit.Details{Engine: frameEngine(req)}
	}

	if frameOpcode(req) == "binary" {
		reply := protocol.NewReply(req, protocol.VerdictAllow)
		reply.Reason = &protocol.Reason{Code: codeFrameBinary}

		det := audit.Details{Engine: frameEngine(req)}
		det.Engine["skip"] = "binary"

		return reply, det
	}

	ask := prior.Evaluate(req.Prior, h.registry.PriorRules(sel.Profile))

	if ask.Skip {
		reply := protocol.NewReply(req, protocol.VerdictAllow)
		reply.Reason = &protocol.Reason{Code: codeSkipped}

		det := audit.Details{Engine: frameEngine(req)}
		det.Engine["skip"] = true
		det.Engine["actions"] = ask.Outcomes

		return reply, det
	}

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	got := h.loader.LoadMany(ctx, req.RequestStore.Headers, req.Store.Body)

	hdr := h.headers(req, got[0])
	b := got[1]

	if code, why := bodyError(b); code != "" {
		h.log.Warn("frame payload not inspectable", "rid", req.RID, "body", why)

		det := audit.Details{Engine: frameEngine(req)}
		det.Engine["body"] = why

		return protocol.ErrorReply(req, code), det
	}

	out, err := engine.Apply(eng, frameInput(req, hdr, b))

	if err != nil {
		h.log.Error("engine failed on a frame", "rid", req.RID, "error", err.Error())

		det := audit.Details{Engine: frameEngine(req)}
		det.Engine["error"] = err.Error()

		return protocol.ErrorReply(req, codeInternalError), det
	}

	opts := h.opts
	opts.ScalePercent = ask.Percent

	reply := verdict.From(req, out, opts)
	det := verdict.Detail(out)

	applyAsk(det, ask, out)

	for k, v := range frameEngine(req) {
		det.Engine[k] = v
	}

	if sel.Unknown {
		det.Engine["profile_requested"] = sel.Profile
	}

	fired := prior.Fire(h.registry.Outcomes(sel.Profile), reply.Verdict,
		scoreOf(reply), out.Matched, req.Conn.ClientIP, codeOf(reply))

	if len(fired.Names) != 0 {
		det.Engine["outcomes"] = fired.Names
	}

	if err := h.publish(ctx, fired.Bans, req); err != nil {
		h.log.Error("geo unavailable for a list write", "rid", req.RID,
			"profile", sel.Profile, "error", err.Error())

		det.Engine["geo"] = err.Error()

		return protocol.ErrorReply(req, codeGeoUnavailable), det
	}

	if len(fired.Actions) != 0 {
		reply.Actions = fired.Actions
	}

	h.log.Info("verdict",
		"rid", req.RID,
		"inspector", req.Inspector,
		"phase", req.Phase,
		"conn", req.ConnID,
		"seq", req.Seq,
		"opcode", frameOpcode(req),
		"uri", req.HTTP.URI,
		"client_ip", req.Conn.ClientIP,
		"profile", sel.Profile,
		"verdict", reply.Verdict,
		"score", scoreOf(reply),
		"reason", codeOf(reply),
		"crs_anomaly_score", out.AnomalyScore,
		"asks", len(fired.Actions),
		"lists", len(fired.Bans),
		"engine_ms", out.EngineMS,
		"budget_ms", budget.Milliseconds(),
	)

	return reply, det
}

func frameInput(req *protocol.Request, hdr []protocol.Header, b body.Body) *engine.Input {
	payload := frameArg + "=" + url.QueryEscape(string(b.Data))

	headers := make([][2]string, 0, len(hdr)+3)
	hasHost := false

	for _, h := range hdr {
		if _, drop := frameDropHeaders[strings.ToLower(h.Name())]; drop {
			continue
		}

		if strings.EqualFold(h.Name(), "host") {
			hasHost = true
		}

		headers = append(headers, [2]string{h.Name(), h.Value()})
	}

	if !hasHost && req.HTTP.Host != "" {
		headers = append(headers, [2]string{"Host", req.HTTP.Host})
	}

	headers = append(headers,
		[2]string{"Content-Type", "application/x-www-form-urlencoded"},
		[2]string{"Content-Length", strconv.Itoa(len(payload))},
	)

	version := req.HTTP.Version
	if version == "" {
		version = "HTTP/1.1"
	}

	return &engine.Input{
		RID:        req.RID,
		ClientIP:   req.Conn.ClientIP,
		ClientPort: req.Conn.ClientPort,
		ServerIP:   req.Conn.ServerIP,
		ServerPort: req.Conn.ServerPort,
		Method:     "POST",
		URI:        req.HTTP.URI,
		Args:       "",
		Version:    version,
		Host:       req.HTTP.Host,
		Headers:    headers,
		Body:       []byte(payload),
	}
}

func frameEngine(req *protocol.Request) map[string]any {
	e := map[string]any{
		"phase":  protocol.PhaseFrame,
		"conn":   req.ConnID,
		"seq":    req.Seq,
		"opcode": frameOpcode(req),
	}

	if req.Stream != nil {
		e["direction"] = req.Stream.Direction
		e["fin"] = req.Stream.Fin

		if req.Stream.Subprotocol != "" {
			e["subprotocol"] = req.Stream.Subprotocol
		}
	}

	return e
}

func frameOpcode(req *protocol.Request) string {
	if req.Stream == nil || req.Stream.Opcode == "" {
		return "unknown"
	}

	return req.Stream.Opcode
}
