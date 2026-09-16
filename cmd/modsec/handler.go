package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-modsec/internal/audit"
	"github.com/exemt/placitum-modsec/internal/body"
	"github.com/exemt/placitum-modsec/internal/config"
	"github.com/exemt/placitum-modsec/internal/engine"
	"github.com/exemt/placitum-modsec/internal/prior"
	"github.com/exemt/placitum-modsec/internal/protocol"
	"github.com/exemt/placitum-modsec/internal/queue"
	"github.com/exemt/placitum-modsec/internal/rules"
	"github.com/exemt/placitum-modsec/internal/sticky"
	"github.com/exemt/placitum-modsec/internal/verdict"
	"github.com/exemt/placitum-shared/dataset"
	"github.com/exemt/placitum-shared/netinfo"
)

const (
	codeUnsupportedVersion = "MODSEC_UNSUPPORTED_VERSION"
	codeMalformed          = "MODSEC_MALFORMED_REQUEST"
	codeInternalError      = "MODSEC_INTERNAL_ERROR"
	codeUnknownProfile     = "MODSEC_UNKNOWN_PROFILE"
	codeWrongPhase         = "MODSEC_PHASE_NOT_SUPPORTED"
	codeBodyUnavailable    = "MODSEC_BODY_UNAVAILABLE"
	codeBodyTruncated      = "MODSEC_BODY_TRUNCATED"
	codeResumeLost         = "MODSEC_RESUME_LOST"
	codeSkipped            = "MODSEC_SKIPPED"
	codeGeoUnavailable     = "MODSEC_GEO_UNAVAILABLE"
)

type handler struct {
	cfg      *config.Config
	log      *slog.Logger
	nc       *nats.Conn
	audit    *audit.Sink
	registry *rules.Registry
	loader   *body.Loader
	opts     verdict.Options
	pool     *queue.Pool

	inbox  string
	sticky *sticky.Registry[*engine.Live]

	lists    *dataset.Publisher
	resolver *netinfo.Resolver
}

func (h *handler) receive(msg *nats.Msg) {
	defer h.recoverInto(msg.Reply, "")

	req, err := protocol.Parse(msg.Data)
	if err != nil {
		rid := ""

		var pe *protocol.ParseError
		if errors.As(err, &pe) {
			rid = pe.RID
		}

		h.log.Warn("message rejected", "error", err.Error(), "bytes", len(msg.Data))
		h.send(msg.Reply, protocol.FallbackReply(rid, h.cfg.Name, codeMalformed), nil,
			audit.Details{})

		return
	}

	if !h.cfg.Supports(req.V) {
		reply := protocol.ErrorReply(req, codeUnsupportedVersion)
		reply.V = protocol.Version
		h.send(msg.Reply, reply, req, audit.Details{})

		return
	}

	if req.Release != nil {
		h.releaseState(req)

		return
	}

	if !h.supports(req.Phase) {
		h.send(msg.Reply, protocol.ErrorReply(req, codeWrongPhase), req,
			audit.Details{})

		return
	}

	h.pool.Submit(&queue.Task{
		Req:      req,
		Reply:    msg.Reply,
		Personal: h.inbox != "" && msg.Subject == h.inbox,
	})
}

func (h *handler) evaluate(t *queue.Task, budget time.Duration, shed string) {
	defer h.recoverInto(t.Reply, t.Req.RID)

	if shed != "" {
		reply := protocol.ShedReply(t.Req, shed)

		det := audit.Details{Engine: map[string]any{
			"shed":      shed,
			"budget_ms": float64(budget.Microseconds()) / 1000,
		}}

		var fired prior.Fired
		if shed == queue.ReasonQueueLimit && t.Req.Phase == protocol.PhaseRequest {
			fired = prior.FireOverload(h.registry.Outcomes(t.Req.Route.Profile),
				t.Fill, true, t.Req.Conn.ClientIP, shed)

			if len(fired.Actions) != 0 {
				reply.Actions = fired.Actions
			}

			if err := h.publish(context.Background(), fired.Bans, t.Req); err != nil {
				h.log.Error("geo unavailable for a list write", "rid", t.Req.RID,
					"profile", t.Req.Route.Profile, "error", err.Error())

				det.Engine["geo"] = err.Error()
			}

			if len(fired.Names) != 0 {
				det.Engine["outcomes"] = fired.Names
			}
		}

		h.log.Warn("shed", "rid", t.Req.RID, "reason", shed,
			"budget_ms", budget.Milliseconds(),
			"asks", len(fired.Actions), "lists", len(fired.Bans))
		h.send(t.Reply, reply, t.Req, det)

		return
	}

	reply, det := h.inspect(t, budget)
	h.send(t.Reply, reply, t.Req, det)
}

func (h *handler) supports(phase string) bool {
	switch phase {
	case protocol.PhaseRequest:
		return true

	case protocol.PhaseResponse:
		return true

	case protocol.PhaseFrame:
		return true

	default:
		return false
	}
}

func (h *handler) inspect(t *queue.Task, budget time.Duration) (*protocol.Reply,
	audit.Details) {

	req := t.Req

	if req.Phase == protocol.PhaseResponse {
		return h.inspectResponse(req, budget, t.Personal)
	}

	if req.Phase == protocol.PhaseFrame {
		return h.inspectFrame(req, budget)
	}

	eng, sel := h.registry.Select(req.Route.Profile)

	if eng == nil {
		h.log.Warn("unknown profile", "rid", req.RID, "profile", sel.Profile)

		return protocol.ErrorReply(req, codeUnknownProfile), audit.Details{}
	}

	ask := prior.Evaluate(req.Prior, h.registry.PriorRules(sel.Profile))

	if ask.Skip {
		reply := protocol.NewReply(req, protocol.VerdictAllow)
		reply.Reason = &protocol.Reason{Code: codeSkipped}

		h.log.Info("skipped by a prior ask",
			"rid", req.RID,
			"uri", req.HTTP.URI,
			"client_ip", req.Conn.ClientIP,
			"profile", sel.Profile,
		)

		return reply, audit.Details{Engine: map[string]any{
			"skip":    true,
			"actions": ask.Outcomes,
		}}
	}

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	got := h.loader.LoadMany(ctx, req.Store.Headers, req.Store.Args, req.Store.Body)

	hdr := h.headers(req, got[0])
	args := argsOf(got[1])
	b := got[2]

	if code, why := bodyError(b); code != "" {
		h.log.Warn("body not inspectable", "rid", req.RID, "body", why)

		return protocol.ErrorReply(req, code),
			audit.Details{Engine: map[string]any{"body": why}}
	}

	keep := h.wantsResume(req)

	var (
		out  *engine.Outcome
		live *engine.Live
		err  error
	)

	if keep {
		out, live, err = engine.ApplyKeep(eng, input(req, args, hdr, b))
	} else {
		out, err = engine.Apply(eng, input(req, args, hdr, b))
	}

	if err != nil {
		if live != nil {
			live.Discard()
		}

		h.log.Error("engine failed", "rid", req.RID, "error", err.Error())

		return protocol.ErrorReply(req, codeInternalError),
			audit.Details{Engine: map[string]any{"error": err.Error()}}
	}

	opts := h.opts
	opts.ScalePercent = ask.Percent

	reply := verdict.From(req, out, opts)
	det := verdict.Detail(out)

	applyAsk(det, ask, out)

	if sel.Unknown {
		det.Engine["profile_requested"] = sel.Profile
	}

	fired := prior.Fire(h.registry.Outcomes(sel.Profile), reply.Verdict,
		scoreOf(reply), out.Matched, req.Conn.ClientIP, codeOf(reply))

	more := prior.FireOverload(h.registry.Outcomes(sel.Profile), t.Fill, false,
		req.Conn.ClientIP, queue.ReasonQueueLimit)

	fired.Actions = append(fired.Actions, more.Actions...)
	fired.Bans = append(fired.Bans, more.Bans...)
	fired.Names = append(fired.Names, more.Names...)

	if len(fired.Names) != 0 {
		det.Engine["outcomes"] = fired.Names
	}

	if err := h.publish(ctx, fired.Bans, req); err != nil {
		if live != nil {
			live.Discard()
		}

		h.log.Error("geo unavailable for a list write", "rid", req.RID,
			"profile", sel.Profile, "error", err.Error())

		det.Engine["geo"] = err.Error()

		return protocol.ErrorReply(req, codeGeoUnavailable), det
	}

	if len(fired.Actions) != 0 {
		reply.Actions = fired.Actions
	}

	if live != nil {
		h.offerContinue(req, reply, det, live)
	}

	h.log.Info("verdict",
		"rid", req.RID,
		"inspector", req.Inspector,
		"wave", req.Wave,
		"method", req.HTTP.Method,
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

func (h *handler) headers(req *protocol.Request, loaded body.Body) []protocol.Header {
	if !loaded.Available() || len(loaded.Data) == 0 {
		return nil
	}

	var pairs []protocol.Header
	if err := json.Unmarshal(loaded.Data, &pairs); err != nil {
		h.log.Warn("headers blob is not an array of pairs",
			"rid", req.RID, "error", err.Error())
		return nil
	}

	return pairs
}

func argsOf(loaded body.Body) string {
	if !loaded.Available() {
		return ""
	}

	return string(loaded.Data)
}

func input(req *protocol.Request, args string, hdr []protocol.Header,
	b body.Body) *engine.Input {

	headers := make([][2]string, 0, len(hdr))

	for _, h := range hdr {
		headers = append(headers, [2]string{h.Name(), h.Value()})
	}

	return &engine.Input{
		RID:        req.RID,
		ClientIP:   req.Conn.ClientIP,
		ClientPort: req.Conn.ClientPort,
		ServerIP:   req.Conn.ServerIP,
		ServerPort: req.Conn.ServerPort,
		Method:     req.HTTP.Method,
		URI:        req.HTTP.URI,
		Args:       args,
		Version:    req.HTTP.Version,
		Host:       req.HTTP.Host,
		Headers:    headers,
		Body:       b.Data,
	}
}

func bodyError(b body.Body) (code, why string) {
	switch {
	case !b.Available():
		return codeBodyUnavailable, "unavailable:" + b.Unavailable
	case b.Truncated:
		return codeBodyTruncated, "truncated"
	}

	return "", ""
}

func (h *handler) send(subject string, reply *protocol.Reply, req *protocol.Request,
	det audit.Details) {

	if subject == "" {
		h.log.Error("no reply subject in message", "rid", reply.RID)
		return
	}

	payload, err := reply.Marshal()
	if err != nil {
		h.log.Error("reply marshal failed", "rid", reply.RID, "error", err.Error())

		payload, err = protocol.FallbackReply(reply.RID, reply.Inspector,
			codeInternalError).Marshal()
		if err != nil {
			return
		}
	}

	if err := h.nc.Publish(subject, payload); err != nil {
		h.log.Error("respond failed", "rid", reply.RID, "error", err.Error())
	}

	if err := h.audit.Add(req, reply, det); err != nil {
		h.log.Warn("audit publish failed", "rid", reply.RID, "error", err.Error())
	}
}

func (h *handler) recoverInto(subject, rid string) {
	r := recover()
	if r == nil {
		return
	}

	h.log.Error("handler panicked", "rid", rid, "panic", r, "stack", string(debug.Stack()))

	if subject != "" {
		h.send(subject, protocol.FallbackReply(rid, h.cfg.Name, codeInternalError), nil,
			audit.Details{})
	}
}

func applyAsk(det audit.Details, ask prior.Ask, out *engine.Outcome) {
	if len(ask.Outcomes) != 0 {
		det.Engine["actions"] = ask.Outcomes
	}

	if ask.Percent != 0 {
		raw := verdict.Calibrate(out.AnomalyScore, out.Threshold)

		det.Engine["score_scale_percent"] = ask.Percent
		det.Engine["score_raw"] = raw
		det.Engine["score_scaled"] = verdict.ScaleScore(raw, ask.Percent)
	}
}

func scoreOf(r *protocol.Reply) int {
	if r.Score == nil {
		return 0
	}

	return *r.Score
}

func codeOf(r *protocol.Reply) string {
	if r.Reason == nil {
		return ""
	}

	return r.Reason.Code
}

func (h *handler) publish(ctx context.Context, bans []prior.Ban, req *protocol.Request) error {
	if len(bans) == 0 || h.lists == nil {
		return nil
	}

	return writeLists(ctx, h.resolver, h.lists, h.log, req.RID, bans)
}
