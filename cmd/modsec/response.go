package main

import (
	"context"
	"time"

	"github.com/exemt/placitum-modsec/internal/audit"
	"github.com/exemt/placitum-modsec/internal/body"
	"github.com/exemt/placitum-modsec/internal/engine"
	"github.com/exemt/placitum-modsec/internal/prior"
	"github.com/exemt/placitum-modsec/internal/protocol"
	"github.com/exemt/placitum-modsec/internal/rules"
	"github.com/exemt/placitum-modsec/internal/verdict"
)

func (h *handler) inspectResponse(req *protocol.Request, budget time.Duration,
	personal bool) (*protocol.Reply, audit.Details) {

	live := h.resumeState(req)

	ask := prior.Evaluate(req.Prior, h.registry.PriorRules(req.Route.Profile))

	if ask.Skip {
		if live != nil {
			live.Discard()
		}

		reply := protocol.NewReply(req, protocol.VerdictAllow)
		reply.Reason = &protocol.Reason{Code: codeSkipped}

		h.log.Info("skipped by a prior ask",
			"rid", req.RID,
			"phase", req.Phase,
			"uri", req.HTTP.URI,
			"client_ip", req.Conn.ClientIP,
			"profile", req.Route.Profile,
		)

		return reply, audit.Details{Engine: map[string]any{
			"phase":   protocol.PhaseResponse,
			"skip":    true,
			"actions": ask.Outcomes,
		}}
	}

	if live == nil && req.Resume != nil && req.Resume.Require {
		h.log.Error("resume required but state is gone",
			"rid", req.RID,
			"inspector", req.Inspector,
			"uri", req.HTTP.URI,
			"personal", personal,
			"live", h.stickyLive(),
		)

		return verdict.Deny(req, codeResumeLost, h.opts), audit.Details{
			Findings: []audit.Finding{{
				Code:     "modsec-resume-lost",
				Severity: audit.SeverityCritical,
				Target:   audit.TargetURI,
			}},
			Engine: map[string]any{
				"phase":    protocol.PhaseResponse,
				"resumed":  false,
				"resume":   "lost",
				"personal": personal,
			},
		}
	}

	var (
		eng engine.Engine
		sel rules.Selection
	)

	if live == nil {
		eng, sel = h.registry.Select(req.Route.Profile)

	} else {
		sel = rules.Selection{Profile: req.Route.Profile}
	}

	if live == nil && eng == nil {
		h.log.Warn("unknown response profile", "rid", req.RID, "profile", sel.Profile)

		return protocol.ErrorReply(req, codeUnknownProfile), audit.Details{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	locs := []*protocol.Locator{req.Store.Headers, req.Store.Body}

	if live == nil {
		locs = append(locs, req.RequestStore.Headers, req.RequestStore.Args)
	}

	got := h.loader.LoadMany(ctx, locs...)

	rspHdr := h.responseHeaders(req, got[0])
	rspBody := got[1]

	if code, why := bodyError(rspBody); code != "" {
		if live != nil {
			live.Discard()
		}

		h.log.Warn("response body not inspectable", "rid", req.RID, "body", why)

		return protocol.ErrorReply(req, code),
			audit.Details{Engine: map[string]any{"body": why}}
	}

	rsp := &engine.ResponseInput{
		Status:  responseStatus(req),
		Headers: pairs(rspHdr),
		Body:    rspBody.Data,
	}

	var (
		out *engine.Outcome
		err error
	)

	if live != nil {
		out, err = live.Resume(rsp)

	} else {
		reqHdr := h.headers(req, got[2])
		args := argsOf(got[3])

		out, err = engine.ApplyResponse(eng, input(req, args, reqHdr, body.Body{}), rsp)
	}

	if err != nil {
		h.log.Error("engine failed", "rid", req.RID, "phase", req.Phase,
			"error", err.Error())

		return protocol.ErrorReply(req, codeInternalError),
			audit.Details{Engine: map[string]any{"error": err.Error()}}
	}

	opts := h.opts
	opts.ScalePercent = ask.Percent

	reply := verdict.From(req, out, opts)
	det := verdict.Detail(out)

	applyAsk(det, ask, out)

	det.Engine["phase"] = protocol.PhaseResponse
	det.Engine["resumed"] = live != nil
	det.Engine["personal"] = personal

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
			"phase", req.Phase, "profile", sel.Profile, "error", err.Error())

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
		"wave", req.Wave,
		"status", responseStatus(req),
		"uri", req.HTTP.URI,
		"client_ip", req.Conn.ClientIP,
		"profile", sel.Profile,
		"verdict", reply.Verdict,
		"score", scoreOf(reply),
		"reason", codeOf(reply),
		"crs_anomaly_score", out.AnomalyScore,
		"engine_ms", out.EngineMS,
		"budget_ms", budget.Milliseconds(),
		"resumed", live != nil,
		"personal", personal,
	)

	return reply, det
}

func (h *handler) responseHeaders(req *protocol.Request,
	loaded body.Body) []protocol.Header {

	if hdr := h.headers(req, loaded); len(hdr) > 0 {
		return hdr
	}

	if req.Response != nil {
		return req.Response.Headers
	}

	return nil
}

func responseStatus(req *protocol.Request) int {
	if req.Response == nil || req.Response.Status == 0 {
		return 200
	}

	return req.Response.Status
}

func pairs(hdr []protocol.Header) [][2]string {
	out := make([][2]string, 0, len(hdr))

	for _, h := range hdr {
		out = append(out, [2]string{h.Name(), h.Value()})
	}

	return out
}
