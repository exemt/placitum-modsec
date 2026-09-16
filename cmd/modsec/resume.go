package main

import (
	"github.com/exemt/placitum-modsec/internal/audit"
	"github.com/exemt/placitum-modsec/internal/engine"
	"github.com/exemt/placitum-modsec/internal/protocol"
)

func (h *handler) wantsResume(req *protocol.Request) bool {
	if h.sticky == nil || h.inbox == "" {
		return false
	}

	return req.Phase == protocol.PhaseRequest &&
		req.Resume != nil && req.Resume.Want && req.Resume.Token != ""
}

func (h *handler) offerContinue(req *protocol.Request, reply *protocol.Reply,
	det audit.Details, live *engine.Live) {

	if reply.Verdict == protocol.VerdictDeny || reply.Verdict == protocol.VerdictRedirect {
		live.Discard()

		return
	}

	if !h.sticky.Park(req.Resume.Token, live) {
		live.Discard()

		det.Engine["parked"] = false
		h.log.Warn("resume registry is full", "rid", req.RID,
			"max", h.cfg.ResumeMax, "live", h.sticky.Stats().Live)

		return
	}

	det.Engine["parked"] = true

	reply.Continue = &protocol.Continue{
		Subject: h.inbox,
		TTLMS:   h.sticky.TTL().Milliseconds(),
	}
}

func (h *handler) releaseState(req *protocol.Request) {
	if h.sticky == nil || req.Release == nil {
		return
	}

	h.sticky.Drop(req.Release.Token)

	h.log.Info("resume state released",
		"rid", req.RID,
		"inspector", req.Inspector,
		"phase", req.Phase,
		"reason", req.Release.Reason,
		"live", h.sticky.Stats().Live,
	)
}

func (h *handler) stickyLive() int {
	if h.sticky == nil {
		return -1
	}

	return h.sticky.Stats().Live
}

func (h *handler) resumeState(req *protocol.Request) *engine.Live {
	if h.sticky == nil || req.Resume == nil || req.Resume.Token == "" {
		return nil
	}

	live, ok := h.sticky.Take(req.Resume.Token)
	if !ok {
		return nil
	}

	return live
}
