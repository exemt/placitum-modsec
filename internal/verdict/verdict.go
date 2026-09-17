package verdict

import (
	"math"
	"strconv"
	"unicode/utf8"

	"github.com/exemt/placitum-modsec/internal/audit"
	"github.com/exemt/placitum-modsec/internal/engine"
	"github.com/exemt/placitum-modsec/internal/protocol"
)

const evidenceMax = 256

const (
	CodeAnomaly     = "CRS_ANOMALY"
	CodeRuleMatched = "CRS_RULE"
	CodeRedirect    = "CRS_REDIRECT"
)

const DefaultCRSThreshold = 5

type Decisive struct {
	Ranges engine.Ranges
	Tags   map[string]struct{}
}

func (d Decisive) match(r engine.MatchedRule) bool {
	if d.Ranges.Has(r.ID) {
		return true
	}

	for _, tag := range r.Tags {
		if _, ok := d.Tags[tag]; ok {
			return true
		}
	}

	return false
}

func (d Decisive) empty() bool { return len(d.Ranges) == 0 && len(d.Tags) == 0 }

type Options struct {
	StatusMap    *StatusMap
	Decisive     Decisive
	ScalePercent int
}

func From(req *protocol.Request, out *engine.Outcome, opt Options) *protocol.Reply {
	reply := protocol.NewReply(req, protocol.VerdictAllow)

	if iv := out.Intervention; iv != nil && iv.Disruptive {
		return fromIntervention(reply, iv, out, opt)
	}

	if _, ok := decisive(out.Matched, opt.Decisive); ok {
		reply.Verdict = protocol.VerdictDeny
		reply.Reason = &protocol.Reason{Code: CodeRuleMatched}
		reply.Response = &protocol.ResponseRef{Name: opt.statusName(0)}

		return reply
	}

	if out.AnomalyScore > 0 {
		score := ScaleScore(Calibrate(out.AnomalyScore, out.Threshold),
			opt.ScalePercent)

		if err := reply.WithScore(score); err != nil {
			reply.Verdict = protocol.VerdictAllow
			reply.Reason = &protocol.Reason{Code: "MODSEC_SCORE_RANGE"}

			return reply
		}

		reply.Reason = &protocol.Reason{Code: CodeAnomaly}

		return reply
	}

	return reply
}

func Deny(req *protocol.Request, code string, opt Options) *protocol.Reply {
	reply := protocol.NewReply(req, protocol.VerdictDeny)
	reply.Reason = &protocol.Reason{Code: code}
	reply.Response = &protocol.ResponseRef{Name: opt.statusName(0)}

	return reply
}

func fromIntervention(reply *protocol.Reply, iv *engine.Intervention,
	out *engine.Outcome, opt Options) *protocol.Reply {

	switch iv.Action {
	case "redirect":
		if iv.URL == "" {
			break
		}

		reply.Verdict = protocol.VerdictRedirect
		reply.Redirect = &protocol.RedirectRef{URL: iv.URL}
		reply.Reason = &protocol.Reason{Code: CodeRedirect}

		return reply

	case "deny", "block", "drop":
		reply.Verdict = protocol.VerdictDeny
		reply.Response = &protocol.ResponseRef{Name: opt.statusName(iv.Status)}
		reply.Reason = &protocol.Reason{Code: CodeRuleMatched}

		return reply
	}

	return reply
}

func (o Options) statusName(status int) string {
	m := o.StatusMap
	if m == nil {
		m = BuiltinStatusMap()
	}

	return m.Name(status)
}

func ScaleScore(score, percent int) int {
	if percent == 0 || score <= 0 {
		return max(score, 0)
	}

	scaled := int(math.Round(float64(score) * (1 + float64(percent)/100)))

	if scaled < 0 {
		scaled = 0
	}

	return min(scaled, 100)
}

func Calibrate(anomaly, threshold int) int {
	if anomaly <= 0 {
		return 0
	}

	if threshold <= 0 {
		threshold = DefaultCRSThreshold
	}

	score := int(math.Round(100 * float64(anomaly) / float64(threshold) / 2))

	return min(score, 100)
}

func decisive(matched []engine.MatchedRule, d Decisive) (engine.MatchedRule, bool) {
	if d.empty() {
		return engine.MatchedRule{}, false
	}

	for _, r := range matched {
		if d.match(r) {
			return r, true
		}
	}

	return engine.MatchedRule{}, false
}

func ruleID(id int) string {
	if id == 0 {
		return ""
	}

	return strconv.Itoa(id)
}

func Detail(out *engine.Outcome) audit.Details {
	engineData := map[string]any{
		"crs_anomaly_score": out.AnomalyScore,
		"crs_threshold":     out.Threshold,
	}

	if out.Threshold > 0 && out.AnomalyScore >= out.Threshold {
		engineData["crs_would_block"] = true
	}

	findings := make([]audit.Finding, 0, len(out.Matched))

	for _, r := range out.Matched {
		if !r.Finding() {
			continue
		}

		findings = append(findings, finding(r))
	}

	return audit.Details{
		EngineMS: out.EngineMS,
		Findings: findings,
		Engine:   engineData,
	}
}

func finding(r engine.MatchedRule) audit.Finding {
	f := audit.Finding{
		Code:     "crs-" + ruleID(r.ID),
		Severity: severity(r.Severity),
		Target:   r.Target,
		Rule:     ruleID(r.ID),
		Evidence: clip(r.Data, evidenceMax),
		Message:  clip(r.Message, evidenceMax),
		Tags:     tags(r.Tags),
	}

	if f.Target == "" {
		f.Target = audit.TargetURI
	}

	return f
}

const tagsMax = 32

func tags(src []string) []string {
	var out []string

	for _, tag := range src {
		if len(out) == tagsMax {
			break
		}

		if tag != "" {
			out = append(out, clip(tag, engine.TagMax))
		}
	}

	return out
}

func severity(s string) string {
	switch s {
	case "emergency", "alert":
		return audit.SeverityCritical
	case "critical":
		return audit.SeverityHigh
	case "error", "warning":
		return audit.SeverityMedium
	case "notice":
		return audit.SeverityLow
	}

	return audit.SeverityInfo
}

func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}

	cut := max

	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}

	return s[:cut]
}
