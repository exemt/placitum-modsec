package prior

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/exemt/placitum-modsec/internal/engine"
	"github.com/exemt/placitum-modsec/internal/overload"
	"github.com/exemt/placitum-modsec/internal/protocol"
)

const (
	OnDeny  = "deny"
	OnAllow = "allow"
	OnScore = "score"

	OnRule = "rule"

	OnOverload = overload.On

	WriteAddr   = "addr"
	WriteNet    = "net"
	WriteNetAll = "net_all"
	WriteASN    = "asn"
)

var outcomeVerbs = map[string][]string{
	protocol.DoChallenge: {protocol.ApplyRequest},
	protocol.DoThreshold: {protocol.ApplyRequest},
	protocol.DoSkip:      {protocol.ApplyRequest},
	protocol.DoMutate:    {protocol.ApplyRequest},
	protocol.DoReauth:    {protocol.ApplySession},
	protocol.DoNote: {protocol.ApplyRequest, protocol.ApplyIP,
		protocol.ApplyASN, protocol.ApplySession},
	protocol.DoActive:  {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoPassive: {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoOff:     {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoVote:    {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoAudit:   {protocol.ApplyRequest, protocol.ApplyResponse},
	protocol.DoArchive: {protocol.ApplyRequest, protocol.ApplyResponse},
	protocol.DoMark:    {protocol.ApplyRequest},
	protocol.DoScore:   {protocol.ApplyRequest},
}

func auditVerb(do string) bool {
	return do == protocol.DoAudit || do == protocol.DoArchive
}

func recordVerb(do string) bool {
	return auditVerb(do) || do == protocol.DoMark || do == protocol.DoScore
}

func controlVerb(do string) bool {
	return do == protocol.DoActive || do == protocol.DoPassive || do == protocol.DoOff ||
		do == protocol.DoVote
}

func checkPhaseAsk(do, phase, apply string) error {
	if phase == "" {
		return nil
	}

	if !controlVerb(do) {
		return fmt.Errorf("phase is only for active, passive, vote and off")
	}

	switch phase {
	case protocol.PhaseRequest, protocol.PhaseResponse, protocol.PhaseFrame:
	default:
		return fmt.Errorf("phase must be request, response or frame, got %q", phase)
	}

	if apply == protocol.ApplyConn && phase != protocol.PhaseFrame {
		return fmt.Errorf("apply conn needs phase frame")
	}

	return nil
}

type Outcome struct {
	On    string `yaml:"on"`
	At    *int   `yaml:"at"`
	Below bool   `yaml:"below"`
	Eq    bool   `yaml:"eq"`

	Rules  []string `yaml:"rules"`
	Tags   []string `yaml:"tags"`
	ranges engine.Ranges

	To      string               `yaml:"to"`
	Do      string               `yaml:"do"`
	Apply   string               `yaml:"apply"`
	Phase   string               `yaml:"phase"`
	Delta   *int                 `yaml:"delta"`
	Value   *int                 `yaml:"value"`
	Counter string               `yaml:"counter"`
	Group   string               `yaml:"group"`
	Set     string               `yaml:"set"`
	Headers *protocol.ObjectSpec `yaml:"headers"`
	Args    *protocol.ObjectSpec `yaml:"args"`
	Body    *protocol.ObjectSpec `yaml:"body"`
	When    []string             `yaml:"when"`

	Marker string `yaml:"marker"`

	List  string `yaml:"list"`
	Write string `yaml:"write"`
	TTL   string `yaml:"ttl"`

	Code string `yaml:"code"`
}

func (o Outcome) Asks() bool { return o.Do != "" }

func (o Outcome) Subject() string {
	if o.Write == "" {
		return WriteAddr
	}

	return o.Write
}

func (o Outcome) Axis() string {
	if o.Apply != "" {
		return o.Apply
	}

	if axes, ok := outcomeVerbs[o.Do]; ok && (len(axes) == 1 || auditVerb(o.Do)) {
		return axes[0]
	}

	return ""
}

func (o Outcome) Seconds() int {
	n, _ := parseTTL(o.TTL)
	return n
}

func (o Outcome) Matches(verdict string, score int) bool {
	switch o.On {
	case OnAllow:
		return verdict == protocol.VerdictAllow

	case OnDeny:
		return verdict == protocol.VerdictDeny || verdict == protocol.VerdictRedirect

	case OnScore:
		if verdict != protocol.VerdictScore || o.At == nil {
			return false
		}

		if o.Eq {
			return score == *o.At
		}

		if o.Below {
			return score < *o.At
		}

		return score >= *o.At
	}

	return false
}

func validateOutcome(i int, o Outcome) error {
	where := fmt.Sprintf("outcomes[%d]", i)

	switch o.On {
	case OnDeny, OnAllow, OnRule:
		if o.At != nil {
			return fmt.Errorf("%s: at is only for on: score or overload", where)
		}

		if o.Below || o.Eq {
			return fmt.Errorf("%s: below and eq are only for on: score", where)
		}

	case OnOverload:
		if err := overload.Check(o.At); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}

		if o.Below || o.Eq {
			return fmt.Errorf("%s: below and eq are only for on: score", where)
		}

	case OnScore:
		if o.At == nil {
			return fmt.Errorf("%s: on: score needs at", where)
		}

		if *o.At < 0 {
			return fmt.Errorf("%s: at must not be negative", where)
		}

		if o.Below && o.Eq {
			return fmt.Errorf("%s: below and eq are mutually exclusive", where)
		}

	default:
		return fmt.Errorf("%s: unknown on %q", where, o.On)
	}

	if err := checkRuleFilter(o); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}

	if o.Code != "" && !codeRe.MatchString(o.Code) {
		return fmt.Errorf("%s: bad code %q", where, o.Code)
	}

	if o.Asks() && o.List != "" {
		return fmt.Errorf("%s: do and list are mutually exclusive", where)
	}

	if o.Asks() {
		return validateOutcomeAsk(where, o)
	}

	if o.List == "" {
		return fmt.Errorf("%s: neither do nor list", where)
	}

	if !nameRe.MatchString(o.List) {
		return fmt.Errorf("%s: bad dataset name %q", where, o.List)
	}

	switch o.Subject() {
	case WriteAddr, WriteNet, WriteNetAll, WriteASN:
	default:
		return fmt.Errorf("%s: write must be %s, %s, %s or %s, got %q",
			where, WriteAddr, WriteNet, WriteNetAll, WriteASN, o.Write)
	}

	ttl, err := parseTTL(o.TTL)
	if err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}

	if ttl <= 0 {
		return fmt.Errorf("%s: list needs ttl", where)
	}

	return nil
}

func validateOutcomeAsk(where string, o Outcome) error {
	if o.On == OnDeny && !recordVerb(o.Do) {
		return fmt.Errorf("%s: deny ends the phase, an ask has nowhere to go", where)
	}

	axes, ok := outcomeVerbs[o.Do]
	if !ok {
		return fmt.Errorf("%s: unknown verb %q", where, o.Do)
	}

	if o.Apply != "" && !hasString(axes, o.Apply) {
		return fmt.Errorf("%s: verb %q does not take apply %q", where, o.Do, o.Apply)
	}

	if o.Apply == "" && len(axes) != 1 && !auditVerb(o.Do) {
		return fmt.Errorf("%s: %s needs apply", where, o.Do)
	}

	if o.Delta != nil && (*o.Delta < -100 || *o.Delta > 900) {
		return fmt.Errorf("%s: delta %d is out of -100..900 percent", where, *o.Delta)
	}

	if o.Value != nil && (*o.Value < -100 || *o.Value > 100) {
		return fmt.Errorf("%s: value %d is out of -100..100 percent", where, *o.Value)
	}

	if o.Do == protocol.DoThreshold && (o.Delta == nil || *o.Delta == 0) {
		return fmt.Errorf("%s: threshold needs a non-zero delta", where)
	}

	if o.Do == protocol.DoNote && (o.Value == nil || *o.Value == 0) {
		return fmt.Errorf("%s: note needs a non-zero value", where)
	}

	if o.Do == protocol.DoScore {
		if o.To != "" && o.To != "*" {
			return fmt.Errorf("%s: %s takes no to: the module adds to the route's own sum", where, o.Do)
		}

		if o.Value == nil || *o.Value == 0 {
			return fmt.Errorf("%s: score needs a non-zero value", where)
		}
	}

	if controlVerb(o.Do) && (o.To == "" || o.To == "*") {
		return fmt.Errorf("%s: %s needs to: the module switches one call, not everyone", where, o.Do)
	}

	if err := checkPhaseAsk(o.Do, o.Phase, o.Axis()); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}

	if o.Counter != "" {
		if o.Do != protocol.DoNote {
			return fmt.Errorf("%s: counter is only for %q", where, protocol.DoNote)
		}

		if !nameRe.MatchString(o.Counter) {
			return fmt.Errorf("%s: bad counter name %q", where, o.Counter)
		}
	}

	if o.Do == protocol.DoMutate {
		if o.Group == "" {
			return fmt.Errorf("%s: mutate needs a group", where)
		}

		if !nameRe.MatchString(o.Group) {
			return fmt.Errorf("%s: bad group name %q", where, o.Group)
		}

		if o.Set != "on" && o.Set != "off" {
			return fmt.Errorf("%s: mutate needs set: on or off, got %q", where, o.Set)
		}
	} else if o.Group != "" {
		return fmt.Errorf("%s: group is only for %q", where, protocol.DoMutate)
	}

	if o.Do == protocol.DoMark {
		if o.To != "" && o.To != "*" {
			return fmt.Errorf("%s: %s takes no to: the module marks the route's own record", where, o.Do)
		}

		if err := protocol.CheckMarker(o.Marker); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
	} else if o.Marker != "" {
		return fmt.Errorf("%s: marker is only for %q", where, protocol.DoMark)
	}

	ttl, _ := parseTTL(o.TTL)

	if auditVerb(o.Do) {
		if o.To != "" && o.To != "*" {
			return fmt.Errorf("%s: %s takes no to: the module writes the route's own record", where, o.Do)
		}

		if o.Set != "on" && o.Set != "off" {
			return fmt.Errorf("%s: %s needs set: on or off, got %q", where, o.Do, o.Set)
		}

		if o.Set == "off" && (ttl != 0 || len(o.When) != 0 ||
			o.Headers != nil || o.Args != nil || o.Body != nil) {
			return fmt.Errorf("%s: ttl, when and objects are only for set on", where)
		}

		if o.Do == protocol.DoAudit && (ttl != 0 || len(o.When) != 0) {
			return fmt.Errorf("%s: ttl and when are only for archive", where)
		}

		if _, err := protocol.CheckArchiveWhen(o.When); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}

		if o.Apply == protocol.ApplyResponse && o.Args != nil {
			return fmt.Errorf("%s: args has no meaning for the response record", where)
		}

		for _, item := range []struct {
			name string
			spec *protocol.ObjectSpec
		}{{"headers", o.Headers}, {"args", o.Args}, {"body", o.Body}} {
			if err := protocol.CheckObjectSpec(item.name, item.spec, o.Do == protocol.DoAudit); err != nil {
				return fmt.Errorf("%s: %w", where, err)
			}
		}
	}

	if !auditVerb(o.Do) && (len(o.When) != 0 ||
		o.Headers != nil || o.Args != nil || o.Body != nil) {
		return fmt.Errorf("%s: when, headers, args and body are only for audit and archive", where)
	}

	if !auditVerb(o.Do) && o.Do != protocol.DoMutate && o.Set != "" {
		return fmt.Errorf("%s: set is only for mutate, audit and archive", where)
	}

	return nil
}

func hasString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}

	return false
}

func parseTTL(raw string) (int, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return 0, nil
	}

	mult := 1

	switch {
	case strings.HasSuffix(raw, "s"):
		raw = strings.TrimSuffix(raw, "s")
	case strings.HasSuffix(raw, "m"):
		mult, raw = 60, strings.TrimSuffix(raw, "m")
	case strings.HasSuffix(raw, "h"):
		mult, raw = 3600, strings.TrimSuffix(raw, "h")
	case strings.HasSuffix(raw, "d"):
		mult, raw = 86400, strings.TrimSuffix(raw, "d")
	}

	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 0 {
		return 0, fmt.Errorf("bad ttl %q", raw)
	}

	return n * mult, nil
}

func checkRuleFilter(o Outcome) error {
	if o.On != OnRule {
		if len(o.Rules) != 0 || len(o.Tags) != 0 {
			return fmt.Errorf("rules and tags are only for on: rule")
		}

		return nil
	}

	if len(o.Rules) == 0 && len(o.Tags) == 0 {
		return fmt.Errorf("on: rule needs rules or tags")
	}

	if _, err := engine.ParseRanges(o.Rules); err != nil {
		return err
	}

	for _, tag := range o.Tags {
		if badTag(tag) {
			return fmt.Errorf("bad tag %q", tag)
		}
	}

	return nil
}

func badTag(tag string) bool {
	if tag == "" || len(tag) > engine.TagMax || strings.TrimSpace(tag) != tag {
		return true
	}

	for i := 0; i < len(tag); i++ {
		if tag[i] < 0x20 || tag[i] == 0x7f {
			return true
		}
	}

	return false
}

func (o *Outcome) compile() {
	o.ranges, _ = engine.ParseRanges(o.Rules)
}

func (o Outcome) hit(matched []engine.MatchedRule) (engine.MatchedRule, bool) {
	for _, r := range matched {
		if !r.Finding() {
			continue
		}

		if len(o.Rules) != 0 && !o.ranges.Has(r.ID) {
			continue
		}

		if len(o.Tags) != 0 && !r.Tagged(o.Tags) {
			continue
		}

		return r, true
	}

	return engine.MatchedRule{}, false
}

func ruleCode(id int) string {
	return "CRS_RULE_" + strconv.Itoa(id)
}

type Ban struct {
	Dataset string
	Write   string
	Addr    string
	TTL     int
	Reason  string
}

type Fired struct {
	Actions []protocol.Action
	Bans    []Ban
	Names   []string
}

func Fire(outcomes []Outcome, verdict string, score int, matched []engine.MatchedRule,
	addr, code string) Fired {

	return fire(outcomes, func(o Outcome) (string, bool) {
		if o.On == OnRule {
			r, ok := o.hit(matched)

			return ruleCode(r.ID), ok
		}

		return code, o.Matches(verdict, score)
	}, addr)
}

func FireOverload(outcomes []Outcome, fill int, shed bool, addr, code string) Fired {
	return fire(outcomes, func(o Outcome) (string, bool) {
		return code, o.On == OnOverload && overload.Fires(overload.At(o.At), fill, shed)
	}, addr)
}

func fire(outcomes []Outcome, match func(Outcome) (string, bool), addr string) Fired {
	var out Fired

	for _, o := range outcomes {
		code, ok := match(o)
		if !ok {
			continue
		}

		if o.Asks() {
			out.Actions = append(out.Actions, ask(o, code))
			out.Names = append(out.Names, outcomeName(o))

			continue
		}

		if addr == "" {
			continue
		}

		out.Bans = append(out.Bans, Ban{
			Dataset: o.List,
			Write:   o.Subject(),
			Addr:    addr,
			TTL:     o.Seconds(),
			Reason:  reasonOf(o, code),
		})

		out.Names = append(out.Names, outcomeName(o))
	}

	return out
}

func ask(o Outcome, code string) protocol.Action {
	out := protocol.Action{
		To:      o.To,
		Do:      o.Do,
		Apply:   o.Axis(),
		Phase:   o.Phase,
		Code:    reasonOf(o, code),
		Counter: o.Counter,
		Marker:  o.Marker,
		Group:   o.Group,
		Set:     o.Set,
		Headers: o.Headers,
		Args:    o.Args,
		Body:    o.Body,
	}

	if o.Do == protocol.DoArchive && o.Set == "on" {
		if len(o.When) > 0 {
			when, _ := protocol.CheckArchiveWhen(o.When)
			out.When = when
		}

		if n, _ := parseTTL(o.TTL); n > 0 {
			ttl := int64(n)
			out.TTL = &ttl
		}
	}

	if o.Delta != nil {
		out.Delta = *o.Delta
	}

	if o.Value != nil {
		out.Value = *o.Value
	}

	return out
}

func reasonOf(o Outcome, code string) string {
	if o.Code != "" {
		return o.Code
	}

	return code
}

func outcomeName(o Outcome) string {
	if o.Asks() {
		return o.Do
	}

	return o.List
}
