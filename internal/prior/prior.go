package prior

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	yaml "github.com/goccy/go-yaml"

	"github.com/exemt/placitum-modsec/internal/protocol"
)

const FileName = "policy.yaml"

var (
	nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	codeRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
)

const AnyInspector = "*"

type Rule struct {
	From   string   `yaml:"from"`
	Accept []string `yaml:"accept"`
	Apply  []string `yaml:"apply"`
	Codes  []string `yaml:"codes"`
}

func (r Rule) Accepts(verb string) bool {
	for _, v := range r.Accept {
		if v == verb {
			return true
		}
	}

	return false
}

func (r Rule) WantsAxis(axis string) bool {
	if len(r.Apply) == 0 {
		return true
	}

	for _, a := range r.Apply {
		if a == axis {
			return true
		}
	}

	return false
}

func (r Rule) WantsCode(code string) bool {
	if len(r.Codes) == 0 {
		return true
	}

	for _, c := range r.Codes {
		if c == code {
			return true
		}
	}

	return false
}

type Policy struct {
	Rules    []Rule
	Outcomes []Outcome
}

func LoadDir(dir string) (Policy, error) {
	p, _, err := loadFile(filepath.Join(dir, FileName))
	return p, err
}

func Load(path string) (Policy, error) {
	p, _, err := loadFile(path)
	return p, err
}

func loadFile(path string) (Policy, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Policy{}, false, nil
		}

		return Policy{}, false, err
	}

	name := filepath.Base(path)

	var doc struct {
		Prior    []Rule    `yaml:"prior"`
		Outcomes []Outcome `yaml:"outcomes"`
	}

	if err := yaml.UnmarshalWithOptions(raw, &doc, yaml.DisallowUnknownField()); err != nil {
		return Policy{}, false, fmt.Errorf("%s: %w", name, err)
	}

	for i, r := range doc.Prior {
		if err := validate(i, r); err != nil {
			return Policy{}, false, fmt.Errorf("%s: %w", name, err)
		}
	}

	for i, o := range doc.Outcomes {
		if err := validateOutcome(i, o); err != nil {
			return Policy{}, false, fmt.Errorf("%s: %w", name, err)
		}

		doc.Outcomes[i].compile()
	}

	return Policy{Rules: doc.Prior, Outcomes: doc.Outcomes}, true, nil
}

func validate(i int, r Rule) error {
	if r.From == "" {
		return fmt.Errorf("prior[%d]: from is empty", i)
	}

	if len(r.Accept) == 0 {
		return fmt.Errorf("prior[%d]: accept is required", i)
	}

	for _, verb := range r.Accept {
		switch verb {
		case protocol.DoThreshold, protocol.DoSkip:

		case protocol.DoChallenge, protocol.DoReauth, protocol.DoNote:
			return fmt.Errorf("prior[%d]: %q is not ours to apply", i, verb)

		default:
			return fmt.Errorf("prior[%d]: unknown verb %q", i, verb)
		}
	}

	for _, axis := range r.Apply {
		switch axis {
		case protocol.ApplyRequest:

		case protocol.ApplyIP, protocol.ApplyASN, protocol.ApplySession:
			return fmt.Errorf("prior[%d]: axis %q never occurs with %v",
				i, axis, r.Accept)

		default:
			return fmt.Errorf("prior[%d]: unknown axis %q", i, axis)
		}
	}

	if r.From == AnyInspector {
		return fmt.Errorf("prior[%d]: %v need a named sender: they always weaken",
			i, r.Accept)
	}

	return nil
}

type Ask struct {
	Skip     bool
	Percent  int
	Outcomes []ActionOutcome
}

const (
	OutcomeApplied = "applied"
	OutcomeNoRule  = "no_rule"
)

type ActionOutcome struct {
	From  string `json:"from"`
	Do    string `json:"do"`
	Apply string `json:"apply"`
	Code  string `json:"code,omitempty"`
	Delta int    `json:"delta,omitempty"`
	Value int    `json:"value,omitempty"`

	Took    int    `json:"took,omitempty"`
	Outcome string `json:"outcome"`
}

const (
	PercentMin = -100
	PercentMax = 900
)

func Evaluate(entries []protocol.PriorVerdict, rules []Rule) Ask {
	var a Ask

	for _, v := range entries {
		for _, act := range v.Actions {
			a.deliver(v.Inspector, act, rules)
		}
	}

	if a.Percent < PercentMin {
		a.Percent = PercentMin
	}

	if a.Percent > PercentMax {
		a.Percent = PercentMax
	}

	return a
}

func (a *Ask) deliver(from string, act protocol.Action, rules []Rule) {
	out := ActionOutcome{
		From:    from,
		Do:      act.Do,
		Apply:   act.Scope(),
		Code:    act.Code,
		Delta:   act.Delta,
		Value:   act.Value,
		Outcome: OutcomeNoRule,
	}

	for _, r := range rules {
		if r.From != from {
			continue
		}

		if !r.Accepts(act.Do) || !r.WantsAxis(act.Scope()) || !r.WantsCode(act.Code) {
			continue
		}

		a.take(r, act, &out)
	}

	a.Outcomes = append(a.Outcomes, out)
}

func (a *Ask) take(r Rule, act protocol.Action, out *ActionOutcome) {
	switch act.Do {
	case protocol.DoSkip:
		a.Skip = true
		out.apply(0)

	case protocol.DoThreshold:
		a.Percent += act.Delta
		out.apply(act.Delta)
	}
}

func (o *ActionOutcome) apply(took int) {
	o.Outcome = OutcomeApplied
	o.Took += took
}
