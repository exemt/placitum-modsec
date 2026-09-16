package desired

import (
	"sort"
)

const (
	Bucket         = "WAF_DESIRED"
	Key            = "policy/modsec"
	DefaultProfile = "default"
	ApplyOK        = "ok"
	ApplyFailed    = "apply_failed"
)

type File struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

type Profile struct {
	Files []File `json:"files"`
}

type Manifest struct {
	V          int                `json:"v"`
	Rev        int                `json:"rev"`
	ConfigHash string             `json:"config_hash"`
	Profiles   map[string]Profile `json:"profiles"`
	Data       map[string]string  `json:"data,omitempty"`
	Settings   *Settings          `json:"settings,omitempty"`
}

func (m *Manifest) Names() []string {
	names := make([]string, 0, len(m.Profiles))

	for name := range m.Profiles {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}
