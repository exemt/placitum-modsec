/*
 * Поколение правил из JetStream KV. Канон хеша совпадает с контроллером:
 * docs/inspector-config-distribution.md.
 */

package desired

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	// Settings -- свойства процесса из каталога; нет в старых поколениях.
	Settings *Settings `json:"settings,omitempty"`
}

func Parse(raw []byte) (*Manifest, error) {
	var m Manifest

	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}

	if m.V != 1 {
		return nil, fmt.Errorf("manifest: unsupported v %d", m.V)
	}

	if m.Rev < 1 {
		return nil, fmt.Errorf("manifest: rev must be positive")
	}

	if len(m.Profiles) == 0 {
		return nil, fmt.Errorf("manifest: no profiles")
	}

	if _, ok := m.Profiles[DefaultProfile]; !ok {
		return nil, fmt.Errorf("manifest: profile %q is missing", DefaultProfile)
	}

	for name, profile := range m.Profiles {
		if name == "" || len(profile.Files) == 0 {
			return nil, fmt.Errorf("manifest: profile %q is empty", name)
		}

		for _, file := range profile.Files {
			if file.Name == "" {
				return nil, fmt.Errorf("manifest: profile %q has a file without a name", name)
			}
		}
	}

	if err := m.Settings.validate(); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}

	got := HashWith(m.Profiles, m.Settings)

	if m.ConfigHash != "" && m.ConfigHash != got {
		return nil, fmt.Errorf("manifest: config_hash mismatch: got %s want %s", got, m.ConfigHash)
	}

	m.ConfigHash = got

	return &m, nil
}

// Hash -- канон поколения без блока настроек: старые манифесты и тесты.
func Hash(profiles map[string]Profile) string {
	return HashWith(profiles, nil)
}

// HashWith -- канон целиком: профили, затем секция settings, если она есть.
func HashWith(profiles map[string]Profile, settings *Settings) string {
	names := make([]string, 0, len(profiles))

	for name := range profiles {
		names = append(names, name)
	}

	sort.Strings(names)

	sum := sha256.New()

	for _, name := range names {
		_, _ = sum.Write([]byte(name))
		_, _ = sum.Write([]byte{0})

		for _, file := range profiles[name].Files {
			_, _ = sum.Write([]byte(file.Name))
			_, _ = sum.Write([]byte{0})
			_, _ = sum.Write([]byte(file.Text))
			_, _ = sum.Write([]byte{0})
		}
	}

	writeSettings(sum, settings)

	return "sha256:" + hex.EncodeToString(sum.Sum(nil))
}

func (m *Manifest) Names() []string {
	names := make([]string, 0, len(m.Profiles))

	for name := range m.Profiles {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}
