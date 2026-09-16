package desired

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/exemt/placitum-modsec/internal/prior"
)

const (
	PackKey      = "policy/rules-pack"
	BlobPrefix   = "waf.blob."
	packPrefix   = "pack-"
	volumePrefix = "crs-prof-"
)

type Pack struct {
	V        int               `json:"v"`
	Kind     string            `json:"kind"`
	Rev      int               `json:"rev"`
	SHA256   string            `json:"sha256"`
	Prefix   string            `json:"prefix"`
	Files    map[string]string `json:"files"`
	Profiles map[string]string `json:"profiles"`
	Policies map[string]string `json:"policies,omitempty"`
	Data     map[string]string `json:"data"`
	Blobs    int               `json:"blobs"`
	Bytes    int               `json:"bytes"`
	Settings *Settings         `json:"settings,omitempty"`
}

func ParsePack(raw []byte) (*Pack, error) {
	var p Pack

	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}

	if p.V != 1 || p.Kind != "rules-pack" {
		return nil, fmt.Errorf("pack: unsupported v/kind")
	}

	if p.Rev < 1 {
		return nil, fmt.Errorf("pack: rev must be positive")
	}

	if p.SHA256 == "" || !strings.HasPrefix(p.SHA256, "sha256:") {
		return nil, fmt.Errorf("pack: sha256 is missing")
	}

	if p.Prefix == "" {
		p.Prefix = BlobPrefix
	}

	if p.Data == nil {
		p.Data = map[string]string{}
	}

	if p.Policies == nil {
		p.Policies = map[string]string{}
	}

	if len(p.Files) == 0 || len(p.Profiles) == 0 {
		return nil, fmt.Errorf("pack: empty tree")
	}

	if err := p.Settings.validate(); err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}

	return &p, nil
}

func (p *Pack) BlobKey(hash string) string {
	return p.Prefix + strings.TrimPrefix(hash, "sha256:")
}

func (p *Pack) RuntimeProfiles() map[string]string {
	out := make(map[string]string, len(p.Profiles))

	for name, hash := range p.Profiles {
		if strings.HasPrefix(name, volumePrefix) {
			continue
		}

		dest := name
		if short, ok := strings.CutPrefix(name, packPrefix); ok {
			if _, exists := p.Profiles[short]; exists {
				continue
			}
			dest = short
		}

		out[dest] = hash
	}

	return out
}

func Expand(p *Pack, blobs map[string][]byte) (*Manifest, error) {
	runtime := p.RuntimeProfiles()

	if _, ok := runtime[DefaultProfile]; !ok {
		return nil, fmt.Errorf("pack: profile %q is missing", DefaultProfile)
	}

	data := make(map[string]string, len(p.Data))

	for name, hash := range p.Data {
		if err := safeName(name); err != nil {
			return nil, fmt.Errorf("pack: data %s: %w", name, err)
		}

		body, ok := blobs[hash]
		if !ok {
			return nil, fmt.Errorf("pack: data %s blob %s is missing", name, hash)
		}

		data[name] = string(body)
	}

	m := &Manifest{
		V:          1,
		Rev:        p.Rev,
		ConfigHash: p.SHA256,
		Profiles:   make(map[string]Profile, len(runtime)),
		Data:       data,
		Settings:   p.Settings,
	}

	for name, phash := range runtime {
		list, ok := blobs[phash]
		if !ok {
			return nil, fmt.Errorf("pack: profile %q blob %s is missing", name, phash)
		}

		ids := parseUUIDList(string(list))
		if len(ids) == 0 {
			return nil, fmt.Errorf("pack: profile %q is empty", name)
		}

		files := make([]File, 0, len(ids)+1)

		if hash, ok := p.Policies[name]; ok {
			body, ok := blobs[hash]
			if !ok {
				return nil, fmt.Errorf("pack: profile %q policy blob %s is missing",
					name, hash)
			}

			files = append(files, File{Name: prior.FileName, Text: string(body)})
		}

		for i, id := range ids {
			fhash, ok := p.Files[id]
			if !ok {
				return nil, fmt.Errorf("pack: profile %q references unknown file %s", name, id)
			}

			body, ok := blobs[fhash]
			if !ok {
				return nil, fmt.Errorf("pack: file %s blob %s is missing", id, fhash)
			}

			files = append(files, File{
				Name: fmt.Sprintf("%02d-%s.conf", i, id),
				Text: string(body),
			})
		}

		m.Profiles[name] = Profile{Files: files}
	}

	return m, nil
}

func parseUUIDList(text string) []string {
	var out []string

	for _, line := range strings.Split(text, "\n") {
		id := strings.TrimSpace(line)
		if id == "" {
			continue
		}

		out = append(out, id)
	}

	return out
}

func hashOf(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}
