package desired

import "testing"

func TestHashStable(t *testing.T) {
	profiles := map[string]Profile{
		"strict":  {Files: []File{{Name: "00-a.conf", Text: "A"}}},
		"default": {Files: []File{{Name: "00-b.conf", Text: "B"}}},
	}

	first := Hash(profiles)
	second := Hash(profiles)

	if first != second {
		t.Fatalf("hash not stable: %s vs %s", first, second)
	}

	swapped := map[string]Profile{
		"default": {Files: []File{{Name: "00-b.conf", Text: "B"}}},
		"strict":  {Files: []File{{Name: "00-a.conf", Text: "A"}}},
	}

	if Hash(swapped) != first {
		t.Fatal("hash depends on map iteration order")
	}

	changed := map[string]Profile{
		"default": {Files: []File{{Name: "00-b.conf", Text: "C"}}},
		"strict":  {Files: []File{{Name: "00-a.conf", Text: "A"}}},
	}

	if Hash(changed) == first {
		t.Fatal("hash ignored text change")
	}

	// Совпадает с controller/src/rules-manifest.ts hashProfiles.
	const want = "sha256:de9d84c497cdbede6282f74f13d93ca3fb22a71e3b3ca5b871459c7fbe02e826"
	if first != want {
		t.Fatalf("hash diverged from controller: got %s want %s", first, want)
	}
}

func TestParseHashMismatch(t *testing.T) {
	raw := []byte(`{
		"v": 1,
		"rev": 1,
		"config_hash": "sha256:dead",
		"profiles": {
			"default": { "files": [{ "name": "00-a.conf", "text": "x" }] }
		}
	}`)

	if _, err := Parse(raw); err == nil {
		t.Fatal("expected hash mismatch")
	}
}

func TestParseFillsHash(t *testing.T) {
	raw := []byte(`{
		"v": 1,
		"rev": 2,
		"config_hash": "",
		"profiles": {
			"default": { "files": [{ "name": "00-a.conf", "text": "x" }] }
		}
	}`)

	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	if m.ConfigHash != Hash(m.Profiles) {
		t.Fatalf("hash not filled: %s", m.ConfigHash)
	}
}
