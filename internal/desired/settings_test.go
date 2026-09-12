package desired

import (
	"encoding/json"
	"testing"
)

/*
 * Блок настроек у modsec едет в указателе пака и в развёрнутом манифесте: в
 * канон входит, когда есть, и не двигает хеш, когда его нет.
 */
func TestSettingsEnterTheCanonOnlyWhenPresent(t *testing.T) {
	profiles := map[string]Profile{
		"default": {Files: []File{{Name: "00-a.conf", Text: "A"}}},
	}

	if HashWith(profiles, nil) != Hash(profiles) {
		t.Fatal("nil settings must hash like no settings")
	}

	warn := HashWith(profiles, &Settings{LogLevel: "warn"})

	if warn == Hash(profiles) {
		t.Fatal("settings do not move the hash")
	}

	if HashWith(profiles, &Settings{LogLevel: "error"}) == warn {
		t.Fatal("level change does not move the hash")
	}
}

func TestPackCarriesSettingsIntoManifest(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"v": 1, "kind": "rules-pack", "rev": 1,
		"sha256":   "sha256:abc",
		"files":    map[string]string{"f1": "sha256:f1"},
		"profiles": map[string]string{"default": "sha256:p1"},
		"settings": map[string]string{"log_level": "notice"},
	})

	p, err := ParsePack(raw)
	if err != nil {
		t.Fatal(err)
	}

	m, err := Expand(p, map[string][]byte{
		"sha256:p1": []byte("f1\n"),
		"sha256:f1": []byte("SecRuleEngine On\n"),
	})
	if err != nil {
		t.Fatal(err)
	}

	if m.Settings == nil || m.Settings.LogLevel != "notice" {
		t.Fatalf("settings lost on expand: %+v", m.Settings)
	}

	bad, _ := json.Marshal(map[string]any{
		"v": 1, "kind": "rules-pack", "rev": 1,
		"sha256":   "sha256:abc",
		"files":    map[string]string{"f1": "sha256:f1"},
		"profiles": map[string]string{"default": "sha256:p1"},
		"settings": map[string]string{"log_level": "emerg"},
	})

	if _, err := ParsePack(bad); err == nil {
		t.Fatal("foreign log level accepted")
	}
}
