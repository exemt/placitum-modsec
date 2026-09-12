package desired

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestRuntimeProfilesAliasesPackPrefix(t *testing.T) {
	p := &Pack{
		Profiles: map[string]string{
			"pack-default": "sha256:aaa",
			"pack-strict":  "sha256:bbb",
			"crs-prof-001": "sha256:ccc",
			"test":         "sha256:ddd",
		},
	}

	got := p.RuntimeProfiles()
	if _, ok := got["crs-prof-001"]; ok {
		t.Fatal("volume profile must be skipped")
	}

	if got["default"] != "sha256:aaa" || got["strict"] != "sha256:bbb" {
		t.Fatalf("aliases: %#v", got)
	}

	if got["test"] != "sha256:ddd" {
		t.Fatalf("test: %#v", got)
	}

	if _, ok := got["pack-default"]; ok {
		t.Fatal("pack- prefix should be stripped")
	}
}

func TestExpandWritesOrderedConfs(t *testing.T) {
	engine := "aaaaaaaa-aaaa-4aaa-8aaa-000000000001"
	policy := "bbbbbbbb-bbbb-4bbb-8bbb-000000000002"
	engineHash := sum("SecRuleEngine On\n")
	policyHash := sum("SecRule ARGS x\n")
	list := engine + "\n" + policy + "\n"
	listHash := sum(list)

	p := &Pack{
		Rev:    1,
		SHA256: "sha256:tree",
		Files: map[string]string{
			engine: engineHash,
			policy: policyHash,
		},
		Profiles: map[string]string{
			"pack-default": listHash,
		},
	}

	m, err := Expand(p, map[string][]byte{
		engineHash: []byte("SecRuleEngine On\n"),
		policyHash: []byte("SecRule ARGS x\n"),
		listHash:   []byte(list),
	})
	if err != nil {
		t.Fatal(err)
	}

	files := m.Profiles["default"].Files
	if len(files) != 2 {
		t.Fatalf("files: %d", len(files))
	}

	if files[0].Name != "00-"+engine+".conf" || files[0].Text != "SecRuleEngine On\n" {
		t.Fatalf("first: %#v", files[0])
	}

	if files[1].Name != "01-"+policy+".conf" {
		t.Fatalf("second: %#v", files[1])
	}
}

func TestParsePackRejectsOldManifest(t *testing.T) {
	_, err := ParsePack([]byte(`{"v":1,"rev":1,"config_hash":"sha256:x","profiles":{"default":{"files":[]}}}`))
	if err == nil {
		t.Fatal("expected reject")
	}
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}
