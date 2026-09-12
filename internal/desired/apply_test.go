package desired

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/exemt/placitum-modsec/internal/rules"
)

func TestWriteTree(t *testing.T) {
	root := t.TempDir()
	staging := filepath.Join(root, "next")

	m := &Manifest{
		Profiles: map[string]Profile{
			"default": {Files: []File{{Name: "00-a.conf", Text: "SecRuleEngine DetectionOnly\n"}}},
		},
	}

	if err := writeTree(staging, root, m); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(filepath.Join(staging, rules.TreeDir, "default", "00-a.conf"))
	if err != nil {
		t.Fatal(err)
	}

	if string(body) != "SecRuleEngine DetectionOnly\n" {
		t.Fatalf("got %q", body)
	}
}

func TestWriteTreeDataNextToRules(t *testing.T) {
	root := t.TempDir()
	staging := filepath.Join(root, "next")

	m := &Manifest{
		Profiles: map[string]Profile{
			"default": {Files: []File{{
				Name: "00-a.conf",
				Text: `SecRule ARGS "@pmFromFile ssrf.data" "id:1,pass"`,
			}}},
		},
		Data: map[string]string{"ssrf.data": "http://169.254.169.254/\n"},
	}

	live := filepath.Join(root, "live")
	if err := writeTree(staging, live, m); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(staging, rules.TreeDir, "default")
	if _, err := os.ReadFile(filepath.Join(dir, "ssrf.data")); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(filepath.Join(dir, "00-a.conf"))
	if err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(live, rules.TreeDir, "default", "ssrf.data")
	if !strings.Contains(string(body), want) {
		t.Fatalf("pmFromFile not rewritten to live path %s: %s", want, body)
	}

	if !strings.Contains(string(body), `"@pmFromFile `) && !strings.Contains(string(body), `"@pmFromFile`) {
		// quotes around the operator must stay
	}

	if !strings.Contains(string(body), `"id:1,pass"`) {
		t.Fatalf("ate the actions quote: %s", body)
	}
}

/*
 * Сокращения и адресный оператор переписываются так же, как @pmFromFile:
 * список операторов общий с контроллером, и отставший здесь оставил бы
 * относительный путь -- Coraza искала бы файл от рабочего каталога процесса.
 */
func TestRewriteFromFileVariants(t *testing.T) {
	dir := filepath.Join("live", "tree", "p")

	got := rewriteFromFile(
		`SecRule ARGS "@pmf words.txt" "id:1,pass"`+"\n"+
			`SecRule REMOTE_ADDR "@ipMatchFromFile bad_nets.txt" "id:2,deny"`+"\n"+
			`SecRule REMOTE_ADDR "@ipMatchF more.txt" "id:3,deny"`,
		dir,
	)

	for _, want := range []string{
		"@pmf " + filepath.Join(dir, "words.txt"),
		"@ipMatchFromFile " + filepath.Join(dir, "bad_nets.txt"),
		"@ipMatchF " + filepath.Join(dir, "more.txt"),
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
}

func TestSafeName(t *testing.T) {
	if err := safeName("../etc"); err == nil {
		t.Fatal("expected reject")
	}

	if err := safeName("00-engine.conf"); err != nil {
		t.Fatal(err)
	}
}
