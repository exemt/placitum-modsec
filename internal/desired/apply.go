package desired

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/exemt/placitum-modsec/internal/rules"
)

var fromFile = regexp.MustCompile(`@(pmFromFile|pmf|ipMatchFromFile|ipMatchF)\s+([^"\s]+)`)

func Apply(reg *rules.Registry, dataDir string, m *Manifest) error {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("data dir: %w", err)
	}

	staging := filepath.Join(dataDir, ".next")
	prev := filepath.Join(dataDir, ".prev")
	live := filepath.Join(dataDir, rules.TreeDir)

	if err := writeTree(staging, dataDir, m); err != nil {
		_ = os.RemoveAll(staging)
		return err
	}

	_ = os.RemoveAll(prev)

	liveExisted := true

	if err := os.Rename(live, prev); err != nil {
		if !os.IsNotExist(err) {
			_ = os.RemoveAll(staging)
			return fmt.Errorf("park live: %w", err)
		}

		liveExisted = false
	}

	if err := os.Rename(filepath.Join(staging, rules.TreeDir), live); err != nil {
		if liveExisted {
			_ = os.Rename(prev, live)
		}

		_ = os.RemoveAll(staging)
		return fmt.Errorf("promote staging: %w", err)
	}

	_ = os.RemoveAll(staging)

	if err := reg.ReloadFrom(dataDir); err != nil {
		_ = os.RemoveAll(live)

		if liveExisted {
			if restore := os.Rename(prev, live); restore == nil {
				_ = reg.ReloadFrom(dataDir)
			}
		}

		return err
	}

	_ = os.RemoveAll(prev)

	return nil
}

func writeTree(root, liveRoot string, m *Manifest) error {
	if err := os.RemoveAll(root); err != nil {
		return err
	}

	for name, profile := range m.Profiles {
		if err := safeName(name); err != nil {
			return err
		}

		dir := filepath.Join(root, rules.TreeDir, name)
		live := filepath.Join(liveRoot, rules.TreeDir, name)

		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}

		for dataName, body := range m.Data {
			if err := safeName(dataName); err != nil {
				return err
			}

			if err := os.WriteFile(filepath.Join(dir, dataName), []byte(body), 0o644); err != nil {
				return err
			}
		}

		for _, file := range profile.Files {
			if err := safeName(file.Name); err != nil {
				return err
			}

			path := filepath.Join(dir, file.Name)
			text := rewriteFromFile(file.Text, live)
			if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
				return err
			}
		}
	}

	return nil
}

func rewriteFromFile(text, dir string) string {
	return fromFile.ReplaceAllStringFunc(text, func(match string) string {
		sub := fromFile.FindStringSubmatch(match)
		if len(sub) < 3 {
			return match
		}

		return "@" + sub[1] + " " + filepath.Join(dir, filepath.Base(sub[2]))
	})
}

func safeName(name string) error {
	if name == "" || name == "." || name == ".." ||
		strings.ContainsAny(name, `/\`) ||
		strings.Contains(name, "..") {
		return fmt.Errorf("unsafe name %q", name)
	}

	return nil
}
