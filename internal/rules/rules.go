package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/jcchavezs/mergefs"
	mergefsio "github.com/jcchavezs/mergefs/io"

	"github.com/exemt/placitum-modsec/internal/config"
	"github.com/exemt/placitum-modsec/internal/engine"
	corazaengine "github.com/exemt/placitum-modsec/internal/engine/coraza"
	"github.com/exemt/placitum-modsec/internal/prior"
)

const DefaultProfile = "default"

const TreeDir = "http"

var root fs.FS = mergefs.Merge(coreruleset.FS, mergefsio.OSFS)

type Set struct {
	profiles map[string]profile
}

type profile struct {
	engine engine.Engine
	policy prior.Policy
}

func (s *Set) Names() []string {
	names := make([]string, 0, len(s.profiles))

	for name := range s.profiles {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}

func (s *Set) RuleCount(name string) int {
	if p, ok := s.profiles[name]; ok {
		return p.engine.RuleCount()
	}

	return 0
}

type Registry struct {
	dir     string
	current atomic.Pointer[Set]

	mu      sync.Mutex
	unknown map[string]int64
}

type Selection struct {
	Profile string
	Unknown bool
}

func New(cfg *config.Config) (*Registry, error) {
	dir := cfg.ProfilesDir

	if HasDefault(cfg.DataDir) {
		dir = cfg.DataDir
	}

	r := &Registry{
		dir:     dir,
		unknown: make(map[string]int64),
	}

	if err := r.Reload(); err != nil {
		return nil, err
	}

	return r, nil
}

func HasDefault(dir string) bool {
	if dir == "" {
		return false
	}

	entries, err := filepath.Glob(filepath.Join(dir, TreeDir, DefaultProfile, "*.conf"))
	return err == nil && len(entries) > 0
}

func (r *Registry) Reload() error {
	return r.ReloadFrom(r.dir)
}

func (r *Registry) ReloadFrom(dir string) error {
	set, err := build(dir)
	if err != nil {
		return err
	}

	r.current.Store(set)
	r.dir = dir

	return nil
}

func (r *Registry) Dir() string { return r.dir }

func (r *Registry) Current() *Set { return r.current.Load() }

func (r *Registry) Select(profile string) (engine.Engine, Selection) {
	return r.selectFrom(r.current.Load().profiles, profile)
}

func (r *Registry) selectFrom(profiles map[string]profile,
	name string) (engine.Engine, Selection) {

	if name == "" {
		name = DefaultProfile
	}

	if p, ok := profiles[name]; ok {
		return p.engine, Selection{Profile: name}
	}

	r.countUnknown(name)

	return nil, Selection{Profile: name, Unknown: true}
}

func (r *Registry) PriorRules(name string) []prior.Rule {
	profiles := r.current.Load().profiles

	if name == "" {
		name = DefaultProfile
	}

	if p, ok := profiles[name]; ok {
		return p.policy.Rules
	}

	return nil
}

func (r *Registry) Outcomes(name string) []prior.Outcome {
	profiles := r.current.Load().profiles

	if name == "" {
		name = DefaultProfile
	}

	if p, ok := profiles[name]; ok {
		return p.policy.Outcomes
	}

	return nil
}

func (r *Registry) countUnknown(profile string) {
	r.mu.Lock()
	r.unknown[profile]++
	r.mu.Unlock()
}

func (r *Registry) UnknownCounts() map[string]int64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make(map[string]int64, len(r.unknown))

	for k, v := range r.unknown {
		out[k] = v
	}

	return out
}

func build(dir string) (*Set, error) {
	profiles, err := buildTree(dir, TreeDir)
	if err != nil {
		return nil, err
	}

	if _, ok := profiles[DefaultProfile]; !ok {
		return nil, fmt.Errorf("profiles: %s/%s is missing and is mandatory",
			TreeDir, DefaultProfile)
	}

	return &Set{profiles: profiles}, nil
}

func buildTree(dir, tree string) (map[string]profile, error) {
	treeDir := filepath.Join(dir, tree)

	entries, err := os.ReadDir(treeDir)
	if err != nil {
		return nil, fmt.Errorf("profiles %s: %w", tree, err)
	}

	set := map[string]profile{}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		name := e.Name()

		files, err := filepath.Glob(filepath.Join(treeDir, name, "*.conf"))
		if err != nil {
			return nil, fmt.Errorf("profile %s/%q: %w", tree, name, err)
		}

		if len(files) == 0 {
			return nil, fmt.Errorf("profile %s/%q has no .conf files", tree, name)
		}

		sort.Strings(files)

		eng, err := corazaengine.New(root, files)
		if err != nil {
			return nil, fmt.Errorf("profile %s/%q: %w", tree, name, err)
		}

		policy, err := prior.LoadDir(filepath.Join(treeDir, name))
		if err != nil {
			return nil, fmt.Errorf("profile %s/%q: %w", tree, name, err)
		}

		set[name] = profile{engine: eng, policy: policy}
	}

	return set, nil
}
