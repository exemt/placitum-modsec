package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/exemt/placitum-shared/loglevel"
)

type Config struct {
	Servers []string
	Subject string
	Name    string
	Queue   string

	ProfilesDir string
	DataDir     string

	Workers     int
	QueueDepth  int
	QueueFull   string
	QueueExpand string
	ConfPath    string

	ReserveMS   int
	MinBudgetMS int

	DenyRuleIDs []string
	DenyTags    []string

	RedisURL     string
	InternalURL  string
	InternalFrom string

	GeoAddr       string
	GeoTimeout    time.Duration
	GeoNegMax     int
	SecretsDir    string
	StatusMapPath string

	Versions []int
	LogLevel slog.Level

	HeartbeatEvery time.Duration

	ResumeMax int
	ResumeTTL time.Duration
}

const RedisTimeout = 20 * time.Millisecond

func Load() (*Config, error) {
	c := &Config{
		Servers:       splitList(env("NATS_URL", "nats://127.0.0.1:4222")),
		Subject:       env("WAF_MODSEC_SUBJECT", "waf.req.modsec"),
		Name:          env("WAF_MODSEC_NAME", "modsec"),
		ProfilesDir:   env("WAF_MODSEC_PROFILES", "./profiles"),
		DataDir:       env("WAF_MODSEC_DATA", ""),
		DenyRuleIDs:   splitList(env("WAF_MODSEC_DENY_RULE_IDS", "")),
		DenyTags:      splitList(env("WAF_MODSEC_DENY_TAGS", "")),
		GeoAddr:       env("WAF_MODSEC_GEO_ADDR", ""),
		SecretsDir:    env("WAF_MODSEC_SECRETS", ""),
		StatusMapPath: env("WAF_MODSEC_STATUS_MAP", "./status_map.yaml"),
	}

	c.Queue = env("WAF_MODSEC_QUEUE", c.Name)

	var err error

	if c.Workers, err = envInt("WAF_MODSEC_WORKERS", runtime.GOMAXPROCS(0)); err != nil {
		return nil, err
	}

	q := queueSettings{
		Max:    256,
		Full:   QueueFullDrop,
		Expand: QueueExpandOff,
	}

	var file queueFile

	c.ConfPath = confPath("WAF_MODSEC_CONF")
	if c.ConfPath != "" {
		var ferr error
		if file, ferr = loadQueueFile(c.ConfPath); ferr != nil {
			return nil, ferr
		}

		applyQueueFile(&q, file)
	}

	c.RedisURL = exchangeRedis(file)
	c.InternalURL, c.InternalFrom = internalRedis(c.ConfPath, file, c.RedisURL)

	if q.Max, err = envIntIfSet("WAF_MODSEC_QUEUE_DEPTH", q.Max); err != nil {
		return nil, err
	}

	c.QueueDepth = q.Max
	c.QueueFull = envOverride("WAF_MODSEC_QUEUE_FULL", q.Full)
	c.QueueExpand = envOverride("WAF_MODSEC_QUEUE_EXPAND", q.Expand)

	if c.ReserveMS, err = envInt("WAF_MODSEC_RESERVE_MS", 2); err != nil {
		return nil, err
	}

	if c.MinBudgetMS, err = envInt("WAF_MODSEC_MIN_BUDGET_MS", 3); err != nil {
		return nil, err
	}

	if c.Versions, err = envIntList("WAF_MODSEC_VERSIONS", []int{2}); err != nil {
		return nil, err
	}

	if c.LogLevel, err = parseLevel(env("WAF_MODSEC_LOG", "info")); err != nil {
		return nil, err
	}

	if c.GeoTimeout, err = envDuration("WAF_MODSEC_GEO_TIMEOUT", 500*time.Millisecond); err != nil {
		return nil, err
	}

	if c.GeoNegMax, err = envInt("WAF_MODSEC_GEO_NEG_MAX", 0); err != nil {
		return nil, err
	}

	if c.HeartbeatEvery, err = envDuration("WAF_HEARTBEAT_EVERY", 4*time.Second); err != nil {
		return nil, err
	}

	if c.ResumeMax, err = envInt("WAF_MODSEC_RESUME_MAX", c.QueueDepth*4); err != nil {
		return nil, err
	}

	if c.ResumeTTL, err = envDuration("WAF_MODSEC_RESUME_TTL", 30*time.Second); err != nil {
		return nil, err
	}

	return c, c.validate()
}

func (c *Config) validate() error {
	if len(c.Servers) == 0 {
		return fmt.Errorf("NATS_URL is empty")
	}

	if c.Subject == "" || c.Name == "" || c.Queue == "" {
		return fmt.Errorf("subject, name and queue must not be empty")
	}

	if c.Workers < 1 {
		return fmt.Errorf("WAF_MODSEC_WORKERS must be positive, got %d", c.Workers)
	}

	if c.QueueDepth < 1 {
		return fmt.Errorf("queue_max must be positive, got %d", c.QueueDepth)
	}

	switch c.QueueFull {
	case QueueFullDrop, QueueFullWait:
	default:
		return fmt.Errorf("queue_full must be drop or wait, got %q", c.QueueFull)
	}

	switch c.QueueExpand {
	case QueueExpandOff, QueueExpandAsk:
	default:
		return fmt.Errorf("queue_expand must be off or ask, got %q", c.QueueExpand)
	}

	if c.ResumeMax < 0 {
		return fmt.Errorf("WAF_MODSEC_RESUME_MAX must not be negative, got %d",
			c.ResumeMax)
	}

	if c.ResumeMax > 0 && c.ResumeTTL <= 0 {
		return fmt.Errorf("WAF_MODSEC_RESUME_TTL must be positive while "+
			"WAF_MODSEC_RESUME_MAX is %d", c.ResumeMax)
	}

	if c.ReserveMS < 0 || c.MinBudgetMS < 0 {
		return fmt.Errorf("WAF_MODSEC_RESERVE_MS and WAF_MODSEC_MIN_BUDGET_MS must not be negative")
	}

	if len(c.Versions) == 0 {
		return fmt.Errorf("WAF_MODSEC_VERSIONS is empty")
	}

	abs, err := filepath.Abs(c.ProfilesDir)
	if err != nil {
		return fmt.Errorf("WAF_MODSEC_PROFILES: %w", err)
	}

	c.ProfilesDir = abs

	if c.DataDir == "" {
		c.DataDir = abs + ".applied"
	}

	data, err := filepath.Abs(c.DataDir)
	if err != nil {
		return fmt.Errorf("WAF_MODSEC_DATA: %w", err)
	}

	c.DataDir = data

	return nil
}

func (c *Config) Supports(v int) bool {
	for _, known := range c.Versions {
		if known == v {
			return true
		}
	}

	return false
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}

	return def
}

func envInt(name string, def int) (int, error) {
	return envIntIfSet(name, def)
}

func envIntIfSet(name string, def int) (int, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}

	return v, nil
}

func envIntList(name string, def []int) ([]int, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	var out []int

	for _, part := range splitList(raw) {
		v, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}

		out = append(out, v)
	}

	return out, nil
}

func envDuration(name string, def time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}

	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}

	return d, nil
}

func splitList(s string) []string {
	var out []string

	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}

	return out
}

func parseLevel(s string) (slog.Level, error) {
	level, err := loglevel.Parse(s)
	if err != nil {
		return 0, fmt.Errorf("WAF_MODSEC_LOG: %w", err)
	}

	return level, nil
}
