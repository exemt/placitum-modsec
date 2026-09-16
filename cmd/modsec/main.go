package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nuid"

	"github.com/exemt/placitum-modsec/internal/audit"
	"github.com/exemt/placitum-modsec/internal/body"
	"github.com/exemt/placitum-modsec/internal/config"
	"github.com/exemt/placitum-modsec/internal/desired"
	"github.com/exemt/placitum-modsec/internal/engine"
	"github.com/exemt/placitum-modsec/internal/queue"
	"github.com/exemt/placitum-modsec/internal/rules"
	"github.com/exemt/placitum-modsec/internal/sticky"
	"github.com/exemt/placitum-modsec/internal/verdict"
	"github.com/exemt/placitum-shared/dataset"
	"github.com/exemt/placitum-shared/flow"
	"github.com/exemt/placitum-shared/logkit"
	"github.com/exemt/placitum-shared/netinfo"
	"github.com/exemt/placitum-shared/pulse"
)

func main() {
	if err := run(); err != nil {
		slog.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	var (
		logs  *logkit.Sink
		logIO *flow.Counter
	)

	if config.LogShip() {
		logIO = flow.New()
		logs = logkit.NewSink(config.LogWriter(cfg.Name), cfg.Name, logIO)

		defer logs.Close()
	}

	level := new(slog.LevelVar)
	level.Set(cfg.LogLevel)

	log := slog.New(slog.NewJSONHandler(logs.Tee(os.Stdout),
		&slog.HandlerOptions{Level: level}))

	log.Info("build", "version", version, "revision", revision)
	slog.SetDefault(log)

	registry, err := rules.New(cfg)
	if err != nil {
		return err
	}

	set := registry.Current()

	for _, name := range set.Names() {
		log.Info("profile loaded", "profile", name, "rules", set.RuleCount(name))
	}

	opts, err := verdictOptions(cfg, log)
	if err != nil {
		return err
	}

	loader, closeStore, err := bodyLoader(cfg, log)
	if err != nil {
		return err
	}

	defer closeStore()

	nc, err := nats.Connect(joined(cfg.Servers),
		nats.Name("waf-inspector-"+cfg.Name),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(500*time.Millisecond),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Warn("bus disconnected", "error", errText(err))
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			log.Info("bus reconnected", "server", c.ConnectedUrl())
		}),
	)
	if err != nil {
		return err
	}

	defer nc.Close()

	if err := audit.Ensure(nc); err != nil {
		log.Warn("audit stream", "error", err.Error())
	} else {
		log.Info("audit stream", "stream", audit.Stream, "subjects", "waf.audit.>")
	}

	if logs != nil {
		if err := logkit.Ensure(nc); err != nil {
			log.Warn("log stream", "error", err.Error())
		}

		logs.Attach(nc)
		log.Info("log stream", "stream", logkit.Stream,
			"subject", logkit.Subject(logs.Writer()))
	}

	var resolver *netinfo.Resolver

	if cfg.GeoAddr != "" {
		var rerr error

		resolver, rerr = netinfo.New(cfg.GeoAddr, cfg.GeoTimeout, cfg.GeoNegMax, log)
		if rerr != nil {
			return fmt.Errorf("geo resolver: %w", rerr)
		}

		defer resolver.Close()
	}

	auditSink := audit.NewSink(nc, log)

	h := &handler{
		cfg:      cfg,
		log:      log,
		nc:       nc,
		audit:    auditSink,
		registry: registry,
		loader:   loader,
		opts:     opts,
		lists:    dataset.NewBackground(nc, cfg.Name, log),
		resolver: resolver,
	}

	if cfg.ResumeMax > 0 {
		h.inbox = cfg.Subject + ".i." + nuid.Next()
		h.sticky = sticky.New[*engine.Live](cfg.ResumeMax, cfg.ResumeTTL)
	}

	pool := queue.New(cfg.Workers, cfg.QueueDepth, cfg.ReserveMS, cfg.MinBudgetMS, cfg.QueueFull, h.evaluate)
	h.pool = pool

	sub, err := nc.QueueSubscribe(cfg.Subject, cfg.Queue, h.receive)
	if err != nil {
		return err
	}

	if err := sub.SetPendingLimits(cfg.QueueDepth+cfg.Workers+2, 4*1024*1024); err != nil {
		return err
	}

	if h.inbox != "" {
		inboxSub, err := nc.Subscribe(h.inbox, h.receive)
		if err != nil {
			return err
		}

		defer func() { _ = inboxSub.Unsubscribe() }()

		releaseSub, err := nc.Subscribe(cfg.Subject+".release", h.receive)
		if err != nil {
			return err
		}

		defer func() { _ = releaseSub.Unsubscribe() }()

		stop := make(chan struct{})
		defer close(stop)

		go h.sticky.Run(stop, func(n int) {
			log.Warn("resume state expired", "transactions", n,
				"ttl", cfg.ResumeTTL.String())
		})
	}

	log.Info("connected",
		"server", nc.ConnectedUrl(),
		"subject", cfg.Subject,
		"queue", cfg.Queue,
		"inspector", cfg.Name,
		"profiles", set.Names(),
		"resume_inbox", h.inbox,
		"resume_release", cfg.Subject+".release",
		"resume_max", cfg.ResumeMax,
		"resume_ttl", cfg.ResumeTTL.String(),
		"workers", cfg.Workers,
		"queue_max", cfg.QueueDepth,
		"queue_full", cfg.QueueFull,
		"queue_expand", cfg.QueueExpand,
		"conf", cfg.ConfPath,
	)

	watchCtx, stopWatch := context.WithCancel(context.Background())
	defer stopWatch()

	var applied *desired.Applied

	config.LogInternalRedis(log, cfg.InternalURL, cfg.InternalFrom)
	if cfg.InternalURL == "" {
		log.Warn("desired watch skipped", "error", "internal redis is not configured")
	} else {
		rdb, err := desired.OpenBlobs(cfg.InternalURL)
		if err != nil {
			log.Warn("desired redis failed", "error", err.Error())
		} else {
			defer func() { _ = rdb.Close() }()

			applied, err = desired.Watch(watchCtx, nc, rdb, registry, cfg.DataDir, level, log)
			if err != nil {
				log.Warn("desired watch failed", "error", err.Error())
			} else {
				log.Info("desired watch on",
					"bucket", desired.Bucket,
					"key", desired.PackKey,
					"data", cfg.DataDir,
				)
			}
		}
	}

	inspectorID := pulse.NewID()
	stopBeat := startHeartbeat(nc, cfg, inspectorID, pool, applied, logIO, log)
	defer stopBeat()

	waitForSignal(log)
	stopWatch()

	if err := sub.Drain(); err != nil {
		log.Warn("drain failed", "error", err.Error())
	}

	pool.Close()
	auditSink.Close()

	log.Info("drained",
		"accepted", pool.Accepted.Load(),
		"shed", pool.Shed.Load(),
		"expired", pool.Expired.Load(),
		"unknown_profiles", registry.UnknownCounts(),
	)

	return nil
}

func verdictOptions(cfg *config.Config, log *slog.Logger) (verdict.Options, error) {
	var opts verdict.Options

	m, err := verdict.LoadStatusMap(cfg.StatusMapPath)
	if err != nil {
		return opts, err
	}

	if m == nil {
		log.Info("status map not found, using builtin", "path", cfg.StatusMapPath)
		m = verdict.BuiltinStatusMap()
	}

	opts.StatusMap = m

	if opts.Decisive.Ranges, err = engine.ParseRanges(cfg.DenyRuleIDs); err != nil {
		return opts, err
	}

	if len(cfg.DenyTags) > 0 {
		opts.Decisive.Tags = make(map[string]struct{}, len(cfg.DenyTags))

		for _, tag := range cfg.DenyTags {
			opts.Decisive.Tags[tag] = struct{}{}
		}
	}

	return opts, nil
}

func bodyLoader(cfg *config.Config, log *slog.Logger) (*body.Loader, func(), error) {
	if cfg.RedisURL == "" {
		return body.NewLoader(nil, nil), func() {}, nil
	}

	store, err := body.NewRedisStore(cfg.RedisURL, config.RedisTimeout)
	if err != nil {
		return nil, nil, err
	}

	if err := store.Ping(context.Background()); err != nil {
		return nil, nil, err
	}

	log.Info("body store connected", "driver", "redis")

	return body.NewLoader(store, nil), func() { _ = store.Close() }, nil
}

func startHeartbeat(
	nc *nats.Conn,
	cfg *config.Config,
	id string,
	pool *queue.Pool,
	applied *desired.Applied,
	logIO *flow.Counter,
	log *slog.Logger,
) func() {
	subject := pulse.Subject(cfg.Name, id)
	log.Info("heartbeat on",
		"subject", subject,
		"id", id,
		"every", cfg.HeartbeatEvery.String(),
	)

	beat := func() {
		work := &pulse.Work{
			Workers:    cfg.Workers,
			QueueDepth: cfg.QueueDepth,
			Queued:     pool.Queued(),
			Accepted:   pool.Accepted.Load(),
			Shed:       pool.Shed.Load(),
			Expired:    pool.Expired.Load(),
		}
		io := map[string]flow.Flow{"inspect": pool.IO()}

		if logIO != nil {
			io["log"] = logIO.Snapshot()
		}
		msg := pulse.Build(id, cfg.Name, cfg.Subject, cfg.Queue, work, io)
		msg.Version, msg.Revision = version, revision
		if applied != nil {
			hash, rev, apply, names := applied.Snapshot()
			msg.ConfigHash = hash
			msg.Rev = rev
			msg.Apply = apply
			msg.Profiles = names
		}
		if err := pulse.Publish(nc, msg); err != nil {
			log.Warn("heartbeat failed", "error", err.Error())
		}
	}

	beat()
	tick := time.NewTicker(cfg.HeartbeatEvery)

	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				beat()
			}
		}
	}()

	return func() {
		tick.Stop()
		close(done)
	}
}

func waitForSignal(log *slog.Logger) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)

	sig := <-ch
	log.Info("draining", "signal", sig.String())
}

func joined(servers []string) string {
	out := ""

	for i, s := range servers {
		if i > 0 {
			out += ","
		}

		out += s
	}

	return out
}

func errText(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}
