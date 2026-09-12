/*
 * Точка входа инспектора правил.
 *
 * Здесь только инициализация и подписка: решения принимают пакеты internal/...,
 * а этот файл собирает их в конвейер и следит, чтобы ответ уходил на каждом
 * пути без исключения.
 */

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

	/*
	 * Журнал процесса уезжает в waf.log той же пачкой, что и строки nginx:
	 * контур один, и искать причину отказа по трём десяткам docker-логов
	 * незачем. Приёмник поднимается раньше шины -- строки о том, как читался
	 * конфиг, копятся и уезжают первой же пачкой. Копия, не перенос: stdout
	 * остаётся на месте.
	 */
	var (
		logs  *logkit.Sink
		logIO *flow.Counter
	)

	if config.LogShip() {
		logIO = flow.New()
		logs = logkit.NewSink(config.LogWriter(cfg.Name), cfg.Name, logIO)

		defer logs.Close()
	}

	/*
	 * Порог журнала живой: поколение из KV переставляет его без рестарта
	 * (internal/loglevel). Переменная окружения задаёт стартовое значение.
	 */
	level := new(slog.LevelVar)
	level.Set(cfg.LogLevel)

	log := slog.New(slog.NewJSONHandler(logs.Tee(os.Stdout),
		&slog.HandlerOptions{Level: level}))

	log.Info("build", "version", version, "revision", revision)
	slog.SetDefault(log)

	/*
	 * Порядок инициализации важен: набор правил собирается до подписки. Ошибка
	 * в профиле обязана обнаруживаться при старте, а не на первом сообщении --
	 * инспектор, который из-за опечатки начинает всё пропускать, хуже
	 * отказавшего.
	 */
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
		// Инспектор переживает перезапуск шины, а не умирает вместе с ней.
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

	/*
	 * Поток журнала заводит тот писатель, который пришёл первым: на контуре,
	 * где ни одна нода ещё не поднялась, им оказывается инспектор. Публикация
	 * в несуществующий поток -- тишина, а не ошибка.
	 */
	if logs != nil {
		if err := logkit.Ensure(nc); err != nil {
			log.Warn("log stream", "error", err.Error())
		}

		logs.Attach(nc)
		log.Info("log stream", "stream", logkit.Stream,
			"subject", logkit.Subject(logs.Writer()))
	}

	/*
	 * Резолвер подсети и системы нужен только строкам инициаторов с
	 * write: net|asn. Без адреса сервиса гео он nil -- такие строки молчат,
	 * остальное работает.
	 */
	var resolver *netinfo.Resolver

	if cfg.GeoAddr != "" {
		var rerr error

		resolver, rerr = netinfo.New(cfg.GeoAddr, cfg.GeoTimeout, cfg.GeoNegMax, log)
		if rerr != nil {
			return fmt.Errorf("geo resolver: %w", rerr)
		}

		defer resolver.Close()
	}

	/*
	 * События аудита уезжают пачками, а не по одной на инспекцию: при четырёх
	 * инспекторах в наборе это впятеро больше сообщений, чем запросов, и
	 * партия из одного сообщения кладёт вставку у потребителя.
	 *
	 * Закрывается после пула: в очереди события уже отвеченных запросов.
	 */
	auditSink := audit.NewSink(nc, log)

	h := &handler{
		cfg:      cfg,
		log:      log,
		nc:       nc,
		audit:    auditSink,
		registry: registry,
		loader:   loader,
		opts:     opts,
		// Публикатор наборов создаётся всегда, когда есть шина: профиль с
		// инициатором «в набор» может приехать поколением после старта.
		lists:    dataset.NewBackground(nc, cfg.Name, log),
		resolver: resolver,
	}

	/*
	 * Личный subject экземпляра. Имя случайное и живёт ровно столько, сколько
	 * процесс: обещание держать состояние даётся от имени экземпляра, а не
	 * реестра, и умерший экземпляр обязан перестать существовать для модуля --
	 * тот получит no_responders и пойдёт в групповой subject.
	 */
	if cfg.ResumeMax > 0 {
		h.inbox = cfg.Subject + ".i." + nuid.Next()
		h.sticky = sticky.New[*engine.Live](cfg.ResumeMax, cfg.ResumeTTL)
	}

	pool := queue.New(cfg.Workers, cfg.QueueDepth, cfg.ReserveMS, cfg.MinBudgetMS, cfg.QueueFull, h.evaluate)
	h.pool = pool

	// Queue group: горизонтальное масштабирование без координации. Ответ уходит
	// в инбокс того воркера nginx, который спрашивал, потому что его имя
	// приехало в reply-to.
	sub, err := nc.QueueSubscribe(cfg.Subject, cfg.Queue, h.receive)
	if err != nil {
		return err
	}

	// Забираем с шины сразу. pending — запас на полёт в колбэк, не очередь:
	// прокисшие выкидываем из pool, слот занимает свежий запрос.
	if err := sub.SetPendingLimits(cfg.QueueDepth+cfg.Workers+2, 4*1024*1024); err != nil {
		return err
	}

	/*
	 * Личный subject -- подписка без группы: сообщение адресовано этому
	 * экземпляру, и разделить его не с кем. Обработчик тот же: продолжение
	 * отличается от обычного сообщения только тем, что состояние нашлось.
	 */
	if h.inbox != "" {
		inboxSub, err := nc.Subscribe(h.inbox, h.receive)
		if err != nil {
			return err
		}

		defer func() { _ = inboxSub.Unsubscribe() }()

		/*
		 * Освобождения -- общая тема и подписка без группы: модуль не всегда
		 * знает, какой экземпляр держит состояние. Когда волна замыкается на
		 * чужом отказе, наш ответ с личным адресом до модуля уже не доходит, а
		 * сказать «брось» всё равно надо. Ключ есть только у одного экземпляра;
		 * остальные ничего не находят и ничего не делают.
		 */
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

	// Блобы поколения -- из внутреннего Redis контура (internal блока redis в
	// inspector.conf или REDIS_INTERNAL_URL), тело запроса -- из обменника
	// (REDIS_URL): см. bodyLoader ниже.
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

	/*
	 * Дренаж: сначала снимается подписка, потом воркеры дожидаются принятых
	 * сообщений. Без него reload инспектора выглядит на стороне модуля как
	 * всплеск срабатываний политики waf_deadline на его subject.
	 */
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

	if opts.Decisive.Ranges, err = verdict.ParseRanges(cfg.DenyRuleIDs); err != nil {
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
		// Локатор с внешним драйвером приедет только на этапе 6; до тех пор
		// тело приходит инлайном или не приходит вовсе.
		return body.NewLoader(nil, nil), func() {}, nil
	}

	store, err := body.NewRedisStore(cfg.RedisURL, config.RedisTimeout)
	if err != nil {
		return nil, nil, err
	}

	// Недостижимое хранилище -- ошибка старта, а не сюрприз на первом теле.
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

		// Канал журнала -- там же, где темп инспекции: потерянная строка
		// видна ошибкой канала, и это единственное место, где её видно.
		// Сам приёмник о своих потерях молчит по построению.
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
