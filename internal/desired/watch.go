package desired

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/redis/go-redis/v9"

	"github.com/exemt/placitum-modsec/internal/rules"
)

const fetchRetry = 30 * time.Second

type Applied struct {
	mu    sync.RWMutex
	hash  string
	rev   int
	apply string
	names []string
}

func (a *Applied) Snapshot() (hash string, rev int, apply string, names []string) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.hash, a.rev, a.apply, append([]string(nil), a.names...)
}

func (a *Applied) set(hash string, rev int, apply string, names []string) {
	a.mu.Lock()
	a.hash = hash
	a.rev = rev
	a.apply = apply
	a.names = append([]string(nil), names...)
	a.mu.Unlock()
}

func Watch(
	ctx context.Context,
	nc *nats.Conn,
	rdb *redis.Client,
	reg *rules.Registry,
	dataDir string,
	level *slog.LevelVar,
	log *slog.Logger,
) (*Applied, error) {
	applied := &Applied{}

	js, err := jetstream.New(nc)
	if err != nil {
		return nil, err
	}

	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:  Bucket,
		History: 5,
	})
	if err != nil {
		return nil, err
	}

	watcher, err := kv.Watch(ctx, PackKey)
	if err != nil {
		return nil, err
	}

	go func() {
		defer watcher.Stop()

		var (
			pending *Pack
			retry   <-chan time.Time
		)

		handle := func(p *Pack) bool {
			hash, rev, apply, _ := applied.Snapshot()
			if apply == ApplyOK && hash == p.SHA256 && rev == p.Rev {
				return false
			}

			blobs, err := FetchBlobs(ctx, rdb, p)
			if err != nil {
				log.Warn("desired fetch failed",
					"rev", p.Rev,
					"hash", p.SHA256,
					"retry_in", fetchRetry.String(),
					"error", err.Error(),
				)
				applied.set(hash, rev, ApplyFailed, namesOr(reg))
				return true
			}

			m, err := Expand(p, blobs)
			if err != nil {
				log.Warn("desired expand failed",
					"rev", p.Rev,
					"hash", p.SHA256,
					"error", err.Error(),
				)
				applied.set(hash, rev, ApplyFailed, namesOr(reg))
				return false
			}

			if err := Apply(reg, dataDir, m); err != nil {
				log.Warn("desired apply failed",
					"rev", p.Rev,
					"hash", p.SHA256,
					"error", err.Error(),
				)
				applied.set(hash, rev, ApplyFailed, namesOr(reg))
				return false
			}

			applied.set(p.SHA256, p.Rev, ApplyOK, m.Names())

			m.Settings.apply(level, log)

			log.Info("desired applied",
				"rev", p.Rev,
				"hash", p.SHA256,
				"profiles", m.Names(),
			)
			return false
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-retry:
				retry = nil
				if pending == nil {
					continue
				}
				if handle(pending) {
					retry = time.After(fetchRetry)
				} else {
					pending = nil
				}
			case entry, ok := <-watcher.Updates():
				if !ok {
					return
				}

				if entry == nil {
					continue
				}

				switch entry.Operation() {
				case jetstream.KeyValueDelete, jetstream.KeyValuePurge:
					continue
				}

				p, err := ParsePack(entry.Value())
				if err != nil {
					log.Warn("desired rejected", "error", err.Error())
					continue
				}

				pending, retry = nil, nil
				if handle(p) {
					pending = p
					retry = time.After(fetchRetry)
				}
			}
		}
	}()

	return applied, nil
}

func namesOr(reg *rules.Registry) []string {
	if set := reg.Current(); set != nil {
		return set.Names()
	}

	return nil
}
