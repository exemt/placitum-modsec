package sticky

import (
	"sync"
	"time"
)

type State interface {
	Discard()
}

type Registry[T State] struct {
	max int
	ttl time.Duration

	mu    sync.Mutex
	items map[string]*item[T]

	stats Stats
}

type item[T State] struct {
	live    T
	expires time.Time
}

type Stats struct {
	Parked  int64
	Taken   int64
	Expired int64
	Refused int64
	Live    int
}

func New[T State](max int, ttl time.Duration) *Registry[T] {
	return &Registry[T]{
		max:   max,
		ttl:   ttl,
		items: make(map[string]*item[T]),
	}
}

func (r *Registry[T]) TTL() time.Duration { return r.ttl }

func (r *Registry[T]) Park(rid string, live T) bool {
	now := time.Now()

	r.mu.Lock()

	dead := r.expired(now)

	if len(r.items) >= r.max {
		r.stats.Refused++
		r.mu.Unlock()

		discard(dead)

		return false
	}

	if it, ok := r.items[rid]; ok {
		dead = append(dead, it.live)
		delete(r.items, rid)
	}

	r.items[rid] = &item[T]{live: live, expires: now.Add(r.ttl)}
	r.stats.Parked++
	r.mu.Unlock()

	discard(dead)

	return true
}

func (r *Registry[T]) Take(rid string) (T, bool) {
	r.mu.Lock()

	it, ok := r.items[rid]
	if !ok {
		r.mu.Unlock()

		var zero T

		return zero, false
	}

	delete(r.items, rid)

	if time.Now().After(it.expires) {
		r.stats.Expired++
		r.mu.Unlock()

		it.live.Discard()

		var zero T

		return zero, false
	}

	r.stats.Taken++
	r.mu.Unlock()

	return it.live, true
}

func (r *Registry[T]) Drop(rid string) {
	r.mu.Lock()
	it, ok := r.items[rid]

	if ok {
		delete(r.items, rid)
	}

	r.mu.Unlock()

	if ok {
		it.live.Discard()
	}
}

func (r *Registry[T]) Sweep() int {
	r.mu.Lock()
	dead := r.expired(time.Now())
	r.mu.Unlock()

	discard(dead)

	return len(dead)
}

func (r *Registry[T]) Run(done <-chan struct{}, swept func(int)) {
	step := r.ttl / 4

	if step < time.Second {
		step = time.Second
	}

	t := time.NewTicker(step)
	defer t.Stop()

	for {
		select {
		case <-done:
			r.Close()

			return

		case <-t.C:
			if n := r.Sweep(); n > 0 && swept != nil {
				swept(n)
			}
		}
	}
}

func (r *Registry[T]) Close() {
	r.mu.Lock()
	items := r.items
	r.items = make(map[string]*item[T])
	r.mu.Unlock()

	for _, it := range items {
		it.live.Discard()
	}
}

func (r *Registry[T]) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()

	s := r.stats
	s.Live = len(r.items)

	return s
}

func (r *Registry[T]) expired(now time.Time) []T {
	var dead []T

	for rid, it := range r.items {
		if now.After(it.expires) {
			dead = append(dead, it.live)
			delete(r.items, rid)
		}
	}

	r.stats.Expired += int64(len(dead))

	return dead
}

func discard[T State](live []T) {
	for _, l := range live {
		l.Discard()
	}
}
