/*
 * Реестр живых транзакций между фазами одного запроса.
 *
 * Фазы 3-4 движка -- продолжение фаз 1-2, а не отдельная работа: у них общая
 * инициализация, общий контекст запроса и общий счёт. Одно сообщение -- одна
 * фаза, поэтому между двумя сообщениями транзакция обязана где-то жить, и живёт
 * она здесь. Без этого её приходится собирать заново на каждом ответе -- по
 * контексту из сообщения и без тела запроса.
 *
 * Всё, что тут есть, -- это ответ на вопрос «когда её закрыть». Ответов пять:
 * пришло продолжение, фаза запроса отказала, истёк срок, кончился потолок,
 * ушёл процесс. Шестого быть не должно: незакрытая транзакция -- это
 * удержанная память на каждом запросе.
 */

package sticky

import (
	"sync"
	"time"
)

/*
 * State -- то, что реестр хранит. Ему нужно от состояния ровно одно: уметь
 * закрыться. Знать, что за этим стоит транзакция Coraza, реестру незачем, и
 * без этого знания он проверяется без движка вовсе.
 */
type State interface {
	Discard()
}

// Registry -- припаркованные состояния по rid.
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

/*
 * Stats -- счётчики, по которым видно, работает ли липкость. Parked и Taken
 * расходятся ровно на то, что умерло по сроку: маршрут, где эта разница
 * велика, настроен неверно -- продолжение объявлено, а фаза ответа не бежит.
 */
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

// TTL -- срок, который экземпляр обещает модулю в continue.
func (r *Registry[T]) TTL() time.Duration { return r.ttl }

/*
 * Park оставляет транзакцию до продолжения. false означает «не обещаю»: место
 * кончилось. Отказ честнее вытеснения чужой транзакции -- та уже кому-то
 * обещана, а этой ещё ничего не обещали, и модуль по отсутствию continue
 * просто пойдёт в групповой subject.
 */
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

	/*
	 * Тот же rid уже припаркован -- это повтор сообщения фазы запроса: модуль
	 * переспросил после таймаута. Остаётся та транзакция, что отвечает на
	 * последнее сообщение; ключ один, и старой всё равно никто не заберёт.
	 */
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

/*
 * Take забирает транзакцию под продолжение. Она уходит из реестра сразу:
 * дальше ею владеет один воркер, и второе сообщение с тем же rid не получит
 * ту же транзакцию в другой горутине.
 */
func (r *Registry[T]) Take(rid string) (T, bool) {
	r.mu.Lock()

	it, ok := r.items[rid]
	if !ok {
		r.mu.Unlock()

		var zero T

		return zero, false
	}

	delete(r.items, rid)

	/*
	 * Просроченную не отдаём: срок мы обещали, и продолжать после него значило
	 * бы отвечать состоянием, которого могло уже не быть. Модуль обязан
	 * пережить его отсутствие -- в этом и есть контракт отката.
	 */
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

// Drop закрывает транзакцию, продолжения которой не будет: фаза запроса
// отказала, и ответа приложения не появится.
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

// Sweep закрывает всё просроченное. Возвращает число закрытых.
func (r *Registry[T]) Sweep() int {
	r.mu.Lock()
	dead := r.expired(time.Now())
	r.mu.Unlock()

	discard(dead)

	return len(dead)
}

/*
 * Run -- подметальщик. Шаг -- четверть срока: транзакция переживает свой срок
 * не дольше чем на четверть, а будить процесс чаще незачем -- реестр на
 * маршрутах без липкости пуст.
 */
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

// Close закрывает всё, что осталось: процесс уходит, продолжений не будет.
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

/*
 * Вынуть просроченные из карты. Под замком -- только это: закрывает их
 * вызывающий уже без замка, потому что Close движка ходит по коллекциям
 * транзакции, а держать на этом общий замок реестра незачем.
 */
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
