/*
 * Реестр припаркованных состояний. Проверяется здесь одно: каждое состояние
 * рано или поздно закрывается, и закрывается ровно один раз. Всё остальное в
 * этом пакете -- обёртка вокруг карты.
 *
 * Движка здесь нет намеренно: реестру от состояния нужен только Discard().
 */

package sticky

import (
	"testing"
	"time"
)

type fake struct {
	closed int
}

func (f *fake) Discard() { f.closed++ }

func TestParkAndTake(t *testing.T) {
	r := New[*fake](4, time.Minute)
	live := &fake{}

	if !r.Park("rid-1", live) {
		t.Fatal("park refused with room to spare")
	}

	got, ok := r.Take("rid-1")
	if !ok || got != live {
		t.Fatalf("take returned %v, %v", got, ok)
	}

	if live.closed != 0 {
		t.Fatal("taken state was closed by the registry: it belongs to the caller now")
	}

	// Второй раз того же rid нет: состояние ушло владельцу, и отдать его
	// дважды значило бы доиграть транзакцию из двух горутин.
	if _, ok := r.Take("rid-1"); ok {
		t.Fatal("the same state was handed out twice")
	}

	if s := r.Stats(); s.Parked != 1 || s.Taken != 1 || s.Live != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestTakeUnknownRID(t *testing.T) {
	r := New[*fake](4, time.Minute)

	if _, ok := r.Take("never-parked"); ok {
		t.Fatal("state appeared from nowhere")
	}
}

/*
 * Просроченное состояние не отдаётся и закрывается. Срок -- это обещание
 * модулю: продолжать после него значило бы отвечать состоянием, которого могло
 * уже не быть.
 */
func TestTakeRefusesExpired(t *testing.T) {
	r := New[*fake](4, time.Minute)
	live := &fake{}

	r.Park("rid-1", live)
	expire(t, r, "rid-1")

	if _, ok := r.Take("rid-1"); ok {
		t.Fatal("expired state was handed out")
	}

	if live.closed != 1 {
		t.Fatalf("expired state closed %d times, want 1", live.closed)
	}
}

func TestSweepClosesExpired(t *testing.T) {
	r := New[*fake](4, time.Minute)
	old, fresh := &fake{}, &fake{}

	r.Park("old", old)
	r.Park("fresh", fresh)
	expire(t, r, "old")

	if n := r.Sweep(); n != 1 {
		t.Fatalf("swept %d, want 1", n)
	}

	if old.closed != 1 {
		t.Fatalf("expired state closed %d times, want 1", old.closed)
	}

	if fresh.closed != 0 {
		t.Fatal("a live state was swept")
	}

	if _, ok := r.Take("fresh"); !ok {
		t.Fatal("the live state did not survive the sweep")
	}
}

/*
 * Потолок -- это память. Переполненный реестр отказывает новому, а не вытесняет
 * чужое: то уже обещано, а этому ещё ничего не обещали. Закрывает отказанное
 * вызывающий -- реестр его не принимал.
 */
func TestParkRefusesAtCapacity(t *testing.T) {
	r := New[*fake](1, time.Minute)
	first, second := &fake{}, &fake{}

	if !r.Park("rid-1", first) {
		t.Fatal("first park refused")
	}

	if r.Park("rid-2", second) {
		t.Fatal("park accepted past the cap")
	}

	if second.closed != 0 {
		t.Fatal("the registry closed a state it refused to take")
	}

	if _, ok := r.Take("rid-1"); !ok {
		t.Fatal("the parked state was evicted by a refused one")
	}

	if s := r.Stats(); s.Refused != 1 {
		t.Fatalf("stats = %+v, want one refusal", s)
	}
}

// Место освобождается просроченными: подметальщик мог не успеть, и отдавать
// липкость первому же всплеску из-за мертвецов незачем.
func TestParkEvictsExpiredToMakeRoom(t *testing.T) {
	r := New[*fake](1, time.Minute)
	old, live := &fake{}, &fake{}

	r.Park("old", old)
	expire(t, r, "old")

	if !r.Park("new", live) {
		t.Fatal("park refused while the only slot held an expired state")
	}

	if old.closed != 1 {
		t.Fatalf("the expired state was not closed: %d", old.closed)
	}
}

// Повтор сообщения фазы запроса: тот же rid паркуется заново, старое состояние
// закрывается -- забрать его всё равно было бы некому.
func TestParkTwiceClosesThePrevious(t *testing.T) {
	r := New[*fake](4, time.Minute)
	first, second := &fake{}, &fake{}

	r.Park("rid-1", first)
	r.Park("rid-1", second)

	if first.closed != 1 {
		t.Fatalf("the replaced state closed %d times, want 1", first.closed)
	}

	got, ok := r.Take("rid-1")
	if !ok || got != second {
		t.Fatal("take returned the replaced state")
	}
}

// Отказ фазы запроса: ответа приложения не будет, продолжать нечего.
func TestDropClosesState(t *testing.T) {
	r := New[*fake](4, time.Minute)
	live := &fake{}

	r.Park("rid-1", live)
	r.Drop("rid-1")

	if live.closed != 1 {
		t.Fatalf("dropped state closed %d times, want 1", live.closed)
	}

	if _, ok := r.Take("rid-1"); ok {
		t.Fatal("a dropped state was handed out")
	}

	r.Drop("rid-1") // повторный Drop ничего не ломает
}

// Процесс уходит: незакрытая транзакция пережила бы его только как утечка.
func TestCloseClosesEverything(t *testing.T) {
	r := New[*fake](4, time.Minute)
	a, b := &fake{}, &fake{}

	r.Park("a", a)
	r.Park("b", b)
	r.Close()

	if a.closed != 1 || b.closed != 1 {
		t.Fatalf("closed a=%d b=%d, want 1 each", a.closed, b.closed)
	}

	if s := r.Stats(); s.Live != 0 {
		t.Fatalf("stats = %+v, want an empty registry", s)
	}
}

func TestRunSweepsUntilDone(t *testing.T) {
	r := New[*fake](4, 4*time.Second) // шаг подметальщика -- минимум, секунда
	live := &fake{}

	r.Park("rid-1", live)
	expire(t, r, "rid-1")

	done := make(chan struct{})
	swept := make(chan int, 1)

	go r.Run(done, func(n int) { swept <- n })

	select {
	case n := <-swept:
		if n != 1 {
			t.Fatalf("swept %d, want 1", n)
		}

	case <-time.After(3 * time.Second):
		t.Fatal("the sweeper never ran")
	}

	close(done)
}

// Просрочить припаркованное, не дожидаясь срока: тест в том же пакете, и
// подменить время дешевле, чем спать.
func expire(t *testing.T, r *Registry[*fake], rid string) {
	t.Helper()

	r.mu.Lock()
	defer r.mu.Unlock()

	it, ok := r.items[rid]
	if !ok {
		t.Fatalf("%s is not parked", rid)
	}

	it.expires = time.Now().Add(-time.Second)
}
