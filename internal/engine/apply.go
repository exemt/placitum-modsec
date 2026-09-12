/*
 * Отображение сообщения инспекции на вызовы движка.
 *
 * Это прямая таблица из docs/research/modsecurity-inspector.md, и она одинакова
 * для обоих кандидатов движка -- поэтому живёт рядом с интерфейсом, а не внутри
 * реализации. Ни одна строка здесь не зависит от того, Coraza за интерфейсом
 * или libmodsecurity.
 */

package engine

import (
	"strings"
	"time"
)

// Input -- то, что движку нужно от сообщения. Собирается вызывающим кодом из
// protocol.Request и результата internal/body, чтобы этот пакет не зависел ни
// от формата провода, ни от способа получения тела.
type Input struct {
	RID string

	ClientIP   string
	ClientPort int
	ServerIP   string
	ServerPort int

	Method  string
	URI     string
	Args    string
	Version string
	Host    string
	Headers [][2]string

	Body []byte
	// BodyTruncated -- явный признак, а не молчаливая трактовка префикса как
	// целого тела: она источник ложных пропусков.
	BodyTruncated bool
}

/*
 * ResponseInput -- сторона ответа. Тем же типом пользуются оба пути: и
 * продолжение живой транзакции, и её переигровка с нуля.
 */
type ResponseInput struct {
	Status  int
	Proto   string
	Headers [][2]string

	Body          []byte
	BodyTruncated bool
}

// Outcome -- всё, что движок сообщил по итогам транзакции.
type Outcome struct {
	Intervention *Intervention
	Matched      []MatchedRule
	AnomalyScore int
	Threshold    int
	EngineMS     float64
}

/*
 * Live -- транзакция, пережившая сообщение фазы запроса.
 *
 * Она существует затем, что фазы 3-4 движка -- продолжение фаз 1-2, а не
 * отдельная работа: правилам ответа нужны REQUEST_HEADERS, ARGS, SERVER_NAME и
 * входящий счёт той же транзакции. Пока она открыта, она держит память (тело
 * запроса, коллекции, найденное), поэтому закрыть её обязан вызывающий -- либо
 * Resume(), либо Discard(), либо срок, который ведёт реестр.
 */
type Live struct {
	tx    Transaction
	proto string
}

// Apply прогоняет фазы 1-2 и закрывает транзакцию. Путь маршрута, у которого
// фазы ответа нет: продолжать нечего.
func Apply(eng Engine, in *Input) (*Outcome, error) {
	started := time.Now()

	tx, it, err := begin(eng, in)
	if err != nil {
		return nil, err
	}

	defer tx.Close()

	tx.ProcessLogging()

	return outcome(tx, it, 1, 2, tx.Anomaly, started), nil
}

/*
 * ApplyKeep -- то же самое, но транзакция остаётся открытой: маршрут спросит
 * этот же экземпляр о фазах 3-4. ProcessLogging здесь не вызывается намеренно
 * -- фаза 5 сводит счёт обеих сторон и закрывает транзакцию логически, а
 * ответа ещё не было.
 */
func ApplyKeep(eng Engine, in *Input) (*Outcome, *Live, error) {
	started := time.Now()

	tx, it, err := begin(eng, in)
	if err != nil {
		return nil, nil, err
	}

	return outcome(tx, it, 1, 2, tx.Anomaly, started),
		&Live{tx: tx, proto: protocolVersion(in.Version)}, nil
}

// Resume доигрывает фазы 3-4 на живой транзакции и закрывает её.
func (l *Live) Resume(rsp *ResponseInput) (*Outcome, error) {
	started := time.Now()

	defer l.tx.Close()

	return finish(l.tx, rsp, l.proto, started)
}

// Discard закрывает транзакцию, которую никто не продолжил.
func (l *Live) Discard() {
	l.tx.Close()
}

/*
 * ApplyResponse -- откат: продолжения не случилось, состояния нет, и фазы 1-2
 * прогоняются заново.
 *
 * Не ради их находок -- их уже нашёл инспектор фазы запроса, и в отчёт они не
 * попадут. Ради двух других вещей. Первая: инициализация CRS (901) -- это
 * правила фазы 1, они выставляют уровни паранойи, веса severity и пороги, и без
 * их прогона RESPONSE-* складывают нераскрытые макросы вместо весов. Вторая:
 * контекст запроса для правил, которые на него смотрят, -- у стокового CRS
 * таких среди RESPONSE-* нет ни одного, но локальные правила маршрута и
 * корреляция входящего счёта с исходящим читают именно его.
 *
 * Тело запроса сюда не приезжает, поэтому ARGS_POST и REQUEST_BODY у
 * переигранной транзакции пусты, а входящий счёт пересчитан без них. Это и есть
 * цена отката, и она видна в аудите как resumed=false.
 */
func ApplyResponse(eng Engine, in *Input, rsp *ResponseInput) (*Outcome, error) {
	started := time.Now()

	tx, _, err := begin(eng, in)
	if err != nil {
		return nil, err
	}

	defer tx.Close()

	return finish(tx, rsp, protocolVersion(in.Version), started)
}

/*
 * Фазы 1-2 на открытой транзакции. Вмешательство возвращается вызывающему:
 * фазе запроса оно решение, переигровке -- уже вынесенное решение, которое
 * повторять нельзя.
 */
func begin(eng Engine, in *Input) (Transaction, *Intervention, error) {
	tx, err := eng.NewTransaction(in.RID)
	if err != nil {
		return nil, nil, err
	}

	var it *Intervention

	tx.ProcessConnection(in.ClientIP, in.ClientPort, in.ServerIP, in.ServerPort)

	/*
	 * Движку нужен URI вместе со строкой запроса: ARGS_GET он наполняет сам,
	 * разбирая её. Модуль присылает путь и args раздельно, поэтому здесь они
	 * снова склеиваются -- иначе половина CRS осталась бы без входных данных.
	 */
	tx.ProcessURI(requestTarget(in.URI, in.Args), in.Method, protocolVersion(in.Version))

	if in.Host != "" {
		// До ProcessRequestHeaders: иначе SERVER_NAME не виден правилам фазы 1.
		tx.SetServerName(hostname(in.Host))
	}

	for _, h := range in.Headers {
		tx.AddRequestHeader(h[0], h[1])
	}

	if v := tx.ProcessRequestHeaders(); v != nil {
		it = v
	}

	if len(in.Body) > 0 {
		if err := tx.WriteRequestBody(in.Body); err != nil {
			tx.Close()
			return nil, nil, err
		}
	}

	/*
	 * ProcessRequestBody вызывается всегда, даже когда тела нет. Фаза 2 -- это
	 * не только разбор тела: в ней же CRS сводит аномальный счёт (949xxx), и
	 * без этого вызова счёт остался бы нулевым при любых срабатываниях фазы 1.
	 */
	v, err := tx.ProcessRequestBody()
	if err != nil {
		tx.Close()
		return nil, nil, err
	}

	if v != nil && it == nil {
		it = v
	}

	return tx, it, nil
}

// Фазы 3-4 на открытой транзакции -- общие для продолжения и для переигровки.
func finish(tx Transaction, rsp *ResponseInput, proto string,
	started time.Time) (*Outcome, error) {

	var it *Intervention

	for _, h := range rsp.Headers {
		tx.AddResponseHeader(h[0], h[1])
	}

	if v := tx.ProcessResponseHeaders(rsp.Status, proto); v != nil {
		it = v
	}

	if len(rsp.Body) > 0 {
		if err := tx.WriteResponseBody(rsp.Body); err != nil {
			return nil, err
		}
	}

	/*
	 * ProcessResponseBody вызывается всегда, даже когда тела нет: в фазе 4 CRS
	 * сводит исходящий счёт (959100), и без этого вызова он остался бы нулевым
	 * при любых срабатываниях фазы 3.
	 */
	v, err := tx.ProcessResponseBody()
	if err != nil {
		return nil, err
	}

	if v != nil && it == nil {
		it = v
	}

	tx.ProcessLogging()

	return outcome(tx, it, 3, 4, tx.AnomalyOutbound, started), nil
}

// Сборка итога: находки своих фаз, счёт своей стороны, время движка.
func outcome(tx Transaction, it *Intervention, lo, hi int,
	score func() (int, int), started time.Time) *Outcome {

	out := &Outcome{Intervention: it}

	out.Matched = matchedPhases(tx, lo, hi)
	out.AnomalyScore, out.Threshold = score()
	out.EngineMS = float64(time.Since(started).Microseconds()) / 1000

	return out
}

/*
 * Находки названных фаз. Каждая сторона отчитывается за свою: фазы 1-2 уехали
 * в вердикте запроса, и повторить их в вердикте ответа значило бы посчитать
 * одну находку дважды. Фаза 5 не отчитывается вовсе -- её правила (сводка
 * счёта, корреляция) не находки, а пересказ того, что уже посчитано.
 */
func matchedPhases(tx Transaction, lo, hi int) []MatchedRule {
	all := tx.Matched()

	out := make([]MatchedRule, 0, len(all))

	for _, m := range all {
		if m.Phase >= lo && m.Phase <= hi {
			out = append(out, m)
		}
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

func requestTarget(uri, args string) string {
	if args == "" {
		return uri
	}

	return uri + "?" + args
}

// Движку нужна версия вида "1.1", а не "HTTP/1.1": строка запроса собирается им
// самим, и префикс в ней оказался бы дважды.
func protocolVersion(v string) string {
	if v == "" {
		return "1.1"
	}

	return strings.TrimPrefix(v, "HTTP/")
}

// SERVER_NAME -- имя хоста без порта: правила сравнивают его с доменом.
func hostname(host string) string {
	if i := strings.LastIndex(host, ":"); i != -1 && !strings.Contains(host[i:], "]") {
		return host[:i]
	}

	return host
}
