/*
 * Инициаторы по исходу: вторая сторона канала действий.
 *
 * Приём -- половина канала (prior.go); здесь инспектор сам говорит соседям и
 * сам вносит субъекта в живой набор. Условие -- собственный решённый исход
 * запроса, а не его предпосылки: повторённые второй строкой, они разъехались
 * бы с политикой на первой правке.
 *
 * Живут в том же policy.yaml, что и правила приёма, намеренно: две стороны
 * одного канала, и разносить их по двум файлам значит дать им разъехаться.
 */

package prior

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/exemt/placitum-modsec/internal/protocol"
)

const (
	// Триггеры: собственный вердикт этой фазы.
	OnDeny  = "deny"
	OnAllow = "allow"
	OnScore = "score"

	/*
	 * OnOverload -- оценка не начиналась: очередь была полна, и запрос снят на
	 * входе (MODSEC_QUEUE_LIMIT). Протухший бюджет триггером не считается:
	 * дедлайн бывает и у короткой волны, и дёргать инициаторы за латентность
	 * контура значило бы банить клиента ни за что. Вердиктом эта строка не
	 * бывает -- обработчик передаёт её в Fire как имя триггера снятия.
	 */
	OnOverload = "overload"

	/*
	 * Кого писать в набор -- те же слова, что у капчи. Адрес -- самая мелкая и
	 * самая дешёвая для смены единица. Подсеть переживает смену адреса: net --
	 * эффективный анонс, самый узкий (лайт), net_all -- все анонсы, накрывающие
	 * адрес, включая чужие широкие (хард). Автономная система целиком (asn) --
	 * решение другого масштаба, и потому это отдельная строка, а не
	 * переключатель точности. Во что они разворачиваются, решает
	 * netinfo.Values -- одна на всех отправителей.
	 */
	WriteAddr   = "addr"
	WriteNet    = "net"
	WriteNetAll = "net_all"
	WriteASN    = "asn"
)

/*
 * outcomeVerbs -- словарь канала со стороны ОТПРАВИТЕЛЯ: глагол и оси, с
 * которыми он бывает. Он шире того, что инспектор принимает сам (threshold и
 * skip): просить можно о чём угодно из словаря, слушателя выбирает получатель
 * своим правилом приёма.
 *
 * Копия словаря здесь неизбежна и осознанна (docs/inspector-actions.md, «Где
 * он лежит»): за словарём по сети горячий путь не ходит.
 */
var outcomeVerbs = map[string][]string{
	protocol.DoChallenge: {protocol.ApplyRequest},
	protocol.DoThreshold: {protocol.ApplyRequest},
	protocol.DoSkip:      {protocol.ApplyRequest},
	// Переключить группу модификаторов ответа у rewrite: какую и куда,
	// называет отправитель (group + set), примет ли -- правило получателя.
	protocol.DoMutate: {protocol.ApplyRequest},
	protocol.DoReauth: {protocol.ApplySession},
	protocol.DoNote: {protocol.ApplyRequest, protocol.ApplyIP,
		protocol.ApplyASN, protocol.ApplySession},
	// Режим вызова соседа: исполняет модуль от любого спрошенного соседа.
	protocol.DoActive:  {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoPassive: {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoOff:     {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoVote:    {protocol.ApplyRequest, protocol.ApplyConn},
	// Глаголы записи: журнал и архив этого запроса (на кадрах -- кадра либо,
	// с conn, соединения). Исполняет модуль от любого спрошенного
	// инспектора; адресата нет -- запись маршрута.
	protocol.DoAudit:   {protocol.ApplyRequest, protocol.ApplyResponse},
	protocol.DoArchive: {protocol.ApplyRequest, protocol.ApplyResponse},
	// Маркер: метка события на записи. Адресат тот же -- запись маршрута, --
	// но грант ему не нужен: метка ничего не прячет.
	protocol.DoMark: {protocol.ApplyRequest},
	// Очки на маршруте: value со знаком к сумме фазы, исполняет модуль.
	protocol.DoScore: {protocol.ApplyRequest},
}

// auditVerb -- глагол записи: исполняет модуль в адрес записи маршрута,
// поля to нет; сторона set обязательна, срок, предел и набор объектов --
// только у archive с set on.
func auditVerb(do string) bool {
	return do == protocol.DoAudit || do == protocol.DoArchive
}

/*
 * recordVerb -- адресат глагола не сосед, а запись самого маршрута: журнал,
 * архив и маркер. У всех троих поля to нет, все трое исполняются модулем и
 * потому законны на отказе -- в отличие от просьб, которым после deny некуда
 * ехать.
 */
func recordVerb(do string) bool {
	return auditVerb(do) || do == protocol.DoMark || do == protocol.DoScore
}

// archiveObject -- объект обменника, который умеет назвать archive.
func archiveObject(name string) bool {
	return name == "headers" || name == "args" || name == "body"
}

// controlVerb -- глагол исполняет модуль: адресат обязателен.
func controlVerb(do string) bool {
	return do == protocol.DoActive || do == protocol.DoPassive || do == protocol.DoOff ||
		do == protocol.DoVote
}

// checkPhaseAsk -- фаза вызова адресата: только у управляющих глаголов, одно
// из request, response, frame; с осью conn -- только frame либо без поля: до
// конца соединения живут одни кадры. Пусто -- всем вызовам имени.
func checkPhaseAsk(do, phase, apply string) error {
	if phase == "" {
		return nil
	}

	if !controlVerb(do) {
		return fmt.Errorf("phase is only for active, passive, vote and off")
	}

	switch phase {
	case protocol.PhaseRequest, protocol.PhaseResponse, protocol.PhaseFrame:
	default:
		return fmt.Errorf("phase must be request, response or frame, got %q", phase)
	}

	if apply == protocol.ApplyConn && phase != protocol.PhaseFrame {
		return fmt.Errorf("apply conn needs phase frame")
	}

	return nil
}

/*
 * Outcome -- строка «когда → что сделать». Действие ровно одно: просьба
 * соседу (непустой Do) либо запись субъекта в живой набор (непустой List).
 * У deny просьбы не бывает -- отказ обрывает фазу, и волн, которым она
 * адресована, уже не будет.
 */
type Outcome struct {
	On string `yaml:"on"`
	// At -- порог сравнения счёта; только при On == score, и там обязателен.
	At *int `yaml:"at"`
	// Below -- сравнивать в другую сторону: счёт < at вместо счёт >= at.
	Below bool `yaml:"below"`
	// Eq -- точное сравнение: счёт == at. С below взаимоисключимы.
	Eq bool `yaml:"eq"`

	// Просьба соседу.
	To    string `yaml:"to"`
	Do    string `yaml:"do"`
	Apply string `yaml:"apply"`
	// Phase -- фаза вызова адресата у управляющих глаголов; пусто -- всем
	// вызовам имени.
	Phase string `yaml:"phase"`
	Delta *int   `yaml:"delta"`
	Value *int   `yaml:"value"`
	// Counter -- имя корзины получателя при do: note: селектор поверх его
	// правил приёма. Пусто -- корзину называет правило получателя.
	Counter string `yaml:"counter"`
	// Group -- только при do: mutate, обязательна: какую группу модификаторов
	// получателя переключить; куда -- тот же ключ set, что у глаголов записи.
	Group string `yaml:"group"`
	// Set -- у mutate: куда переключить группу (on | off); у глаголов записи
	// (audit, archive): писать или нет. Объекты --
	// каждый со своей стороной, размером и источником; срок -- тот же ключ
	// ttl, что у записи в набор: у строки либо просьба, либо запись.
	Set     string               `yaml:"set"`
	Headers *protocol.ObjectSpec `yaml:"headers"`
	Args    *protocol.ObjectSpec `yaml:"args"`
	Body    *protocol.ObjectSpec `yaml:"body"`
	// When -- только у archive с set on: исходы маршрута, на которых просьбу
	// исполнять (when= директивы). Пусто -- любой, включая перенаправление.
	When []string `yaml:"when"`

	// Marker -- только у mark, и там обязателен: метка события на записи.
	Marker string `yaml:"marker"`

	// Запись в живой набор.
	List  string `yaml:"list"`
	Write string `yaml:"write"`
	TTL   string `yaml:"ttl"`

	// Code -- повод; пусто означает код решения (MODSEC_*).
	Code string `yaml:"code"`
}

// Asks -- эта строка просит соседа, а не пишет в набор.
func (o Outcome) Asks() bool { return o.Do != "" }

// Subject -- кого писать в набор; пустое поле означает адрес клиента.
func (o Outcome) Subject() string {
	if o.Write == "" {
		return WriteAddr
	}

	return o.Write
}

// Axis -- ось просьбы с досочинённой единственной: то, что уедет на провод.
// Модуль ось пишет всегда, и пустая означала бы сообщение старого образца.
func (o Outcome) Axis() string {
	if o.Apply != "" {
		return o.Apply
	}

	if axes, ok := outcomeVerbs[o.Do]; ok && (len(axes) == 1 || auditVerb(o.Do)) {
		return axes[0]
	}

	return ""
}

// Seconds -- срок записи в наборе. Разобран при загрузке, здесь только чтение.
func (o Outcome) Seconds() int {
	n, _ := parseTTL(o.TTL)
	return n
}

/*
 * Matches -- дёргает ли этот исход инициатор. Строки вердиктов и триггеров
 * совпадают по построению: и то и другое -- решение этой фазы.
 *
 * Сравнивается тот счёт, который уходит модулю, -- то есть уже с
 * коэффициентом threshold соседа, если он был. Иначе оператор смотрел бы на
 * одно число, а сосед двигал другое.
 */
func (o Outcome) Matches(verdict string, score int) bool {
	switch o.On {
	case OnAllow:
		return verdict == protocol.VerdictAllow

	case OnDeny:
		return verdict == protocol.VerdictDeny || verdict == protocol.VerdictRedirect

	// Перегрузка не вердикт: обработчик зовёт Fire со строкой триггера, и
	// совпадение имён здесь -- то же построение, что у deny и allow.
	case OnOverload:
		return verdict == OnOverload

	case OnScore:
		if verdict != protocol.VerdictScore || o.At == nil {
			return false
		}

		if o.Eq {
			return score == *o.At
		}

		if o.Below {
			return score < *o.At
		}

		return score >= *o.At
	}

	return false
}

/*
 * validateOutcome -- всё, что можно поймать до трафика. Ошибка здесь стоила бы
 * не строки в логе, а отбракованного модулем ответа: действие неверной формы
 * модуль отвергает вместе со всем ответом инспектора.
 */
func validateOutcome(i int, o Outcome) error {
	where := fmt.Sprintf("outcomes[%d]", i)

	switch o.On {
	case OnDeny, OnAllow, OnOverload:
		if o.At != nil {
			return fmt.Errorf("%s: at is only for on: score", where)
		}

		if o.Below || o.Eq {
			return fmt.Errorf("%s: below and eq are only for on: score", where)
		}

	case OnScore:
		if o.At == nil {
			return fmt.Errorf("%s: on: score needs at", where)
		}

		if *o.At < 0 {
			return fmt.Errorf("%s: at must not be negative", where)
		}

		// Сравнение одно: «ровно at» и «ниже at» разом не бывают.
		if o.Below && o.Eq {
			return fmt.Errorf("%s: below and eq are mutually exclusive", where)
		}

	default:
		return fmt.Errorf("%s: unknown on %q", where, o.On)
	}

	if o.Code != "" && !codeRe.MatchString(o.Code) {
		return fmt.Errorf("%s: bad code %q", where, o.Code)
	}

	if o.Asks() && o.List != "" {
		return fmt.Errorf("%s: do and list are mutually exclusive", where)
	}

	if o.Asks() {
		return validateOutcomeAsk(where, o)
	}

	if o.List == "" {
		return fmt.Errorf("%s: neither do nor list", where)
	}

	if !nameRe.MatchString(o.List) {
		return fmt.Errorf("%s: bad dataset name %q", where, o.List)
	}

	switch o.Subject() {
	case WriteAddr, WriteNet, WriteNetAll, WriteASN:
	default:
		return fmt.Errorf("%s: write must be %s, %s, %s or %s, got %q",
			where, WriteAddr, WriteNet, WriteNetAll, WriteASN, o.Write)
	}

	// Запись без срока пережила бы причину, по которой её сделали.
	ttl, err := parseTTL(o.TTL)
	if err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}

	if ttl <= 0 {
		return fmt.Errorf("%s: list needs ttl", where)
	}

	return nil
}

func validateOutcomeAsk(where string, o Outcome) error {
	/*
	 * Просьба на отказе никуда не доедет: deny обрывает фазу, поздних волн не
	 * будет, и правило, собранное в панели, молча ничего бы не делало.
	 * Исключение -- глаголы записи: их исполняет модуль, а отказ -- главный
	 * случай, когда запрос стоит сохранить.
	 */
	if o.On == OnDeny && !recordVerb(o.Do) {
		return fmt.Errorf("%s: deny ends the phase, an ask has nowhere to go", where)
	}

	axes, ok := outcomeVerbs[o.Do]
	if !ok {
		return fmt.Errorf("%s: unknown verb %q", where, o.Do)
	}

	if o.Apply != "" && !hasString(axes, o.Apply) {
		return fmt.Errorf("%s: verb %q does not take apply %q", where, o.Do, o.Apply)
	}

	// Ось досочиняется там, где выбора нет: у note их четыре, и угадывать,
	// про кого сказано, нельзя -- решения по осям разные.
	// У глаголов записи умолчание -- запись запроса: профили, писанные до
	// оси response, читаются как прежде.
	if o.Apply == "" && len(axes) != 1 && !auditVerb(o.Do) {
		return fmt.Errorf("%s: %s needs apply", where, o.Do)
	}

	if o.Delta != nil && (*o.Delta < -100 || *o.Delta > 900) {
		return fmt.Errorf("%s: delta %d is out of -100..900 percent", where, *o.Delta)
	}

	if o.Value != nil && (*o.Value < -100 || *o.Value > 100) {
		return fmt.Errorf("%s: value %d is out of -100..100 percent", where, *o.Value)
	}

	/*
	 * Модуль отбракует threshold без дельты вместе со всем ответом -- не даём
	 * собрать такой профиль вовсе. Ноль запрещён по той же причине: на проводе
	 * он не отличается от отсутствия, а «ничего не менять» пишется отсутствием
	 * строки, а не строкой с нулём.
	 */
	if o.Do == protocol.DoThreshold && (o.Delta == nil || *o.Delta == 0) {
		return fmt.Errorf("%s: threshold needs a non-zero delta", where)
	}

	if o.Do == protocol.DoNote && (o.Value == nil || *o.Value == 0) {
		return fmt.Errorf("%s: note needs a non-zero value", where)
	}

	// Очки: адресат -- сумма самого маршрута, названный сосед здесь та же
	// битая форма, что у записи; value обязателен и со знаком -- ноль на
	// проводе не отличается от отсутствия.
	if o.Do == protocol.DoScore {
		if o.To != "" && o.To != "*" {
			return fmt.Errorf("%s: %s takes no to: the module adds to the route's own sum", where, o.Do)
		}

		if o.Value == nil || *o.Value == 0 {
			return fmt.Errorf("%s: score needs a non-zero value", where)
		}
	}

	if controlVerb(o.Do) && (o.To == "" || o.To == "*") {
		return fmt.Errorf("%s: %s needs to: the module switches one call, not everyone", where, o.Do)
	}

	if err := checkPhaseAsk(o.Do, o.Phase, o.Axis()); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}

	// Корзина -- селектор note: у прочих глаголов ей нечего значить.
	if o.Counter != "" {
		if o.Do != protocol.DoNote {
			return fmt.Errorf("%s: counter is only for %q", where, protocol.DoNote)
		}

		if !nameRe.MatchString(o.Counter) {
			return fmt.Errorf("%s: bad counter name %q", where, o.Counter)
		}
	}

	// Группа и сторона -- только у mutate, и у mutate -- обе: "переключить"
	// без имени и стороны не просьба, а полуфраза.
	if o.Do == protocol.DoMutate {
		if o.Group == "" {
			return fmt.Errorf("%s: mutate needs a group", where)
		}

		if !nameRe.MatchString(o.Group) {
			return fmt.Errorf("%s: bad group name %q", where, o.Group)
		}

		if o.Set != "on" && o.Set != "off" {
			return fmt.Errorf("%s: mutate needs set: on or off, got %q", where, o.Set)
		}
	} else if o.Group != "" {
		return fmt.Errorf("%s: group is only for %q", where, protocol.DoMutate)
	}

	// Метка -- только у mark, и у mark она обязательна: "пометить" без метки
	// не просьба. Адресат -- запись маршрута, поэтому названный сосед здесь
	// та же битая форма, что у глаголов записи.
	if o.Do == protocol.DoMark {
		if o.To != "" && o.To != "*" {
			return fmt.Errorf("%s: %s takes no to: the module marks the route's own record", where, o.Do)
		}

		if err := protocol.CheckMarker(o.Marker); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
	} else if o.Marker != "" {
		return fmt.Errorf("%s: marker is only for %q", where, protocol.DoMark)
	}

	ttl, _ := parseTTL(o.TTL)

	// Глагол записи: адресат -- запись маршрута, поля to нет; сторона
	// обязательна; срок, предел и набор объектов -- только у archive с set on.
	if auditVerb(o.Do) {
		if o.To != "" && o.To != "*" {
			return fmt.Errorf("%s: %s takes no to: the module writes the route's own record", where, o.Do)
		}

		if o.Set != "on" && o.Set != "off" {
			return fmt.Errorf("%s: %s needs set: on or off, got %q", where, o.Do, o.Set)
		}

		if o.Set == "off" && (ttl != 0 || len(o.When) != 0 ||
			o.Headers != nil || o.Args != nil || o.Body != nil) {
			return fmt.Errorf("%s: ttl, when and objects are only for set on", where)
		}

		if o.Do == protocol.DoAudit && (ttl != 0 || len(o.When) != 0) {
			return fmt.Errorf("%s: ttl and when are only for archive", where)
		}

		// Исход: только два слова и каждое не дважды -- как на проводе.
		if _, err := protocol.CheckArchiveWhen(o.When); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}

		// У записи ответа строки запроса нет.
		if o.Apply == protocol.ApplyResponse && o.Args != nil {
			return fmt.Errorf("%s: args has no meaning for the response record", where)
		}

		for _, item := range []struct {
			name string
			spec *protocol.ObjectSpec
		}{{"headers", o.Headers}, {"args", o.Args}, {"body", o.Body}} {
			if err := protocol.CheckObjectSpec(item.name, item.spec, o.Do == protocol.DoAudit); err != nil {
				return fmt.Errorf("%s: %w", where, err)
			}
		}
	}

	if !auditVerb(o.Do) && (len(o.When) != 0 ||
		o.Headers != nil || o.Args != nil || o.Body != nil) {
		return fmt.Errorf("%s: when, headers, args and body are only for audit and archive", where)
	}

	if !auditVerb(o.Do) && o.Do != protocol.DoMutate && o.Set != "" {
		return fmt.Errorf("%s: set is only for mutate, audit and archive", where)
	}

	return nil
}

func hasString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}

	return false
}

/*
 * parseTTL -- человеческая запись срока ("1h", "15m"): секунды в файле,
 * который правят руками, читаются хуже, чем ошибаются.
 */
func parseTTL(raw string) (int, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return 0, nil
	}

	mult := 1

	switch {
	case strings.HasSuffix(raw, "s"):
		raw = strings.TrimSuffix(raw, "s")
	case strings.HasSuffix(raw, "m"):
		mult, raw = 60, strings.TrimSuffix(raw, "m")
	case strings.HasSuffix(raw, "h"):
		mult, raw = 3600, strings.TrimSuffix(raw, "h")
	case strings.HasSuffix(raw, "d"):
		mult, raw = 86400, strings.TrimSuffix(raw, "d")
	}

	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 0 {
		return 0, fmt.Errorf("bad ttl %q", raw)
	}

	return n * mult, nil
}

/* --- срабатывание ----------------------------------------------------------- */

/*
 * Ban -- запись в живой набор: кого (Write) и про какой адрес. Анонсы и
 * состав системы по адресу разворачивает обработчик у кодера, в бюджете
 * сообщения: этот пакет кодера не знает. Публикуется запись после решения --
 * этот запрос уже решён, а набор нужен следующим и соседним нодам.
 */
type Ban struct {
	Dataset string
	// Write -- кого писать: addr, net, net_all, asn.
	Write  string
	Addr   string
	TTL    int
	Reason string
}

// Fired -- что сделали инициаторы: просьбы уезжают в ответе рядом с вердиктом,
// записи публикуются после него, имена -- в запись аудита.
type Fired struct {
	Actions []protocol.Action
	Bans    []Ban
	Names   []string
}

/*
 * Fire -- инициаторы профиля по решению запроса.
 *
 * Наблюдения на уровне профиля у этого инспектора нет: пассивность -- свойство
 * маршрута, и метку на просьбы ставит модуль, а получатель решает по ней сам
 * (docs/inspector-actions.md, «Пассивного в prior нет»). Поэтому здесь тумблера
 * нет и быть не должно: два места, где выключается одно и то же, разъезжаются.
 */
func Fire(outcomes []Outcome, verdict string, score int, addr string,
	code string) Fired {

	var out Fired

	for _, o := range outcomes {
		if !o.Matches(verdict, score) {
			continue
		}

		if o.Asks() {
			out.Actions = append(out.Actions, ask(o, code))
			out.Names = append(out.Names, outcomeName(o))

			continue
		}

		/*
		 * Адреса нет -- писать некого: сообщение без conn.client_ip. Подсеть и
		 * систему по адресу развернёт обработчик.
		 */
		if addr == "" {
			continue
		}

		out.Bans = append(out.Bans, Ban{
			Dataset: o.List,
			Write:   o.Subject(),
			Addr:    addr,
			TTL:     o.Seconds(),
			Reason:  reasonOf(o, code),
		})

		out.Names = append(out.Names, outcomeName(o))
	}

	return out
}

func ask(o Outcome, code string) protocol.Action {
	out := protocol.Action{
		To:      o.To,
		Do:      o.Do,
		Apply:   o.Axis(),
		Phase:   o.Phase,
		Code:    reasonOf(o, code),
		Counter: o.Counter,
		Marker:  o.Marker,
		Group:   o.Group,
		Set:     o.Set,
		Headers: o.Headers,
		Args:    o.Args,
		Body:    o.Body,
	}

	// Срок архива -- только у archive с set on; ноль в YAML значит "как на
	// маршруте", поэтому на провод едет лишь названный.
	if o.Do == protocol.DoArchive && o.Set == "on" {
		// Исход просьбы: слова проверены на загрузке, здесь -- канонический
		// порядок, чтобы провод не зависел от порядка слов в файле.
		if len(o.When) > 0 {
			when, _ := protocol.CheckArchiveWhen(o.When)
			out.When = when
		}

		if n, _ := parseTTL(o.TTL); n > 0 {
			ttl := int64(n)
			out.TTL = &ttl
		}
	}

	if o.Delta != nil {
		out.Delta = *o.Delta
	}

	if o.Value != nil {
		out.Value = *o.Value
	}

	return out
}

// reasonOf -- повод: свой из строки либо код решения, по которому она сработала.
func reasonOf(o Outcome, code string) string {
	if o.Code != "" {
		return o.Code
	}

	return code
}

// outcomeName -- как строка называется в записи аудита: по действию, а не по
// порядковому номеру, -- номер поедет при первой правке таблицы.
func outcomeName(o Outcome) string {
	if o.Asks() {
		return o.Do
	}

	return o.List
}
