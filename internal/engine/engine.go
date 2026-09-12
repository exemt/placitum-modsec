/*
 * Интерфейс движка правил, не зависящий от того, Coraza за ним или
 * libmodsecurity.
 *
 * Пакет не решает, блокировать ли запрос. Он исполняет фазы и возвращает то,
 * что вернул движок, включая список сработавших правил для audit; перевод
 * вмешательства в вердикт протокола -- обязанность internal/verdict.
 */

package engine

// Intervention -- вмешательство движка. Пять полей одинаковы по смыслу у обоих
// кандидатов: у libmodsecurity это ModSecurityIntervention, у Coraza --
// types.Interruption плюс режим движка.
type Intervention struct {
	Status     int
	Pause      int
	URL        string
	Log        string
	Disruptive bool
	// Action движка: deny, block, drop, redirect, allow. Именно по нему
	// internal/verdict выбирает строку таблицы соответствия.
	Action string
	RuleID int
}

// MatchedRule -- сработавшее правило в виде, достаточном для audit и для
// решения о безусловном отказе, но без ссылок на типы конкретного движка.
type MatchedRule struct {
	ID       int      `json:"id"`
	Phase    int      `json:"phase"`
	Severity string   `json:"severity"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"msg,omitempty"`
	// Data -- фрагмент совпавших данных, то есть кусок пользовательского
	// ввода. Ответу модулю он не достаётся никогда: место находки и её улика
	// живут в событии kind=inspector, см. internal/verdict.
	Data string `json:"data,omitempty"`
	// Target -- где сработало, в терминах общей формы находки: uri, args, body,
	// header:<имя>, cookie:<имя>. Пусто, когда движок места не назвал. Ровно
	// это нужно логеру, чтобы подсветить место в запросе, и взять его больше
	// неоткуда: модуль содержимого не разбирает.
	Target string `json:"target,omitempty"`
}

// Transaction -- состояние одного сообщения инспекции. Создаётся и уничтожается
// в его пределах, между сообщениями не переживает ничего: контракт инспектора
// требует stateless-обработки, см. docs/inspectors.md#контракт.
//
// Методы идут в порядке фаз и повторяют таблицу из README этого пакета.
type Transaction interface {
	ProcessConnection(clientIP string, clientPort int, serverIP string, serverPort int)
	ProcessURI(uri, method, httpVersion string)
	SetServerName(name string)
	AddRequestHeader(name, value string)
	ProcessRequestHeaders() *Intervention

	WriteRequestBody(b []byte) error
	ProcessRequestBody() (*Intervention, error)

	// Фазы 3-4. Вызываются на сообщении фазы ответа, поверх восстановленного
	// контекста запроса: одно сообщение -- одна транзакция, и здесь она просто
	// доигрывается дальше, чем на фазе запроса.
	AddResponseHeader(name, value string)
	ProcessResponseHeaders(status int, proto string) *Intervention
	WriteResponseBody(b []byte) error
	ProcessResponseBody() (*Intervention, error)

	// Matched возвращает всё, что сработало за транзакцию, независимо от того,
	// было ли вмешательство.
	Matched() []MatchedRule

	// Anomaly отдаёт аномальный счёт CRS и действующий порог. Обе величины --
	// сырые числа шкалы CRS: приводит их к score протокола internal/verdict, а
	// в audit они попадают как есть.
	Anomaly() (score, threshold int)

	// AnomalyOutbound -- то же для исходящей стороны, правила RESPONSE-*.
	// Отдельным методом, а не флагом: на фазе ответа счёт входящей стороны
	// тоже существует (он посеян из prior), и складывать их в одно число
	// значило бы отдать модулю сумму, которую он уже один раз применил.
	AnomalyOutbound() (score, threshold int)

	ProcessLogging()
	Close() error
}

// Engine -- собранный и проверенный набор правил. Потокобезопасен на чтение:
// воркеры создают транзакции параллельно. Загрузка в уже используемый набор не
// делается никогда, обновление -- только атомарной подменой указателя в
// internal/rules.
type Engine interface {
	NewTransaction(rid string) (Transaction, error)
	RuleCount() int
}
