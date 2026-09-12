/*
 * Перевод вмешательства движка и сработавших правил в вердикт протокола и в
 * находки аудита.
 *
 * Два правила канала, за которые отвечает именно этот пакет:
 *
 *   - status и url с провода не подставляются в ответ. У отказа едет только
 *     символьное имя записи каталога waf_deny_response по таблице status_map:
 *     наличие вмешательства не даёт инспектору права решать, какую страницу
 *     увидит клиент.
 *   - текст правила вместе с фрагментом совпавших данных в ответ не попадает
 *     вовсе. Модулю едет решение и код причины; чем оно объясняется, живёт в
 *     событии kind=inspector, где у подробностей есть форма и потребитель.
 */

package verdict

import (
	"fmt"
	"math"
	"strconv"
	"unicode/utf8"

	"github.com/exemt/placitum-modsec/internal/audit"
	"github.com/exemt/placitum-modsec/internal/engine"
	"github.com/exemt/placitum-modsec/internal/protocol"
)

// evidenceMax -- сколько байт улики уезжает в аудит. Цитата, а не содержимое:
// полный объект достаётся из обменника, а сюда попадает столько, сколько нужно,
// чтобы находку было видно в списке.
const evidenceMax = 256

// Коды причин. CRS_ANOMALY -- одно значение на все срабатывания скоринга:
// разложение категорий CRS по отдельным кодам остаётся открытым вопросом
// (см. README инспектора), а данные для его решения складываются в audit.
const (
	CodeAnomaly     = "CRS_ANOMALY"
	CodeRuleMatched = "CRS_RULE"
	CodeRedirect    = "CRS_REDIRECT"
)

// DefaultCRSThreshold используется, когда набор правил не выставил
// tx.inbound_anomaly_score_threshold: без знаменателя калибровка невозможна, а
// оставлять находку без счёта хуже, чем считать её по штатному порогу CRS.
const DefaultCRSThreshold = 5

// Decisive описывает находки, которые блокируют сами по себе, не глядя на счёт.
// Пустой набор -- рабочее значение по умолчанию: всё уходит в score, и порог
// применяет модуль. Наполняется он тогда, когда на маршруте есть класс правил,
// срабатывание которого не нуждается в подтверждении чужими вкладами.
type Decisive struct {
	Ranges [][2]int
	Tags   map[string]struct{}
}

func (d Decisive) match(r engine.MatchedRule) bool {
	for _, rng := range d.Ranges {
		if r.ID >= rng[0] && r.ID <= rng[1] {
			return true
		}
	}

	for _, tag := range r.Tags {
		if _, ok := d.Tags[tag]; ok {
			return true
		}
	}

	return false
}

func (d Decisive) empty() bool { return len(d.Ranges) == 0 && len(d.Tags) == 0 }

type Options struct {
	StatusMap *StatusMap
	Decisive  Decisive
	// ScalePercent -- коэффициент к отдаваемому счёту на этот запрос: сумма
	// принятых threshold-просьб соседей в процентах, уже срезанная потолками
	// правил профиля (internal/prior). Плюс -- поведение клиента дороже
	// (строже), минус -- скидка. Ни пороги CRS, ни waf_score_deny не
	// двигаются -- модуль видит обычный вердикт обычного инспектора, просто
	// вклад этого инспектора стоит иначе.
	ScalePercent int
}

// From строит ответ по итогам транзакции.
//
// Порядок ветвей повторяет таблицу из README инспектора: вмешательство движка,
// затем безусловная находка, затем счёт, затем allow.
func From(req *protocol.Request, out *engine.Outcome, opt Options) *protocol.Reply {
	reply := protocol.NewReply(req, protocol.VerdictAllow)

	if iv := out.Intervention; iv != nil && iv.Disruptive {
		return fromIntervention(reply, iv, out, opt)
	}

	/*
	 * Вмешательства нет -- либо движок работает в DetectionOnly (штатный
	 * режим), либо сработавшее правило не было disruptive. Во втором случае
	 * правило всё равно попадает в audit: "ничего не нашли" и "нашли, но не
	 * стали ничего делать" -- разные события.
	 */
	if _, ok := decisive(out.Matched, opt.Decisive); ok {
		reply.Verdict = protocol.VerdictDeny
		reply.Reason = &protocol.Reason{Code: CodeRuleMatched}
		reply.Response = &protocol.ResponseRef{Name: opt.statusName(0)}

		return reply
	}

	if out.AnomalyScore > 0 {
		score := ScaleScore(Calibrate(out.AnomalyScore, out.Threshold),
			opt.ScalePercent)

		if err := reply.WithScore(score); err != nil {
			// Недостижимо: Calibrate возвращает 0..100. Но ответ с негодным
			// счётом модуль отбраковывает целиком, поэтому лучше отдать allow с
			// причиной, чем молча выпасть из решения волны.
			reply.Verdict = protocol.VerdictAllow
			reply.Reason = &protocol.Reason{Code: "MODSEC_SCORE_RANGE"}

			return reply
		}

		reply.Reason = &protocol.Reason{Code: CodeAnomaly}

		return reply
	}

	return reply
}

func fromIntervention(reply *protocol.Reply, iv *engine.Intervention,
	out *engine.Outcome, opt Options) *protocol.Reply {

	switch iv.Action {
	case "redirect":
		/*
		 * Единственное место, где с провода едет адрес, а не имя: цель редиректа
		 * знает только тот, кто её назвал. Модуль сверит её с
		 * waf_redirect_allow маршрута, а ответ с непрошедшей целью отбракует
		 * целиком -- то есть отсутствие проверки здесь не создаёт открытого
		 * редиректа, а создаёт молчание инспектора.
		 */
		if iv.URL == "" {
			break
		}

		reply.Verdict = protocol.VerdictRedirect
		reply.Redirect = &protocol.RedirectRef{URL: iv.URL}
		reply.Reason = &protocol.Reason{Code: CodeRedirect}

		return reply

	// drop -- это deny: разрыва соединения в протоколе нет.
	case "deny", "block", "drop":
		reply.Verdict = protocol.VerdictDeny
		reply.Response = &protocol.ResponseRef{Name: opt.statusName(iv.Status)}
		reply.Reason = &protocol.Reason{Code: CodeRuleMatched}

		return reply
	}

	/*
	 * allow и всё незнакомое: запрос идёт дальше, а срабатывание остаётся в
	 * находках. "Ничего не нашли" и "нашли, но не стали ничего делать" -- разные
	 * события, и различаются они именно там.
	 */
	return reply
}

func (o Options) statusName(status int) string {
	m := o.StatusMap
	if m == nil {
		m = BuiltinStatusMap()
	}

	return m.Name(status)
}

/*
 * Калибровка счёта.
 *
 *     score = min(100, round(100 * crs_anomaly_score / crs_threshold / 2))
 *
 * Знаменатель с двойкой -- "двукратное превышение порога CRS = полная
 * уверенность инспектора". Аномальный счёт CRS не подставляется в score как
 * есть: он без верхней границы и измеряется относительно своего порога, а
 * score протокола -- калиброванная уверенность 0..100. Точная форма
 * уточняется на своём трафике в role=advisory, но преобразование обязано
 * существовать до первого мандатного запроса.
 */
/*
 * ScaleScore -- калиброванный счёт, умноженный на коэффициент просьб соседей:
 * множитель 1 + percent/100. Применяется к тому, что инспектор отдаёт, а не к
 * порогам: числа конфигурации не двигаются, меняется цена поведения клиента на
 * этом запросе. -100 даёт ноль -- «не считать вовсе», больше нуля из скидки не
 * сделать; верх прижат к 100, как любой score протокола.
 */
func ScaleScore(score, percent int) int {
	if percent == 0 || score <= 0 {
		return max(score, 0)
	}

	scaled := int(math.Round(float64(score) * (1 + float64(percent)/100)))

	if scaled < 0 {
		scaled = 0
	}

	return min(scaled, 100)
}

func Calibrate(anomaly, threshold int) int {
	if anomaly <= 0 {
		return 0
	}

	if threshold <= 0 {
		threshold = DefaultCRSThreshold
	}

	score := int(math.Round(100 * float64(anomaly) / float64(threshold) / 2))

	return min(score, 100)
}

func decisive(matched []engine.MatchedRule, d Decisive) (engine.MatchedRule, bool) {
	if d.empty() {
		return engine.MatchedRule{}, false
	}

	for _, r := range matched {
		if d.match(r) {
			return r, true
		}
	}

	return engine.MatchedRule{}, false
}

func ruleID(id int) string {
	if id == 0 {
		return ""
	}

	return strconv.Itoa(id)
}

/*
 * Detail собирает подробности для события kind=inspector: по одной находке на
 * сработавшее правило плюс сырые величины CRS.
 *
 * Величины остаются сырыми намеренно: по score протокола обратно к аномальному
 * счёту не вернуться, а именно он нужен, чтобы подобрать калибровку и порог по
 * реальному трафику.
 */
func Detail(out *engine.Outcome) audit.Details {
	engineData := map[string]any{
		"crs_anomaly_score": out.AnomalyScore,
		"crs_threshold":     out.Threshold,
	}

	if out.Threshold > 0 && out.AnomalyScore >= out.Threshold {
		// Что сделал бы CRS со своим порогом. Инспектор этого не делает
		// намеренно: порог -- дело модуля, а расхождение видно в аудите.
		engineData["crs_would_block"] = true
	}

	findings := make([]audit.Finding, 0, len(out.Matched))

	for _, r := range out.Matched {
		if r.Message == "" {
			// Служебные правила CRS (инициализация, маркеры) находкой не
			// являются: они ничего не нашли, они настраивают транзакцию.
			continue
		}

		findings = append(findings, finding(r))
	}

	return audit.Details{
		EngineMS: out.EngineMS,
		Findings: findings,
		Engine:   engineData,
	}
}

/*
 * Одна находка. Код -- "crs-<id>": пространство имён открыто, но код обязан
 * быть стабильным между версиями движка, потому что по нему строят исключения,
 * а идентификатор правила CRS ровно такой и есть.
 */
func finding(r engine.MatchedRule) audit.Finding {
	f := audit.Finding{
		Code:     "crs-" + ruleID(r.ID),
		Severity: severity(r.Severity),
		Target:   r.Target,
		Rule:     ruleID(r.ID),
		Evidence: clip(r.Data, evidenceMax),
	}

	/*
	 * Движок места не назвал -- значит, назвать его нечем. Правило требует
	 * target, и подставлять сюда правдоподобную догадку хуже, чем отдать
	 * находку с самым общим местом: путь есть у любого запроса.
	 */
	if f.Target == "" {
		f.Target = audit.TargetURI
	}

	return f
}

/*
 * Шкала SecLang в общую. Перевод, а не переименование: у SecLang восемь
 * уровней от emergency до debug, у общей шкалы пять, и смысл сохраняется в
 * порядке, а не в названиях.
 */
func severity(s string) string {
	switch s {
	case "emergency", "alert":
		return audit.SeverityCritical
	case "critical":
		return audit.SeverityHigh
	case "error", "warning":
		return audit.SeverityMedium
	case "notice":
		return audit.SeverityLow
	}

	return audit.SeverityInfo
}

// clip режет по границе UTF-8: обрубленная последовательность превращает запись
// аудита в нечитаемую для потребителя, который её валидирует.
func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}

	cut := max

	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}

	return s[:cut]
}

// ParseRanges разбирает список правил вида "920100-920999,942100" в диапазоны.
func ParseRanges(items []string) ([][2]int, error) {
	var out [][2]int

	for _, item := range items {
		lo, hi, ok := cutRange(item)
		if !ok {
			return nil, fmt.Errorf("invalid rule id or range: %q", item)
		}

		out = append(out, [2]int{lo, hi})
	}

	return out, nil
}

func cutRange(item string) (int, int, bool) {
	if lo, hi, found := cut(item, '-'); found {
		l, err1 := strconv.Atoi(lo)
		h, err2 := strconv.Atoi(hi)

		if err1 != nil || err2 != nil || l > h {
			return 0, 0, false
		}

		return l, h, true
	}

	v, err := strconv.Atoi(item)
	if err != nil {
		return 0, 0, false
	}

	return v, v, true
}

func cut(s string, sep byte) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}

	return s, "", false
}
