/*
 * Конвейер одного сообщения: разбор -> очередь -> бюджет -> профиль -> обменник ->
 * движок -> вердикт -> ответ.
 *
 * Каждый шаг делегирован своему пакету; здесь только порядок и то, что ответ
 * уходит на каждом пути, включая панику внутри обработки. Молчание неотличимо
 * от перегрузки, см. docs/inspectors.md#контракт.
 *
 * Ответ несёт решение и код причины. Сработавшие правила, аномальный счёт CRS и
 * время движка уезжают отдельным событием kind=inspector, уже после ответа:
 * подробностями дедлайн волны двигать нельзя.
 */

package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-modsec/internal/audit"
	"github.com/exemt/placitum-modsec/internal/body"
	"github.com/exemt/placitum-modsec/internal/config"
	"github.com/exemt/placitum-modsec/internal/engine"
	"github.com/exemt/placitum-modsec/internal/prior"
	"github.com/exemt/placitum-modsec/internal/protocol"
	"github.com/exemt/placitum-modsec/internal/queue"
	"github.com/exemt/placitum-modsec/internal/rules"
	"github.com/exemt/placitum-modsec/internal/sticky"
	"github.com/exemt/placitum-modsec/internal/verdict"
	"github.com/exemt/placitum-shared/dataset"
	"github.com/exemt/placitum-shared/netinfo"
)

// Коды причин инспектора. Все начинаются с MODSEC_, чтобы в аудите их было
// видно отдельно от кодов набора правил.
const (
	codeUnsupportedVersion = "MODSEC_UNSUPPORTED_VERSION"
	codeMalformed          = "MODSEC_MALFORMED_REQUEST"
	codeInternalError      = "MODSEC_INTERNAL_ERROR"
	codeUnknownProfile     = "MODSEC_UNKNOWN_PROFILE"
	codeWrongPhase         = "MODSEC_PHASE_NOT_SUPPORTED"
	codeBodyUnavailable    = "MODSEC_BODY_UNAVAILABLE"
	// В обменнике лежит префикс тела (waf_body_limit ... trim, срез снимка).
	// Движку нужно тело целиком: префикс структурированного тела документом
	// быть перестаёт, и проверка содержимого не состоится.
	codeBodyTruncated = "MODSEC_BODY_TRUNCATED"
	// Маршрут требовал продолжить транзакцию (resume=require), а состояния
	// под ключом нет. Отказ -- решение маршрута: он предпочёл не пропускать,
	// чем проверять на переигранной транзакции без тела запроса.
	codeResumeLost = "MODSEC_RESUME_LOST"
	// Сосед попросил не проверять этот запрос, и в профиле маршрута есть
	// правило, принимающее skip от него. Решение оператора, а не соседа:
	// без правила просьба не значит ничего.
	codeSkipped = "MODSEC_SKIPPED"
	// Инициатор пишет в набор подсеть или систему (write: net | net_all |
	// asn), а кодер гео молчит: записи не будет, и молча пропускать её нельзя
	// -- решает waf_exception маршрута. Вердикт движка остаётся в аудите.
	codeGeoUnavailable = "MODSEC_GEO_UNAVAILABLE"
)

type handler struct {
	cfg      *config.Config
	log      *slog.Logger
	nc       *nats.Conn
	audit    *audit.Sink
	registry *rules.Registry
	loader   *body.Loader
	opts     verdict.Options
	pool     *queue.Pool

	// Личный subject экземпляра и реестр припаркованных транзакций. Пустой
	// subject означает, что липкость выключена: продолжение не обещается.
	inbox  string
	sticky *sticky.Registry[*engine.Live]

	// lists -- публикатор активных наборов: им пишут инициаторы по исходу.
	lists *dataset.Publisher
	// resolver -- кодер гео: анонсы и состав системы, когда инициатор пишет
	// не адрес (net, net_all, asn). nil -- кодера нет: такие строки отвечают
	// error, адрес пишется как всегда.
	resolver *netinfo.Resolver
}

/*
 * receive исполняется в потоке приёма и обязан быть дешёвым: разбор нужен,
 * потому что без deadline_ms не проверить бюджет, а всё остальное уходит в пул
 * воркеров.
 */
func (h *handler) receive(msg *nats.Msg) {
	defer h.recoverInto(msg.Reply, "")

	req, err := protocol.Parse(msg.Data)
	if err != nil {
		rid := ""

		var pe *protocol.ParseError
		if errors.As(err, &pe) {
			rid = pe.RID
		}

		h.log.Warn("message rejected", "error", err.Error(), "bytes", len(msg.Data))
		h.send(msg.Reply, protocol.FallbackReply(rid, h.cfg.Name, codeMalformed), nil,
			audit.Details{})

		return
	}

	/*
	 * Незнакомая версия схемы -- error: разъезд модуля и инспектора означает,
	 * что правил никто не применял. Прежний deny блокировал за ошибку
	 * развёртывания, allow пропускал бы непроверенное -- решает маршрут.
	 */
	if !h.cfg.Supports(req.V) {
		reply := protocol.ErrorReply(req, codeUnsupportedVersion)
		reply.V = protocol.Version
		h.send(msg.Reply, reply, req, audit.Details{})

		return
	}

	/*
	 * Освобождение обрабатывается здесь же, в потоке приёма, и дальше не идёт:
	 * работы в нём нет -- только освободить память, -- а очередь воркеров ждёт
	 * бюджета, которого у этого сообщения не бывает. Ответа оно не получает:
	 * слот в модуле закрыт до того, как оно отправлено.
	 */
	if req.Release != nil {
		h.releaseState(req)

		return
	}

	/*
	 * Обе стороны транзакции HTTP обслуживает один набор правил, поэтому
	 * отдельного условия у фазы ответа нет: умеет инспектор фазы 1-2 -- умеет и
	 * 3-4. Кадры не обслуживаются вовсе.
	 *
	 * Сообщение не своей фазы -- расхождение конфигурации, и ответ на него
	 * deny: allow открывал бы маршрут, на котором инспектор не смотрит.
	 */
	if !h.supports(req.Phase) {
		h.send(msg.Reply, protocol.ErrorReply(req, codeWrongPhase), req,
			audit.Details{})

		return
	}

	h.pool.Submit(&queue.Task{
		Req:      req,
		Reply:    msg.Reply,
		Personal: h.inbox != "" && msg.Subject == h.inbox,
	})
}

// evaluate исполняется воркером. shed непустой означает, что оценка не
// начиналась: очередь была полна либо бюджет уже вышел.
func (h *handler) evaluate(t *queue.Task, budget time.Duration, shed string) {
	defer h.recoverInto(t.Reply, t.Req.RID)

	if shed != "" {
		/*
		 * Правила не применялись -- ни по очереди, ни по бюджету. Прежняя пара
		 * «очередь -> allow, бюджет -> deny» была догадкой о том, что важнее на
		 * этом маршруте; теперь это говорит waf_exception … inspector.
		 */
		reply := protocol.ShedReply(t.Req, shed)

		det := audit.Details{Engine: map[string]any{
			"shed":      shed,
			"budget_ms": float64(budget.Microseconds()) / 1000,
		}}

		/*
		 * Инициаторы on: overload -- только на снятии из-за полной очереди и,
		 * как у остальных триггеров, только на фазе запроса. Протухший бюджет
		 * их не дёргает: дедлайн бывает и у короткой волны, а запись клиента в
		 * набор за латентность контура была бы баном ни за что. Ответ этого
		 * пути мгновенный, поэтому просьбы в нём доезжают до модуля; записи и
		 * без него уехали бы -- их публикует сам инспектор.
		 */
		var fired prior.Fired
		if shed == queue.ReasonQueueLimit && t.Req.Phase == protocol.PhaseRequest {
			fired = prior.Fire(h.registry.Outcomes(t.Req.Route.Profile),
				prior.OnOverload, 0, t.Req.Conn.ClientIP, shed)

			if len(fired.Actions) != 0 {
				reply.Actions = fired.Actions
			}

			// Ответ этого пути и так error: молчащий кодер его хуже не сделает,
			// но несостоявшаяся запись обязана быть видна. Бюджета у снятого
			// запроса нет -- кодер ограничен своим таймаутом.
			if err := h.publish(context.Background(), fired.Bans, t.Req); err != nil {
				h.log.Error("geo unavailable for a list write", "rid", t.Req.RID,
					"profile", t.Req.Route.Profile, "error", err.Error())

				det.Engine["geo"] = err.Error()
			}

			if len(fired.Names) != 0 {
				det.Engine["outcomes"] = fired.Names
			}
		}

		h.log.Warn("shed", "rid", t.Req.RID, "reason", shed,
			"budget_ms", budget.Milliseconds(),
			"asks", len(fired.Actions), "lists", len(fired.Bans))
		h.send(t.Reply, reply, t.Req, det)

		return
	}

	reply, det := h.inspect(t, budget)
	h.send(t.Reply, reply, t.Req, det)
}

func (h *handler) supports(phase string) bool {
	switch phase {
	case protocol.PhaseRequest:
		return true

	case protocol.PhaseResponse:
		return true

	case protocol.PhaseFrame:
		return true

	default:
		return false
	}
}

func (h *handler) inspect(t *queue.Task, budget time.Duration) (*protocol.Reply,
	audit.Details) {

	req := t.Req

	if req.Phase == protocol.PhaseResponse {
		return h.inspectResponse(req, budget, t.Personal)
	}

	if req.Phase == protocol.PhaseFrame {
		return h.inspectFrame(req, budget)
	}

	eng, sel := h.registry.Select(req.Route.Profile)

	/*
	 * Профиля с таким именем среди загруженных нет. Ни отказа за чужую ошибку
	 * развёртывания, ни отката на default: чужой набор правил -- это проверка
	 * не того, и выдавать её за проверку маршрута нельзя. Проверки не было, и
	 * распорядиться этим должен маршрут -- waf_exception класса inspector.
	 */
	if eng == nil {
		h.log.Warn("unknown profile", "rid", req.RID, "profile", sel.Profile)

		return protocol.ErrorReply(req, codeUnknownProfile), audit.Details{}
	}

	/*
	 * Просьбы соседей из prior -- против правил приёма профиля: threshold --
	 * коэффициент к счёту, который уедет модулю (пороги не двигаются), skip
	 * снимает проверку целиком. Исход каждой просьбы уезжает в kind=inspector.
	 */
	ask := prior.Evaluate(req.Prior, h.registry.PriorRules(sel.Profile))

	if ask.Skip {
		/*
		 * До обменника и движка: «не проверять» означает не проверять. Транзакция
		 * не паркуется, и продолжения фаза ответа не получит -- но и не
		 * спросит: сквозной prior привезёт ту же просьбу и туда.
		 */
		reply := protocol.NewReply(req, protocol.VerdictAllow)
		reply.Reason = &protocol.Reason{Code: codeSkipped}

		h.log.Info("skipped by a prior ask",
			"rid", req.RID,
			"uri", req.HTTP.URI,
			"client_ip", req.Conn.ClientIP,
			"profile", sel.Profile,
		)

		return reply, audit.Details{Engine: map[string]any{
			"skip":    true,
			"actions": ask.Outcomes,
		}}
	}

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	/*
	 * Три объекта обменника одним походом. Порознь это были три последовательных
	 * round-trip внутри бюджета волны -- на каждом запросе, а не только на
	 * подозрительном.
	 */
	got := h.loader.LoadMany(ctx, req.Store.Headers, req.Store.Args, req.Store.Body)

	hdr := h.headers(req, got[0])
	args := argsOf(got[1])
	b := got[2]

	if code, why := bodyError(b); code != "" {
		h.log.Warn("body not inspectable", "rid", req.RID, "body", why)

		return protocol.ErrorReply(req, code),
			audit.Details{Engine: map[string]any{"body": why}}
	}

	/*
	 * Липкость: маршрут объявил resume= у инспектора более поздней фазы, и
	 * транзакция остаётся открытой -- фазы 3-4 доиграются поверх её состояния,
	 * а не поверх переигранного. Обещание даётся только вместе с местом в
	 * реестре: continue без припаркованной транзакции отправил бы модуль в
	 * личный subject за состоянием, которого нет.
	 */
	keep := h.wantsResume(req)

	var (
		out  *engine.Outcome
		live *engine.Live
		err  error
	)

	if keep {
		out, live, err = engine.ApplyKeep(eng, input(req, args, hdr, b))
	} else {
		out, err = engine.Apply(eng, input(req, args, hdr, b))
	}

	if err != nil {
		if live != nil {
			live.Discard()
		}

		/*
		 * Движок не смог оценить: проверки не было. Прежний deny блокировал
		 * трафик за внутреннюю ошибку Coraza, прежний allow выключал бы CRS
		 * на ней же -- обе половины выбирали за маршрут.
		 */
		h.log.Error("engine failed", "rid", req.RID, "error", err.Error())

		return protocol.ErrorReply(req, codeInternalError),
			audit.Details{Engine: map[string]any{"error": err.Error()}}
	}

	opts := h.opts
	opts.ScalePercent = ask.Percent

	reply := verdict.From(req, out, opts)
	det := verdict.Detail(out)

	applyAsk(det, ask, out)

	if sel.Unknown {
		det.Engine["profile_requested"] = sel.Profile
	}

	/*
	 * Инициаторы по исходу: просьбы уезжают этим же ответом, записи в наборы --
	 * после него. Судят они тот счёт, который уходит модулю: коэффициент
	 * соседа уже в нём.
	 */
	fired := prior.Fire(h.registry.Outcomes(sel.Profile), reply.Verdict,
		scoreOf(reply), req.Conn.ClientIP, codeOf(reply))

	if len(fired.Names) != 0 {
		det.Engine["outcomes"] = fired.Names
	}

	/*
	 * Строка требует кодер, а кодер молчит: запись в набор не состоялась.
	 * Молча пропустить нельзя -- бан, которого не было, выглядит как бан, --
	 * поэтому error, и что делать с запросом, решает waf_exception; решение
	 * движка остаётся в записи аудита. Припаркованная транзакция снимается:
	 * продолжения без обещания не будет.
	 */
	if err := h.publish(ctx, fired.Bans, req); err != nil {
		if live != nil {
			live.Discard()
		}

		h.log.Error("geo unavailable for a list write", "rid", req.RID,
			"profile", sel.Profile, "error", err.Error())

		det.Engine["geo"] = err.Error()

		return protocol.ErrorReply(req, codeGeoUnavailable), det
	}

	if len(fired.Actions) != 0 {
		reply.Actions = fired.Actions
	}

	if live != nil {
		h.offerContinue(req, reply, det, live)
	}

	h.log.Info("verdict",
		"rid", req.RID,
		"inspector", req.Inspector,
		"wave", req.Wave,
		"method", req.HTTP.Method,
		"uri", req.HTTP.URI,
		"client_ip", req.Conn.ClientIP,
		"profile", sel.Profile,
		"verdict", reply.Verdict,
		"score", scoreOf(reply),
		"reason", codeOf(reply),
		"crs_anomaly_score", out.AnomalyScore,
		"asks", len(fired.Actions),
		"lists", len(fired.Bans),
		"engine_ms", out.EngineMS,
		"budget_ms", budget.Milliseconds(),
	)

	return reply, det
}

/*
 * Заголовки из обменника. Объект лежит там JSON-массивом пар: порядок получения
 * значим, а дубликаты имён (Set-Cookie, Forwarded) в объекте потерялись бы.
 *
 * Недоступность здесь молчаливая: движок отработает по тому, что есть. Отказ
 * обменника -- дело модуля, и он о нём уже знает.
 */
func (h *handler) headers(req *protocol.Request, loaded body.Body) []protocol.Header {
	if !loaded.Available() || len(loaded.Data) == 0 {
		return nil
	}

	var pairs []protocol.Header
	if err := json.Unmarshal(loaded.Data, &pairs); err != nil {
		h.log.Warn("headers blob is not an array of pairs",
			"rid", req.RID, "error", err.Error())
		return nil
	}

	return pairs
}

/*
 * Строка запроса из обменника, сырой, как пришла. Движку она нужна целиком: ARGS
 * он наполняет сам, разбирая её, -- и разбирает по своим правилам, а не по
 * чужим.
 */
func argsOf(loaded body.Body) string {
	if !loaded.Available() {
		return ""
	}

	return string(loaded.Data)
}

func input(req *protocol.Request, args string, hdr []protocol.Header,
	b body.Body) *engine.Input {

	headers := make([][2]string, 0, len(hdr))

	for _, h := range hdr {
		headers = append(headers, [2]string{h.Name(), h.Value()})
	}

	return &engine.Input{
		RID:        req.RID,
		ClientIP:   req.Conn.ClientIP,
		ClientPort: req.Conn.ClientPort,
		ServerIP:   req.Conn.ServerIP,
		ServerPort: req.Conn.ServerPort,
		Method:     req.HTTP.Method,
		URI:        req.HTTP.URI,
		Args:       args,
		Version:    req.HTTP.Version,
		Host:       req.HTTP.Host,
		Headers:    headers,
		Body:       b.Data,
	}
}

/*
 * Тело не целиком -- проверки не будет. Движку нужен весь объект: правила по
 * содержимому молчат без тела, а префикс структурированного тела документом
 * быть перестаёт, и allow означал бы "проверил, чисто". Чья это недоступность
 * -- маршрута (причина приехала в локаторе) или наша (обменник не ответил, не
 * расшифровалось, не сошёлся хеш) -- для вердикта не важно: проверки не было
 * в обоих случаях. Исход выбирает waf_exception класса inspector; причина
 * остаётся в коде ответа и в записи аудита (engine.body).
 */
func bodyError(b body.Body) (code, why string) {
	switch {
	case !b.Available():
		return codeBodyUnavailable, "unavailable:" + b.Unavailable
	case b.Truncated:
		return codeBodyTruncated, "truncated"
	}

	return "", ""
}

func (h *handler) send(subject string, reply *protocol.Reply, req *protocol.Request,
	det audit.Details) {

	if subject == "" {
		h.log.Error("no reply subject in message", "rid", reply.RID)
		return
	}

	payload, err := reply.Marshal()
	if err != nil {
		// Ответ, который нельзя сериализовать, всё равно должен уйти: иначе
		// волна ждёт до дедлайна впустую.
		h.log.Error("reply marshal failed", "rid", reply.RID, "error", err.Error())

		payload, err = protocol.FallbackReply(reply.RID, reply.Inspector,
			codeInternalError).Marshal()
		if err != nil {
			return
		}
	}

	if err := h.nc.Publish(subject, payload); err != nil {
		h.log.Error("respond failed", "rid", reply.RID, "error", err.Error())
	}

	/*
	 * Аудит после inbox: волна уже получила ответ. Обычный PUB на subject из
	 * сообщения, без JS API. Ошибка сюда не возвращается.
	 */
	if err := h.audit.Add(req, reply, det); err != nil {
		h.log.Warn("audit publish failed", "rid", reply.RID, "error", err.Error())
	}
}

/*
 * Паника внутри обработки одного сообщения обязана быть перехвачена и
 * превращена в allow с машинным кодом причины, а не в падение процесса.
 */
func (h *handler) recoverInto(subject, rid string) {
	r := recover()
	if r == nil {
		return
	}

	h.log.Error("handler panicked", "rid", rid, "panic", r, "stack", string(debug.Stack()))

	if subject != "" {
		h.send(subject, protocol.FallbackReply(rid, h.cfg.Name, codeInternalError), nil,
			audit.Details{})
	}
}

/*
 * applyAsk дописывает в событие kind=inspector исходы просьб соседей и тройку
 * чисел коэффициента: сырой счёт, процент, эффективный. Без неё собственные
 * вердикты не объяснить: в записи виден score, а во сколько раз он подорожал
 * или подешевел по чужой просьбе, взялось бы ниоткуда.
 */
func applyAsk(det audit.Details, ask prior.Ask, out *engine.Outcome) {
	if len(ask.Outcomes) != 0 {
		det.Engine["actions"] = ask.Outcomes
	}

	if ask.Percent != 0 {
		raw := verdict.Calibrate(out.AnomalyScore, out.Threshold)

		det.Engine["score_scale_percent"] = ask.Percent
		det.Engine["score_raw"] = raw
		det.Engine["score_scaled"] = verdict.ScaleScore(raw, ask.Percent)
	}
}

func scoreOf(r *protocol.Reply) int {
	if r.Score == nil {
		return 0
	}

	return *r.Score
}

func codeOf(r *protocol.Reply) string {
	if r.Reason == nil {
		return ""
	}

	return r.Reason.Code
}

/*
 * publish -- записи инициаторов в активные наборы, см. lists.go: адрес как
 * есть, анонсы и состав системы -- у кодера, в бюджете сообщения; кодер
 * спрашивается только строкой, которой он нужен. Отказ keeper не отменяет
 * ничего: этот запрос уже решён. Ошибка -- кодер нужен и молчит.
 */
func (h *handler) publish(ctx context.Context, bans []prior.Ban, req *protocol.Request) error {
	if len(bans) == 0 || h.lists == nil {
		return nil
	}

	return writeLists(ctx, h.resolver, h.lists, h.log, req.RID, bans)
}
