/*
 * Ветка фазы кадров: сообщение WebSocket от клиента как транзакция движка.
 *
 * У кадра нет ни метода, ни заголовков, ни строки запроса -- только байты и
 * контекст рукопожатия. CRS же написан для HTTP, и почти все его правила
 * смотрят в ARGS, а не в сырое REQUEST_BODY. Поэтому кадр подаётся движку
 * как POST на адрес рукопожатия с телом application/x-www-form-urlencoded из
 * одного аргумента: frame=<полезная нагрузка>. Разбор URLENCODED кладёт её в
 * ARGS_POST:frame, и правила 941/942/930 работают по ней как по любому полю
 * формы. Заголовки рукопожатия (Cookie, User-Agent, Origin) едут в ту же
 * транзакцию из request_store -- фазе 1 есть на что смотреть.
 *
 * Границы первой итерации:
 * - JSON внутри кадра не раскладывается по полям: строка целиком -- один
 *   аргумент. Сигнатуры по ней находятся, но именованных полей движок не
 *   видит; разбор JSON-процессором -- следующий шаг;
 * - транзакция на кадр, без состояния по соединению: подозрительность
 *   сессии не копится, каждый кадр судится сам;
 * - заголовки рукопожатия читаются из обменника на каждом кадре, кеша по
 *   conn_id нет;
 * - двоичные кадры пропускаются с кодом MODSEC_FRAME_BINARY; продолжения
 *   (continuation) судятся как текст, потому что опкод сообщения без
 *   состояния по соединению неизвестен.
 */

package main

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/exemt/placitum-modsec/internal/audit"
	"github.com/exemt/placitum-modsec/internal/body"
	"github.com/exemt/placitum-modsec/internal/engine"
	"github.com/exemt/placitum-modsec/internal/prior"
	"github.com/exemt/placitum-modsec/internal/protocol"
	"github.com/exemt/placitum-modsec/internal/verdict"
)

// frameArg -- имя аргумента, под которым полезная нагрузка кадра видна
// правилам: ARGS_POST:frame. Имя фиксированное, чтобы локальные правила
// профиля могли адресовать кадры отдельно от полей форм.
const frameArg = "frame"

// Двоичный кадр не инспектируется: CRS написан для текста, и произвольные
// байты (protobuf, msgpack, нулевые байты) набирают у него очки правилами о
// недопустимых символах, а не о содержимом. Пропуск -- с кодом, чтобы в
// аудите было видно, что кадр не судили, а не что он чист.
const codeFrameBinary = "MODSEC_FRAME_BINARY"

// Заголовки рукопожатия, которые в синтетическую транзакцию не переносятся:
// длину и тип тела задаёт кадр, а не запрос апгрейда.
var frameDropHeaders = map[string]struct{}{
	"content-type":      {},
	"content-length":    {},
	"transfer-encoding": {},
}

func (h *handler) inspectFrame(req *protocol.Request, budget time.Duration) (
	*protocol.Reply, audit.Details) {

	eng, sel := h.registry.Select(req.Route.Profile)

	// Профиля с таким именем нет: проверять кадр нечем, а чужим набором правил
	// подменять его не станем (см. handler.go).
	if eng == nil {
		h.log.Warn("unknown frame profile", "rid", req.RID, "profile", sel.Profile)

		return protocol.ErrorReply(req, codeUnknownProfile),
			audit.Details{Engine: frameEngine(req)}
	}

	if frameOpcode(req) == "binary" {
		reply := protocol.NewReply(req, protocol.VerdictAllow)
		reply.Reason = &protocol.Reason{Code: codeFrameBinary}

		det := audit.Details{Engine: frameEngine(req)}
		det.Engine["skip"] = "binary"

		return reply, det
	}

	ask := prior.Evaluate(req.Prior, h.registry.PriorRules(sel.Profile))

	if ask.Skip {
		reply := protocol.NewReply(req, protocol.VerdictAllow)
		reply.Reason = &protocol.Reason{Code: codeSkipped}

		det := audit.Details{Engine: frameEngine(req)}
		det.Engine["skip"] = true
		det.Engine["actions"] = ask.Outcomes

		return reply, det
	}

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	/*
	 * Два объекта одним походом: заголовки рукопожатия из request_store и
	 * полезная нагрузка кадра из store. Заголовков может не быть вовсе --
	 * маршрут их не снимал -- и тогда фаза 1 идёт по адресу и хосту.
	 */
	got := h.loader.LoadMany(ctx, req.RequestStore.Headers, req.Store.Body)

	hdr := h.headers(req, got[0])
	b := got[1]

	// Нагрузка не целиком -- проверки не будет: см. bodyError в handler.go.
	if code, why := bodyError(b); code != "" {
		h.log.Warn("frame payload not inspectable", "rid", req.RID, "body", why)

		det := audit.Details{Engine: frameEngine(req)}
		det.Engine["body"] = why

		return protocol.ErrorReply(req, code), det
	}

	out, err := engine.Apply(eng, frameInput(req, hdr, b))

	if err != nil {
		// Движок не смог оценить кадр: проверки не было, исход выбирает маршрут.
		h.log.Error("engine failed on a frame", "rid", req.RID, "error", err.Error())

		det := audit.Details{Engine: frameEngine(req)}
		det.Engine["error"] = err.Error()

		return protocol.ErrorReply(req, codeInternalError), det
	}

	opts := h.opts
	opts.ScalePercent = ask.Percent

	reply := verdict.From(req, out, opts)
	det := verdict.Detail(out)

	applyAsk(det, ask, out)

	for k, v := range frameEngine(req) {
		det.Engine[k] = v
	}

	if sel.Unknown {
		det.Engine["profile_requested"] = sel.Profile
	}

	/*
	 * Инициаторы по исходу работают и на кадрах: сессия, шлющая инъекции
	 * сообщением за сообщением, -- тот же субъект, что и клиент, шлющий их
	 * запросами, и записывать её в набор надо тем же правилом.
	 */
	fired := prior.Fire(h.registry.Outcomes(sel.Profile), reply.Verdict,
		scoreOf(reply), req.Conn.ClientIP, codeOf(reply))

	if len(fired.Names) != 0 {
		det.Engine["outcomes"] = fired.Names
	}

	// Кодер нужен и молчит -- тот же error, что на запросе: см. inspect.
	if err := h.publish(ctx, fired.Bans, req); err != nil {
		h.log.Error("geo unavailable for a list write", "rid", req.RID,
			"profile", sel.Profile, "error", err.Error())

		det.Engine["geo"] = err.Error()

		return protocol.ErrorReply(req, codeGeoUnavailable), det
	}

	if len(fired.Actions) != 0 {
		reply.Actions = fired.Actions
	}

	h.log.Info("verdict",
		"rid", req.RID,
		"inspector", req.Inspector,
		"phase", req.Phase,
		"conn", req.ConnID,
		"seq", req.Seq,
		"opcode", frameOpcode(req),
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
 * Кадр как вход движка: POST на адрес рукопожатия, заголовки рукопожатия без
 * тех, что описывают тело, и тело из одного аргумента формы. Метод POST, а не
 * GET рукопожатия: правило 920170 CRS считает тело у GET аномалией, и каждый
 * кадр набирал бы очки ни за что.
 */
func frameInput(req *protocol.Request, hdr []protocol.Header, b body.Body) *engine.Input {
	payload := frameArg + "=" + url.QueryEscape(string(b.Data))

	headers := make([][2]string, 0, len(hdr)+3)
	hasHost := false

	for _, h := range hdr {
		if _, drop := frameDropHeaders[strings.ToLower(h.Name())]; drop {
			continue
		}

		if strings.EqualFold(h.Name(), "host") {
			hasHost = true
		}

		headers = append(headers, [2]string{h.Name(), h.Value()})
	}

	/*
	 * Маршрут мог не снимать заголовки рукопожатия, и тогда транзакция без
	 * Host набирает у CRS критические пять очков правилом 920280 на каждом
	 * кадре -- ровно порог. Хост едет инлайном в секции http всегда.
	 */
	if !hasHost && req.HTTP.Host != "" {
		headers = append(headers, [2]string{"Host", req.HTTP.Host})
	}

	headers = append(headers,
		[2]string{"Content-Type", "application/x-www-form-urlencoded"},
		[2]string{"Content-Length", strconv.Itoa(len(payload))},
	)

	version := req.HTTP.Version
	if version == "" {
		version = "HTTP/1.1"
	}

	return &engine.Input{
		RID:        req.RID,
		ClientIP:   req.Conn.ClientIP,
		ClientPort: req.Conn.ClientPort,
		ServerIP:   req.Conn.ServerIP,
		ServerPort: req.Conn.ServerPort,
		Method:     "POST",
		URI:        req.HTTP.URI,
		Args:       "",
		Version:    version,
		Host:       req.HTTP.Host,
		Headers:    headers,
		Body:       []byte(payload),
	}
}

// frameEngine -- что из кадрирования уезжает в событие аудита: без этого
// находка на кадре неотличима от находки на запросе с тем же адресом.
func frameEngine(req *protocol.Request) map[string]any {
	e := map[string]any{
		"phase":  protocol.PhaseFrame,
		"conn":   req.ConnID,
		"seq":    req.Seq,
		"opcode": frameOpcode(req),
	}

	if req.Stream != nil {
		e["direction"] = req.Stream.Direction
		e["fin"] = req.Stream.Fin

		if req.Stream.Subprotocol != "" {
			e["subprotocol"] = req.Stream.Subprotocol
		}
	}

	return e
}

func frameOpcode(req *protocol.Request) string {
	if req.Stream == nil || req.Stream.Opcode == "" {
		return "unknown"
	}

	return req.Stream.Opcode
}
