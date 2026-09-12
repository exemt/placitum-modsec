/*
 * Фаза ответа: фазы 3-4 движка.
 *
 * Путей три, и они не равны. Основной -- продолжение: транзакция этого запроса
 * жива с фазы запроса, у неё настоящий контекст и настоящий входящий счёт, и
 * фазы 3-4 просто доигрываются (resume.go).
 *
 * Откат -- переигровка: состояния нет (экземпляр умер, реестр был полон, срок
 * истёк, маршрут его не просил), и фазы 1-2 прогоняются заново по контексту
 * запроса из сообщения -- ради инициализации CRS и ради правил, которые на
 * этот контекст смотрят. Тело запроса при этом не приезжает, поэтому ARGS_POST
 * и REQUEST_BODY у переигранной транзакции пусты, а входящий счёт пересчитан
 * без них. Это и есть цена отката, и она видна в аудите полем resumed.
 *
 * Отказ -- маршрут сказал resume=require: переигровка ему не годится (его
 * правила фазы ответа смотрят на тело запроса или на настоящий входящий счёт),
 * и потерянное состояние для него -- не деградация, а отсутствие проверки.
 * Тогда deny с MODSEC_RESUME_LOST и ошибка в логе: такое на работающем
 * контуре значит либо переполненный реестр, либо умерший экземпляр, либо
 * ответ приложения дольше WAF_MODSEC_RESUME_TTL.
 */

package main

import (
	"context"
	"time"

	"github.com/exemt/placitum-modsec/internal/audit"
	"github.com/exemt/placitum-modsec/internal/body"
	"github.com/exemt/placitum-modsec/internal/engine"
	"github.com/exemt/placitum-modsec/internal/prior"
	"github.com/exemt/placitum-modsec/internal/protocol"
	"github.com/exemt/placitum-modsec/internal/rules"
	"github.com/exemt/placitum-modsec/internal/verdict"
)

func (h *handler) inspectResponse(req *protocol.Request, budget time.Duration,
	personal bool) (*protocol.Reply, audit.Details) {

	/*
	 * Состояние забирается до всего остального: оно определяет, нужен ли набор
	 * правил вообще. У продолжения движок уже выбран -- тот, на котором шли
	 * фазы 1-2.
	 */
	live := h.resumeState(req)

	/*
	 * Просьбы соседей -- до resume=require: prior сквозной, и принятый на фазе
	 * запроса skip приезжает и сюда. Отказ из-за потерянного состояния на
	 * запросе, который решено не проверять, был бы отказом ни за что. Взятое
	 * состояние при skip закрывается -- продолжение не понадобится.
	 */
	ask := prior.Evaluate(req.Prior, h.registry.PriorRules(req.Route.Profile))

	if ask.Skip {
		if live != nil {
			live.Discard()
		}

		reply := protocol.NewReply(req, protocol.VerdictAllow)
		reply.Reason = &protocol.Reason{Code: codeSkipped}

		h.log.Info("skipped by a prior ask",
			"rid", req.RID,
			"phase", req.Phase,
			"uri", req.HTTP.URI,
			"client_ip", req.Conn.ClientIP,
			"profile", req.Route.Profile,
		)

		return reply, audit.Details{Engine: map[string]any{
			"phase":   protocol.PhaseResponse,
			"skip":    true,
			"actions": ask.Outcomes,
		}}
	}

	/*
	 * Состояния нет, а маршрут без него проверять отказался (resume=require):
	 * фазы 1-2 переигрывать запрещено, продолжать нечего -- проверки не будет.
	 * Отсюда error со своим поводом: чем это кончится для запроса, говорит
	 * waf_exception класса inspector, а не инспектор. В логе это error и на
	 * живом контуре так быть не должно: причину (реестр, срок, экземпляр)
	 * надо искать.
	 */
	if live == nil && req.Resume != nil && req.Resume.Require {
		h.log.Error("resume required but state is gone",
			"rid", req.RID,
			"inspector", req.Inspector,
			"uri", req.HTTP.URI,
			"personal", personal,
			"live", h.stickyLive(),
		)

		return protocol.ErrorReply(req, codeResumeLost), audit.Details{
			Findings: []audit.Finding{{
				Code:     "modsec-resume-lost",
				Severity: audit.SeverityCritical,
				Target:   audit.TargetURI,
			}},
			Engine: map[string]any{
				"phase":    protocol.PhaseResponse,
				"resumed":  false,
				"resume":   "lost",
				"personal": personal,
			},
		}
	}

	var (
		eng engine.Engine
		sel rules.Selection
	)

	if live == nil {
		/*
		 * Набор тот же, что у фазы запроса: одна транзакция на весь запрос,
		 * значит и одни правила. Профиль выбирается по тому же тегу маршрута --
		 * разойтись между фазами он не может, маршрут называет его один раз.
		 */
		eng, sel = h.registry.Select(req.Route.Profile)

	} else {
		sel = rules.Selection{Profile: req.Route.Profile}
	}

	// Профиля с таким именем нет, а продолжать нечего: проверки не будет, и
	// исход выбирает маршрут (см. handler.go).
	if live == nil && eng == nil {
		h.log.Warn("unknown response profile", "rid", req.RID, "profile", sel.Profile)

		return protocol.ErrorReply(req, codeUnknownProfile), audit.Details{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	/*
	 * Все объекты обменника, нужные этой фазе, одним походом: заголовки и тело
	 * ответа, а при переигрывании -- ещё заголовки и строка запроса. Порознь
	 * это были до четырёх последовательных round-trip внутри бюджета волны.
	 */
	locs := []*protocol.Locator{req.Store.Headers, req.Store.Body}

	if live == nil {
		locs = append(locs, req.RequestStore.Headers, req.RequestStore.Args)
	}

	got := h.loader.LoadMany(ctx, locs...)

	rspHdr := h.responseHeaders(req, got[0])
	rspBody := got[1]

	// Тело ответа не целиком -- проверки не будет: см. bodyError в handler.go.
	if code, why := bodyError(rspBody); code != "" {
		if live != nil {
			live.Discard()
		}

		h.log.Warn("response body not inspectable", "rid", req.RID, "body", why)

		return protocol.ErrorReply(req, code),
			audit.Details{Engine: map[string]any{"body": why}}
	}

	rsp := &engine.ResponseInput{
		Status:  responseStatus(req),
		Headers: pairs(rspHdr),
		Body:    rspBody.Data,
	}

	var (
		out *engine.Outcome
		err error
	)

	if live != nil {
		out, err = live.Resume(rsp)

	} else {
		/*
		 * Контекст запроса из обменника: объекты фазы запроса живут до конца фазы
		 * ответа ровно ради этого. Тела среди них нет -- см. шапку файла.
		 */
		reqHdr := h.headers(req, got[2])
		args := argsOf(got[3])

		out, err = engine.ApplyResponse(eng, input(req, args, reqHdr, body.Body{}), rsp)
	}

	if err != nil {
		// Движок не смог оценить: проверки не было. Прежний deny блокировал
		// ответ приложения за внутреннюю ошибку Coraza -- выбор не инспектора.
		h.log.Error("engine failed", "rid", req.RID, "phase", req.Phase,
			"error", err.Error())

		return protocol.ErrorReply(req, codeInternalError),
			audit.Details{Engine: map[string]any{"error": err.Error()}}
	}

	opts := h.opts
	opts.ScalePercent = ask.Percent

	reply := verdict.From(req, out, opts)
	det := verdict.Detail(out)

	applyAsk(det, ask, out)

	det.Engine["phase"] = protocol.PhaseResponse
	det.Engine["resumed"] = live != nil
	det.Engine["personal"] = personal

	if sel.Unknown {
		det.Engine["profile_requested"] = sel.Profile
	}

	/*
	 * Продолжения дальше не обещаем: транзакция закрыта фазой 5, а следующей
	 * фазы у транзакции HTTP нет. У кадров она будет своя.
	 */
	h.log.Info("verdict",
		"rid", req.RID,
		"inspector", req.Inspector,
		"phase", req.Phase,
		"wave", req.Wave,
		"status", responseStatus(req),
		"uri", req.HTTP.URI,
		"client_ip", req.Conn.ClientIP,
		"profile", sel.Profile,
		"verdict", reply.Verdict,
		"score", scoreOf(reply),
		"reason", codeOf(reply),
		"crs_anomaly_score", out.AnomalyScore,
		"engine_ms", out.EngineMS,
		"budget_ms", budget.Milliseconds(),
		"resumed", live != nil,
		"personal", personal,
	)

	return reply, det
}

/*
 * Заголовки ответа. Основной путь -- объект обменника: маршрут применил к нему
 * mask= и deny=, то есть set-cookie уже приведён к хешу. Инлайновый список из
 * секции response читается только когда объекта нет: модуль, приславший его
 * инлайном, списков не применял, и полагаться на этот путь нельзя.
 */
func (h *handler) responseHeaders(req *protocol.Request,
	loaded body.Body) []protocol.Header {

	if hdr := h.headers(req, loaded); len(hdr) > 0 {
		return hdr
	}

	if req.Response != nil {
		return req.Response.Headers
	}

	return nil
}

func responseStatus(req *protocol.Request) int {
	if req.Response == nil || req.Response.Status == 0 {
		// Ноль движку отдавать нельзя: правила сравнивают STATUS с диапазонами,
		// и "нет статуса" превратилось бы в "статус 0" -- совпадение, которого
		// в жизни не бывает.
		return 200
	}

	return req.Response.Status
}

func pairs(hdr []protocol.Header) [][2]string {
	out := make([][2]string, 0, len(hdr))

	for _, h := range hdr {
		out = append(out, [2]string{h.Name(), h.Value()})
	}

	return out
}
