/*
 * Липкость: продолжение транзакции между фазами одного запроса.
 *
 * Смысл в одном: фазы 3-4 движка -- продолжение фаз 1-2. Правилам ответа нужны
 * REQUEST_HEADERS, ARGS, SERVER_NAME и входящий счёт той же транзакции, и взять
 * их неоткуда, кроме как из неё самой. Поэтому экземпляр, отработавший фазу
 * запроса, оставляет транзакцию открытой и называет модулю свой личный subject;
 * модуль публикует туда фазу ответа, и она доигрывается там же.
 *
 * Обещание всегда отзывается: экземпляр мог умереть, реестр -- переполниться,
 * срок -- истечь. Тогда сообщение приходит в групповой subject, состояния нет,
 * и фазы 1-2 переигрываются по контексту запроса (response.go). Разница видна в
 * аудите полем resumed.
 */

package main

import (
	"github.com/exemt/placitum-modsec/internal/audit"
	"github.com/exemt/placitum-modsec/internal/engine"
	"github.com/exemt/placitum-modsec/internal/protocol"
)

/*
 * Держать ли транзакцию открытой. Спрашивает об этом маршрут: resume= у
 * waf_inspect той фазы, которая продолжение потребляет, приезжает признаком
 * want в сообщении фазы запроса. Без него транзакция умерла бы по сроку, заняв
 * память на каждом запросе маршрута, которому липкость не нужна.
 */
func (h *handler) wantsResume(req *protocol.Request) bool {
	if h.sticky == nil || h.inbox == "" {
		return false
	}

	// Ключ обязателен: без него состояние некуда положить и нечем отозвать.
	return req.Phase == protocol.PhaseRequest &&
		req.Resume != nil && req.Resume.Want && req.Resume.Token != ""
}

/*
 * Обещать продолжение. Обещание и место в реестре -- одно действие: continue
 * без припаркованной транзакции отправил бы модуль в личный subject за
 * состоянием, которого нет, и стоил бы лишнего круга по шине.
 */
func (h *handler) offerContinue(req *protocol.Request, reply *protocol.Reply,
	det audit.Details, live *engine.Live) {

	/*
	 * Отказ и редирект фазу ответа отменяют: ответа приложения не будет вовсе,
	 * клиент получит страницу каталога. Продолжать нечего.
	 */
	if reply.Verdict == protocol.VerdictDeny || reply.Verdict == protocol.VerdictRedirect {
		live.Discard()

		return
	}

	/*
	 * Ключ -- тот, что назвал модуль. Своего инспектор не придумывает: свой
	 * существовал бы только в этом ответе, а ответ может не дойти -- волна
	 * замыкается на чужом отказе, -- и отозвать состояние стало бы нечем.
	 */
	if !h.sticky.Park(req.Resume.Token, live) {
		live.Discard()

		// Не молча: переполненный реестр означает, что липкость на этом
		// экземпляре перестала работать, и увидеть это надо по трафику, а не по
		// росту латентности фазы ответа.
		det.Engine["parked"] = false
		h.log.Warn("resume registry is full", "rid", req.RID,
			"max", h.cfg.ResumeMax, "live", h.sticky.Stats().Live)

		return
	}

	det.Engine["parked"] = true

	reply.Continue = &protocol.Continue{
		Subject: h.inbox,
		TTLMS:   h.sticky.TTL().Milliseconds(),
	}
}

/*
 * Бросить состояние: модуль сообщил, что продолжение не понадобится. Запрос
 * закончился, не дойдя до фазы, которая его потребляет, -- отказом раньше,
 * обходом фазы, обрывом клиента.
 *
 * Без этого сообщения транзакция дожила бы до своего срока, то есть держала бы
 * память на каждый такой запрос. Срок при этом остаётся: сообщение может не
 * доехать, и второй раз про этот rid никто не напомнит.
 */
func (h *handler) releaseState(req *protocol.Request) {
	if h.sticky == nil || req.Release == nil {
		return
	}

	h.sticky.Drop(req.Release.Token)

	h.log.Info("resume state released",
		"rid", req.RID,
		"inspector", req.Inspector,
		"phase", req.Phase,
		"reason", req.Release.Reason,
		"live", h.sticky.Stats().Live,
	)
}

// Сколько транзакций припарковано, для лога. Реестра может не быть вовсе
// (WAF_MODSEC_RESUME_MAX=0) -- тогда липкость выключена на этом экземпляре,
// и это само по себе ответ на вопрос, куда делось состояние.
func (h *handler) stickyLive() int {
	if h.sticky == nil {
		return -1
	}

	return h.sticky.Stats().Live
}

/*
 * Забрать состояние под фазу ответа. Ключ приезжает в сообщении вместе с
 * require: модуль шлёт их на любой маршрут с resume=, в какой бы subject
 * сообщение ни пришло. Нашлось -- продолжаем; нет -- что делать дальше,
 * решает require (response.go).
 */
func (h *handler) resumeState(req *protocol.Request) *engine.Live {
	if h.sticky == nil || req.Resume == nil || req.Resume.Token == "" {
		return nil
	}

	live, ok := h.sticky.Take(req.Resume.Token)
	if !ok {
		return nil
	}

	return live
}
