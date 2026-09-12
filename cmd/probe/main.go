/*
 * Проба: публикует сообщение инспекции на subject и ждёт вердикт.
 *
 * Проба идёт тем же путём, что и реальный запрос от модуля, и в этом её смысл
 * как healthcheck: если она вернула вердикт, значит живы и соединение с шиной,
 * и подписка, и набор правил, и пул воркеров. TCP-пинг до NATS не сказал бы ни
 * про одно из этого.
 *
 * Содержимое запроса идёт тем же путём тоже: заголовки и строка запроса
 * кладутся в обменник, а в сообщение едут локаторы. Без REDIS_URL проба
 * ограничивается путём и методом -- этого хватает, чтобы проверить живость, но
 * не хватает, чтобы поймать правило CRS по строке запроса.
 *
 *     modsec-probe --uri /healthcheck
 *     modsec-probe --uri '/?id=1%27+or+1%3D1' --expect score
 */

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-modsec/internal/body"
	"github.com/exemt/placitum-modsec/internal/protocol"
)

// storeTTL -- страховка от того, что проба положила и не убрала. Ключи пробы
// живут ровно столько, сколько может длиться её инспекция.
const storeTTL = time.Minute

func main() {
	var (
		servers   = flag.String("servers", env("NATS_URL", "nats://127.0.0.1:4222"), "адреса шины через запятую")
		subject   = flag.String("subject", env("WAF_MODSEC_SUBJECT", "waf.req.modsec"), "subject инспектора")
		name      = flag.String("inspector", env("WAF_MODSEC_NAME", "modsec"), "имя инспектора в сообщении")
		redisURL  = flag.String("redis", env("REDIS_URL", ""), "обменник для заголовков и строки запроса")
		profile   = flag.String("profile", "default", "значение route.profile")
		uri       = flag.String("uri", "/healthcheck", "путь запроса, можно со строкой запроса")
		method    = flag.String("method", "GET", "метод запроса")
		userAgent = flag.String("user-agent", "modsec-probe", "заголовок User-Agent")
		clientIP  = flag.String("client-ip", "127.0.0.1", "conn.client_ip: им резолвятся подсеть и система")
		expect    = flag.String("expect", "", "ожидаемый вердикт: allow, score, redirect, deny")
		timeout   = flag.Duration("timeout", time.Second, "сколько ждать ответа")
		quiet     = flag.Bool("quiet", false, "не печатать ответ, только код возврата")
	)

	flag.Parse()

	if err := run(*servers, *subject, *name, *redisURL, *profile, *uri, *method,
		*userAgent, *clientIP, *expect, *timeout, *quiet); err != nil {

		fmt.Fprintln(os.Stderr, "probe:", err)
		os.Exit(1)
	}
}

func run(servers, subject, name, redisURL, profile, uri, method, userAgent, clientIP,
	expect string, timeout time.Duration, quiet bool) error {

	nc, err := nats.Connect(servers, nats.Timeout(timeout), nats.NoReconnect())
	if err != nil {
		return err
	}

	defer nc.Close()

	req := request(name, profile, uri, method, clientIP, timeout)

	if err := place(req, redisURL, uri, userAgent, timeout); err != nil {
		return err
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}

	msg, err := nc.Request(subject, payload, timeout)
	if err != nil {
		return fmt.Errorf("no verdict from %s: %w", subject, err)
	}

	var reply protocol.Reply

	if err := json.Unmarshal(msg.Data, &reply); err != nil {
		return fmt.Errorf("malformed reply: %w", err)
	}

	if !quiet {
		out, _ := json.Marshal(reply)
		fmt.Println(string(out))
	}

	if expect != "" && reply.Verdict != expect {
		return fmt.Errorf("verdict is %q, expected %q", reply.Verdict, expect)
	}

	return nil
}

func request(name, profile, uri, method, clientIP string,
	timeout time.Duration) *protocol.Request {
	path, args, _ := strings.Cut(uri, "?")

	return &protocol.Request{
		V:          protocol.Version,
		RID:        fmt.Sprintf("%016x", time.Now().UnixNano()),
		Phase:      protocol.PhaseRequest,
		Inspector:  name,
		DeadlineMS: int(timeout.Milliseconds()),
		Node:       "probe",
		Conn: protocol.Conn{
			ClientIP:   clientIP,
			ClientPort: 12345,
			ServerIP:   "127.0.0.1",
			ServerPort: 8080,
		},
		HTTP: protocol.HTTP{
			Method:   method,
			Scheme:   "http",
			Host:     "probe.local",
			URI:      path,
			ArgsSize: int64(len(args)),
			Version:  "HTTP/1.1",
		},
		// Тела у пробы нет: healthcheck не должен зависеть от того, читает ли
		// маршрут тело.
		Needs: []string{protocol.NeedHeaders, protocol.NeedArgs},
		Route: protocol.Route{ServerName: "probe.local", Location: "/", Profile: profile},
		Score: protocol.ScoreState{DenyAt: 100},
	}
}

/*
 * Складывает то, что в контуре складывает модуль, и заполняет локаторы. Без
 * обменника локаторы остаются пустыми, и needs честно пустеет вслед за ними:
 * заявка, которой нечем ответить, ввела бы инспектора в заблуждение.
 */
func place(req *protocol.Request, redisURL, uri, userAgent string,
	timeout time.Duration) error {

	_, args, _ := strings.Cut(uri, "?")

	if redisURL == "" {
		req.Needs = nil
		return nil
	}

	store, err := body.NewRedisStore(redisURL, timeout)
	if err != nil {
		return err
	}

	defer store.Close()

	ctx := context.Background()

	headers, err := json.Marshal([]protocol.Header{
		{"host", "probe.local"},
		{"user-agent", userAgent},
		{"accept", "*/*"},
	})
	if err != nil {
		return err
	}

	base := "probe:" + req.RID + ":req"

	if err := store.Put(ctx, base+":hdr", headers, storeTTL); err != nil {
		return err
	}

	req.Store.Headers = &protocol.Locator{
		Store:  "probe",
		Driver: "redis",
		Key:    base + ":hdr",
		Size:   int64(len(headers)),
	}

	if args == "" {
		return nil
	}

	if err := store.Put(ctx, base+":arg", []byte(args), storeTTL); err != nil {
		return err
	}

	req.Store.Args = &protocol.Locator{
		Store:  "probe",
		Driver: "redis",
		Key:    base + ":arg",
		Size:   int64(len(args)),
	}

	return nil
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}

	return def
}
