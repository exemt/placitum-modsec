package main

import (
	"context"
	"crypto/rand"
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

const storeTTL = time.Minute

type probe struct {
	servers, subject, name, redisURL, profile string
	uri, method, userAgent, clientIP, expect  string
	timeout                                   time.Duration
	quiet                                     bool

	phase        string
	status       int
	responseBody string

	auditSubject string
}

func main() {
	var p probe

	flag.StringVar(&p.servers, "servers", env("NATS_URL", "nats://127.0.0.1:4222"), "bus addresses, comma-separated")
	flag.StringVar(&p.subject, "subject", env("WAF_MODSEC_SUBJECT", "waf.req.modsec"), "inspector subject")
	flag.StringVar(&p.name, "inspector", env("WAF_MODSEC_NAME", "modsec"), "inspector name in the message")
	flag.StringVar(&p.redisURL, "redis", env("REDIS_URL", ""), "exchange for headers, query string and response body")
	flag.StringVar(&p.profile, "profile", "default", "route.profile value")
	flag.StringVar(&p.uri, "uri", "/healthcheck", "request path, optionally with a query string")
	flag.StringVar(&p.method, "method", "GET", "request method")
	flag.StringVar(&p.userAgent, "user-agent", "modsec-probe", "User-Agent header")
	flag.StringVar(&p.clientIP, "client-ip", "127.0.0.1", "conn.client_ip: the network and system are resolved from it")
	flag.StringVar(&p.expect, "expect", "", "expected verdict: allow, score, redirect, deny")
	flag.DurationVar(&p.timeout, "timeout", time.Second, "how long to wait for the answer and the event")
	flag.BoolVar(&p.quiet, "quiet", false, "print nothing, only set the exit code")
	flag.StringVar(&p.phase, "phase", protocol.PhaseRequest, "message phase: request or response")
	flag.IntVar(&p.status, "status", 200, "application response status for the response phase")
	flag.StringVar(&p.responseBody, "response-body", "", "application response body for the response phase")
	flag.StringVar(&p.auditSubject, "audit-subject", "",
		"where the inspector publishes the kind=inspector event; empty means nowhere")

	flag.Parse()

	if err := run(p); err != nil {
		fmt.Fprintln(os.Stderr, "probe:", err)
		os.Exit(1)
	}
}

func run(p probe) error {
	if p.phase != protocol.PhaseRequest && p.phase != protocol.PhaseResponse {
		return fmt.Errorf("phase must be request or response, got %q", p.phase)
	}

	nc, err := nats.Connect(p.servers, nats.Timeout(p.timeout), nats.NoReconnect())
	if err != nil {
		return err
	}

	defer nc.Close()

	var events *nats.Subscription

	if p.auditSubject != "" {
		if events, err = nc.SubscribeSync(p.auditSubject); err != nil {
			return err
		}
	}

	req := request(p)

	if err := place(req, p); err != nil {
		return err
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}

	msg, err := nc.Request(p.subject, payload, p.timeout)
	if err != nil {
		return fmt.Errorf("no verdict from %s: %w", p.subject, err)
	}

	var reply protocol.Reply

	if err := json.Unmarshal(msg.Data, &reply); err != nil {
		return fmt.Errorf("malformed reply: %w", err)
	}

	if !p.quiet {
		out, _ := json.Marshal(reply)
		fmt.Println(string(out))
	}

	if events != nil {
		ev, err := events.NextMsg(p.timeout)
		if err != nil {
			return fmt.Errorf("no audit event on %s: %w", p.auditSubject, err)
		}

		if !p.quiet {
			fmt.Println(string(ev.Data))
		}
	}

	if p.expect != "" && reply.Verdict != p.expect {
		return fmt.Errorf("verdict is %q, expected %q", reply.Verdict, p.expect)
	}

	return nil
}

func request(p probe) *protocol.Request {
	path, args, _ := strings.Cut(p.uri, "?")

	req := &protocol.Request{
		V:          protocol.Version,
		RID:        fmt.Sprintf("%016x", time.Now().UnixNano()),
		Phase:      p.phase,
		Inspector:  p.name,
		DeadlineMS: int(p.timeout.Milliseconds()),
		Node:       "probe",
		Conn: protocol.Conn{
			ClientIP:   p.clientIP,
			ClientPort: 12345,
			ServerIP:   "127.0.0.1",
			ServerPort: 8080,
		},
		HTTP: protocol.HTTP{
			Method:   p.method,
			Scheme:   "http",
			Host:     "probe.local",
			URI:      path,
			ArgsSize: int64(len(args)),
			Version:  "HTTP/1.1",
		},
		Needs: []string{protocol.NeedHeaders, protocol.NeedArgs},
		Route: protocol.Route{ServerName: "probe.local", Location: "/", Profile: p.profile},
		Score: protocol.ScoreState{DenyAt: 100},
	}

	if p.phase == protocol.PhaseResponse {
		req.Needs = []string{protocol.NeedHeaders, protocol.NeedBody}
		req.Response = &protocol.Response{Status: p.status}
	}

	if p.auditSubject != "" {
		req.Ray = uuid4()
		req.AuditSubject = &p.auditSubject
	}

	return req
}

func place(req *protocol.Request, p probe) error {
	_, args, _ := strings.Cut(p.uri, "?")

	if p.redisURL == "" {
		req.Needs = nil
		return nil
	}

	store, err := body.NewRedisStore(p.redisURL, p.timeout)
	if err != nil {
		return err
	}

	defer store.Close()

	ctx := context.Background()
	base := "probe:" + req.RID

	put := func(key string, data []byte) (*protocol.Locator, error) {
		if err := store.Put(ctx, base+key, data, storeTTL); err != nil {
			return nil, err
		}

		return &protocol.Locator{
			Store:    "probe",
			Driver:   "redis",
			Key:      base + key,
			Size:     int64(len(data)),
			Complete: true,
		}, nil
	}

	headers, err := json.Marshal([]protocol.Header{
		{"host", "probe.local"},
		{"user-agent", p.userAgent},
		{"accept", "*/*"},
	})
	if err != nil {
		return err
	}

	target := &req.Store
	if p.phase == protocol.PhaseResponse {
		target = &req.RequestStore
	}

	if target.Headers, err = put(":req:hdr", headers); err != nil {
		return err
	}

	if args != "" {
		if target.Args, err = put(":req:arg", []byte(args)); err != nil {
			return err
		}
	}

	if p.phase != protocol.PhaseResponse {
		return nil
	}

	rspHeaders, err := json.Marshal([]protocol.Header{
		{"content-type", "text/html; charset=utf-8"},
	})
	if err != nil {
		return err
	}

	if req.Store.Headers, err = put(":rsp:hdr", rspHeaders); err != nil {
		return err
	}

	req.Store.Body, err = put(":rsp:body", []byte(p.responseBody))

	return err
}

func uuid4() string {
	var b [16]byte

	_, _ = rand.Read(b[:])

	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}

	return def
}
