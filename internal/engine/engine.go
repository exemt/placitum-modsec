package engine

type Intervention struct {
	Status     int
	Pause      int
	URL        string
	Log        string
	Disruptive bool
	Action     string
	RuleID     int
}

type MatchedRule struct {
	ID       int      `json:"id"`
	Phase    int      `json:"phase"`
	Severity string   `json:"severity"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"msg,omitempty"`
	Data     string   `json:"data,omitempty"`
	Target   string   `json:"target,omitempty"`
}

const TagMax = 128

func (r MatchedRule) Finding() bool { return r.Message != "" }

func (r MatchedRule) Tagged(tags []string) bool {
	for _, have := range r.Tags {
		for _, want := range tags {
			if have == want {
				return true
			}
		}
	}

	return false
}

type Transaction interface {
	ProcessConnection(clientIP string, clientPort int, serverIP string, serverPort int)
	ProcessURI(uri, method, httpVersion string)
	SetServerName(name string)
	AddRequestHeader(name, value string)
	ProcessRequestHeaders() *Intervention

	WriteRequestBody(b []byte) error
	ProcessRequestBody() (*Intervention, error)

	AddResponseHeader(name, value string)
	ProcessResponseHeaders(status int, proto string) *Intervention
	WriteResponseBody(b []byte) error
	ProcessResponseBody() (*Intervention, error)

	Matched() []MatchedRule

	Anomaly() (score, threshold int)

	AnomalyOutbound() (score, threshold int)

	ProcessLogging()
	Close() error
}

type Engine interface {
	NewTransaction(rid string) (Transaction, error)
	RuleCount() int
}
