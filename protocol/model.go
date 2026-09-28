package protocol

const (
	ObservationSchemaVersion = "probing.observation/v1"
	BatchSchemaVersion       = "probing.batch/v1"
	AdapterProtocolVersion   = "probing.adapter/v1"
)

type ObservationKind string

const (
	ObservationSSHAuthFailure ObservationKind = "ssh_auth_failure"
	ObservationHTTPRequest    ObservationKind = "http_request"
)

type Observation struct {
	SchemaVersion string           `json:"schema_version"`
	EventID       string           `json:"event_id"`
	Cursor        string           `json:"cursor"`
	Kind          ObservationKind  `json:"kind"`
	ObservedAt    string           `json:"observed_at"`
	SourceIP      string           `json:"source_ip"`
	SSH           *SSHObservation  `json:"ssh,omitempty"`
	HTTP          *HTTPObservation `json:"http,omitempty"`
}

type SSHObservation struct {
	Username string `json:"username"`
	// Password is the plaintext credential the source attempted, when the
	// upstream honeypot captures it (e.g. Cowrie). It is omitted for sources
	// that never expose the attempted secret, such as the OpenSSH journal.
	Password string `json:"password,omitempty"`
}

type HTTPObservation struct {
	RequestTarget string `json:"request_target"`
	Status        int    `json:"status"`
}

type SignedBatch struct {
	Payload   BatchPayload `json:"payload"`
	Signature Signature    `json:"signature"`
}

type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

type BatchPayload struct {
	SchemaVersion     string        `json:"schema_version"`
	SourceID          string        `json:"source_id"`
	SourceEpoch       string        `json:"source_epoch"`
	Sequence          string        `json:"sequence"`
	PreviousBatchHash string        `json:"previous_batch_hash,omitempty"`
	CreatedAt         string        `json:"created_at"`
	ObservationWindow TimeRange     `json:"observation_window"`
	ClassifierVersion string        `json:"classifier_version"`
	Records           []BatchRecord `json:"records"`
}

type TimeRange struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type BatchRecord struct {
	Kind            ObservationKind `json:"kind"`
	SourceIP        string          `json:"source_ip"`
	Username        string          `json:"username,omitempty"`
	Password        string          `json:"password,omitempty"`
	Path            string          `json:"path,omitempty"`
	Count           uint64          `json:"count"`
	FirstObservedAt string          `json:"first_observed_at"`
	LastObservedAt  string          `json:"last_observed_at"`
	HourlyBuckets   []HourlyBucket  `json:"hourly_buckets"`
	RuleIDs         []string        `json:"rule_ids"`
}

type HourlyBucket struct {
	Hour  string `json:"hour"`
	Count uint64 `json:"count"`
}
