package ingest

const (
	RegistrySchemaVersion   = "probing.registry/v1"
	LedgerSchemaVersion     = "probing.acceptance-ledger/v1"
	RollupSchemaVersion     = "probing.rollup/v1"
	QuarantineSchemaVersion = "probing.quarantine/v1"
	PublicLabel             = "self-reported suspected probes"
)

type Registry struct {
	SchemaVersion string               `json:"schema_version"`
	Repository    string               `json:"repository"`
	Sources       []SourceRegistration `json:"sources"`
}

type SourceRegistration struct {
	SourceID    string `json:"source_id"`
	SourceEpoch string `json:"source_epoch"`
	KeyID       string `json:"key_id"`
	PublicKey   string `json:"public_key"`
	BlobPrefix  string `json:"blob_prefix"`
	Enabled     bool   `json:"enabled"`
}

type Ledger struct {
	SchemaVersion string                  `json:"schema_version"`
	Repository    string                  `json:"repository"`
	UpdatedAt     string                  `json:"updated_at,omitempty"`
	Sources       []LedgerSource          `json:"sources"`
	Periods       map[string]PeriodLedger `json:"periods"`
}

type LedgerSource struct {
	SourceID     string        `json:"source_id"`
	SourceEpoch  string        `json:"source_epoch"`
	NextSequence string        `json:"next_sequence"`
	PreviousHash string        `json:"previous_hash"`
	Batches      []LedgerBatch `json:"batches"`
}

type LedgerBatch struct {
	Sequence    string `json:"sequence"`
	PayloadHash string `json:"payload_hash"`
	BlobName    string `json:"blob_name"`
}

type PeriodLedger struct {
	Total     uint64            `json:"total"`
	Sources   map[string]uint64 `json:"sources"`
	SourceIPs map[string]uint64 `json:"source_ips"`
	Usernames map[string]uint64 `json:"usernames"`
	Paths     map[string]uint64 `json:"paths"`
}

type RollupFile struct {
	SchemaVersion string         `json:"schema_version"`
	Label         string         `json:"label"`
	Granularity   string         `json:"granularity"`
	UpdatedAt     string         `json:"updated_at,omitempty"`
	Periods       []RollupPeriod `json:"periods"`
}

type RollupPeriod struct {
	Start     string        `json:"start"`
	End       string        `json:"end"`
	Total     uint64        `json:"total"`
	Sources   []SourceTotal `json:"sources"`
	SourceIPs []ValueTotal  `json:"source_ips"`
	Usernames []ValueTotal  `json:"usernames"`
	Paths     []ValueTotal  `json:"paths"`
}

type SourceTotal struct {
	SourceID    string `json:"source_id"`
	SourceEpoch string `json:"source_epoch"`
	Count       uint64 `json:"count"`
}

type ValueTotal struct {
	Value string `json:"value"`
	Count uint64 `json:"count"`
}

type Quarantine struct {
	SchemaVersion string            `json:"schema_version"`
	UpdatedAt     string            `json:"updated_at"`
	Entries       []QuarantineEntry `json:"entries"`
}

type QuarantineEntry struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Reason string `json:"reason"`
}

type Result struct {
	Accepted    int
	Replayed    int
	Quarantined int
	DeleteBlobs []string
}
