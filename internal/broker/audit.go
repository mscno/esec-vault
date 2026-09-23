package broker

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// AuditEntry is one decision recorded in the audit log.
type AuditEntry struct {
	Time     time.Time `json:"ts"`
	UID      uint32    `json:"uid"`
	PID      uint32    `json:"pid"`
	Op       string    `json:"op"`
	Project  string    `json:"project,omitempty"`
	Env      string    `json:"env,omitempty"`
	Decision string    `json:"decision"`
	Detail   string    `json:"detail,omitempty"`
}

// AuditLogger appends JSON-lines audit entries to a file (0600).
type AuditLogger struct {
	mu   sync.Mutex
	path string
}

// NewAuditLogger opens (creating if needed) the audit log at path.
func NewAuditLogger(path string) (*AuditLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600) //nolint:gosec // path is constructed from trusted home dir
	if err != nil {
		return nil, err
	}
	return &AuditLogger{path: path}, f.Close()
}

// Log appends an entry. Audit failures are reported to the caller but must
// never silently drop a decision: callers should fail closed on error.
func (a *AuditLogger) Log(e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	e.Time = time.Now().UTC()
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(data, '\n'))
	return err
}
