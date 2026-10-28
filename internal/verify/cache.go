package verify

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/mscno/esec-vault/internal/paths"
)

// The keys each repository's history used, kept until one of its refs
// changes: reading a large history is slow, and the daemon checks daily.

type historyCache map[string]historyEntry // by git common dir

type historyEntry struct {
	Stamp string       `json:"stamp"`
	Keys  []HistoryKey `json:"keys"`
}

func historyFile() string { return filepath.Join(paths.Home(), "verify-history.json") }

func readHistoryCache() historyCache {
	c := historyCache{}
	if data, err := os.ReadFile(historyFile()); err == nil {
		_ = json.Unmarshal(data, &c)
	}
	return c
}

func loadHistory(common, stamp string) ([]HistoryKey, bool) {
	e, ok := readHistoryCache()[common]
	if !ok || e.Stamp != stamp {
		return nil, false
	}
	return e.Keys, true
}

// saveHistory records a repository's keys. It is a cache: failing to
// write it only costs time.
func saveHistory(common, stamp string, keys []HistoryKey) {
	c := readHistoryCache()
	for dir := range c {
		if _, err := os.Stat(dir); err != nil {
			delete(c, dir) // the repository is gone
		}
	}
	c[common] = historyEntry{Stamp: stamp, Keys: keys}
	data, err := json.Marshal(c)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(paths.Home(), ".verify-history-*.tmp")
	if err != nil {
		return
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return
	}
	if tmp.Close() == nil {
		_ = os.Rename(tmp.Name(), historyFile())
	}
}
