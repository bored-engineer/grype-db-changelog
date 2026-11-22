// Package providers loads providers.json, the manifest of each grype-db
// data provider's earliest known ghcr.io tag.
package providers

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// DateLayout is the Go reference layout for the "YY-MM-DD" form used
// throughout this project, matching the ghcr.io tags themselves.
const DateLayout = "06-01-02"

type manifest struct {
	Providers map[string]string `json:"providers"`
}

// Load reads and parses a providers.json manifest into provider -> start
// date.
func Load(path string) (map[string]time.Time, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("os.ReadFile failed: %w", err)
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("json.Unmarshal failed: %w", err)
	}
	out := make(map[string]time.Time, len(m.Providers))
	for name, start := range m.Providers {
		t, err := time.Parse(DateLayout, start)
		if err != nil {
			return nil, fmt.Errorf("time.Parse failed for provider %s: %w", name, err)
		}
		out[name] = t
	}
	return out, nil
}
