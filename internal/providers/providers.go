// Package providers loads providers.json, the manifest of each grype-db
// data provider's known availability window on ghcr.io.
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

// Provider is one entry from providers.json.
type Provider struct {
	Start time.Time
	// End is nil for a provider still being published. Once set, it marks
	// a deliberately-confirmed removal (not just an outage): cmd/changelog
	// stops carrying the provider's last known data forward once a day
	// being built is after End, though a fresh ref always overrides this
	// regardless of End, in case the removal was recorded in error.
	End *time.Time
}

type rawEntry struct {
	Start string  `json:"start"`
	End   *string `json:"end,omitempty"`
}

type rawManifest struct {
	Providers map[string]rawEntry `json:"providers"`
}

// Load reads and parses a providers.json manifest.
func Load(path string) (map[string]Provider, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("os.ReadFile failed: %w", err)
	}
	var raw rawManifest
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("json.Unmarshal failed: %w", err)
	}
	out := make(map[string]Provider, len(raw.Providers))
	for name, entry := range raw.Providers {
		start, err := time.Parse(DateLayout, entry.Start)
		if err != nil {
			return nil, fmt.Errorf("time.Parse failed for provider %s start: %w", name, err)
		}
		p := Provider{Start: start}
		if entry.End != nil {
			end, err := time.Parse(DateLayout, *entry.End)
			if err != nil {
				return nil, fmt.Errorf("time.Parse failed for provider %s end: %w", name, err)
			}
			p.End = &end
		}
		out[name] = p
	}
	return out, nil
}
