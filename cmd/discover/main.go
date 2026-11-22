// discover computes which (provider, date) pairs still need exporting:
// candidates are every date >= a provider's known start date that isn't
// already present as refs/raw/grype/<provider>/<date> on origin, confirmed
// to actually exist on ghcr.io (providers occasionally miss a day), checked
// oldest-date-first and capped so a single run never schedules more than
// one GitHub Actions matrix can hold (max 256 entries).
//
// Output is a JSON array like [{"provider":"alpine","date":"23-02-16"},...]
// for a workflow's `matrix: include: ${{ fromJson(...) }}`.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/bored-engineer/grype-db-changelog/internal/providers"
)

type candidate struct {
	Provider string `json:"provider"`
	Date     string `json:"date"`
}

const dateLayout = providers.DateLayout

// existingPairs lists every refs/raw/grype/<provider>/<date> ref already on
// origin, as a "<provider>/<date>" set.
func existingPairs() (map[string]bool, error) {
	cmd := exec.Command("git", "ls-remote", "origin", "refs/raw/grype/*")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-remote failed: %w", err)
	}
	existing := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		// refs/raw/grype/<provider>/<date>
		parts := strings.Split(fields[1], "/")
		if len(parts) != 5 {
			continue
		}
		existing[parts[3]+"/"+parts[4]] = true
	}
	return existing, nil
}

// exists checks whether ghcr.io actually has provider:date, via a HEAD-style
// check that never pulls the manifest body.
func exists(ctx context.Context, provider, date string) bool {
	ref, err := name.ParseReference(fmt.Sprintf("ghcr.io/anchore/grype-db/data/%s:%s", provider, date))
	if err != nil {
		return false
	}
	_, err = remote.Head(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	return err == nil
}

func main() {
	startFlag := flag.String("start", "", "earliest date to consider (YY-MM-DD, inclusive)")
	endFlag := flag.String("end", "", "latest date to consider (YY-MM-DD, inclusive; default: today)")
	maxFlag := flag.Int("max", 256, "maximum number of confirmed candidates to return")
	providersFlag := flag.String("providers", "providers.json", "path to the provider start-date manifest")
	concurrency := flag.Int("concurrency", 16, "concurrent ghcr.io existence checks")
	flag.Parse()

	if *startFlag == "" {
		log.Fatal("-start is required")
	}
	start, err := time.Parse(dateLayout, *startFlag)
	if err != nil {
		log.Fatalf("time.Parse(-start) failed: %v", err)
	}
	end := time.Now().UTC()
	if *endFlag != "" {
		end, err = time.Parse(dateLayout, *endFlag)
		if err != nil {
			log.Fatalf("time.Parse(-end) failed: %v", err)
		}
	}

	manifest, err := providers.Load(*providersFlag)
	if err != nil {
		log.Fatalf("providers.Load failed: %v", err)
	}
	names := make([]string, 0, len(manifest))
	for p := range manifest {
		names = append(names, p)
	}
	sort.Strings(names)

	existing, err := existingPairs()
	if err != nil {
		log.Fatalf("existingPairs failed: %v", err)
	}

	// Build the full candidate list (oldest date first, providers sorted
	// for determinism within a date) before confirming existence, so the
	// "stop once we have -max confirmed" check below is in a stable order.
	var pending []candidate
	for d := start; !d.After(end); d = d.AddDate(0, 0, 1) {
		date := d.Format(dateLayout)
		for _, p := range names {
			entry := manifest[p]
			if d.Before(entry.Start) {
				continue
			}
			if entry.End != nil && d.After(*entry.End) {
				// Confirmed-removed as of this date: don't go looking for
				// data we don't expect to find.
				continue
			}
			if existing[p+"/"+date] {
				continue
			}
			pending = append(pending, candidate{Provider: p, Date: date})
		}
	}

	ctx := context.Background()
	var confirmed []candidate
	const batchSize = 200
	for i := 0; i < len(pending) && len(confirmed) < *maxFlag; i += batchSize {
		batch := pending[i:min(i+batchSize, len(pending))]
		results := make([]bool, len(batch))

		sem := make(chan struct{}, *concurrency)
		var wg sync.WaitGroup
		for j, c := range batch {
			wg.Add(1)
			sem <- struct{}{}
			go func(j int, c candidate) {
				defer wg.Done()
				defer func() { <-sem }()
				results[j] = exists(ctx, c.Provider, c.Date)
			}(j, c)
		}
		wg.Wait()

		for j, ok := range results {
			if ok {
				confirmed = append(confirmed, batch[j])
				if len(confirmed) >= *maxFlag {
					break
				}
			}
		}
	}

	out, err := json.Marshal(confirmed)
	if err != nil {
		log.Fatalf("json.Marshal failed: %v", err)
	}
	fmt.Println(string(out))
	fmt.Fprintf(os.Stderr, "%d confirmed candidate(s) (of %d considered)\n", len(confirmed), len(pending))
}
