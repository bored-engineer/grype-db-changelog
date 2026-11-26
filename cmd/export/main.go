package main

import (
	"archive/tar"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
)

// stdout receives the fast-import stream (a variable for tests).
var stdout io.Writer = os.Stdout

// sanitize turns a vunnel record identifier into a safe relative file path.
// Identifiers already use "/" to group related records (Alpine's
// "edge/CVE-...", NVD's "2026/CVE-..."), which makes a fine directory
// structure as-is. Some providers (KEV's "kev:CVE-...", Debian's
// "debian:10/CVE-...") prefix the identifier with the provider's own name
// followed by ":" — strip that exact prefix rather than blindly replacing
// ":" with "-", since the provider name is already the parent directory and
// an exact-prefix strip can't collide the way a generic substitution could.
func sanitize(provider, id string) string {
	if rest, ok := strings.CutPrefix(id, provider+":"); ok {
		id = rest
	}
	return strings.ReplaceAll(id, ":", "-")
}

// canonicalize recursively sorts every array of objects by their own
// canonical (key-sorted) JSON encoding, so that semantically-identical but
// differently-ordered upstream data serializes identically across export
// runs. Confirmed necessary empirically: an Amazon Linux ALAS record's
// FixedIn list came back with the same six packages in a different order
// between two otherwise-unrelated days
// (https://github.com/bored-engineer/grype-db-changelog/commit/6b981675ad5d04e338cbc1d3d953f46d04efb086),
// most likely from vunnel/grype-db building that list from an unordered
// Python set/dict internally. Plain scalar arrays (strings, numbers) are
// left untouched: no reordering was observed there, and their order may be
// meaningful (e.g. NVD's reference/description lists, independently
// verified as already stable across runs).
//
// Object arrays under an orderedKeys key are left in upstream order too:
// their order is part of their meaning.
//
// json.Number values (see decodeJSON) become number, which keeps the
// upstream text of each number through to the YAML.
func canonicalize(v any) any {
	return canonicalizeIn("", v)
}

// orderedKeys name object arrays whose order is meaningful. OSV's
// affected[].ranges[].events is a sequence: each "introduced" pairs with
// the "fixed" (or "last_affected"/"limit") that follows it, so sorting
// [introduced 0, fixed 1.18.6, introduced 1.19.0-0, fixed 1.19.1] into
// [fixed, fixed, introduced, introduced] loses which range is which
// (govulndb's GO-2022-0969, for one).
var orderedKeys = map[string]bool{
	"events": true,
}

func canonicalizeIn(key string, v any) any {
	switch v := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, val := range v {
			out[k] = canonicalizeIn(k, val)
		}
		return out
	case []any:
		type keyed struct {
			val any
			key string
		}
		out := make([]keyed, len(v))
		allObjects := len(v) > 0
		for i, val := range v {
			// Elements inherit no key: an array nested directly in an
			// ordered one isn't itself known to be ordered.
			c := canonicalizeIn("", val)
			_, isObject := c.(map[string]any)
			allObjects = allObjects && isObject
			b, err := json.Marshal(c)
			if err != nil {
				// Unreachable: c was just decoded from JSON.
				panic(err)
			}
			out[i] = keyed{val: c, key: string(b)}
		}
		if allObjects && !orderedKeys[key] {
			sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
		}
		result := make([]any, len(out))
		for i, k := range out {
			result[i] = k.val
		}
		return result
	case json.Number:
		return number(v)
	default:
		return v
	}
}

// number is a JSON number kept as its original text. Decoded as float64
// instead, 10.0 would be written as 10, and integers past 2^53 would lose
// precision.
type number string

// MarshalJSON writes the number as-is (canonicalize's sort key).
func (n number) MarshalJSON() ([]byte, error) { return []byte(n), nil }

// MarshalYAML writes the number as a plain YAML int or float, not as the
// quoted string yaml.v3 would make of a string type. The encoder drops the
// tag whenever the text already resolves to it.
func (n number) MarshalYAML() (any, error) {
	tag := "!!int"
	if strings.ContainsAny(string(n), ".eE") {
		tag = "!!float"
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: string(n)}, nil
}

// decodeJSON is json.Unmarshal, but with numbers as json.Number.
func decodeJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return fmt.Errorf("unexpected data after the JSON value")
	}
	return nil
}

// envelope mirrors vunnel's Envelope type (schema/identifier/item).
// identifier is dropped: it's redundant with the file path (modulo
// sanitize(), which is why it strips exactly the provider-name prefix
// rather than guessing). schema is kept, as a comment on the file's first
// line (see schemaComment): it isn't uniform within a build - bitnami's
// mixes OSV 1.5.0 and 1.6.2, for records vunnel hasn't rewritten since a
// schema bump - and it's what grype-db parses each record by.
type envelope struct {
	Schema any `json:"schema"`
	Item   any `json:"item"`
}

// vunnelSchemaBase is stripped from schema URLs in the comment: every
// schema vunnel has published lives under it, and the rest of the URL
// (e.g. "vulnerability/osv/schema-1.6.2.json") is what tells them apart.
// Any other URL is written in full.
const vunnelSchemaBase = "https://raw.githubusercontent.com/anchore/vunnel/main/schema/"

// schemaComment returns the "# schema: ..." line for an envelope's
// schema, or "" if it has none.
func schemaComment(schema any) string {
	var s string
	switch v := schema.(type) {
	case nil:
		return ""
	case string:
		s = strings.TrimPrefix(v, vunnelSchemaBase)
	default:
		// Not a URL string (no vunnel version writes one); keep whatever
		// it is, as JSON.
		b, err := json.Marshal(v)
		if err != nil {
			// Unreachable: v was just decoded from JSON.
			panic(err)
		}
		s = string(b)
	}
	if s == "" {
		return ""
	}
	if strings.ContainsAny(s, "\r\n") {
		s = strconv.Quote(s) // a newline would end the comment
	}
	return "# schema: " + s + "\n"
}

// emit writes the fast-import filemodify command for one vunnel record's
// item, re-encoding its JSON as YAML for better diffs. Unlike trivy-db,
// vunnel's records are already plain JSON, so no decoding/enum-resolving
// step is needed here.
//
// seen tracks every path this export run has already written, case-folded,
// so two distinct ids that only differ by case (or that collide after
// sanitize()'s substitutions) are caught here as a hard error instead of
// silently overwriting each other on a case-insensitive filesystem at
// checkout time — the failure mode trivy-db-changelog hit.
func emit(seen map[string]string, provider string, id string, record []byte) error {
	var env envelope
	if err := decodeJSON(record, &env); err != nil {
		return fmt.Errorf("json.Unmarshal failed for %s: %w", id, err)
	}
	if provider == "hummingbird" {
		dropGeneratedDates(env.Item)
	}
	pretty, err := yaml.Marshal(canonicalize(env.Item))
	if err != nil {
		return fmt.Errorf("yaml.Marshal failed for %s: %w", id, err)
	}
	pretty = append([]byte(schemaComment(env.Schema)), pretty...)
	// No "providers/" wrapper directory: the provider name is already the
	// top-level category here, the same role trivy-db-changelog's
	// os/packages/vulnerability/data-source directories play - there's no
	// further grouping above it to justify an extra wrapping directory.
	name := path.Join(provider, sanitize(provider, id)) + ".yaml"
	key := strings.ToLower(name)
	if other, ok := seen[key]; ok && other != id {
		return fmt.Errorf("case-insensitive path collision: %q and %q both map to %q", other, id, name)
	}
	seen[key] = id
	fmt.Fprintf(stdout, "M 100644 inline %s\n", name)
	fmt.Fprintf(stdout, "data %d\n%s\n", len(pretty), string(pretty))
	return nil
}

// dropGeneratedDates removes the three timestamps in a hummingbird CSAF
// document's tracking block that only record when Red Hat's generator last
// ran: current_release_date, generator.date and each revision_history
// entry's date. They're regenerated daily while version stays "1" and the
// history holds a single "Last generated version" entry, so they were the
// only change in ~98% of hummingbird's modified files.
func dropGeneratedDates(item any) {
	root, _ := item.(map[string]any)
	doc, _ := root["document"].(map[string]any)
	tracking, _ := doc["tracking"].(map[string]any)
	if tracking == nil {
		return
	}
	delete(tracking, "current_release_date")
	if gen, ok := tracking["generator"].(map[string]any); ok {
		delete(gen, "date")
	}
	if revs, ok := tracking["revision_history"].([]any); ok {
		for _, r := range revs {
			if rev, ok := r.(map[string]any); ok {
				delete(rev, "date")
			}
		}
	}
}

// metadata mirrors the subset of vunnel's per-provider metadata.json this
// tool cares about: when the cache was captured, for the commit timestamp,
// and the build's provenance, for trailers (see trailers).
type metadata struct {
	Provider   string    `json:"provider"`
	DataSource string    `json:"dataSource,omitempty"`
	URLs       []string  `json:"urls,omitempty"`
	Listing    *struct{} `json:"listing,omitempty"`
	Timestamp  time.Time `json:"timestamp,omitempty"`
	// Processor is the vunnel version that built the results (e.g.
	// "vunnel@0.67.0-post.3+45d8771"). Older builds don't record it.
	Processor string `json:"processor,omitempty"`
	// Stale is set when the results were imported from an earlier
	// archive rather than built from the upstream source this run, so the
	// build carries no news from the source.
	Stale bool `json:"stale,omitempty"`
}

// Trailers recording metadata.json's provenance on the staged commit;
// cmd/changelog keeps them (its Captured trailer joins this block).
const (
	processorTrailer = "Processor: "
	staleTrailer     = "Stale: true"
	capturedTrailer  = "Captured: "
)

// trailers returns the trailer lines for a build's metadata, or nil.
// Stale is written only when true: older builds don't record it, so its
// absence can't be read as "fresh" anyway.
func trailers(meta metadata) []string {
	var t []string
	// One line only: a newline in it would end the trailer block.
	if p := strings.Join(strings.Fields(meta.Processor), " "); p != "" {
		t = append(t, processorTrailer+p)
	}
	if meta.Stale {
		t = append(t, staleTrailer)
	}
	// Only when metadata.json has one: a stand-in would claim a capture
	// time the build never recorded.
	if !meta.Timestamp.IsZero() {
		t = append(t, capturedTrailer+meta.Timestamp.UTC().Format(time.RFC3339))
	}
	return t
}

// commitMessage is the staged commit's message: the subject, then the
// metadata trailers, if any.
func commitMessage(subject string, meta metadata) string {
	t := trailers(meta)
	if len(t) == 0 {
		return subject
	}
	return subject + "\n\n" + strings.Join(t, "\n")
}

// EmptyBuildTrailer marks a staged commit for an upstream build whose
// tarball has no entries at all - anchore has published at least one
// (debian, 2023-03-14: a 32-byte layer). cmd/changelog carries the
// provider's previous snapshot forward for it instead of chaining the
// empty tree as "every record deleted" (and then "re-added" by the next
// build). Must match cmd/changelog's copy.
const EmptyBuildTrailer = "Empty-Build: true"

// header writes the fast-import preamble for refName's (orphan) commit.
func header(refName string, committerTime time.Time, message string) {
	// "feature done": fast-import refuses to update any ref unless the
	// stream ends with an explicit "done" (written by main only after
	// export returns successfully). Without it, an export that dies
	// mid-stream - a registry hiccup, say - leaves fast-import to commit
	// the truncated snapshot as if it were complete, and the pipe hides
	// the failure unless the shell runs with pipefail (GitHub Actions'
	// default bash doesn't).
	fmt.Fprintf(stdout, "feature done\n")
	fmt.Fprintf(stdout, "reset %s\n", refName)
	fmt.Fprintf(stdout, "commit %s\n", refName)
	fmt.Fprintf(stdout, "committer grype-db-changelog <41898282+github-actions[bot]@users.noreply.github.com> %d +0000\n", committerTime.Unix())
	fmt.Fprintf(stdout, "data %d\n%s\n", len(message), message)
	fmt.Fprintf(stdout, "deleteall\n")
}

// export writes refName's commit for the image to stdout as a fast-import
// stream. publishTime (may be zero) is the build's GHCR publish time, from
// the caller: it dates the commit and its subject.
func export(ctx context.Context, provider string, ref name.Reference, publishTime time.Time) error {
	img, err := withRetry(ctx, "fetching the manifest", func() (v1.Image, error) {
		return remote.Image(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	})
	if err != nil {
		return fmt.Errorf("remote.Image failed: %w", err)
	}
	dgst, err := img.Digest()
	if err != nil {
		return fmt.Errorf("(v1.Image).Digest failed: %w", err)
	}
	dgstRef := ref.Context().Digest(dgst.String())

	// refs/raw/<provider>/<digest> (":" is invalid in ref names), keyed by
	// digest rather than by the tag we were pulled via, so the same ref
	// name results regardless of which tag (if any) a given build happens
	// to carry - untagged intermediate builds (e.g. an incremental
	// provider's intra-day rebuilds) get their own ref too.
	refName := "refs/raw/" + provider + "/" + strings.ReplaceAll(dgstRef.DigestStr(), ":", "-")

	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("(v1.Image).Layers failed: %w", err)
	} else if len(layers) != 1 {
		return fmt.Errorf("(v1.Image).Layers unexpected length: %d", len(layers))
	}

	rc, closer, err := layerReader(ctx, ref.Context(), layers[0])
	if err != nil {
		return fmt.Errorf("opening the layer failed: %w", err)
	}
	defer func() {
		if err := closer.Close(); err != nil {
			log.Printf("(io.Closer).Close failed: %v", err)
		}
	}()

	// Will contain the extracted 'results.db' file. Everything else in the
	// tarball (notably provider/input/*, which can run into the gigabytes)
	// is streamed past and discarded without ever touching disk.
	dbFile, err := os.CreateTemp("", "grype-db-*.db")
	if err != nil {
		return fmt.Errorf("os.CreateTemp failed: %w", err)
	}
	defer func() {
		if err := os.Remove(dbFile.Name()); err != nil {
			log.Printf("os.Remove failed: %v", err)
		}
	}()

	var meta metadata
	var sawResults bool
	entries := 0

	resultsPath := path.Join(provider, "results", "results.db")
	metadataPath := path.Join(provider, "metadata.json")

	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("(tar.Reader).Next failed: %w", err)
		}
		entries++
		switch hdr.Name {
		case resultsPath:
			if _, err := io.Copy(dbFile, tr); err != nil {
				return fmt.Errorf("io.Copy failed: %w", err)
			}
			sawResults = true
		case metadataPath:
			b, err := io.ReadAll(tr)
			if err != nil {
				return fmt.Errorf("io.ReadAll failed: %w", err)
			}
			if err := json.Unmarshal(b, &meta); err != nil {
				return fmt.Errorf("json.Unmarshal of metadata.json failed: %w", err)
			}
		default:
			// Deliberately ignored: provider/input/* (raw upstream mirror,
			// can be multi-GB), provider/checksums, provider/results/observed-fix-dates.db.
		}
	}
	// Read to the very end - past the tar trailer and any padding - so
	// the blob's digest gets verified before anything is committed.
	if _, err := io.Copy(io.Discard, rc); err != nil {
		return fmt.Errorf("reading the rest of the layer failed: %w", err)
	}
	// The subject (and the staged commit's date) is the GHCR publish time:
	// when Grype users could first see this build, and never out of order.
	// metadata.json's timestamp goes in the Captured trailer instead (see
	// trailers): it's when vunnel last recorded new results, which a run
	// that finds nothing new leaves unchanged, so it can lag by days.
	committerTime := publishTime
	if committerTime.IsZero() {
		committerTime = meta.Timestamp.UTC()
	}
	if committerTime.IsZero() {
		committerTime = time.Now().UTC()
	}
	message := fmt.Sprintf("%s %s: %s", provider, committerTime.Format(time.RFC3339), dgstRef.String())

	if !sawResults {
		// Only a tarball with no entries at all counts as an empty build.
		// One with content but no results.db fails loudly instead: that
		// would more likely mean the layout changed upstream, which must
		// not silently turn every later build into a no-op.
		if entries == 0 {
			log.Printf("%s is an empty upstream build; staging it as a carry-forward", dgstRef)
			header(refName, committerTime, message+"\n\nUpstream published this build as an empty tarball (no\nresults.db), so the previous snapshot is carried forward.\n\n"+EmptyBuildTrailer)
			return nil
		}
		return fmt.Errorf("tarball has %d entries but no %s", entries, resultsPath)
	}
	if err := dbFile.Close(); err != nil {
		return fmt.Errorf("(*os.File).Close failed: %w", err)
	}

	db, err := sql.Open("sqlite", dbFile.Name())
	if err != nil {
		return fmt.Errorf("sql.Open failed: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("(*sql.DB).Close failed: %v", err)
		}
	}()

	rows, err := db.QueryContext(ctx, "SELECT id, record FROM results ORDER BY id")
	if err != nil {
		return fmt.Errorf("(*sql.DB).QueryContext failed: %w", err)
	}
	defer rows.Close()

	header(refName, committerTime, commitMessage(message, meta))

	seen := map[string]string{}
	for rows.Next() {
		var id string
		var record []byte
		if err := rows.Scan(&id, &record); err != nil {
			return fmt.Errorf("(*sql.Rows).Scan failed: %w", err)
		}
		if len(record) == 0 {
			continue
		}
		if err := emit(seen, provider, id, record); err != nil {
			return fmt.Errorf("emit failed: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("(*sql.Rows).Err failed: %w", err)
	}

	return nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if len(os.Args) != 3 && len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <provider> <image> [publish-time (RFC 3339)]\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}
	var publishTime time.Time
	if len(os.Args) == 4 && os.Args[3] != "" {
		t, err := time.Parse(time.RFC3339, os.Args[3])
		if err != nil {
			log.Fatalf("parsing publish time %q failed: %v", os.Args[3], err)
		}
		publishTime = t.UTC()
	}
	provider := os.Args[1]
	ref, err := name.ParseReference(os.Args[2])
	if err != nil {
		log.Fatalf("name.ParseReference failed: %v", err)
	}

	if err := export(ctx, provider, ref, publishTime); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(stdout, "done\n")
}
