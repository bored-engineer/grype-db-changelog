package main

import (
	"archive/tar"
	"bufio"
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
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/sync/errgroup"
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
		quote := false
		for k, val := range v {
			out[k] = canonicalizeIn(k, val)
			quote = quote || needsQuotes(k)
		}
		if quote {
			return quotedKeys(out)
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
	case string:
		if needsQuotes(v) {
			return quoted(v)
		}
		return v
	default:
		return v
	}
}

// quoted is a string yaml.v3 can't write as a block scalar: a multi-line
// string starting with whitespace. yaml.v3 gives those a block scalar
// that's either unparseable (a leading space inside a list: the |4
// indentation indicator is off by the list's indent) or reads back as a
// different string (a leading newline is dropped). Written double-quoted
// instead, which always round-trips. It marshals to JSON as a plain
// string, so canonicalize's sort keys are unchanged.
type quoted string

// needsQuotes reports whether yaml.v3 would write s as a broken block
// scalar (see quoted).
func needsQuotes(s string) bool {
	r, _ := utf8.DecodeRuneInString(s)
	return unicode.IsSpace(r) && strings.ContainsRune(s, '\n')
}

// quotedKeys is a map with a key needsQuotes is true of: yaml.v3 gets
// those wrong as keys too, so the map is written by hand, with keys sorted
// and the troublesome ones double-quoted. Only such (vanishingly rare)
// maps take this path, so every other map keeps yaml.v3's own key order.
// It marshals to JSON as a plain map, so sort keys are unchanged.
type quotedKeys map[string]any

func (m quotedKeys) MarshalYAML() (any, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, k := range keys {
		key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}
		if needsQuotes(k) {
			key.Style = yaml.DoubleQuotedStyle
		}
		var val yaml.Node
		if err := val.Encode(m[k]); err != nil {
			return nil, err
		}
		node.Content = append(node.Content, key, &val)
	}
	return node, nil
}

func (q quoted) MarshalYAML() (any, error) {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: string(q), Style: yaml.DoubleQuotedStyle}, nil
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
// item, re-encoding its JSON as YAML for better diffs (see render and
// write; export runs them in parallel via emitAll).
func emit(seen map[string]string, provider string, id string, record []byte) error {
	name, data, err := render(provider, id, record)
	if err != nil {
		return err
	}
	return write(seen, id, name, data)
}

// render returns one record's path and file contents. Unlike trivy-db,
// vunnel's records are already plain JSON, so no decoding/enum-resolving
// step is needed here. Safe to call concurrently.
func render(provider string, id string, record []byte) (string, []byte, error) {
	var env envelope
	if err := decodeJSON(record, &env); err != nil {
		return "", nil, fmt.Errorf("json.Unmarshal failed for %s: %w", id, err)
	}
	switch provider {
	case "hummingbird":
		dropGeneratedDates(env.Item)
	case "arch":
		dedupeArchAdvisories(env.Item)
	case "photon":
		canonicalPhotonAdvisories(env.Item)
	}
	pretty, err := yaml.Marshal(canonicalize(env.Item))
	if err != nil {
		return "", nil, fmt.Errorf("yaml.Marshal failed for %s: %w", id, err)
	}
	pretty = append([]byte(schemaComment(env.Schema)), pretty...)
	// No "providers/" wrapper directory: the provider name is already the
	// top-level category here, the same role trivy-db-changelog's
	// os/packages/vulnerability/data-source directories play - there's no
	// further grouping above it to justify an extra wrapping directory.
	name, err := recordPath(provider, id)
	if err != nil {
		return "", nil, err
	}
	return name, pretty, nil
}

// recordPath is the file a record is written to. path.Join would quietly
// resolve "." and ".." segments, so an id like "../x" or "debian:10/../.."
// would land outside the provider's directory, where cmd/changelog (which
// only takes the provider's subtree) drops it without a word. Refused
// instead, along with absolute ids and control characters (a newline would
// break the fast-import stream).
func recordPath(provider, id string) (string, error) {
	rel := sanitize(provider, id)
	if rel == "" || strings.HasPrefix(rel, "/") || strings.ContainsFunc(rel, unicode.IsControl) {
		return "", fmt.Errorf("unusable record id %q", id)
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == "." || seg == ".." {
			return "", fmt.Errorf("unusable record id %q", id)
		}
	}
	return path.Join(provider, rel) + ".yaml", nil
}

// write emits one rendered file to the fast-import stream.
//
// seen tracks every path this export run has already written, case-folded,
// so two distinct ids that only differ by case (or that collide after
// sanitize()'s substitutions) are caught here as a hard error instead of
// silently overwriting each other on a case-insensitive filesystem at
// checkout time — the failure mode trivy-db-changelog hit.
func write(seen map[string]string, id, name string, data []byte) error {
	key := strings.ToLower(name)
	if other, ok := seen[key]; ok && other != id {
		return fmt.Errorf("case-insensitive path collision: %q and %q both map to %q", other, id, name)
	}
	seen[key] = id
	// Errors matter: a write that fails (fast-import gone) stops the
	// export rather than rendering every remaining record into the void.
	if _, err := fmt.Fprintf(stdout, "M 100644 inline %s\ndata %d\n", name, len(data)); err != nil {
		return fmt.Errorf("writing the fast-import stream failed: %w", err)
	}
	if _, err := stdout.Write(data); err != nil {
		return fmt.Errorf("writing the fast-import stream failed: %w", err)
	}
	if _, err := io.WriteString(stdout, "\n"); err != nil {
		return fmt.Errorf("writing the fast-import stream failed: %w", err)
	}
	return nil
}

// emitAll renders rows' records on every CPU and writes them from one
// goroutine, which keeps seen single-threaded. Order doesn't matter:
// fast-import builds the same tree whatever order files arrive in.
// Rendering was ~3/4 of a big export's time (sles: 770K records, 8GB of
// JSON), and ran on one core.
func emitAll(ctx context.Context, provider string, rows *sql.Rows) (int, error) {
	type rec struct {
		id     string
		record []byte
	}
	type file struct {
		id, name string
		data     []byte
	}
	g, ctx := errgroup.WithContext(ctx)
	recs := make(chan rec, 256)
	files := make(chan file, 256)

	g.Go(func() error {
		defer close(recs)
		for rows.Next() {
			var r rec
			// Scan into *[]byte copies the value, so it outlives the row.
			if err := rows.Scan(&r.id, &r.record); err != nil {
				return fmt.Errorf("(*sql.Rows).Scan failed: %w", err)
			}
			if len(r.record) == 0 {
				continue
			}
			select {
			case recs <- r:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("(*sql.Rows).Err failed: %w", err)
		}
		return nil
	})

	var workers sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		workers.Add(1)
		g.Go(func() error {
			defer workers.Done()
			for r := range recs {
				name, data, err := render(provider, r.id, r.record)
				if err != nil {
					return fmt.Errorf("emit failed: %w", err)
				}
				select {
				case files <- file{r.id, name, data}:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		})
	}
	go func() {
		workers.Wait()
		close(files)
	}()

	n := 0
	g.Go(func() error {
		seen := map[string]string{}
		for f := range files {
			if err := write(seen, f.id, f.name, f.data); err != nil {
				return fmt.Errorf("emit failed: %w", err)
			}
			n++
		}
		return nil
	})
	err := g.Wait()
	return n, err
}

// dropGeneratedDates removes the three timestamps in a hummingbird CSAF
// document's tracking block that only record when Red Hat's generator last
// ran: current_release_date, generator.date and each revision_history
// entry's date. They're regenerated daily while version stays "1" and the
// history holds a single "Last generated version" entry, so they were the
// only change in ~98% of hummingbird's modified files.
// dedupeArchAdvisories removes repeated ids from an arch record's
// Vulnerability.Metadata.Advisories, keeping the first of each. Upstream
// lists some ASA ids twice in one build and once in the next, and that
// flip was the only change in essentially every modified arch file (~50 a
// build, ~70% of them flipping back to a version seen days earlier).
func dedupeArchAdvisories(item any) {
	root, _ := item.(map[string]any)
	vuln, _ := root["Vulnerability"].(map[string]any)
	meta, _ := vuln["Metadata"].(map[string]any)
	advisories, ok := meta["Advisories"].([]any)
	if !ok {
		return
	}
	seen := make(map[string]bool, len(advisories))
	out := advisories[:0:0]
	for _, a := range advisories {
		if s, ok := a.(string); ok {
			if seen[s] {
				continue
			}
			seen[s] = true
		}
		out = append(out, a)
	}
	meta["Advisories"] = out
}

// photonAdvisoryLink matches the photon wiki page vunnel links an advisory
// to: Security-Update-<ver>-<n> or Security-Updates-<ver>-<n>, where <n>
// may be zero-padded.
var photonAdvisoryLink = regexp.MustCompile(`^(https://github\.com/vmware/photon/wiki/)Security-Updates?-(\d+\.\d+)-0*(\d+)$`)

// canonicalPhotonAdvisories rewrites each photon AdvisorySummary entry that
// cites an advisory with two wiki pages to its Security-Updates page and
// that page's ID. vunnel maps each CVE to its earliest advisory, and for
// those 579 old advisories both pages carry the same date, so which one
// wins depends on the order os.listdir returns them in - and it changes
// between builds, flipping ~1,000 files at a time. Both pages are real
// upstream data; this only picks one of them every time.
func canonicalPhotonAdvisories(item any) {
	root, _ := item.(map[string]any)
	vuln, _ := root["Vulnerability"].(map[string]any)
	fixedIn, _ := vuln["FixedIn"].([]any)
	for _, f := range fixedIn {
		fix, _ := f.(map[string]any)
		va, _ := fix["VendorAdvisory"].(map[string]any)
		summaries, _ := va["AdvisorySummary"].([]any)
		for _, a := range summaries {
			adv, _ := a.(map[string]any)
			link, _ := adv["Link"].(string)
			m := photonAdvisoryLink.FindStringSubmatch(link)
			if m == nil {
				continue
			}
			canon, ok := photonDuplicateAdvisories[m[2]+"-"+m[3]]
			if !ok {
				continue
			}
			adv["Link"] = m[1] + canon.page
			adv["ID"] = canon.id
		}
	}
}

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
	Timestamp time.Time `json:"timestamp,omitempty"`
	// Processor is the vunnel version that built the results (e.g.
	// "vunnel@0.67.0-post.3+45d8771"). Older builds don't record it.
	Processor string `json:"processor,omitempty"`
	// Stale is set when the results were imported from an earlier
	// archive rather than built from the upstream source this run, so the
	// build carries no news from the source.
	Stale bool `json:"stale,omitempty"`
}

// parseMetadata decodes metadata.json field by field, leniently: only
// provenance trailers come from it, so a field of an unexpected type (or a
// timestamp that won't parse, like "") is logged and left out rather than
// failing the export - which would hold back every later build of every
// provider, since the changelog is chained strictly in order. Only a file
// that isn't a JSON object at all is an error.
func parseMetadata(b []byte) (metadata, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return metadata{}, fmt.Errorf("json.Unmarshal of metadata.json failed: %w", err)
	}
	var m metadata
	for key, dst := range map[string]any{"timestamp": &m.Timestamp, "processor": &m.Processor, "stale": &m.Stale} {
		v, ok := raw[key]
		if !ok {
			continue
		}
		if err := json.Unmarshal(v, dst); err != nil {
			log.Printf("metadata.json: ignoring %s %s: %v", key, v, err)
		}
	}
	return m, nil
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

	layerStart := time.Now()
	layerBytes, _ := layers[0].Size()
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
	// In a directory of its own, removed whole: SQLite may leave -wal and
	// -shm files beside the database.
	tmpDir, err := os.MkdirTemp("", "grype-db-*")
	if err != nil {
		return fmt.Errorf("os.MkdirTemp failed: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			log.Printf("os.RemoveAll failed: %v", err)
		}
	}()
	dbFile, err := os.Create(filepath.Join(tmpDir, "results.db"))
	if err != nil {
		return fmt.Errorf("os.Create failed: %w", err)
	}

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
			if sawResults {
				return fmt.Errorf("tarball has more than one %s", resultsPath)
			}
			if _, err := io.Copy(dbFile, tr); err != nil {
				return fmt.Errorf("io.Copy failed: %w", err)
			}
			sawResults = true
		case metadataPath:
			b, err := io.ReadAll(tr)
			if err != nil {
				return fmt.Errorf("io.ReadAll failed: %w", err)
			}
			if meta, err = parseMetadata(b); err != nil {
				return err
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
	layerTime := time.Since(layerStart)
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

	// Storage order, not ORDER BY id: that walks the id index and reads
	// each row from a random spot in what can be a 9GB file. The order
	// doesn't matter (see emitAll).
	rows, err := db.QueryContext(ctx, "SELECT id, record FROM results")
	if err != nil {
		return fmt.Errorf("(*sql.DB).QueryContext failed: %w", err)
	}
	defer rows.Close()

	header(refName, committerTime, commitMessage(message, meta))

	encodeStart := time.Now()
	n, err := emitAll(ctx, provider, rows)
	if err != nil {
		return err
	}
	// One line, which export.yml shows next to each export's total time.
	log.Printf("stages: layer %s (%s), %d records %s", layerTime.Round(time.Second), humanBytes(layerBytes), n, time.Since(encodeStart).Round(time.Second))
	return nil
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MiB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func main() {
	// SIGTERM (timeout, runner shutdown) and SIGPIPE (fast-import died, so
	// stdout's reader is gone) cancel the export like ^C does, instead of
	// killing the process outright: that skipped every defer, leaving the
	// multi-GB temp results.db behind. With SIGPIPE caught, writes to the
	// dead pipe return EPIPE, which write() reports.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGPIPE)
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

	// Buffered: unbuffered, every record cost three write syscalls, ~3/4
	// of the CPU time encoding sles's 770K records. Nothing is flushed on
	// failure, and fast-import commits nothing without the final "done".
	bw := bufio.NewWriterSize(os.Stdout, 1<<20)
	stdout = bw
	if err := export(ctx, provider, ref, publishTime); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(stdout, "done\n")
	if err := bw.Flush(); err != nil {
		log.Fatalf("writing the fast-import stream failed: %v", err)
	}
}
