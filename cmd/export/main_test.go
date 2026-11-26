package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func mustUnmarshal(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	return v
}

func TestCanonicalizeSortsObjectArrays(t *testing.T) {
	// Same FixedIn-shaped entries, two different upstream orderings - the
	// real case from
	// https://github.com/bored-engineer/grype-db-changelog/commit/6b981675ad5d04e338cbc1d3d953f46d04efb086
	a := mustUnmarshal(t, `{"FixedIn":[{"Name":"ntp"},{"Name":"sntp"},{"Name":"ntpdate"}]}`)
	b := mustUnmarshal(t, `{"FixedIn":[{"Name":"sntp"},{"Name":"ntpdate"},{"Name":"ntp"}]}`)
	ca, cb := canonicalize(a), canonicalize(b)
	if !reflect.DeepEqual(ca, cb) {
		t.Fatalf("canonicalize did not converge: %#v vs %#v", ca, cb)
	}
}

func TestCanonicalizeLeavesScalarArraysInPlace(t *testing.T) {
	// Order may be meaningful for plain scalar arrays (e.g. NVD's ordered
	// reference/description lists) - only arrays of objects get sorted.
	v := mustUnmarshal(t, `{"urls":["b","a","c"]}`)
	got := canonicalize(v)
	want := mustUnmarshal(t, `{"urls":["b","a","c"]}`)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("canonicalize reordered a scalar array: got %#v, want %#v", got, want)
	}
}

func TestCanonicalizeRecursesIntoNestedArrays(t *testing.T) {
	a := mustUnmarshal(t, `{"outer":[{"inner":[{"x":2},{"x":1}]},{"id":1}]}`)
	b := mustUnmarshal(t, `{"outer":[{"id":1},{"inner":[{"x":1},{"x":2}]}]}`)
	ca, cb := canonicalize(a), canonicalize(b)
	if !reflect.DeepEqual(ca, cb) {
		t.Fatalf("canonicalize did not converge on nested arrays: %#v vs %#v", ca, cb)
	}
}

func TestCanonicalizeKeepsOSVEventOrder(t *testing.T) {
	// govulndb's GO-2022-0969: two ranges in one events list. Sorted,
	// they'd read [fixed, fixed, introduced, introduced] and the pairing
	// would be lost. The ranges array itself is still sorted.
	in := `{"affected":[{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.18.6"},{"introduced":"1.19.0-0"},{"fixed":"1.19.1"}]}]}]}`
	got := canonicalize(mustUnmarshal(t, in))
	want := mustUnmarshal(t, in)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("canonicalize reordered OSV events: got %#v, want %#v", got, want)
	}
}

func TestCanonicalizeSortsArraysNestedInEvents(t *testing.T) {
	// Only the events array itself is ordered, not object arrays inside it.
	a := mustUnmarshal(t, `{"events":[{"x":[{"b":1},{"a":1}]},{"y":1}]}`)
	b := mustUnmarshal(t, `{"events":[{"x":[{"a":1},{"b":1}]},{"y":1}]}`)
	if ca, cb := canonicalize(a), canonicalize(b); !reflect.DeepEqual(ca, cb) {
		t.Fatalf("canonicalize did not sort inside events: %#v vs %#v", ca, cb)
	}
}

func TestNumbersKeepTheirText(t *testing.T) {
	var v any
	if err := decodeJSON([]byte(`{"baseScore":10.0,"impactScore":6.0,"score":1e-05,"count":3,"big":12345678901234567891,"neg":-2.50,"str":"10.0"}`), &v); err != nil {
		t.Fatalf("decodeJSON failed: %v", err)
	}
	out, err := yaml.Marshal(canonicalize(v))
	if err != nil {
		t.Fatalf("yaml.Marshal failed: %v", err)
	}
	want := `baseScore: 10.0
big: 12345678901234567891
count: 3
impactScore: 6.0
neg: -2.50
score: 1e-05
str: "10.0"
`
	if string(out) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
	// And they decode back as numbers, not strings.
	var back map[string]any
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatalf("yaml.Unmarshal failed: %v", err)
	}
	if _, ok := back["baseScore"].(float64); !ok {
		t.Errorf("baseScore decoded as %T, want float64", back["baseScore"])
	}
	if _, ok := back["count"].(int); !ok {
		t.Errorf("count decoded as %T, want int", back["count"])
	}
}

func TestNumbersSortLikeTheirText(t *testing.T) {
	// The sort key is the number's own text, so differently-ordered
	// upstream arrays still converge.
	var a, b any
	if err := decodeJSON([]byte(`[{"s":7.0},{"s":10.0}]`), &a); err != nil {
		t.Fatal(err)
	}
	if err := decodeJSON([]byte(`[{"s":10.0},{"s":7.0}]`), &b); err != nil {
		t.Fatal(err)
	}
	if ca, cb := canonicalize(a), canonicalize(b); !reflect.DeepEqual(ca, cb) {
		t.Fatalf("canonicalize did not converge: %#v vs %#v", ca, cb)
	}
}

func TestDecodeJSONRejectsTrailingData(t *testing.T) {
	var v any
	if err := decodeJSON([]byte(`{"a":1}{"b":2}`), &v); err == nil {
		t.Fatal("expected an error for trailing data")
	}
}

func TestWithRetry(t *testing.T) {
	old := setupBackoff
	setupBackoff = time.Millisecond
	t.Cleanup(func() { setupBackoff = old })

	calls := 0
	got, err := withRetry(context.Background(), "test", func() (string, error) {
		calls++
		if calls < 3 {
			return "", errors.New("dial tcp: i/o timeout")
		}
		return "ok", nil
	})
	if err != nil || got != "ok" || calls != 3 {
		t.Fatalf("got (%q, %v) after %d calls, want (\"ok\", nil) after 3", got, err, calls)
	}

	calls = 0
	if _, err := withRetry(context.Background(), "test", func() (string, error) {
		calls++
		return "", errors.New("down")
	}); err == nil || calls != setupAttempts {
		t.Fatalf("got %v after %d calls, want an error after %d", err, calls, setupAttempts)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls = 0
	if _, err := withRetry(ctx, "test", func() (string, error) {
		calls++
		return "", errors.New("down")
	}); err == nil || calls != 1 {
		t.Fatalf("got %v after %d calls, want an error after 1 (context canceled)", err, calls)
	}
}

func TestSchemaComment(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want string
	}{
		{"https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/osv/schema-1.6.2.json", "# schema: vulnerability/osv/schema-1.6.2.json\n"},
		{"https://example.com/other/schema.json", "# schema: https://example.com/other/schema.json\n"},
		{nil, ""},
		{"", ""},
		{"a\nb", "# schema: \"a\\nb\"\n"},
		{map[string]any{"v": "1"}, "# schema: {\"v\":\"1\"}\n"},
	} {
		if got := schemaComment(tc.in); got != tc.want {
			t.Errorf("schemaComment(%#v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestEmitWritesSchemaComment(t *testing.T) {
	var buf bytes.Buffer
	old := stdout
	stdout = &buf
	t.Cleanup(func() { stdout = old })
	rec := `{"schema":"https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/known-exploited/schema-1.0.0.json","identifier":"kev:cve-2026-1","item":{"a":1.0}}`
	if err := emit(map[string]string{}, "kev", "kev:cve-2026-1", []byte(rec)); err != nil {
		t.Fatalf("emit failed: %v", err)
	}
	body := "# schema: vulnerability/known-exploited/schema-1.0.0.json\na: 1.0\n"
	want := fmt.Sprintf("M 100644 inline kev/cve-2026-1.yaml\ndata %d\n%s\n", len(body), body)
	if buf.String() != want {
		t.Fatalf("got:\n%q\nwant:\n%q", buf.String(), want)
	}
	// Still one YAML document, with the item at its root.
	var back map[string]any
	if err := yaml.Unmarshal([]byte(body), &back); err != nil || back["a"] != 1.0 {
		t.Fatalf("yaml.Unmarshal = %#v, %v", back, err)
	}
}

func TestCommitMessage(t *testing.T) {
	subj := "kev 2026-11-25T00:22:13Z: ghcr.io/anchore/grype-db/data/kev@sha256:00"
	for _, tc := range []struct {
		meta metadata
		want string
	}{
		{metadata{}, subj},
		{metadata{Processor: "vunnel@0.67.0-post.3+45d8771"}, subj + "\n\nProcessor: vunnel@0.67.0-post.3+45d8771"},
		{metadata{Processor: "vunnel@1", Stale: true}, subj + "\n\nProcessor: vunnel@1\nStale: true"},
		{metadata{Stale: true}, subj + "\n\nStale: true"},
		{metadata{Processor: "multi\nline  value"}, subj + "\n\nProcessor: multi line value"},
		{metadata{Processor: "vunnel@1", Timestamp: time.Date(2026, 5, 1, 9, 18, 0, 123456000, time.FixedZone("", 3600))}, subj + "\n\nProcessor: vunnel@1\nCaptured: 2026-05-01T08:18:00Z"},
	} {
		if got := commitMessage(subj, tc.meta); got != tc.want {
			t.Errorf("commitMessage(%+v) = %q, want %q", tc.meta, got, tc.want)
		}
	}
}

func TestMetadataDecodesProvenance(t *testing.T) {
	var m metadata
	in := `{"provider":"kev","timestamp":"2026-11-25T00:22:13.021942+00:00","processor":"vunnel@0.67.0","stale":true,"listing":{"digest":"x"},"schema":{"version":"1.0.3"}}`
	if err := json.Unmarshal([]byte(in), &m); err != nil {
		t.Fatal(err)
	}
	if m.Processor != "vunnel@0.67.0" || !m.Stale {
		t.Fatalf("got %+v", m)
	}
	// Older builds: null or absent.
	m = metadata{}
	if err := json.Unmarshal([]byte(`{"provider":"mariner","timestamp":"2024-01-11T01:29:08.659711+00:00","processor":null,"stale":null}`), &m); err != nil {
		t.Fatal(err)
	}
	if m.Processor != "" || m.Stale {
		t.Fatalf("got %+v", m)
	}
}

func TestDropGeneratedDates(t *testing.T) {
	item := mustUnmarshal(t, `{"document":{"tracking":{"current_release_date":"2026-11-20T18:26:59+00:00","generator":{"date":"2026-11-20T18:26:59+00:00","engine":{"name":"CSAF Generator"}},"id":"CVE-2008-1891","initial_release_date":"2008-04-15T00:00:00+00:00","revision_history":[{"date":"2026-11-20T18:26:59+00:00","number":"1","summary":"Last generated version"}],"version":"1"}}}`)
	dropGeneratedDates(item)
	want := mustUnmarshal(t, `{"document":{"tracking":{"generator":{"engine":{"name":"CSAF Generator"}},"id":"CVE-2008-1891","initial_release_date":"2008-04-15T00:00:00+00:00","revision_history":[{"number":"1","summary":"Last generated version"}],"version":"1"}}}`)
	if !reflect.DeepEqual(item, want) {
		t.Fatalf("got %#v", item)
	}
	// Records without a tracking block are left alone.
	for _, in := range []string{`{}`, `{"document":{}}`, `{"document":"x"}`, `[]`} {
		v := mustUnmarshal(t, in)
		dropGeneratedDates(v)
		if !reflect.DeepEqual(v, mustUnmarshal(t, in)) {
			t.Errorf("changed %s", in)
		}
	}
}

// resultsDB writes a vunnel-style results.db with the given records.
func resultsDB(t *testing.T, records map[string]string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "results.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec("CREATE TABLE results (id VARCHAR NOT NULL PRIMARY KEY, record BLOB)"); err != nil {
		t.Fatal(err)
	}
	for id, rec := range records {
		if _, err := db.Exec("INSERT INTO results VALUES (?, ?)", id, []byte(rec)); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// parseStream splits fast-import filemodify commands into path -> data.
func parseStream(t *testing.T, s string) map[string]string {
	t.Helper()
	files := map[string]string{}
	for s != "" {
		var name string
		var n int
		line, rest, _ := strings.Cut(s, "\n")
		if _, err := fmt.Sscanf(line, "M 100644 inline %s", &name); err != nil {
			t.Fatalf("bad command %q", line)
		}
		line, rest, _ = strings.Cut(rest, "\n")
		if _, err := fmt.Sscanf(line, "data %d", &n); err != nil {
			t.Fatalf("bad data line %q", line)
		}
		files[name] = rest[:n]
		s = rest[n+1:]
	}
	return files
}

func TestEmitAllMatchesEmit(t *testing.T) {
	records := map[string]string{"": `{"item":{}}`}
	delete(records, "")
	for i := range 2000 {
		id := fmt.Sprintf("kev:cve-2026-%d", i)
		records[id] = fmt.Sprintf(`{"schema":"https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/known-exploited/schema-1.0.0.json","identifier":%q,"item":{"n":%d.0,"l":[{"b":%d},{"a":1}]}}`, id, i, i)
	}
	records["kev:cve-empty"] = ""
	db := resultsDB(t, records)

	var want bytes.Buffer
	old := stdout
	t.Cleanup(func() { stdout = old })
	stdout = &want
	seen := map[string]string{}
	for id, rec := range records {
		if rec == "" {
			continue
		}
		if err := emit(seen, "kev", id, []byte(rec)); err != nil {
			t.Fatal(err)
		}
	}

	var got bytes.Buffer
	stdout = &got
	rows, err := db.Query("SELECT id, record FROM results")
	if err != nil {
		t.Fatal(err)
	}
	n, err := emitAll(context.Background(), "kev", rows)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2000 {
		t.Fatalf("emitAll wrote %d files, want 2000 (the empty record skipped)", n)
	}
	if g, w := parseStream(t, got.String()), parseStream(t, want.String()); !reflect.DeepEqual(g, w) {
		t.Fatalf("emitAll's files differ from emit's (%d vs %d files)", len(g), len(w))
	}
}

func TestEmitAllReportsCollision(t *testing.T) {
	var buf bytes.Buffer
	old := stdout
	stdout = &buf
	t.Cleanup(func() { stdout = old })
	db := resultsDB(t, map[string]string{
		"kev:CVE-2026-1": `{"item":{"a":1}}`,
		"kev:cve-2026-1": `{"item":{"a":2}}`,
	})
	rows, err := db.Query("SELECT id, record FROM results")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := emitAll(context.Background(), "kev", rows); err == nil || !strings.Contains(err.Error(), "collision") {
		t.Fatalf("got %v, want a collision error", err)
	}
}

func TestEmitAllReportsBadRecord(t *testing.T) {
	var buf bytes.Buffer
	old := stdout
	stdout = &buf
	t.Cleanup(func() { stdout = old })
	records := map[string]string{"kev:bad": `{not json`}
	for i := range 500 {
		records[fmt.Sprintf("kev:cve-%d", i)] = `{"item":{"a":1}}`
	}
	rows, err := resultsDB(t, records).Query("SELECT id, record FROM results")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := emitAll(context.Background(), "kev", rows); err == nil || !strings.Contains(err.Error(), "kev:bad") {
		t.Fatalf("got %v, want the bad record's error", err)
	}
}

func TestEmitCaseCollision(t *testing.T) {
	seen := map[string]string{}
	if err := emit(seen, "kev", "kev:CVE-2026-1", []byte(`{"item":{"a":1}}`)); err != nil {
		t.Fatalf("first emit failed: %v", err)
	}
	// Differs only by case after stripping the "kev:" prefix -> same path.
	if err := emit(seen, "kev", "kev:cve-2026-1", []byte(`{"item":{"a":2}}`)); err == nil {
		t.Fatalf("expected a case-collision error, got none")
	}
	// No "kev:" prefix to strip, but happens to equal the first id's
	// post-strip path exactly -> same collision, different cause.
	if err := emit(seen, "kev", "CVE-2026-1", []byte(`{"item":{"a":3}}`)); err == nil {
		t.Fatalf("expected a prefix-strip collision error, got none")
	}
}

func TestEmitNoFalsePositive(t *testing.T) {
	seen := map[string]string{}
	if err := emit(seen, "kev", "kev:CVE-2026-1", []byte(`{"item":{"a":1}}`)); err != nil {
		t.Fatalf("first emit failed: %v", err)
	}
	if err := emit(seen, "kev", "kev:CVE-2026-2", []byte(`{"item":{"a":2}}`)); err != nil {
		t.Fatalf("second emit (distinct id) unexpectedly failed: %v", err)
	}
	// Re-emitting the exact same id (e.g. a re-run) must not be flagged.
	if err := emit(seen, "kev", "kev:CVE-2026-1", []byte(`{"item":{"a":1}}`)); err != nil {
		t.Fatalf("re-emitting the same id unexpectedly failed: %v", err)
	}
}

func TestSanitizeStripsProviderPrefix(t *testing.T) {
	cases := []struct {
		provider, id, want string
	}{
		{"kev", "kev:CVE-2026-1", "CVE-2026-1"},
		{"debian", "debian:10/CVE-1999-0199", "10/CVE-1999-0199"},
		{"alpine", "3.10/CVE-2009-3895", "3.10/CVE-2009-3895"}, // no prefix, unchanged
		{"nvd", "1999/CVE-1999-0001", "1999/CVE-1999-0001"},    // no prefix, unchanged
	}
	for _, c := range cases {
		if got := sanitize(c.provider, c.id); got != c.want {
			t.Errorf("sanitize(%q, %q) = %q, want %q", c.provider, c.id, got, c.want)
		}
	}
}

// Multi-line strings starting with whitespace, in every position yaml.v3
// handles differently: yaml.v3's own block scalars for these either fail
// to parse or read back changed.
func TestLeadingWhitespaceStringsRoundTrip(t *testing.T) {
	for _, s := range []string{
		" leading space\n\nsecond paragraph\n",
		"  two spaces\nb",
		"\nleading newline\nb",
		"\tleading tab\nb",
		" line separator\nb",
		" nbsp\nb",
		" single line keeps plain quoting",
		"plain\nmulti-line\n",
	} {
		for name, v := range map[string]any{
			"top":      map[string]any{"k": s},
			"map":      map[string]any{"k": map[string]any{"v": s}},
			"list":     map[string]any{"k": []any{s, "y"}},
			"list-map": map[string]any{"k": []any{map[string]any{"lang": "en", "value": s}, map[string]any{"lang": "es"}}},
		} {
			out, err := yaml.Marshal(canonicalize(v))
			if err != nil {
				t.Fatalf("%s %q: yaml.Marshal failed: %v", name, s, err)
			}
			var back any
			if err := yaml.Unmarshal(out, &back); err != nil {
				t.Errorf("%s %q: doesn't parse: %v\n%s", name, s, err, out)
				continue
			}
			if !reflect.DeepEqual(back, v) {
				t.Errorf("%s %q: reads back as %#v\n%s", name, s, back, out)
			}
		}
	}
	// Ordinary multi-line text keeps its block scalar.
	out, _ := yaml.Marshal(canonicalize(map[string]any{"k": "a\nb\n"}))
	if want := "k: |\n    a\n    b\n"; string(out) != want {
		t.Errorf("got %q, want %q", out, want)
	}
}
