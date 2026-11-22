package main

import (
	"encoding/json"
	"reflect"
	"testing"
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
