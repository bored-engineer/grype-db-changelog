package main

import "testing"

func TestEmitCaseCollision(t *testing.T) {
	seen := map[string]string{}
	if err := emit(seen, "kev", "kev:CVE-2026-1", []byte(`{"a":1}`)); err != nil {
		t.Fatalf("first emit failed: %v", err)
	}
	// Differs only by case after sanitize() -> same path, different id.
	if err := emit(seen, "kev", "kev:cve-2026-1", []byte(`{"a":2}`)); err == nil {
		t.Fatalf("expected a case-collision error, got none")
	}
	// sanitize() turns ":" into "-", so this also collides on the exact
	// same path even though the raw ids are nothing alike.
	if err := emit(seen, "kev", "kev-CVE-2026-1", []byte(`{"a":3}`)); err == nil {
		t.Fatalf("expected a sanitize-collision error, got none")
	}
}

func TestEmitNoFalsePositive(t *testing.T) {
	seen := map[string]string{}
	if err := emit(seen, "kev", "kev:CVE-2026-1", []byte(`{"a":1}`)); err != nil {
		t.Fatalf("first emit failed: %v", err)
	}
	if err := emit(seen, "kev", "kev:CVE-2026-2", []byte(`{"a":2}`)); err != nil {
		t.Fatalf("second emit (distinct id) unexpectedly failed: %v", err)
	}
	// Re-emitting the exact same id (e.g. a re-run) must not be flagged.
	if err := emit(seen, "kev", "kev:CVE-2026-1", []byte(`{"a":1}`)); err != nil {
		t.Fatalf("re-emitting the same id unexpectedly failed: %v", err)
	}
}
