package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// testOverlay writes a README and workflow outside the repo under test.
func testOverlay(t *testing.T, readme string) *overlay {
	t.Helper()
	dir := t.TempDir()
	ov := &overlay{
		readme:    filepath.Join(dir, "README.md"),
		workflow:  filepath.Join(dir, "dispatcher.yml"),
		generator: "0123456789abcdef0123456789abcdef01234567",
	}
	if err := os.WriteFile(ov.readme, []byte(readme), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ov.workflow, []byte("name: Backfill\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return ov
}

func show(t *testing.T, rev string) string {
	t.Helper()
	out, err := git(nil, "show", rev)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOverlayAppliedOnTopOnlyWhenChanged(t *testing.T) {
	newRepo(t)
	stage(t, "nvd", "sha256:n1", 100, map[string]string{"a.yaml": "1"})
	ov := testOverlay(t, "v1")

	if _, err := run([]candidate{cand("nvd", "sha256:n1", 150)}, ov); err != nil {
		t.Fatal(err)
	}
	if got := show(t, changelogRef+":README.md"); got != "v1" {
		t.Fatalf("README.md = %q", got)
	}
	if got := show(t, changelogRef+":"+overlayWorkflow); got != "name: Backfill" {
		t.Fatalf("%s = %q", overlayWorkflow, got)
	}
	msg, _ := git(nil, "log", "-1", "--format=%s%n%(trailers:key=Generator-Commit,valueonly)%n%ct %at", changelogRef)
	if want := overlaySubject + "\n" + ov.generator + "\n\n150 150"; msg != want {
		t.Fatalf("overlay commit = %q, want %q", msg, want)
	}
	if got := show(t, changelogRef+"~1:nvd/a.yaml"); got != "1" {
		t.Fatalf("overlay's parent should be the nvd snapshot, has a.yaml = %q", got)
	}

	// The next snapshot carries the overlay forward; unchanged, it isn't
	// committed again.
	stage(t, "nvd", "sha256:n2", 200, map[string]string{"a.yaml": "2"})
	if _, err := run([]candidate{cand("nvd", "sha256:n2", 250)}, ov); err != nil {
		t.Fatal(err)
	}
	if got := subjects(t); len(got) != 3 || got[2] != "nvd@sha256:n2" {
		t.Fatalf("subjects = %v, want the nvd snapshot at the tip", got)
	}
	if got := show(t, changelogRef+":README.md"); got != "v1" {
		t.Fatalf("README.md not carried forward: %q", got)
	}
	if out, _ := git(nil, "diff-tree", "--name-only", "-r", "--no-commit-id", changelogRef); out != "nvd/a.yaml" {
		t.Fatalf("data commit touched %q, want only nvd/a.yaml", out)
	}

	// A README change is committed even when nothing new is chained.
	ov = testOverlay(t, "v2")
	if _, err := run(nil, ov); err != nil {
		t.Fatal(err)
	}
	if got := show(t, changelogRef+":README.md"); got != "v2" {
		t.Fatalf("README.md = %q, want v2", got)
	}
	if out, _ := git(nil, "log", "-1", "--format=%s %ct", changelogRef); out != overlaySubject+" 250" {
		t.Fatalf("tip = %q", out)
	}
}

func TestOverlayNeedsAChain(t *testing.T) {
	newRepo(t)
	if _, err := run(nil, testOverlay(t, "v1")); err != nil {
		t.Fatal(err)
	}
	if _, err := git(nil, "rev-parse", "--verify", "--quiet", changelogRef); err == nil {
		t.Fatal("created the changelog branch with no snapshots in it")
	}
}

// The dispatcher's triggers must match backfill.yml's: once "changelog" is
// the default branch, only the dispatcher's schedule fires.
func TestDispatcherMatchesBackfill(t *testing.T) {
	load := func(p string) map[string]any {
		b, err := os.ReadFile(filepath.Join("..", "..", ".github", p))
		if err != nil {
			t.Fatal(err)
		}
		var w map[string]any
		if err := yaml.Unmarshal(b, &w); err != nil {
			t.Fatal(err)
		}
		return w["on"].(map[string]any)
	}
	backfill, dispatcher := load("workflows/backfill.yml"), load("changelog-dispatcher.yml")
	if !reflect.DeepEqual(backfill["schedule"], dispatcher["schedule"]) {
		t.Errorf("schedules differ:\nbackfill.yml:   %v\ndispatcher.yml: %v", backfill["schedule"], dispatcher["schedule"])
	}
	if !reflect.DeepEqual(backfill["workflow_dispatch"], dispatcher["workflow_dispatch"]) {
		t.Errorf("workflow_dispatch inputs differ")
	}
	calls, ok := backfill["workflow_call"].(map[string]any)
	if !ok {
		t.Fatal("backfill.yml has no workflow_call trigger")
	}
	for name := range backfill["workflow_dispatch"].(map[string]any)["inputs"].(map[string]any) {
		if _, ok := calls["inputs"].(map[string]any)[name]; !ok {
			t.Errorf("workflow_call has no %q input", name)
		}
	}
	b, _ := os.ReadFile(filepath.Join("..", "..", ".github", "changelog-dispatcher.yml"))
	if !strings.Contains(string(b), "uses: bored-engineer/grype-db-changelog/.github/workflows/backfill.yml@generator") {
		t.Error("dispatcher doesn't call backfill.yml@generator")
	}
}
