package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// newRepo creates an empty git repository and chdirs into it for the
// duration of the test (run() operates on the current directory).
func newRepo(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if _, err := git(nil, "init", "-q"); err != nil {
		t.Fatal(err)
	}
}

// stage writes an orphan refs/raw/<provider>/<digest> commit the way
// cmd/export does: a single <provider>/ directory (or nothing at all, for
// an empty snapshot), committed at the given unix time.
func stage(t *testing.T, provider, digest string, unix int64, files map[string]string) {
	t.Helper()
	stageMsg(t, provider, digest, unix, files, "")
}

func stageMsg(t *testing.T, provider, digest string, unix int64, files map[string]string, body string) {
	t.Helper()
	var in strings.Builder
	ref := rawRef(provider, digest)
	msg := fmt.Sprintf("%s %d: ghcr.io/anchore/grype-db/data/%s@%s", provider, unix, provider, digest)
	if body != "" {
		msg += "\n\n" + body
	}
	fmt.Fprintf(&in, "reset %s\ncommit %s\ncommitter t <t@t> %d +0000\ndata %d\n%s\ndeleteall\n", ref, ref, unix, len(msg), msg)
	for name, body := range files {
		fmt.Fprintf(&in, "M 100644 inline %s/%s\ndata %d\n%s\n", provider, name, len(body), body)
	}
	cmd := gitCmd("fast-import", "--quiet")
	cmd.Stdin = strings.NewReader(in.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fast-import failed: %v: %s", err, out)
	}
}

func subjects(t *testing.T) []string {
	t.Helper()
	out, err := git(nil, "log", "--reverse", "--format=%s", changelogRef)
	if err != nil {
		t.Fatal(err)
	}
	var s []string
	for _, line := range strings.Split(out, "\n") {
		s = append(s, strings.Fields(line)[0]+"@"+line[strings.LastIndexByte(line, '@')+1:])
	}
	return s
}

func TestRunOrdersByCaptureTimeAndStopsAtMissing(t *testing.T) {
	newRepo(t)
	stage(t, "nvd", "sha256:n1", 100, map[string]string{"a.yaml": "1"})
	stage(t, "github", "sha256:g1", 50, map[string]string{"b.yaml": "1"})
	stage(t, "nvd", "sha256:n2", 200, map[string]string{"a.yaml": "2"})
	// sha256:g2 deliberately not staged (its export "failed").
	stage(t, "nvd", "sha256:n3", 300, map[string]string{"a.yaml": "3"})

	chained, err := run([]candidate{
		{"nvd", "sha256:n1"},
		{"github", "sha256:g1"},
		{"nvd", "sha256:n2"},
		{"github", "sha256:g2"},
		{"nvd", "sha256:n3"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// github@g1 was captured before nvd@n1 so goes first; n3 is after the
	// missing g2, so it must wait for the next run.
	want := []string{"github@sha256:g1", "nvd@sha256:n1", "nvd@sha256:n2"}
	if got := subjects(t); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("chain = %v, want %v", got, want)
	}
	if len(chained) != 3 || chained[0] != rawRef("github", "sha256:g1") {
		t.Fatalf("chained refs = %v", chained)
	}
	if got, _ := git(nil, "show", changelogRef+":nvd/a.yaml"); got != "2" {
		t.Fatalf("nvd/a.yaml = %q, want 2", got)
	}

	// Next run: g2 is now exported; continues from the existing tip and
	// carries github/ forward through nvd's commit.
	stage(t, "github", "sha256:g2", 250, map[string]string{"b.yaml": "2"})
	if _, err := run([]candidate{{"github", "sha256:g2"}, {"nvd", "sha256:n3"}}); err != nil {
		t.Fatal(err)
	}
	want = append(want, "github@sha256:g2", "nvd@sha256:n3")
	if got := subjects(t); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("chain = %v, want %v", got, want)
	}
	if got, _ := git(nil, "show", changelogRef+":github/b.yaml"); got != "2" {
		t.Fatalf("github/b.yaml = %q, want 2", got)
	}
}

func TestOrderNeverReordersWithinProvider(t *testing.T) {
	// nvd's capture times go backwards; its publish order must still win.
	got := order([]snapshot{
		{provider: "nvd", ref: "n1", unix: 300, index: 0},
		{provider: "github", ref: "g1", unix: 150, index: 1},
		{provider: "nvd", ref: "n2", unix: 100, index: 2},
	})
	var refs []string
	for _, s := range got {
		refs = append(refs, s.ref)
	}
	if want := "g1,n1,n2"; strings.Join(refs, ",") != want {
		t.Fatalf("order = %v, want %s", refs, want)
	}
}

func TestRunEmptySnapshotRemovesProvider(t *testing.T) {
	newRepo(t)
	stage(t, "echo", "sha256:e1", 100, map[string]string{"a.yaml": "1"})
	stage(t, "kev", "sha256:k1", 150, map[string]string{"a.yaml": "1"})
	stage(t, "echo", "sha256:e2", 200, nil)

	if _, err := run([]candidate{{"echo", "sha256:e1"}, {"kev", "sha256:k1"}, {"echo", "sha256:e2"}}); err != nil {
		t.Fatal(err)
	}
	out, err := git(nil, "ls-tree", "--name-only", changelogRef)
	if err != nil {
		t.Fatal(err)
	}
	if out != "kev" {
		t.Fatalf("root tree = %q, want just kev", out)
	}
}

func gitCmd(args ...string) *exec.Cmd { return exec.Command("git", args...) }

func TestRunEmptyBuildCarriesForward(t *testing.T) {
	newRepo(t)
	stage(t, "debian", "sha256:d1", 100, map[string]string{"a.yaml": "1"})
	// What cmd/export stages for a zero-entry upstream tarball.
	stageMsg(t, "debian", "sha256:d2", 200, nil, "Upstream published this build as an empty tarball.\n\n"+emptyBuildTrailer)
	stage(t, "debian", "sha256:d3", 300, map[string]string{"a.yaml": "3"})

	chained, err := run([]candidate{{"debian", "sha256:d1"}, {"debian", "sha256:d2"}, {"debian", "sha256:d3"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(chained) != 3 {
		t.Fatalf("chained = %v, want all 3 (the empty build must not block)", chained)
	}
	// d2's commit is empty: same tree as d1's, so debian never "vanishes".
	t1, _ := git(nil, "rev-parse", changelogRef+"~2^{tree}")
	t2, _ := git(nil, "rev-parse", changelogRef+"~1^{tree}")
	if t1 != t2 {
		t.Fatalf("empty build changed the tree: %s -> %s", t1, t2)
	}
	if got, _ := git(nil, "show", changelogRef+":debian/a.yaml"); got != "3" {
		t.Fatalf("debian/a.yaml = %q, want 3", got)
	}
	// Its subject still ends in provider@digest, so discover sees it as chained.
	if got := subjects(t); got[1] != "debian@sha256:d2" {
		t.Fatalf("chain = %v", got)
	}
}
