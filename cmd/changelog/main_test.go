package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/bored-engineer/grype-db-changelog/internal/providers"
)

// mustGit runs a git command in the current directory (the test's temp
// repo), failing the test on error.
func mustGit(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestBuildDayRemovesPastEnd(t *testing.T) {
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(cwd)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	mustGit(t, "init", "-q")

	makeRef := func(provider, date, content string) {
		path := "providers/" + provider + "/x.yaml"
		if err := os.MkdirAll("providers/"+provider, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		mustGit(t, "add", path)
		treeSHA := mustGit(t, "write-tree")
		commitSHA := mustGit(t, "commit-tree", treeSHA, "-m", provider+" "+date)
		mustGit(t, "update-ref", "refs/raw/grype/"+provider+"/"+date, commitSHA)
		// reset the index so the next makeRef call starts clean
		mustGit(t, "read-tree", "--empty")
	}

	day1, _ := time.Parse(providers.DateLayout, "26-01-01")
	manifest := map[string]providers.Provider{
		"alive": {Start: day1},
		"gone":  {Start: day1, End: &day1}, // confirmed removed as of day1
	}

	makeRef("alive", "26-01-01", "alive v1")
	makeRef("gone", "26-01-01", "gone v1")
	if err := buildDay("26-01-01", manifest); err != nil {
		t.Fatalf("buildDay(day1) failed: %v", err)
	}

	// day1 itself must still include "gone" - End is inclusive of the day
	// it's confirmed on, removal only takes effect strictly after it.
	out := mustGit(t, "ls-tree", "-r", "--name-only", "refs/heads/changelog")
	if !strings.Contains(out, "providers/gone/x.yaml") {
		t.Fatalf("expected 'gone' still present on its end date, tree:\n%s", out)
	}

	// day2: no new ref for either provider.
	if err := buildDay("26-01-02", manifest); err != nil {
		t.Fatalf("buildDay(day2) failed: %v", err)
	}
	out = mustGit(t, "ls-tree", "-r", "--name-only", "refs/heads/changelog")
	if strings.Contains(out, "providers/gone/") {
		t.Fatalf("expected 'gone' to be dropped after its end date, tree:\n%s", out)
	}
	if !strings.Contains(out, "providers/alive/x.yaml") {
		t.Fatalf("expected 'alive' to still be carried forward, tree:\n%s", out)
	}

	subject := mustGit(t, "log", "-1", "--format=%s", "refs/heads/changelog")
	if !strings.Contains(subject, "removed: gone") {
		t.Fatalf("expected commit message to mention the removal, got: %q", subject)
	}

	// day3: "gone" unexpectedly publishes again - a fresh ref must always
	// win over a recorded (possibly mistaken) end date.
	makeRef("gone", "26-01-03", "gone is back")
	if err := buildDay("26-01-03", manifest); err != nil {
		t.Fatalf("buildDay(day3) failed: %v", err)
	}
	out = mustGit(t, "ls-tree", "-r", "--name-only", "refs/heads/changelog")
	if !strings.Contains(out, "providers/gone/x.yaml") {
		t.Fatalf("expected a fresh ref to override the recorded end date, tree:\n%s", out)
	}
}

func TestBuildDayWarnsOnStaleness(t *testing.T) {
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(cwd)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	mustGit(t, "init", "-q")

	makeRef := func(provider, date string) {
		path := "providers/" + provider + "/x.yaml"
		if err := os.MkdirAll("providers/"+provider, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(date), 0o644); err != nil {
			t.Fatal(err)
		}
		mustGit(t, "add", path)
		treeSHA := mustGit(t, "write-tree")
		commitSHA := mustGit(t, "commit-tree", treeSHA, "-m", provider+" "+date)
		mustGit(t, "update-ref", "refs/raw/grype/"+provider+"/"+date, commitSHA)
		mustGit(t, "read-tree", "--empty")
	}

	day1, _ := time.Parse(providers.DateLayout, "26-01-01")
	manifest := map[string]providers.Provider{
		"quiet": {Start: day1}, // no End recorded - not (yet) a confirmed removal
	}
	makeRef("quiet", "26-01-01")
	if err := buildDay("26-01-01", manifest); err != nil {
		t.Fatalf("buildDay(day1) failed: %v", err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStderr := os.Stderr
	os.Stderr = w
	buildErr := buildDay("26-01-20", manifest) // 19 days later, past staleWarnDays
	os.Stderr = origStderr
	w.Close()
	var buf [4096]byte
	n, _ := r.Read(buf[:])
	captured := string(buf[:n])

	if buildErr != nil {
		t.Fatalf("buildDay(day20) failed: %v", buildErr)
	}
	if !strings.Contains(captured, "quiet") || !strings.Contains(captured, "hasn't published") {
		t.Fatalf("expected a staleness warning for 'quiet', got stderr: %q", captured)
	}
	// Carried forward, not removed - no End date was ever recorded for it.
	out := mustGit(t, "ls-tree", "-r", "--name-only", "refs/heads/changelog")
	if !strings.Contains(out, "providers/quiet/x.yaml") {
		t.Fatalf("expected 'quiet' to still be carried forward (warn, don't remove), tree:\n%s", out)
	}
}
