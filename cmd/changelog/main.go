// changelog advances refs/heads/changelog by chaining one commit per
// exported provider snapshot as a plain single-parent chain (not a merge)
// - mirrors trivy-db-changelog's update-changelog.sh, generalized to carry
// forward every OTHER provider's unchanged subtree each time just one
// provider's snapshot advances.
//
// A real merge parent into the exported snapshot commit was this repo's
// own earlier design, and is rejected here for the same reason
// trivy-db-changelog moved off an equivalent design: a merge parent whose
// tree is reused unchanged for every "carried forward" provider is
// TREESAME to the whole prior tree, which makes `git log -- <provider>`
// (even with --diff-filter=A) collapse to the wrong commit under git's
// default history simplification. A plain chain has no such ambiguity.
//
// The changelog branch is the single source of truth for what has been
// chained: each commit's subject names the provider and digest it came
// from. refs/raw/<provider>/<digest> is only a staging area between the
// export jobs and this one - every ref this tool chains is printed to
// stdout (one per line) so the caller can delete it in the same atomic
// push that advances the branch.
//
// With -readme/-workflow/-generator it also copies generator's README.md
// and a thin dispatcher workflow onto the branch (see applyOverlay), so
// "changelog" can be the repository's default branch.
//
// Run from inside the target git repository (it shells out to plumbing
// commands rather than using a git library: it only ever references
// existing tree objects by SHA, so it never re-reads blob content and
// works in a blob-less partial clone).
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
	"time"
)

const changelogRef = "refs/heads/changelog"

// emptyBuildTrailer marks a staged snapshot of an upstream build that was
// published as an empty tarball. Must match cmd/export's copy.
const emptyBuildTrailer = "Empty-Build: true"

func git(env []string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Env = append(os.Environ(), env...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s failed: %w: %s", strings.Join(args, " "), err, errb.String())
	}
	return strings.TrimRight(out.String(), "\n"), nil
}

func mktree(input string) (string, error) {
	cmd := exec.Command("git", "mktree")
	cmd.Stdin = strings.NewReader(input)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git mktree failed: %w: %s", err, errb.String())
	}
	return strings.TrimRight(out.String(), "\n"), nil
}

// entry is one root tree entry of a changelog commit: a provider's
// directory, or one of the overlay files (README.md, .github/).
type entry struct{ mode, typ, sha string }

// rootEntries returns the entries at the root of the given changelog
// commit's tree (empty if there is no previous commit, i.e. nothing has
// been built yet). Data commits carry every entry they don't change
// forward, so the overlay stays in place under newer snapshots.
func rootEntries(commit string) (map[string]entry, error) {
	entries := map[string]entry{}
	if commit == "" {
		return entries, nil
	}
	out, err := git(nil, "ls-tree", commit)
	if err != nil {
		return nil, fmt.Errorf("ls-tree failed: %w", err)
	}
	if out == "" {
		return entries, nil
	}
	for _, line := range strings.Split(out, "\n") {
		// "<mode> <type> <sha>\t<name>"
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			return nil, fmt.Errorf("unexpected ls-tree line: %q", line)
		}
		fields := strings.Fields(line[:tab])
		if len(fields) != 3 {
			return nil, fmt.Errorf("unexpected ls-tree entry: %q", line)
		}
		entries[line[tab+1:]] = entry{fields[0], fields[1], fields[2]}
	}
	return entries, nil
}

// writeTree writes the root tree for the given entries.
func writeTree(tree map[string]entry) (string, error) {
	names := make([]string, 0, len(tree))
	for name := range tree {
		names = append(names, name)
	}
	sort.Strings(names)
	var in bytes.Buffer
	for _, name := range names {
		e := tree[name]
		fmt.Fprintf(&in, "%s %s %s\t%s\n", e.mode, e.typ, e.sha, name)
	}
	return mktree(in.String())
}

// candidate mirrors one entry of the discover job's output, which lists
// them in the order they are to be chained: GHCR publish order.
type candidate struct {
	Provider string `json:"provider"`
	Digest   string `json:"digest"`
	// Created is the GHCR publish time (RFC 3339). It dates the commit.
	Created string `json:"created"`
}

func rawRef(provider, digest string) string {
	return "refs/raw/" + provider + "/" + strings.ReplaceAll(digest, ":", "-")
}

// snapshot is one resolved, ready-to-chain exported snapshot.
type snapshot struct {
	provider string
	ref      string
	// subtree is the provider's directory tree, or "" if the snapshot
	// had zero records (fast-import then commits an empty tree, so there
	// is no <provider>/ directory to resolve).
	subtree string
	// carry is set for an empty upstream build: the provider's previous
	// subtree is kept as-is (an empty commit), rather than mirroring a
	// build that never had any data as every record being deleted.
	carry bool
	// published is the GHCR publish time, which dates the changelog
	// commit; captured is the raw commit's committer time (the build's
	// own capture time), recorded in a trailer.
	published string
	captured  string
	message   string
}

// capturedTrailer records a snapshot's capture time on its changelog
// commit, whose dates are the publish time.
const capturedTrailer = "Captured: "

// resolve looks up the candidate's staged refs/raw ref. ok is false if it
// doesn't exist locally (the export leg for it may have failed).
func resolve(c candidate) (s snapshot, ok bool, err error) {
	ref := rawRef(c.Provider, c.Digest)
	published, err := time.Parse(time.RFC3339, c.Created)
	if err != nil {
		return snapshot{}, false, fmt.Errorf("%s %s has no valid publish time %q: %w", c.Provider, c.Digest, c.Created, err)
	}
	if _, err := git(nil, "rev-parse", "--verify", "--quiet", ref+"^{commit}"); err != nil {
		return snapshot{}, false, nil
	}

	// One call for both: "<iso>\x00<full message>".
	out, err := git(nil, "log", "-1", "--format=%cI%x00%B", ref)
	if err != nil {
		return snapshot{}, false, fmt.Errorf("reading %s's commit failed: %w", ref, err)
	}
	parts := strings.SplitN(out, "\x00", 2)
	if len(parts) != 2 {
		return snapshot{}, false, fmt.Errorf("unexpected log output for %s: %q", ref, out)
	}
	s = snapshot{
		provider:  c.Provider,
		ref:       ref,
		published: published.UTC().Format(time.RFC3339),
		captured:  parts[0],
		message:   strings.TrimRight(parts[1], "\n"),
	}
	for _, line := range strings.Split(s.message, "\n") {
		if line == emptyBuildTrailer {
			s.carry = true
			return s, true, nil
		}
	}

	subtree, err := git(nil, "rev-parse", "--verify", "--quiet", ref+":"+c.Provider)
	if err != nil {
		// Only acceptable if the snapshot is genuinely empty - anything
		// else at the root means the export wrote something unexpected.
		entries, lsErr := git(nil, "ls-tree", ref)
		if lsErr != nil {
			return snapshot{}, false, fmt.Errorf("ls-tree %s failed: %w", ref, lsErr)
		}
		if entries != "" {
			return snapshot{}, false, fmt.Errorf("%s has no %s/ directory but is not empty:\n%s", ref, c.Provider, entries)
		}
		subtree = ""
	}
	s.subtree = subtree
	return s, true, nil
}

// buildOne advances tree (root name -> entry, mutated in place) onto
// a new commit chaining onto parent (which may be "").
func buildOne(tree map[string]entry, parent string, s snapshot) (string, error) {
	switch {
	case s.carry:
		// Tree unchanged: the commit records the build without
		// pretending its (nonexistent) data replaced the last snapshot.
	case s.subtree == "":
		// A zero-record snapshot is mirrored faithfully: git can't
		// represent an empty directory, so the provider's directory goes.
		delete(tree, s.provider)
	default:
		tree[s.provider] = entry{"040000", "tree", s.subtree}
	}

	rootTree, err := writeTree(tree)
	if err != nil {
		return "", fmt.Errorf("mktree for root failed: %w", err)
	}

	commitArgs := []string{"commit-tree", rootTree}
	if parent != "" {
		commitArgs = append(commitArgs, "-p", parent)
	}
	commitArgs = append(commitArgs, "-m", withTrailer(s.message, capturedTrailer+s.captured))
	newCommit, err := git(botEnv(s.published), commitArgs...)
	if err != nil {
		return "", fmt.Errorf("commit-tree failed: %w", err)
	}
	return newCommit, nil
}

func botEnv(date string) []string {
	return []string{
		"GIT_AUTHOR_NAME=grype-db-changelog",
		"GIT_AUTHOR_EMAIL=41898282+github-actions[bot]@users.noreply.github.com",
		"GIT_AUTHOR_DATE=" + date,
		"GIT_COMMITTER_NAME=grype-db-changelog",
		"GIT_COMMITTER_EMAIL=41898282+github-actions[bot]@users.noreply.github.com",
		"GIT_COMMITTER_DATE=" + date,
	}
}

// overlay is what applyOverlay copies onto the changelog branch.
type overlay struct {
	readme   string // local path of generator's README.md
	workflow string // local path of the dispatcher, committed as overlayWorkflow
	// generator is the generator commit both were read from.
	generator string
	// updateWorkflow lets the workflow be created or changed. GitHub
	// refuses any push that does that from an Actions token ("refusing to
	// allow a GitHub App to create or update workflow ... without
	// `workflows` permission"), so the backfill job leaves it off and a
	// change to the dispatcher is pushed by hand, once, with this set.
	// Snapshot and README commits carry the file forward unchanged, which
	// GitHub allows.
	updateWorkflow bool
}

const (
	overlayWorkflow  = ".github/workflows/backfill.yml"
	overlaySubject   = "docs: update README and workflows from generator"
	generatorTrailer = "Generator-Commit: "
)

// applyOverlay puts generator's README.md and the dispatcher workflow at
// the root of the changelog branch, so the branch is browsable on its own
// and, as the repository's default branch, still has a workflow GitHub
// will schedule. It commits on top of parent only when they differ from
// what's already there, which data commits carry forward unchanged, so
// it's a commit per generator change, not per run. The whole .github/
// directory is replaced: nothing else on the branch lives there.
//
// Without ov.updateWorkflow, .github/ is left exactly as the tip has it,
// and a mismatch with the dispatcher is only warned about (see overlay).
//
// The commit is dated like its parent, not "now": a build published
// between this run's listing and its commit would otherwise be chained
// next run with a date earlier than this commit's.
func applyOverlay(tree map[string]entry, parent string, ov overlay) (string, error) {
	readme, err := git(nil, "hash-object", "-w", "--", ov.readme)
	if err != nil {
		return "", err
	}
	workflow, err := git(nil, "hash-object", "-w", "--", ov.workflow)
	if err != nil {
		return "", err
	}
	workflows, err := mktree(fmt.Sprintf("100644 blob %s\t%s\n", workflow, path.Base(overlayWorkflow)))
	if err != nil {
		return "", err
	}
	github, err := mktree(fmt.Sprintf("040000 tree %s\t%s\n", workflows, path.Base(path.Dir(overlayWorkflow))))
	if err != nil {
		return "", err
	}
	tree["README.md"] = entry{"100644", "blob", readme}
	dotGithub := path.Dir(path.Dir(overlayWorkflow))
	if ov.updateWorkflow {
		tree[dotGithub] = entry{"040000", "tree", github}
	} else if tree[dotGithub].sha != github {
		log.Printf("::warning::%s on the changelog branch differs from generator's dispatcher; "+
			"an Actions token can't push workflow changes, so push it by hand: "+
			"go run ./cmd/changelog -update-workflow -readme README.md -workflow .github/changelog-dispatcher.yml -generator $(git rev-parse HEAD) - <<< '[]'",
			overlayWorkflow)
	}

	root, err := writeTree(tree)
	if err != nil {
		return "", fmt.Errorf("mktree for root failed: %w", err)
	}
	if parentTree, err := git(nil, "rev-parse", parent+"^{tree}"); err != nil {
		return "", err
	} else if root == parentTree {
		return parent, nil
	}
	date, err := git(nil, "log", "-1", "--format=%cI", parent)
	if err != nil {
		return "", err
	}
	commit, err := git(botEnv(date), "commit-tree", root, "-p", parent, "-m", overlaySubject, "-m", generatorTrailer+ov.generator)
	if err != nil {
		return "", fmt.Errorf("commit-tree failed: %w", err)
	}
	return commit, nil
}

// withTrailer appends a trailer line to message, joining its existing
// trailer block if its last paragraph is one (e.g. "Empty-Build: true").
func withTrailer(message, trailer string) string {
	paras := strings.Split(message, "\n\n")
	if len(paras) > 1 {
		last := paras[len(paras)-1]
		isTrailers := true
		for _, line := range strings.Split(last, "\n") {
			if k, _, ok := strings.Cut(line, ": "); !ok || k == "" || strings.ContainsAny(k, " \t") {
				isTrailers = false
				break
			}
		}
		if isTrailers {
			return message + "\n" + trailer
		}
	}
	return message + "\n\n" + trailer
}

// run chains the longest prefix of candidates whose raw refs all exist,
// in the order given (GHCR publish order, oldest first), and returns the
// raw refs it chained. It stops at the first missing one instead of
// skipping it: a skipped snapshot would have to be chained later on top of
// snapshots published after it, and the changelog's dates would go
// backwards.
//
// Publish order, not capture order: the chain is append-only, and a build
// can be published days after its capture time (seen: 5.6 days for nvd),
// so ordering by capture time would mean inserting into the past. Within
// each provider the two orders agree.
//
// With ov set, the overlay is applied on top afterwards (see applyOverlay),
// even if nothing new was chained.
func run(candidates []candidate, ov *overlay) ([]string, error) {
	var snaps []snapshot
	for i, c := range candidates {
		s, ok, err := resolve(c)
		if err != nil {
			return nil, fmt.Errorf("resolve(%s, %s) failed: %w", c.Provider, c.Digest, err)
		}
		if !ok {
			log.Printf("stopping at %s %s: %s not found locally (export may have failed); %d later candidate(s) deferred to the next run",
				c.Provider, c.Digest, rawRef(c.Provider, c.Digest), len(candidates)-i-1)
			break
		}
		snaps = append(snaps, s)
	}

	if len(snaps) == 0 {
		log.Print("nothing new to build")
		if ov == nil {
			return nil, nil
		}
	}

	prevCommit, err := git(nil, "rev-parse", "--verify", "--quiet", changelogRef)
	if err != nil {
		prevCommit = "" // first run: no previous changelog commit yet
	}
	tree, err := rootEntries(prevCommit)
	if err != nil {
		return nil, fmt.Errorf("rootEntries failed: %w", err)
	}

	parent := prevCommit
	chained := make([]string, 0, len(snaps))
	for _, s := range snaps {
		newCommit, err := buildOne(tree, parent, s)
		if err != nil {
			return nil, fmt.Errorf("buildOne(%s) failed: %w", s.ref, err)
		}
		parent = newCommit
		chained = append(chained, s.ref)
	}
	if ov != nil && parent != "" {
		if parent, err = applyOverlay(tree, parent, *ov); err != nil {
			return nil, fmt.Errorf("applyOverlay failed: %w", err)
		}
	}
	if parent == prevCommit {
		return chained, nil
	}

	updateArgs := []string{"update-ref", changelogRef, parent}
	if prevCommit != "" {
		updateArgs = append(updateArgs, prevCommit)
	}
	if _, err := git(nil, updateArgs...); err != nil {
		return nil, fmt.Errorf("update-ref failed: %w", err)
	}

	log.Printf("chained %d snapshot(s), new tip %s", len(chained), parent)
	return chained, nil
}

func main() {
	var ov overlay
	flag.StringVar(&ov.readme, "readme", "", "README.md to copy onto the branch")
	flag.StringVar(&ov.workflow, "workflow", "", "dispatcher workflow to copy onto the branch as "+overlayWorkflow)
	flag.StringVar(&ov.generator, "generator", "", "generator commit both files come from")
	flag.BoolVar(&ov.updateWorkflow, "update-workflow", false, "also create or update the workflow (needs a token with the workflows scope to push)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-readme FILE -workflow FILE -generator SHA] <candidates.json|->\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}
	var ovp *overlay
	switch set := ov.readme != "" || ov.workflow != "" || ov.generator != ""; {
	case set && (ov.readme == "" || ov.workflow == "" || ov.generator == ""):
		log.Fatal("-readme, -workflow and -generator go together")
	case set:
		ovp = &ov
	}

	var b []byte
	var err error
	if flag.Arg(0) == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(flag.Arg(0))
	}
	if err != nil {
		log.Fatalf("reading candidates failed: %v", err)
	}

	var candidates []candidate
	if err := json.Unmarshal(b, &candidates); err != nil {
		log.Fatalf("json.Unmarshal failed: %v", err)
	}

	chained, err := run(candidates, ovp)
	if err != nil {
		log.Fatal(err)
	}
	for _, ref := range chained {
		fmt.Println(ref)
	}
}
