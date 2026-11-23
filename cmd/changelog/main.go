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
// Run from inside the target git repository (it shells out to plumbing
// commands rather than using a git library: it only ever references
// existing tree objects by SHA, so it never re-reads blob content and
// works in a blob-less partial clone).
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
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

// existingProviders returns the provider->tree-sha map already present at
// the root of the given changelog commit's tree (empty if there is no
// previous commit, i.e. nothing has been built yet).
func existingProviders(commit string) (map[string]string, error) {
	providers := map[string]string{}
	if commit == "" {
		return providers, nil
	}
	out, err := git(nil, "ls-tree", commit)
	if err != nil {
		return nil, fmt.Errorf("ls-tree failed: %w", err)
	}
	if out == "" {
		return providers, nil
	}
	for _, line := range strings.Split(out, "\n") {
		// "<mode> <type> <sha>\t<name>"
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			return nil, fmt.Errorf("unexpected ls-tree line: %q", line)
		}
		name := line[tab+1:]
		fields := strings.Fields(line[:tab])
		if len(fields) != 3 {
			return nil, fmt.Errorf("unexpected ls-tree entry: %q", line)
		}
		providers[name] = fields[2]
	}
	return providers, nil
}

// candidate mirrors one entry of the discover job's output.
type candidate struct {
	Provider string `json:"provider"`
	Digest   string `json:"digest"`
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
	// date is the raw commit's committer timestamp (vunnel's capture
	// time), both as unix seconds for ordering and ISO 8601 for reuse.
	unix    int64
	date    string
	message string
	index   int
}

// resolve looks up the candidate's staged refs/raw ref. ok is false if it
// doesn't exist locally (the export leg for it may have failed).
func resolve(c candidate, index int) (s snapshot, ok bool, err error) {
	ref := rawRef(c.Provider, c.Digest)
	if _, err := git(nil, "rev-parse", "--verify", "--quiet", ref+"^{commit}"); err != nil {
		return snapshot{}, false, nil
	}

	// One call for both: "<unix>\x00<iso>\x00<full message>".
	out, err := git(nil, "log", "-1", "--format=%ct%x00%cI%x00%B", ref)
	if err != nil {
		return snapshot{}, false, fmt.Errorf("reading %s's commit failed: %w", ref, err)
	}
	parts := strings.SplitN(out, "\x00", 3)
	if len(parts) != 3 {
		return snapshot{}, false, fmt.Errorf("unexpected log output for %s: %q", ref, out)
	}
	unix, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return snapshot{}, false, fmt.Errorf("parsing %s's committer time %q failed: %w", ref, parts[0], err)
	}
	s = snapshot{
		provider: c.Provider,
		ref:      ref,
		unix:     unix,
		date:     parts[1],
		message:  strings.TrimRight(parts[2], "\n"),
		index:    index,
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

// order interleaves the snapshots by capture time while preserving each
// provider's own relative order exactly: a k-way merge of the
// per-provider queues, always taking the queue whose head was captured
// earliest. The input order (GHCR publish time) can disagree with capture
// time across providers - nvd captured before github but published after
// it, say - and a plain sort by capture time could also reorder a single
// provider's snapshots if its capture times are ever non-monotonic, which
// would make that provider's tree go back in time. Merging can't.
func order(snaps []snapshot) []snapshot {
	queues := map[string][]snapshot{}
	var providers []string
	for _, s := range snaps {
		if _, ok := queues[s.provider]; !ok {
			providers = append(providers, s.provider)
		}
		queues[s.provider] = append(queues[s.provider], s)
	}
	out := make([]snapshot, 0, len(snaps))
	for len(out) < len(snaps) {
		best := ""
		for _, p := range providers {
			q := queues[p]
			if len(q) == 0 {
				continue
			}
			if best == "" {
				best = p
				continue
			}
			b := queues[best][0]
			if q[0].unix < b.unix || (q[0].unix == b.unix && q[0].index < b.index) {
				best = p
			}
		}
		out = append(out, queues[best][0])
		queues[best] = queues[best][1:]
	}
	return out
}

// buildOne advances tree (provider -> subtree SHA, mutated in place) onto
// a new commit chaining onto parent (which may be "").
func buildOne(tree map[string]string, parent string, s snapshot) (string, error) {
	switch {
	case s.carry:
		// Tree unchanged: the commit records the build without
		// pretending its (nonexistent) data replaced the last snapshot.
	case s.subtree == "":
		// A zero-record snapshot is mirrored faithfully: git can't
		// represent an empty directory, so the provider's directory goes.
		delete(tree, s.provider)
	default:
		tree[s.provider] = s.subtree
	}

	names := make([]string, 0, len(tree))
	for name := range tree {
		names = append(names, name)
	}
	sort.Strings(names)

	var rootTreeInput bytes.Buffer
	for _, name := range names {
		fmt.Fprintf(&rootTreeInput, "040000 tree %s\t%s\n", tree[name], name)
	}
	rootTree, err := mktree(rootTreeInput.String())
	if err != nil {
		return "", fmt.Errorf("mktree for root failed: %w", err)
	}

	env := []string{
		"GIT_AUTHOR_NAME=grype-db-changelog",
		"GIT_AUTHOR_EMAIL=41898282+github-actions[bot]@users.noreply.github.com",
		"GIT_AUTHOR_DATE=" + s.date,
		"GIT_COMMITTER_NAME=grype-db-changelog",
		"GIT_COMMITTER_EMAIL=41898282+github-actions[bot]@users.noreply.github.com",
		"GIT_COMMITTER_DATE=" + s.date,
	}
	commitArgs := []string{"commit-tree", rootTree}
	if parent != "" {
		commitArgs = append(commitArgs, "-p", parent)
	}
	commitArgs = append(commitArgs, "-m", s.message)
	newCommit, err := git(env, commitArgs...)
	if err != nil {
		return "", fmt.Errorf("commit-tree failed: %w", err)
	}
	return newCommit, nil
}

// run chains the longest prefix of candidates (oldest first) whose raw
// refs all exist, and returns the raw refs it chained. It stops at the
// first missing one instead of skipping it: a skipped snapshot would be
// chained by some later run on top of NEWER snapshots of the same
// provider, making that provider's tree jump back in time and forward
// again.
func run(candidates []candidate) ([]string, error) {
	var snaps []snapshot
	for i, c := range candidates {
		s, ok, err := resolve(c, i)
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
		return nil, nil
	}

	prevCommit, err := git(nil, "rev-parse", "--verify", "--quiet", changelogRef)
	if err != nil {
		prevCommit = "" // first run: no previous changelog commit yet
	}
	tree, err := existingProviders(prevCommit)
	if err != nil {
		return nil, fmt.Errorf("existingProviders failed: %w", err)
	}

	parent := prevCommit
	chained := make([]string, 0, len(snaps))
	for _, s := range order(snaps) {
		newCommit, err := buildOne(tree, parent, s)
		if err != nil {
			return nil, fmt.Errorf("buildOne(%s) failed: %w", s.ref, err)
		}
		parent = newCommit
		chained = append(chained, s.ref)
	}

	updateArgs := []string{"update-ref", changelogRef, parent}
	if prevCommit != "" {
		updateArgs = append(updateArgs, prevCommit)
	}
	if _, err := git(nil, updateArgs...); err != nil {
		return nil, fmt.Errorf("update-ref failed: %w", err)
	}

	log.Printf("built %d commit(s), new tip %s", len(chained), parent)
	return chained, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <candidates.json|->\n", os.Args[0])
		os.Exit(1)
	}

	var b []byte
	var err error
	if os.Args[1] == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(os.Args[1])
	}
	if err != nil {
		log.Fatalf("reading candidates failed: %v", err)
	}

	var candidates []candidate
	if err := json.Unmarshal(b, &candidates); err != nil {
		log.Fatalf("json.Unmarshal failed: %v", err)
	}

	chained, err := run(candidates)
	if err != nil {
		log.Fatal(err)
	}
	for _, ref := range chained {
		fmt.Println(ref)
	}
}
