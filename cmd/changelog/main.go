// changelog advances refs/heads/changelog by chaining one commit per
// exported provider snapshot, oldest first, as a plain single-parent chain
// (not a merge) - mirrors trivy-db-changelog's update-changelog.sh,
// generalized to carry forward every OTHER provider's unchanged subtree
// each time just one provider's snapshot advances.
//
// A real merge parent into refs/raw/<provider>/<digest> was this repo's
// own earlier design, and is rejected here for the same reason
// trivy-db-changelog moved off an equivalent design: a merge parent whose
// tree is reused unchanged for every "carried forward" provider is
// TREESAME to the whole prior tree, which makes `git log -- <provider>`
// (even with --diff-filter=A) collapse to the wrong commit
// under git's default history simplification - confirmed to be exactly
// what that repo hit for real. A plain chain has no such ambiguity. The
// raw commit a given change came from is still discoverable via an
// "Export-Commit: <sha>" trailer in the message, not a real parent edge.
//
// Run from inside the target git repository (it shells out to plumbing
// commands rather than using a git library, matching trivy-db-changelog's
// and this repo's own ls-tree/mktree/commit-tree approach: it only ever
// references existing tree/blob objects by SHA, so it never re-reads blob
// content).
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
	"strings"
)

const changelogRef = "refs/heads/changelog"

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
// the root of the given changelog commit's tree ("" if there is no
// previous commit, i.e. nothing has been built yet). The provider name is
// itself the top-level category here (no "providers/" wrapper directory -
// there's nothing above it to group), so this is just that commit's root
// tree.
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

// buildOne advances tree (provider -> subtree SHA, mutated in place) onto
// a new commit chaining onto parent (which may be ""), reusing the
// candidate's refs/raw/<provider>/<digest> ref's own (single top-level
// <provider>/ directory) tree and its committer date. ok is false if the
// ref doesn't exist locally - the matrix leg meant to export it may have
// failed (fail-fast is off) - in which case the caller should move on
// without advancing.
func buildOne(tree map[string]string, parent, provider, digest string) (newCommit string, ok bool, err error) {
	ref := "refs/raw/" + provider + "/" + strings.ReplaceAll(digest, ":", "-")
	refSHA, err := git(nil, "rev-parse", "--verify", "--quiet", ref)
	if err != nil {
		log.Printf("skipping %s %s: %s not found locally (export may have failed)", provider, digest, ref)
		return "", false, nil
	}

	subtree, err := git(nil, "rev-parse", "--verify", ref+":"+provider)
	if err != nil {
		return "", false, fmt.Errorf("resolving %s in %s failed: %w", provider, ref, err)
	}
	tree[provider] = subtree

	// The root tree itself - no "providers/" wrapper, since the provider
	// name is already the top-level category. Reuses every subtree by
	// SHA (git mktree never re-reads blob content).
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
		return "", false, fmt.Errorf("mktree for root failed: %w", err)
	}

	date, err := git(nil, "log", "-1", "--format=%cI", ref)
	if err != nil {
		return "", false, fmt.Errorf("resolving %s's committer date failed: %w", ref, err)
	}
	rawMessage, err := git(nil, "log", "-1", "--format=%B", ref)
	if err != nil {
		return "", false, fmt.Errorf("resolving %s's message failed: %w", ref, err)
	}
	message := strings.TrimRight(rawMessage, "\n") + "\n\nExport-Commit: " + refSHA

	env := []string{
		"GIT_AUTHOR_NAME=grype-db-changelog",
		"GIT_AUTHOR_EMAIL=41898282+github-actions[bot]@users.noreply.github.com",
		"GIT_AUTHOR_DATE=" + date,
		"GIT_COMMITTER_NAME=grype-db-changelog",
		"GIT_COMMITTER_EMAIL=41898282+github-actions[bot]@users.noreply.github.com",
		"GIT_COMMITTER_DATE=" + date,
	}
	commitArgs := []string{"commit-tree", rootTree}
	if parent != "" {
		commitArgs = append(commitArgs, "-p", parent)
	}
	commitArgs = append(commitArgs, "-m", message)
	newCommit, err = git(env, commitArgs...)
	if err != nil {
		return "", false, fmt.Errorf("commit-tree failed: %w", err)
	}
	return newCommit, true, nil
}

func run(candidates []candidate) error {
	prevCommit, err := git(nil, "rev-parse", "--verify", "--quiet", changelogRef)
	if err != nil {
		prevCommit = "" // first run: no previous changelog commit yet
	}

	tree, err := existingProviders(prevCommit)
	if err != nil {
		return fmt.Errorf("existingProviders failed: %w", err)
	}

	parent := prevCommit
	built := 0
	for _, c := range candidates {
		newCommit, ok, err := buildOne(tree, parent, c.Provider, c.Digest)
		if err != nil {
			return fmt.Errorf("buildOne(%s, %s) failed: %w", c.Provider, c.Digest, err)
		}
		if !ok {
			continue
		}
		parent = newCommit
		built++
	}

	if built == 0 {
		fmt.Fprintln(os.Stderr, "nothing new to build")
		return nil
	}

	updateArgs := []string{"update-ref", changelogRef, parent}
	if prevCommit != "" {
		updateArgs = append(updateArgs, prevCommit)
	}
	if _, err := git(nil, updateArgs...); err != nil {
		return fmt.Errorf("update-ref failed: %w", err)
	}

	fmt.Printf("built %d commit(s), new tip %s\n", built, parent)
	return nil
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

	if err := run(candidates); err != nil {
		log.Fatal(err)
	}
}
