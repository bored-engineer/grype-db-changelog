// changelog builds one combined commit on refs/heads/changelog for a given
// calendar day, splicing together whichever providers published a new
// refs/raw/grype/<provider>/<date> commit that day with whatever was already
// present for every other provider in the previous changelog commit.
//
// Run from inside the target git repository (it shells out to plumbing
// commands rather than using a git library, matching trivy-db-changelog's
// own ls-tree/mktree/commit-tree approach: it only ever references existing
// tree/blob objects by SHA, so it never re-reads blob content).
package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
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

// providerRef matches one refs/raw/grype/<provider>/<date> ref.
type providerRef struct {
	provider string
	commit   string
}

// providersAt lists every refs/raw/grype/<provider>/<date> ref that exists
// for exactly this date.
func providersAt(date string) ([]providerRef, error) {
	out, err := git(nil, "for-each-ref", "--format=%(refname) %(objectname)", "refs/raw/grype/*/"+date)
	if err != nil {
		return nil, fmt.Errorf("for-each-ref failed: %w", err)
	}
	var refs []providerRef
	if out == "" {
		return refs, nil
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("unexpected for-each-ref line: %q", line)
		}
		// refs/raw/grype/<provider>/<date>
		parts := strings.Split(fields[0], "/")
		if len(parts) != 5 {
			return nil, fmt.Errorf("unexpected ref name: %q", fields[0])
		}
		refs = append(refs, providerRef{provider: parts[3], commit: fields[1]})
	}
	return refs, nil
}

// existingProviders returns the provider->tree-sha map already present
// under providers/ in the given changelog commit's tree ("" if there is no
// previous commit, i.e. this is the first day being built).
func existingProviders(commit string) (map[string]string, error) {
	providers := map[string]string{}
	if commit == "" {
		return providers, nil
	}
	treeSHA, err := git(nil, "rev-parse", "--verify", commit+":providers")
	if err != nil {
		// No providers/ directory yet at all.
		return providers, nil
	}
	out, err := git(nil, "ls-tree", treeSHA)
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

func buildDay(date string) error {
	prevCommit, err := git(nil, "rev-parse", "--verify", changelogRef)
	if err != nil {
		prevCommit = "" // first run: no previous changelog commit yet
	}

	tree, err := existingProviders(prevCommit)
	if err != nil {
		return fmt.Errorf("existingProviders failed: %w", err)
	}

	refs, err := providersAt(date)
	if err != nil {
		return fmt.Errorf("providersAt failed: %w", err)
	}
	if len(refs) == 0 && prevCommit == "" {
		return fmt.Errorf("no refs/raw/grype/*/%s refs found and no previous changelog commit to carry forward", date)
	}

	var advanced []string // provider names, for the commit message
	var parents []string
	if prevCommit != "" {
		parents = append(parents, prevCommit)
	}
	for _, ref := range refs {
		subtree, err := git(nil, "rev-parse", "--verify", ref.commit+":providers/"+ref.provider)
		if err != nil {
			return fmt.Errorf("resolving providers/%s in %s failed: %w", ref.provider, ref.commit, err)
		}
		tree[ref.provider] = subtree
		parents = append(parents, ref.commit)
		advanced = append(advanced, ref.provider)
	}
	if len(parents) == 0 {
		return fmt.Errorf("no parents resolved for %s (nothing to commit)", date)
	}

	// Build providers/ itself, then the root tree wrapping it, reusing every
	// subtree by SHA (git mktree never re-reads blob content).
	names := make([]string, 0, len(tree))
	for name := range tree {
		names = append(names, name)
	}
	sort.Strings(names)

	var providersTreeInput bytes.Buffer
	for _, name := range names {
		fmt.Fprintf(&providersTreeInput, "040000 tree %s\t%s\n", tree[name], name)
	}
	providersTree, err := mktree(providersTreeInput.String())
	if err != nil {
		return fmt.Errorf("mktree for providers/ failed: %w", err)
	}

	rootTree, err := mktree(fmt.Sprintf("040000 tree %s\tproviders\n", providersTree))
	if err != nil {
		return fmt.Errorf("mktree for root failed: %w", err)
	}

	sort.Strings(advanced)
	message := fmt.Sprintf("%s: %s", date, strings.Join(advanced, ", "))
	if len(advanced) == 0 {
		message = fmt.Sprintf("%s: (no provider updates; carried forward)", date)
	}

	// date is the same "YY-MM-DD" form used by the ghcr.io tags (and so the
	// refs/raw/grype/<provider>/<date> ref names); "06-01-02" is Go's
	// reference layout for that two-digit-year form.
	commitTime, err := time.Parse("06-01-02", date)
	if err != nil {
		return fmt.Errorf("time.Parse failed: %w", err)
	}
	env := []string{
		fmt.Sprintf("GIT_AUTHOR_NAME=grype-db-changelog"),
		fmt.Sprintf("GIT_AUTHOR_EMAIL=41898282+github-actions[bot]@users.noreply.github.com"),
		fmt.Sprintf("GIT_AUTHOR_DATE=%d +0000", commitTime.Unix()),
		fmt.Sprintf("GIT_COMMITTER_NAME=grype-db-changelog"),
		fmt.Sprintf("GIT_COMMITTER_EMAIL=41898282+github-actions[bot]@users.noreply.github.com"),
		fmt.Sprintf("GIT_COMMITTER_DATE=%d +0000", commitTime.Unix()),
	}

	commitArgs := []string{"commit-tree", rootTree}
	for _, p := range parents {
		commitArgs = append(commitArgs, "-p", p)
	}
	commitArgs = append(commitArgs, "-m", message)
	newCommit, err := git(env, commitArgs...)
	if err != nil {
		return fmt.Errorf("commit-tree failed: %w", err)
	}

	updateArgs := []string{"update-ref", changelogRef, newCommit}
	if prevCommit != "" {
		updateArgs = append(updateArgs, prevCommit)
	}
	if _, err := git(nil, updateArgs...); err != nil {
		return fmt.Errorf("update-ref failed: %w", err)
	}

	fmt.Println(newCommit)
	return nil
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

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <YY-MM-DD>\n", os.Args[0])
		os.Exit(1)
	}
	if err := buildDay(os.Args[1]); err != nil {
		log.Fatal(err)
	}
}
