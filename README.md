# grype-db-changelog

A readable, diffable history of
[`anchore/grype-db`](https://github.com/anchore/grype-db)'s vulnerability
data, the feed behind the [Grype](https://github.com/anchore/grype) scanner.

## Why

Grype's database is built from per-provider snapshots that Anchore publishes
as OCI images, `ghcr.io/anchore/grype-db/data/<provider>`: one each for NVD,
GitHub advisories, Debian, Ubuntu, RHEL, Alpine, Wolfi and two dozen others.
Each provider is rebuilt at least once a day (amazon, fedora, github, nvd
and rhel three times). Every image carries a SQLite `results.db` of raw
JSON records. The only way to see what a provider said yesterday is to dig
the old digest out of the package's version history, download a multi-GB
image and query the database inside it.

That makes ordinary questions hard to answer. When did this CVE first show
up for my distro? When did the fixed version appear? Did a scan result
change because the vulnerability data changed underneath it? These are
useful when you're debugging a scanner finding or checking upstream's data
quality, and they're invisible once the next build lands.

This repo re-exports every build of every provider as git history. Each
record becomes one human-readable YAML file, and each upstream build
becomes one commit, so you can `git log`, `git diff` and `git blame` it like
any other codebase. The **`changelog`** branch holds 25,000+ snapshots
across 26 providers, going back to February 2023. The one provider left out
is epss: [FIRST](https://www.first.org/epss/) publishes EPSS's full daily
history itself, and its ~400K scores, nearly all of which shift a little
every day, would be over 90% of everything stored here.

## Example: tracing Java4Shell (CVE-2026-114938)

[Java4Shell](https://calif.io/java4shell) is a pre-auth memory-corruption
bug in OpenJDK's Base64 decoder. It shows what this repo buys you: the
history alone gives a timeline of which source knew about it, and when it
first knew of a fix, without cross-referencing a dozen separate trackers.

```console
$ git log --reverse --diff-filter=A --format='%cI %s' changelog -- ':(icase)*/cve-2026-114938.yaml' | cut -d' ' -f1,2
2026-11-18T00:23:53Z debian
2026-11-18T00:28:30Z nvd
2026-11-18T13:44:37Z secureos
2026-11-18T13:44:59Z echo
2026-11-18T13:48:38Z alpine
2026-11-18T18:12:23Z rhel
2026-11-19T00:23:01Z wolfi
2026-11-19T00:24:23Z chainguard
2026-11-19T17:22:07Z rhel
2026-11-20T00:36:04Z ubuntu
2026-11-20T01:01:17Z sles
2026-11-20T01:05:12Z hummingbird
2026-11-21T00:23:23Z minimos
$ git log --format='%cI' -G'Version: 17.0.21.1' changelog -- debian/12/cve-2026-114938.yaml
2026-11-20T00:24:55Z
```

| When (UTC)           | What |
|----------------------|------|
| 2026-11-17           | Disclosed publicly by [Calif](https://calif.io/java4shell); [CVE-2026-114938](https://www.tenable.com/blog/java4shell-cve-2026-114938-frequently-asked-questions-about-openjdk-rce-vulnerability) assigned |
| 2026-11-18T00:23:53Z | Debian 12, 13, 14 and unstable list `openjdk-17` as affected, with no fix yet (`Version: None`) |
| 2026-11-18T00:28:30Z | NVD's record, with Oracle's CVSS 3.1 score of 8.1 |
| 2026-11-18T13:48:38Z | Alpine 3.23, 3.24 and edge |
| 2026-11-18T18:12:23Z | RHEL 6 through 10 (the EUS streams followed on 2026-11-19) |
| 2026-11-19T00:23:01Z | Wolfi, then Chainguard a minute later |
| 2026-11-20T00:24:55Z | Debian 12's fix lands: `openjdk-17` `17.0.21.1+2-1~deb12u1` |
| 2026-11-20T00:36:04Z | Ubuntu 16.04 through 26.10. The record already carries fixes for `openjdk-17`, `-21` and `-25` dated 2026-11-18, two days before grype-db had them |
| 2026-11-20T01:01:17Z | SUSE: every SLES 12.5 through 16.1 stream |

Two things stand out that no single tracker shows. Ubuntu had fixed
packages out on the 18th, but anyone scanning with Grype couldn't see them
until the 20th. And as of this writing, the GitHub advisory, Amazon Linux
and Oracle Linux feeds have no record for it at all. Re-running the first
command, rather than guessing, is how you'd check whether that's still true.

## Using it

The `changelog` branch is big: tens of thousands of commits over a tree of
about 3.5 million files. Clone just that branch, without file
contents, and git fetches the blobs you actually look at on demand:

```bash
git clone --filter=blob:none --single-branch -b changelog https://github.com/bored-engineer/grype-db-changelog.git
```

That's still several GB of trees for the full history. For the recent past
only, add `--shallow-since`, e.g. `--shallow-since=2026-11-01` (about 200MB
for a couple of weeks).

Each provider is a top-level directory, with one YAML file per vunnel record
under it, named after the record's ID (`debian/12/cve-2026-114938.yaml`,
`nvd/2026/cve-2026-114938.yaml`, `wolfi/rolling/CVE-2026-114938.yaml`). Its
first line is a comment naming the vunnel schema the record was written
with, e.g. `# schema: vulnerability/osv/schema-1.6.2.json` (relative to
[vunnel's `schema/`](https://github.com/anchore/vunnel/tree/main/schema)).
One build can mix schema versions, for records vunnel hasn't rewritten
since a schema bump, so `git grep '^# schema:' changelog -- bitnami` shows
which records are on which. Each snapshot commit advances exactly one
provider and leaves the others untouched:

```text
debian 2026-11-20T00:24:55Z: ghcr.io/anchore/grype-db/data/debian@sha256:08cfd720…

Processor: vunnel@0.67.0-post.3+45d8771
Captured: 2026-11-20T00:21:26Z
```

- The **subject** names the provider, when GHCR published the build, and
  the exact image it was exported from.
- The **commit date** is that same publish time, which is when Grype users
  could first have seen the build. Commits are in publish order, so
  `git log --since/--until` and "what did provider X look like at time T"
  both work as you'd expect.
- **`Captured:`** is the timestamp from the build's `metadata.json`: when
  vunnel last recorded new results for the provider. A run that finds
  nothing new leaves it unchanged, so it can trail the publish time by
  hours or days, and even read older than the build before it.
- **`Processor:`** is the vunnel version that built the snapshot (older
  builds don't record it). When a provider's files change en masse, a new
  `Processor:` usually means vunnel's output changed, not the source data.
- **`Stale: true`** marks a build whose results vunnel imported from an
  earlier archive instead of building them from the source feed, so it
  says nothing new about the source.
- **`docs: update README and workflows from generator`** commits are the
  only other kind. They copy this README and a small workflow onto the
  branch whenever those change (see [Branches](#branches)), and touch no
  provider data.
- **`Empty-Build: true`** marks a build upstream published as an empty
  tarball. It carries the previous snapshot forward unchanged rather than
  deleting the provider.

## How it works

- **[`cmd/export`](https://github.com/bored-engineer/grype-db-changelog/tree/generator/cmd/export)** downloads one provider image by digest,
  pulls `results.db` and `metadata.json` out of its layer, and writes one
  YAML file per record. Arrays of objects are sorted canonically, because
  upstream reorders them between builds for no semantic reason and that
  would otherwise show up as noise in the diffs. The exception is OSV's
  `events`, kept in upstream order so each range reads introduced, then
  fixed. Numbers are written exactly as upstream's JSON has them.
  hummingbird's CSAF documents leave out three timestamps in
  `document.tracking` (`current_release_date`, `generator.date` and each
  `revision_history` entry's `date`): Red Hat regenerates the documents
  daily, so they were the only change in ~98% of hummingbird's modified
  files. It prints a
  [`git fast-import`](https://git-scm.com/docs/git-fast-import) stream that
  stages the snapshot as `refs/raw/<provider>/<digest>`. It streams the
  layer itself, resuming with HTTP Range requests when GHCR drops a
  connection, since ubuntu's layers are ~5.5GB.
- **[`cmd/changelog`](https://github.com/bored-engineer/grype-db-changelog/tree/generator/cmd/changelog)** chains staged snapshots onto the
  `changelog` branch. Each new commit reuses the snapshot's provider tree by
  SHA and carries every other provider's subtree forward, so it never
  re-reads file contents and runs in a blob-less clone. The branch is a
  plain single-parent chain, not merges, so `git log -- <path>` simplifies
  history correctly.
- **[`backfill.yml`](https://github.com/bored-engineer/grype-db-changelog/blob/generator/.github/workflows/backfill.yml)** runs six times a day,
  an hour after each of upstream's publish windows (00:00, 08:00 and 16:00
  UTC) plus a sweep three hours later for stragglers. It reads the
  provider list from grype-db's own
  [nightly publish config](https://github.com/anchore/grype-db/blob/main/config/grype-db/publish-nightly-r2.yaml),
  so a provider anchore adds is picked up on the next run, lists every
  provider's GHCR version history, works out which versions aren't chained
  yet, oldest first, and fans those out across parallel
  **[`export.yml`](https://github.com/bored-engineer/grype-db-changelog/blob/generator/.github/workflows/export.yml)** jobs. A final job then
  chains them in publish order and deletes their staging refs, in one
  atomic push. Each run takes at most 1,000 versions, which is how the
  initial backfill of upstream's history was done, one batch at a time.

## Branches

- **`changelog`**: the data, one commit per upstream build, as described
  above, and the repository's default branch. Its tip also carries a copy
  of this README, so the branch explains itself, and a thin
  `.github/workflows/backfill.yml`, so GitHub still finds a workflow to
  schedule on the default branch. That workflow
  ([`changelog-dispatcher.yml`](https://github.com/bored-engineer/grype-db-changelog/blob/generator/.github/changelog-dispatcher.yml))
  only forwards to the real one on `generator` with a ref-pinned reusable
  workflow call, so it never needs to track the job logic. The backfill
  job re-copies the README whenever it changes on `generator`. GitHub
  doesn't let an Actions token change workflow files, so a change to the
  dispatcher (which only happens when the schedule or inputs change) is
  pushed by hand with `cmd/changelog -update-workflow`; until it is,
  backfill runs still chain the data but fail, saying so.
- **`generator`**: the code, the real workflows and the source of this
  README. Everything under [How it works](#how-it-works) lives here.
- **`refs/raw/<provider>/<digest>`**: a short-lived staging area between
  the export jobs and the changelog job. Refs exist only while a batch is in
  flight; the `changelog` branch is the source of truth for what has been
  exported.
