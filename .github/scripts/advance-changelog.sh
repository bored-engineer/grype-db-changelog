#!/usr/bin/env bash
# Advances refs/heads/changelog one day at a time, starting the day after
# its current tip (or the project's start date if it doesn't exist yet),
# stopping as soon as a day has no refs/raw/grype/* data at all (either we
# genuinely haven't exported it yet, or it's past "today").
#
# Runs inside the same checkout actions/checkout already authenticated
# (ref: generator), rather than a separate nested clone: a nested `git
# init`'d directory does not inherit Checkout's injected credentials, which
# bit trivy-db-changelog's equivalent script. Fetching extra refs into this
# same working copy's .git sidesteps that entirely.
set -euo pipefail

PROJECT_START="2023-02-16" # see providers.json's "_comment" for why

git fetch origin 'refs/raw/grype/*:refs/raw/grype/*' 'refs/heads/changelog:refs/heads/changelog' 2>&1 \
  | grep -v '^$' || true

to_short() {
  # "2026-11-21" -> "26-11-21"
  echo "${1:2}"
}

start_full="$PROJECT_START"
if git rev-parse --verify refs/heads/changelog >/dev/null 2>&1; then
  subject=$(git log -1 --format=%s refs/heads/changelog)
  last_short="${subject%%:*}" # e.g. "26-11-21"
  start_full=$(date -u -d "20${last_short} +1 day" +%Y-%m-%d)
fi
end_full=$(date -u -d "${END_DATE:-today}" +%Y-%m-%d)

echo "advancing changelog from $start_full through $end_full"

d="$start_full"
built=0
while [ "$(date -u -d "$d" +%s)" -le "$(date -u -d "$end_full" +%s)" ]; do
  short=$(to_short "$(date -u -d "$d" +%Y-%m-%d)")
  if ! git for-each-ref --format='%(refname)' "refs/raw/grype/*/$short" | grep -q .; then
    echo "no refs/raw/grype/*/$short data yet; stopping"
    break
  fi
  go run ./cmd/changelog "$short"
  built=$((built + 1))
  d=$(date -u -d "$d +1 day" +%Y-%m-%d)
done

if [ "$built" -eq 0 ]; then
  echo "nothing new to build"
  exit 0
fi

echo "built $built day(s); pushing"
git push origin refs/heads/changelog:refs/heads/changelog
