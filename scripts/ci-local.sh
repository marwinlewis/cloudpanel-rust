#!/usr/bin/env bash
# Run the same checks as .github/workflows/ci.yml in an Ubuntu 24.04 container as an
# unprivileged user, so CI failures show up before pushing. Needs Docker.
#
#   scripts/ci-local.sh
#
# Uses the working tree as it is (including uncommitted changes) but only files git
# knows about, like actions/checkout. Build caches live in Docker volumes.
set -euo pipefail

cd "$(dirname "$0")/.."
image=cloudpanel-ci-local

docker build -q -t "$image" -f scripts/ci-local.Dockerfile scripts >/dev/null

# Tracked + new (not ignored) files, streamed into the container.
git ls-files -z --cached --others --exclude-standard \
  | tar --null -T - -cf - \
  | MSYS_NO_PATHCONV=1 docker run --rm -i \
      -v cloudpanel-ci-cargo-registry:/home/runner/.cargo/registry \
      -v cloudpanel-ci-target:/home/runner/target \
      -e CARGO_TARGET_DIR=/home/runner/target \
      "$image" bash -c '
        set -euo pipefail
        mkdir -p src
        cd src
        tar -xf -
        git init -q && git -c core.safecrlf=false add -A
        step() { echo; echo "==> $*"; "$@"; }
        step cargo fmt --check
        step cargo clippy --all-targets --locked -- -D warnings
        step cargo test --locked
        echo; echo "==> UI JavaScript syntax"
        files=$(git ls-files "ui/*.js")
        [ -n "$files" ] || { echo "no UI JavaScript files found"; exit 1; }
        for f in $files; do node --check "$f"; done
        step shellcheck install.sh
        step shellcheck -S warning scripts/debian-e2e/security.sh
        echo; echo "All CI checks passed."
      '
