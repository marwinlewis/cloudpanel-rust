#!/usr/bin/env bash
#
# Syncs release notes from CHANGELOG.md to GitHub Releases (/releases page).
#
# Usage:
#   ./scripts/sync-release-notes.sh --all
#   ./scripts/sync-release-notes.sh --tag v0.4.4
#   ./scripts/sync-release-notes.sh --all --dry-run
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

python3 "${SCRIPT_DIR}/sync-release-notes.py" --changelog "${REPO_ROOT}/CHANGELOG.md" "$@"
