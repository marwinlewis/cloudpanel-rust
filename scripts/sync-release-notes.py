#!/usr/bin/env python3
"""
Syncs release notes from CHANGELOG.md to GitHub Releases (/releases page).

Supports:
1. GitHub CLI (`gh`): If authenticated via `gh auth login`.
2. GitHub REST API: If `GITHUB_TOKEN` or `GH_TOKEN` environment variable is set.

Usage:
    # Preview all releases to sync:
    python3 scripts/sync-release-notes.py --all --dry-run

    # Sync a specific release:
    python3 scripts/sync-release-notes.py --tag v0.4.4

    # Sync all releases defined in CHANGELOG.md to GitHub:
    python3 scripts/sync-release-notes.py --all
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import urllib.error
from pathlib import Path

REPO_DEFAULT = "marwinlewis/cloudpanel-rust"

def get_all_changelog_versions(changelog_path: Path):
    content = changelog_path.read_text(encoding="utf-8")
    version_regex = re.compile(r"^##\s+\[(v?[0-9][^\]]+)\]", re.MULTILINE)
    versions = []
    for m in version_regex.finditer(content):
        v = m.group(1)
        if not v.startswith("v"):
            v = "v" + v
        versions.append(v)
    return versions

def extract_section(changelog_path: Path, tag: str) -> str:
    script_path = changelog_path.parent / "scripts" / "extract-changelog.py"
    if script_path.exists():
        res = subprocess.run(
            [sys.executable, str(script_path), "--changelog", str(changelog_path), "--tag", tag],
            capture_output=True,
            text=True,
            encoding="utf-8"
        )
        if res.returncode == 0:
            return res.stdout.strip()
    
    # Fallback inline extraction
    content = changelog_path.read_text(encoding="utf-8")
    v_core = tag.lstrip("v")
    header_regex = re.compile(rf"^##\s+\[v?{re.escape(v_core)}\](?:\s*-\s*[^\n]+)?", re.MULTILINE)
    m = header_regex.search(content)
    if not m:
        raise ValueError(f"Version {tag} not found in {changelog_path}")
    start = m.end()
    next_m = re.compile(r"^##\s+\[", re.MULTILINE).search(content, pos=start)
    section = content[start:next_m.start()] if next_m else content[start:]
    lines = [l for l in section.splitlines() if l.strip() != "---"]
    return "\n".join(lines).strip()

def sync_via_gh_cli(tag: str, notes: str, repo: str, dry_run: bool = False) -> bool:
    if dry_run:
        print(f"[DRY RUN] gh release edit {tag} --repo {repo} with {len(notes)} bytes")
        return True

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".md") as tmp:
        tmp.write(notes + "\n")
        tmp_path = tmp.name

    try:
        # Check if release exists
        view_cmd = ["gh", "release", "view", tag, "--repo", repo]
        check = subprocess.run(view_cmd, capture_output=True, text=True)
        if check.returncode == 0:
            edit_cmd = ["gh", "release", "edit", tag, "--repo", repo, "--notes-file", tmp_path]
            res = subprocess.run(edit_cmd, capture_output=True, text=True)
            if res.returncode == 0:
                print(f"✓ Updated GitHub release notes for {tag}")
                return True
            else:
                print(f"✗ Failed to edit release {tag}: {res.stderr.strip()}", file=sys.stderr)
                return False
        else:
            # Create release if tag exists
            create_cmd = ["gh", "release", "create", tag, "--repo", repo, "--title", tag, "--notes-file", tmp_path]
            res = subprocess.run(create_cmd, capture_output=True, text=True)
            if res.returncode == 0:
                print(f"✓ Created GitHub release and notes for {tag}")
                return True
            else:
                print(f"✗ Failed to create release {tag}: {res.stderr.strip()}", file=sys.stderr)
                return False
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass

def sync_via_github_api(tag: str, notes: str, repo: str, token: str, dry_run: bool = False) -> bool:
    if dry_run:
        print(f"[DRY RUN] GitHub API update {tag} in {repo} with {len(notes)} bytes")
        return True

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "cloudpanel-changelog-syncer",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            release_id = data.get("id")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Need to create release
            create_url = f"https://api.github.com/repos/{repo}/releases"
            payload = json.dumps({"tag_name": tag, "name": tag, "body": notes}).encode("utf-8")
            post_req = urllib.request.Request(create_url, data=payload, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(post_req) as post_resp:
                    print(f"✓ Created release {tag} on GitHub via API")
                    return True
            except Exception as post_err:
                print(f"✗ Failed creating release {tag} via API: {post_err}", file=sys.stderr)
                return False
        else:
            print(f"✗ GitHub API error inspecting {tag}: {e}", file=sys.stderr)
            return False

    patch_url = f"https://api.github.com/repos/{repo}/releases/{release_id}"
    patch_payload = json.dumps({"body": notes}).encode("utf-8")
    patch_req = urllib.request.Request(patch_url, data=patch_payload, headers=headers, method="PATCH")

    try:
        with urllib.request.urlopen(patch_req) as patch_resp:
            print(f"✓ Updated release notes for {tag} on GitHub via API")
            return True
    except Exception as e:
        print(f"✗ Failed updating release {tag} via API: {e}", file=sys.stderr)
        return False

def main():
    parser = argparse.ArgumentParser(description="Sync release notes from CHANGELOG.md to GitHub Releases")
    parser.add_argument("--tag", help="Specific tag to sync (e.g. v0.4.4)")
    parser.add_argument("--all", action="store_true", help="Sync all versions listed in CHANGELOG.md")
    parser.add_argument("--repo", default=REPO_DEFAULT, help=f"GitHub repository (default: {REPO_DEFAULT})")
    parser.add_argument("--changelog", default="CHANGELOG.md", help="Path to CHANGELOG.md")
    parser.add_argument("--dry-run", action="store_true", help="Preview sync actions without making changes")

    args = parser.parse_args()

    changelog_path = Path(args.changelog)
    if not changelog_path.is_absolute():
        candidate = Path(__file__).resolve().parent.parent / args.changelog
        if candidate.exists():
            changelog_path = candidate

    if not changelog_path.exists():
        print(f"Error: {changelog_path} not found", file=sys.stderr)
        sys.exit(1)

    if args.all:
        tags = get_all_changelog_versions(changelog_path)
    elif args.tag:
        tags = [args.tag]
    else:
        print("Please specify --tag <tag> or --all. Use --help for usage.", file=sys.stderr)
        sys.exit(1)

    # Detect auth mechanism
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    has_gh_cli = shutil.which("gh") is not None

    if not token and not has_gh_cli and not args.dry_run:
        print("Error: Neither `gh` CLI nor GITHUB_TOKEN environment variable is available.", file=sys.stderr)
        print("To authenticate:", file=sys.stderr)
        print("  1. Run: gh auth login", file=sys.stderr)
        print("  OR", file=sys.stderr)
        print("  2. Set GITHUB_TOKEN=<your-github-token>", file=sys.stderr)
        sys.exit(1)

    success_count = 0
    fail_count = 0

    print(f"Found {len(tags)} release(s) to process for {args.repo}...")
    for tag in tags:
        try:
            notes = extract_section(changelog_path, tag)
            if not notes:
                print(f"⚠ No notes found for {tag}, skipping")
                continue

            if token:
                ok = sync_via_github_api(tag, notes, args.repo, token, dry_run=args.dry_run)
            else:
                ok = sync_via_gh_cli(tag, notes, args.repo, dry_run=args.dry_run)

            if ok:
                success_count += 1
            else:
                fail_count += 1
        except Exception as e:
            print(f"✗ Error processing {tag}: {e}", file=sys.stderr)
            fail_count += 1

    print(f"\nDone: {success_count} succeeded, {fail_count} failed.")

if __name__ == "__main__":
    main()
