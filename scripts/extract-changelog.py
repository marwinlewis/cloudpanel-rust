#!/usr/bin/env python3
"""
Extract release notes for a specific version tag from CHANGELOG.md.
Used by GitHub Actions to populate GitHub Releases (/releases page)
and by release automation scripts.

Usage:
    python3 scripts/extract-changelog.py --tag v0.4.4
    python3 scripts/extract-changelog.py --tag v0.4.4 --output release_notes.md
"""

import argparse
import re
import sys
from pathlib import Path

def extract_changelog(changelog_path: Path, tag: str) -> str:
    if not changelog_path.exists():
        raise FileNotFoundError(f"Changelog not found at {changelog_path}")

    content = changelog_path.read_text(encoding="utf-8")

    # Clean tag: "v0.4.4" or "0.4.4"
    version_core = tag.lstrip("v")
    
    # Pattern to match version header:
    # ## [v0.4.4] - 2026-11-22 or ## [0.4.4] - 2026-11-22 or ## [v0.4.4]
    header_regex = re.compile(
        rf"^##\s+\[v?{re.escape(version_core)}\](?:\s*-\s*([^\n]+))?",
        re.MULTILINE
    )

    match = header_regex.search(content)
    if not match:
        raise ValueError(f"Version {tag} (or {version_core}) not found in {changelog_path.name}")

    start_idx = match.end()

    # Find the next version header: starts with "## [" or end of file before link definitions
    next_header_regex = re.compile(r"^##\s+\[", re.MULTILINE)
    next_match = next_header_regex.search(content, pos=start_idx)

    if next_match:
        section = content[start_idx:next_match.start()]
    else:
        # Check if reference links section starts (e.g. [Unreleased]: or [v0.4.4]:)
        link_regex = re.compile(r"^\[(?:v?[0-9]|Unreleased)", re.MULTILINE)
        link_match = link_regex.search(content, pos=start_idx)
        if link_match:
            section = content[start_idx:link_match.start()]
        else:
            section = content[start_idx:]

    # Clean section: trim leading/trailing whitespace and markdown horizontal rules
    lines = section.splitlines()
    # Strip leading empty lines or horizontal rules
    while lines and (not lines[0].strip() or lines[0].strip() == "---"):
        lines.pop(0)
    # Strip trailing empty lines or horizontal rules
    while lines and (not lines[-1].strip() or lines[-1].strip() == "---"):
        lines.pop()

    return "\n".join(lines).strip()

def main():
    parser = argparse.ArgumentParser(description="Extract release notes from CHANGELOG.md for a tag")
    parser.add_argument("--tag", required=True, help="Release tag (e.g. v0.4.4 or 0.4.4)")
    parser.add_argument("--changelog", default="CHANGELOG.md", help="Path to CHANGELOG.md")
    parser.add_argument("--output", "-o", help="Output file path (default: stdout)")

    args = parser.parse_args()

    changelog_path = Path(args.changelog)
    if not changelog_path.is_absolute():
        # Resolve relative to repo root if run from anywhere inside repo
        candidate = Path(__file__).resolve().parent.parent / args.changelog
        if candidate.exists():
            changelog_path = candidate

    try:
        notes = extract_changelog(changelog_path, args.tag)
        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(notes + "\n", encoding="utf-8")
            print(f"Extracted release notes for {args.tag} to {out_path}", file=sys.stderr)
        else:
            print(notes)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
