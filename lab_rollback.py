#!/usr/bin/env python3
"""Reversibility, Change-Tracking, and Emergency Rollback Manager.

Provides immutable baseline backups, before/after snapshots, detailed change
tracking, per-change revert, one-command emergency reset, and post-rollback
SHA-256 + automated test verification for the isolated Newton Security Lab.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import difflib
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any


IGNORED_DIRS = {".git", ".lab_backups", "__pycache__", ".pytest_cache"}


def sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_project_files(root: Path) -> list[Path]:
    """Return sorted relative file paths in the lab root, excluding backups/git."""
    files: list[Path] = []
    for item in root.rglob("*"):
        if not item.is_file():
            continue
        rel = item.relative_to(root)
        if any(part in IGNORED_DIRS for part in rel.parts):
            continue
        files.append(rel)
    return sorted(files)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def backups_dir(root: Path) -> Path:
    return root / ".lab_backups"


def baseline_dir(root: Path) -> Path:
    return backups_dir(root) / "baseline"


def manifest_path(root: Path) -> Path:
    return backups_dir(root) / "baseline_manifest.json"


def init_baseline(root: Path) -> int:
    """Create an immutable baseline backup. Refuses to overwrite an existing one."""
    b_dir = baseline_dir(root)
    m_path = manifest_path(root)
    if b_dir.exists() or m_path.exists():
        print("ERROR: Baseline already exists and is protected from overwrite.", file=sys.stderr)
        return 1

    b_dir.mkdir(parents=True, exist_ok=False)
    files = collect_project_files(root)
    manifest_files: dict[str, str] = {}
    for rel in files:
        src = root / rel
        dst = b_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        manifest_files[rel.as_posix()] = sha256_file(src)

    manifest = {
        "created_at": utc_now(),
        "root": str(root),
        "file_count": len(manifest_files),
        "files": manifest_files,
    }
    m_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Baseline created: {len(manifest_files)} files preserved in {b_dir}")
    return 0


def snapshot_dir(root: Path, change_id: str) -> Path:
    return backups_dir(root) / "snapshots" / change_id


def begin_change(root: Path, change_id: str, reason: str, rel_paths: list[str]) -> int:
    """Capture BEFORE snapshot for a set of relative file paths."""
    s_dir = snapshot_dir(root, change_id)
    if s_dir.exists():
        print(f"ERROR: Snapshot '{change_id}' already exists.", file=sys.stderr)
        return 1

    before_dir = s_dir / "before"
    before_dir.mkdir(parents=True, exist_ok=False)
    before_hashes: dict[str, str | None] = {}

    for rel_str in rel_paths:
        rel = Path(rel_str)
        src = root / rel
        if src.is_file():
            dst = before_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            before_hashes[rel.as_posix()] = sha256_file(src)
        else:
            before_hashes[rel.as_posix()] = None

    meta = {
        "change_id": change_id,
        "started_at": utc_now(),
        "reason": reason,
        "files": [Path(p).as_posix() for p in rel_paths],
        "before_hashes": before_hashes,
        "status": "in_progress",
    }
    (s_dir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(f"Captured BEFORE snapshot '{change_id}' for {len(rel_paths)} path(s).")
    return 0


def commit_change(root: Path, change_id: str) -> int:
    """Capture AFTER snapshot, unified diff, and append to changelog."""
    s_dir = snapshot_dir(root, change_id)
    meta_path = s_dir / "meta.json"
    if not meta_path.is_file():
        print(f"ERROR: No BEFORE snapshot found for '{change_id}'.", file=sys.stderr)
        return 1

    meta: dict[str, Any] = json.loads(meta_path.read_text(encoding="utf-8"))
    after_dir = s_dir / "after"
    after_dir.mkdir(parents=True, exist_ok=True)

    after_hashes: dict[str, str | None] = {}
    diffs: list[str] = []

    for rel_str in meta["files"]:
        rel = Path(rel_str)
        cur = root / rel
        before_file = s_dir / "before" / rel
        if cur.is_file():
            dst = after_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(cur, dst)
            after_hashes[rel_str] = sha256_file(cur)
        else:
            after_hashes[rel_str] = None

        before_lines = (
            before_file.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
            if before_file.is_file()
            else []
        )
        after_lines = (
            cur.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
            if cur.is_file()
            else []
        )
        diff = "".join(
            difflib.unified_diff(
                before_lines,
                after_lines,
                fromfile=f"a/{rel_str}",
                tofile=f"b/{rel_str}",
            )
        )
        if diff:
            diffs.append(diff)

    (s_dir / "diff.patch").write_text("\n".join(diffs), encoding="utf-8")
    meta["completed_at"] = utc_now()
    meta["after_hashes"] = after_hashes
    meta["status"] = "recorded"
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    append_changelog(root, meta)
    print(f"Recorded change '{change_id}' in changelog with before/after snapshots.")
    return 0


def append_changelog(root: Path, entry: dict[str, Any]) -> None:
    """Append a change or revert entry to JSONL and Markdown changelogs."""
    b_root = backups_dir(root)
    b_root.mkdir(parents=True, exist_ok=True)
    jsonl = b_root / "changelog.jsonl"
    with jsonl.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")

    md_path = b_root / "CHANGELOG.md"
    if not md_path.exists():
        md_path.write_text("# Lab Change Tracking Log\n\n", encoding="utf-8")
    ts = entry.get("completed_at") or entry.get("reverted_at") or utc_now()
    action = entry.get("action", "CHANGE")
    lines = [
        f"## [{ts}] {action}: `{entry['change_id']}`",
        f"- **Reason:** {entry.get('reason', 'N/A')}",
        f"- **Files:** {', '.join(f'`{f}`' for f in entry.get('files', []))}",
        "",
    ]
    with md_path.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def revert_change(root: Path, change_id: str) -> int:
    """Revert an individual recorded change back to its BEFORE snapshot."""
    s_dir = snapshot_dir(root, change_id)
    meta_path = s_dir / "meta.json"
    if not meta_path.is_file():
        print(f"ERROR: Unknown change_id '{change_id}'.", file=sys.stderr)
        return 1

    meta: dict[str, Any] = json.loads(meta_path.read_text(encoding="utf-8"))
    for rel_str in meta["files"]:
        rel = Path(rel_str)
        target = root / rel
        before_file = s_dir / "before" / rel
        if before_file.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(before_file, target)
        elif target.exists():
            target.unlink()

    append_changelog(
        root,
        {
            "action": "REVERT",
            "change_id": change_id,
            "reverted_at": utc_now(),
            "reason": f"Reverted change '{change_id}' to BEFORE snapshot",
            "files": meta["files"],
        },
    )
    print(f"Reverted individual change '{change_id}'.")
    return 0


def verify_against_baseline(root: Path, run_tests: bool = True) -> int:
    """Verify workspace matches baseline SHA-256 manifest and optionally run tests."""
    m_path = manifest_path(root)
    if not m_path.is_file():
        print("ERROR: Baseline manifest missing. Run init-baseline first.", file=sys.stderr)
        return 1

    manifest = json.loads(m_path.read_text(encoding="utf-8"))
    expected: dict[str, str] = manifest["files"]
    current_files = {rel.as_posix(): sha256_file(root / rel) for rel in collect_project_files(root)}

    mismatches: list[str] = []
    missing: list[str] = []
    extra = sorted(set(current_files) - set(expected))

    for rel_str, exp_hash in expected.items():
        if rel_str not in current_files:
            missing.append(rel_str)
        elif current_files[rel_str] != exp_hash:
            mismatches.append(rel_str)

    if missing or mismatches or extra:
        print("BASELINE DRIFT DETECTED:")
        if missing:
            print(f"  Missing files: {missing}")
        if mismatches:
            print(f"  Modified files: {mismatches}")
        if extra:
            print(f"  Extra untracked files: {extra}")
        return 2

    print(f"Hash verification PASSED: {len(expected)}/{len(expected)} files match immutable baseline.")
    if run_tests:
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", str(root), "-p", "test_*.py", "-v"],
            cwd=str(root),
            check=False,
        )
        if proc.returncode != 0:
            print("Automated test verification FAILED.", file=sys.stderr)
            return proc.returncode
        print("Automated test verification PASSED.")
    return 0


def emergency_reset(root: Path, run_tests: bool = True) -> int:
    """Restore complete local simulation from immutable baseline and verify."""
    b_dir = baseline_dir(root)
    m_path = manifest_path(root)
    if not b_dir.is_dir() or not m_path.is_file():
        print("ERROR: Baseline backup missing; cannot perform reset.", file=sys.stderr)
        return 1

    manifest = json.loads(m_path.read_text(encoding="utf-8"))
    expected_files: dict[str, str] = manifest["files"]

    # Remove extra experimental files outside .git / .lab_backups
    for rel in collect_project_files(root):
        if rel.as_posix() not in expected_files:
            (root / rel).unlink()

    # Restore exact baseline copies
    for rel_str in expected_files:
        src = b_dir / rel_str
        dst = root / rel_str
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    append_changelog(
        root,
        {
            "action": "EMERGENCY_RESET",
            "change_id": f"reset-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "reverted_at": utc_now(),
            "reason": "Full emergency reset to immutable baseline",
            "files": sorted(expected_files.keys()),
        },
    )
    print("Workspace files restored from immutable baseline.")
    return verify_against_baseline(root, run_tests=run_tests)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Newton Security Lab Reversibility & Rollback Manager")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent, help="Lab root directory")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init-baseline", help="Create immutable baseline backup")

    p_begin = sub.add_parser("begin-change", help="Snapshot BEFORE state for files to be modified")
    p_begin.add_argument("--id", required=True, help="Unique change identifier")
    p_begin.add_argument("--reason", required=True, help="Why the modification is being made")
    p_begin.add_argument("files", nargs="+", help="Relative file paths")

    p_commit = sub.add_parser("commit-change", help="Snapshot AFTER state and log diff/hashes")
    p_commit.add_argument("--id", required=True, help="Change identifier started with begin-change")

    p_rev = sub.add_parser("revert-change", help="Revert an individual change to its BEFORE snapshot")
    p_rev.add_argument("change_id", help="Change identifier to revert")

    p_ver = sub.add_parser("verify", help="Verify workspace hashes against baseline and run tests")
    p_ver.add_argument("--no-tests", action="store_true", help="Skip running unittest suite")

    p_reset = sub.add_parser("reset", help="One-command EMERGENCY RESET to clean baseline")
    p_reset.add_argument("--no-tests", action="store_true", help="Skip running unittest suite after reset")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve()
    if args.cmd == "init-baseline":
        return init_baseline(root)
    if args.cmd == "begin-change":
        return begin_change(root, args.id, args.reason, args.files)
    if args.cmd == "commit-change":
        return commit_change(root, args.id)
    if args.cmd == "revert-change":
        return revert_change(root, args.change_id)
    if args.cmd == "verify":
        return verify_against_baseline(root, run_tests=not args.no_tests)
    if args.cmd == "reset":
        return emergency_reset(root, run_tests=not args.no_tests)
    return 1


if __name__ == "__main__":
    sys.exit(main())
