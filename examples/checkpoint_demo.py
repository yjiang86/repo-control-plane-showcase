"""Run an isolated checkpoint example using synthetic files only."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.devcheckpointctl.core import (
    ExportRequest, FreezeRequest, export_checkpoint, freeze_checkpoint,
    observe_subject,
)


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "--no-optional-locks", "-c", "core.hooksPath=", "-C", str(repo), *args],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout


def snapshot(repo: Path) -> tuple[bytes, bytes, bytes]:
    return (
        git(repo, "rev-parse", "HEAD"),
        git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all"),
        (repo / ".git/index").read_bytes(),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-root", type=Path, required=True)
    args = parser.parse_args()
    work_root = args.work_root.resolve(strict=True)
    if not work_root.is_dir():
        parser.error("work-root must be an existing local directory")
    case = work_root / ("checkpoint-demo-" + uuid.uuid4().hex[:12])
    case.mkdir()
    repo = case / "synthetic-repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.name", "Synthetic Example")
    git(repo, "config", "user.email", "example@example.invalid")
    for name in ["subject.txt", "unrelated.txt"]:
        (repo / name).write_text("before\n", encoding="utf8")
    git(repo, "add", "--", "subject.txt", "unrelated.txt")
    git(repo, "commit", "-m", "Create synthetic example input")
    (repo / "unrelated.txt").write_text("unrelated staged change\n", encoding="utf8")
    git(repo, "add", "--", "unrelated.txt")
    (repo / "subject.txt").write_text("selected change\n", encoding="utf8")
    before = snapshot(repo)
    subject = observe_subject(repo, ("subject.txt",))
    frozen = freeze_checkpoint(FreezeRequest(
        repo_root=repo, activity="example", label="selected change",
        owner="Example", task="synthetic-checkpoint", paths=("subject.txt",),
        expected_subject_sha256=subject["subject_sha256"],
    ))
    patch_path = case / "selected.patch"
    exported = export_checkpoint(ExportRequest(repo, "example", patch_path))
    patch = patch_path.read_bytes()
    assert frozen["expected_subject_bound"] is True
    assert snapshot(repo) == before, "Original repository state changed"
    assert b"subject.txt" in patch and b"unrelated.txt" not in patch
    assert hashlib.sha256(patch).hexdigest() == exported["patch_sha256"]
    print(json.dumps({
        "status": "PASS", "synthetic_only": True,
        "head_status_index_preserved": True,
        "unrelated_staged_change_excluded": True,
        "expected_subject_bound": True,
        "patch_sha256": exported["patch_sha256"],
        "output_directory": str(case),
    }, indent=2))


if __name__ == "__main__":
    main()
