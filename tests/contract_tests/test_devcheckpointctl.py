from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from tools.frozenpatch import (
    CANONICAL_PATCH_GIT_CONFIG,
    canonical_git_environment,
    tree_patch_arguments,
)
from tools.devcheckpointctl import cli, core
from tools.leasectl.core import LockCoordinator, LockError, MAX_GIT_MUTATION_TTL_SECONDS


def git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.decode("utf-8", errors="replace"))
    return completed.stdout.decode("utf-8").strip()


def git_bytes(repo: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.decode("utf-8", errors="replace"))
    return completed.stdout


def canonical_git_bytes(repo: Path, *arguments: str) -> bytes:
    command = ["git"]
    for key, value in CANONICAL_PATCH_GIT_CONFIG:
        command.extend(["-c", f"{key}={value}"])
    command.extend(["-C", str(repo), *arguments])
    environment = canonical_git_environment()
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=environment,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.decode("utf-8", errors="replace"))
    return completed.stdout


class DevCheckpointCtlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="devcheckpointctl-test-")
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        git(self.repo, "init")
        git(self.repo, "config", "user.name", "Fixture")
        git(self.repo, "config", "user.email", "fixture@example.invalid")
        (self.repo / "subject.txt").write_text("v1\n", encoding="utf-8", newline="\n")
        (self.repo / "other.txt").write_text("other\n", encoding="utf-8", newline="\n")
        git(self.repo, "add", "--", "subject.txt", "other.txt")
        git(self.repo, "commit", "-m", "fixture: base")
        self.base = git(self.repo, "rev-parse", "HEAD")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def request(
        self,
        *paths: str,
        label: str = "green-1",
        expected_subject_sha256: str | None = None,
    ) -> core.FreezeRequest:
        return core.FreezeRequest(
            repo_root=self.repo.resolve(),
            activity="fixture-activity",
            label=label,
            owner="Fixture_Mgr",
            task="fixture-task",
            paths=tuple(paths),
            expected_subject_sha256=expected_subject_sha256,
        )

    def assert_reason(self, reason: str, function, *arguments) -> core.CheckpointError:
        with self.assertRaises(core.CheckpointError) as raised:
            function(*arguments)
        self.assertEqual(raised.exception.reason_code, reason)
        return raised.exception

    def identity(self) -> tuple[str, bytes, bytes]:
        head = git(self.repo, "rev-parse", "HEAD")
        status = subprocess.run(
            ["git", "-C", str(self.repo), "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            stdout=subprocess.PIPE,
            check=True,
        ).stdout
        index = Path(git(self.repo, "rev-parse", "--git-path", "index"))
        if not index.is_absolute():
            index = self.repo / index
        return head, status, index.read_bytes()

    def assert_subject_rows(self, observed: dict) -> None:
        rows = observed["path_snapshots"]
        self.assertEqual([row["path"] for row in rows], observed["path_set"])
        for row in rows:
            self.assertEqual(set(row), {"path", "exists", "mode", "size", "sha256"})
            source = self.repo / row["path"]
            self.assertIs(row["exists"], source.exists())
            if row["exists"]:
                data = source.read_bytes()
                self.assertIn(row["mode"], ("100644", "100755"))
                self.assertEqual(row["size"], len(data))
                self.assertEqual(row["sha256"], hashlib.sha256(data).hexdigest())
            else:
                self.assertEqual((row["mode"], row["size"], row["sha256"]), (None, None, None))
        preimage = {
            "base_head": observed["base_head"],
            "paths": [{
                "path": row["path"],
                "snapshot": [row["exists"], row["mode"], row["size"], row["sha256"]],
            } for row in rows],
        }
        encoded = (json.dumps(
            preimage, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ) + "\n").encode("utf-8")
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), observed["subject_sha256"])

    def test_freeze_chain_deduplicates_and_preserves_canonical_state(self) -> None:
        (self.repo / "subject.txt").write_text("v2\n", encoding="utf-8", newline="\n")
        (self.repo / "foreign.tmp").write_text("foreign\n", encoding="utf-8", newline="\n")
        before = self.identity()

        first = core.freeze_checkpoint(self.request("subject.txt"))
        self.assertEqual(first["status"], "FROZEN")
        self.assertEqual(first["base_head"], self.base)
        self.assertEqual(first["changed_paths"], ["subject.txt"])
        self.assertEqual(first["checkpoint_depth"], 1)
        self.assertEqual(self.identity(), before)
        self.assertEqual(
            git(self.repo, "show", f"{first['checkpoint_commit']}:subject.txt"),
            "v2",
        )
        with self.assertRaises(AssertionError):
            git(self.repo, "show", f"{first['checkpoint_commit']}:foreign.tmp")

        same = core.freeze_checkpoint(self.request(label="same-bytes"))
        self.assertEqual(same["status"], "UNCHANGED")
        self.assertEqual(same["checkpoint_commit"], first["checkpoint_commit"])

        (self.repo / "subject.txt").write_text("v3\n", encoding="utf-8", newline="\n")
        second = core.freeze_checkpoint(self.request(label="green-2"))
        self.assertEqual(second["status"], "FROZEN")
        self.assertEqual(second["parent_checkpoint"], first["checkpoint_commit"])
        self.assertEqual(second["checkpoint_depth"], 2)
        self.assertEqual(self.identity()[0], self.base)

        observed = core.inspect_checkpoint(self.repo.resolve(), "fixture-activity")
        self.assertEqual(observed["status"], "EXACT")
        self.assertEqual(observed["checkpoint_commit"], second["checkpoint_commit"])
        self.assertEqual(observed["changed_paths"], ["subject.txt"])
        self.assertEqual(observed["checkpoint_label"], "green-2")
        self.assertEqual(observed["owner"], "Fixture_Mgr")
        self.assertEqual(observed["task"], "fixture-task")
        listed = core.list_checkpoints(self.repo.resolve())
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["checkpoints"][0]["activity"], "fixture-activity")
        self.assertEqual(listed["checkpoints"][0]["owner"], "Fixture_Mgr")
        self.assertEqual(listed["checkpoints"][0]["task"], "fixture-task")
        self.assertEqual(listed["checkpoints"][0]["tool_version"], "0.1.1")

        output = self.root / "checkpoint.patch"
        exported = core.export_checkpoint(
            core.ExportRequest(self.repo.resolve(), "fixture-activity", output.resolve())
        )
        self.assertEqual(exported["status"], "EXPORTED")
        self.assertEqual(exported["patch_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
        self.assertIn(b"subject.txt", output.read_bytes())
        self.assertNotIn(b"foreign.tmp", output.read_bytes())
        self.assert_reason(
            "EXPORT_TARGET_EXISTS",
            core.export_checkpoint,
            core.ExportRequest(self.repo.resolve(), "fixture-activity", output.resolve()),
        )

    def test_fail_closed_boundaries_and_cli(self) -> None:
        self.assert_reason(
            "INPUT_INVALID",
            core.freeze_checkpoint,
            core.FreezeRequest(
                repo_root=self.repo.resolve(),
                activity="MixedCase",
                label="invalid",
                owner="Fixture_Mgr",
                task="fixture-task",
                paths=("subject.txt",),
            ),
        )
        self.assert_reason("PATH_SET_REQUIRED", core.freeze_checkpoint, self.request())
        self.assert_reason(
            "PATH_SET_INVALID",
            core.freeze_checkpoint,
            self.request("../outside.txt"),
        )
        (self.repo / "subject.txt").write_text("v2\n", encoding="utf-8", newline="\n")
        frozen = core.freeze_checkpoint(self.request("subject.txt"))
        self.assertEqual(frozen["status"], "FROZEN")
        self.assert_reason(
            "PATH_SET_CHANGED",
            core.freeze_checkpoint,
            self.request("subject.txt", "other.txt"),
        )

        (self.repo / "other.txt").write_text("changed\n", encoding="utf-8", newline="\n")
        git(self.repo, "add", "--", "other.txt")
        git(self.repo, "commit", "-m", "fixture: advance base")
        self.assert_reason("BASE_HEAD_CHANGED", core.freeze_checkpoint, self.request())

        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = cli.main(
                [
                    "inspect",
                    "--repo-root",
                    str(self.repo.resolve()),
                    "--activity",
                    "fixture-activity",
                ]
            )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout.getvalue())["base_state"], "MOVED")
        self.assertEqual(stderr.getvalue(), "")

    def test_no_change_does_not_create_a_checkpoint_ref(self) -> None:
        result = core.freeze_checkpoint(
            core.FreezeRequest(
                repo_root=self.repo.resolve(),
                activity="no-change",
                label="base-bytes",
                owner="Fixture_Mgr",
                task="fixture-task",
                paths=("subject.txt",),
            )
        )
        self.assertEqual(result["status"], "NO_CHANGE")
        self.assertIsNone(result["checkpoint_commit"])
        self.assertEqual(core.list_checkpoints(self.repo.resolve())["count"], 0)

    def test_posix_worktree_mode_uses_current_executable_bits(self) -> None:
        executable = mock.Mock()
        executable.stat.return_value.st_mode = stat.S_IFREG | stat.S_IXUSR
        other_executable = mock.Mock()
        other_executable.stat.return_value.st_mode = stat.S_IFREG | stat.S_IXOTH
        regular = mock.Mock()
        regular.stat.return_value.st_mode = stat.S_IFREG
        self.assertEqual(
            core._worktree_mode(executable, "100644", platform_name="posix"),
            "100755",
        )
        self.assertEqual(
            core._worktree_mode(regular, "100755", platform_name="posix"),
            "100644",
        )
        self.assertEqual(
            core._worktree_mode(other_executable, "100644", platform_name="posix"),
            "100644",
        )
        self.assertEqual(
            core._worktree_mode(executable, "100644", platform_name="nt"),
            "100644",
        )

    def test_freeze_renews_maximum_git_mutation_lock(self) -> None:
        (self.repo / "subject.txt").write_text("v2\n", encoding="utf-8", newline="\n")
        original = core.LockCoordinator.renew_active
        renewals: list[dict[str, object]] = []

        def observed_renew(instance, **arguments):
            renewals.append(dict(arguments))
            return original(instance, **arguments)

        with mock.patch.object(core.LockCoordinator, "renew_active", new=observed_renew):
            result = core.freeze_checkpoint(self.request("subject.txt"))
        self.assertEqual(result["status"], "FROZEN")
        self.assertGreaterEqual(len(renewals), 5)
        self.assertTrue(
            all(
                renewal["ttl_seconds"] == MAX_GIT_MUTATION_TTL_SECONDS
                and renewal["new_nonce"] == renewal["nonce"]
                for renewal in renewals
            )
        )

    def test_lost_git_mutation_lock_fails_before_creating_checkpoint_ref(self) -> None:
        (self.repo / "subject.txt").write_text("v2\n", encoding="utf-8", newline="\n")
        request = core.FreezeRequest(
            repo_root=self.repo.resolve(),
            activity="lost-lock",
            label="must-fail",
            owner="Fixture_Mgr",
            task="fixture-task",
            paths=("subject.txt",),
        )
        with mock.patch.object(
            core.LockCoordinator,
            "renew_active",
            side_effect=LockError("simulated lock loss"),
        ):
            self.assert_reason("GIT_MUTATION_LOCK_LOST", core.freeze_checkpoint, request)
        missing = subprocess.run(
            [
                "git",
                "-C",
                str(self.repo),
                "rev-parse",
                "--verify",
                "--quiet",
                "refs/codex/dev-checkpoints/lost-lock",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(missing.returncode, 0)

    def test_expected_subject_rejects_path_lock_handoff_without_advancing_ref(self) -> None:
        locks = LockCoordinator(self.repo)
        subject = self.repo / "subject.txt"
        ref = "refs/codex/dev-checkpoints/fixture-activity"
        for has_prior in (False, True):
            with self.subTest(has_prior=has_prior):
                previous = None
                if has_prior:
                    subject.write_bytes(b"v0\n")
                    previous = core.freeze_checkpoint(self.request("subject.txt"))["checkpoint_commit"]
                locks.acquire(
                    lock_kind="PATH_LOCK", task="task-a", owner="Owner_A",
                    ttl_seconds=120, paths=[{"kind": "exact", "path": "subject.txt"}],
                    nonce="nonce-a", lock_id="LOCK-subject-a", base_head=self.base,
                )
                try:
                    subject.write_bytes(b"v2\n")
                    expected = core.observe_subject(self.repo.resolve(), ("subject.txt",))
                    self.assert_subject_rows(expected)
                finally:
                    locks.release(lock_id="LOCK-subject-a", owner="Owner_A", nonce="nonce-a")
                a_status = self.identity()[1]
                locks.acquire(
                    lock_kind="PATH_LOCK", task="task-b", owner="Owner_B",
                    ttl_seconds=120, paths=[{"kind": "exact", "path": "subject.txt"}],
                    nonce="nonce-b", lock_id="LOCK-subject-b", base_head=self.base,
                )
                try:
                    subject.write_bytes(b"v3\n")
                finally:
                    locks.release(lock_id="LOCK-subject-b", owner="Owner_B", nonce="nonce-b")
                before = self.identity()
                self.assertEqual(a_status, before[1])
                with mock.patch.object(core, "_git", wraps=core._git) as calls:
                    self.assert_reason(
                        "EXPECTED_SUBJECT_MISMATCH", core.freeze_checkpoint,
                        self.request("subject.txt", expected_subject_sha256=expected["subject_sha256"]),
                    )
                commands = [call.args[1][0] for call in calls.call_args_list]
                self.assertNotIn("commit-tree", commands)
                self.assertNotIn("update-ref", commands)
                self.assertEqual(core._resolve_ref(self.repo, ref), previous)
                self.assertEqual(subject.read_bytes(), b"v3\n")
                self.assertEqual(self.identity(), before)
                self.assertEqual(locks.status()["active_locks"], [])

    def test_subject_cli_bound_freeze_preserves_legacy_metadata(self) -> None:
        (self.repo / "subject.txt").write_bytes(b"v2\n")
        stdout, stderr = io.StringIO(), io.StringIO()
        before = self.identity()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = cli.main([
                "subject", "--repo-root", str(self.repo.resolve()),
                "--path", "subject.txt", "--path", "other.txt",
            ])
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        observed = json.loads(stdout.getvalue())
        self.assertEqual(observed["status"], "OBSERVED")
        self.assertEqual(observed["base_head"], self.base)
        self.assertEqual(observed["path_set"], ["other.txt", "subject.txt"])
        self.assert_subject_rows(observed)
        self.assertEqual(self.identity(), before)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = cli.main([
                "freeze", "--repo-root", str(self.repo.resolve()),
                "--activity", "fixture-activity", "--label", "cli-bound",
                "--owner", "Fixture_Mgr", "--task", "fixture-task",
                "--path", "other.txt", "--path", "subject.txt",
                "--expected-subject-sha256", observed["subject_sha256"],
            ])
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        frozen = json.loads(stdout.getvalue())
        self.assertEqual(frozen["status"], "FROZEN")
        self.assertTrue(frozen["expected_subject_bound"])
        self.assertEqual(frozen["subject_sha256"], observed["subject_sha256"])
        self.assertEqual(frozen["path_set_sha256"], observed["path_set_sha256"])
        self.assertEqual(self.identity(), before)
        self.assertEqual(
            git_bytes(self.repo, "show", f"{frozen['checkpoint_commit']}:subject.txt"), b"v2\n",
        )
        metadata = json.loads(git_bytes(self.repo, "show", "-s", "--format=%B", frozen["checkpoint_commit"]))
        self.assertEqual(set(metadata), {
            "activity", "base_head", "checkpoint_label", "path_set", "path_set_sha256",
            "protocol", "schema_version", "owner", "task", "tool_version",
        })
        self.assertEqual(metadata["schema_version"], 1)
        self.assertEqual(core._commit_metadata(self.repo, frozen["checkpoint_commit"]), metadata)
        self.assertEqual(core.inspect_checkpoint(self.repo.resolve(), "fixture-activity")["status"], "EXACT")
        self.assertEqual(core.list_checkpoints(self.repo.resolve())["count"], 1)
        exported = core.export_checkpoint(core.ExportRequest(
            self.repo.resolve(), "fixture-activity", (self.root / "bound.patch").resolve(),
        ))
        self.assertEqual(exported["patch_sha256"], frozen["patch_sha256"])
        same = core.freeze_checkpoint(self.request(
            label="new-label", expected_subject_sha256=observed["subject_sha256"],
        ))
        self.assertEqual(same["status"], "UNCHANGED")
        self.assertEqual(same["checkpoint_commit"], frozen["checkpoint_commit"])
        self.assertTrue(same["expected_subject_bound"])
        self.assertEqual(same["subject_sha256"], observed["subject_sha256"])

    def test_subject_identity_dimensions_and_legacy_no_change_returns(self) -> None:
        subject = self.repo / "subject.txt"
        observed = core.observe_subject(self.repo.resolve(), ("subject.txt",))
        unchanged_base = core.freeze_checkpoint(self.request("subject.txt"))
        self.assertEqual(unchanged_base["status"], "NO_CHANGE")
        self.assertFalse(unchanged_base["expected_subject_bound"])
        self.assertEqual(unchanged_base["subject_sha256"], observed["subject_sha256"])
        wrong = "0" * 64 if observed["subject_sha256"] != "0" * 64 else "1" * 64
        self.assert_reason(
            "EXPECTED_SUBJECT_MISMATCH", core.freeze_checkpoint,
            self.request("subject.txt", expected_subject_sha256=wrong),
        )
        self.assertIsNone(core._resolve_ref(self.repo, "refs/codex/dev-checkpoints/fixture-activity"))
        expanded = core.observe_subject(self.repo.resolve(), ("subject.txt", "other.txt"))
        reordered = core.observe_subject(self.repo.resolve(), ("other.txt", "subject.txt"))
        self.assertEqual(expanded["subject_sha256"], reordered["subject_sha256"])
        self.assertNotEqual(expanded["subject_sha256"], observed["subject_sha256"])
        self.assertNotEqual(expanded["path_set_sha256"], observed["path_set_sha256"])
        git(self.repo, "commit", "--allow-empty", "-m", "fixture: new base, same bytes")
        rebased = core.observe_subject(self.repo.resolve(), ("subject.txt",))
        self.assertNotEqual(rebased["base_head"], observed["base_head"])
        self.assertNotEqual(rebased["subject_sha256"], observed["subject_sha256"])
        with mock.patch.object(core, "_git", wraps=core._git) as calls:
            self.assert_reason(
                "EXPECTED_SUBJECT_MISMATCH", core.freeze_checkpoint,
                self.request("subject.txt", expected_subject_sha256=observed["subject_sha256"]),
            )
        commands = [call.args[1][0] for call in calls.call_args_list]
        self.assertNotIn("commit-tree", commands)
        self.assertNotIn("update-ref", commands)
        self.assertIsNone(core._resolve_ref(self.repo, "refs/codex/dev-checkpoints/fixture-activity"))
        with mock.patch.object(core, "_worktree_mode", return_value="100755"):
            executable = core.observe_subject(self.repo.resolve(), ("subject.txt",))
        self.assertNotEqual(executable["subject_sha256"], rebased["subject_sha256"])
        self.assertEqual(executable["path_snapshots"][0]["mode"], "100755")
        subject.unlink()
        deleted = core.observe_subject(self.repo.resolve(), ("subject.txt",))
        self.assertNotEqual(deleted["subject_sha256"], rebased["subject_sha256"])
        untracked = self.repo / "untracked.bin"
        untracked.write_bytes(b"\x00\xffA\r\n")
        first = core.observe_subject(self.repo.resolve(), ("untracked.bin",))
        untracked.write_bytes(b"\x00\xffB\r\n")
        second = core.observe_subject(self.repo.resolve(), ("untracked.bin",))
        self.assertNotEqual(first["subject_sha256"], second["subject_sha256"])
        mixed = core.observe_subject(self.repo.resolve(), ("subject.txt", "untracked.bin"))
        self.assert_subject_rows(mixed)
        frozen = core.freeze_checkpoint(self.request(
            "subject.txt", "untracked.bin", expected_subject_sha256=mixed["subject_sha256"],
        ))
        self.assertEqual(frozen["status"], "FROZEN")
        self.assertEqual(frozen["subject_sha256"], mixed["subject_sha256"])
        self.assertEqual(git(self.repo, "ls-tree", frozen["checkpoint_commit"], "--", "subject.txt"), "")
        self.assertEqual(
            git_bytes(self.repo, "show", f"{frozen['checkpoint_commit']}:untracked.bin"), b"\x00\xffB\r\n",
        )
        same = core.freeze_checkpoint(self.request())
        self.assertEqual(same["status"], "UNCHANGED")
        self.assertFalse(same["expected_subject_bound"])
        self.assertEqual(same["subject_sha256"], mixed["subject_sha256"])
        self.assert_reason(
            "EXPECTED_SUBJECT_MISMATCH", core.freeze_checkpoint,
            self.request(expected_subject_sha256=wrong),
        )
        self.assertEqual(
            core._resolve_ref(self.repo, "refs/codex/dev-checkpoints/fixture-activity"), frozen["checkpoint_commit"],
        )

    def test_subject_input_validation_and_read_only_drift_detection(self) -> None:
        for invalid in ("", "A" * 64, "0" * 63, "0" * 65, "g" * 64):
            with self.subTest(invalid=invalid), mock.patch.object(core.LockCoordinator, "acquire") as acquire:
                self.assert_reason(
                    "INPUT_INVALID", core.freeze_checkpoint,
                    self.request("subject.txt", expected_subject_sha256=invalid),
                )
                acquire.assert_not_called()
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(core.LockCoordinator, "acquire") as acquire:
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = cli.main([
                    "freeze", "--repo-root", str(self.repo.resolve()),
                    "--activity", "fixture-activity", "--label", "invalid-cli",
                    "--owner", "Fixture_Mgr", "--task", "fixture-task",
                    "--path", "subject.txt", "--expected-subject-sha256", "A" * 64,
                ])
            acquire.assert_not_called()
        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(json.loads(stderr.getvalue())["reason_code"], "INPUT_INVALID")
        before = {
            path.relative_to(self.repo).as_posix(): path.read_bytes()
            for path in self.repo.rglob("*") if path.is_file()
        }
        original_open = Path.open

        def read_only_open(path, mode="r", *args, **kwargs):
            self.assertFalse(any(flag in mode for flag in "wax+"), "observer opened a file for writing")
            return original_open(path, mode, *args, **kwargs)

        with (
            mock.patch.object(core.LockCoordinator, "acquire") as acquire,
            mock.patch.object(core.tempfile, "TemporaryDirectory", side_effect=AssertionError("observer created tempdir")),
            mock.patch.object(core.os, "fsync", side_effect=AssertionError("observer called fsync")),
            mock.patch.object(Path, "open", new=read_only_open),
        ):
            observed = core.observe_subject(self.repo.resolve(), ("subject.txt", "other.txt"))
            acquire.assert_not_called()
        self.assertEqual(observed["status"], "OBSERVED")
        self.assert_subject_rows(observed)
        self.assertEqual({
            path.relative_to(self.repo).as_posix(): path.read_bytes()
            for path in self.repo.rglob("*") if path.is_file()
        }, before)
        original_capture = core._capture_regular_file
        injected = False

        def drifting_capture(source, repo, destination: Path | None):
            nonlocal injected
            self.assertIsNone(destination)
            captured = original_capture(source, repo, destination)
            if source == self.repo / "subject.txt" and not injected:
                injected = True
                source.write_bytes(b"v3\n")
            return captured

        with mock.patch.object(core, "_capture_regular_file", new=drifting_capture):
            self.assert_reason(
                "CANONICAL_STATE_CHANGED", core.observe_subject,
                self.repo.resolve(), ("subject.txt",),
            )
        self.assertTrue(injected)
        self.assertIsNone(core._resolve_ref(self.repo, "refs/codex/dev-checkpoints/fixture-activity"))

    def test_subject_observation_allows_disjoint_path_writer_but_rejects_target_drift(self) -> None:
        locks = LockCoordinator(self.repo)
        acquired = []
        try:
            for owner, path in (("A", "subject.txt"), ("B", "other.txt")):
                locks.acquire(
                    lock_kind="PATH_LOCK", task=f"task-{owner}", owner=f"Owner_{owner}",
                    ttl_seconds=120, paths=[{"kind": "exact", "path": path}],
                    nonce=f"nonce-{owner}", lock_id=f"LOCK-observe-{owner}", base_head=self.base,
                )
                acquired.append(owner)
            self.assertEqual(len(locks.status()["active_locks"]), 2)
            expected = core.observe_subject(self.repo.resolve(), ("subject.txt",))
            original_capture = core._capture_regular_file
            target = "other.txt"
            injected = False

            def write_during_observation(source, repo, destination: Path | None):
                nonlocal injected
                self.assertIsNone(destination)
                captured = original_capture(source, repo, destination)
                if source == self.repo / "subject.txt" and not injected:
                    injected = True
                    (self.repo / target).write_bytes(b"changed\n")
                return captured

            with mock.patch.object(core, "_capture_regular_file", new=write_during_observation):
                observed = core.observe_subject(self.repo.resolve(), ("subject.txt",))
            self.assertTrue(injected)
            self.assertEqual((self.repo / "other.txt").read_bytes(), b"changed\n")
            self.assertEqual(observed["subject_sha256"], expected["subject_sha256"])
            self.assert_subject_rows(observed)
            target = "subject.txt"
            injected = False
            with mock.patch.object(core, "_capture_regular_file", new=write_during_observation):
                self.assert_reason(
                    "CANONICAL_STATE_CHANGED", core.observe_subject,
                    self.repo.resolve(), ("subject.txt",),
                )
            self.assertTrue(injected)
        finally:
            for owner in reversed(acquired):
                locks.release(lock_id=f"LOCK-observe-{owner}", owner=f"Owner_{owner}", nonce=f"nonce-{owner}")

    def test_subject_observation_rejects_head_branch_and_index_drift(self) -> None:
        original_capture = core._capture_regular_file
        for state_part in ("head", "branch", "index"):
            with self.subTest(state_part=state_part):
                injected = False

                def change_repository_state(source, repo, destination: Path | None):
                    nonlocal injected
                    self.assertIsNone(destination)
                    captured = original_capture(source, repo, destination)
                    if source == self.repo / "subject.txt" and not injected:
                        injected = True
                        if state_part == "head":
                            git(self.repo, "commit", "--allow-empty", "-m", "fixture: observed HEAD moved")
                        elif state_part == "branch":
                            git(self.repo, "branch", "-m", "fixture-renamed")
                        else:
                            git(self.repo, "update-index", "--assume-unchanged", "--", "other.txt")
                    return captured

                with mock.patch.object(core, "_capture_regular_file", new=change_repository_state):
                    self.assert_reason(
                        "CANONICAL_STATE_CHANGED", core.observe_subject,
                        self.repo.resolve(), ("subject.txt",),
                    )
                self.assertTrue(injected)
                self.assertEqual((self.repo / "subject.txt").read_bytes(), b"v1\n")
        self.assertIsNone(core._resolve_ref(self.repo, "refs/codex/dev-checkpoints/fixture-activity"))

    def test_transient_multi_file_bytes_fail_before_creating_checkpoint_ref(self) -> None:
        (self.repo / "subject.txt").write_text("v2\n", encoding="utf-8", newline="\n")
        original_capture = core._capture_regular_file
        injected = False

        def transient_capture(source, repo, destination):
            nonlocal injected
            if source == self.repo / "subject.txt" and not injected:
                injected = True
                original = source.read_bytes()
                source.write_bytes(b"transient\n")
                try:
                    return original_capture(source, repo, destination)
                finally:
                    source.write_bytes(original)
            return original_capture(source, repo, destination)

        with mock.patch.object(core, "_capture_regular_file", new=transient_capture):
            self.assert_reason(
                "CANONICAL_STATE_CHANGED",
                core.freeze_checkpoint,
                self.request("other.txt", "subject.txt"),
            )
        self.assertTrue(injected)
        self.assertEqual((self.repo / "subject.txt").read_bytes(), b"v2\n")
        self.assertIsNone(core._resolve_ref(self.repo, "refs/codex/dev-checkpoints/fixture-activity"))

    def test_final_prepublication_drift_preserves_prior_checkpoint_ref(self) -> None:
        (self.repo / "subject.txt").write_text("v2\n", encoding="utf-8", newline="\n")
        first = core.freeze_checkpoint(self.request("subject.txt", label="initial"))
        (self.repo / "subject.txt").write_text("v3\n", encoding="utf-8", newline="\n")
        original_git = core._git
        injected = False

        def drifting_git(repo, arguments, **kwargs):
            nonlocal injected
            result = original_git(repo, arguments, **kwargs)
            if arguments[0] == "commit-tree" and not injected:
                injected = True
                (self.repo / "subject.txt").write_text("v4\n", encoding="utf-8", newline="\n")
            return result

        with mock.patch.object(core, "_git", new=drifting_git):
            self.assert_reason(
                "CANONICAL_STATE_CHANGED",
                core.freeze_checkpoint,
                self.request("subject.txt"),
            )
        self.assertTrue(injected)
        self.assertEqual(
            core._resolve_ref(self.repo, "refs/codex/dev-checkpoints/fixture-activity"),
            first["checkpoint_commit"],
        )

    def test_export_rejects_target_inside_repository(self) -> None:
        (self.repo / "subject.txt").write_text("v2\n", encoding="utf-8", newline="\n")
        frozen = core.freeze_checkpoint(self.request("subject.txt"))
        self.assertEqual(frozen["status"], "FROZEN")
        self.assert_reason(
            "EXPORT_TARGET_INVALID",
            core.export_checkpoint,
            core.ExportRequest(
                self.repo.resolve(),
                "fixture-activity",
                (self.repo / "inside.patch").resolve(),
            ),
        )

    def test_diff_allowlist_rejects_unbound_or_noncanonical_paths(self) -> None:
        canonical = tree_patch_arguments(self.base, self.base, ("subject.txt",))
        self.assertTrue(core._arguments_allowed(canonical))
        self.assertFalse(
            core._arguments_allowed(
                tree_patch_arguments(self.base, self.base, ())
            )
        )
        escaped = (*canonical[:-1], "../outside")
        self.assertFalse(
            core._arguments_allowed(escaped)
        )

    def test_export_is_canonical_full_index_binary_and_host_independent(self) -> None:
        binary = self.repo / "binary.bin"
        binary.write_bytes(bytes(range(256)) * 4)
        (self.repo / "subject.txt").write_text("v2\n", encoding="utf-8", newline="\n")
        (self.repo / "other.txt").write_text("foreign staged\n", encoding="utf-8")
        git(self.repo, "add", "--", "other.txt")
        before = self.identity()
        order = self.root / "diff-order.txt"
        order.write_text("subject.txt\nbinary.bin\n", encoding="utf-8", newline="\n")
        hostile = {
            "core.abbrev": "7",
            "core.quotePath": "false",
            "diff.algorithm": "histogram",
            "diff.context": "0",
            "diff.indentHeuristic": "true",
            "diff.interHunkContext": "99",
            "diff.mnemonicPrefix": "true",
            "diff.noprefix": "true",
            "diff.orderFile": str(order),
            "diff.renames": "true",
            "color.ui": "always",
        }
        for key, value in hostile.items():
            git(self.repo, "config", "--local", key, value)
        hostile_global = self.root / "hostile-global.gitconfig"
        git(self.repo, "config", "--file", str(hostile_global), "core.autocrlf", "true")
        with mock.patch.dict(
            core.os.environ,
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_GLOBAL": str(hostile_global),
                "GIT_CONFIG_KEY_0": "diff.algorithm",
                "GIT_CONFIG_VALUE_0": "minimal",
                "GIT_DIFF_OPTS": "-U0",
                "GIT_DIR": str(self.root / "wrong-git-dir"),
                "GIT_EXTERNAL_DIFF": "missing-external-diff",
                "GIT_WORK_TREE": str(self.root / "wrong-work-tree"),
            },
        ):
            frozen = core.freeze_checkpoint(self.request("binary.bin", "subject.txt"))
            output = self.root / "canonical.patch"
            exported = core.export_checkpoint(
                core.ExportRequest(self.repo.resolve(), "fixture-activity", output.resolve())
            )
        expected = canonical_git_bytes(
            self.repo,
            *tree_patch_arguments(
                self.base,
                frozen["checkpoint_commit"],
                ("binary.bin", "subject.txt"),
            ),
        )
        raw = output.read_bytes()
        self.assertEqual(raw, expected)
        self.assertEqual(exported["patch_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertRegex(raw, rb"index [0-9a-f]{40}\.\.[0-9a-f]{40}")
        self.assertIn(b"GIT binary patch", raw)
        self.assertEqual(self.identity(), before)

    def test_existing_git_mutation_lock_blocks_checkpoint(self) -> None:
        (self.repo / "subject.txt").write_text("v2\n", encoding="utf-8", newline="\n")
        locks = LockCoordinator(self.repo)
        locks.acquire(
            lock_kind="GIT_MUTATION_LOCK",
            task="other-task",
            owner="Other_Mgr",
            ttl_seconds=300,
            nonce="other-nonce",
            lock_id="LOCK-other-git",
            base_head=self.base,
        )
        try:
            self.assert_reason(
                "GIT_MUTATION_LOCK_UNAVAILABLE",
                core.freeze_checkpoint,
                self.request("subject.txt"),
            )
        finally:
            locks.release(lock_id="LOCK-other-git", owner="Other_Mgr", nonce="other-nonce")


if __name__ == "__main__":
    unittest.main()
