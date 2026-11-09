from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import errno
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import jsonschema

from tools.leasectl import core
from tools.leasectl.cli import build_parser
from tools.leasectl.core import (
    LockConflict,
    LockCoordinator,
    LockError,
    git_head,
    normalize_path_rules,
    normalize_repo_path,
    path_rules_intersect,
)


ROOT = Path(__file__).resolve().parents[2]


def run_git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def create_repo(root: Path) -> Path:
    repo = root / "repo"
    repo.mkdir()
    run_git(repo, "init", "-b", "main")
    run_git(repo, "config", "user.name", "Synthetic Tester")
    run_git(repo, "config", "user.email", "synthetic@example.invalid")
    (repo / "README.md").write_text("synthetic\n", encoding="utf-8")
    run_git(repo, "add", "README.md")
    run_git(repo, "commit", "-m", "initial")
    return repo


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 6, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


def _competing_acquire(repo: str, lock_id: str, start_gate: object) -> str:
    start_gate.wait(timeout=15)
    try:
        LockCoordinator(Path(repo), lock_timeout_seconds=10).acquire(
            lock_kind="PATH_LOCK",
            task=f"task-{lock_id}",
            owner=lock_id,
            ttl_seconds=120,
            paths=[{"kind": "prefix", "path": "shared"}],
            nonce=f"nonce-{lock_id}",
            lock_id=lock_id,
        )
    except LockError:
        return "CONFLICT"
    return "ACQUIRED"


class PathNormalizationTests(unittest.TestCase):
    def test_separator_and_unicode_normalization(self) -> None:
        self.assertEqual(normalize_repo_path(r"project_a\reports\x.md"), "project_a/reports/x.md")
        self.assertEqual(normalize_repo_path("cafe\u0301/report.md"), "caf\u00e9/report.md")

    def test_absolute_escape_git_and_windows_aliases_are_rejected(self) -> None:
        rejected = [
            "C:/repo/file.txt",
            r"\\server\share\file.txt",
            "/absolute/file.txt",
            "../escape.txt",
            "a/../escape.txt",
            ".git/index",
            "folder/CON.txt",
            "folder/trailing. ",
        ]
        for value in rejected:
            with self.subTest(value=value), self.assertRaises(LockError):
                normalize_repo_path(value)

    def test_segment_aware_intersection(self) -> None:
        prefix = {"kind": "prefix", "path": "project_a"}
        child = {"kind": "exact", "path": "project_a/report.md"}
        sibling = {"kind": "prefix", "path": "project_a0"}
        self.assertTrue(path_rules_intersect(prefix, child))
        self.assertFalse(path_rules_intersect(prefix, sibling))

    def test_case_collision_and_internal_overlap_fail(self) -> None:
        with self.assertRaisesRegex(LockError, "internally overlapping"):
            normalize_path_rules(
                [
                    {"kind": "prefix", "path": "Reports"},
                    {"kind": "exact", "path": "reports/result.md"},
                ]
            )

    def test_exact_parent_and_child_are_conservatively_overlapping(self) -> None:
        self.assertTrue(
            path_rules_intersect(
                {"kind": "exact", "path": "src"},
                {"kind": "exact", "path": "src/app.py"},
            )
        )
        self.assertTrue(
            path_rules_intersect(
                {"kind": "exact", "path": "src"},
                {"kind": "prefix", "path": "src/app"},
            )
        )


class GitObservationProcessTests(unittest.TestCase):
    def test_lock_git_children_never_create_windows_console_windows(self) -> None:
        completed = subprocess.CompletedProcess([], 0, "", "")
        pinned = str(Path(sys.executable).resolve())
        repo = Path("repo").resolve()
        with (
            patch("tools.leasectl.core._git_executable", return_value=pinned),
            patch("tools.leasectl.core.subprocess.run", return_value=completed) as runner,
            patch.dict(
                os.environ,
                {
                    "GIT_DIR": "poison",
                    "git_work_tree": "poison",
                    "GIT_CONFIG_COUNT": "99",
                },
                clear=False,
            ),
        ):
            core._run_git(repo, ["rev-parse", "HEAD"])
        command = runner.call_args.args[0]
        self.assertEqual(command[0], pinned)
        self.assertEqual(runner.call_args.kwargs["executable"], pinned)
        self.assertIn(f"safe.directory={repo.as_posix()}", command)
        self.assertNotIn("safe.directory=*", command)
        self.assertEqual(command[command.index("-C") + 1], str(repo))
        self.assertEqual(runner.call_args.kwargs["cwd"], str(Path(pinned).parent))
        environment = runner.call_args.kwargs["env"]
        self.assertNotIn("GIT_DIR", environment)
        self.assertNotIn("git_work_tree", environment)
        self.assertEqual(environment["GIT_CONFIG_COUNT"], "0")
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(
            runner.call_args.kwargs["creationflags"],
            core.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )

    def test_host_identity_incident_trusts_only_the_exact_lock_repo_per_process(self) -> None:
        completed = subprocess.CompletedProcess([], 0, "", "")
        pinned = str(Path(sys.executable).resolve())
        exact_root = (Path("different-owner-repo") / "leaf").resolve()
        with (
            patch("tools.leasectl.core._git_executable", return_value=pinned),
            patch("tools.leasectl.core.subprocess.run", return_value=completed) as runner,
            patch.dict(
                os.environ,
                {"GIT_CONFIG_GLOBAL": "ambient", "GIT_CONFIG_COUNT": "99"},
                clear=False,
            ),
        ):
            core._run_git(exact_root, ["rev-parse", "--show-toplevel"])

        command = runner.call_args.args[0]
        trusted = [value for value in command if value.startswith("safe.directory=")]
        self.assertEqual(trusted, [f"safe.directory={exact_root.as_posix()}"])
        self.assertEqual(runner.call_args.kwargs["env"]["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(runner.call_args.kwargs["env"]["GIT_CONFIG_COUNT"], "0")

    def test_git_executable_rejects_resolution_outside_absolute_path_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            allowed = root / "allowed"
            outside = root / "outside"
            allowed.mkdir()
            outside.mkdir()
            executable = outside / ("git.exe" if os.name == "nt" else "git")
            executable.write_bytes(b"not executable")
            with (
                patch.dict(os.environ, {"PATH": str(allowed)}, clear=False),
                patch("tools.leasectl.core.shutil.which", return_value=str(executable)),
                self.assertRaisesRegex(LockError, "Git command unavailable"),
            ):
                core._git_executable()

    def test_repository_context_ignores_ambient_git_redirection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target_root = root / "target-root"
            foreign_root = root / "foreign-root"
            target_root.mkdir()
            foreign_root.mkdir()
            target = create_repo(target_root)
            foreign = create_repo(foreign_root)
            with patch.dict(
                os.environ,
                {
                    "GIT_DIR": str(foreign / ".git"),
                    "GIT_WORK_TREE": str(foreign),
                    "GIT_COMMON_DIR": str(foreign / ".git"),
                    "GIT_OBJECT_DIRECTORY": str(foreign / ".git" / "objects"),
                },
                clear=False,
            ):
                coordinator = LockCoordinator(target)
                acquired = coordinator.acquire(
                    lock_kind="PATH_LOCK",
                    task="ambient-redirection-test",
                    owner="test-owner",
                    ttl_seconds=120,
                    paths=[{"kind": "exact", "path": "README.md"}],
                    nonce="ambient-redirection-nonce",
                    lock_id="ambient-redirection-lock",
                )
                self.assertEqual(
                    coordinator.git_common_dir,
                    (target / ".git").resolve(),
                )
                coordinator.release(
                    lock_id=acquired["lock"]["lock_id"],
                    owner="test-owner",
                    nonce="ambient-redirection-nonce",
                )
            self.assertFalse((foreign / ".git" / "toplayer-runtime").exists())


class AdoptionLockObservationTests(unittest.TestCase):
    def test_batch_context_rejects_missing_or_extra_identity_rows(self) -> None:
        for output in ("", "one-row", "first\nsecond\nextra"):
            with self.subTest(output=output), patch.object(core, "_run_git", return_value=output):
                with self.assertRaisesRegex(LockError, "invalid shape"):
                    core._git_repository_context(Path.cwd())

    def test_batch_context_cannot_append_arbitrary_git_arguments(self) -> None:
        with self.assertRaisesRegex(LockError, "outside the allowlist"):
            core._git_observation_spec(Path.cwd(), ["rev-parse", "--show-toplevel", "--git-common-dir", "--git-dir"])

    def test_adoption_audit_accepts_exact_lock_observation_and_replay_command(self) -> None:
        from tools.adoptctl import core as adoption
        root = Path("observation-leaf").resolve()
        with patch.object(core, "_git_executable", return_value=str(Path(sys.executable).resolve())):
            argv, environment, cwd = core._git_observation_spec(root, ["rev-parse", "--show-toplevel", "--git-common-dir"])
            details = adoption._readonly_git_details(argv[0], argv, cwd, environment, allowed_worktree=root)
        self.assertIsNotNone(details)
        self.assertEqual(details[0], ["rev-parse", "--show-toplevel", "--git-common-dir"])
        self.assertTrue(adoption._allowed_readonly_git_command(tuple(details[0])))

    def test_adoption_audit_refuses_forged_lock_observation_tuple(self) -> None:
        from tools.adoptctl import core as adoption
        root, foreign = Path("observation-leaf").resolve(), Path("foreign-observation").resolve()
        with patch.object(core, "_git_executable", return_value=str(Path(sys.executable).resolve())):
            argv, environment, cwd = core._git_observation_spec(root, ["worktree", "list", "--porcelain"])
            foreign_argv, foreign_environment, foreign_cwd = core._git_observation_spec(foreign, ["worktree", "list", "--porcelain"])
            forged = [
                (argv[0], foreign_argv, foreign_cwd, foreign_environment),
                (argv[0], argv, str(root), environment),
                (argv[0], argv, cwd, {**environment, "GIT_DIR": "foreign"}),
                (argv[0], argv + ["--force"], cwd, environment),
                (str(foreign / "git.exe"), argv, cwd, environment),
            ]
            for executable, arguments, invoked_cwd, invoked_environment in forged:
                with self.subTest(arguments=arguments, cwd=invoked_cwd):
                    self.assertIsNone(adoption._readonly_git_details(
                        executable, arguments, invoked_cwd, invoked_environment, allowed_worktree=root))


    def test_lock_observation_binds_real_windows_audit_executable_and_tuple(self) -> None:
        from tools.adoptctl import core as adoption
        observed = []
        enabled = {"value": False}

        def capture(event, args):
            if enabled["value"] and event == "subprocess.Popen":
                observed.append(args)

        sys.addaudithook(capture)
        with tempfile.TemporaryDirectory() as temporary:
            repo = create_repo(Path(temporary))
            enabled["value"] = True
            try:
                core._run_git(repo, ["rev-parse", "--show-toplevel", "--git-common-dir"])
            finally:
                enabled["value"] = False
            self.assertEqual(len(observed), 1)
            executable, arguments, cwd, environment = observed[0]
            self.assertIsNotNone(executable, "real Popen audit must bind the application executable")
            self.assertIsNotNone(adoption._readonly_git_details(
                executable, arguments, cwd, environment, allowed_worktree=repo))
            self.assertIsNone(adoption._readonly_git_details(
                None, arguments, cwd, environment, allowed_worktree=repo))


class LockCoordinatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = create_repo(self.root)
        self.clock = Clock()
        self.coordinator = LockCoordinator(self.repo, now_fn=self.clock)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def acquire_path(
        self,
        lock_id: str,
        path: str,
        *,
        kind: str = "prefix",
        owner: str | None = None,
        ttl: int = 300,
    ) -> dict:
        return self.coordinator.acquire(
            lock_kind="PATH_LOCK",
            task=f"task-{lock_id}",
            owner=owner or f"owner-{lock_id}",
            ttl_seconds=ttl,
            paths=[{"kind": kind, "path": path}],
            nonce=f"nonce-{lock_id}",
            lock_id=lock_id,
        )

    def test_status_is_read_only_and_does_not_create_runtime_storage(self) -> None:
        runtime = self.coordinator.runtime_dir
        before = sorted(path.relative_to(self.repo).as_posix() for path in self.repo.rglob("*"))
        result = self.coordinator.status()
        after = sorted(path.relative_to(self.repo).as_posix() for path in self.repo.rglob("*"))
        self.assertEqual(result["runtime_state"], "ABSENT")
        self.assertEqual(result["active_locks"], [])
        self.assertEqual(before, after)
        self.assertFalse(runtime.exists())

    def test_atomic_state_write_retries_bounded_windows_sharing_denials(self) -> None:
        destination = self.root / "state.json"
        denial = PermissionError("transient Windows sharing denial")
        with (
            patch("tools.leasectl.core.os.name", "nt"),
            patch("tools.leasectl.core.os.replace", side_effect=[denial, denial, None]) as replace,
            patch("tools.leasectl.core.time.sleep") as sleep,
        ):
            core._atomic_write_json(destination, {"state": "safe"})
        self.assertEqual(replace.call_count, 3)
        self.assertEqual(
            [call.args[0] for call in sleep.call_args_list],
            list(core.WINDOWS_ATOMIC_REPLACE_RETRY_DELAYS_SECONDS[:2]),
        )

    def test_atomic_state_write_fails_closed_after_bounded_windows_retries(self) -> None:
        destination = self.root / "state.json"
        denial = PermissionError("persistent Windows sharing denial")
        with (
            patch("tools.leasectl.core.os.name", "nt"),
            patch("tools.leasectl.core.os.replace", side_effect=denial) as replace,
            patch("tools.leasectl.core.time.sleep") as sleep,
            self.assertRaisesRegex(LockError, "cannot be written atomically"),
        ):
            core._atomic_write_json(destination, {"state": "blocked"})
        self.assertEqual(
            replace.call_count,
            len(core.WINDOWS_ATOMIC_REPLACE_RETRY_DELAYS_SECONDS) + 1,
        )
        self.assertEqual(
            sleep.call_count,
            len(core.WINDOWS_ATOMIC_REPLACE_RETRY_DELAYS_SECONDS),
        )
        self.assertFalse(destination.exists())

    def test_existing_state_without_mutex_fails_closed(self) -> None:
        self.coordinator.runtime_dir.mkdir(parents=True)
        self.coordinator.state_path.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "coordination_scope": "single_host_single_git_common_dir",
                    "locks": [],
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(LockError, "lock file is absent"):
            self.coordinator.status()

    def test_no_grant_or_toplayer_configuration_is_required(self) -> None:
        result = self.acquire_path("LOCK-NO-GRANT", "src")
        record = result["lock"]
        self.assertEqual(result["status"], "ACQUIRED")
        self.assertEqual(record["lock_kind"], "PATH_LOCK")
        self.assertEqual(record["base_head"], git_head(self.repo))
        forbidden = {
            "grant",
            "capabilities",
            "budget",
            "publication_remote",
            "source_lease_bindings",
            "receipt",
            "release_identity",
        }
        self.assertTrue(forbidden.isdisjoint(record))
        self.assertFalse((self.repo / ".toplayer").exists())

    def test_disjoint_path_locks_coexist(self) -> None:
        self.acquire_path("LOCK-BIOAI", "bioai_frontier_atlas")
        second = self.acquire_path("LOCK-UAI2", "project_a")
        self.assertEqual(second["status"], "ACQUIRED")
        self.assertEqual(len(self.coordinator.status()["active_locks"]), 2)

    def test_overlapping_exact_prefix_and_case_collisions_fail(self) -> None:
        self.acquire_path("LOCK-FIRST", "reports")
        for candidate in ("reports/result.md", "REPORTS/other.md"):
            with self.subTest(candidate=candidate), self.assertRaisesRegex(
                LockConflict, "lock conflict requires wait, coordination, or handoff"
            ):
                self.acquire_path("LOCK-SECOND", candidate, kind="exact")
        self.assertEqual(len(self.coordinator.status()["active_locks"]), 1)

    def test_project_a_and_project_a0_do_not_collide(self) -> None:
        self.acquire_path("LOCK-UAI2", "project_a")
        result = self.acquire_path("LOCK-UAI20", "project_a0")
        self.assertEqual(result["status"], "ACQUIRED")

    def test_git_mutation_lock_excludes_all_path_locks(self) -> None:
        path = self.acquire_path("LOCK-PATH", "src")
        with self.assertRaisesRegex(LockError, "lock conflict"):
            self.coordinator.acquire(
                lock_kind="GIT_MUTATION_LOCK",
                task="git-one",
                owner="owner-one",
                ttl_seconds=120,
                nonce="nonce-git-one",
                lock_id="LOCK-GIT-ONE",
            )
        self.coordinator.release(
            lock_id=path["lock"]["lock_id"],
            owner=path["lock"]["owner"],
            nonce=path["lock"]["nonce"],
        )
        first = self.coordinator.acquire(
            lock_kind="GIT_MUTATION_LOCK",
            task="git-one",
            owner="owner-one",
            ttl_seconds=120,
            nonce="nonce-git-one",
            lock_id="LOCK-GIT-ONE",
        )
        self.assertEqual(first["lock"]["paths"], [])
        with self.assertRaisesRegex(LockError, "lock conflict"):
            self.coordinator.acquire(
                lock_kind="GIT_MUTATION_LOCK",
                task="git-two",
                owner="owner-two",
                ttl_seconds=120,
                nonce="nonce-git-two",
                lock_id="LOCK-GIT-TWO",
            )
        with self.assertRaisesRegex(LockError, "lock conflict"):
            self.acquire_path("LOCK-PATH-WHILE-GIT", "other")
        self.assertEqual(len(self.coordinator.status()["active_locks"]), 1)

    def test_legacy_names_are_aliases_not_authority(self) -> None:
        path = self.coordinator.acquire(
            lock_kind="PROJECT_PATH_LEASE",
            task="legacy-name",
            owner="owner",
            ttl_seconds=120,
            paths=[{"kind": "exact", "path": "legacy.txt"}],
            nonce="legacy-nonce",
            lock_id="LOCK-LEGACY-PATH",
        )
        self.assertEqual(path["lock"]["lock_kind"], "PATH_LOCK")
        self.coordinator.release(
            lock_id=path["lock"]["lock_id"],
            owner=path["lock"]["owner"],
            nonce=path["lock"]["nonce"],
        )
        git = self.coordinator.acquire(
            lock_kind="GIT_PUBLICATION_LEASE",
            task="legacy-git-name",
            owner="owner",
            ttl_seconds=120,
            nonce="legacy-git-nonce",
            lock_id="LOCK-LEGACY-GIT",
        )
        self.assertEqual(git["lock"]["lock_kind"], "GIT_MUTATION_LOCK")
        self.assertEqual(git["legacy_alias_used"], "GIT_PUBLICATION_LEASE")

    def test_git_mutation_lock_has_short_ttl_ceiling(self) -> None:
        with self.assertRaisesRegex(LockError, "between 1 and 900"):
            self.coordinator.acquire(
                lock_kind="GIT_MUTATION_LOCK",
                task="too-long",
                owner="owner",
                ttl_seconds=901,
            )

    def test_authority_and_rebind_classes_are_retired(self) -> None:
        for legacy_class in (
            "HOT_STATE_LEASE",
            "SHARED_CORE_LEASE",
            "FIRST_REBIND_LEASE",
            "RELEASE_REBIND_LEASE",
            "PAUSED_ZERO_GRANT_REBIND_LEASE",
        ):
            with self.subTest(legacy_class=legacy_class), self.assertRaisesRegex(
                LockError, "is retired"
            ):
                self.coordinator.acquire(
                    lock_kind=legacy_class,
                    task="retired",
                    owner="owner",
                    ttl_seconds=120,
                    paths=[{"kind": "exact", "path": "x"}],
                )

    def test_renew_rotates_nonce_and_release_checks_owner_and_nonce(self) -> None:
        self.acquire_path("LOCK-ROTATE", "src", owner="owner")
        renewed = self.coordinator.renew(
            lock_id="LOCK-ROTATE",
            owner="owner",
            nonce="nonce-LOCK-ROTATE",
            new_nonce="nonce-rotated",
            ttl_seconds=600,
        )
        self.assertEqual(renewed["status"], "RENEWED")
        with self.assertRaisesRegex(LockError, "owner or nonce mismatch"):
            self.coordinator.release(
                lock_id="LOCK-ROTATE",
                owner="owner",
                nonce="nonce-LOCK-ROTATE",
            )
        released = self.coordinator.release(
            lock_id="LOCK-ROTATE",
            owner="owner",
            nonce="nonce-rotated",
        )
        self.assertEqual(released["status"], "RELEASED")
        self.assertEqual(self.coordinator.status()["active_locks"], [])

    def test_expired_lock_can_be_recovered_only_without_new_conflict(self) -> None:
        self.acquire_path("LOCK-STALE", "src", owner="owner", ttl=10)
        self.clock.advance(11)
        recovered = self.coordinator.renew(
            lock_id="LOCK-STALE",
            owner="owner",
            nonce="nonce-LOCK-STALE",
            new_nonce="nonce-recovered",
            ttl_seconds=120,
        )
        self.assertEqual(recovered["status"], "RECOVERED")
        self.assertEqual(recovered["lock"]["base_head"], git_head(self.repo))

        self.clock.advance(121)
        replacement = self.acquire_path("LOCK-REPLACEMENT", "src")
        self.assertIn("LOCK-STALE", replacement["stale_locks_recovered"])
        with self.assertRaisesRegex(LockError, "unknown lock_id"):
            self.coordinator.renew(
                lock_id="LOCK-STALE",
                owner="owner",
                nonce="nonce-recovered",
                ttl_seconds=120,
            )

    def test_renew_active_is_strict_and_leaves_expired_or_foreign_state_bytes_unchanged(self) -> None:
        acquired = self.acquire_path("LOCK-STRICT", "strict", owner="owner", ttl=10)["lock"]
        state_before_foreign = self.coordinator.state_path.read_bytes()
        with self.assertRaisesRegex(LockError, "owner or nonce mismatch"):
            self.coordinator.renew_active(
                lock_id="LOCK-STRICT",
                owner="foreign-owner",
                nonce=acquired["nonce"],
                ttl_seconds=120,
            )
        self.assertEqual(self.coordinator.state_path.read_bytes(), state_before_foreign)
        with self.assertRaisesRegex(LockError, "owner or nonce mismatch"):
            self.coordinator.renew_active(
                lock_id="LOCK-STRICT",
                owner="owner",
                nonce="foreign-nonce",
                ttl_seconds=120,
            )
        self.assertEqual(self.coordinator.state_path.read_bytes(), state_before_foreign)

        self.clock.advance(11)
        state_before_expired = self.coordinator.state_path.read_bytes()
        with self.assertRaisesRegex(LockError, "unexpired active"):
            self.coordinator.renew_active(
                lock_id="LOCK-STRICT",
                owner="owner",
                nonce=acquired["nonce"],
                ttl_seconds=120,
            )
        self.assertEqual(self.coordinator.state_path.read_bytes(), state_before_expired)

    def test_tiny_ttl_multiple_renew_active_calls_are_never_recovered(self) -> None:
        lock = self.acquire_path("LOCK-TINY", "tiny", owner="owner", ttl=3)["lock"]
        statuses: list[str] = []
        for _ in range(5):
            self.clock.advance(1)
            result = self.coordinator.renew_active(
                lock_id="LOCK-TINY",
                owner="owner",
                nonce=lock["nonce"],
                new_nonce=lock["nonce"],
                ttl_seconds=3,
            )
            statuses.append(result["status"])
            lock = result["lock"]
        self.assertEqual(statuses, ["RENEWED"] * 5)
        self.assertEqual(self.coordinator.status()["active_locks"][0]["lock_id"], "LOCK-TINY")

    def test_renew_active_retry_after_atomic_replace_failure_preserves_then_retries(self) -> None:
        lock = self.acquire_path("LOCK-RETRY", "retry", owner="owner")["lock"]
        before = self.coordinator.state_path.read_bytes()
        with patch("tools.leasectl.core._atomic_replace", side_effect=OSError("injected replace failure")):
            with self.assertRaisesRegex(LockError, "cannot be written atomically"):
                self.coordinator.renew_active(
                    lock_id="LOCK-RETRY",
                    owner="owner",
                    nonce=lock["nonce"],
                    new_nonce="retry-nonce",
                    ttl_seconds=120,
                )
        self.assertEqual(self.coordinator.state_path.read_bytes(), before)
        retried = self.coordinator.renew_active(
            lock_id="LOCK-RETRY",
            owner="owner",
            nonce=lock["nonce"],
            new_nonce="retry-nonce",
            ttl_seconds=120,
        )
        self.assertEqual(retried["status"], "RENEWED")

    def test_base_head_is_recorded_and_optional_assertion_fails_stale(self) -> None:
        with self.assertRaisesRegex(LockError, "base_head assertion"):
            self.coordinator.acquire(
                lock_kind="PATH_LOCK",
                task="stale",
                owner="owner",
                ttl_seconds=120,
                paths=[{"kind": "exact", "path": "x"}],
                base_head="0" * 40,
            )

    def test_tilde_number_is_not_assumed_to_be_a_windows_short_name(self) -> None:
        result = self.acquire_path(
            "LOCK-LEGITIMATE-TILDE", "backup~1/report.txt", kind="exact"
        )
        self.assertEqual(result["status"], "ACQUIRED")

    def test_unknown_renew_and_release_do_not_create_runtime_storage(self) -> None:
        self.assertFalse(self.coordinator.runtime_dir.exists())
        with self.assertRaisesRegex(LockError, "unknown lock_id"):
            self.coordinator.renew(
                lock_id="MISSING",
                owner="owner",
                nonce="nonce",
                ttl_seconds=120,
            )
        with self.assertRaisesRegex(LockError, "unknown lock_id"):
            self.coordinator.release(
                lock_id="MISSING", owner="owner", nonce="nonce"
            )
        self.assertFalse(self.coordinator.runtime_dir.exists())

    def test_renew_reports_other_expired_locks_it_prunes(self) -> None:
        self.acquire_path("LOCK-TARGET", "target", ttl=10)
        self.acquire_path("LOCK-OTHER", "other", ttl=10)
        self.clock.advance(11)
        result = self.coordinator.renew(
            lock_id="LOCK-TARGET",
            owner="owner-LOCK-TARGET",
            nonce="nonce-LOCK-TARGET",
            new_nonce="nonce-recovered",
            ttl_seconds=120,
        )
        self.assertEqual(result["status"], "RECOVERED")
        self.assertEqual(result["stale_locks_recovered"], ["LOCK-OTHER"])

    def test_renew_revalidates_redirect_surface(self) -> None:
        result = self.acquire_path("LOCK-SURFACE", "src")
        target_path = self.repo / "src"
        target_path.mkdir()

        def redirected(path: Path) -> bool:
            return path == target_path

        with patch("tools.leasectl.core._is_redirect", side_effect=redirected):
            with self.assertRaisesRegex(LockError, "symlink or reparse"):
                self.coordinator.renew(
                    lock_id="LOCK-SURFACE",
                    owner="owner-LOCK-SURFACE",
                    nonce=result["lock"]["nonce"],
                    ttl_seconds=120,
                )

    def test_lock_record_matches_portable_schema(self) -> None:
        record = self.acquire_path("LOCK-SCHEMA", "src")["lock"]
        schema = json.loads(
            (ROOT / "schemas" / "dynamic_write_lease.schema.json").read_text(
                encoding="utf-8"
            )
        )
        validator = jsonschema.Draft202012Validator(schema)
        validator.validate(record)
        invalid_git = dict(record)
        invalid_git.update(
            {
                "lock_kind": "GIT_MUTATION_LOCK",
                "paths": [],
                "ttl_seconds": 901,
            }
        )
        with self.assertRaises(jsonschema.ValidationError):
            validator.validate(invalid_git)

    def test_legacy_v1_state_migrates_to_concurrency_only(self) -> None:
        self.coordinator.runtime_dir.mkdir(parents=True)
        self.coordinator.lock_path.write_bytes(b"0")
        legacy = {
            "schema_version": 1,
            "coordination_scope": "single_host_single_git_common_dir",
            "repo_id": "legacy-repo",
            "leases": [
                {
                    "state": "ACTIVE",
                    "lease_id": "LEGACY-PATH",
                    "lease_class": "PROJECT_PATH_LEASE",
                    "task_package_id": "legacy-task",
                    "owner": "legacy-owner",
                    "base_head": git_head(self.repo),
                    "write_paths": [{"kind": "prefix", "path": "legacy"}],
                    "acquired_at": "2026-08-06T12:00:00Z",
                    "expires_at": "2026-08-06T12:10:00Z",
                    "ttl_seconds": 600,
                    "nonce": "legacy-nonce",
                    "grant": {"grant_id": "IGNORED"},
                }
            ],
            "retired_lease_ids": [],
            "receipt_outbox": [{"legacy": "ignored"}],
        }
        self.coordinator.state_path.write_text(
            json.dumps(legacy), encoding="utf-8", newline="\n"
        )
        status = self.coordinator.status()
        self.assertTrue(status["legacy_runtime_detected"])
        self.assertEqual(status["active_locks"][0]["lock_kind"], "PATH_LOCK")
        self.assertNotIn("grant", status["active_locks"][0])

        result = self.acquire_path("LOCK-NEW", "new-path")
        self.assertTrue(result["legacy_runtime_migrated"])
        persisted = json.loads(self.coordinator.state_path.read_text(encoding="utf-8"))
        self.assertEqual(persisted["schema_version"], 2)
        self.assertEqual(set(persisted), {"schema_version", "coordination_scope", "locks"})
        self.assertNotIn("receipt_outbox", persisted)

    def test_expired_malformed_legacy_row_is_dropped_before_validation(self) -> None:
        self.coordinator.runtime_dir.mkdir(parents=True)
        self.coordinator.lock_path.write_bytes(b"0")
        legacy = {
            "schema_version": 1,
            "leases": [
                {
                    "state": "ACTIVE",
                    "lease_id": "EXPIRED-RETIRED",
                    "lease_class": "RELEASE_REBIND_LEASE",
                    "expires_at": "2026-08-06T11:59:59Z"
                }
            ],
        }
        self.coordinator.state_path.write_text(json.dumps(legacy), encoding="utf-8")
        status = self.coordinator.status()
        self.assertTrue(status["legacy_runtime_detected"])
        self.assertEqual(status["active_locks"], [])

    def test_unexpired_legacy_row_with_ambiguous_state_fails_closed(self) -> None:
        self.coordinator.runtime_dir.mkdir(parents=True)
        self.coordinator.lock_path.write_bytes(b"0")
        legacy = {
            "schema_version": 1,
            "leases": [
                {
                    "lease_id": "AMBIGUOUS-LIVE",
                    "lease_class": "PROJECT_PATH_LEASE",
                    "expires_at": "2026-08-06T12:10:00Z",
                    "write_paths": [{"kind": "prefix", "path": "src"}],
                }
            ],
        }
        self.coordinator.state_path.write_text(json.dumps(legacy), encoding="utf-8")
        with self.assertRaisesRegex(LockError, "ambiguous state"):
            self.coordinator.status()

    def test_live_legacy_git_lease_with_paths_fails_closed(self) -> None:
        self.coordinator.runtime_dir.mkdir(parents=True)
        self.coordinator.lock_path.write_bytes(b"0")
        legacy = {
            "schema_version": 1,
            "leases": [
                {
                    "state": "ACTIVE",
                    "lease_id": "LEGACY-GIT-WITH-PATHS",
                    "lease_class": "GIT_PUBLICATION_LEASE",
                    "expires_at": "2026-08-06T12:10:00Z",
                    "write_paths": [{"kind": "exact", "path": "src/app.py"}],
                }
            ],
        }
        self.coordinator.state_path.write_text(json.dumps(legacy), encoding="utf-8")
        with self.assertRaisesRegex(LockError, "also claims paths"):
            self.coordinator.status()

    def test_live_retired_lease_preserves_only_its_path_conflict(self) -> None:
        self.coordinator.runtime_dir.mkdir(parents=True)
        self.coordinator.lock_path.write_bytes(b"0")
        legacy = {
            "schema_version": 1,
            "leases": [
                {
                    "state": "ACTIVE",
                    "lease_id": "LEGACY-REBIND",
                    "lease_class": "RELEASE_REBIND_LEASE",
                    "task_package_id": "old-transition",
                    "owner": "old-owner",
                    "base_head": git_head(self.repo),
                    "write_paths": [{"kind": "exact", "path": ".toplayer/repo.yaml"}],
                    "acquired_at": "2026-08-06T11:59:00Z",
                    "expires_at": "2026-08-06T12:10:00Z",
                    "ttl_seconds": 660,
                    "nonce": "old-nonce",
                    "grant": {"ignored": True},
                }
            ],
        }
        self.coordinator.state_path.write_text(json.dumps(legacy), encoding="utf-8")
        status = self.coordinator.status()
        migrated = status["active_locks"][0]
        self.assertEqual(migrated["lock_kind"], "PATH_LOCK")
        self.assertNotIn("grant", migrated)
        self.acquire_path("LOCK-DISJOINT", "src")
        with self.assertRaisesRegex(LockError, "lock conflict"):
            self.acquire_path(
                "LOCK-OVERLAP", ".toplayer/repo.yaml", kind="exact"
            )

    def test_status_and_writer_share_atomic_mutex(self) -> None:
        self.acquire_path("LOCK-SEED", "seed")

        def read_many() -> None:
            for _ in range(25):
                self.coordinator.status()

        def write_many() -> None:
            for index in range(10):
                lock_id = f"LOCK-WRITER-{index}"
                result = self.acquire_path(lock_id, f"path-{index}")
                self.coordinator.release(
                    lock_id=lock_id,
                    owner=f"owner-{lock_id}",
                    nonce=result["lock"]["nonce"],
                )

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(read_many), executor.submit(write_many)]
            for future in futures:
                future.result()

    def test_competing_processes_have_one_winner(self) -> None:
        context = multiprocessing.get_context("spawn")
        with context.Manager() as manager:
            start_gate = manager.Barrier(2)
            with ProcessPoolExecutor(max_workers=2, mp_context=context) as executor:
                futures = [
                    executor.submit(
                        _competing_acquire,
                        str(self.repo),
                        lock_id,
                        start_gate,
                    )
                    for lock_id in ("LOCK-PROCESS-A", "LOCK-PROCESS-B")
                ]
                results = [future.result() for future in futures]
        self.assertEqual(sorted(results), ["ACQUIRED", "CONFLICT"])


class FairnessGateTests(unittest.TestCase):
    """Deterministic gate behaviour with a second OS handle; no timing races."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.lock_path = Path(self.temporary.name) / "state.lock"
        self.lock_path.write_bytes(b"0")

    @contextmanager
    def held(self, region: str):
        if os.name == "nt":
            import msvcrt

            with self.lock_path.open("r+b") as handle:
                offset = 0 if region == "mutex" else core._FAIRNESS_GATE_OFFSET
                handle.seek(offset)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                try:
                    yield
                finally:
                    handle.seek(offset)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            target = self.lock_path if region == "mutex" else self.lock_path.parent
            descriptor = os.open(target, os.O_RDONLY)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                try:
                    yield
                finally:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def test_held_gate_makes_a_new_caller_wait(self) -> None:
        with self.held("gate"):
            with self.assertRaisesRegex(LockError, "timed out"):
                with core._interprocess_lock(self.lock_path, 0.2):
                    self.fail("entered while another waiter held the gate")
        with core._interprocess_lock(self.lock_path, 1.0):
            pass

    def test_mutex_timeout_releases_the_gate(self) -> None:
        with self.held("mutex"):
            with self.assertRaisesRegex(LockError, "timed out"):
                with core._interprocess_lock(self.lock_path, 0.2):
                    self.fail("entered while the mutex was held")
            with self.held("gate"):
                pass

    def test_gate_is_released_while_the_mutex_is_held(self) -> None:
        with core._interprocess_lock(self.lock_path, 1.0):
            with self.held("gate"):
                pass

    def test_non_contention_gate_error_fails_fast(self) -> None:
        calls = []

        def broken() -> None:
            calls.append(None)
            raise OSError(errno.EBADF, "bad descriptor")

        with self.assertRaises(core.LockUnavailable):
            core._poll_until(broken, time.monotonic() + 5, gate=True)
        self.assertEqual(len(calls), 1)

    def test_mutex_retries_any_os_error_until_success(self) -> None:
        calls = []

        def flaky() -> None:
            calls.append(None)
            if len(calls) < 3:
                raise OSError(errno.EINVAL, "transient")

        core._poll_until(flaky, time.monotonic() + 5)
        self.assertEqual(len(calls), 3)

    def test_broken_gate_falls_back_to_the_mutex(self) -> None:
        def broken() -> None:
            raise OSError(errno.EBADF, "bad descriptor")

        gate = (broken, lambda: None, lambda: None)
        with patch.object(core, "_fairness_gate", return_value=gate):
            with core._interprocess_lock(self.lock_path, 1.0):
                pass
            with self.held("mutex"):
                with self.assertRaisesRegex(LockError, "timed out"):
                    with core._interprocess_lock(self.lock_path, 0.2):
                        self.fail("entered without the mutex")

    def test_missing_gate_keeps_mutual_exclusion(self) -> None:
        with patch.object(core, "_fairness_gate", return_value=None):
            with core._interprocess_lock(self.lock_path, 1.0):
                pass
            with self.held("mutex"):
                with self.assertRaisesRegex(LockError, "timed out"):
                    with core._interprocess_lock(self.lock_path, 0.2):
                        self.fail("entered without the mutex")


    def test_gate_cleanup_errors_do_not_leave_the_mutex_held(self) -> None:
        def broken() -> None:
            raise OSError(errno.EBADF, "cleanup failure")
        with (
            patch.object(core, "_fairness_gate", return_value=(lambda: None, broken, broken)),
            core._interprocess_lock(self.lock_path, 1),
        ):
            pass
        with self.held("mutex"):
            pass

    def test_gate_cleanup_errors_preserve_mutex_timeout(self) -> None:
        events = []
        def cleanup(name: str) -> None:
            events.append(name)
            raise OSError(errno.EBADF, "cleanup failure")
        gate = (lambda: None, lambda: cleanup("drop"), lambda: cleanup("close"))
        with self.held("mutex"), patch.object(core, "_fairness_gate", return_value=gate):
            with self.assertRaisesRegex(LockError, "timed out"):
                with core._interprocess_lock(self.lock_path, 0):
                    self.fail("entered a held mutex")
        self.assertEqual(events, ["drop", "close"])
        with self.held("mutex"):
            pass

    def test_timeout_drops_the_gate_before_closing_it(self) -> None:
        events = []
        def unavailable() -> None:
            raise OSError(errno.EACCES, "held mutex")
        gate = tuple(lambda name=name: events.append(name) for name in ("take", "drop", "close"))
        with patch.object(core, "_fairness_gate", return_value=gate):
            with self.assertRaisesRegex(LockError, "timed out"):
                core._acquire_with_gate(unavailable, None, self.lock_path, 0)
        self.assertEqual(events, ["take", "drop", "close"])

    def test_helper_closes_its_handle_when_acquisition_fails(self) -> None:
        opened = []
        if os.name == "nt":
            original = Path.open
            def tracked(path, *args, **kwargs):
                handle = original(path, *args, **kwargs)
                opened.append(handle)
                return handle
            with self.held("gate"), patch.object(Path, "open", tracked):
                try:
                    with self.assertRaises(OSError), self.held("gate"):
                        self.fail("entered a held gate")
                    self.assertTrue(opened[-1].closed)
                finally:
                    for handle in opened:
                        handle.close()
        else:
            original = os.open
            def tracked(*args, **kwargs):
                descriptor = original(*args, **kwargs)
                opened.append(descriptor)
                return descriptor
            with self.held("gate"), patch.object(os, "open", tracked):
                verified_closed = False
                try:
                    with self.assertRaises(OSError), self.held("gate"):
                        self.fail("entered a held gate")
                    with self.assertRaises(OSError) as failure:
                        os.fstat(opened[-1])
                    self.assertEqual(failure.exception.errno, errno.EBADF)
                    verified_closed = True
                finally:
                    # Skip cleanup once the helper's close is verified (the number may be reused);
                    # a failing run may still close an already-closed number.
                    if not verified_closed:
                        for descriptor in opened:
                            try:
                                os.close(descriptor)
                            except OSError:
                                pass

    def test_three_contenders_keep_mutual_exclusion(self) -> None:
        # This checks exclusion, not FIFO or starvation freedom.
        import threading
        start = threading.Barrier(3)
        events = []
        def contender(index: int) -> None:
            start.wait(timeout=5)
            with core._interprocess_lock(self.lock_path, 2):
                events.append(("enter", index))
                time.sleep(0.01)
                events.append(("leave", index))
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(contender, index) for index in range(3)]
            for future in futures:
                future.result(timeout=10)
        self.assertEqual(len(events), 6)
        for index in range(0, 6, 2):
            self.assertEqual(events[index][0], "enter")
            self.assertEqual(events[index + 1], ("leave", events[index][1]))

    @unittest.skipUnless(os.name == "posix", "POSIX directory gate")
    def test_posix_non_directory_parent_returns_no_gate(self) -> None:
        parent = self.lock_path.parent / "not-a-directory"
        parent.write_bytes(b"x")
        with self.lock_path.open("r+b") as handle:
            self.assertIsNone(core._fairness_gate(handle, parent / "state.lock"))

    @unittest.skipUnless(os.name == "posix", "POSIX directory gate")
    def test_posix_non_directory_gate_metadata_returns_no_gate(self) -> None:
        # Both stats name one regular file, so only the S_ISDIR check can reject it.
        regular = os.lstat(self.lock_path)
        with (
            self.lock_path.open("r+b") as handle,
            patch.object(os, "fstat", return_value=regular),
            patch.object(os, "lstat", return_value=regular),
            patch.object(os, "close", wraps=os.close) as closed,
        ):
            result = core._fairness_gate(handle, self.lock_path)
            try:
                self.assertIsNone(result)
                closed.assert_called_once()
            finally:
                if result is not None:
                    result[2]()

    @unittest.skipUnless(os.name == "posix", "POSIX flock")
    def test_posix_timeout_never_unlocks_an_unheld_mutex(self) -> None:
        import fcntl
        import stat

        original = fcntl.flock
        unlocked_regular = []

        def tracked(descriptor: int, operation: int) -> None:
            if operation & fcntl.LOCK_UN:
                unlocked_regular.append(stat.S_ISREG(os.fstat(descriptor).st_mode))
            original(descriptor, operation)

        with self.held("mutex"):
            with patch.object(fcntl, "flock", tracked):
                with self.assertRaisesRegex(LockError, "timed out"):
                    with core._interprocess_lock(self.lock_path, 0.2):
                        self.fail("entered a held mutex")
        self.assertNotIn(True, unlocked_regular)
        self.assertIn(False, unlocked_regular)

    @unittest.skipUnless(os.name == "posix", "POSIX directory gate")
    def test_posix_metadata_failures_close_the_gate(self) -> None:
        for name in ("fstat", "lstat"):
            with self.subTest(operation=name):
                with (
                    self.lock_path.open("r+b") as handle,
                    patch.object(os, name, side_effect=OSError(errno.EIO, "metadata failure")),
                    patch.object(os, "close", wraps=os.close) as closed,
                ):
                    self.assertIsNone(core._fairness_gate(handle, self.lock_path))
                    closed.assert_called_once()
                    descriptor = closed.call_args.args[0]
                with self.assertRaises(OSError) as failure:
                    os.fstat(descriptor)
                self.assertEqual(failure.exception.errno, errno.EBADF)

    @unittest.skipUnless(os.name == "posix", "POSIX directory gate")
    def test_posix_changed_parent_identity_returns_no_gate(self) -> None:
        alternate = self.lock_path.parent / "alternate"
        alternate.mkdir()
        metadata = os.lstat(alternate)
        with (
            self.lock_path.open("r+b") as handle,
            patch.object(os, "lstat", return_value=metadata),
            patch.object(os, "close", wraps=os.close) as closed,
        ):
            result = core._fairness_gate(handle, self.lock_path)
            try:
                self.assertIsNone(result)
                closed.assert_called_once()
            finally:
                if result is not None:
                    result[2]()

    @unittest.skipUnless(os.name == "posix", "POSIX directory gate")
    def test_posix_metadata_cleanup_failure_still_falls_back(self) -> None:
        original = os.close
        def closed_then_failed(descriptor: int) -> None:
            original(descriptor)
            raise OSError(errno.EIO, "close reported failure")
        with (
            self.lock_path.open("r+b") as handle,
            patch.object(os, "fstat", side_effect=OSError(errno.EIO, "metadata failure")),
            patch.object(os, "close", side_effect=closed_then_failed) as closed,
        ):
            self.assertIsNone(core._fairness_gate(handle, self.lock_path))
            closed.assert_called_once()


class CliSurfaceTests(unittest.TestCase):
    def test_five_commands_and_no_authority_arguments(self) -> None:
        parser = build_parser()
        help_text = parser.format_help()
        self.assertIn("concurrency only", help_text)
        subcommands = next(
            action for action in parser._actions if action.dest == "command"
        ).choices
        self.assertEqual(set(subcommands), {"status", "acquire", "renew", "renew-active", "release"})
        acquire_help = subcommands["acquire"].format_help()
        release_help = subcommands["release"].format_help()
        for forbidden in (
            "--grant-id",
            "--control-plane",
            "--holder-role",
            "--release-identity",
            "--source-lease-id",
            "--release-outcome",
        ):
            self.assertNotIn(forbidden, acquire_help + release_help)


if __name__ == "__main__":
    unittest.main()
