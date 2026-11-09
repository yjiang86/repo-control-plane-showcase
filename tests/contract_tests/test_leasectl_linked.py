from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import copy
import io
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import jsonschema

from tests.contract_tests.test_leasectl import Clock, create_repo, run_git
from tools.leasectl import core
from tools.leasectl.cli import main
from tools.leasectl.core import LockConflict, LockCoordinator, LockError, git_head


ROOT = Path(__file__).resolve().parents[2]


def canonical(path: Path) -> str:
    return os.path.normcase(str(path.resolve()))


def _competing_git_acquire(repo: str, lock_id: str, gate: object) -> dict:
    coordinator = LockCoordinator(Path(repo), git_only=True, lock_timeout_seconds=10)
    gate.wait(timeout=30)
    try:
        result = coordinator.acquire(
            lock_kind="GIT_MUTATION_LOCK", task=lock_id, owner=lock_id,
            ttl_seconds=120, nonce=f"nonce-{lock_id}", lock_id=lock_id,
        )
        outcome = result["status"]
    except LockConflict:
        outcome = "CONFLICT"
    return {"status": outcome, "pid": os.getpid(), "runtime": canonical(coordinator.runtime_dir)}


class LinkedGitLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.repo = create_repo(self.root)
        self.clock = Clock()

    def linked(self, name: str = "linked") -> Path:
        child = self.root / name
        run_git(self.repo, "worktree", "add", "--detach", str(child), "HEAD")
        return child

    def coordinator(self, root: Path | None = None, *, git_only: bool = True) -> LockCoordinator:
        return LockCoordinator(root or self.repo, git_only=git_only, now_fn=self.clock)

    def acquire(self, coordinator: LockCoordinator, **overrides: object) -> dict:
        arguments = {
            "lock_kind": "GIT_MUTATION_LOCK", "task": "synthetic-task",
            "owner": "owner", "nonce": "nonce", "lock_id": "LINKED-GIT", "ttl_seconds": 120,
        }
        arguments.update(overrides)
        return coordinator.acquire(**arguments)

    def owned_operation(self, coordinator: LockCoordinator, operation: str, **overrides: object) -> dict:
        arguments = {"lock_id": "LINKED-GIT", "owner": "owner", "nonce": "nonce"}
        if operation != "release":
            arguments.update(ttl_seconds=120, new_nonce="renewed-nonce")
        arguments.update(overrides)
        return getattr(coordinator, operation)(**arguments)

    def assert_refused_unchanged(self, coordinator: LockCoordinator, operation: str, **overrides: object) -> None:
        before = coordinator.state_path.read_bytes()
        with self.assertRaises(LockError):
            self.owned_operation(coordinator, operation, **overrides)
        self.assertEqual(coordinator.state_path.read_bytes(), before)

    def test_linked_roots_share_storage_and_conflict(self) -> None:
        child = self.linked()
        primary, peer = self.coordinator(), self.coordinator(child)
        self.assertEqual(primary.runtime_dir, peer.runtime_dir)
        self.assertEqual(primary.lock_path, peer.lock_path)
        self.assertEqual(primary.state_path, peer.state_path)
        record = self.acquire(primary)["lock"]
        self.assertEqual(record["git_context"], {
            "repo_root": canonical(self.repo),
            "git_dir": canonical(self.repo / ".git"),
        })
        before = primary.state_path.read_bytes()
        self.assertEqual(peer.status()["active_locks"], [record])
        with self.assertRaises(LockConflict):
            self.acquire(peer, lock_id="PEER", owner="peer", nonce="peer-nonce")
        self.assertEqual(primary.state_path.read_bytes(), before)

    def test_simultaneous_linked_processes_have_exactly_one_winner(self) -> None:
        child = self.linked()
        context = multiprocessing.get_context("spawn")
        with context.Manager() as manager:
            gate = manager.Barrier(2)
            with ProcessPoolExecutor(max_workers=2, mp_context=context) as pool:
                futures = [pool.submit(_competing_git_acquire, str(repo), identifier, gate)
                           for repo, identifier in ((self.repo, "PROCESS-A"), (child, "PROCESS-B"))]
                results = [future.result(timeout=60) for future in futures]
        self.assertEqual(sorted(row["status"] for row in results), ["ACQUIRED", "CONFLICT"])
        self.assertEqual(len({row["pid"] for row in results}), 2)
        self.assertEqual(len({row["runtime"] for row in results}), 1)
        status = LockCoordinator(self.repo, git_only=True).status()
        self.assertEqual(len(status["active_locks"]), 1)

    def test_same_or_different_head_never_authenticates_another_root(self) -> None:
        child = self.linked()
        primary, peer = self.coordinator(), self.coordinator(child)
        self.acquire(primary)
        self.assertEqual(git_head(self.repo), git_head(child))
        for head_state in ("same", "different"):
            if head_state == "different":
                run_git(child, "commit", "--allow-empty", "-m", "synthetic peer advance")
                self.assertNotEqual(git_head(self.repo), git_head(child))
            for operation in ("renew", "renew_active", "release"):
                with self.subTest(head=head_state, operation=operation):
                    self.assert_refused_unchanged(peer, operation)

    def test_owner_nonce_and_bound_git_dir_mismatch_preserve_bytes(self) -> None:
        child = self.linked()
        coordinator = self.coordinator()
        self.acquire(coordinator)
        for mismatch in ({"owner": "foreign"}, {"nonce": "foreign"}):
            for operation in ("renew", "renew_active", "release"):
                with self.subTest(mismatch=mismatch, operation=operation):
                    self.assert_refused_unchanged(coordinator, operation, **mismatch)
        state = json.loads(coordinator.state_path.read_text(encoding="utf-8"))
        peer_git_dir = Path(run_git(child, "rev-parse", "--git-dir"))
        state["locks"][0]["git_context"]["git_dir"] = canonical(peer_git_dir)
        coordinator.state_path.write_text(json.dumps(state), encoding="utf-8")
        for operation in ("renew", "renew_active", "release"):
            with self.subTest(bound_git_dir=operation):
                self.assert_refused_unchanged(coordinator, operation)

    def test_stale_base_assertion_refuses_before_storage_and_after_existing_state(self) -> None:
        self.linked()
        coordinator = self.coordinator()
        with self.assertRaisesRegex(LockError, "base_head"):
            self.acquire(coordinator, base_head="0" * 40)
        self.assertFalse(coordinator.runtime_dir.exists())
        self.acquire(coordinator)
        before = coordinator.state_path.read_bytes()
        with self.assertRaisesRegex(LockError, "base_head"):
            self.acquire(coordinator, lock_id="STALE", base_head="0" * 40)
        self.assertEqual(coordinator.state_path.read_bytes(), before)

    def test_same_root_head_change_allows_strict_renewal_rotation_and_release(self) -> None:
        self.linked()
        coordinator = self.coordinator()
        acquired = self.acquire(coordinator)["lock"]
        run_git(self.repo, "commit", "--allow-empty", "-m", "synthetic owner advance")
        self.assertNotEqual(git_head(self.repo), acquired["base_head"])
        renewed = self.owned_operation(coordinator, "renew_active")
        self.assertEqual(renewed["status"], "RENEWED")
        self.assertEqual(renewed["lock"]["base_head"], acquired["base_head"])
        self.assertEqual(renewed["lock"]["git_context"], acquired["git_context"])
        self.assertEqual(renewed["lock"]["nonce"], "renewed-nonce")
        self.assert_refused_unchanged(coordinator, "release")
        self.assertEqual(self.owned_operation(coordinator, "release", nonce="renewed-nonce")["status"], "RELEASED")

    def test_expiry_strict_rejection_and_same_context_recovery(self) -> None:
        child = self.linked()
        coordinator, peer = self.coordinator(), self.coordinator(child)
        self.acquire(coordinator, ttl_seconds=10)
        self.clock.advance(11)
        self.assert_refused_unchanged(coordinator, "renew_active")
        self.assert_refused_unchanged(peer, "renew")
        run_git(self.repo, "commit", "--allow-empty", "-m", "synthetic expired owner advance")
        recovered = self.owned_operation(coordinator, "renew")
        self.assertEqual(recovered["status"], "RECOVERED")
        self.assertEqual(recovered["lock"]["base_head"], git_head(self.repo))
        self.clock.advance(121)
        replacement = self.acquire(peer, lock_id="REPLACEMENT", owner="peer", nonce="peer-nonce")
        self.assertEqual(replacement["stale_locks_recovered"], ["LINKED-GIT"])
        self.assert_refused_unchanged(coordinator, "renew", nonce="renewed-nonce")

    def test_git_only_rejects_path_and_alias_without_creating_storage(self) -> None:
        coordinator = self.coordinator()
        for topology in ("single", "linked"):
            if topology == "linked":
                self.linked()
            for kind in ("PATH_LOCK", "PROJECT_PATH_LEASE"):
                with self.subTest(topology=topology, kind=kind), self.assertRaises(LockError):
                    self.acquire(coordinator, lock_kind=kind, paths=[{"kind": "exact", "path": "data"}])
                self.assertFalse(coordinator.runtime_dir.exists())

    def test_existing_path_blocks_git_and_default_object_rechecks_all_operations(self) -> None:
        ordinary = self.coordinator(git_only=False)
        self.acquire(ordinary, lock_kind="PATH_LOCK", paths=[{"kind": "prefix", "path": "data"}])
        before = ordinary.state_path.read_bytes()
        child = self.linked()
        with self.assertRaises(LockError):
            self.coordinator(git_only=False)
        peer = self.coordinator(child)
        self.assertEqual(peer.status()["active_locks"][0]["lock_kind"], "PATH_LOCK")
        with self.assertRaises(LockConflict):
            self.acquire(peer, lock_id="PEER")
        with self.assertRaises(LockError):
            ordinary.status()
        with self.assertRaises(LockError):
            self.acquire(ordinary, lock_id="LATE", lock_kind="PATH_LOCK", paths=[{"kind": "exact", "path": "other"}])
        for operation in ("renew", "renew_active", "release"):
            with self.subTest(operation=operation):
                self.assert_refused_unchanged(ordinary, operation)
                self.assert_refused_unchanged(peer, operation)
        self.assertEqual(ordinary.state_path.read_bytes(), before)

    def test_default_topology_is_rechecked_after_mutex_acquisition(self) -> None:
        ordinary = self.coordinator(git_only=False)
        self.acquire(ordinary)
        self.owned_operation(ordinary, "release")
        before = ordinary.state_path.read_bytes()
        original_mutex = core._interprocess_lock

        @contextmanager
        def grow_inside_mutex(path: Path, timeout: float):
            with original_mutex(path, timeout):
                self.linked()
                yield

        with patch.object(core, "_interprocess_lock", grow_inside_mutex):
            with self.assertRaises(LockError):
                self.acquire(ordinary, lock_kind="PATH_LOCK", paths=[{"kind": "exact", "path": "late"}])
        self.assertEqual(ordinary.state_path.read_bytes(), before)

    def test_git_lock_remains_exclusive_when_topology_shrinks(self) -> None:
        child = self.linked()
        coordinator = self.coordinator()
        self.acquire(coordinator)
        run_git(self.repo, "worktree", "remove", str(child))
        ordinary = self.coordinator(git_only=False)
        before = coordinator.state_path.read_bytes()
        with self.assertRaises(LockConflict):
            self.acquire(ordinary, lock_id="PATH", lock_kind="PATH_LOCK", paths=[{"kind": "exact", "path": "data"}])
        self.assert_refused_unchanged(ordinary, "release")
        self.assertEqual(coordinator.state_path.read_bytes(), before)
        self.assertEqual(self.owned_operation(coordinator, "release")["status"], "RELEASED")
        self.assertEqual(ordinary.status()["active_locks"], [])

    def test_unbound_ordinary_git_record_cannot_be_mutated_by_git_only(self) -> None:
        ordinary = self.coordinator(git_only=False)
        record = self.acquire(ordinary)["lock"]
        self.assertNotIn("git_context", record)
        self.linked()
        coordinator = self.coordinator()
        self.assertEqual(coordinator.status()["active_locks"], [record])
        with self.assertRaises(LockConflict):
            self.acquire(coordinator, lock_id="NEW")
        for operation in ("renew", "renew_active", "release"):
            with self.subTest(operation=operation):
                self.assert_refused_unchanged(coordinator, operation)

    def test_git_ttl_ceiling_applies_to_acquire_and_both_renewals(self) -> None:
        self.linked()
        coordinator = self.coordinator()
        with self.assertRaisesRegex(LockError, "900"):
            self.acquire(coordinator, ttl_seconds=901)
        self.assertFalse(coordinator.runtime_dir.exists())
        self.acquire(coordinator, ttl_seconds=900)
        for operation in ("renew", "renew_active"):
            with self.subTest(operation=operation):
                self.assert_refused_unchanged(coordinator, operation, ttl_seconds=901)

    def test_existing_state_without_mutex_is_never_repaired_by_acquire(self) -> None:
        self.linked()
        coordinator = self.coordinator()
        self.acquire(coordinator)
        before = coordinator.state_path.read_bytes()
        coordinator.lock_path.unlink()
        with self.assertRaises(LockError):
            coordinator.status()
        with self.assertRaises(LockError):
            self.acquire(coordinator, lock_id="NEW")
        for operation in ("renew", "renew_active", "release"):
            with self.subTest(operation=operation):
                self.assert_refused_unchanged(coordinator, operation)
        self.assertFalse(coordinator.lock_path.exists())
        self.assertEqual(coordinator.state_path.read_bytes(), before)

    def test_malformed_context_and_record_fail_closed_without_state_rewrite(self) -> None:
        self.linked()
        coordinator = self.coordinator()
        self.acquire(coordinator)
        state = json.loads(coordinator.state_path.read_text(encoding="utf-8"))
        context = state["locks"][0]["git_context"]
        invalid_contexts = [
            None, {}, [], {"repo_root": context["repo_root"]},
            {**context, "extra": "not-allowed"}, {**context, "repo_root": "relative"},
            {**context, "git_dir": "relative"}, {**context, "repo_root": 123},
            {**context, "repo_root": context["repo_root"] + "\n"},
        ]
        for invalid in invalid_contexts:
            with self.subTest(context=invalid):
                changed = copy.deepcopy(state)
                changed["locks"][0]["git_context"] = invalid
                coordinator.state_path.write_text(json.dumps(changed), encoding="utf-8")
                before = coordinator.state_path.read_bytes()
                with self.assertRaises(LockError):
                    coordinator.status()
                with self.assertRaises(LockError):
                    self.acquire(coordinator, lock_id="NEW")
                self.assert_refused_unchanged(coordinator, "release")
                self.assertEqual(coordinator.state_path.read_bytes(), before)
        changed = copy.deepcopy(state)
        changed["locks"][0].update(lock_kind="PATH_LOCK", paths=[{"kind": "exact", "path": "data"}])
        coordinator.state_path.write_text(json.dumps(changed), encoding="utf-8")
        before = coordinator.state_path.read_bytes()
        with self.assertRaises(LockError):
            coordinator.status()
        self.assertEqual(coordinator.state_path.read_bytes(), before)

    def test_detected_state_redirection_is_refused_without_mutation(self) -> None:
        self.linked()
        coordinator = self.coordinator()
        self.acquire(coordinator)
        before = coordinator.state_path.read_bytes()
        original_detector = core._is_redirect
        with patch.object(core, "_is_redirect", side_effect=lambda path: path == coordinator.state_path or original_detector(path)):
            with self.assertRaisesRegex(LockError, "redirection"):
                coordinator.status()
            with self.assertRaisesRegex(LockError, "redirection"):
                self.acquire(coordinator, lock_id="NEW")
            self.assert_refused_unchanged(coordinator, "release")
        self.assertEqual(coordinator.state_path.read_bytes(), before)

    def test_status_is_read_only_for_absent_and_present_shared_storage(self) -> None:
        child = self.linked()
        primary, peer = self.coordinator(), self.coordinator(child)
        for coordinator in (primary, peer):
            self.assertEqual(coordinator.status()["runtime_state"], "ABSENT")
        self.assertFalse(primary.runtime_dir.exists())
        self.acquire(primary)
        before = {path.name: path.read_bytes() for path in primary.runtime_dir.iterdir()}
        for coordinator in (primary, peer):
            self.assertEqual(coordinator.status()["runtime_state"], "PRESENT")
        after = {path.name: path.read_bytes() for path in primary.runtime_dir.iterdir()}
        self.assertEqual(after, before)

    def test_portable_schema_accepts_git_context_and_rejects_invalid_shapes(self) -> None:
        self.linked()
        record = self.acquire(self.coordinator())["lock"]
        schema = json.loads((ROOT / "schemas" / "dynamic_write_lease.schema.json").read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)
        validator.validate(record)
        legacy_record = copy.deepcopy(record)
        legacy_record.pop("git_context")
        validator.validate(legacy_record)
        invalid = []
        for context in (None, {}, [], {"repo_root": "relative", "git_dir": "relative"}, {**record["git_context"], "extra": "no"}):
            changed = copy.deepcopy(record)
            changed["git_context"] = context
            invalid.append(changed)
        changed = copy.deepcopy(record)
        changed.update(lock_kind="PATH_LOCK", paths=[{"kind": "exact", "path": "data"}])
        invalid.append(changed)
        changed = copy.deepcopy(record)
        changed["ttl_seconds"] = 901
        invalid.append(changed)
        for row in invalid:
            with self.subTest(row=row), self.assertRaises(jsonschema.ValidationError):
                validator.validate(row)

    def test_native_exact_child_move_remove_preserves_other_registrations_and_recovery(self) -> None:
        moved, removed, retained = self.linked("move-me"), self.linked("remove-me"), self.linked("keep-me")
        target = self.root / "moved-child"
        recovery = self.root / "recovery"
        recovery.mkdir()
        preserved = {}
        for child in (moved, removed):
            payload = (child / "README.md").read_bytes()
            preserved[child.name] = payload
            (recovery / child.name).write_bytes(payload)
        references = run_git(self.repo, "show-ref")
        primary_index = (self.repo / ".git" / "index").read_bytes()
        retained_index_path = Path(run_git(retained, "rev-parse", "--git-dir")) / "index"
        retained_index = retained_index_path.read_bytes()
        retained_files = {path.name: path.read_bytes() for path in retained.iterdir() if path.is_file()}
        coordinator = self.coordinator()
        self.acquire(coordinator)
        run_git(self.repo, "worktree", "move", str(moved), str(target))
        self.assertFalse(moved.exists())
        self.assertEqual((target / "README.md").read_bytes(), preserved[moved.name])
        run_git(self.repo, "worktree", "remove", str(removed))
        self.assertFalse(removed.exists())
        actual = {canonical(Path(line[len("worktree "):])) for line in run_git(self.repo, "worktree", "list", "--porcelain").splitlines() if line.startswith("worktree ")}
        self.assertEqual(actual, {canonical(path) for path in (self.repo, target, retained)})
        self.assertEqual(run_git(self.repo, "show-ref"), references)
        self.assertEqual((self.repo / ".git" / "index").read_bytes(), primary_index)
        self.assertEqual(retained_index_path.read_bytes(), retained_index)
        self.assertEqual({path.name: path.read_bytes() for path in retained.iterdir() if path.is_file()}, retained_files)
        self.assertEqual({path.name: path.read_bytes() for path in recovery.iterdir()}, preserved)
        self.assertEqual(self.owned_operation(coordinator, "release")["status"], "RELEASED")

    def test_moved_acquiring_root_cannot_rebind_owned_record(self) -> None:
        child = self.linked()
        coordinator = self.coordinator(child)
        self.acquire(coordinator)
        target = self.root / "moved"
        run_git(self.repo, "worktree", "move", str(child), str(target))
        relocated = self.coordinator(target)
        for operation in ("renew", "renew_active", "release"):
            with self.subTest(operation=operation):
                self.assert_refused_unchanged(coordinator, operation)
                self.assert_refused_unchanged(relocated, operation)

    def test_all_cli_operations_use_explicit_git_only_mode(self) -> None:
        self.linked()

        def invoke(*arguments: str) -> tuple[int, dict]:
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = main([*arguments, "--repo-root", str(self.repo)])
            return code, json.loads(out.getvalue() if code == 0 else err.getvalue())

        code, result = invoke("status")
        self.assertEqual(code, 2)
        self.assertEqual(result["error_code"], "LOCK_COORDINATION_FAILED")
        code, result = invoke("status", "--git-only")
        self.assertEqual((code, result["runtime_state"]), (0, "ABSENT"))
        code, result = invoke("acquire", "--git-only", "--lock-kind", "GIT_MUTATION_LOCK",
                              "--task", "cli", "--owner", "owner", "--nonce", "nonce",
                              "--lock-id", "CLI", "--ttl-seconds", "120")
        self.assertEqual((code, result["status"]), (0, "ACQUIRED"))
        for command, old, new in (("renew", "nonce", "rotated"), ("renew-active", "rotated", "strict")):
            code, result = invoke(command, "--git-only", "--lock-id", "CLI", "--owner", "owner",
                                  "--nonce", old, "--new-nonce", new, "--ttl-seconds", "120")
            self.assertEqual((code, result["status"]), (0, "RENEWED"))
        code, result = invoke("release", "--git-only", "--lock-id", "CLI", "--owner", "owner", "--nonce", "strict")
        self.assertEqual((code, result["status"]), (0, "RELEASED"))
        code, result = invoke("status", "--git-only")
        self.assertEqual((code, result["active_locks"]), (0, []))


class LinkedGitTemporalBoundaryTests(unittest.TestCase):
    """Simulate slow observations while retaining real state files and OS locks."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def fixture(self, git_only: bool) -> tuple[LockCoordinator, Clock]:
        parent = self.root / ("git-only" if git_only else "default")
        parent.mkdir()
        repo = create_repo(parent)
        clock = Clock()
        return LockCoordinator(repo, git_only=git_only, now_fn=clock), clock

    def acquire(self, coordinator: LockCoordinator, *, lock_id: str = "TIME-LOCK") -> dict:
        return coordinator.acquire(
            lock_kind="GIT_MUTATION_LOCK", task="temporal-fixture", owner="owner",
            lock_id=lock_id, nonce="nonce", ttl_seconds=10,
        )

    @contextmanager
    def delayed_locked_identity(self, coordinator: LockCoordinator, clock: Clock):
        calls = []
        inside = {"locked": False}
        original_mutex = core._interprocess_lock
        original_observation = coordinator._revalidate_context

        @contextmanager
        def observed_mutex(path: Path, timeout: float):
            with original_mutex(path, timeout):
                inside["locked"] = True
                try:
                    yield
                finally:
                    inside["locked"] = False

        def delayed_observation() -> None:
            original_observation()
            if inside["locked"]:
                calls.append(clock())
                clock.advance(11)

        # Keep real Git identity checks. Simulate elapsed time specifically
        # after the fresh observation under the real interprocess lock.
        with (patch.object(core, "_interprocess_lock", observed_mutex),
              patch.object(coordinator, "_revalidate_context", side_effect=delayed_observation)):
            yield calls
        self.assertTrue(calls, "locked fresh identity was not observed")

    def assert_current_interval(self, record: dict, clock: Clock) -> None:
        start = core.parse_utc(record["acquired_at"], "acquired_at")
        end = core.parse_utc(record["expires_at"], "expires_at")
        self.assertEqual(start, clock())
        self.assertEqual((end - start).total_seconds(), 10)
        self.assertEqual(record["ttl_seconds"], 10)

    def test_strict_renewal_crossing_locked_identity_expiry_refuses_both_modes(self) -> None:
        for git_only in (False, True):
            with self.subTest(git_only=git_only):
                coordinator, clock = self.fixture(git_only)
                self.acquire(coordinator)
                before = coordinator.state_path.read_bytes()
                with self.delayed_locked_identity(coordinator, clock):
                    with self.assertRaisesRegex(LockError, "unexpired active"):
                        coordinator.renew_active(
                            lock_id="TIME-LOCK", owner="owner", nonce="nonce",
                            new_nonce="must-not-be-written", ttl_seconds=10,
                        )
                self.assertEqual(coordinator.state_path.read_bytes(), before)

    def test_acquire_interval_begins_after_locked_identity_observation(self) -> None:
        for git_only in (False, True):
            with self.subTest(git_only=git_only):
                coordinator, clock = self.fixture(git_only)
                with self.delayed_locked_identity(coordinator, clock):
                    result = self.acquire(coordinator)
                self.assertEqual(result["status"], "ACQUIRED")
                self.assert_current_interval(result["lock"], clock)

    def test_acquire_interval_and_expiry_classification_follow_slow_head_read(self) -> None:
        for git_only in (False, True):
            with self.subTest(git_only=git_only):
                coordinator, clock = self.fixture(git_only)
                self.acquire(coordinator)
                observed_head = git_head(coordinator.repo_root)
                head_calls = []

                def simulate_slow_head(repo: Path) -> str:
                    self.assertEqual(repo, coordinator.repo_root)
                    head_calls.append(clock())
                    clock.advance(11)
                    return observed_head

                with patch.object(core, "git_head", side_effect=simulate_slow_head):
                    result = self.acquire(coordinator, lock_id="AFTER-SLOW-HEAD")
                self.assertTrue(head_calls)
                self.assertEqual(result["status"], "ACQUIRED")
                self.assertEqual(result["stale_locks_recovered"], ["TIME-LOCK"])
                self.assertEqual(result["lock"]["base_head"], observed_head)
                self.assert_current_interval(result["lock"], clock)

    def test_status_classifies_expiry_after_locked_identity_without_writing(self) -> None:
        for git_only in (False, True):
            with self.subTest(git_only=git_only):
                coordinator, clock = self.fixture(git_only)
                acquired = self.acquire(coordinator)["lock"]
                before = coordinator.state_path.read_bytes()
                with self.delayed_locked_identity(coordinator, clock):
                    result = coordinator.status()
                self.assertEqual(result["active_locks"], [])
                self.assertEqual(result["expired_locks"], [acquired])
                self.assertEqual(coordinator.state_path.read_bytes(), before)

    def test_release_classifies_expiry_after_locked_identity(self) -> None:
        for git_only in (False, True):
            with self.subTest(git_only=git_only):
                coordinator, clock = self.fixture(git_only)
                self.acquire(coordinator)
                with self.delayed_locked_identity(coordinator, clock):
                    result = coordinator.release(lock_id="TIME-LOCK", owner="owner", nonce="nonce")
                self.assertEqual(result["status"], "RELEASED")
                self.assertEqual(result["observed_state"], "EXPIRED")
                self.assertEqual(json.loads(coordinator.state_path.read_text(encoding="utf-8"))["locks"], [])

    def test_ordinary_renewal_crossing_locked_identity_expiry_is_recovered(self) -> None:
        for git_only in (False, True):
            with self.subTest(git_only=git_only):
                coordinator, clock = self.fixture(git_only)
                self.acquire(coordinator)
                with self.delayed_locked_identity(coordinator, clock):
                    result = coordinator.renew(
                        lock_id="TIME-LOCK", owner="owner", nonce="nonce",
                        new_nonce="recovered-nonce", ttl_seconds=10,
                    )
                self.assertEqual(result["status"], "RECOVERED")
                self.assertEqual(result["lock"]["nonce"], "recovered-nonce")
                self.assert_current_interval(result["lock"], clock)

    def test_expired_recovery_interval_is_resampled_after_extra_head_read(self) -> None:
        for git_only in (False, True):
            with self.subTest(git_only=git_only):
                coordinator, clock = self.fixture(git_only)
                original = self.acquire(coordinator)["lock"]
                run_git(coordinator.repo_root, "commit", "--allow-empty", "-m", "synthetic recovery head")
                observed_head = git_head(coordinator.repo_root)
                self.assertNotEqual(original["base_head"], observed_head)
                clock.advance(11)
                head_calls = []

                def simulate_slow_head(repo: Path) -> str:
                    self.assertEqual(repo, coordinator.repo_root)
                    head_calls.append(clock())
                    clock.advance(7)
                    return observed_head

                with patch.object(core, "git_head", side_effect=simulate_slow_head):
                    result = coordinator.renew(
                        lock_id="TIME-LOCK", owner="owner", nonce="nonce",
                        new_nonce="recovered-nonce", ttl_seconds=10,
                    )
                self.assertTrue(head_calls)
                self.assertEqual(result["status"], "RECOVERED")
                self.assertEqual(result["lock"]["base_head"], observed_head)
                self.assert_current_interval(result["lock"], clock)


    def test_strict_renewal_crossing_state_read_expiry_refuses_both_modes(self) -> None:
        for git_only in (False, True):
            with self.subTest(git_only=git_only):
                coordinator, clock = self.fixture(git_only)
                self.acquire(coordinator)
                before = coordinator.state_path.read_bytes()
                original_read = coordinator._read_state
                read_calls = []

                def simulate_slow_read(now):
                    result = original_read(now)
                    read_calls.append(clock())
                    clock.advance(11)
                    return result

                # Preserve real parsing and OS serialization; advance only the
                # simulated elapsed time after the actual state read returns.
                with patch.object(coordinator, "_read_state", side_effect=simulate_slow_read):
                    with self.assertRaisesRegex(LockError, "unexpired active"):
                        coordinator.renew_active(
                            lock_id="TIME-LOCK", owner="owner", nonce="nonce",
                            new_nonce="must-not-be-written", ttl_seconds=10,
                        )
                self.assertTrue(read_calls)
                self.assertEqual(coordinator.state_path.read_bytes(), before)

    def test_path_validation_expiry_refuses_strict_and_recovers_ordinary(self) -> None:
        coordinator, clock = self.fixture(False)
        original_validate = core._validate_path_surface
        for operation in ("renew_active", "renew"):
            with self.subTest(operation=operation):
                # The second acquisition replaces the first expired fixture
                # row, giving each operation a fresh ten-second interval.
                coordinator.acquire(
                    lock_kind="PATH_LOCK", task="temporal-path-fixture", owner="owner",
                    lock_id="PATH-TIME", nonce="nonce", ttl_seconds=10,
                    paths=[{"kind": "exact", "path": "README.md"}],
                )
                before = coordinator.state_path.read_bytes()
                path_calls = []

                def simulate_slow_path_validation(repo: Path, rules: list[dict[str, str]]) -> None:
                    original_validate(repo, rules)
                    path_calls.append(clock())
                    clock.advance(11)

                with patch.object(core, "_validate_path_surface", side_effect=simulate_slow_path_validation):
                    arguments = {
                        "lock_id": "PATH-TIME", "owner": "owner", "nonce": "nonce",
                        "new_nonce": "after-path-observation", "ttl_seconds": 10,
                    }
                    if operation == "renew_active":
                        with self.assertRaisesRegex(LockError, "unexpired active"):
                            coordinator.renew_active(**arguments)
                    else:
                        result = coordinator.renew(**arguments)
                self.assertTrue(path_calls)
                if operation == "renew_active":
                    self.assertEqual(coordinator.state_path.read_bytes(), before)
                else:
                    self.assertEqual(result["status"], "RECOVERED")
                    self.assertEqual(result["lock"]["nonce"], "after-path-observation")
                    self.assert_current_interval(result["lock"], clock)


if __name__ == "__main__":
    unittest.main()
