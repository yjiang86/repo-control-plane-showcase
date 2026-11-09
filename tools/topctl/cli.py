from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import date, datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
from typing import Any

import yaml


REPO_REQUIRED_KEYS = {
    "schema_version",
    "repo_id",
    "repo_family",
    "repo_role",
    "lifecycle",
    "control_plane",
    "profiles",
    "local_overlay",
}
REPO_OPTIONAL_KEYS: set[str] = set()
PROFILE_REQUIRED_KEYS = {"schema_version", "profile_id"}
PROFILE_OPTIONAL_KEYS = {"characteristics", "requirements"}
LOCK_CONTRACT = "CP_MINIMAL_STATIC_RENDER"
LOCK_REQUIRED_KEYS = {
    "schema_version",
    "contract",
    "input_sha256",
    "rendered_agents",
}
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
GIT_OID_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
CONTROL_CHARACTER_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
ALLOWED_LIFECYCLE_STATES = {
    "DEVELOPMENT_PAUSED",
    "SCOPED_DEVELOPMENT_ACTIVE",
}
@dataclass(frozen=True)
class RenderComposition:
    repo_root: Path
    control_plane: Path
    repo_config: dict[str, Any]
    profiles: tuple[dict[str, Any], ...]
    input_manifest: dict[str, Any]
    input_sha256: str
    rendered_bytes: bytes


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_ready(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, nested in value.items():
            if not isinstance(key, str):
                raise ValueError("YAML object keys must be strings")
            result[key] = _json_ready(nested)
        return result
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ValueError(f"unsupported YAML value type: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    try:
        text = json.dumps(
            _json_ready(value),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise ValueError(f"value is not canonical-JSON compatible: {error}") from error
    return text.encode("utf-8")


def pretty_json(value: Any) -> str:
    return json.dumps(
        _json_ready(value), ensure_ascii=False, indent=2, sort_keys=True
    )


def normalize_markdown_bytes(payload: bytes, label: str) -> bytes:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} must be UTF-8") from error
    if text.startswith("\ufeff"):
        raise ValueError(f"{label} must not contain a UTF-8 BOM")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return (text.rstrip("\n") + "\n").encode("utf-8")


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a YAML object")
    return _json_ready(value)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return _json_ready(value)


def _require_exact_keys(
    value: dict[str, Any],
    required: set[str],
    optional: set[str],
    label: str,
) -> None:
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - required - optional)
    if missing:
        raise ValueError(f"{label} missing fields: {missing}")
    if unknown:
        raise ValueError(f"{label} contains unknown fields: {unknown}")


def _require_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(f"{label} must be a canonical identifier")
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _require_string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    result = [_require_identifier(item, f"{label}[{index}]") for index, item in enumerate(value)]
    if len(result) != len(set(result)):
        raise ValueError(f"{label} must not contain duplicates")
    return result


def _canonical_relative_path(value: Any, label: str) -> str:
    text = _require_string(value, label)
    if "\\" in text or ":" in text or CONTROL_CHARACTER_PATTERN.search(text):
        raise ValueError(f"{label} must be a canonical relative path")
    path = PurePosixPath(text)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{label} must be a canonical relative path")
    if path.as_posix() != text or text.endswith("/"):
        raise ValueError(f"{label} must be a canonical relative path")
    return text


def validate_repo_config(config: dict[str, Any]) -> None:
    _require_exact_keys(config, REPO_REQUIRED_KEYS, REPO_OPTIONAL_KEYS, "repo declaration")
    if config["schema_version"] != 3:
        raise ValueError("repo declaration schema_version must be 3")
    for field in ("repo_id", "repo_family", "repo_role"):
        _require_identifier(config[field], f"repo declaration {field}")

    lifecycle = config["lifecycle"]
    if not isinstance(lifecycle, dict):
        raise ValueError("repo declaration lifecycle must be an object")
    _require_exact_keys(
        lifecycle,
        {"state"},
        {"effective_date", "reason"},
        "repo declaration lifecycle",
    )
    if lifecycle["state"] not in ALLOWED_LIFECYCLE_STATES:
        raise ValueError("repo declaration lifecycle.state is unsupported")

    control_plane = config["control_plane"]
    if not isinstance(control_plane, dict):
        raise ValueError("repo declaration control_plane must be an object")
    _require_exact_keys(
        control_plane,
        {"repo_id", "remote", "release", "commit_sha"},
        set(),
        "repo declaration control_plane",
    )
    _require_identifier(control_plane["repo_id"], "control_plane.repo_id")
    for field in ("remote", "release"):
        _require_string(control_plane[field], f"control_plane.{field}")
    if not isinstance(control_plane["commit_sha"], str) or not GIT_OID_PATTERN.fullmatch(
        control_plane["commit_sha"]
    ):
        raise ValueError("control_plane.commit_sha must be an exact Git object ID")
    profiles = _require_string_list(config["profiles"], "repo declaration profiles")
    if profiles != config["profiles"]:
        raise ValueError("repo declaration profiles are invalid")

    overlay = config["local_overlay"]
    if not isinstance(overlay, dict):
        raise ValueError("repo declaration local_overlay must be an object")
    _require_exact_keys(overlay, {"agents"}, set(), "repo declaration local_overlay")
    overlay["agents"] = _canonical_relative_path(
        overlay["agents"], "repo declaration local_overlay.agents"
    )



def validate_profile(profile: dict[str, Any], expected_id: str) -> None:
    _require_exact_keys(
        profile,
        PROFILE_REQUIRED_KEYS,
        PROFILE_OPTIONAL_KEYS,
        f"profile {expected_id}",
    )
    if profile["schema_version"] != 1:
        raise ValueError(f"profile {expected_id} schema_version must be 1")
    if _require_identifier(profile["profile_id"], "profile_id") != expected_id:
        raise ValueError("profile identity mismatch")
    for field in ("characteristics", "requirements"):
        if field in profile and not isinstance(profile[field], dict):
            raise ValueError(f"profile {expected_id} {field} must be an object")


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _resolve_control_plane_source(control_plane: Path, relative: str) -> Path:
    path = (control_plane / relative).resolve()
    if not _is_within(path, control_plane) or not path.is_file():
        raise ValueError(f"control-plane source missing or outside root: {relative}")
    return path


def _resolve_repo_relative_or_absolute(repo_root: Path, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = repo_root / path
    return path.resolve()


def _render_agents(
    config: dict[str, Any],
    profiles: list[dict[str, Any]],
    base_policy: bytes,
    overlay: bytes,
    input_sha256: str,
) -> bytes:
    parts = [
        "# Managed Repository Instructions\n\n",
        f"<!-- generated-by: topctl {LOCK_CONTRACT} -->\n",
        f"<!-- input-sha256: {input_sha256} -->\n\n",
        "## Repository Identity\n\n",
        f"- repo_id: `{config['repo_id']}`\n",
        f"- repo_family: `{config['repo_family']}`\n",
        f"- repo_role: `{config['repo_role']}`\n\n",
        "## Shared Base Policy\n\n",
        base_policy.decode("utf-8"),
        "\n## Active Profiles\n\n",
        "Profiles are applied in declared order and add repository-specific requirements.\n",
    ]
    for profile in profiles:
        parts.extend(
            [
                f"\n### `{profile['profile_id']}`\n\n",
                "```json\n",
                pretty_json(profile),
                "\n```\n",
            ]
        )
    parts.extend(["\n## Repository Overlay\n\n", overlay.decode("utf-8")])
    return "".join(parts).encode("utf-8")


def compose_render(repo_root: Path, control_plane: Path) -> RenderComposition:
    repo_root = repo_root.resolve()
    control_plane = control_plane.resolve()
    config = load_yaml(repo_root / ".toplayer" / "repo.yaml")
    validate_repo_config(config)
    base_policy = normalize_markdown_bytes(
        _resolve_control_plane_source(control_plane, "policies/AGENTS.base.md").read_bytes(),
        "base policy",
    )

    profile_documents: list[dict[str, Any]] = []
    profile_sources: list[dict[str, Any]] = []
    for profile_id in config["profiles"]:
        relative = f"profiles/{profile_id}.yaml"
        profile = load_yaml(_resolve_control_plane_source(control_plane, relative))
        validate_profile(profile, profile_id)
        profile_documents.append(profile)
        profile_sources.append(
            {
                "path": relative,
                "profile_id": profile_id,
                "canonical_sha256": sha256_bytes(canonical_json_bytes(profile)),
            }
        )

    overlay_relative = config["local_overlay"]["agents"]
    overlay_path = (repo_root / overlay_relative).resolve()
    if not _is_within(overlay_path, repo_root) or not overlay_path.is_file():
        raise ValueError("repo overlay missing or outside repo_root")
    overlay = normalize_markdown_bytes(overlay_path.read_bytes(), "repo overlay")

    effective_config = _json_ready(config)
    sources = {
        "base_policy": {
            "path": "policies/AGENTS.base.md",
            "canonical_sha256": sha256_bytes(base_policy),
        },
        "profiles": profile_sources,
        "overlay": {
            "path": overlay_relative,
            "canonical_sha256": sha256_bytes(overlay),
        },
    }
    input_manifest = {
        "schema_version": 2,
        "contract": LOCK_CONTRACT,
        "repo": effective_config,
        "sources": sources,
    }
    input_sha256 = sha256_bytes(canonical_json_bytes(input_manifest))
    rendered = _render_agents(
        config, profile_documents, base_policy, overlay, input_sha256
    )
    return RenderComposition(
        repo_root=repo_root,
        control_plane=control_plane,
        repo_config=config,
        profiles=tuple(profile_documents),
        input_manifest=input_manifest,
        input_sha256=input_sha256,
        rendered_bytes=rendered,
    )


def build_render_lock(composition: RenderComposition) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "contract": LOCK_CONTRACT,
        "input_sha256": composition.input_sha256,
        "rendered_agents": {
            "path": "AGENTS.md",
            "bytes": len(composition.rendered_bytes),
            "sha256": sha256_bytes(composition.rendered_bytes),
        },
    }


def validate_render_lock(lock: dict[str, Any]) -> None:
    _require_exact_keys(lock, LOCK_REQUIRED_KEYS, set(), "render lock")
    if lock["schema_version"] != 2 or lock["contract"] != LOCK_CONTRACT:
        raise ValueError(f"render lock must use schema 2 and contract {LOCK_CONTRACT}")
    if not isinstance(lock["input_sha256"], str) or not SHA256_PATTERN.fullmatch(lock["input_sha256"]):
        raise ValueError("render lock input_sha256 must be a lowercase SHA-256")
    rendered = lock["rendered_agents"]
    if not isinstance(rendered, dict):
        raise ValueError("render lock rendered_agents must be an object")
    _require_exact_keys(rendered, {"path", "bytes", "sha256"}, set(), "render lock rendered_agents")
    if rendered["path"] != "AGENTS.md":
        raise ValueError("render lock rendered_agents.path must be AGENTS.md")
    if isinstance(rendered["bytes"], bool) or not isinstance(rendered["bytes"], int) or rendered["bytes"] < 0:
        raise ValueError("render lock rendered_agents.bytes must be non-negative")
    if not isinstance(rendered["sha256"], str) or not SHA256_PATTERN.fullmatch(rendered["sha256"]):
        raise ValueError("render lock rendered_agents.sha256 must be a lowercase SHA-256")


def check_lock(composition: RenderComposition, lock: dict[str, Any]) -> list[str]:
    validate_render_lock(lock)
    expected = build_render_lock(composition)
    errors: list[str] = []
    if lock["input_sha256"] != expected["input_sha256"]:
        errors.append(
            f"input hash mismatch: expected={lock['input_sha256']} observed={expected['input_sha256']}"
        )
    for field, label in (("bytes", "rendered byte-count"), ("sha256", "rendered hash")):
        if lock["rendered_agents"][field] != expected["rendered_agents"][field]:
            errors.append(
                f"{label} mismatch: expected={lock['rendered_agents'][field]} observed={expected['rendered_agents'][field]}"
            )
    return errors


def check_rendered_file(
    composition: RenderComposition, lock: dict[str, Any], rendered_path: Path
) -> list[str]:
    errors = check_lock(composition, lock)
    if not rendered_path.is_file():
        errors.append(f"rendered output missing: {rendered_path}")
        return errors
    payload = rendered_path.read_bytes()
    expected = lock["rendered_agents"]
    if len(payload) != expected["bytes"]:
        errors.append(
            f"output byte-count mismatch: expected={expected['bytes']} observed={len(payload)}"
        )
    observed_hash = sha256_bytes(payload)
    if observed_hash != expected["sha256"]:
        errors.append(
            f"output hash mismatch: expected={expected['sha256']} observed={observed_hash}"
        )
    if payload != composition.rendered_bytes:
        errors.append("output bytes differ from deterministic composition")
    return errors


def validate_temporary_output_dir(
    output_dir: Path, repo_root: Path, control_plane: Path
) -> Path:
    output_dir = output_dir.resolve()
    temp_root = Path(tempfile.gettempdir()).resolve()
    if not output_dir.is_dir():
        raise ValueError("output directory must already exist")
    if output_dir == temp_root or not _is_within(output_dir, temp_root):
        raise ValueError("output directory must be below the system temporary root")
    if _is_within(output_dir, repo_root.resolve()) or _is_within(output_dir, control_plane.resolve()):
        raise ValueError("output directory must not be inside a repository")
    cursor = output_dir
    while _is_within(cursor, temp_root):
        if (cursor / ".git").exists():
            raise ValueError("output directory must not be inside a Git repository")
        if cursor == temp_root:
            break
        cursor = cursor.parent
    if any(output_dir.iterdir()):
        raise ValueError("output directory must be empty")
    return output_dir


def render_to_temporary_directory(
    composition: RenderComposition, lock: dict[str, Any], output_dir: Path
) -> Path:
    errors = check_lock(composition, lock)
    if errors:
        raise ValueError("; ".join(errors))
    output_dir = validate_temporary_output_dir(
        output_dir, composition.repo_root, composition.control_plane
    )
    target = output_dir / "AGENTS.md"
    target.write_bytes(composition.rendered_bytes)
    return target


def command_status(args: argparse.Namespace) -> int:
    composition = compose_render(Path(args.repo_root), Path(args.control_plane))
    lock_path = _resolve_repo_relative_or_absolute(composition.repo_root, args.lock)
    candidate = build_render_lock(composition)
    if lock_path.is_file():
        errors = check_lock(composition, load_json(lock_path))
        lock_state = "MATCH" if not errors else "DRIFT"
    else:
        errors = [f"render lock missing: {lock_path}"]
        lock_state = "MISSING"
    print(
        json.dumps(
            {
                "repo_id": composition.repo_config["repo_id"],
                "profile_order": composition.repo_config["profiles"],
                "lifecycle_state": composition.repo_config["lifecycle"]["state"],
                "input_sha256": composition.input_sha256,
                "rendered_agents": candidate["rendered_agents"],
                "lock_path": str(lock_path),
                "lock_state": lock_state,
                "errors": errors,
                "lock_candidate": candidate,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def command_render(args: argparse.Namespace) -> int:
    composition = compose_render(Path(args.repo_root), Path(args.control_plane))
    lock = load_json(_resolve_repo_relative_or_absolute(composition.repo_root, args.lock))
    target = render_to_temporary_directory(composition, lock, Path(args.output_dir))
    print(
        json.dumps(
            {
                "status": "RENDERED",
                "output": str(target),
                "bytes": target.stat().st_size,
                "sha256": sha256_file(target),
                "input_sha256": composition.input_sha256,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def command_check(args: argparse.Namespace) -> int:
    composition = compose_render(Path(args.repo_root), Path(args.control_plane))
    lock = load_json(_resolve_repo_relative_or_absolute(composition.repo_root, args.lock))
    errors = check_rendered_file(composition, lock, Path(args.rendered_agents))
    print(
        json.dumps(
            {
                "repo_id": composition.repo_config["repo_id"],
                "status": "PASS" if not errors else "FAIL",
                "input_sha256": composition.input_sha256,
                "rendered_agents": str(Path(args.rendered_agents).resolve()),
                "errors": errors,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 1 if errors else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="topctl")
    subparsers = parser.add_subparsers(dest="command", required=True)
    status = subparsers.add_parser(
        "status", help="show deterministic policy inputs and lock state without writing"
    )
    status.add_argument("--repo-root", required=True)
    status.add_argument("--control-plane", required=True)
    status.add_argument("--lock", default=".toplayer/render.lock.json")
    status.set_defaults(func=command_status)
    render = subparsers.add_parser(
        "render", help="render AGENTS.md into an empty system temporary directory"
    )
    render.add_argument("--repo-root", required=True)
    render.add_argument("--control-plane", required=True)
    render.add_argument("--lock", required=True)
    render.add_argument("--output-dir", required=True)
    render.set_defaults(func=command_render)
    check = subparsers.add_parser(
        "check", help="read-only validation of policy inputs, lock, and AGENTS.md"
    )
    check.add_argument("--repo-root", required=True)
    check.add_argument("--control-plane", required=True)
    check.add_argument("--lock", required=True)
    check.add_argument("--rendered-agents", required=True)
    check.set_defaults(func=command_check)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as error:
        print(json.dumps({"status": "ERROR", "error": str(error)}, indent=2), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
