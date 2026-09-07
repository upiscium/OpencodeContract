"""Shared read-only consumer audit implementation."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import tomllib
from typing import Any, Mapping

PROFILE_AGENT_DIRS = {
    # packages/opencode/config/agents is the canonical dotnix package-owned path.
    # Keep the legacy config.d path as a read-only audit fallback while older
    # pinned consumers finish migrating; dotnix itself does not need to retain it.
    "global": (
        Path("packages/opencode/config/agents"),
        Path("config.d/opencode/agents"),
    ),
    "agent-core": (Path("components/agent-core/.opencode/agents"),),
}
SUMMARY_KEYS = ("PASS", "INTENTIONAL_DIFFERENCE", "DIFF", "MISSING")
LOCAL_MANIFEST_KEYS = {
    "schema_version", "profile", "enabled_by_default", "opt_in", "dispatch",
    "max_in_flight", "required_tools", "retry_limit", "retry_eligibility",
    "retry_exclusions", "retry_model_policy", "fallback", "workers", "metrics",
}


def parse_frontmatter(path: Path) -> dict[str, Any]:
    """Parse the scalar fields needed by the audit without a YAML dependency."""
    result: dict[str, Any] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return result
    if not lines or lines[0].strip() != "---":
        return result
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if line.startswith((" ", "\t")) or ":" not in line:
            continue
        key, value = line.split(":", 1)
        value = value.strip().strip('"').strip("'")
        if value in {"true", "false"}:
            result[key] = value == "true"
        else:
            result[key] = value
    return result


def _frontmatter_permissions(path: Path) -> dict[str, str]:
    """Parse one scalar indentation level under a frontmatter permission map."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return {}
    if not lines or lines[0].strip() != "---":
        return {}
    permissions: dict[str, str] = {}
    in_permissions = False
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if line == "permission:":
            in_permissions = True
            continue
        if in_permissions and line and not line[0].isspace():
            break
        if in_permissions and line.startswith("  ") and ":" in line:
            key, value = line.strip().split(":", 1)
            permissions[key.strip('"\'')] = value.strip().strip('"\'')
    return permissions


def _profile_agent_dir(profile: str, consumer_root: Path) -> Path:
    candidates = [consumer_root / relative for relative in PROFILE_AGENT_DIRS[profile]]
    return next(
        (candidate for candidate in candidates if candidate.exists() or candidate.is_symlink()),
        candidates[0],
    )


def _is_confined_path(path: Path, consumer_root: Path) -> bool:
    """Reject escapes and symlinked components below a possibly symlinked root."""
    try:
        relative = path.relative_to(consumer_root)
        resolved_root = consumer_root.resolve()
        if not path.resolve().is_relative_to(resolved_root):
            return False
    except (OSError, ValueError):
        return False
    current = consumer_root
    for component in relative.parts:
        current /= component
        if current.is_symlink():
            return False
    return True


def _string_list(value: Any) -> list[str] | None:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        return None
    return value


def _audit_local_workers(
    consumer_root: Path,
    documents: Mapping[str, Mapping[str, Any]],
) -> tuple[list[str], Counter[str]]:
    """Audit one atomic Global bundle; never search repository-local layers."""
    agent_dir = _profile_agent_dir("global", consumer_root)
    if not _is_confined_path(agent_dir, consumer_root):
        return [], Counter()
    manifest = agent_dir.parent / "local-workers.toml"
    if not manifest.exists() and not manifest.is_symlink():
        return ["PASS local_workers=absent"], Counter(PASS=1)
    if manifest.is_symlink() or not manifest.is_file():
        return ["DIFF UNEXPECTED_DRIFT local_workers=manifest_not_regular"], Counter(DIFF=1)

    try:
        with manifest.open("rb") as handle:
            doc = tomllib.load(handle)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return [f"DIFF UNEXPECTED_DRIFT local_workers=parse_error={exc}"], Counter(DIFF=1)

    policy = documents["optional-workers"]
    contract = policy["contract"]
    worker_policy = policy["workers"]
    permission_policy = policy["permissions"]
    metric_policy = policy["metrics"]
    errors: list[str] = []

    if set(doc) != LOCAL_MANIFEST_KEYS:
        errors.append("manifest_schema")
    exact_fields = {
        "schema_version": 1,
        "profile": contract["profile"],
        "enabled_by_default": contract["enabled_by_default"],
        "opt_in": contract["opt_in"],
        "dispatch": contract["dispatch"],
        "max_in_flight": contract["max_in_flight"],
        "required_tools": contract["required_tools"],
        "retry_limit": contract["retry_limit"],
        "retry_eligibility": contract["retry_eligibility"],
        "retry_exclusions": contract["retry_exclusions"],
        "retry_model_policy": contract["retry_model_policy"],
        "fallback": contract["fallback"],
    }
    for field, expected in exact_fields.items():
        actual = doc.get(field)
        if type(actual) is not type(expected) or actual != expected:
            errors.append(f"manifest_{field}")

    workers = doc.get("workers")
    if not isinstance(workers, list) or any(not isinstance(item, dict) for item in workers):
        workers = []
        errors.append("workers_schema")
    allowed_workers = worker_policy["allowed"]
    worker_names = [item.get("class") for item in workers]
    if worker_names != allowed_workers or len(set(name for name in worker_names if isinstance(name, str))) != len(worker_names):
        errors.append("worker_classes")

    canonical_models = {
        model["id"] for model in documents["models"]["models"].values()
        if isinstance(model, dict) and isinstance(model.get("id"), str)
    }
    config_path = agent_dir.parent / "opencode.json"
    config: Any = None
    if config_path.is_symlink() or not config_path.is_file():
        errors.append("opencode_json_missing_or_not_regular")
    else:
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            errors.append("opencode_json_invalid")
    provider_table = config.get("provider") if isinstance(config, dict) else None
    if not isinstance(provider_table, dict):
        provider_table = {}
        errors.append("provider_table_invalid")

    required_permissions = {
        "*": permission_policy["default"],
        **{tool: "allow" for tool in permission_policy["allowed"]},
        **{tool: "deny" for tool in permission_policy["explicitly_denied"]},
    }
    for item in workers:
        worker = item.get("class")
        provider_id = item.get("provider")
        model_id = item.get("model")
        if set(item) != {"class", "provider", "model", "role"}:
            errors.append(f"worker_{worker}_schema")
        if item.get("role") != worker_policy["role"]:
            errors.append(f"worker_{worker}_authority")
        if not all(isinstance(value, str) and value for value in (worker, provider_id, model_id)):
            errors.append("worker_identifier")
            continue
        binding = f"{provider_id}/{model_id}"
        if binding in canonical_models:
            errors.append(f"worker_{worker}_canonical_model")
        provider = provider_table.get(provider_id)
        models = provider.get("models") if isinstance(provider, dict) else None
        if not isinstance(models, dict) or model_id not in models:
            errors.append(f"worker_{worker}_unresolved_model")

        agent = agent_dir / f"{worker}.md"
        if agent.is_symlink() or not agent.is_file():
            errors.append(f"agent_{worker}_missing_or_not_regular")
            continue
        frontmatter = parse_frontmatter(agent)
        if frontmatter.get("mode") != worker_policy["mode"] or frontmatter.get("hidden") is not worker_policy["hidden"]:
            errors.append(f"agent_{worker}_visibility_or_mode")
        if frontmatter.get("model") != binding or frontmatter.get("model") in canonical_models:
            errors.append(f"agent_{worker}_binding")
        if _frontmatter_permissions(agent) != required_permissions:
            errors.append(f"agent_{worker}_permissions")

    metrics = doc.get("metrics")
    expected_metrics = {key: metric_policy[key] for key in ("counters", "optional_observations", "metadata")}
    if not isinstance(metrics, dict) or set(metrics) != set(expected_metrics):
        errors.append("metrics_schema")
    else:
        for field, expected in expected_metrics.items():
            actual = _string_list(metrics.get(field))
            if actual != expected or actual is None or len(actual) != len(set(actual)):
                errors.append(f"metrics_{field}")

    if errors:
        reasons = ",".join(sorted(set(errors)))
        return [f"DIFF UNEXPECTED_DRIFT local_workers=invalid reasons={reasons}"], Counter(DIFF=1)
    return ["PASS local_workers=valid static_guarantee=configuration_only"], Counter(PASS=1)


def _audit_profile_contract(
    profile: str,
    consumer_root: Path,
    documents: Mapping[str, Mapping[str, Any]],
) -> tuple[list[str], Counter[str]]:
    if profile not in PROFILE_AGENT_DIRS:
        raise ValueError(f"unknown profile: {profile}")

    models = documents["models"]["models"]
    roles = documents["roles"]["roles"]
    lines: list[str] = []
    counts: Counter[str] = Counter()

    if profile == "agent-core":
        model_fallback_path = (
            consumer_root / "components/agent-core/.automation/model-fallback.toml"
        )
        if model_fallback_path.exists() or model_fallback_path.is_symlink():
            lines.append(
                "DIFF UNEXPECTED_DRIFT profile=agent-core "
                "model_fallback_policy=model-fallback.toml expected=absent"
            )
            counts["DIFF"] += 1
        else:
            lines.append("PASS profile=agent-core model_fallback_policy=absent")
            counts["PASS"] += 1

    agent_dir = _profile_agent_dir(profile, consumer_root)
    if not _is_confined_path(agent_dir, consumer_root):
        lines.append(
            f"DIFF UNEXPECTED_DRIFT profile={profile} agent_directory={agent_dir} unsafe_path=forbidden"
        )
        counts["DIFF"] += 1
        return lines, counts
    if not agent_dir.is_dir():
        lines.append(f"MISSING UNEXPECTED_DRIFT profile={profile} agent_directory={agent_dir}")
        counts["MISSING"] += 1
        return lines, counts

    expected_roles = {role_id for role_id, role in roles.items() if profile in role["profiles"]}
    for role_id in sorted(expected_roles):
        assignment = documents[profile]["assignments"][role_id]
        expected_model = models[assignment["primary_model"]]["id"]
        expected_mode = roles[role_id]["kind"]
        primary_path = agent_dir / f"{role_id}.md"
        if primary_path.is_symlink() or not _is_confined_path(primary_path, consumer_root):
            lines.append(
                f"DIFF UNEXPECTED_DRIFT profile={profile} role={role_id} "
                f"agent={role_id} unsafe_path=forbidden"
            )
            counts["DIFF"] += 1
            continue
        if not primary_path.is_file():
            lines.append(f"MISSING UNEXPECTED_DRIFT profile={profile} role={role_id} agent={role_id}")
            counts["MISSING"] += 1
        else:
            primary = parse_frontmatter(primary_path)
            if primary.get("model") != expected_model:
                lines.append(
                    f"DIFF UNEXPECTED_DRIFT profile={profile} role={role_id} primary_model="
                    f"{primary.get('model')!r} expected={expected_model!r}"
                )
                counts["DIFF"] += 1
            else:
                lines.append(f"PASS profile={profile} role={role_id} primary_model={expected_model}")
                counts["PASS"] += 1
            if primary.get("mode") != expected_mode:
                lines.append(
                    f"DIFF UNEXPECTED_DRIFT profile={profile} role={role_id} "
                    f"mode={primary.get('mode')!r} expected={expected_mode!r}"
                )
                counts["DIFF"] += 1
            else:
                lines.append(f"PASS profile={profile} role={role_id} mode={expected_mode}")
                counts["PASS"] += 1

    for role_id in sorted(set(roles) - expected_roles):
        if (agent_dir / f"{role_id}.md").exists():
            lines.append(
                f"DIFF UNEXPECTED_DRIFT profile={profile} role={role_id} "
                f"agent={role_id} expected=absent"
            )
            counts["DIFF"] += 1
        else:
            lines.append(f"INTENTIONAL_DIFFERENCE profile={profile} role={role_id} expected=absent")
            counts["INTENTIONAL_DIFFERENCE"] += 1

    fallback_residue = sorted(agent_dir.glob("*-fallback.md"))
    if fallback_residue:
        for path in fallback_residue:
            lines.append(
                f"DIFF UNEXPECTED_DRIFT profile={profile} agent={path.stem} "
                "fallback_residue=forbidden"
            )
            counts["DIFF"] += 1
    else:
        lines.append(f"PASS profile={profile} fallback_agents=absent")
        counts["PASS"] += 1

    if profile == "global":
        optional_agents: set[str] = set()
        if (agent_dir.parent / "local-workers.toml").is_file():
            optional_agents = set(documents["optional-workers"]["workers"]["allowed"])
        registered_agents = expected_roles | optional_agents
        for path in sorted(agent_dir.glob("*.md")):
            if path.stem not in registered_agents and not path.name.endswith("-fallback.md"):
                lines.append(
                    f"DIFF UNEXPECTED_DRIFT profile={profile} agent={path.stem} "
                    "unregistered_agent=forbidden"
                )
                counts["DIFF"] += 1

    return lines, counts


def _policy_difference_lines(
    documents: Mapping[str, Mapping[str, Any]],
) -> tuple[list[str], Counter[str]]:
    lines: list[str] = []
    counts: Counter[str] = Counter()
    for difference in documents["invariants"].get("intentional_differences", []):
        role_id = difference["role"]
        field = difference["field"]
        global_value = documents["global"]["assignments"][role_id][field]
        agent_core_value = documents["agent-core"]["assignments"][role_id][field]
        lines.append(
            f"INTENTIONAL_DIFFERENCE id={difference['id']} role={role_id} field={field} "
            f"global={global_value} agent-core={agent_core_value}"
        )
        counts["INTENTIONAL_DIFFERENCE"] += 1
    return lines, counts


def audit_profiles(
    consumers: Mapping[str, Path],
    documents: Mapping[str, Mapping[str, Any]],
) -> tuple[list[str], Counter[str]]:
    """Audit one or more explicitly bound profiles with shared accounting."""
    lines: list[str] = []
    counts: Counter[str] = Counter()
    for profile, consumer_root in consumers.items():
        profile_lines, profile_counts = _audit_profile_contract(profile, consumer_root, documents)
        lines.extend(profile_lines)
        counts.update(profile_counts)
        if profile == "global":
            local_lines, local_counts = _audit_local_workers(consumer_root, documents)
            lines.extend(local_lines)
            counts.update(local_counts)
    difference_lines, difference_counts = _policy_difference_lines(documents)
    lines.extend(difference_lines)
    counts.update(difference_counts)
    return lines, counts


def audit_profile(
    profile: str,
    consumer_root: Path,
    policy_documents: Mapping[str, Mapping[str, Any]],
) -> tuple[list[str], Counter[str]]:
    """Audit one consumer using an explicit profile; never infer from its path."""
    return audit_profiles({profile: consumer_root}, policy_documents)


def format_summary(counts: Counter[str]) -> str:
    return "SUMMARY " + " ".join(f"{key}={counts[key]}" for key in SUMMARY_KEYS)


def invalid_consumer_roots(consumers: Mapping[str, Path]) -> list[Path]:
    """Return explicitly supplied consumer roots that are not directories."""
    return [path for path in consumers.values() if not path.is_dir()]


def result_exit_code(lines: list[str], counts: Counter[str], strict: bool) -> int:
    """Apply common policy-invalid and strict conformity exit semantics."""
    if any(line.startswith("DIFF POLICY_INVALID ") for line in lines):
        return 1
    if strict and (counts["DIFF"] or counts["MISSING"]):
        return 1
    return 0
