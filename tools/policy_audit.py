"""Shared read-only consumer audit implementation."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
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


def parse_frontmatter(path: Path) -> dict[str, Any]:
    """Parse the scalar fields needed by the audit without a YAML dependency."""
    result: dict[str, Any] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
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

    candidates = [consumer_root / relative for relative in PROFILE_AGENT_DIRS[profile]]
    agent_dir = next((candidate for candidate in candidates if candidate.is_dir()), candidates[0])
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
        primary = parse_frontmatter(primary_path)
        if not primary_path.is_file():
            lines.append(f"MISSING UNEXPECTED_DRIFT profile={profile} role={role_id} agent={role_id}")
            counts["MISSING"] += 1
        else:
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
