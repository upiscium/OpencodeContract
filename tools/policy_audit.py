"""Shared read-only consumer audit implementation."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import stat
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
PERMISSION_MANIFEST_NAME = "opencode-contract-permissions.toml"
PERMISSION_MANIFEST_KEYS = {
    "schema_version", "contract", "profile", "surfaces", "probes",
}
PERMISSION_SURFACE_KEYS = {
    "id", "boundary", "base_source", "agent_source", "signals",
}
PERMISSION_PROBE_KEYS = {"surface", "tool", "input", "classes"}
PERMISSION_BOUNDARIES = {"parent", "leaf"}
PERMISSION_ACTIONS = {"allow", "ask", "deny"}
_PERMISSION_MISSING = object()


def _secure_read_file(
    path: Path,
    consumer_root: Path,
) -> tuple[bytes | None, str, str | None]:
    """Read a regular consumer file without following path-component symlinks."""
    try:
        relative = path.relative_to(consumer_root)
    except ValueError:
        return None, "error", "path_not_confined"

    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        return None, "error", "secure_open_unavailable"

    common_flags = os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0)
    directory_flags = common_flags | directory_flag
    directory_fd = -1
    file_fd = -1
    try:
        directory_fd = os.open(os.fspath(consumer_root), directory_flags)
        parts = relative.parts
        if not parts or any(part in {"", ".", ".."} for part in parts):
            return None, "error", "path_not_confined"
        for component in parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            parts[-1],
            common_flags | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            return None, "error", "not_regular"
        with os.fdopen(file_fd, "rb") as handle:
            file_fd = -1
            return handle.read(), "ok", None
    except FileNotFoundError:
        return None, "missing", "file_missing"
    except NotADirectoryError:
        return None, "error", "path_not_directory"
    except OSError as exc:
        return None, "error", f"secure_open_error={exc}"
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if directory_fd >= 0:
            os.close(directory_fd)


def parse_frontmatter(path: Path, consumer_root: Path) -> dict[str, Any]:
    """Parse the scalar fields needed by the audit without a YAML dependency."""
    result: dict[str, Any] = {}
    content, status, _reason = _secure_read_file(path, consumer_root)
    if status != "ok" or content is None:
        return result
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return result
    if not lines or lines[0].strip() != "---":
        return result
    closed = False
    for line in lines[1:]:
        if line.strip() == "---":
            closed = True
            break
        if line.startswith((" ", "\t")) or ":" not in line:
            continue
        key, value = line.split(":", 1)
        value = value.strip().strip('"').strip("'")
        if value in {"true", "false"}:
            result[key] = value == "true"
        else:
            result[key] = value
    return result if closed else {}


def _frontmatter_permissions(path: Path, consumer_root: Path) -> dict[str, str]:
    """Parse the flat permission map used by the optional-worker contract."""
    content, status, _reason = _secure_read_file(path, consumer_root)
    if status != "ok" or content is None:
        return {}
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return {}
    try:
        document = _parse_bounded_frontmatter(text)
    except ValueError:
        return {}
    permissions = document.get("permission")
    if not isinstance(permissions, Mapping):
        return {}
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in permissions.items()):
        return {}
    return dict(permissions)


def _frontmatter_commentless_value(value: str) -> str:
    """Remove a simple YAML-style comment without treating # in quotes specially."""
    in_single = False
    in_double = False
    escaped = False
    for index, character in enumerate(value):
        if in_double and escaped:
            escaped = False
            continue
        if in_double and character == "\\":
            escaped = True
            continue
        if character == "'" and not in_double:
            in_single = not in_single
        elif character == '"' and not in_single:
            in_double = not in_double
        elif character == "#" and not in_single and not in_double:
            if index == 0 or value[index - 1].isspace():
                return value[:index].rstrip()
    return value.strip()


def _frontmatter_token(value: str) -> Any:
    """Parse the bounded scalar subset needed by permission frontmatter."""
    value = _frontmatter_commentless_value(value)
    if not value:
        return ""
    if len(value) >= 2 and value[0] == value[-1] == '"':
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid double-quoted scalar: {exc}") from exc
        if not isinstance(decoded, str):
            raise ValueError("quoted frontmatter key or value is not a string")
        return decoded
    if len(value) >= 2 and value[0] == value[-1] == "'":
        return value[1:-1].replace("''", "'")
    if value == "true":
        return True
    if value == "false":
        return False
    if value in {"null", "~"}:
        return None
    try:
        if value.isdigit() or (
            value.startswith(("+", "-")) and value[1:].isdigit()
        ):
            return int(value)
        if any(character in value for character in ".eE"):
            return float(value)
    except ValueError:
        pass
    return value


def _frontmatter_mapping_separator(line: str) -> int:
    """Find a mapping colon while leaving quoted pattern keys intact."""
    in_single = False
    in_double = False
    escaped = False
    for index, character in enumerate(line):
        if in_double and escaped:
            escaped = False
            continue
        if in_double and character == "\\":
            escaped = True
            continue
        if character == "'" and not in_double:
            in_single = not in_single
        elif character == '"' and not in_single:
            in_double = not in_double
        elif character == ":" and not in_single and not in_double:
            return index
    return -1


def _parse_bounded_frontmatter(text: str) -> dict[str, Any]:
    """Parse frontmatter mappings without depending on a generic YAML parser."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise ValueError("missing frontmatter opening delimiter")

    closing_index: int | None = None
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            closing_index = index
            break
    if closing_index is None:
        raise ValueError("missing frontmatter closing delimiter")

    result: dict[str, Any] = {}
    # Each stack item represents a mapping opened by a key with no scalar
    # value.  Keeping the indentation and insertion order is sufficient for
    # the bounded permission syntax and preserves ordered pattern rules.
    stack: list[tuple[int, dict[str, Any]]] = [(-1, result)]
    previous_indent = -1
    previous_opened_mapping = True
    saw_content = False

    for line_number, line in enumerate(lines[1:closing_index], start=2):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        leading = line[: len(line) - len(line.lstrip(" "))]
        if "\t" in leading:
            raise ValueError(f"tabs are not supported at line {line_number}")
        indent = len(leading)
        if not saw_content and indent != 0:
            raise ValueError(f"nested first key at line {line_number}")
        if (
            saw_content
            and indent > previous_indent
            and not previous_opened_mapping
        ):
            raise ValueError(f"unexpected indentation at line {line_number}")

        while stack and stack[-1][0] >= indent:
            stack.pop()
        if not stack:
            raise ValueError(f"invalid indentation at line {line_number}")

        separator = _frontmatter_mapping_separator(line)
        if separator < 0:
            raise ValueError(f"expected mapping entry at line {line_number}")
        raw_key = line[:separator]
        raw_value = line[separator + 1 :]
        key_value = _frontmatter_token(raw_key.strip())
        if not isinstance(key_value, str) or not key_value:
            raise ValueError(f"invalid mapping key at line {line_number}")
        parent = stack[-1][1]
        if key_value in parent:
            raise ValueError(f"duplicate mapping key {key_value!r} at line {line_number}")

        value = _frontmatter_commentless_value(raw_value.strip())
        if not value:
            child: dict[str, Any] = {}
            parent[key_value] = child
            stack.append((indent, child))
            previous_opened_mapping = True
        else:
            parent[key_value] = _frontmatter_token(value)
            previous_opened_mapping = False
        previous_indent = indent
        saw_content = True

    return result


def _profile_agent_dir(profile: str, consumer_root: Path) -> Path:
    candidates = [consumer_root / relative for relative in PROFILE_AGENT_DIRS[profile]]
    for candidate in candidates:
        if candidate.exists() or candidate.is_symlink():
            return candidate
        # A partially deployed preferred bundle must not silently fall back to
        # an older bundle merely because its agents directory is absent.
        bundle_dir = candidate.parent if profile == "global" else candidate.parent.parent
        if bundle_dir.exists() or bundle_dir.is_symlink():
            return candidate
    return candidates[0]


def _is_confined_path(path: Path, consumer_root: Path) -> bool:
    """Reject escapes and symlinked components below a possibly symlinked root."""
    try:
        relative = path.relative_to(consumer_root)
        resolved_root = consumer_root.resolve()
        if not path.resolve().is_relative_to(resolved_root):
            return False
    except (OSError, RuntimeError, ValueError):
        return False
    current = consumer_root
    for component in relative.parts:
        current /= component
        if current.is_symlink():
            return False
    return True


def _agent_inventory(agent_dir: Path, consumer_root: Path) -> tuple[list[Path], list[Path]]:
    """Find recursively loadable Markdown while rejecting followed symlinks."""
    markdown: list[Path] = []
    unsafe: list[Path] = []
    for path in sorted(agent_dir.rglob("*")):
        if path.is_symlink():
            # OpenCode follows symlinks while scanning agents. Reject Markdown
            # links and directory links rather than following them out of the
            # selected profile-owned inventory.
            if path.suffix == ".md" or path.is_dir():
                unsafe.append(path)
            continue
        if path.is_file() and path.suffix == ".md":
            if _is_confined_path(path, consumer_root):
                markdown.append(path)
            else:
                unsafe.append(path)
    return markdown, unsafe


def _agent_identity(agent_dir: Path, path: Path) -> str:
    """Match OpenCode's extension-free, agent-directory-relative identity."""
    return path.relative_to(agent_dir).with_suffix("").as_posix()


def _string_list(value: Any) -> list[str] | None:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        return None
    return value


def _permission_bundle_dir(profile: str, agent_dir: Path) -> Path:
    """Return the selected consumer-owned bundle containing its manifest."""
    if profile == "global":
        return agent_dir.parent
    return agent_dir.parent.parent


def _permission_wildcard_match(pattern: str, value: str) -> bool:
    """Match only OpenCode's literal, * and ? wildcard syntax."""
    pattern_index = 0
    value_index = 0
    last_star = -1
    star_value_index = 0

    # Greedy star backtracking is equivalent to the bounded recursive matcher
    # for this two-wildcard language, but cannot exhaust Python's call stack on
    # a long valid probe input.
    while value_index < len(value):
        if pattern_index < len(pattern) and (
            pattern[pattern_index] == "?"
            or pattern[pattern_index] == value[value_index]
        ):
            pattern_index += 1
            value_index += 1
        elif pattern_index < len(pattern) and pattern[pattern_index] == "*":
            last_star = pattern_index
            star_value_index = value_index
            pattern_index += 1
        elif last_star >= 0:
            pattern_index = last_star + 1
            star_value_index += 1
            value_index = star_value_index
        else:
            return False

    while pattern_index < len(pattern) and pattern[pattern_index] == "*":
        pattern_index += 1
    return pattern_index == len(pattern)


def _permission_resolution_order(
    value: Any,
    allowed: list[str],
    location: str,
    errors: list[str],
) -> dict[str, int]:
    """Turn the canonical fail-closed overlap declaration into ranks."""
    if not isinstance(value, str):
        errors.append(f"{location}: missing overlap resolution")
        return {}
    parts = value.split("-over-")
    if len(parts) != len(allowed) or set(parts) != set(allowed):
        errors.append(f"{location}: invalid overlap resolution {value!r}")
        return {}
    # The first item in the policy resolution string is the strongest.
    return {item: len(parts) - index for index, item in enumerate(parts)}


def _permission_contract_context(
    profile: str,
    documents: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, Any] | None, list[str]]:
    """Resolve canonical classes and the selected profile's boundary binding."""
    errors: list[str] = []
    document = documents.get("permission-semantics")
    if not isinstance(document, Mapping):
        return None, ["permission-semantics document is missing"]
    contract = document.get("contract")
    if not isinstance(contract, Mapping):
        return None, ["permission-semantics contract is not a table"]

    profiles = contract.get("profiles")
    if not isinstance(profiles, list) or profile not in profiles:
        errors.append(f"unknown profile {profile!r} in canonical permission contract")

    class_values = contract.get("operation_classes")
    class_ids: list[str] = []
    if not isinstance(class_values, list):
        errors.append("canonical operation_classes is not a list")
    else:
        for class_id in class_values:
            if not isinstance(class_id, str) or not class_id:
                errors.append(f"invalid canonical operation class {class_id!r}")
            elif class_id in class_ids:
                errors.append(f"duplicate canonical operation class {class_id!r}")
            else:
                class_ids.append(class_id)

    dispositions = contract.get("dispositions")
    if not isinstance(dispositions, list) or not all(
        isinstance(item, str) and item for item in dispositions
    ):
        errors.append("canonical dispositions are invalid")
        disposition_values: list[str] = []
    else:
        disposition_values = list(dispositions)
    escalations = contract.get("escalation_outcomes")
    if not isinstance(escalations, list) or not all(
        isinstance(item, str) and item for item in escalations
    ):
        errors.append("canonical escalation_outcomes are invalid")
        escalation_values: list[str] = []
    else:
        escalation_values = list(escalations)

    allow_requires_role_permission = contract.get(
        "allow_requires_configured_role_permission"
    )
    if type(allow_requires_role_permission) is not bool:
        errors.append(
            "canonical allow_requires_configured_role_permission is invalid"
        )

    signals_value = document.get("signals")
    signal_ids: list[str] = []
    if not isinstance(signals_value, Mapping):
        errors.append("canonical signals are not a table")
    else:
        for signal_id, definition in signals_value.items():
            if not isinstance(signal_id, str) or not signal_id:
                errors.append(f"invalid canonical signal {signal_id!r}")
            elif not isinstance(definition, Mapping):
                errors.append(f"canonical signal {signal_id!r} is not a table")
            elif signal_id in signal_ids:
                errors.append(f"duplicate canonical signal {signal_id!r}")
            else:
                signal_ids.append(signal_id)

    operations_value = document.get("operation_classes")
    operations: dict[str, Mapping[str, Any]] = {}
    if not isinstance(operations_value, list):
        errors.append("canonical operation class definitions are not a list")
    else:
        for operation in operations_value:
            if not isinstance(operation, Mapping):
                errors.append("canonical operation class definition is not a table")
                continue
            operation_id = operation.get("id")
            if isinstance(operation_id, str) and operation_id:
                if operation_id in operations:
                    errors.append(f"duplicate canonical operation definition {operation_id!r}")
                else:
                    operations[operation_id] = operation

    for class_id in class_ids:
        operation = operations.get(class_id)
        if operation is None:
            errors.append(f"missing canonical operation definition {class_id!r}")
            continue
        for boundary in PERMISSION_BOUNDARIES:
            disposition = operation.get(f"{boundary}_disposition")
            escalation = operation.get(f"{boundary}_escalation")
            if disposition not in disposition_values:
                errors.append(
                    f"canonical {class_id}.{boundary}_disposition is invalid"
                )
            if escalation not in escalation_values:
                errors.append(
                    f"canonical {class_id}.{boundary}_escalation is invalid"
                )

    conditional_classes: list[str] = []
    if allow_requires_role_permission is True:
        for class_id in class_ids:
            operation = operations.get(class_id)
            if operation is not None and all(
                operation.get(f"{boundary}_disposition") == "allow"
                for boundary in PERMISSION_BOUNDARIES
            ):
                conditional_classes.append(class_id)

    bindings = document.get("profile_bindings")
    binding: Mapping[str, Any] | None = None
    if isinstance(bindings, list):
        for candidate in bindings:
            if isinstance(candidate, Mapping) and candidate.get("profile") == profile:
                binding = candidate
                break
    if binding is None:
        errors.append(f"missing canonical profile binding for {profile!r}")

    authorities_value = document.get("authorities")
    authorities = authorities_value if isinstance(authorities_value, Mapping) else {}
    boundary_authorities: dict[str, str] = {}
    if binding is not None:
        for boundary, field in (("parent", "parent_authority"), ("leaf", "leaf_authority")):
            authority = binding.get(field)
            if not isinstance(authority, str) or not authority:
                errors.append(f"profile binding {profile!r} has no {field}")
                continue
            if authority not in authorities or not isinstance(authorities[authority], Mapping):
                errors.append(f"profile binding {profile!r} references unknown authority {authority!r}")
                continue
            boundary_authorities[boundary] = authority

    disposition_rank = _permission_resolution_order(
        contract.get("overlap_resolution"),
        disposition_values,
        "canonical overlap_resolution",
        errors,
    )
    escalation_rank = _permission_resolution_order(
        contract.get("overlap_escalation_resolution"),
        escalation_values,
        "canonical overlap_escalation_resolution",
        errors,
    )
    if errors:
        return None, errors
    return {
        "classes": class_ids,
        "mandatory_classes": [
            class_id for class_id in class_ids if class_id not in conditional_classes
        ],
        "conditional_classes": conditional_classes,
        "operations": operations,
        "authorities": boundary_authorities,
        "signals": signal_ids,
        "disposition_rank": disposition_rank,
        "escalation_rank": escalation_rank,
    }, []


def _permission_expected_surfaces(
    profile: str,
    documents: Mapping[str, Mapping[str, Any]],
) -> dict[str, tuple[str, str]]:
    """Return canonical executable role surfaces and their source paths."""
    profile_document = documents.get(profile, {})
    surface_policy = profile_document.get("permission_surfaces", {})
    prefix = "agents" if profile == "global" else ".opencode/agents"
    expected: dict[str, tuple[str, str]] = {}
    if not isinstance(surface_policy, Mapping):
        return expected
    for boundary, field in (("parent", "parent_roles"), ("leaf", "leaf_roles")):
        roles = surface_policy.get(field, [])
        if not isinstance(roles, list):
            continue
        for role in roles:
            if isinstance(role, str) and role:
                expected[role] = (boundary, f"{prefix}/{role}.md")
    return expected


def _permission_manifest_schema(
    document: Any,
    profile: str,
    class_ids: list[str],
    mandatory_class_ids: list[str],
    expected_surfaces: Mapping[str, tuple[str, str]],
    signal_ids: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Validate and normalize the closed consumer-owned permission manifest."""
    errors: list[str] = []
    if not isinstance(document, Mapping):
        return [], [], ["manifest is not a table"]

    unknown = set(document) - PERMISSION_MANIFEST_KEYS
    missing = PERMISSION_MANIFEST_KEYS - set(document)
    if unknown:
        errors.append(f"manifest unknown fields={sorted(unknown)!r}")
    if missing:
        errors.append(f"manifest missing fields={sorted(missing)!r}")

    if type(document.get("schema_version")) is not int or document.get("schema_version") != 1:
        errors.append("manifest schema_version must be 1")
    if document.get("contract") != "permission-semantics":
        errors.append("manifest contract must be 'permission-semantics'")
    manifest_profile = document.get("profile")
    if not isinstance(manifest_profile, str) or manifest_profile not in PROFILE_AGENT_DIRS:
        errors.append(f"manifest invalid profile={manifest_profile!r}")
    elif manifest_profile != profile:
        errors.append(
            f"manifest profile={manifest_profile!r} does not match selected profile={profile!r}"
        )

    surfaces_value = document.get("surfaces")
    surface_order: list[str] = []
    surfaces: dict[str, dict[str, Any]] = {}
    if not isinstance(surfaces_value, list):
        errors.append("manifest surfaces must be a list")
    elif not surfaces_value:
        errors.append("manifest surfaces must not be empty")
    else:
        for index, item in enumerate(surfaces_value):
            location = f"surfaces[{index}]"
            if not isinstance(item, Mapping):
                errors.append(f"{location} must be a table")
                continue
            item_unknown = set(item) - PERMISSION_SURFACE_KEYS
            item_missing = PERMISSION_SURFACE_KEYS - set(item)
            if item_unknown:
                errors.append(f"{location} unknown fields={sorted(item_unknown)!r}")
            if item_missing:
                errors.append(f"{location} missing fields={sorted(item_missing)!r}")

            surface_id = item.get("id")
            if not isinstance(surface_id, str) or not surface_id:
                errors.append(f"{location}.id must be a non-empty string")
                surface_id = None
            elif surface_id in surfaces:
                errors.append(f"{location}.id duplicate={surface_id!r}")
                surface_id = None
            elif surface_id not in expected_surfaces:
                errors.append(f"{location}.id unknown={surface_id!r}")

            boundary = item.get("boundary")
            if not isinstance(boundary, str) or boundary not in PERMISSION_BOUNDARIES:
                errors.append(f"{location}.boundary invalid={boundary!r}")
                boundary = None
            base_source = item.get("base_source")
            if not isinstance(base_source, str) or not base_source:
                errors.append(f"{location}.base_source must be a non-empty string")
                base_source = None
            elif Path(base_source).is_absolute() or any(
                part in {".", ".."} for part in Path(base_source).parts
            ):
                errors.append(f"{location}.base_source must be normalized and relative")

            agent_source = item.get("agent_source")
            if not isinstance(agent_source, str) or not agent_source:
                errors.append(f"{location}.agent_source must be a non-empty string")
                agent_source = None
            elif Path(agent_source).is_absolute() or any(
                part in {".", ".."} for part in Path(agent_source).parts
            ):
                errors.append(f"{location}.agent_source must be normalized and relative")

            signal_values = item.get("signals")
            signals: list[str] = []
            if not isinstance(signal_values, list):
                errors.append(f"{location}.signals must be a list")
            else:
                for signal_index, signal in enumerate(signal_values):
                    signal_location = f"{location}.signals[{signal_index}]"
                    if not isinstance(signal, str) or not signal:
                        errors.append(f"{signal_location} must be a non-empty string")
                    elif signal not in signal_ids:
                        errors.append(f"{signal_location} unknown={signal!r}")
                    elif signal in signals:
                        errors.append(f"{signal_location} duplicate={signal!r}")
                    else:
                        signals.append(signal)

            if surface_id is not None:
                surface_order.append(surface_id)
                surfaces[surface_id] = {
                    "id": surface_id,
                    "boundary": boundary,
                    "base_source": base_source,
                    "agent_source": agent_source,
                    "signals": signals,
                    "probes": [],
                }

    missing_surfaces = set(expected_surfaces) - set(surfaces)
    extra_surfaces = set(surfaces) - set(expected_surfaces)
    if missing_surfaces:
        errors.append(f"missing_executable_surfaces={sorted(missing_surfaces)!r}")
    if extra_surfaces:
        errors.append(f"unknown_executable_surfaces={sorted(extra_surfaces)!r}")

    probes_value = document.get("probes")
    probes: list[dict[str, Any]] = []
    seen_probe_keys: set[tuple[str, str, str]] = set()
    covered: dict[str, set[str]] = {surface_id: set() for surface_id in surface_order}
    class_set = set(class_ids)
    mandatory_class_set = set(mandatory_class_ids)
    if not isinstance(probes_value, list):
        errors.append("manifest probes must be a list")
    elif not probes_value:
        errors.append("manifest probes must not be empty")
    else:
        for index, item in enumerate(probes_value):
            location = f"probes[{index}]"
            if not isinstance(item, Mapping):
                errors.append(f"{location} must be a table")
                continue
            item_unknown = set(item) - PERMISSION_PROBE_KEYS
            item_missing = PERMISSION_PROBE_KEYS - set(item)
            if item_unknown:
                errors.append(f"{location} unknown fields={sorted(item_unknown)!r}")
            if item_missing:
                errors.append(f"{location} missing fields={sorted(item_missing)!r}")

            surface_id = item.get("surface")
            tool = item.get("tool")
            input_value = item.get("input")
            valid_identity = (
                isinstance(surface_id, str)
                and bool(surface_id)
                and isinstance(tool, str)
                and bool(tool)
                and isinstance(input_value, str)
                and bool(input_value)
            )
            if not isinstance(surface_id, str) or not surface_id:
                errors.append(f"{location}.surface must be a non-empty string")
            elif surface_id not in surfaces:
                errors.append(f"{location}.surface dangling={surface_id!r}")
            if not isinstance(tool, str) or not tool:
                errors.append(f"{location}.tool must be a non-empty string")
            if not isinstance(input_value, str) or not input_value:
                errors.append(f"{location}.input must be a non-empty string")

            class_values = item.get("classes")
            normalized_classes: list[str] = []
            if not isinstance(class_values, list):
                errors.append(f"{location}.classes must be a list")
            elif not class_values:
                errors.append(f"{location}.classes must not be empty")
            else:
                seen_classes: set[str] = set()
                for class_index, class_id in enumerate(class_values):
                    class_location = f"{location}.classes[{class_index}]"
                    if not isinstance(class_id, str) or not class_id:
                        errors.append(f"{class_location} must be a non-empty string")
                        continue
                    if class_id not in class_set:
                        errors.append(f"{class_location} unknown={class_id!r}")
                    if class_id in seen_classes:
                        errors.append(f"{class_location} duplicate={class_id!r}")
                    seen_classes.add(class_id)
                    normalized_classes.append(class_id)

            if valid_identity:
                probe_key = (surface_id, tool, input_value)
                if probe_key in seen_probe_keys:
                    input_digest = hashlib.sha256(input_value.encode("utf-8")).hexdigest()
                    errors.append(
                        f"{location} duplicate=surface={surface_id!r}:tool={tool!r}:"
                        f"input_sha256={input_digest}"
                    )
                seen_probe_keys.add(probe_key)
                probe = {
                    "surface": surface_id,
                    "tool": tool,
                    "input": input_value,
                    "classes": normalized_classes,
                }
                probes.append(probe)
                if surface_id in surfaces:
                    surfaces[surface_id]["probes"].append(probe)
                    covered[surface_id].update(
                        class_id
                        for class_id in normalized_classes
                        if class_id in mandatory_class_set
                    )

    for surface_id in surface_order:
        missing_classes = [
            class_id
            for class_id in mandatory_class_ids
            if class_id not in covered[surface_id]
        ]
        if missing_classes:
            errors.append(
                f"surface={surface_id!r} missing_coverage={missing_classes!r}"
            )

    declared_boundaries = {
        surface["boundary"]
        for surface in surfaces.values()
        if surface["boundary"] in PERMISSION_BOUNDARIES
    }
    for boundary in sorted(PERMISSION_BOUNDARIES - declared_boundaries):
        errors.append(f"missing_boundary_surface={boundary}")

    return [surfaces[surface_id] for surface_id in surface_order], probes, errors


def _permission_source_path(
    manifest_dir: Path,
    consumer_root: Path,
    source: str,
) -> tuple[Path | None, str, str | None]:
    """Resolve one declared source while retaining consumer confinement."""
    raw_path = Path(source)
    if raw_path.is_absolute():
        return None, "error", "source_is_absolute"
    try:
        path = manifest_dir / raw_path
        if not _is_confined_path(path, consumer_root) or not _is_confined_path(path, manifest_dir):
            return None, "error", "source_path_not_confined"
        if path.is_symlink():
            return None, "error", "source_not_regular_or_symlink"
        if not path.exists():
            return path, "missing", "source_missing"
        if not path.is_file():
            return None, "error", "source_not_regular"
    except (OSError, ValueError) as exc:
        return None, "error", f"source_path_error={exc}"
    return path, "ok", None


def _permission_source_inventory_errors(
    profile: str,
    agent_dir: Path,
    documents: Mapping[str, Mapping[str, Any]],
    surfaces: list[dict[str, Any]],
) -> list[str]:
    """Require each manifest surface to bind a canonical executable agent."""
    expected = _permission_expected_surfaces(profile, documents)
    declared = {surface["id"]: surface for surface in surfaces}
    errors: list[str] = []
    for role, (boundary, agent_source) in expected.items():
        surface = declared.get(role)
        if surface is None:
            errors.append(f"missing_executable_surface={role}")
            continue
        if surface["boundary"] != boundary:
            errors.append(
                f"surface_boundary_mismatch={role}:actual={surface['boundary']}:expected={boundary}"
            )
        if surface["base_source"] != "opencode.json":
            errors.append(
                f"surface_base_source_mismatch={role}:actual={surface['base_source']!r}:"
                "expected='opencode.json'"
            )
        if surface["agent_source"] != agent_source:
            errors.append(
                f"surface_agent_source_mismatch={role}:actual={surface['agent_source']!r}:"
                f"expected={agent_source!r}"
            )
    return errors


def _permission_read_source(
    path: Path,
    consumer_root: Path,
    source_kind: str,
) -> tuple[Any, str | None, str]:
    """Read one JSON or bounded frontmatter permission source."""
    content, read_status, read_reason = _secure_read_file(path, consumer_root)
    if read_status != "ok" or content is None:
        return (
            _PERMISSION_MISSING,
            f"source_secure_read={read_reason or read_status}",
            read_status,
        )
    try:
        text = content.decode("utf-8")
        if source_kind == "json":
            document = json.loads(text)
        else:
            document = _parse_bounded_frontmatter(text)
    except (OSError, UnicodeError, ValueError) as exc:
        return _PERMISSION_MISSING, f"source_parse_error={exc}", "error"
    if not isinstance(document, Mapping):
        return _PERMISSION_MISSING, "source_document_not_a_mapping", "error"
    return document.get("permission", _PERMISSION_MISSING), None, "ok"


def _permission_value_error(value: Any) -> str | None:
    """Validate action scalar and per-tool ordered pattern-map shapes."""
    if value is _PERMISSION_MISSING:
        return None
    if isinstance(value, str):
        if value not in PERMISSION_ACTIONS:
            return f"invalid_action={value!r}"
        return None
    if not isinstance(value, Mapping):
        return "non_string_action=permission"

    for tool, rule in value.items():
        if not isinstance(tool, str):
            return "non_string_action=tool_key"
        if isinstance(rule, str):
            if rule not in PERMISSION_ACTIONS:
                return f"invalid_action={rule!r} tool={tool!r}"
            continue
        if not isinstance(rule, Mapping):
            return f"non_string_action=tool={tool!r}"
        for pattern, action in rule.items():
            if not isinstance(pattern, str):
                return f"non_string_action=pattern tool={tool!r}"
            if not isinstance(action, str):
                return f"non_string_action=pattern={pattern!r} tool={tool!r}"
            if action not in PERMISSION_ACTIONS:
                return f"invalid_action={action!r} pattern={pattern!r} tool={tool!r}"
    return None


def _permission_effective_action(
    base_value: Any,
    agent_value: Any,
    tool: str,
    input_value: str,
) -> tuple[str | None, bool]:
    """Evaluate one executable agent's ordered permission layers."""
    # OpenCode flattens each configured layer in insertion order, merges the
    # layers, and applies the last rule matching both permission and input.
    # This matters when a broad permission key such as "*" appears after a
    # tool-specific rule, or when an agent overrides the project map.
    effective: str | None = None
    matched = False
    for layer in (base_value, agent_value):
        if layer is _PERMISSION_MISSING:
            continue
        if isinstance(layer, str):
            effective = layer
            matched = True
            continue
        if not isinstance(layer, Mapping):
            continue
        for permission_pattern, configured in layer.items():
            if not _permission_wildcard_match(permission_pattern, tool):
                continue
            if isinstance(configured, str):
                effective = configured
                matched = True
                continue
            if not isinstance(configured, Mapping):
                continue
            for input_pattern, action in configured.items():
                if _permission_wildcard_match(input_pattern, input_value):
                    effective = action
                    matched = True
    return effective, matched


def _permission_observation_line(
    status: str,
    profile: str,
    surface: Mapping[str, Any],
    probe: Mapping[str, Any],
    authority: str,
    expected: str,
    actual: str,
    expected_escalation: str,
    reason: str | None = None,
) -> str:
    classes = ",".join(probe["classes"])
    input_digest = hashlib.sha256(probe["input"].encode("utf-8")).hexdigest()
    line = (
        f"{status} profile={profile} surface={surface['id']} "
        f"base_source={surface['base_source']} agent_source={surface['agent_source']} "
        f"classes={classes} boundary={surface['boundary']} authority={authority} "
        f"signals={','.join(surface['signals'])} "
        f"expected={expected} actual={actual} input_sha256={input_digest} "
        f"expected_escalation={expected_escalation}"
    )
    if reason:
        line += f" reason={reason.replace(chr(10), ' ')}"
    return line


def _audit_permission_contract(
    profile: str,
    consumer_root: Path,
    agent_dir: Path,
    documents: Mapping[str, Mapping[str, Any]],
) -> tuple[list[str], Counter[str]]:
    """Audit consumer-owned permission probes against the canonical semantics."""
    lines: list[str] = []
    counts: Counter[str] = Counter()
    bundle_dir = _permission_bundle_dir(profile, agent_dir)
    manifest = bundle_dir / PERMISSION_MANIFEST_NAME

    if not _is_confined_path(bundle_dir, consumer_root):
        lines.append(
            f"DIFF UNEXPECTED_DRIFT profile={profile} permission_manifest={manifest} "
            "reason=manifest_path_not_confined"
        )
        counts["DIFF"] += 1
        return lines, counts
    if manifest.is_symlink():
        lines.append(
            f"DIFF UNEXPECTED_DRIFT profile={profile} permission_manifest={manifest} "
            "reason=manifest_not_regular_or_symlink"
        )
        counts["DIFF"] += 1
        return lines, counts
    if not _is_confined_path(manifest, consumer_root):
        lines.append(
            f"DIFF UNEXPECTED_DRIFT profile={profile} permission_manifest={manifest} "
            "reason=manifest_path_not_confined"
        )
        counts["DIFF"] += 1
        return lines, counts
    manifest_content, manifest_status, manifest_reason = _secure_read_file(
        manifest,
        consumer_root,
    )
    if manifest_status == "missing":
        lines.append(
            f"MISSING UNEXPECTED_DRIFT profile={profile} permission_manifest={manifest} "
            "reason=manifest_missing"
        )
        counts["MISSING"] += 1
        return lines, counts
    if manifest_status != "ok" or manifest_content is None:
        reason = "manifest_not_regular" if manifest_reason == "not_regular" else (
            f"manifest_secure_read_error={manifest_reason or manifest_status}"
        )
        lines.append(
            f"DIFF UNEXPECTED_DRIFT profile={profile} permission_manifest={manifest} "
            f"reason={reason}"
        )
        counts["DIFF"] += 1
        return lines, counts

    try:
        manifest_document = tomllib.loads(manifest_content.decode("utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        lines.append(
            f"DIFF UNEXPECTED_DRIFT profile={profile} permission_manifest={manifest} "
            f"reason=manifest_parse_error={str(exc).replace(chr(10), ' ')}"
        )
        counts["DIFF"] += 1
        return lines, counts

    context, context_errors = _permission_contract_context(profile, documents)
    if context is None:
        reason = ";".join(context_errors)
        lines.append(
            f"DIFF UNEXPECTED_DRIFT profile={profile} permission_manifest={manifest} "
            f"reason=canonical_permission_contract_invalid={reason}"
        )
        counts["DIFF"] += 1
        return lines, counts

    expected_surfaces = _permission_expected_surfaces(profile, documents)
    surfaces, _probes, manifest_errors = _permission_manifest_schema(
        manifest_document,
        profile,
        context["classes"],
        context["mandatory_classes"],
        expected_surfaces,
        context["signals"],
    )
    if manifest_errors:
        reason = ";".join(manifest_errors)
        lines.append(
            f"DIFF UNEXPECTED_DRIFT profile={profile} permission_manifest={manifest} "
            f"reason=manifest_schema_invalid={reason}"
        )
        counts["DIFF"] += 1
        return lines, counts

    signal_errors: list[str] = []
    for surface in surfaces:
        for class_id in context["classes"]:
            escalation = context["operations"][class_id][
                f"{surface['boundary']}_escalation"
            ]
            if escalation in context["signals"] and escalation not in surface["signals"]:
                signal_errors.append(
                    f"surface={surface['id']!r} missing_signal={escalation!r}"
                )
    if signal_errors:
        lines.append(
            f"DIFF UNEXPECTED_DRIFT profile={profile} permission_manifest={manifest} "
            "reason=manifest_signal_invalid=" + ";".join(signal_errors)
        )
        counts["DIFF"] += 1
        return lines, counts

    inventory_errors = _permission_source_inventory_errors(
        profile,
        agent_dir,
        documents,
        surfaces,
    )
    if inventory_errors:
        reason = ";".join(inventory_errors)
        lines.append(
            f"DIFF UNEXPECTED_DRIFT profile={profile} permission_manifest={manifest} "
            f"reason=manifest_source_inventory_invalid={reason}"
        )
        counts["DIFF"] += 1
        return lines, counts

    source_specs: dict[str, str] = {"opencode.json": "json"}
    for surface in surfaces:
        source_specs[surface["agent_source"]] = "agent-frontmatter"
    source_results: dict[str, tuple[str, Any, str | None]] = {}
    for source, source_kind in source_specs.items():
        source_path, source_status, source_reason = _permission_source_path(
            bundle_dir,
            consumer_root,
            source,
        )
        if source_status == "ok" and source_path is not None:
            permission_value, parse_reason, read_status = _permission_read_source(
                source_path,
                consumer_root,
                source_kind,
            )
            if parse_reason:
                source_results[source] = (
                    "missing" if read_status == "missing" else "error",
                    _PERMISSION_MISSING,
                    parse_reason,
                )
            else:
                value_reason = _permission_value_error(permission_value)
                source_results[source] = (
                    "error" if value_reason else "ok",
                    permission_value,
                    value_reason,
                )
        else:
            source_results[source] = (
                source_status,
                _PERMISSION_MISSING,
                source_reason,
            )

    for surface in surfaces:
        boundary = surface["boundary"]
        authority = context["authorities"][boundary]
        operations = context["operations"]
        disposition_rank = context["disposition_rank"]
        escalation_rank = context["escalation_rank"]
        for probe in surface["probes"]:
            expected_dispositions = [
                operations[class_id][f"{boundary}_disposition"]
                for class_id in probe["classes"]
            ]
            expected_escalations = [
                operations[class_id][f"{boundary}_escalation"]
                for class_id in probe["classes"]
            ]
            expected = max(expected_dispositions, key=disposition_rank.__getitem__)
            expected_escalation = max(
                expected_escalations,
                key=escalation_rank.__getitem__,
            )

            base_status, base_value, base_reason = source_results[surface["base_source"]]
            agent_status, agent_value, agent_reason = source_results[surface["agent_source"]]
            if base_status != "ok" or agent_status != "ok":
                source_status = (
                    "missing"
                    if "missing" in {base_status, agent_status}
                    else "error"
                )
                source_reason = ";".join(
                    reason
                    for reason in (
                        f"base_source={base_reason}" if base_reason else None,
                        f"agent_source={agent_reason}" if agent_reason else None,
                    )
                    if reason
                )
                status = "MISSING UNEXPECTED_DRIFT" if source_status == "missing" else "DIFF UNEXPECTED_DRIFT"
                actual = "unavailable" if source_status == "missing" else "invalid_source"
                lines.append(
                    _permission_observation_line(
                        status,
                        profile,
                        surface,
                        probe,
                        authority,
                        expected,
                        actual,
                        expected_escalation,
                        source_reason,
                    )
                )
                counts["MISSING" if source_status == "missing" else "DIFF"] += 1
                continue

            actual, matched = _permission_effective_action(
                base_value,
                agent_value,
                probe["tool"],
                probe["input"],
            )
            if not matched:
                lines.append(
                    _permission_observation_line(
                        "DIFF UNEXPECTED_DRIFT",
                        profile,
                        surface,
                        probe,
                        authority,
                        expected,
                        "unproven",
                        expected_escalation,
                        "implicit_default",
                    )
                )
                counts["DIFF"] += 1
            elif actual == expected:
                lines.append(
                    _permission_observation_line(
                        "PASS",
                        profile,
                        surface,
                        probe,
                        authority,
                        expected,
                        actual,
                        expected_escalation,
                    )
                )
                counts["PASS"] += 1
            else:
                lines.append(
                    _permission_observation_line(
                        "DIFF UNEXPECTED_DRIFT",
                        profile,
                        surface,
                        probe,
                        authority,
                        expected,
                        actual,
                        expected_escalation,
                        "permission_action_mismatch",
                    )
                )
                counts["DIFF"] += 1
    return lines, counts


def _audit_local_workers(
    consumer_root: Path,
    documents: Mapping[str, Mapping[str, Any]],
) -> tuple[list[str], Counter[str]]:
    """Audit one atomic Global bundle; never search repository-local layers."""
    agent_dir = _profile_agent_dir("global", consumer_root)
    if not _is_confined_path(agent_dir, consumer_root):
        return [], Counter()
    manifest = agent_dir.parent / "local-workers.toml"
    if manifest.is_symlink():
        return ["DIFF UNEXPECTED_DRIFT local_workers=manifest_not_regular"], Counter(DIFF=1)

    manifest_content, manifest_status, manifest_reason = _secure_read_file(
        manifest,
        consumer_root,
    )
    if manifest_status == "missing":
        return ["PASS local_workers=absent"], Counter(PASS=1)
    if manifest_status != "ok" or manifest_content is None:
        reason = "manifest_not_regular" if manifest_reason == "not_regular" else (
            f"manifest_secure_read_error={manifest_reason or manifest_status}"
        )
        return [f"DIFF UNEXPECTED_DRIFT local_workers={reason}"], Counter(DIFF=1)

    try:
        doc = tomllib.loads(manifest_content.decode("utf-8"))
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
    if config_path.is_symlink():
        errors.append("opencode_json_missing_or_not_regular")
    else:
        config_content, config_status, _config_reason = _secure_read_file(
            config_path,
            consumer_root,
        )
        if config_status != "ok" or config_content is None:
            errors.append("opencode_json_invalid")
        else:
            try:
                config = json.loads(config_content.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
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
        frontmatter = parse_frontmatter(agent, consumer_root)
        if frontmatter.get("mode") != worker_policy["mode"] or frontmatter.get("hidden") is not worker_policy["hidden"]:
            errors.append(f"agent_{worker}_visibility_or_mode")
        if frontmatter.get("model") != binding or frontmatter.get("model") in canonical_models:
            errors.append(f"agent_{worker}_binding")
        if _frontmatter_permissions(agent, consumer_root) != required_permissions:
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

    permission_lines, permission_counts = _audit_permission_contract(
        profile,
        consumer_root,
        agent_dir,
        documents,
    )
    lines.extend(permission_lines)
    counts.update(permission_counts)

    if not agent_dir.is_dir():
        lines.append(f"MISSING UNEXPECTED_DRIFT profile={profile} agent_directory={agent_dir}")
        counts["MISSING"] += 1
        return lines, counts

    expected_roles = {role_id for role_id, role in roles.items() if profile in role["profiles"]}
    agent_markdown, unsafe_inventory_paths = _agent_inventory(agent_dir, consumer_root)
    if profile == "global":
        for path in unsafe_inventory_paths:
            identity = _agent_identity(agent_dir, path)
            if path.parent == agent_dir and identity in expected_roles:
                # The canonical flat-path check below owns this diagnostic.
                continue
            lines.append(
                f"DIFF UNEXPECTED_DRIFT profile={profile} agent={identity} "
                "unsafe_path=forbidden"
            )
            counts["DIFF"] += 1

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
            primary = parse_frontmatter(primary_path, consumer_root)
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

    fallback_residue = [path for path in agent_markdown if path.name.endswith("-fallback.md")]
    unsafe_fallback_residue = [
        path for path in unsafe_inventory_paths
        if path.suffix == ".md" and path.name.endswith("-fallback.md")
    ]
    if fallback_residue or unsafe_fallback_residue:
        for path in fallback_residue:
            lines.append(
                f"DIFF UNEXPECTED_DRIFT profile={profile} agent={_agent_identity(agent_dir, path)} "
                "fallback_residue=forbidden"
            )
            counts["DIFF"] += 1
        if profile != "global":
            for path in unsafe_fallback_residue:
                lines.append(
                    f"DIFF UNEXPECTED_DRIFT profile={profile} agent={_agent_identity(agent_dir, path)} "
                    "unsafe_path=forbidden"
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
        for path in agent_markdown:
            identity = _agent_identity(agent_dir, path)
            if identity not in registered_agents and not path.name.endswith("-fallback.md"):
                lines.append(
                    f"DIFF UNEXPECTED_DRIFT profile={profile} agent={identity} "
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
