#!/usr/bin/env python3
"""Validate the OpenCode shared policy contract using only the standard library."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
POLICY_FILES = {
    "models": Path("policy/models.toml"),
    "roles": Path("policy/roles.toml"),
    "model-availability": Path("policy/model-availability.toml"),
    "invariants": Path("policy/invariants.toml"),
    "optional-workers": Path("policy/optional-workers.toml"),
    "permission-semantics": Path("policy/permission-semantics.toml"),
    "global": Path("profiles/global.toml"),
    "agent-core": Path("profiles/agent-core.toml"),
}
MODEL_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._:-]*$")
VALID_CLASSIFICATIONS = {"COMMON", "GLOBAL_ONLY", "AGENT_CORE_ONLY", "PROFILE_VARIANT"}
VALID_KINDS = {"primary", "subagent"}

PERMISSION_TOP_LEVEL_KEYS = {
    "schema_version", "contract", "authorities", "profile_bindings",
    "operation_classes", "signals",
}
PERMISSION_POLICY_LOCATION = "policy/permission-semantics"
PERMISSION_PROFILES = ("global", "agent-core")
PERMISSION_AUTHORITIES = ("approval-capable-parent", "non-interactive-leaf")
PERMISSION_OPERATION_CLASSES = (
    "safe-read-only",
    "local-filesystem-delete",
    "repository-history-destruction",
    "remote-destructive-operation",
    "privilege-escalation",
    "system-store-destruction",
)
PERMISSION_DISPOSITIONS = ("allow", "ask", "deny")
PERMISSION_ESCALATIONS = ("none", "NEEDS_APPROVAL", "BLOCKED")

PERMISSION_CONTRACT_KEYS = {
    "id", "closed_world", "profiles", "authorities", "operation_classes",
    "dispositions", "escalation_outcomes", "unknown_operation_class",
    "allow_requires_configured_role_permission", "unknown_profile",
    "unknown_authority", "out_of_authority",
}
PERMISSION_CONTRACT_VALUES = {
    "id": "permission-semantics",
    "closed_world": True,
    "profiles": list(PERMISSION_PROFILES),
    "authorities": list(PERMISSION_AUTHORITIES),
    "operation_classes": list(PERMISSION_OPERATION_CLASSES),
    "dispositions": list(PERMISSION_DISPOSITIONS),
    "escalation_outcomes": list(PERMISSION_ESCALATIONS),
    "allow_requires_configured_role_permission": True,
    "unknown_operation_class": "BLOCKED",
    "unknown_profile": "BLOCKED",
    "unknown_authority": "BLOCKED",
    "out_of_authority": "BLOCKED",
}

PERMISSION_AUTHORITY_VALUES = {
    "approval-capable-parent": {
        "interactive": True,
        "can_ask": True,
        "can_execute_non_escalated": True,
        "can_execute_approval_required": True,
        "can_execute_denied": False,
        "can_mutate_permissions": False,
        "can_bypass": False,
        "independent_reevaluation": True,
        "relay_leaf_request": False,
        "auto_approve_escalation": False,
    },
    "non-interactive-leaf": {
        "interactive": False,
        "can_ask": False,
        "can_execute_non_escalated": True,
        "can_execute_approval_required": False,
        "can_execute_denied": False,
        "can_mutate_permissions": False,
        "can_bypass": False,
        "independent_reevaluation": False,
        "relay_leaf_request": False,
        "auto_approve_escalation": False,
        "escalation_behavior": "return-outcome-to-parent",
    },
}
PERMISSION_AUTHORITY_KEYS = {
    authority: set(values)
    for authority, values in PERMISSION_AUTHORITY_VALUES.items()
}
PERMISSION_PROFILE_BINDING_KEYS = {"profile", "parent_authority", "leaf_authority"}

PERMISSION_OPERATION_VALUES = {
    "safe-read-only": {
        "id": "safe-read-only",
        "parent_disposition": "allow",
        "leaf_disposition": "allow",
        "parent_escalation": "none",
        "leaf_escalation": "none",
        "mutation_scope": "read-only",
        "bounded": True,
        "structural": False,
        "destructive": False,
    },
    "local-filesystem-delete": {
        "id": "local-filesystem-delete",
        "parent_disposition": "ask",
        "leaf_disposition": "deny",
        "parent_escalation": "none",
        "leaf_escalation": "NEEDS_APPROVAL",
        "mutation_scope": "bounded-local",
        "bounded": True,
        "structural": False,
        "destructive": True,
        "exact_target_required": True,
    },
    "repository-history-destruction": {
        "id": "repository-history-destruction",
        "parent_disposition": "deny",
        "leaf_disposition": "deny",
        "parent_escalation": "BLOCKED",
        "leaf_escalation": "BLOCKED",
        "mutation_scope": "repository-structural",
        "bounded": False,
        "structural": True,
        "destructive": True,
        "irreversible": True,
        "exact_target_required": True,
    },
    "remote-destructive-operation": {
        "id": "remote-destructive-operation",
        "parent_disposition": "deny",
        "leaf_disposition": "deny",
        "parent_escalation": "BLOCKED",
        "leaf_escalation": "BLOCKED",
        "mutation_scope": "remote-structural",
        "bounded": False,
        "structural": True,
        "destructive": True,
        "irreversible": True,
        "exact_target_required": True,
    },
    "privilege-escalation": {
        "id": "privilege-escalation",
        "parent_disposition": "deny",
        "leaf_disposition": "deny",
        "parent_escalation": "BLOCKED",
        "leaf_escalation": "BLOCKED",
        "mutation_scope": "authority-change",
        "bounded": False,
        "structural": False,
        "destructive": False,
        "permission_mutation": True,
    },
    "system-store-destruction": {
        "id": "system-store-destruction",
        "parent_disposition": "deny",
        "leaf_disposition": "deny",
        "parent_escalation": "BLOCKED",
        "leaf_escalation": "BLOCKED",
        "mutation_scope": "system-structural",
        "bounded": False,
        "structural": True,
        "destructive": True,
        "irreversible": True,
        "exact_target_required": True,
    },
}
PERMISSION_OPERATION_KEYS = {
    operation: set(values)
    for operation, values in PERMISSION_OPERATION_VALUES.items()
}
PERMISSION_OPERATION_ALL_KEYS = set().union(*PERMISSION_OPERATION_KEYS.values())

PERMISSION_SIGNAL_VALUES = {
    "NEEDS_APPROVAL": {
        "kind": "permission-escalation",
        "interactive_boundary": "approval-capable-parent",
        "terminal": False,
        "leaf_direct_ask": False,
        "leaf_direct_execution": False,
        "leaf_permission_mutation": False,
        "permission_bypass": False,
        "parent_independent_reevaluation": True,
        "parent_relay": False,
        "parent_auto_approve": False,
        "leaf_executes_denied_operation": False,
        "out_of_authority": "BLOCKED",
        "user_rejection": "final-for-exact-operation-within-task",
        "rejection_bypass_methods_forbidden": [
            "retry",
            "rephrase",
            "redelegation",
            "equivalent-substitute",
        ],
        "required_evidence": [
            "operation_class",
            "operation_identity",
            "scope",
            "purpose",
            "evidence",
            "least_privilege",
            "safe_alternatives",
            "configured_authority",
        ],
    },
    "NEEDS_DECISION": {
        "kind": "requirements-product-or-architecture-ambiguity",
        "interactive_boundary": "only-when-human-judgment-required",
        "terminal": False,
        "permission_approval_resolves": False,
        "parent_must_resolve_from_contract_or_evidence": True,
        "leaf_direct_ask": False,
        "permission_denial_resolution": "not-an-approval-path",
        "required_evidence": [
            "ambiguity",
            "known_evidence",
            "requirements_or_product_or_architecture",
            "options",
            "recommendation",
        ],
    },
}
PERMISSION_SIGNAL_KEYS = {
    signal: set(values)
    for signal, values in PERMISSION_SIGNAL_VALUES.items()
}


def load_policy(root: Path = ROOT) -> tuple[dict[str, dict[str, Any]], list[str]]:
    documents: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for name, relative in POLICY_FILES.items():
        path = root / relative
        try:
            with path.open("rb") as handle:
                documents[name] = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            errors.append(f"{relative}: {exc}")
    return documents, errors


def _literal_model_ids(value: Any, location: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            found.extend(_literal_model_ids(child, f"{location}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_literal_model_ids(child, f"{location}[{index}]"))
    elif isinstance(value, str) and MODEL_ID.fullmatch(value):
        found.append(location)
    return found


def _permission_check_keys(
    value: Any,
    expected: set[str],
    location: str,
    errors: list[str],
) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{location}: must be a table")
        return False
    unknown = set(value) - expected
    missing = expected - set(value)
    if unknown:
        errors.append(f"{location}: unknown fields {sorted(unknown)}")
    if missing:
        errors.append(f"{location}: missing fields {sorted(missing)}")
    return True


def _permission_check_values(
    value: dict[str, Any],
    expected: dict[str, Any],
    location: str,
    errors: list[str],
) -> None:
    for field, expected_value in expected.items():
        if field not in value:
            continue
        actual = value[field]
        if type(actual) is not type(expected_value) or actual != expected_value:
            errors.append(f"{location}.{field}: must be {expected_value!r}")


def _permission_check_reference_list(
    value: dict[str, Any],
    field: str,
    allowed: tuple[str, ...],
    reference_name: str,
    location: str,
    errors: list[str],
) -> None:
    references = value.get(field)
    if field not in value or not isinstance(references, list):
        return
    for reference in references:
        if not isinstance(reference, str) or reference not in allowed:
            errors.append(
                f"{location}.{field}: unknown {reference_name} {reference!r}"
            )


def _permission_check_operation_semantics(
    operation: dict[str, Any],
    location: str,
    errors: list[str],
) -> None:
    disposition_fields = ("parent_disposition", "leaf_disposition")
    escalation_fields = ("parent_escalation", "leaf_escalation")
    for field in disposition_fields:
        if field in operation:
            disposition = operation[field]
            if not isinstance(disposition, str) or disposition not in PERMISSION_DISPOSITIONS:
                errors.append(f"{location}.{field}: unknown disposition {disposition!r}")
    for field in escalation_fields:
        if field in operation:
            escalation = operation[field]
            if not isinstance(escalation, str) or escalation not in PERMISSION_ESCALATIONS:
                errors.append(f"{location}.{field}: unknown escalation {escalation!r}")

    valid_pairs = {
        ("allow", "none"),
        ("ask", "none"),
        ("deny", "NEEDS_APPROVAL"),
        ("deny", "BLOCKED"),
    }
    for disposition_field, escalation_field in zip(disposition_fields, escalation_fields):
        if disposition_field not in operation or escalation_field not in operation:
            continue
        disposition = operation[disposition_field]
        escalation = operation[escalation_field]
        if isinstance(disposition, str) and isinstance(escalation, str):
            if disposition in PERMISSION_DISPOSITIONS and escalation in PERMISSION_ESCALATIONS:
                if (disposition, escalation) not in valid_pairs:
                    errors.append(
                        f"{location}: contradictory {disposition_field}/"
                        f"{escalation_field} combination"
                    )

    if operation.get("structural") is True:
        for field in disposition_fields:
            if operation.get(field) == "allow" or operation.get(field) == "ask":
                errors.append(f"{location}.{field}: structural operations must deny")
        for field in escalation_fields:
            if operation.get(field) != "BLOCKED":
                errors.append(f"{location}.{field}: structural operations must be BLOCKED")

    if operation.get("destructive") is True or operation.get("permission_mutation") is True:
        for field in disposition_fields:
            if operation.get(field) == "allow":
                errors.append(f"{location}.{field}: destructive or permission-mutating operations cannot allow")

    if operation.get("id") != "safe-read-only":
        for disposition_field, escalation_field in zip(disposition_fields, escalation_fields):
            if operation.get(disposition_field) == "allow" and operation.get(escalation_field) == "none":
                errors.append(
                    f"{location}: silent allow is only valid for safe-read-only"
                )


def _validate_permission_semantics(document: Any, errors: list[str]) -> None:
    if not _permission_check_keys(document, PERMISSION_TOP_LEVEL_KEYS, PERMISSION_POLICY_LOCATION, errors):
        return

    contract = document.get("contract")
    contract_location = f"{PERMISSION_POLICY_LOCATION}.contract"
    if _permission_check_keys(contract, PERMISSION_CONTRACT_KEYS, contract_location, errors):
        _permission_check_values(
            contract, PERMISSION_CONTRACT_VALUES, contract_location, errors
        )
        _permission_check_reference_list(
            contract, "profiles", PERMISSION_PROFILES, "profile", contract_location, errors
        )
        _permission_check_reference_list(
            contract, "authorities", PERMISSION_AUTHORITIES, "authority", contract_location, errors
        )
        _permission_check_reference_list(
            contract,
            "operation_classes",
            PERMISSION_OPERATION_CLASSES,
            "operation class",
            contract_location,
            errors,
        )
        _permission_check_reference_list(
            contract,
            "dispositions",
            PERMISSION_DISPOSITIONS,
            "disposition",
            contract_location,
            errors,
        )
        _permission_check_reference_list(
            contract,
            "escalation_outcomes",
            PERMISSION_ESCALATIONS,
            "escalation outcome",
            contract_location,
            errors,
        )

    authorities = document.get("authorities")
    if isinstance(authorities, dict):
        _permission_check_keys(
            authorities,
            set(PERMISSION_AUTHORITY_VALUES),
            f"{PERMISSION_POLICY_LOCATION}.authorities",
            errors,
        )
        for authority in authorities:
            if authority not in PERMISSION_AUTHORITY_VALUES:
                errors.append(
                    f"{PERMISSION_POLICY_LOCATION}.authorities: unknown authority {authority!r}"
                )
        for authority, expected in PERMISSION_AUTHORITY_VALUES.items():
            definition = authorities.get(authority)
            location = f"{PERMISSION_POLICY_LOCATION}.authorities.{authority}"
            if _permission_check_keys(definition, PERMISSION_AUTHORITY_KEYS[authority], location, errors):
                _permission_check_values(definition, expected, location, errors)
    else:
        _permission_check_keys(
            authorities,
            set(PERMISSION_AUTHORITY_VALUES),
            f"{PERMISSION_POLICY_LOCATION}.authorities",
            errors,
        )

    bindings = document.get("profile_bindings")
    if not isinstance(bindings, list):
        errors.append(f"{PERMISSION_POLICY_LOCATION}.profile_bindings: must be an array of tables")
    else:
        if len(bindings) != len(PERMISSION_PROFILES):
            errors.append(
                f"{PERMISSION_POLICY_LOCATION}.profile_bindings: exactly two entries are required"
            )
        seen_profiles: set[str] = set()
        expected_bindings = {
            "global": {
                "profile": "global",
                "parent_authority": "approval-capable-parent",
                "leaf_authority": "non-interactive-leaf",
            },
            "agent-core": {
                "profile": "agent-core",
                "parent_authority": "approval-capable-parent",
                "leaf_authority": "non-interactive-leaf",
            },
        }
        for index, binding in enumerate(bindings):
            location = f"{PERMISSION_POLICY_LOCATION}.profile_bindings[{index}]"
            if not _permission_check_keys(binding, PERMISSION_PROFILE_BINDING_KEYS, location, errors):
                continue
            profile = binding.get("profile")
            if not isinstance(profile, str) or profile not in PERMISSION_PROFILES:
                errors.append(f"{location}.profile: unknown profile {profile!r}")
                continue
            if profile in seen_profiles:
                errors.append(f"{location}.profile: duplicate profile {profile!r}")
            seen_profiles.add(profile)
            _permission_check_values(binding, expected_bindings[profile], location, errors)
            for field in ("parent_authority", "leaf_authority"):
                reference = binding.get(field)
                if not isinstance(reference, str) or reference not in PERMISSION_AUTHORITIES:
                    errors.append(f"{location}.{field}: unknown authority {reference!r}")
        missing_profiles = set(PERMISSION_PROFILES) - seen_profiles
        if missing_profiles:
            errors.append(
                f"{PERMISSION_POLICY_LOCATION}.profile_bindings: missing profiles {sorted(missing_profiles)}"
            )

    operation_classes = document.get("operation_classes")
    if not isinstance(operation_classes, list):
        errors.append(f"{PERMISSION_POLICY_LOCATION}.operation_classes: must be an array of tables")
    else:
        if len(operation_classes) != len(PERMISSION_OPERATION_CLASSES):
            errors.append(
                f"{PERMISSION_POLICY_LOCATION}.operation_classes: exactly six entries are required"
            )
        seen_operations: set[str] = set()
        for index, operation in enumerate(operation_classes):
            location = f"{PERMISSION_POLICY_LOCATION}.operation_classes[{index}]"
            if not isinstance(operation, dict):
                errors.append(f"{location}: must be a table")
                continue
            operation_id = operation.get("id")
            if not isinstance(operation_id, str):
                errors.append(f"{location}.id: unknown operation class {operation_id!r}")
                _permission_check_keys(operation, PERMISSION_OPERATION_ALL_KEYS, location, errors)
                continue
            if operation_id not in PERMISSION_OPERATION_VALUES:
                errors.append(f"{location}.id: unknown operation class {operation_id!r}")
                _permission_check_keys(operation, PERMISSION_OPERATION_ALL_KEYS, location, errors)
                continue
            if operation_id in seen_operations:
                errors.append(f"{location}.id: duplicate operation class {operation_id!r}")
            seen_operations.add(operation_id)
            expected = PERMISSION_OPERATION_VALUES[operation_id]
            operation_location = f"{location}.{operation_id}"
            if _permission_check_keys(
                operation, PERMISSION_OPERATION_KEYS[operation_id], operation_location, errors
            ):
                _permission_check_values(operation, expected, operation_location, errors)
            _permission_check_operation_semantics(operation, operation_location, errors)
        missing_operations = set(PERMISSION_OPERATION_CLASSES) - seen_operations
        if missing_operations:
            errors.append(
                f"{PERMISSION_POLICY_LOCATION}.operation_classes: missing classes {sorted(missing_operations)}"
            )

    signals = document.get("signals")
    if isinstance(signals, dict):
        signal_location = f"{PERMISSION_POLICY_LOCATION}.signals"
        _permission_check_keys(signals, set(PERMISSION_SIGNAL_VALUES), signal_location, errors)
        for signal in signals:
            if signal not in PERMISSION_SIGNAL_VALUES:
                errors.append(f"{signal_location}: unknown signal {signal!r}")
        for signal, expected in PERMISSION_SIGNAL_VALUES.items():
            definition = signals.get(signal)
            location = f"{signal_location}.{signal}"
            if _permission_check_keys(definition, PERMISSION_SIGNAL_KEYS[signal], location, errors):
                _permission_check_values(definition, expected, location, errors)
    else:
        _permission_check_keys(
            signals,
            set(PERMISSION_SIGNAL_VALUES),
            f"{PERMISSION_POLICY_LOCATION}.signals",
            errors,
        )


def validate_policy(root: Path = ROOT) -> list[str]:
    docs, errors = load_policy(root)
    if errors:
        return errors

    for name, doc in docs.items():
        if type(doc.get("schema_version")) is not int or doc["schema_version"] != 1:
            errors.append(f"{POLICY_FILES[name]}: schema_version must be 1")

    _validate_permission_semantics(docs["permission-semantics"], errors)

    optional = docs["optional-workers"]
    expected_optional = {
        "contract": {
            "profile": "global",
            "phase": 1,
            "presence": "optional",
            "enabled_by_default": False,
            "authority": "nonauthoritative-read-only-advisory",
            "opt_in": "explicit-manual",
            "dispatch": "manual-or-shadow",
            "runtime_enforcement": "procedural-parent-control",
            "static_audit_guarantee": "declarations-and-configuration-only",
            "canonical_substitution": "forbidden",
            "automatic_model_fallback": "forbidden",
            "fallback": "none",
            "failure_result": "BLOCKED",
            "max_in_flight": 1,
            "retry_limit": 1,
            "max_attempts": 2,
            "required_tools": ["read", "grep"],
            "retry_eligibility": "normal_successful_response_with_required_tool_call_count_0",
            "retry_model_policy": "same_agent_same_model_only",
            "retry_binding": "same-objective-agent-provider-model-and-required-tool",
            "retry_exclusions": [
                "api_failure", "runtime_failure", "model_failure", "permission_failure",
                "schema_failure", "wrong_evidence", "blocked_response", "approval_or_decision",
                "non_normal_response", "required_tool_call_count_gt_0",
            ],
        },
        "workers": {
            "allowed": ["local-investigator", "local-tracer", "local-background"],
            "role": "read-only advisory", "canonical": False, "hidden": True, "mode": "subagent",
        },
        "permissions": {
            "default": "deny", "allowed": ["read", "grep"],
            "explicitly_denied": [
                "glob", "list", "lsp", "bash", "edit", "task", "question", "webfetch",
                "websearch", "skill", "todowrite", "external_directory", "doom_loop",
            ],
        },
        "evidence": {
            "validation_owner": "parent",
            "tool_call_count_source": "parent-observed-session-events",
            "worker_output_trust": "untrusted",
            "required_fields": ["path", "line_or_range", "snippet", "mechanism", "confidence", "unverified_areas"],
            "wrong_or_unsupported_result": "BLOCKED",
            "wrong_or_unsupported_retry": False,
        },
        "metrics": {
            "counters": [
                "local_task_total", "local_task_completed", "local_task_rejected",
                "local_task_retried", "local_tool_required_miss", "local_wrong_answer_detected",
                "local_runtime_failure",
            ],
            "optional_observations": ["local_task_latency_ms", "local_input_tokens", "local_output_tokens"],
            "metadata": [
                "attempts", "retry_reason", "worker", "configured_model", "required_tool",
                "required_tool_call_count", "failure_class",
            ],
            "forbidden_content": ["prompt_text", "file_content", "tool_output"],
        },
    }
    expected_top = {"schema_version", *expected_optional}
    if set(optional) != expected_top:
        errors.append(f"policy/optional-workers.toml: top-level keys must be exactly {sorted(expected_top)}")
    for section, expected in expected_optional.items():
        actual = optional.get(section)
        if not isinstance(actual, dict):
            errors.append(f"optional-workers.{section}: must be a table")
            continue
        unknown = set(actual) - set(expected)
        missing = set(expected) - set(actual)
        if unknown:
            errors.append(f"optional-workers.{section}: unknown fields {sorted(unknown)}")
        if missing:
            errors.append(f"optional-workers.{section}: missing fields {sorted(missing)}")
        for field, value in expected.items():
            if field in actual and (type(actual[field]) is not type(value) or actual[field] != value):
                errors.append(f"optional-workers.{section}.{field}: must be {value!r}")

    models = docs["models"].get("models", {})
    families = docs["models"].get("quota_families", {})
    if not isinstance(models, dict):
        errors.append("policy/models.toml: models must be a table")
        models = {}
    if not isinstance(families, dict):
        errors.append("policy/models.toml: quota_families must be a table")
        families = {}
    if not models or not families:
        errors.append("policy/models.toml: models and quota_families are required")
    seen_model_ids: dict[str, str] = {}
    for alias, model in models.items():
        if not isinstance(model, dict):
            errors.append(f"models.{alias}: model definition must be a table")
            continue
        model_id = model.get("id")
        family = model.get("quota_family")
        if not isinstance(model_id, str) or not MODEL_ID.fullmatch(model_id):
            errors.append(f"models.{alias}: malformed model id {model_id!r}")
        elif model_id in seen_model_ids:
            errors.append(f"models.{alias}: duplicate model id also used by {seen_model_ids[model_id]}")
        else:
            seen_model_ids[model_id] = alias
        if family not in families:
            errors.append(f"models.{alias}: unknown quota family {family!r}")
    models = {alias: model for alias, model in models.items() if isinstance(model, dict)}

    profiles = {"global", "agent-core"}
    roles = docs["roles"].get("roles", {})
    if not isinstance(roles, dict):
        errors.append("policy/roles.toml: roles must be a table")
        roles = {}
    for role_id, role in roles.items():
        if not isinstance(role, dict):
            errors.append(f"roles.{role_id}: role definition must be a table")
            continue
        classification = role.get("classification")
        applicable = role.get("profiles")
        if classification not in VALID_CLASSIFICATIONS:
            errors.append(f"roles.{role_id}: invalid classification {classification!r}")
        if role.get("kind") not in VALID_KINDS:
            errors.append(f"roles.{role_id}: kind must be primary or subagent")
        if not isinstance(applicable, list) or not applicable:
            errors.append(f"roles.{role_id}: non-empty profiles list is required")
            applicable = []
        unknown = set(applicable) - profiles
        if unknown:
            errors.append(f"roles.{role_id}: unknown profiles {sorted(unknown)}")
        if classification == "COMMON" and set(applicable) != profiles:
            errors.append(f"roles.{role_id}: COMMON roles must apply to both profiles")
        if classification == "GLOBAL_ONLY" and set(applicable) != {"global"}:
            errors.append(f"roles.{role_id}: GLOBAL_ONLY role has inconsistent applicability")
        if classification == "AGENT_CORE_ONLY" and set(applicable) != {"agent-core"}:
            errors.append(f"roles.{role_id}: AGENT_CORE_ONLY role has inconsistent applicability")
    roles = {role_id: role for role_id, role in roles.items() if isinstance(role, dict)}

    assignments: dict[str, dict[str, Any]] = {}
    for profile_id in sorted(profiles):
        profile_doc = docs[profile_id]
        metadata = profile_doc.get("profile", {})
        if not isinstance(metadata, dict):
            errors.append(f"profiles/{profile_id}.toml: profile must be a table")
            metadata = {}
        if metadata.get("id") != profile_id:
            errors.append(f"profiles/{profile_id}.toml: profile.id must equal {profile_id!r}")
        if not metadata.get("implementation_owner") or not metadata.get("layer"):
            errors.append(f"profiles/{profile_id}.toml: implementation_owner and layer are required")
        if not isinstance(metadata.get("invariants"), list) or not metadata["invariants"]:
            errors.append(f"profiles/{profile_id}.toml: invariants are required")
        assignments[profile_id] = profile_doc.get("assignments", {})
        if not isinstance(assignments[profile_id], dict):
            errors.append(f"profiles/{profile_id}.toml: assignments must be a table")
            assignments[profile_id] = {}
        for role_id, assignment in assignments[profile_id].items():
            if not isinstance(assignment, dict):
                errors.append(f"profiles/{profile_id}.toml assignments.{role_id}: must be a table")
                continue
            if role_id not in roles:
                errors.append(f"profiles/{profile_id}.toml: unknown role {role_id!r}")
                continue
            if profile_id not in roles[role_id].get("profiles", []):
                errors.append(f"profiles/{profile_id}.toml: role {role_id!r} is not applicable")
            unknown_assignment_fields = set(assignment) - {"primary_model", "authority"}
            if unknown_assignment_fields:
                errors.append(
                    f"profiles/{profile_id}.toml assignments.{role_id}: unsupported fields "
                    f"{sorted(unknown_assignment_fields)}"
                )
            if assignment.get("primary_model") not in models:
                errors.append(
                    f"profiles/{profile_id}.toml assignments.{role_id}: unknown model "
                    f"{assignment.get('primary_model')!r}"
                )
            if not assignment.get("authority"):
                errors.append(f"profiles/{profile_id}.toml assignments.{role_id}: authority is required")
        assignments[profile_id] = {
            role_id: assignment
            for role_id, assignment in assignments[profile_id].items()
            if isinstance(assignment, dict)
        }
        expected = {role_id for role_id, role in roles.items() if profile_id in role.get("profiles", [])}
        missing = expected - set(assignments[profile_id])
        extra = set(assignments[profile_id]) - expected
        if missing:
            errors.append(f"profiles/{profile_id}.toml: missing role assignments {sorted(missing)}")
        if extra:
            errors.append(f"profiles/{profile_id}.toml: inapplicable role assignments {sorted(extra)}")

    availability_doc = docs["model-availability"]
    unknown_availability_sections = set(availability_doc) - {"schema_version", "policy"}
    if unknown_availability_sections:
        errors.append(
            "policy/model-availability.toml: unknown top-level keys "
            f"{sorted(unknown_availability_sections)}"
        )

    availability = availability_doc.get("policy", {})
    if not isinstance(availability, dict):
        errors.append("model-availability.policy: must be a table")
        availability = {}
    required_availability = {
        "model_substitution": "forbidden",
        "alternate_model_retry": "forbidden",
        "unavailable_result": "BLOCKED",
        "report_exact_provider_model_failure": True,
        "fallback_agents": "forbidden",
    }
    unknown_availability_fields = set(availability) - set(required_availability)
    if unknown_availability_fields:
        errors.append(
            "model-availability.policy: unknown fields "
            f"{sorted(unknown_availability_fields)}"
        )
    for field, expected in required_availability.items():
        if field not in availability:
            errors.append(f"model-availability.policy.{field}: required field is missing")
        elif type(availability[field]) is not type(expected) or availability[field] != expected:
            errors.append(
                f"model-availability.policy.{field}: must be {expected!r}"
            )

    semantic_ids: dict[str, str] = {}
    difference_targets: set[tuple[str, str]] = set()
    for section in ("invariants", "intentional_differences"):
        entries = docs["invariants"].get(section, [])
        if not isinstance(entries, list):
            errors.append(f"policy/invariants.toml: {section} must be an array of tables")
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                errors.append(f"policy/invariants.toml: {section} entries must be tables")
                continue
            semantic_id = entry.get("id")
            if not isinstance(semantic_id, str) or not semantic_id:
                errors.append(f"policy/invariants.toml: {section} entry requires id")
            elif semantic_id in semantic_ids:
                errors.append(f"policy/invariants.toml: duplicate semantic id {semantic_id!r}")
            else:
                semantic_ids[semantic_id] = section
            if section == "invariants" and (entry.get("scope") not in {"common", *profiles} or not entry.get("statement")):
                errors.append(f"invariants.{semantic_id}: scope and statement are required")
            if section == "intentional_differences":
                role_id = entry.get("role")
                field = entry.get("field")
                if role_id not in roles:
                    errors.append(f"intentional_differences.{semantic_id}: unknown role {role_id!r}")
                    continue
                if roles[role_id].get("classification") != "COMMON":
                    errors.append(f"intentional_differences.{semantic_id}: role must be COMMON")
                if field not in {"primary_model", "authority"}:
                    errors.append(f"intentional_differences.{semantic_id}: unsupported field {field!r}")
                    continue
                target = (role_id, field)
                if target in difference_targets:
                    errors.append(
                        f"intentional_differences.{semantic_id}: duplicate role/field declaration {target!r}"
                    )
                difference_targets.add(target)
                values = [assignments[profile_id].get(role_id, {}).get(field) for profile_id in sorted(profiles)]
                if any(value is None for value in values):
                    errors.append(
                        f"intentional_differences.{semantic_id}: field {field!r} must resolve in both profiles"
                    )
                elif values[0] == values[1]:
                    errors.append(
                        f"intentional_differences.{semantic_id}: declared field does not differ between profiles"
                    )
                forbidden_value_keys = {"global", "agent-core", "classification"} & set(entry)
                if forbidden_value_keys:
                    errors.append(
                        f"intentional_differences.{semantic_id}: canonical values must not be duplicated "
                        f"({sorted(forbidden_value_keys)})"
                    )

    for name, doc in docs.items():
        if name == "models":
            continue
        for location in _literal_model_ids(doc, name):
            errors.append(f"{location}: provider model literal is only allowed in policy/models.toml")
    return errors


def main() -> int:
    errors = validate_policy(ROOT)
    if errors:
        for error in errors:
            print(f"ERROR {error}", file=sys.stderr)
        print(f"INVALID ({len(errors)} error(s))", file=sys.stderr)
        return 1
    print("VALID policy contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
