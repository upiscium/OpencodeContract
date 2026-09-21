from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from audit_consumers import audit  # noqa: E402
from policy_audit import audit_profile, result_exit_code  # noqa: E402
from validate_policy import load_policy, validate_policy  # noqa: E402


PERMISSION_CLASSES = (
    "safe-read-only",
    "local-filesystem-delete",
    "repository-history-destruction",
    "remote-destructive-operation",
    "privilege-escalation",
    "system-store-destruction",
)
PERMISSION_PROBES = (
    ("git status", "safe-read-only"),
    ("rm -rf cache", "local-filesystem-delete"),
    ("git reset --hard HEAD", "repository-history-destruction"),
    ("git push --force origin main", "remote-destructive-operation"),
    ("sudo command", "privilege-escalation"),
    ("nix store delete /nix/store/example", "system-store-destruction"),
)
PARENT_BASH_PERMISSIONS = {
    "*": "ask",
    "git status*": "allow",
    "rm*": "ask",
    "git reset --hard*": "deny",
    "git clean*": "deny",
    "git push --force*": "deny",
    "git push --delete*": "deny",
    "sudo*": "deny",
    "nix store delete*": "deny",
}
LEAF_BASH_PERMISSIONS = {
    "*": "ask",
    "git status*": "allow",
    "rm*": "deny",
    "git reset --hard*": "deny",
    "git clean*": "deny",
    "git push --force*": "deny",
    "git push --delete*": "deny",
    "sudo*": "deny",
    "nix store delete*": "deny",
}


class PolicyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.docs, cls.parse_errors = load_policy(ROOT)

    def make_consumer_fixture(self, root: Path) -> tuple[Path, Path, Path, Path]:
        dotnix_root = root / "dotnix"
        templates_root = root / "Templates"
        dotnix_bundle = dotnix_root / "config.d/opencode"
        templates_bundle = templates_root / "components/agent-core"
        dotnix_agents = dotnix_bundle / "agents"
        templates_agents = templates_bundle / ".opencode/agents"
        dotnix_agents.mkdir(parents=True)
        templates_agents.mkdir(parents=True)

        models = self.docs["models"]["models"]
        roles = self.docs["roles"]["roles"]
        for profile, bundle, directory in (
            ("global", dotnix_bundle, dotnix_agents),
            ("agent-core", templates_bundle, templates_agents),
        ):
            assignments = self.docs[profile]["assignments"]
            surface_policy = self.docs[profile]["permission_surfaces"]
            parent_roles = set(surface_policy["parent_roles"])
            for role, assignment in assignments.items():
                mode = roles[role]["kind"]
                model = models[assignment["primary_model"]]["id"]
                role_permissions = (
                    PARENT_BASH_PERMISSIONS
                    if role in parent_roles
                    else LEAF_BASH_PERMISSIONS
                )
                permission_lines = "\n".join(
                    f"    {json.dumps(pattern)}: {action}"
                    for pattern, action in role_permissions.items()
                )
                (directory / f"{role}.md").write_text(
                    f"---\nmode: {mode}\nmodel: {model}\n"
                    f"permission:\n  bash:\n{permission_lines}\n---\n",
                    encoding="utf-8",
                )

            bundle.joinpath("opencode.json").write_text(
                json.dumps({"permission": {"bash": PARENT_BASH_PERMISSIONS}}),
                encoding="utf-8",
            )
            source_prefix = "agents" if profile == "global" else ".opencode/agents"
            surface_roles = [
                (role, "parent") for role in surface_policy["parent_roles"]
            ] + [
                (role, "leaf") for role in surface_policy["leaf_roles"]
            ]
            manifest_lines = [
                "schema_version = 1",
                'contract = "permission-semantics"',
                f'profile = "{profile}"',
            ]
            for surface_id, boundary in surface_roles:
                manifest_lines.extend(
                    [
                        "",
                        "[[surfaces]]",
                        f'id = "{surface_id}"',
                        f'boundary = "{boundary}"',
                        'base_source = "opencode.json"',
                        f'agent_source = "{source_prefix}/{surface_id}.md"',
                        'signals = ["NEEDS_APPROVAL", "NEEDS_DECISION"]',
                    ]
                )
            for surface_id, _ in surface_roles:
                for input_value, class_id in PERMISSION_PROBES:
                    manifest_lines.extend(
                        [
                            "",
                            "[[probes]]",
                            f'surface = "{surface_id}"',
                            'tool = "bash"',
                            f"input = {json.dumps(input_value)}",
                            f'classes = ["{class_id}"]',
                        ]
                    )
            bundle.joinpath("opencode-contract-permissions.toml").write_text(
                "\n".join(manifest_lines) + "\n",
                encoding="utf-8",
            )
        return dotnix_root, templates_root, dotnix_agents, templates_agents

    def test_policy_is_valid(self) -> None:
        self.assertEqual([], validate_policy(ROOT))

    def copy_policy_fixture(self, root: Path) -> Path:
        shutil.copytree(ROOT / "policy", root / "policy")
        shutil.copytree(ROOT / "profiles", root / "profiles")
        return root / "policy/permission-semantics.toml"

    def assert_permission_semantics_error(self, errors: list[str], *terms: str) -> None:
        relevant = [error for error in errors if "policy/permission-semantics" in error]
        self.assertTrue(relevant, errors)
        rendered = "\n".join(relevant)
        for term in terms:
            self.assertIn(term, rendered)

    def test_permission_semantics_has_exact_six_classes_and_matrices(self) -> None:
        document = self.docs["permission-semantics"]
        contract = document["contract"]
        expected_classes = [
            "safe-read-only",
            "local-filesystem-delete",
            "repository-history-destruction",
            "remote-destructive-operation",
            "privilege-escalation",
            "system-store-destruction",
        ]
        self.assertEqual(expected_classes, contract["operation_classes"])
        self.assertEqual("bounded-cross-consumer-safety", contract["scope"])
        self.assertEqual(
            "consumer-mapped-semantic-class", contract["classification_input"]
        )
        self.assertEqual(
            "consumer-owned-outside-contract",
            contract["unclassified_consumer_operation"],
        )
        self.assertTrue(contract["allow_requires_configured_role_permission"])
        self.assertEqual("deny-over-ask-over-allow", contract["overlap_resolution"])
        self.assertEqual(
            "BLOCKED-over-NEEDS_APPROVAL-over-none",
            contract["overlap_escalation_resolution"],
        )
        self.assertEqual(10, len(contract["required_invariant_ids"]))

        classes = document["operation_classes"]
        self.assertEqual(6, len(classes))
        self.assertEqual(expected_classes, [operation["id"] for operation in classes])
        expected_matrix = {
            "safe-read-only": ("allow", "allow", "none", "none"),
            "local-filesystem-delete": ("ask", "deny", "none", "NEEDS_APPROVAL"),
            "repository-history-destruction": ("deny", "deny", "BLOCKED", "BLOCKED"),
            "remote-destructive-operation": ("deny", "deny", "BLOCKED", "BLOCKED"),
            "privilege-escalation": ("deny", "deny", "BLOCKED", "BLOCKED"),
            "system-store-destruction": ("deny", "deny", "BLOCKED", "BLOCKED"),
        }
        actual_matrix = {
            operation["id"]: (
                operation["parent_disposition"],
                operation["leaf_disposition"],
                operation["parent_escalation"],
                operation["leaf_escalation"],
            )
            for operation in classes
        }
        self.assertEqual(expected_matrix, actual_matrix)

    def test_permission_policy_has_no_concrete_command_literals(self) -> None:
        policy_text = (ROOT / "policy/permission-semantics.toml").read_text(
            encoding="utf-8"
        )
        for literal in (
            "rm -rf",
            "git reset --hard",
            "git clean",
            "sudo",
            "nix store delete",
        ):
            with self.subTest(literal=literal):
                self.assertNotIn(literal, policy_text)

    def test_local_filesystem_delete_requires_parent_approval(self) -> None:
        operation = {
            item["id"]: item for item in self.docs["permission-semantics"]["operation_classes"]
        }["local-filesystem-delete"]
        self.assertEqual("ask", operation["parent_disposition"])
        self.assertEqual("deny", operation["leaf_disposition"])
        self.assertEqual("NEEDS_APPROVAL", operation["leaf_escalation"])
        self.assertEqual("none", operation["parent_escalation"])
        self.assertEqual("bounded-destructive", operation["category"])

    def test_permission_invariants_are_anchored_to_the_contract(self) -> None:
        required = set(
            self.docs["permission-semantics"]["contract"]["required_invariant_ids"]
        )
        entries = {
            entry["id"]: entry for entry in self.docs["invariants"]["invariants"]
        }
        self.assertTrue(required.issubset(entries))
        self.assertTrue(
            all(
                entries[invariant_id]["contract"] == "permission-semantics"
                for invariant_id in required
            )
        )

    def test_permission_invariant_anchor_cannot_drift_to_another_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.copy_policy_fixture(root)
            invariants_path = root / "policy/invariants.toml"
            invariants_path.write_text(
                invariants_path.read_text(encoding="utf-8").replace(
                    'contract = "permission-semantics"',
                    'contract = "other-contract"',
                    1,
                ),
                encoding="utf-8",
            )
            self.assertIn(
                "must reference permission-semantics",
                "\n".join(validate_policy(root)),
            )

    def test_permission_invariant_anchors_are_closed_and_bidirectional(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_policy_fixture(root)
            invariants_path = root / "policy/invariants.toml"
            invariants_path.write_text(
                invariants_path.read_text(encoding="utf-8")
                + '\n[[invariants]]\nid = "unlisted-anchor"\nscope = "common"\n'
                + 'contract = "permission-semantics"\nstatement = "extra"\n',
                encoding="utf-8",
            )
            self.assertIn(
                "unlisted permission-semantics anchors",
                "\n".join(validate_policy(root)),
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_policy_fixture(root)
            invariants_path = root / "policy/invariants.toml"
            invariants_path.write_text(
                invariants_path.read_text(encoding="utf-8").replace(
                    'contract = "permission-semantics"',
                    'contract = "permission-semantics"\nextra = true',
                    1,
                ),
                encoding="utf-8",
            )
            self.assertIn(
                "unknown fields ['extra']",
                "\n".join(validate_policy(root)),
            )

    def test_structural_history_remote_privilege_and_system_operations_are_denied(self) -> None:
        operations = {
            item["id"]: item for item in self.docs["permission-semantics"]["operation_classes"]
        }
        structural = (
            "repository-history-destruction",
            "remote-destructive-operation",
            "system-store-destruction",
        )
        for operation_id in structural:
            with self.subTest(operation=operation_id):
                operation = operations[operation_id]
                self.assertEqual("structural-destructive", operation["category"])
                self.assertEqual("deny", operation["parent_disposition"])
                self.assertEqual("deny", operation["leaf_disposition"])
                self.assertEqual("BLOCKED", operation["parent_escalation"])
                self.assertEqual("BLOCKED", operation["leaf_escalation"])

        privilege = operations["privilege-escalation"]
        self.assertEqual("deny", privilege["parent_disposition"])
        self.assertEqual("deny", privilege["leaf_disposition"])
        self.assertEqual("BLOCKED", privilege["parent_escalation"])
        self.assertEqual("BLOCKED", privilege["leaf_escalation"])
        self.assertEqual("authority-change", privilege["category"])

    def test_needs_approval_has_minimum_evidence_and_fail_closed_invariants(self) -> None:
        signal = self.docs["permission-semantics"]["signals"]["NEEDS_APPROVAL"]
        self.assertEqual("permission-escalation", signal["kind"])
        self.assertEqual("approval-capable-parent", signal["interactive_boundary"])
        self.assertFalse(signal["terminal"])
        self.assertFalse(signal["leaf_direct_ask"])
        self.assertFalse(signal["leaf_direct_execution"])
        self.assertFalse(signal["leaf_permission_mutation"])
        self.assertFalse(signal["permission_bypass"])
        self.assertTrue(signal["parent_independent_reevaluation"])
        self.assertFalse(signal["parent_relay"])
        self.assertFalse(signal["parent_auto_approve"])
        self.assertFalse(signal["leaf_executes_denied_operation"])
        self.assertEqual("BLOCKED", signal["out_of_authority"])
        self.assertEqual(
            {"retry", "rephrase", "redelegation", "equivalent-substitute"},
            set(signal["rejection_bypass_methods_forbidden"]),
        )
        self.assertTrue(
            {
                "operation_class",
                "operation_identity",
                "scope",
                "purpose",
                "evidence",
                "least_privilege",
                "safe_alternatives",
                "configured_authority",
            }.issubset(signal["required_evidence"])
        )

    def test_needs_decision_is_not_a_permission_approval_path(self) -> None:
        signals = self.docs["permission-semantics"]["signals"]
        approval = signals["NEEDS_APPROVAL"]
        decision = signals["NEEDS_DECISION"]
        self.assertEqual("requirements-product-or-architecture-ambiguity", decision["kind"])
        self.assertEqual("only-when-human-judgment-required", decision["interactive_boundary"])
        self.assertFalse(decision["terminal"])
        self.assertFalse(decision["permission_approval_resolves"])
        self.assertTrue(decision["parent_must_resolve_from_contract_or_evidence"])
        self.assertFalse(decision["leaf_direct_ask"])
        self.assertEqual("not-an-approval-path", decision["permission_denial_resolution"])
        self.assertNotEqual(approval["kind"], decision["kind"])
        self.assertNotEqual(approval["interactive_boundary"], decision["interactive_boundary"])
        self.assertTrue(
            {
                "ambiguity",
                "known_evidence",
                "requirements_or_product_or_architecture",
                "options",
                "recommendation",
            }.issubset(decision["required_evidence"])
        )

    def test_permission_semantics_rejects_unknown_semantic_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.copy_policy_fixture(root)
            contents = path.read_text(encoding="utf-8").replace(
                '  "safe-read-only",',
                '  "unknown-semantic-operation",',
                1,
            )
            path.write_text(contents, encoding="utf-8")
            self.assert_permission_semantics_error(
                validate_policy(root), "unknown-semantic-operation", "operation"
            )

    def test_permission_semantics_rejects_unknown_disposition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.copy_policy_fixture(root)
            contents = path.read_text(encoding="utf-8").replace(
                'id = "local-filesystem-delete"\nparent_disposition = "ask"',
                'id = "local-filesystem-delete"\nparent_disposition = "prompt"',
                1,
            )
            path.write_text(contents, encoding="utf-8")
            self.assert_permission_semantics_error(
                validate_policy(root), "local-filesystem-delete", "disposition"
            )

    def test_permission_semantics_rejects_non_fail_closed_overlap_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.copy_policy_fixture(root)
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    'overlap_resolution = "deny-over-ask-over-allow"',
                    'overlap_resolution = "allow-over-deny"',
                    1,
                ),
                encoding="utf-8",
            )
            self.assert_permission_semantics_error(
                validate_policy(root), "overlap_resolution", "deny-over-ask-over-allow"
            )

    def test_permission_semantics_rejects_non_fail_closed_overlap_escalation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.copy_policy_fixture(root)
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    'overlap_escalation_resolution = "BLOCKED-over-NEEDS_APPROVAL-over-none"',
                    'overlap_escalation_resolution = "NEEDS_APPROVAL-over-BLOCKED-over-none"',
                    1,
                ),
                encoding="utf-8",
            )
            self.assert_permission_semantics_error(
                validate_policy(root),
                "overlap_escalation_resolution",
                "BLOCKED-over-NEEDS_APPROVAL-over-none",
            )

    def test_permission_semantics_rejects_missing_required_operation_class(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.copy_policy_fixture(root)
            contents = path.read_text(encoding="utf-8")
            start = contents.index('\n[[operation_classes]]\nid = "system-store-destruction"')
            end = contents.index("\n[signals.NEEDS_APPROVAL]", start)
            path.write_text(contents[:start] + contents[end:], encoding="utf-8")
            self.assert_permission_semantics_error(
                validate_policy(root), "system-store-destruction", "operation"
            )

    def test_permission_semantics_rejects_malformed_profile_and_authority_references(self) -> None:
        variants = (
            ('profile = "global"', 'profile = "unknown-profile"', "unknown-profile", "profile"),
            (
                'parent_authority = "approval-capable-parent"',
                'parent_authority = "unknown-authority"',
                "unknown-authority",
                "authority",
            ),
        )
        for old, new, reference, field in variants:
            with self.subTest(reference=reference):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    path = self.copy_policy_fixture(root)
                    contents = path.read_text(encoding="utf-8").replace(old, new, 1)
                    path.write_text(contents, encoding="utf-8")
                    self.assert_permission_semantics_error(
                        validate_policy(root), reference, field
                    )

    def test_permission_semantics_rejects_contradictory_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.copy_policy_fixture(root)
            contents = path.read_text(encoding="utf-8").replace(
                'id = "safe-read-only"\n'
                'parent_disposition = "allow"\n'
                'leaf_disposition = "allow"\n'
                'parent_escalation = "none"',
                'id = "safe-read-only"\n'
                'parent_disposition = "allow"\n'
                'leaf_disposition = "allow"\n'
                'parent_escalation = "NEEDS_APPROVAL"',
                1,
            )
            path.write_text(contents, encoding="utf-8")
            self.assert_permission_semantics_error(
                validate_policy(root), "safe-read-only", "parent_escalation"
            )

    def test_permission_semantics_rejects_undeclared_schema_extension(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.copy_policy_fixture(root)
            contents = path.read_text(encoding="utf-8").replace(
                "closed_world = true\n",
                "closed_world = true\nundeclared_extension = true\n",
                1,
            )
            path.write_text(contents, encoding="utf-8")
            self.assert_permission_semantics_error(
                validate_policy(root), "undeclared_extension", "contract"
            )

    def test_permission_semantics_rejects_unknown_top_level_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.copy_policy_fixture(root)
            path.write_text(
                path.read_text(encoding="utf-8")
                + "\n[unexpected]\nenabled = true\n",
                encoding="utf-8",
            )
            self.assert_permission_semantics_error(
                validate_policy(root), "unexpected", "unknown fields"
            )

    def test_permission_semantics_rejects_invalid_schema_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.copy_policy_fixture(root)
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "schema_version = 1", "schema_version = 2", 1
                ),
                encoding="utf-8",
            )
            self.assertIn(
                "policy/permission-semantics.toml: schema_version must be 1",
                validate_policy(root),
            )

    def test_permission_semantics_rejects_local_delete_silent_allow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.copy_policy_fixture(root)
            contents = path.read_text(encoding="utf-8").replace(
                'id = "local-filesystem-delete"\n'
                'parent_disposition = "ask"\n'
                'leaf_disposition = "deny"',
                'id = "local-filesystem-delete"\n'
                'parent_disposition = "ask"\n'
                'leaf_disposition = "allow"',
                1,
            )
            path.write_text(contents, encoding="utf-8")
            self.assert_permission_semantics_error(
                validate_policy(root), "local-filesystem-delete", "leaf_disposition"
            )

    def test_permission_semantics_rejects_structural_destruction_ask_or_allow(self) -> None:
        class_header = (
            'id = "repository-history-destruction"\n'
            'parent_disposition = "deny"\n'
            'leaf_disposition = "deny"'
        )
        for field in ("parent_disposition", "leaf_disposition"):
            for value in ("ask", "allow"):
                with self.subTest(field=field, value=value):
                    with tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary)
                        path = self.copy_policy_fixture(root)
                        contents = path.read_text(encoding="utf-8")
                        replacement = class_header.replace(
                            f'{field} = "deny"', f'{field} = "{value}"', 1
                        )
                        self.assertNotEqual(class_header, replacement)
                        path.write_text(contents.replace(class_header, replacement, 1), encoding="utf-8")
                        self.assert_permission_semantics_error(
                            validate_policy(root), "repository-history-destruction", field
                        )

    def test_optional_workers_are_global_noncanonical_and_procedural(self) -> None:
        optional = self.docs["optional-workers"]
        contract = optional["contract"]
        self.assertEqual("global", contract["profile"])
        self.assertEqual("optional", contract["presence"])
        self.assertFalse(contract["enabled_by_default"])
        self.assertEqual("procedural-parent-control", contract["runtime_enforcement"])
        self.assertEqual(1, contract["retry_limit"])
        self.assertEqual(2, contract["max_attempts"])
        self.assertEqual(
            ["local-investigator", "local-tracer", "local-background"],
            optional["workers"]["allowed"],
        )

    def test_parent_evidence_validation_is_fail_closed(self) -> None:
        evidence = self.docs["optional-workers"]["evidence"]
        self.assertEqual("parent", evidence["validation_owner"])
        self.assertEqual("parent-observed-session-events", evidence["tool_call_count_source"])
        self.assertEqual("untrusted", evidence["worker_output_trust"])
        self.assertEqual("BLOCKED", evidence["wrong_or_unsupported_result"])
        self.assertFalse(evidence["wrong_or_unsupported_retry"])

    def test_optional_worker_contract_rejects_unknown_and_retry_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "policy", root / "policy")
            shutil.copytree(ROOT / "profiles", root / "profiles")
            path = root / "policy/optional-workers.toml"
            path.write_text(path.read_text() + "\n[contract.extra]\nenabled = true\n", encoding="utf-8")
            self.assertTrue(any("optional-workers.contract: unknown fields" in error for error in validate_policy(root)))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "policy", root / "policy")
            shutil.copytree(ROOT / "profiles", root / "profiles")
            path = root / "policy/optional-workers.toml"
            path.write_text(path.read_text().replace("retry_limit = 1", "retry_limit = 2"), encoding="utf-8")
            self.assertIn("optional-workers.contract.retry_limit: must be 1", validate_policy(root))

    def test_malformed_table_is_reported_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "policy", root / "policy")
            shutil.copytree(ROOT / "profiles", root / "profiles")
            (root / "policy/roles.toml").write_text('schema_version = 1\nroles = "invalid"\n', encoding="utf-8")
            errors = validate_policy(root)
            self.assertIn("policy/roles.toml: roles must be a table", errors)

    def test_malformed_permission_contract_is_reported_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "policy", root / "policy")
            shutil.copytree(ROOT / "profiles", root / "profiles")
            (root / "policy/permission-semantics.toml").write_text(
                "schema_version = 1\ncontract = \"invalid\"\n",
                encoding="utf-8",
            )
            errors = validate_policy(root)
            self.assertTrue(
                any("policy/permission-semantics.contract: must be a table" in error for error in errors),
                errors,
            )

    def test_validator_rejects_duplicated_intentional_difference_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "policy", root / "policy")
            shutil.copytree(ROOT / "profiles", root / "profiles")
            invariants_path = root / "policy/invariants.toml"
            contents = invariants_path.read_text(encoding="utf-8").replace(
                'role = "general"\nfield = "authority"',
                'role = "general"\nfield = "authority"\nglobal = "foo"\nagent-core = "bar"',
                1,
            )
            invariants_path.write_text(contents, encoding="utf-8")
            errors = validate_policy(root)
            self.assertTrue(any("canonical values must not be duplicated" in error for error in errors))

    def test_exact_model_aliases_and_no_provider_literals(self) -> None:
        self.assertEqual([], self.parse_errors)
        models = self.docs["models"]["models"]
        self.assertEqual({"sol", "terra", "luna"}, set(models.keys()))
        self.assertEqual(
            {
                "sol": "openai/gpt-5.6-sol",
                "terra": "openai/gpt-5.6-terra",
                "luna": "openai/gpt-5.6-luna",
            },
            {alias: model["id"] for alias, model in models.items()},
        )
        model_ids = {model["id"] for model in models.values()}
        self.assertNotIn("spark", {alias for alias in models})
        self.assertNotIn("openai/gpt-5.3-codex-spark", model_ids)
        self.assertNotIn("openai/gpt-5.3-codex-terra", model_ids)
        self.assertNotIn("openai/gpt-5.3-codex-sol", model_ids)
        self.assertFalse(any("spark" in model_id for model_id in model_ids))
        self.assertEqual({"gpt56"}, set(self.docs["models"]["quota_families"]))
        self.assertTrue(all(model["quota_family"] == "gpt56" for model in models.values()))
        self.assertFalse((ROOT / "policy/fallback.toml").exists())

    def test_fixed_model_invariants_replace_routing_invariants(self) -> None:
        identifiers = {item["id"] for item in self.docs["invariants"]["invariants"]}
        self.assertTrue(
            {
                "model-alias-only",
                "single-configured-model",
                "model-substitution-forbidden",
                "alternate-model-retry-forbidden",
                "availability-fail-closed",
                "exact-model-failure-reporting",
                "fallback-agents-forbidden",
                "consumer-audit-read-only",
            }.issubset(identifiers)
        )
        self.assertFalse(any(identifier.startswith("fallback-preserves-") for identifier in identifiers))

    def test_all_model_assignments_are_known(self) -> None:
        self.assertEqual([], self.parse_errors)
        models = self.docs["models"]["models"]
        for profile in ("global", "agent-core"):
            for assignment in self.docs[profile]["assignments"].values():
                self.assertIn(assignment["primary_model"], models)

    def test_profile_scoping_does_not_force_roles(self) -> None:
        for role_id, role in self.docs["roles"]["roles"].items():
            if role["classification"] == "GLOBAL_ONLY":
                self.assertNotIn(role_id, self.docs["agent-core"]["assignments"])
            if role["classification"] == "AGENT_CORE_ONLY":
                self.assertNotIn(role_id, self.docs["global"]["assignments"])

    def test_profile_only_roles_are_not_common(self) -> None:
        task_orchestrator = self.docs["roles"]["roles"]["task-orchestrator"]
        self.assertEqual("AGENT_CORE_ONLY", task_orchestrator["classification"])
        self.assertEqual(["agent-core"], task_orchestrator["profiles"])
        self.assertNotIn("task-orchestrator", self.docs["global"]["assignments"])

    def test_permission_surface_mapping_binds_only_executable_authorities(self) -> None:
        self.assertEqual(
            ["build"],
            self.docs["global"]["permission_surfaces"]["parent_roles"],
        )
        self.assertEqual(
            ["task-orchestrator"],
            self.docs["agent-core"]["permission_surfaces"]["parent_roles"],
        )
        for profile in ("global", "agent-core"):
            surface_roles = {
                *self.docs[profile]["permission_surfaces"]["parent_roles"],
                *self.docs[profile]["permission_surfaces"]["leaf_roles"],
            }
            self.assertNotIn("plan", surface_roles)
            self.assertTrue(surface_roles <= set(self.docs[profile]["assignments"]))

    def test_quota_family_is_defined_once_per_model(self) -> None:
        families = self.docs["models"]["quota_families"]
        for model in self.docs["models"]["models"].values():
            self.assertIsInstance(model["quota_family"], str)
            self.assertIn(model["quota_family"], families)

    def test_current_common_primary_assignments(self) -> None:
        expected = {
            "build": ("sol", "sol"),
            "plan": ("luna", "luna"),
            "architect": ("sol", "sol"),
            "general": ("luna", "luna"),
            "explore": ("luna", "luna"),
            "verifier": ("luna", "luna"),
            "reviewer": ("luna", "luna"),
            "investigator": ("luna", "luna"),
            "security-reviewer": ("terra", "terra"),
            "scout": ("luna", "luna"),
            "task-orchestrator": (None, "luna"),
        }
        for role, (global_model, agent_core_model) in expected.items():
            if role in self.docs["global"]["assignments"]:
                self.assertEqual(global_model, self.docs["global"]["assignments"][role]["primary_model"])
            self.assertEqual(agent_core_model, self.docs["agent-core"]["assignments"][role]["primary_model"])

    def test_intentional_differences_are_only_build_and_general_authority(self) -> None:
        identifiers = {item["id"] for item in self.docs["invariants"]["intentional_differences"]}
        self.assertEqual({"build-authority", "general-authority"}, identifiers)

    def test_intentional_differences_derive_canonical_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dotnix, templates, _, _ = self.make_consumer_fixture(Path(temporary))
            lines, counts = audit(dotnix, templates, ROOT)
            self.assertEqual(0, counts["DIFF"])
            self.assertEqual(0, counts["MISSING"])
            self.assertTrue(any(line.startswith("INTENTIONAL_DIFFERENCE id=build-authority ") for line in lines))
            self.assertTrue(any(line.startswith("INTENTIONAL_DIFFERENCE id=general-authority ") for line in lines))
            self.assertNotIn("INTENTIONAL_DIFFERENCE id=general-primary-model", "\n".join(lines))

    def test_task_orchestrator_global_absence_is_intentional(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dotnix, templates, _, _ = self.make_consumer_fixture(Path(temporary))
            lines, _ = audit(dotnix, templates, ROOT)
            differences = [
                line
                for line in lines
                if line.startswith("INTENTIONAL_DIFFERENCE") and "role=task-orchestrator" in line
            ]
            self.assertIn("INTENTIONAL_DIFFERENCE profile=global role=task-orchestrator expected=absent", differences)

    def test_permission_fixture_is_conforming_for_both_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dotnix, templates, _, _ = self.make_consumer_fixture(Path(temporary))
            consumers = {"global": dotnix, "agent-core": templates}
            for profile, consumer in consumers.items():
                with self.subTest(profile=profile):
                    lines, counts = audit_profile(profile, consumer, self.docs)
                    self.assertEqual(0, counts["DIFF"], lines)
                    self.assertEqual(0, counts["MISSING"], lines)
                    surfaces = [
                        *self.docs[profile]["permission_surfaces"]["parent_roles"],
                        *self.docs[profile]["permission_surfaces"]["leaf_roles"],
                    ]
                    for surface in surfaces:
                        observed = {
                            class_id
                            for _, class_id in PERMISSION_PROBES
                            if any(
                                line.startswith(f"PASS profile={profile} surface={surface} ")
                                and f"classes={class_id}" in line
                                for line in lines
                            )
                        }
                        self.assertEqual(set(PERMISSION_CLASSES), observed, surface)
                    bundle = (
                        consumer / "config.d/opencode"
                        if profile == "global"
                        else consumer / "components/agent-core"
                    )
                    self.assertTrue((bundle / "opencode-contract-permissions.toml").is_file())
                    self.assertEqual(
                        PARENT_BASH_PERMISSIONS,
                        json.loads((bundle / "opencode.json").read_text(encoding="utf-8"))[
                            "permission"
                        ]["bash"],
                    )

    def test_permission_manifest_missing_is_strict_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dotnix, _, _, _ = self.make_consumer_fixture(Path(temporary))
            (dotnix / "config.d/opencode/opencode-contract-permissions.toml").unlink()
            lines, counts = audit_profile("global", dotnix, self.docs)
            self.assertEqual(1, counts["MISSING"], lines)
            self.assertEqual(1, result_exit_code(lines, counts, strict=True))

    def test_matching_primary_models_and_modes_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dotnix, templates, dotnix_agents, templates_agents = self.make_consumer_fixture(Path(temporary))
            lines, counts = audit(dotnix, templates, ROOT)
            self.assertEqual(0, counts["DIFF"])
            self.assertEqual(0, counts["MISSING"])
            self.assertIn(
                "PASS profile=global role=build primary_model=openai/gpt-5.6-sol",
                lines,
            )
            self.assertIn(
                "PASS profile=agent-core role=plan mode=primary",
                lines,
            )
            self.assertIn("PASS profile=global fallback_agents=absent", lines)
            self.assertIn("PASS profile=agent-core fallback_agents=absent", lines)
            self.assertIn("PASS profile=agent-core model_fallback_policy=absent", lines)
            self.assertEqual(0, len(list(dotnix_agents.glob("*-fallback.md"))))
            self.assertEqual(0, len(list(templates_agents.glob("*-fallback.md"))))

    def test_wrong_primary_model_is_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dotnix, templates, _, _ = self.make_consumer_fixture(Path(temporary))
            plan_path = dotnix / "config.d/opencode/agents/plan.md"
            plan_path.write_text(
                plan_path.read_text(encoding="utf-8").replace("openai/gpt-5.6-luna", "openai/wrong"),
                encoding="utf-8",
            )
            lines, counts = audit(dotnix, templates, ROOT)
            self.assertEqual(1, counts["DIFF"])
            self.assertTrue(any("DIFF UNEXPECTED_DRIFT profile=global role=plan primary_model" in line for line in lines))

    def test_wrong_primary_mode_is_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dotnix, templates, dotnix_agents, _ = self.make_consumer_fixture(Path(temporary))
            build_path = dotnix_agents / "build.md"
            build_path.write_text(
                build_path.read_text(encoding="utf-8").replace("mode: primary", "mode: subagent"),
                encoding="utf-8",
            )
            lines, counts = audit(dotnix, templates, ROOT)
            self.assertEqual(1, counts["DIFF"])
            self.assertTrue(any("DIFF UNEXPECTED_DRIFT profile=global role=build mode='subagent' expected='primary'" in line for line in lines))

    def test_primary_fallback_residue_any_profile_is_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dotnix, templates, dotnix_agents, templates_agents = self.make_consumer_fixture(Path(temporary))
            (dotnix_agents / "foo-fallback.md").write_text(
                "---\nmode: subagent\nmodel: openai/gpt-5.6-sol\n---\n",
                encoding="utf-8",
            )
            (templates_agents / "foo-fallback.md").write_text(
                "---\nmode: subagent\nmodel: openai/gpt-5.6-luna\n---\n",
                encoding="utf-8",
            )
            _, counts = audit(dotnix, templates, ROOT)
            self.assertEqual(2, counts["DIFF"])

    def test_agent_core_model_fallback_policy_is_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dotnix, templates, _, _ = self.make_consumer_fixture(Path(temporary))
            binding_path = templates / "components/agent-core/.automation/model-fallback.toml"
            binding_path.parent.mkdir(parents=True)
            binding_path.write_text("version = 1\n", encoding="utf-8")
            lines, counts = audit(dotnix, templates, ROOT)
            self.assertEqual(1, counts["DIFF"])
            self.assertIn("DIFF UNEXPECTED_DRIFT profile=agent-core model_fallback_policy=model-fallback.toml expected=absent", lines)

    def test_missing_primary_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dotnix, templates, dotnix_agents, templates_agents = self.make_consumer_fixture(Path(temporary))
            (dotnix_agents / "build.md").unlink()
            (templates_agents / "build.md").unlink()
            _, counts = audit(dotnix, templates, ROOT)
            self.assertEqual(8, counts["MISSING"])

    def test_model_availability_contract_is_accepted(self) -> None:
        availability = self.docs["model-availability"]["policy"]
        expected = {
            "model_substitution": "forbidden",
            "alternate_model_retry": "forbidden",
            "unavailable_result": "BLOCKED",
            "report_exact_provider_model_failure": True,
            "fallback_agents": "forbidden",
        }
        self.assertEqual(expected, availability)

    def test_model_availability_contract_rejects_invalid_fields(self) -> None:
        variants = [
            ("model_substitution", "allowed"),
            ("alternate_model_retry", "allowed"),
            ("unavailable_result", "allowed"),
            ("report_exact_provider_model_failure", False),
            ("report_exact_provider_model_failure", 1),
            ("fallback_agents", True),
        ]
        for field, value in variants:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                shutil.copytree(ROOT / "policy", root / "policy")
                shutil.copytree(ROOT / "profiles", root / "profiles")
                availability_path = root / "policy/model-availability.toml"
                contents = availability_path.read_text(encoding="utf-8")
                marker = f"{field} = "
                lines = []
                for line in contents.splitlines():
                    if line.startswith(marker):
                        if isinstance(value, bool):
                            rendered = "true" if value else "false"
                        elif isinstance(value, str):
                            rendered = f"\"{value}\""
                        else:
                            rendered = str(value)
                        lines.append(f"{marker}{rendered}")
                    else:
                        lines.append(line)
                availability_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                errors = validate_policy(root)
                self.assertTrue(any(field in error for error in errors))

    def test_model_availability_contract_rejects_unknown_policy_field(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "policy", root / "policy")
            shutil.copytree(ROOT / "profiles", root / "profiles")
            availability_path = root / "policy/model-availability.toml"
            contents = availability_path.read_text(encoding="utf-8").replace(
                'fallback_agents = "forbidden"',
                'fallback_agents = "forbidden"\nemergency_model_substitution = "allowed"',
            )
            availability_path.write_text(contents, encoding="utf-8")
            errors = validate_policy(root)
            self.assertIn(
                "model-availability.policy: unknown fields ['emergency_model_substitution']",
                errors,
            )

    def test_model_availability_contract_rejects_unknown_top_level_table(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "policy", root / "policy")
            shutil.copytree(ROOT / "profiles", root / "profiles")
            availability_path = root / "policy/model-availability.toml"
            contents = availability_path.read_text(encoding="utf-8")
            availability_path.write_text(
                contents + "\n[legacy_fallback]\nenabled = true\n",
                encoding="utf-8",
            )
            errors = validate_policy(root)
            self.assertIn(
                "policy/model-availability.toml: unknown top-level keys ['legacy_fallback']",
                errors,
            )

    def test_model_availability_contract_rejects_missing_required_field(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "policy", root / "policy")
            shutil.copytree(ROOT / "profiles", root / "profiles")
            availability_path = root / "policy/model-availability.toml"
            contents = availability_path.read_text(encoding="utf-8").replace(
                'fallback_agents = "forbidden"\n',
                "",
            )
            availability_path.write_text(contents, encoding="utf-8")
            errors = validate_policy(root)
            self.assertIn(
                "model-availability.policy.fallback_agents: required field is missing",
                errors,
            )

    def test_model_availability_contract_rejects_non_integer_schema_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "policy", root / "policy")
            shutil.copytree(ROOT / "profiles", root / "profiles")
            availability_path = root / "policy/model-availability.toml"
            contents = availability_path.read_text(encoding="utf-8").replace(
                "schema_version = 1",
                "schema_version = true",
                1,
            )
            availability_path.write_text(contents, encoding="utf-8")
            errors = validate_policy(root)
            self.assertIn(
                "policy/model-availability.toml: schema_version must be 1",
                errors,
            )

    def test_role_assignment_rejects_substitution_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "policy", root / "policy")
            shutil.copytree(ROOT / "profiles", root / "profiles")
            profile_path = root / "profiles/global.toml"
            contents = profile_path.read_text(encoding="utf-8").replace(
                'primary_model = "sol"\nauthority = "implementation-orchestrator"',
                'primary_model = "sol"\nauthority = "implementation-orchestrator"\nfallback_model = "luna"',
                1,
            )
            profile_path.write_text(contents, encoding="utf-8")
            errors = validate_policy(root)
            self.assertTrue(any("unsupported fields ['fallback_model']" in error for error in errors))

    def test_no_provider_model_literals_outside_models(self) -> None:
        self.assertEqual([], self.parse_errors)

        def has_model_literal(node) -> bool:
            if isinstance(node, dict):
                return any(has_model_literal(value) for value in node.values())
            if isinstance(node, list):
                return any(has_model_literal(value) for value in node)
            return isinstance(node, str) and node.startswith("openai/")

        for name, document in self.docs.items():
            if name == "models":
                continue
            self.assertFalse(has_model_literal(document), f"{name} contains provider model literals")


if __name__ == "__main__":
    unittest.main()
