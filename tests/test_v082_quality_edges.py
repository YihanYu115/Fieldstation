from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from test_v081 import v81_bundle
from test_v082 import V082RendererTests

from issue_manager import IssueManager
from issue_manager.adapter_service import AdapterService
from issue_manager.errors import ConflictError, NotFoundError, ValidationError
from issue_manager.field_bundle_service import FIELD_BUNDLE_VERSION
from issue_manager.registry_service import (
    _reference_locations,
    _resolve_reference_from_entries,
    _validate_report_renderer,
    _validate_report_template_v2,
    _version_matches,
    legacy_policy_semantic_findings,
    load_bundle,
    validate_json_instance,
)
from issue_manager.store import Store, canonical_json, now


class V082BoundaryCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.manager = IssueManager.initialize(self.root / "ledger")
        installed = self.manager.registry.install_bundle(v81_bundle())
        self.manager.registry.activate_bundle(installed["bundle_id"])
        self.issue_type = self.manager.registry.resolve(
            "org.example.v81/issue_type/specimen@1.0.0"
        )
        self.template = self.manager.registry.resolve(
            "org.example.v81/record_template/measurement@1.0.0"
        )
        self.manager.create_issue(
            "sample-a",
            "specimen",
            issue_type_registration_id=self.issue_type["registration_id"],
        )

    def tearDown(self) -> None:
        self.manager.close()
        self.temporary.cleanup()

    def test_field_action_shared_validator_boundary_matrix(self) -> None:
        service = self.manager.field_bundles
        record = self.manager.records.create(
            "sample-a", self.template["registration_id"], data={"name": "base"}
        )
        other = self.manager.records.create(
            "sample-a", self.template["registration_id"], data={"name": "other"}
        )
        invalid = [
            [],
            {"action_type": "unknown"},
            {"action_type": "record_revise"},
            {
                "action_type": "record_revise",
                "record_instance_id": "missing",
                "base_record_revision_id": record["record_revision_id"],
                "data": {},
            },
            {
                "action_type": "record_revise",
                "record_instance_id": record["record_instance_id"],
                "base_record_revision_id": other["record_revision_id"],
                "data": {},
            },
            {
                "action_type": "record_revise",
                "record_instance_id": record["record_instance_id"],
                "base_record_revision_id": record["record_revision_id"],
                "data": [],
            },
            {
                "action_type": "record_revise",
                "record_instance_id": record["record_instance_id"],
                "base_record_revision_id": record["record_revision_id"],
                "data": {},
                "evidence_links": {},
            },
            {
                "action_type": "record_revise",
                "record_instance_id": record["record_instance_id"],
                "base_record_revision_id": record["record_revision_id"],
                "data": {},
                "conflict_policy": "overwrite",
            },
            {"action_type": "record_create"},
            {
                "action_type": "record_create",
                "target_issue_id": "sample-a",
                "template_reference": self.template["registration_id"],
                "data": [],
            },
            {
                "action_type": "record_create",
                "target_issue_id": "sample-a",
                "template_reference": self.template["registration_id"],
                "data": {},
                "evidence_links": {},
            },
            {"action_type": "working_entry", "target_issue_id": "sample-a"},
            {
                "action_type": "working_entry",
                "target_issue_id": "sample-a",
                "body": "x",
                "evidence_refs": {},
            },
            {"action_type": "evidence_create", "locator": ""},
            {
                "action_type": "evidence_create",
                "locator": "fixture:x",
                "target_issue_id": "missing",
            },
        ]
        for candidate in invalid:
            with self.subTest(candidate=candidate), self.assertRaises(
                (ValidationError, NotFoundError)
            ):
                service._normalize_action(candidate)  # type: ignore[arg-type]

        normalized = service._normalize_action(
            {
                "action_type": "record_create",
                "target_issue_id": "sample-a",
                "template_reference": self.template["registration_id"],
                "data": {"name": "created"},
            }
        )
        self.assertEqual(
            normalized["issue_type_registration_id"], self.issue_type["registration_id"]
        )
        self.assertEqual(
            service._normalize_action(
                {
                    "action_type": "evidence_create",
                    "locator": "fixture:evidence",
                    "target_issue_id": "sample-a",
                }
            )["target_issue_id"],
            "sample-a",
        )
        with self.assertRaises(NotFoundError):
            service.conflicts("missing")

    def test_report_scope_query_and_template_boundary_matrix(self) -> None:
        reports = self.manager.reports
        parent_type = self.manager.registry.resolve(
            "org.example.v81/issue_type/parent@1.0.0"
        )
        self.manager.create_issue(
            "root-a",
            "parent",
            issue_type_registration_id=parent_type["registration_id"],
        )
        self.manager.create_issue(
            "child-a",
            "specimen",
            parent_issue_id="root-a",
            issue_type_registration_id=self.issue_type["registration_id"],
        )
        normalized, issue_ids = reports._normalize_scope(
            {"root_issue_id": "root-a"}
        )
        self.assertEqual(normalized["root_issue_id"], "root-a")
        self.assertEqual(issue_ids, ["child-a", "root-a"])
        self.assertEqual(
            reports._normalize_scope(
                {
                    "issue_type_refs": [
                        "org.example.v81/issue_type/specimen@1.0.0"
                    ]
                }
            )[0]["issue_type_registration_ids"],
            [self.issue_type["registration_id"]],
        )
        for scope in (
            {"unknown": True},
            {"issue_id": "sample-a", "root_issue_id": "sample-a"},
            {"issue_ids": "bad"},
            {"issue_type_registration_ids": "bad"},
            {"issue_type_refs": "bad"},
            {"issue_type": "missing"},
        ):
            with self.subTest(scope=scope), self.assertRaises(
                (ValidationError, ConflictError)
            ):
                reports._normalize_scope(scope)  # type: ignore[arg-type]

        aware = "2026-01-01T00:00:00+00:00"
        self.assertTrue(
            reports._query_matches(
                {"values": {"when": aware}},
                [{"field": "when", "operator": "gte", "value": aware}],
            )
        )
        for value, expected in ((True, 1), ("bad", 1), ("2026-01-01", aware)):
            matched, findings = reports._query_evaluate(
                {"values": {"x": value}},
                [{"field": "x", "operator": "lt", "value": expected}],
            )
            self.assertFalse(matched)
            self.assertEqual(findings[0]["code"], "query_value_invalid")
        matched, findings = reports._query_evaluate(
            {"values": {"x": 1}},
            [{"field": "x", "operator": "eq", "value": "1"}],
        )
        self.assertFalse(matched)
        self.assertEqual(findings[0]["code"], "query_value_invalid")

        for definition in (
            {"record_template_selection": {}},
            {"record_template_selection": {"mode": "all"}},
            {
                "record_template_selection": {
                    "mode": "all_for_issue_types",
                    "issue_type_refs": [],
                }
            },
            {"record_templates": "bad"},
            {"record_templates": [], "renderer_reference": 1},
            {"record_templates": [], "renderer_config": []},
        ):
            with self.subTest(definition=definition), self.assertRaises(ValidationError):
                _validate_report_template_v2(definition)  # type: ignore[arg-type]

    def test_registry_policy_and_renderer_schema_boundary_matrix(self) -> None:
        policy = {
            "policy_version": 7,
            "issue_types": {
                "bad": "invalid",
                "custom": {"allowed_children": [], "hook": "python"},
            },
            "publication": {"custom_gate": True},
            "publication_requirements": {"unknown_status": {}},
            "conclusion_schemas": {
                "typed": {"required": ["score"], "type": "number"}
            },
            "custom_section": {},
        }
        codes = {item["code"] for item in legacy_policy_semantic_findings(policy)}
        self.assertEqual(
            codes,
            {
                "unknown_policy_sections",
                "issue_type_definition_invalid",
                "unknown_issue_type_logic",
                "unknown_publication_logic",
                "unknown_publication_profiles",
                "custom_conclusion_schema_not_declarative",
            },
        )
        valid_renderer = {
            "adapter_name": "renderer",
            "adapter_version": "1.0.0",
            "protocol_version": "issue-manager-adapter/v1",
            "supported_media_types": ["text/plain"],
            "default_media_type": "text/plain",
            "default_extension": "txt",
            "configuration_schema": {},
            "deterministic_output": True,
        }
        _validate_report_renderer(valid_renderer)
        mutations = [
            {**valid_renderer, "extra": True},
            {**valid_renderer, "adapter_name": ""},
            {**valid_renderer, "supported_media_types": []},
            {**valid_renderer, "default_media_type": "application/json"},
            {**valid_renderer, "default_extension": "bad extension"},
            {**valid_renderer, "deterministic_output": 1},
        ]
        for definition in mutations:
            with self.subTest(definition=definition), self.assertRaises(ValidationError):
                _validate_report_renderer(definition)

    def test_adapter_descriptor_and_state_edges(self) -> None:
        service: AdapterService = self.manager.adapters
        with self.assertRaises(ValidationError):
            service.install([], self.root / "missing")  # type: ignore[arg-type]
        with self.assertRaises(ValidationError):
            service.install(
                {
                    "kind": "report",
                    "name": "x",
                    "version": "1.0.0",
                    "protocol_version": "bad",
                    "timeout_seconds": 1,
                    "maximum_output_bytes": 1,
                },
                self.root / "missing",
            )
        with self.assertRaises(NotFoundError):
            service.verify("missing@1.0.0", kind="report")

        descriptor_file = self.root / "descriptor.json"
        descriptor_file.write_text("[]\n", encoding="utf-8", newline="\n")
        with self.assertRaises(ValidationError):
            service.install(descriptor_file, self.root / "missing")

        executable = self.root / ("adapter.cmd" if os.name == "nt" else "adapter")
        if os.name == "nt":
            executable.write_text(
                f'@"{sys.executable}" -c "print(1)"\n', encoding="utf-8", newline="\n"
            )
        else:
            executable.write_text("#!/bin/sh\necho 1\n", encoding="utf-8", newline="\n")
            executable.chmod(0o755)
        base = {
            "name": "ambiguous",
            "version": "1.0.0",
            "protocol_version": "issue-manager-adapter/v1",
            "timeout_seconds": 1,
            "maximum_output_bytes": 1024,
        }
        service.install({**base, "kind": "report"}, executable)
        service.install({**base, "kind": "import"}, executable)
        with self.assertRaises(ConflictError):
            service._find("ambiguous@1.0.0")
        service.set_enabled(
            "ambiguous@1.0.0", False, kind="import", reason="test disambiguation"
        )
        self.assertEqual(service._find("ambiguous@1.0.0")["adapter_kind"], "report")

        executable.write_text("drift\n", encoding="utf-8", newline="\n")
        service.set_enabled(
            "ambiguous@1.0.0", False, kind="report", reason="drift test"
        )
        with self.assertRaises(ConflictError):
            service.set_enabled("ambiguous@1.0.0", True, kind="report")

        auth = MagicMock(actor_id="operator")
        self.assertEqual(service._actor(auth, "fallback"), "operator")
        auth.require.assert_called_once_with("maintenance")

    def test_registry_reference_and_schema_failure_matrix(self) -> None:
        for expression, expected in (
            ("=2.0.0", False),
            (">=2.0.0", False),
            ("<=0.9.0", False),
            (">1.0.0", False),
            ("<1.0.0", False),
            ("^2.0.0", False),
            ("~1.1.0", False),
            ("*", True),
        ):
            with self.subTest(expression=expression):
                self.assertEqual(_version_matches("1.0.0", expression), expected)
        with self.assertRaises(ValidationError):
            _version_matches("1.0.0", "!=1.0.0")

        schema = {
            "type": "array",
            "items": {"type": "integer", "minimum": 1, "maximum": 2},
            "minItems": 2,
            "maxItems": 3,
        }
        codes = {item["code"] for item in validate_json_instance([], schema)}
        self.assertIn("minItems", codes)
        codes = {item["code"] for item in validate_json_instance([0, 3, 1, 1], schema)}
        self.assertEqual(codes, {"minimum", "maximum", "maxItems"})
        self.assertEqual(
            validate_json_instance(True, {"type": ["boolean", "null"]})[0]["code"],
            "type",
        )
        self.assertEqual(
            validate_json_instance(math.inf, {"type": "number"})[0]["code"],
            "non_finite_number",
        )

        locations = _reference_locations(
            {
                "record_template_refs": ["good", 3],
                "nested": [{"issue_type": "issue"}],
            }
        )
        self.assertEqual(len(locations), 2)
        owner = {
            "bundle_id": "bundle-a",
            "registration_id": "reg_owner",
        }
        entries = [
            {
                "bundle_id": "bundle-a",
                "registration_id": "reg_target",
                "namespace": "org.test",
                "kind": "record_template",
                "name": "target",
                "version": "1.0.0",
                "content_hash": "hash",
            }
        ]
        self.assertEqual(
            _resolve_reference_from_entries(
                "reg_target", "record_template", owner, entries, set(), strict=True
            )[0]["registration_id"],
            "reg_target",
        )
        with self.assertRaises(ValidationError):
            _resolve_reference_from_entries(
                "org.test/issue_type/target@1.0.0",
                "record_template",
                owner,
                entries,
                set(),
                strict=True,
            )
        with self.assertRaises(ValidationError):
            _resolve_reference_from_entries(
                "reg_target", "issue_type", owner, entries, set(), strict=True
            )
        self.assertIsNone(
            _resolve_reference_from_entries(
                "missing", "record_template", owner, entries, set(), strict=False
            )
        )
        self.assertEqual(load_bundle({"name": "manifest-only"})["registrations"], [])
        manifest = self.root / "bad-manifest.json"
        manifest.write_text("[]\n", encoding="utf-8", newline="\n")
        with self.assertRaises(ValidationError):
            load_bundle(manifest)
        directory = self.root / "bundle"
        directory.mkdir()
        (directory / "manifest.json").write_text(
            canonical_json({"registrations": "bad"}) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        with self.assertRaises(ValidationError):
            load_bundle(directory)

        template_base = {
            "columns": [],
            "field_policies": {},
            "query": {},
            "record_templates": [],
        }
        with self.assertRaises(ValidationError):
            _validate_report_template_v2(
                {
                    **template_base,
                    "record_template_selection": {
                        "mode": "all_for_issue_types",
                        "issue_type_refs": ["x"],
                    },
                }
            )
        invalid_selection = dict(template_base)
        invalid_selection.pop("record_templates")
        invalid_selection["record_template_selection"] = {
            "mode": "bad",
            "issue_type_refs": [],
        }
        with self.assertRaises(ValidationError):
            _validate_report_template_v2(invalid_selection)

    def test_report_query_renderer_and_hash_failure_matrix(self) -> None:
        reports = self.manager.reports
        row = {
            "issue_id": "sample-a",
            "record_instance_id": "record-a",
            "values": {
                "number": 1.0,
                "flag": True,
                "time": "2026-01-01T00:00:00+00:00",
                "naive": "2026-01-01",
                "bad_time": "not-a-time",
                "nonfinite": math.inf,
            },
        }
        cases = [
            ({"field": "flag", "operator": "eq", "value": 1}, False, "query_value_invalid"),
            ({"field": "number", "operator": "in", "value": ["1"]}, False, "query_value_invalid"),
            ({"field": "naive", "operator": "lt", "value": "2027-01-01"}, False, "query_value_invalid"),
            ({"field": "bad_time", "operator": "lt", "value": "2027-01-01T00:00:00+00:00"}, False, "query_value_invalid"),
            ({"field": "nonfinite", "operator": "eq", "value": math.inf}, False, "non_finite_number"),
            ({"field": "time", "operator": "lt", "value": "2027-01-01T00:00:00+00:00"}, True, None),
            ({"field": "missing", "operator": "exists", "value": False}, True, None),
        ]
        for condition, matched, code in cases:
            with self.subTest(condition=condition):
                actual, findings = reports._query_evaluate(row, [condition])
                self.assertEqual(actual, matched)
                self.assertEqual(findings[0]["code"] if findings else None, code)

        self.assertEqual(
            reports._accepted_template_ids({}, is_v2=True), set()
        )
        with self.assertRaises(ValidationError):
            reports._accepted_template_ids(
                {"record_template_selection": {"mode": "unsupported"}}, is_v2=True
            )
        self.assertEqual(
            reports._accepted_template_ids(
                {
                    "record_template_selection": {
                        "mode": "all_for_issue_types",
                        "issue_type_refs": [],
                    }
                },
                is_v2=True,
            ),
            set(),
        )
        selected_templates = reports._accepted_template_ids(
            {
                "record_template_selection": {
                    "mode": "all_for_issue_types",
                    "issue_type_refs": [
                        "org.example.v81/issue_type/specimen@1.0.0"
                    ],
                }
            },
            is_v2=True,
        )
        self.assertIn(self.template["registration_id"], selected_templates)
        with self.assertRaises(ValidationError):
            reports._prepare_renderer(
                {"renderer_config": []}, output_format=None, media_type=None
            )
        with self.assertRaises(ValidationError):
            reports._prepare_renderer({}, output_format="markdown", media_type="text/csv")
        self.assertIsNone(reports._current_hash("unknown", "missing"))
        self.assertIsNone(reports._current_hash("manifest", "missing"))

        renderer_definition = {
            "adapter_name": "renderer",
            "adapter_version": "1.0.0",
            "protocol_version": "issue-manager-adapter/v1",
            "supported_media_types": ["text/plain"],
            "default_media_type": "text/plain",
            "default_extension": "txt",
            "configuration_schema": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            "deterministic_output": True,
        }
        registration = {
            "registration_id": "reg_renderer",
            "content_hash": "registration-hash",
            "state": "active",
            "name": "renderer",
            "version": "1.0.0",
            "definition": renderer_definition,
        }
        adapter = {
            "enabled": True,
            "adapter_name": "renderer",
            "adapter_version": "1.0.0",
            "executable_hash": "executable-hash",
            "descriptor_hash": "descriptor-hash",
            "protocol_version": "issue-manager-adapter/v1",
            "state_revision": 0,
        }
        with (
            patch.object(self.manager.registry, "resolve", return_value=registration),
            patch.object(self.manager.adapters, "_find", return_value=adapter),
            patch.object(self.manager.adapters, "verify", return_value={"ok": True}),
        ):
            prepared_renderer = reports._prepare_renderer(
                {"renderer_reference": "renderer", "renderer_config": {}},
                output_format="text/plain",
                media_type=None,
            )
            self.assertEqual(prepared_renderer["media_type"], "text/plain")
        for adapter_delta, verification, definition_delta, config, media in (
            ({"enabled": False}, {"ok": True}, {}, {}, None),
            ({}, {"ok": False}, {}, {}, None),
            ({"protocol_version": "bad"}, {"ok": True}, {}, {}, None),
            ({}, {"ok": True}, {}, {"unexpected": True}, None),
            ({}, {"ok": True}, {}, {}, "application/json"),
        ):
            with self.subTest(adapter_delta=adapter_delta, config=config, media=media):
                local_adapter = {**adapter, **adapter_delta}
                local_registration = {
                    **registration,
                    "definition": {**renderer_definition, **definition_delta},
                }
                with (
                    patch.object(
                        self.manager.registry, "resolve", return_value=local_registration
                    ),
                    patch.object(
                        self.manager.adapters, "_find", return_value=local_adapter
                    ),
                    patch.object(
                        self.manager.adapters, "verify", return_value=verification
                    ),
                    self.assertRaises((ConflictError, ValidationError)),
                ):
                    reports._prepare_renderer(
                        {
                            "renderer_reference": "renderer",
                            "renderer_config": config,
                        },
                        output_format=None,
                        media_type=media,
                    )

    def test_registered_renderer_envelope_failure_matrix(self) -> None:
        renderer_reference = V082RendererTests._install_renderer(self)
        report_template = self.manager.registry.resolve(
            "org.example.v81/report_template/summary@1.0.0"
        )
        definition = dict(report_template["definition"])
        definition["renderer_reference"] = renderer_reference
        definition["renderer_config"] = {}
        content_hash = hashlib.sha256(
            canonical_json(
                {
                    key: (
                        definition if key == "definition" else report_template[key]
                    )
                    for key in (
                        "namespace",
                        "kind",
                        "name",
                        "version",
                        "api_version",
                        "definition",
                    )
                }
            ).encode("utf-8")
        ).hexdigest()
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE registry_entries SET definition_json=?,content_hash=? "
                "WHERE registration_id=?",
                (
                    canonical_json(definition),
                    content_hash,
                    report_template["registration_id"],
                ),
            )
        prepared = self.manager.reports.prepare(
            report_template["registration_id"], scope={"issue_id": "sample-a"}
        )
        good = {
            "content_base64": "b2s=",
            "media_type": "text/plain",
            "extension": "txt",
            "metadata": {},
        }
        cases = [
            {**good, "unknown": True},
            {**good, "media_type": "application/json"},
            {**good, "extension": "bad"},
            {**good, "metadata": []},
            {**good, "content_base64": "%%%"},
        ]
        for envelope in cases:
            with self.subTest(envelope=envelope), patch.object(
                self.manager.adapters,
                "execute",
                return_value={
                    "result": envelope,
                    "executable_hash": "hash",
                    "descriptor_hash": "hash",
                },
            ), self.assertRaises(ValidationError):
                self.manager.reports.build(prepared["report_build_id"])

        shown = self.manager.reports.show(prepared["report_build_id"])
        shown["renderer_snapshot"]["deterministic_output"] = False
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE report_builds SET renderer_snapshot_json=? WHERE report_build_id=?",
                (
                    canonical_json(shown["renderer_snapshot"]),
                    prepared["report_build_id"],
                ),
            )
        nondeterministic = self.manager.reports.reproduce(
            prepared["report_build_id"], rerun_renderer=True
        )
        self.assertEqual(nondeterministic["renderer_identity"]["status"], "drifted")
        self.assertFalse(nondeterministic["rerun"]["attempted"])
        self.assertFalse(nondeterministic["execution_reproducible"])

        config_prepared = self.manager.reports.prepare(
            report_template["registration_id"], scope={"issue_id": "sample-a"}
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE report_builds SET renderer_config_json=? WHERE report_build_id=?",
                (
                    canonical_json({"unexpected": True}),
                    config_prepared["report_build_id"],
                ),
            )
        with self.assertRaises(ConflictError):
            self.manager.reports.build(config_prepared["report_build_id"])

        snapshot_prepared = self.manager.reports.prepare(
            report_template["registration_id"], scope={"issue_id": "sample-a"}
        )
        snapshot = self.manager.reports.show(snapshot_prepared["report_build_id"])[
            "renderer_snapshot"
        ]
        snapshot["unexpected"] = True
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE report_builds SET renderer_snapshot_json=? WHERE report_build_id=?",
                (canonical_json(snapshot), snapshot_prepared["report_build_id"]),
            )
        with self.assertRaises(ConflictError):
            self.manager.reports.build(snapshot_prepared["report_build_id"])
        self.assertTrue(
            self.manager.reports.reproduce(
                snapshot_prepared["report_build_id"], rerun_renderer=False
            )["report_model_hash_valid"]
        )

        state_prepared = self.manager.reports.prepare(
            report_template["registration_id"], scope={"issue_id": "sample-a"}
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE registry_entries SET state='deprecated' WHERE registration_id=?",
                (report_template["registration_id"],),
            )
        with self.assertRaises(ConflictError):
            self.manager.reports.build(state_prepared["report_build_id"])
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE registry_entries SET state='active' WHERE registration_id=?",
                (report_template["registration_id"],),
            )

        oversized_prepared = self.manager.reports.prepare(
            report_template["registration_id"], scope={"issue_id": "sample-a"}
        )
        adapter_row = self.manager.adapters._find("plain-renderer@1.0.0", "report")
        descriptor = json.loads(adapter_row["descriptor_json"])
        descriptor["maximum_output_bytes"] = 1
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE adapter_allowlist SET descriptor_json=? WHERE adapter_kind='report' "
                "AND adapter_name='plain-renderer' AND adapter_version='1.0.0'",
                (canonical_json(descriptor),),
            )
        self.assertEqual(
            self.manager.reports.renderer_identity(oversized_prepared["report_build_id"])[
                "status"
            ],
            "drifted",
        )
        with self.assertRaises(ConflictError):
            self.manager.reports.build(oversized_prepared["report_build_id"])

    def test_field_triage_failure_retry_and_conflict_decisions(self) -> None:
        service = self.manager.field_bundles

        def bundle(bundle_id: str, event: dict) -> dict:
            return {
                "manifest": {
                    "bundle_id": bundle_id,
                    "bundle_version": FIELD_BUNDLE_VERSION,
                    "created_by": "fixture",
                    "created_at": now(),
                    "source_namespace": "fixture.platform",
                    "source_owner": "organizer-agent",
                    "attachments": [],
                },
                "events": [event],
            }

        unknown = service.upload(
            bundle(
                "triage-unknown",
                {"event_id": "unknown", "event_type": "observation"},
            )
        )
        preview = service.route(unknown["field_bundle_id"], dry_run=True)
        self.assertEqual(preview["state"], "needs_triage")
        routed = service.route(unknown["field_bundle_id"])
        event = service.show(unknown["field_bundle_id"])["events"][0]
        with self.assertRaises(ValidationError):
            service.triage(
                event["field_bundle_event_id"],
                {"action": "split", "actions": []},
                expected_revision=event["state_revision"],
            )
        with self.assertRaises(ValidationError):
            service.triage(
                event["field_bundle_event_id"],
                "unsupported",
                expected_revision=event["state_revision"],
            )
        rejected = service.triage(
            event["field_bundle_event_id"],
            "reject",
            expected_revision=event["state_revision"],
        )
        self.assertEqual(rejected["state"], "rejected")
        self.assertEqual(service.apply(routed["field_bundle_id"])["state"], "applied")
        self.assertTrue(service.apply(routed["field_bundle_id"])["idempotent_replay"])
        self.assertEqual(
            service._conflicts(
                {
                    "manifest": {"known_issue_revisions": {"sample-a": 0}},
                    "events": [],
                }
            ),
            [],
        )
        with patch.object(
            service,
            "show",
            return_value={
                "state": "ready",
                "routing_state_revision": 0,
                "manifest": {},
                "events": [
                    {
                        "field_bundle_event_id": "already-applied",
                        "event_index": 0,
                        "event_type": "record_patch",
                        "processing_state": "applied",
                    }
                ],
            },
        ):
            self.assertEqual(service.route("fixture", dry_run=True)["routed"], [])
        with (
            patch.object(
                service,
                "show",
                return_value={
                    "state": "ready",
                    "routing_state_revision": 0,
                    "manifest": {},
                    "events": [
                        {
                            "field_bundle_event_id": "invalid-normalized",
                            "event_index": 0,
                            "event_type": "record_patch",
                            "processing_state": "staged",
                        }
                    ],
                },
            ),
            patch.object(
                service,
                "_route_action",
                return_value=(
                    {
                        "action_type": "record_revise",
                        "record_instance_id": "missing",
                        "data": {},
                    },
                    None,
                ),
            ),
        ):
            invalid_preview = service.route("fixture", dry_run=True)
            self.assertEqual(
                invalid_preview["needs_triage"][0]["reason"],
                "record_base_revision_required",
            )

        failure = service.upload(
            bundle(
                "apply-failure",
                {
                    "event_id": "note",
                    "event_type": "observation",
                    "target_issue_id": "sample-a",
                    "body": "offline note",
                },
            )
        )
        service.route(failure["field_bundle_id"])
        with patch.object(service, "_apply_once", side_effect=RuntimeError("injected")):
            with self.assertRaisesRegex(RuntimeError, "injected"):
                service.apply(failure["field_bundle_id"])
        failed = service.show(failure["field_bundle_id"])
        self.assertEqual(failed["state"], "failed")
        retried = service.retry(
            failure["field_bundle_id"],
            expected_revision=failed["routing_state_revision"],
        )
        self.assertEqual(retried["state"], "staged")
        with self.assertRaises(ConflictError):
            service.retry(
                failure["field_bundle_id"],
                expected_revision=retried["routing_state_revision"],
            )

        record = self.manager.records.create(
            "sample-a", self.template["registration_id"], data={"name": "base"}
        )
        conflict_bundle = service.upload(
            bundle(
                "conflict-decisions",
                {
                    "event_id": "patch",
                    "event_type": "record_patch",
                    "record_instance_id": record["record_instance_id"],
                    "base_record_revision_id": record["record_revision_id"],
                    "data": {"name": "offline"},
                },
            )
        )
        service.route(conflict_bundle["field_bundle_id"])
        self.manager.records.revise(
            record["record_instance_id"],
            {"name": "online"},
            expected_revision_id=record["record_revision_id"],
        )
        self.assertEqual(
            service.apply(conflict_bundle["field_bundle_id"])["state"],
            "needs_triage",
        )
        conflict = service.conflicts(conflict_bundle["field_bundle_id"])[0]
        with self.assertRaises(ValidationError):
            service.resolve_conflict(
                conflict["integration_conflict_id"],
                "unsupported",
                expected_revision=0,
            )
        more = service.resolve_conflict(
            conflict["integration_conflict_id"],
            "needs_more_information",
            expected_revision=0,
        )
        self.assertEqual(more["state"], "needs_more_information")
        self.assertEqual(
            service.resolve_conflict(
                conflict["integration_conflict_id"],
                "keep_internal",
                expected_revision=1,
            )["state"],
            "resolved",
        )
        self.assertTrue(service.conflicts(conflict_bundle["field_bundle_id"])[0]["resolutions"])

        with self.assertRaises(NotFoundError):
            service.resolve_conflict("missing", "keep_internal", expected_revision=0)
        with self.assertRaises(ConflictError):
            service.resolve_conflict(
                conflict["integration_conflict_id"],
                "keep_internal",
                expected_revision=99,
            )

        inactive = self.manager.records.create(
            "sample-a", self.template["registration_id"], data={"name": "inactive"}
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE record_instances SET lifecycle_status='void' "
                "WHERE record_instance_id=?",
                (inactive["record_instance_id"],),
            )
        with self.assertRaises(ValidationError):
            service._normalize_action(
                {
                    "action_type": "record_revise",
                    "record_instance_id": inactive["record_instance_id"],
                    "base_record_revision_id": inactive["record_revision_id"],
                    "data": {},
                }
            )
        self.assertIsNone(
            service._normalize_action(
                {"action_type": "evidence_create", "locator": "urn:test:unscoped"}
            )["target_issue_id"]
        )
        parent_type = self.manager.registry.resolve(
            "org.example.v81/issue_type/parent@1.0.0"
        )
        self.manager.create_issue(
            "parent-only",
            "parent",
            issue_type_registration_id=parent_type["registration_id"],
        )
        with self.assertRaises(ValidationError):
            service._normalize_action(
                {
                    "action_type": "record_create",
                    "target_issue_id": "parent-only",
                    "template_reference": self.template["registration_id"],
                    "data": {},
                }
            )

        event_stub = {"event_hash": "event"}
        valid_action = service._normalize_action(
            {
                "action_type": "evidence_create",
                "locator": "urn:test:identity",
            }
        )
        identity = service._action_identity(valid_action)
        action_row = {
            "field_bundle_event_action_id": "action",
            "action_hash": "wrong",
            "target_issue_id": identity[0],
            "target_record_instance_id": identity[1],
            "base_record_revision_id": identity[2],
            "record_template_registration_id": identity[3],
            "record_template_content_hash": identity[4],
            "conflict_policy": identity[5],
            "validation_state": identity[6],
        }
        with self.assertRaises(ValidationError):
            service._apply_action(event_stub, action_row, [], "actor")
        with self.assertRaises(ConflictError):
            service._apply_action(event_stub, action_row, valid_action, "actor")
        action_row["action_hash"] = hashlib.sha256(
            canonical_json(valid_action).encode("utf-8")
        ).hexdigest()
        action_row["target_issue_id"] = "drift"
        with self.assertRaises(ConflictError):
            service._apply_action(event_stub, action_row, valid_action, "actor")

        conflicted_bundle = service.show(conflict_bundle["field_bundle_id"])
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE field_bundles SET state='failed' WHERE field_bundle_id=?",
                (conflicted_bundle["field_bundle_id"],),
            )
        with self.assertRaises(ConflictError):
            service.route(conflicted_bundle["field_bundle_id"])
        with self.assertRaises(ConflictError):
            service.apply(conflicted_bundle["field_bundle_id"])
        with self.assertRaises(ConflictError):
            service._apply_once(conflicted_bundle["field_bundle_id"])
        applied_bundle = service.show(unknown["field_bundle_id"])
        self.assertTrue(
            service._apply_once(applied_bundle["field_bundle_id"])["idempotent_replay"]
        )

        ready = service.route(
            failure["field_bundle_id"],
            expected_revision=retried["routing_state_revision"],
        )
        ready_bundle = service.show(ready["field_bundle_id"])
        with self.assertRaises(ConflictError):
            service._apply_once(
                ready["field_bundle_id"],
                expected_revision=ready_bundle["routing_state_revision"] + 1,
            )


if __name__ == "__main__":
    unittest.main()


class StoreRecoveryAndFindingTests(unittest.TestCase):
    def test_store_validation_backup_restore_and_finding_lifecycle(self) -> None:
        with self.assertRaises(ValidationError):
            Store._execute_sql_script(sqlite3.connect(":memory:"), "CREATE TABLE broken(")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "ledger"
            manager = IssueManager.initialize(root)
            finding_id = "migration_finding_test"
            with manager.store.transaction() as conn:
                conn.execute(
                    "INSERT INTO migration_findings(finding_id,migration_version,object_type,"
                    "object_id,classification,code,details_json,state) "
                    "VALUES (?,11,'field_action','action','requires_triage','test','{}','open')",
                    (finding_id,),
                )
            with self.assertRaises(NotFoundError):
                manager.store.resolve_migration_finding(
                    "missing", {"action": "resolve"}, actor="organizer-agent"
                )
            with self.assertRaises(ConflictError):
                manager.store.resolve_migration_finding(
                    finding_id, {}, actor="organizer-agent"
                )
            shown = manager.store.migration_finding(finding_id)
            self.assertEqual(shown["allowed_actions"], [])
            rejected = manager.store.validate_migration_finding_resolution(
                finding_id,
                {
                    "action": "waive",
                    "reason": "a reason is not proof",
                    "subject_hash": shown["subject_hash"],
                },
            )
            self.assertFalse(rejected["valid"])
            self.assertEqual(rejected["code"], "migration_resolution_handler_unknown")
            with self.assertRaises(ConflictError):
                manager.store.resolve_migration_finding(
                    finding_id,
                    {
                        "action": "waive",
                        "reason": "a reason is not proof",
                        "subject_hash": shown["subject_hash"],
                    },
                    actor="organizer-agent",
                )
            self.assertEqual(
                manager.store.row(
                    "SELECT COUNT(*) FROM migration_finding_resolution_attempts "
                    "WHERE finding_id=? AND accepted=0",
                    (finding_id,),
                )["COUNT(*)"],
                2,
            )
            self.assertEqual(manager.store.migration_findings()[0]["state"], "open")
            # This synthetic blocker exists only to exercise the rejection ledger.
            with manager.store.transaction() as conn:
                conn.execute(
                    "DELETE FROM migration_finding_resolution_attempts WHERE finding_id=?",
                    (finding_id,),
                )
                conn.execute("DELETE FROM migration_findings WHERE finding_id=?", (finding_id,))

            backup = Store.create_backup(root, label="v082-rehearsal", mode="full")
            verified = Store.verify_backup(root, backup["backup_id"])
            self.assertTrue(verified["ok"])
            manager.close()
            restored = Store.restore_backup(root, backup["backup_id"])
            self.assertEqual(restored["restored"], backup["backup_id"])
            reopened = IssueManager(root)
            try:
                self.assertTrue(reopened.doctor()["ok"])
                with patch("issue_manager.store.os.chmod", side_effect=OSError("acl")):
                    reopened.store._harden_permissions()
                original_policy = reopened.store.policy_path.read_text(encoding="utf-8")
                reopened.store.policy_path.write_text(
                    original_policy + "\n", encoding="utf-8", newline="\n"
                )
                with self.assertRaises(ValidationError):
                    reopened.store._record_policy_snapshot()
                reopened.store.policy_path.write_text(
                    original_policy, encoding="utf-8", newline="\n"
                )
            finally:
                reopened.close()

            journal_path = root / "runtime" / "restore_journal.json"
            journal_path.write_text("{", encoding="utf-8", newline="\n")
            Store._recover_interrupted_restore(root)
            journal_path.write_text(
                canonical_json({"pid": os.getpid(), "phase": "staging"}) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            Store._recover_interrupted_restore(root)
            journal_path.write_text(
                canonical_json({"pid": -1, "phase": "staging"}) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            Store._recover_interrupted_restore(root)
            self.assertEqual(
                json.loads(journal_path.read_text(encoding="utf-8"))["phase"],
                "staging_abandoned",
            )
            journal_path.write_text(
                canonical_json({"pid": -1, "phase": "completed"}) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            Store._recover_interrupted_restore(root)
            journal_path.write_text(
                canonical_json(
                    {
                        "pid": -1,
                        "phase": "switching",
                        "rollback_stage": str(root / "missing-rollback"),
                    }
                )
                + "\n",
                encoding="utf-8",
                newline="\n",
            )
            with self.assertRaises(ValidationError):
                Store._recover_interrupted_restore(root)
            Store._set_raw_maintenance(root / "no-ledger", False)
            empty_root = root / "empty-ledger"
            empty_root.mkdir()
            sqlite3.connect(empty_root / "issue_ledger.sqlite").close()
            Store._set_raw_maintenance(empty_root, False)

            rollback_stage = root / "runtime" / "recovery-stage"
            Store._prepare_restore_stage(root, backup["backup_id"], rollback_stage)
            journal_path.write_text(
                canonical_json(
                    {
                        "pid": -1,
                        "phase": "switching",
                        "rollback_stage": str(rollback_stage),
                    }
                )
                + "\n",
                encoding="utf-8",
                newline="\n",
            )
            Store._recover_interrupted_restore(root)
            self.assertEqual(
                json.loads(journal_path.read_text(encoding="utf-8"))["phase"],
                "auto_rolled_back",
            )
