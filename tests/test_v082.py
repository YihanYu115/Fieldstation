from __future__ import annotations

import copy
import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_v081 import v81_bundle

from issue_manager import IssueManager
from issue_manager.errors import AdapterExecutionError, ConflictError, ValidationError
from issue_manager.field_bundle_service import FIELD_BUNDLE_VERSION
from issue_manager.registry_service import (
    _validate_json_schema_definition,
    build_issue_type_semantics,
    validate_json_instance,
)
from issue_manager.store import canonical_json, now


class V082Base(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        bundle = v81_bundle()
        for entry in bundle["registrations"]:
            if entry["kind"] == "report_template":
                entry["definition"]["field_policies"]["missing"] = "block"
        self.manager = IssueManager.initialize(self.root / "ledger")
        installed = self.manager.registry.install_bundle(bundle)
        self.manager.registry.activate_bundle(installed["bundle_id"])
        self.issue_type = self.manager.registry.resolve(
            "org.example.v81/issue_type/specimen@1.0.0"
        )
        self.record_template = self.manager.registry.resolve(
            "org.example.v81/record_template/measurement@1.0.0"
        )
        self.report_template = self.manager.registry.resolve(
            "org.example.v81/report_template/summary@1.0.0"
        )
        self.manager.create_issue(
            "sample-a",
            "specimen",
            issue_type_registration_id=self.issue_type["registration_id"],
        )
        self.organizer = self.manager.credentials.path_for("organizer-agent")

    def tearDown(self) -> None:
        self.manager.close()
        self.temporary.cleanup()

    def bundle(self, bundle_id: str, event: dict) -> dict:
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

    def publish(self) -> None:
        prepared = self.manager.prepare_refresh("sample-a")
        issue = self.manager.show_issue("sample-a")
        proposal = self.manager.proposals.create(
            {
                "issue_id": "sample-a",
                "expected_conclusion_revision": issue["conclusion_revision"],
                "status": "provisional",
                "statement": "report basis",
                "basis_snapshot_token": prepared["proposal_template"]["basis_snapshot_token"],
                "structured_outputs": {"result": "ok"},
                "limitations": [],
                "evidence_refs": [],
                "basis": [],
            },
            credential=self.organizer,
        )
        self.manager.proposals.validate(proposal["proposal_id"], credential=self.organizer)
        self.manager.proposals.apply(proposal["proposal_id"], credential=self.organizer)


class V082ConcurrencyAndReportTests(V082Base):
    def test_field_record_revise_requires_base_and_conflicts_atomically(self) -> None:
        record = self.manager.records.create(
            "sample-a", self.record_template["registration_id"], data={"name": "base"}
        )
        missing = self.manager.field_bundles.upload(
            self.bundle(
                "missing-base",
                {
                    "event_id": "patch-missing",
                    "event_type": "record_patch",
                    "record_instance_id": record["record_instance_id"],
                    "data": {"name": "offline"},
                },
            )
        )
        routed_missing = self.manager.field_bundles.route(missing["field_bundle_id"])
        self.assertEqual(routed_missing["state"], "needs_triage")
        self.assertEqual(
            routed_missing["needs_triage"][0]["reason"],
            "record_base_revision_required",
        )

        uploaded = self.manager.field_bundles.upload(
            self.bundle(
                "concurrent",
                {
                    "event_id": "patch-concurrent",
                    "event_type": "record_patch",
                    "record_instance_id": record["record_instance_id"],
                    "base_record_revision_id": record["record_revision_id"],
                    "data": {"name": "offline"},
                },
            )
        )
        self.assertEqual(
            self.manager.field_bundles.route(uploaded["field_bundle_id"])["state"],
            "ready",
        )
        online = self.manager.records.revise(
            record["record_instance_id"],
            {"name": "online"},
            expected_revision_id=record["record_revision_id"],
        )
        applied = self.manager.field_bundles.apply(uploaded["field_bundle_id"])
        self.assertEqual(applied["state"], "needs_triage")
        self.assertEqual(
            self.manager.records.show(record["record_instance_id"])["current_revision_id"],
            online["record_revision_id"],
        )
        conflict = self.manager.field_bundles.conflicts("concurrent")[0]
        resolved = self.manager.field_bundles.resolve_conflict(
            conflict["integration_conflict_id"],
            "accept_as_new_revision",
            expected_revision=0,
        )
        self.assertEqual(resolved["state"], "resolved")
        self.assertEqual(len(self.manager.records.history(record["record_instance_id"])), 3)
        replay = self.manager.field_bundles.resolve_conflict(
            conflict["integration_conflict_id"],
            "accept_as_new_revision",
            expected_revision=1,
        )
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(len(self.manager.records.history(record["record_instance_id"])), 3)

    def test_filtered_rows_are_not_direct_basis_but_can_affect_consumed_conclusions(self) -> None:
        selected = self.manager.records.create(
            "sample-a",
            self.record_template["registration_id"],
            data={
                "name": "A",
                "measurement": {"value": 1.0, "unit": "m"},
                "optional": "complete",
            },
        )
        filtered = self.manager.records.create(
            "sample-a", self.record_template["registration_id"], data={"name": "B"}
        )
        self.publish()
        prepared = self.manager.reports.prepare(
            self.report_template["registration_id"],
            scope={"issue_id": "sample-a"},
            query={"name": {"eq": "A"}},
        )
        self.assertEqual(prepared["rows"], 1)
        self.assertEqual(prepared["query_filtered_count"], 1)
        record_inputs = {
            item["object_id"]
            for item in prepared["inputs"]
            if item["object_type"] == "record_revision"
        }
        self.assertEqual(record_inputs, {selected["record_revision_id"]})
        self.manager.records.revise(
            filtered["record_instance_id"],
            {"name": "B2"},
            expected_revision_id=filtered["record_revision_id"],
        )
        # The report excludes B, but its selected Issue conclusion consumed B
        # in its prepared context. That indirect dependency remains effective.
        with self.assertRaises(ConflictError):
            self.manager.reports.build(prepared["report_build_id"])
        self.publish()
        refreshed = self.manager.reports.prepare(
            self.report_template["registration_id"], scope={"issue_id": "sample-a"}, query={"name": {"eq": "A"}})
        self.assertEqual(self.manager.reports.build(refreshed["report_build_id"])["state"], "built")
        with self.assertRaises(ValidationError):
            self.manager.reports.prepare(
                self.report_template["registration_id"],
                scope={"issue_id": "sample-a"},
                query={"optional": {"exists": False}},
            )

    def test_scope_v2_rejects_bare_name_ambiguity(self) -> None:
        other = self.manager.registry.install_bundle(v81_bundle("org.example.other"))
        self.manager.registry.activate_bundle(other["bundle_id"])
        with self.assertRaises(ConflictError) as caught:
            self.manager.reports.prepare(
                self.report_template["registration_id"],
                scope={"issue_type": "specimen"},
            )
        self.assertEqual(caught.exception.details["code"], "issue_type_scope_ambiguous")
        prepared = self.manager.reports.prepare(
            self.report_template["registration_id"],
            scope={
                "issue_type_registration_ids": [self.issue_type["registration_id"]]
            },
        )
        self.assertEqual(
            prepared["normalized_scope"]["issue_type_registration_ids"],
            [self.issue_type["registration_id"]],
        )


class V082RendererTests(V082Base):
    def _install_renderer(self) -> str:
        renderer_script = self.root / "renderer.py"
        renderer_script.write_text(
            "import base64,json,os,sys\n"
            "request=json.load(sys.stdin)['request']\n"
            "content=(json.dumps(request['neutral_report_model'],sort_keys=True)+'\\n').encode()\n"
            "sensitive=[k for k in os.environ if k.startswith('ISSUE') or 'LEDGER' in k or 'TOKEN' in k]\n"
            "print(json.dumps({'content_base64':base64.b64encode(content).decode(),"
            "'media_type':'text/plain','extension':'txt','metadata':{'sensitive_environment':sensitive}}))\n",
            encoding="utf-8",
            newline="\n",
        )
        if os.name == "nt":
            executable = self.root / "renderer.cmd"
            executable.write_text(
                f'@"{sys.executable}" "{renderer_script}"\n',
                encoding="utf-8",
                newline="\n",
            )
        else:
            executable = renderer_script
            executable.write_text(
                f"#!{sys.executable}\n" + renderer_script.read_text(encoding="utf-8"),
                encoding="utf-8",
                newline="\n",
            )
            executable.chmod(0o755)
        descriptor = {
            "kind": "report",
            "name": "plain-renderer",
            "version": "1.0.0",
            "protocol_version": "issue-manager-adapter/v1",
            "timeout_seconds": 10,
            "maximum_output_bytes": 1024 * 1024,
        }
        self.manager.adapters.install(descriptor, executable)
        bundle = {
            "manifest": {
                "bundle_format": "issue-manager-feature-bundle/v1",
                "namespace": "org.example.renderer",
                "name": "renderer",
                "version": "1.0.0",
                "core_api": ">=0.8,<0.9",
                "registrations": [],
                "dependencies": [],
            },
            "registrations": [
                {
                    "kind": "report_renderer",
                    "name": "plain",
                    "version": "1.0.0",
                    "api_version": "report-renderer/v1",
                    "definition": {
                        "adapter_name": "plain-renderer",
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
                    },
                }
            ],
        }
        installed = self.manager.registry.install_bundle(bundle)
        self.manager.registry.activate_bundle(installed["bundle_id"])
        return "org.example.renderer/report_renderer/plain@1.0.0"

    def test_renderer_executable_drift_after_process_discards_result(self) -> None:
        self._install_renderer()
        execute = self.manager.adapters._bounded_execute

        def mutate_after_execution(adapter, request, **kwargs):
            result = execute(adapter, request, **kwargs)
            executable = Path(adapter["executable_path"])
            executable.write_bytes(executable.read_bytes() + b"\n")
            return result

        with patch.object(self.manager.adapters, "_bounded_execute", side_effect=mutate_after_execution):
            with self.assertRaises(AdapterExecutionError) as error:
                self.manager.adapters.execute("plain-renderer@1.0.0", kind="report", payload={"neutral_report_model": {}})
        self.assertEqual(error.exception.code, "adapter_identity_drift")
        self.assertEqual(error.exception.details["phase"], "after_execution")

    def test_registered_renderer_build_and_drift_gate(self) -> None:
        renderer_reference = self._install_renderer()
        template = self.manager.registry.resolve(self.report_template["registration_id"])
        definition = copy.deepcopy(template["definition"])
        definition["renderer_reference"] = renderer_reference
        definition["renderer_config"] = {}
        updated_template_hash = hashlib.sha256(
            canonical_json(
                {
                    "namespace": template["namespace"],
                    "kind": template["kind"],
                    "name": template["name"],
                    "version": template["version"],
                    "api_version": template["api_version"],
                    "definition": definition,
                }
            ).encode("utf-8")
        ).hexdigest()
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE registry_entries SET definition_json=?,content_hash=? "
                "WHERE registration_id=?",
                (
                    canonical_json(definition),
                    updated_template_hash,
                    template["registration_id"],
                ),
            )
        self.publish()
        self.manager.records.create(
            "sample-a",
            self.record_template["registration_id"],
            data={
                "name": "renderer",
                "measurement": {"value": 1.0, "unit": "m"},
                "optional": "complete",
            },
        )
        prepared = self.manager.reports.prepare(
            template["registration_id"], scope={"issue_id": "sample-a"}
        )
        self.assertEqual(prepared["renderer_snapshot"]["renderer_kind"], "adapter")
        built = self.manager.reports.build(prepared["report_build_id"])
        self.assertEqual(built["state"], "built")
        self.assertEqual(
            built["render_receipt"]["metadata"]["sensitive_environment"], []
        )
        reproduced = self.manager.reports.reproduce(
            prepared["report_build_id"], rerun_renderer=True
        )
        self.assertTrue(reproduced["reproducible"])

        second = self.manager.reports.prepare(
            template["registration_id"], scope={"issue_id": "sample-a"}
        )
        self.manager.adapters.set_enabled(
            "plain-renderer@1.0.0", False, kind="report", reason="drift test"
        )
        with self.assertRaises(ConflictError):
            self.manager.reports.build(second["report_build_id"])
        self.assertEqual(
            self.manager.reports.show(second["report_build_id"])["state"], "stale"
        )


class V082StrictJsonAndMigrationTests(unittest.TestCase):
    def test_required_only_policy_and_non_finite_json(self) -> None:
        semantics = build_issue_type_semantics(
            "legacy",
            "issue-type/v1",
            {"conclusion_schema": "score"},
            legacy_policy={
                "conclusion_schemas": {"score": {"required": ["score"]}},
                "publication": {},
                "publication_requirements": {},
            },
        )
        schema = semantics["conclusion"]["structured_outputs_schema"]
        self.assertEqual(schema["properties"]["score"], {})
        _validate_json_schema_definition(schema, path="test")
        self.assertEqual(validate_json_instance({"score": 2.5}, schema), [])
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value), self.assertRaises(ValidationError) as caught:
                canonical_json({"nested": [value]})
            self.assertEqual(
                caught.exception.details["errors"][0]["code"], "non_finite_number"
            )
