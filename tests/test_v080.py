from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from issue_manager import IssueManager
from issue_manager.errors import ConflictError, PermissionError, ValidationError
from issue_manager.registry_service import prepare_bundle


def neutral_bundle(namespace: str = "org.example.neutral") -> dict:
    return {
        "manifest": {
            "bundle_format": "issue-manager-feature-bundle/v1",
            "namespace": namespace,
            "name": "measurements",
            "version": "1.0.0",
            "core_api": ">=0.8,<0.9",
            "registrations": [],
            "dependencies": [],
        },
        "registrations": [
            {
                "kind": "issue_type",
                "name": "specimen",
                "api_version": "issue-type/v1",
                "definition": {"allowed_children": [], "rollup_mode": "semantic"},
            },
            {
                "kind": "record_template",
                "name": "measurement",
                "api_version": "record-template/v1",
                "definition": {
                    "applies_to_issue_types": ["specimen"],
                    "additional_fields": False,
                    "fields": {
                        "label": {"type": "string", "required": True, "queryable": True},
                        "value": {
                            "type": "uncertain_quantity",
                            "allowed_units": ["m", "cm"],
                            "unit_factors": {"m": 1, "cm": 0.01},
                            "queryable": True,
                        },
                    },
                    "profiles": {
                        "draft": {"required": []},
                        "report": {"required": ["label", "value"]},
                    },
                },
            },
            {
                "kind": "mapping_profile",
                "name": "measurement-csv",
                "api_version": "mapping-profile/v1",
                "definition": {
                    "external_object_type": "measurement-row",
                    "external_object_id_field": "row_id",
                    "target_issue_field": "issue_id",
                    "target_template_ref": f"{namespace}/record_template/measurement@1.0.0",
                    "mappings": [
                        {"source": "label", "target": "label"},
                        {"source": "value_cm", "target": "value", "coerce": "number", "unit": "cm"},
                    ],
                },
            },
            {
                "kind": "report_template",
                "name": "measurement-summary",
                "api_version": "report-template/v1",
                "definition": {
                    "title": "Measurement summary",
                    "record_templates": [f"{namespace}/record_template/measurement@1.0.0"],
                    "record_validation_profile": "report",
                    "columns": [
                        {"field_path": "label", "title": "Label"},
                        {"field_path": "value", "title": "Value", "unit": "m", "round": 3},
                    ],
                    "sort": ["issue_id"],
                    "output_format": "json",
                },
            },
        ],
    }


class V080RegistryRecordReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.manager = IssueManager.initialize(Path(self.temporary.name) / "ledger")
        installed = self.manager.registry.install_bundle(neutral_bundle())
        self.bundle_id = installed["bundle_id"]
        self.manager.registry.activate_bundle(self.bundle_id)
        issue_type = self.manager.registry.resolve(
            "org.example.neutral/issue_type/specimen@1.0.0"
        )
        self.manager.create_issue(
            "specimen-a",
            "specimen",
            issue_type_registration_id=issue_type["registration_id"],
        )

    def tearDown(self) -> None:
        self.manager.close()
        self.temporary.cleanup()

    def test_registry_identity_lifecycle_and_declarative_boundary(self) -> None:
        validated = self.manager.registry.validate_bundle(neutral_bundle())
        replay = self.manager.registry.install_bundle(neutral_bundle())
        self.assertTrue(replay["idempotent_replay"])
        changed = neutral_bundle()
        changed["registrations"][0]["definition"]["rollup_mode"] = "mechanical"
        with self.assertRaises(ConflictError):
            self.manager.registry.install_bundle(changed)
        second = neutral_bundle("org.example.other")
        second_result = self.manager.registry.install_bundle(second)
        self.assertNotEqual(validated["content_hash"], second_result["content_hash"])
        malicious = neutral_bundle("org.example.unsafe")
        malicious["registrations"][0]["definition"]["python"] = "eval('x')"
        with self.assertRaises(ValidationError):
            prepare_bundle(malicious)
        executable = neutral_bundle("org.example.executable")
        executable["registrations"] = [
            {
                "kind": "import_adapter",
                "name": "unsafe-adapter",
                "definition": {"protocol": "adapter/v1"},
            }
        ]
        with self.assertRaises(PermissionError):
            self.manager.registry.install_bundle(executable)
        self.manager.registry.disable_bundle(self.bundle_id, reason="test disable")
        historical = self.manager.registry.resolve(
            "org.example.neutral/record_template/measurement@1.0.0",
            for_creation=False,
        )
        self.assertEqual(historical["state"], "disabled")
        with self.assertRaises(ConflictError):
            self.manager.registry.resolve(
                "org.example.neutral/record_template/measurement@1.0.0"
            )

    def test_record_revision_index_and_report_concurrency_gate(self) -> None:
        record = self.manager.records.create(
            "specimen-a",
            "org.example.neutral/record_template/measurement@1.0.0",
            data={"label": "length", "value": {"value": 125, "unit": "cm", "uncertainty": 1}},
        )
        first = self.manager.records.show(record["record_instance_id"])
        self.assertEqual(first["current_revision"]["data"]["value"]["unit"], "cm")
        indexed = self.manager.store.row(
            "SELECT number_value,unit_code FROM record_value_index WHERE record_revision_id=? "
            "AND field_path='value'",
            (record["record_revision_id"],),
        )
        self.assertEqual(indexed, {"number_value": 125.0, "unit_code": "cm"})
        prepared = self.manager.reports.prepare(
            "org.example.neutral/report_template/measurement-summary@1.0.0",
            scope={"issue_id": "specimen-a"},
        )
        self.assertEqual(prepared["rows"], 1)
        self.manager.records.revise(
            record["record_instance_id"],
            {"label": "length", "value": {"value": 126, "unit": "cm", "uncertainty": 1}},
            expected_revision_id=record["record_revision_id"],
        )
        with self.assertRaises(ConflictError):
            self.manager.reports.build(prepared["report_build_id"])
        self.assertEqual(
            self.manager.reports.show(prepared["report_build_id"])["state"], "stale"
        )
        prepared_again = self.manager.reports.prepare(
            "org.example.neutral/report_template/measurement-summary@1.0.0",
            scope={"issue_id": "specimen-a"},
        )
        built = self.manager.reports.build(prepared_again["report_build_id"])
        self.assertTrue(Path(built["output_path"]).is_file())
        self.assertTrue(
            self.manager.reports.reproduce(prepared_again["report_build_id"])[
                "reproducible"
            ]
        )
        rebuilt = self.manager.records.rebuild_index()
        self.assertEqual(rebuilt["revisions"], 2)


class V080ImportAndFieldBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.manager = IssueManager.initialize(self.root / "ledger")
        installed = self.manager.registry.install_bundle(neutral_bundle())
        self.manager.registry.activate_bundle(installed["bundle_id"])
        issue_type = self.manager.registry.resolve(
            "org.example.neutral/issue_type/specimen@1.0.0"
        )
        self.manager.create_issue(
            "specimen-a",
            "specimen",
            issue_type_registration_id=issue_type["registration_id"],
        )

    def tearDown(self) -> None:
        self.manager.close()
        self.temporary.cleanup()

    def _csv_job(self, namespace: str, value: str = "12.5") -> str:
        source = self.root / f"source-{namespace.replace('.', '-')}"
        source.mkdir(exist_ok=True)
        with (source / "records.csv").open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(
                stream, fieldnames=["row_id", "issue_id", "label", "value_cm", "extra"]
            )
            writer.writeheader()
            writer.writerow(
                {
                    "row_id": "record-001",
                    "issue_id": "specimen-a",
                    "label": "width",
                    "value_cm": value,
                    "extra": "preserve me",
                }
            )
        job = self.manager.imports.inspect(
            source,
            adapter_name="csv-table-v1",
            source_namespace=namespace,
            source_owner="owner",
        )
        self.manager.imports.stage(
            job["import_job_id"],
            mapping_reference="org.example.neutral/mapping_profile/measurement-csv@1.0.0",
        )
        self.manager.imports.validate(job["import_job_id"])
        return job["import_job_id"]

    def test_external_identity_namespace_idempotency_and_unmapped_preservation(self) -> None:
        first_job = self._csv_job("lab.one")
        first = self.manager.imports.apply(first_job)
        self.assertEqual(first["state"], "applied")
        self.assertEqual(
            self.manager.imports.show(first_job)["items"][0]["extensions"]["unmapped"],
            {"extra": "preserve me", "issue_id": "specimen-a"},
        )
        second_job = self._csv_job("lab.two")
        second = self.manager.imports.apply(second_job)
        self.assertEqual(second["state"], "applied")
        mapping_count = self.manager.store.row(
            "SELECT COUNT(*) AS n FROM external_object_mappings WHERE external_object_id='record-001'"
        )
        self.assertEqual(mapping_count["n"], 2)
        replay = self.manager.imports.apply(first_job)
        self.assertTrue(replay["idempotent_replay"])

    def test_field_bundle_replay_and_conflict_triage(self) -> None:
        record = self.manager.records.create(
            "specimen-a",
            "org.example.neutral/record_template/measurement@1.0.0",
            data={"label": "base", "value": {"value": 1, "unit": "m"}},
        )
        bundle = {
            "manifest": {
                "bundle_id": "field-bundle-1",
                "bundle_version": "issue-manager-field-bundle/v1",
                "created_by": "owner",
                "created_at": "2026-08-10T10:00:00+08:00",
                "source_namespace": "lab.field",
                "source_owner": "owner",
                "base_activity_cursor": 0,
                "known_issue_revisions": {"specimen-a": {"working_revision": 0}},
                "attachments": [],
            },
            "events": [
                {
                    "event_id": "event-1",
                    "event_type": "record_patch",
                    "record_instance_id": record["record_instance_id"],
                    "base_record_revision_id": record["record_revision_id"],
                    "patch": {"label": "offline"},
                }
            ],
        }
        preview = self.manager.field_bundles.upload(bundle, dry_run=True)
        self.assertEqual(preview["state"], "staged")
        self.manager.records.revise(
            record["record_instance_id"],
            {"label": "online", "value": {"value": 1, "unit": "m"}},
            expected_revision_id=record["record_revision_id"],
        )
        uploaded = self.manager.field_bundles.upload(bundle)
        self.assertEqual(uploaded["state"], "needs_triage")
        self.assertEqual(
            self.manager.field_bundles.show("field-bundle-1")["events"][0][
                "processing_state"
            ],
            "triage",
        )
        self.assertTrue(self.manager.field_bundles.upload(bundle)["idempotent_replay"])
        changed = json.loads(json.dumps(bundle))
        changed["events"][0]["patch"]["label"] = "different"
        with self.assertRaises(ConflictError):
            self.manager.field_bundles.upload(changed)


if __name__ == "__main__":
    unittest.main()
