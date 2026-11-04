from __future__ import annotations

import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from issue_manager.errors import (
    ConflictError,
    LeaseExpiredError,
    NotFoundError,
    ValidationError,
)
from issue_manager.errors import (
    PermissionError as ManagerPermissionError,
)
from issue_manager.projection import _mermaid, export_all
from issue_manager.service import IssueManager


class UpgradeQualityEdgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.manager = IssueManager.initialize(Path(self.temp.name) / "ledger")
        self.organizer = self.manager.credentials.path_for("organizer-agent")
        self.field = self.manager.credentials.path_for("experiment-agent")
        self.reviewer1 = self.manager.credentials.path_for("review-agent-1")
        self.reviewer2 = self.manager.credentials.path_for("review-agent-2")
        self.manager.create_issue("edge-target", "episode", "Edge target")
        self.manager.create_issue("edge-provider", "episode", "Edge provider")
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.manager.close)

    @staticmethod
    def _packet(request_id: str, **extra: object) -> dict[str, object]:
        return {
            "packet_version": 2,
            "request_id": request_id,
            "routing_hints": {"sample": "edge", "topic": "quality"},
            "observations": ["edge observation"],
            **extra,
        }

    @staticmethod
    def _v1_packet() -> dict[str, object]:
        return {
            "packet_version": 1,
            "request_id": "legacy-edge",
            "target": {"sample": "edge", "qubits": ["q1"]},
            "topic": "quality",
            "question": "legacy question",
            "actions": ["inspect"],
            "observations": [],
            "interpretation": [],
            "alternatives": [],
            "confidence": "medium",
            "next_action": "triage",
            "evidence": [],
        }

    @staticmethod
    def _changeset(intent: str = "edge maintenance") -> dict[str, object]:
        return {
            "changeset_version": 1,
            "intent": intent,
            "source_packet_ids": [],
            "expected_revisions": {},
            "operations": [
                {"op": "append_work", "issue_id": "edge-target", "body": intent}
            ],
        }

    @staticmethod
    def _reviewed_changeset() -> dict[str, object]:
        return {
            "changeset_version": 1,
            "intent": "review hard dependency",
            "source_packet_ids": [],
            "expected_revisions": {},
            "operations": [
                {
                    "op": "add_relation",
                    "consumer": "edge-target",
                    "provider": "edge-provider",
                    "relation_type": "depends_on",
                    "impact_policy": "hard",
                }
            ],
        }

    def test_intake_schema_identity_links_and_lease_edges(self) -> None:
        validate = self.manager.intake._validate_packet
        valid_v1 = self._v1_packet()
        invalid_packets: list[dict[str, object]] = [
            {"packet_version": 1},
            {**valid_v1, "target": {}},
            {**valid_v1, "confidence": "certain"},
            {"packet_version": 2, "observations": ["x"]},
            {
                "packet_version": 2,
                "request_id": "bad-hints",
                "routing_hints": [],
                "observations": ["x"],
            },
            {
                "packet_version": 2,
                "request_id": "exact-id",
                "routing_hints": {"issue_id": "edge-target"},
                "observations": ["x"],
            },
            {
                "packet_version": 2,
                "request_id": "bad-confidence",
                "confidence": "certain",
                "observations": ["x"],
            },
            {"packet_version": 3, "request_id": "future", "observations": ["x"]},
            {
                "packet_version": 2,
                "request_id": "bad-list",
                "observations": "not-a-list",
            },
            {"packet_version": 2, "request_id": "no-signal"},
            {
                "packet_version": 2,
                "request_id": "bad-evidence",
                "observations": ["x"],
                "evidence": [{"kind": "dataset"}],
            },
            {
                **valid_v1,
                "evidence": [
                    {
                        "kind": "dataset",
                        "locator": "/legacy::dataset=1",
                        "manifest": {},
                    }
                ],
            },
        ]
        for index, packet in enumerate(invalid_packets):
            with self.subTest(schema_case=index), self.assertRaises(ValidationError):
                validate(packet)
        validate(valid_v1)
        legacy_view = self.manager.intake._v2_view(valid_v1)
        self.assertEqual(legacy_view["packet_version"], 2)
        self.assertEqual(legacy_view["legacy_packet_version"], 1)

        packet = self._packet("stable-request")
        created = self.manager.intake.submit(
            packet, credential=self.organizer, idempotency_key="stable-first"
        )
        same = self.manager.intake.submit(
            packet, credential=self.organizer, idempotency_key="stable-second"
        )
        self.assertTrue(same["idempotent_replay"])
        with self.assertRaises(ConflictError):
            self.manager.intake.submit(
                {**packet, "observations": ["different"]},
                credential=self.organizer,
                idempotency_key="stable-third",
            )

        orphan_packet = self._packet("orphan-task")
        orphan = self.manager.intake.submit(
            orphan_packet, credential=self.organizer, idempotency_key="orphan-first"
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "DELETE FROM triage_tasks WHERE triage_task_id=?",
                (orphan["triage_task_id"],),
            )
        with self.assertRaises(ConflictError):
            self.manager.intake.submit(
                orphan_packet, credential=self.organizer, idempotency_key="orphan-second"
            )

        for index, relation in enumerate(
            (
                "not-an-object",
                {"type": "unknown", "packet_id": created["packet_id"]},
                {"type": "followup_of", "packet_id": "missing-packet"},
            )
        ):
            with self.subTest(relation_case=index), self.assertRaises(ValidationError):
                self.manager.intake.submit(
                    self._packet(f"bad-relation-{index}", related_packets=[relation]),
                    credential=self.organizer,
                )
        linked = self.manager.intake.submit(
            self._packet(
                "valid-relation",
                related_packets=[
                    {
                        "type": "followup_of",
                        "packet_id": created["packet_id"],
                        "rationale": "explicit lineage",
                    }
                ],
            ),
            credential=self.organizer,
        )
        self.assertTrue(self.manager.intake.show(linked["packet_id"])["links"])
        with self.assertRaises(NotFoundError):
            self.manager.intake.show("missing-packet")
        with self.assertRaises(NotFoundError):
            self.manager.intake._task("missing-packet")

        claimed = self.manager.intake.claim(created["packet_id"], credential=self.organizer)
        with self.assertRaises(ConflictError):
            self.manager.intake.claim(created["packet_id"], credential=self.field)
        self.assertEqual(
            self.manager.intake.heartbeat(created["packet_id"], credential=self.organizer)[
                "packet_id"
            ],
            created["packet_id"],
        )
        self.assertEqual(
            self.manager.intake.release(created["packet_id"], credential=self.organizer)["state"],
            "pending",
        )
        with self.assertRaises(ConflictError):
            self.manager.intake.heartbeat(created["packet_id"], credential=self.organizer)
        self.manager.intake.claim(created["packet_id"], credential=self.organizer)
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE triage_tasks SET lease_until='2000-01-01T00:00:00+00:00' "
                "WHERE packet_id=?",
                (created["packet_id"],),
            )
        with self.assertRaises(ConflictError):
            self.manager.intake.heartbeat(created["packet_id"], credential=self.organizer)
        self.assertEqual(claimed["state"], "claimed")

    def test_changeset_validation_review_and_optimistic_lock_edges(self) -> None:
        invalid: list[dict[str, object]] = [
            {**self._changeset(), "changeset_version": 2},
            {**self._changeset(), "intent": " "},
            {**self._changeset(), "source_packet_ids": "not-a-list"},
            {**self._changeset(), "source_packet_ids": ["missing-packet"]},
            {**self._changeset(), "expected_revisions": []},
            {
                **self._changeset(),
                "expected_revisions": {"edge-target": "not-an-object"},
            },
        ]
        for index, payload in enumerate(invalid):
            with self.subTest(create_case=index), self.assertRaises(ValidationError):
                self.manager.changesets.create(payload, credential=self.organizer)
        with self.assertRaises(NotFoundError):
            self.manager.changesets.show("missing-changeset")
        with self.assertRaises(NotFoundError):
            self.manager.changesets.claim_review(
                "missing-changeset", credential=self.reviewer1
            )
        with self.assertRaises(NotFoundError):
            self.manager.changesets.submit_review(
                "missing-changeset",
                decision="pass",
                rationale="missing",
                credential=self.reviewer1,
            )

        created = self.manager.changesets.create(
            self._changeset(), credential=self.organizer, idempotency_key="create-edge"
        )
        replay = self.manager.changesets.create(
            self._changeset(), credential=self.organizer, idempotency_key="create-edge"
        )
        self.assertTrue(replay["idempotent_replay"])
        self.assertTrue(self.manager.changesets.list_changesets())
        self.assertEqual(
            self.manager.changesets.list_changesets("draft")[0]["changeset_id"],
            created["changeset_id"],
        )
        with self.assertRaises(ConflictError):
            self.manager.changesets.claim_review(
                created["changeset_id"], credential=self.reviewer1
            )
        applied_directly = self.manager.changesets.apply(
            created["changeset_id"], credential=self.organizer
        )
        self.assertEqual(applied_directly["state"], "applied")
        self.assertTrue(
            self.manager.changesets.apply(
                created["changeset_id"], credential=self.organizer
            )["idempotent_replay"]
        )
        with self.assertRaises(ConflictError):
            self.manager.changesets.validate(
                created["changeset_id"], credential=self.organizer
            )
        with self.assertRaises(ConflictError):
            self.manager.changesets.submit_review(
                created["changeset_id"],
                decision="pass",
                rationale="already applied",
                credential=self.reviewer1,
            )

        hash_tamper = self.manager.changesets.create(
            self._changeset("hash tamper"), credential=self.organizer
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE changesets SET changeset_hash='tampered' WHERE changeset_id=?",
                (hash_tamper["changeset_id"],),
            )
        with self.assertRaises(ConflictError):
            self.manager.changesets.validate(
                hash_tamper["changeset_id"], credential=self.organizer
            )

        risk_tamper = self.manager.changesets.create(
            self._changeset("risk tamper"), credential=self.organizer
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE changesets SET risk_tier='T3' WHERE changeset_id=?",
                (risk_tamper["changeset_id"],),
            )
        with self.assertRaises(ConflictError):
            self.manager.changesets.validate(
                risk_tamper["changeset_id"], credential=self.organizer
            )

        optimistic = deepcopy(self._changeset("optimistic lock"))
        optimistic["expected_revisions"] = {
            "edge-target": {"working_revision": 99, "conclusion_revision": 0}
        }
        locked = self.manager.changesets.create(optimistic, credential=self.organizer)
        with self.assertRaises(ConflictError):
            self.manager.changesets.validate(locked["changeset_id"], credential=self.organizer)

        reviewed = self.manager.changesets.create(
            self._reviewed_changeset(), credential=self.organizer
        )
        self.manager.changesets.validate(reviewed["changeset_id"], credential=self.organizer)
        with self.assertRaises(ManagerPermissionError):
            self.manager.changesets.apply(reviewed["changeset_id"], credential=self.organizer)
        with self.assertRaises(ManagerPermissionError):
            self.manager.changesets.claim_review(
                reviewed["changeset_id"], credential=self.organizer
            )
        with self.assertRaises(ConflictError):
            self.manager.changesets.heartbeat_review(
                reviewed["changeset_id"], credential=self.reviewer1
            )
        with self.assertRaises(ConflictError):
            self.manager.changesets.release_review(
                reviewed["changeset_id"], credential=self.reviewer1
            )
        with self.assertRaises(ValidationError):
            self.manager.changesets.submit_review(
                reviewed["changeset_id"],
                decision="maybe",
                rationale=" ",
                credential=self.reviewer1,
            )
        with self.assertRaises(ManagerPermissionError):
            self.manager.changesets.submit_review(
                reviewed["changeset_id"],
                decision="pass",
                rationale="not claimed",
                credential=self.reviewer1,
            )

        assignment = self.manager.changesets.claim_review(
            reviewed["changeset_id"], credential=self.reviewer1
        )
        replay_assignment = self.manager.changesets.claim_review(
            reviewed["changeset_id"], credential=self.reviewer1
        )
        self.assertTrue(replay_assignment["idempotent_replay"])
        heartbeat = self.manager.changesets.heartbeat_review(
            reviewed["changeset_id"], credential=self.reviewer1
        )
        self.assertEqual(heartbeat["assignment_id"], assignment["assignment_id"])
        released = self.manager.changesets.release_review(
            reviewed["changeset_id"], credential=self.reviewer1
        )
        self.assertFalse(released["idempotent_replay"])
        self.assertTrue(
            self.manager.changesets.release_review(
                reviewed["changeset_id"], credential=self.reviewer1
            )["idempotent_replay"]
        )
        self.manager.changesets.claim_review(
            reviewed["changeset_id"], credential=self.reviewer1
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE changeset_review_assignments SET lease_until='2000-01-01T00:00:00+00:00' "
                "WHERE changeset_id=? AND reviewer_actor_id='review-agent-1'",
                (reviewed["changeset_id"],),
            )
        with self.assertRaises(LeaseExpiredError):
            self.manager.changesets.heartbeat_review(
                reviewed["changeset_id"], credential=self.reviewer1
            )
        with self.assertRaises(LeaseExpiredError):
            self.manager.changesets.submit_review(
                reviewed["changeset_id"],
                decision="pass",
                rationale="expired assignment",
                credential=self.reviewer1,
            )

        rejected = self.manager.changesets.create(
            self._reviewed_changeset(), credential=self.organizer
        )
        self.manager.changesets.validate(rejected["changeset_id"], credential=self.organizer)
        self.manager.changesets.claim_review(
            rejected["changeset_id"], credential=self.reviewer2
        )
        decision = self.manager.changesets.submit_review(
            rejected["changeset_id"],
            decision="reject",
            rationale="dependency direction is unsupported",
            credential=self.reviewer2,
        )
        self.assertEqual(decision["decision"], "reject")
        with self.assertRaises(ConflictError):
            self.manager.changesets.release_review(
                rejected["changeset_id"], credential=self.reviewer2
            )

    def test_nested_request_constraint_walk_rejects_code(self) -> None:
        with self.assertRaises(ValidationError):
            self.manager.evidence_requests._reject_executable_payload(
                [{"safe": "value"}, {"nested": {"code": "print('no')"}}]
            )

    def test_projection_replacement_and_hidden_relation_edges(self) -> None:
        self.manager.add_relation(
            "edge-target",
            "edge-provider",
            "depends_on",
            impact_policy="soft",
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE issues SET work_status='archived' WHERE issue_id='edge-provider'"
            )
        graph = _mermaid(self.manager)
        self.assertNotIn("edge-provider", graph)
        first = export_all(self.manager)
        second = export_all(self.manager)
        self.assertEqual(first["export_root"], second["export_root"])
        self.assertTrue((Path(second["export_root"]) / "evidence-proof-history.json").exists())
        previous = self.manager.store.ledger_dir / ".exports-previous"
        previous.mkdir()
        export_all(self.manager)
        final = self.manager.store.ledger_dir / "exports"
        final.replace(previous)
        with patch("issue_manager.projection._render_all", side_effect=RuntimeError("render")):
            with self.assertRaises(RuntimeError):
                export_all(self.manager)
        self.assertTrue(final.exists())
        self.assertFalse(previous.exists())


if __name__ == "__main__":
    unittest.main()
