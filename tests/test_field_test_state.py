import json

from scripts import field_test_state
from scripts.field_test_state import _collect_scoped_evidence_ids


def test_collect_scoped_evidence_ids_reads_public_scoped_projection_fields():
    projection = {
        "roots": ["ev_root"],
        "support_ids": ["ev_support"],
        "discovery_ids": ["ev_discovery"],
        "candidate_states": [
            {"candidate_id": "ev_candidate", "status": "T"},
            {"candidate_id": "ev_support", "status": "T"},
        ],
    }

    assert _collect_scoped_evidence_ids(projection) == {
        "ev_root", "ev_support", "ev_discovery", "ev_candidate"
    }


def test_collect_scoped_evidence_ids_ignores_non_projection_shapes():
    projection = {
        "evidence": [{"evidence_id": "not-a-scoped-candidate"}],
        "roots": "invalid",
        "candidate_states": [None, {"candidate_id": 4}],
    }

    assert _collect_scoped_evidence_ids(projection) == set()


def test_public_snapshot_reads_currentness_value_from_inspect_issue_shape(tmp_path, monkeypatch):
    token_file = tmp_path / "session.token"
    token_file.write_text(json.dumps({"token": "test-token"}), encoding="utf-8")
    binding = {"endpoint": "http://manager.invalid", "token_file": str(token_file)}
    runtime = {"run_dir": str(tmp_path)}
    public_result = {
        "issue": {"revision": 1, "current_conclusion_id": "issue@r1"},
        "current_conclusion": {
            "currentness": {"currentness": "current"},
        },
        "scoped_context": {"roots": [], "support_ids": [], "discovery_ids": []},
    }
    monkeypatch.setattr(field_test_state, "_http", lambda *args, **kwargs: public_result)

    snapshot = field_test_state._public_snapshot(runtime, "issue", "conclusion", binding)

    assert snapshot["conclusion_currentness"] == "current"
