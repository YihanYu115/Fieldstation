"""Finite assessment records over frozen inputs; no role or model semantics."""
from __future__ import annotations

import hashlib
import json

from .errors import ConflictError, ValidationError
from .store import canonical_json


def text(value, limit):
    return isinstance(value, str) and bool(value.strip()) and len(value) <= limit


def references(value, *, empty=False):
    return (isinstance(value, list) and (empty or bool(value)) and len(value) <= 16
            and all(text(v, 512) for v in value) and len(set(value)) == len(value))


def validate_spec(spec):
    if (not isinstance(spec, dict) or set(spec) != {
            "target_proposal_id", "change_refs", "policy", "purpose"}
            or not (spec["target_proposal_id"] is None or text(spec["target_proposal_id"], 512))
            or not references(spec["change_refs"])
            or not text(spec["policy"], 128) or not text(spec["purpose"], 128)):
        raise ValidationError("Expected bounded assessment target, changes, policy and purpose")
    return spec


def stored_spec(conn, item_id):
    row = conn.execute("SELECT payload_json FROM workflow_events WHERE work_item_id=? "
                       "AND event_type='work_item.assessment' ORDER BY rowid LIMIT 1", (item_id,)).fetchone()
    return json.loads(row["payload_json"])["assessment"] if row else None


def freeze(spec, prepared):
    selected = prepared["materials"].get("evidence", {})
    if not set(spec["change_refs"]) <= set(selected):
        raise ValidationError("Assessment changes must be selected frozen Evidence")
    target = None
    if spec["target_proposal_id"] is not None:
        target = next((p for p in prepared["prior_proposals"]
                       if p["proposal_id"] == spec["target_proposal_id"]), None)
        if target is None:
            raise ValidationError("Assessment target must be a same-Issue frozen proposal")
        target = {k: target[k] for k in ("proposal_id", "proposal_hash", "state")}
    return dict(spec=spec, target=target)


def validate_output(output):
    if (set(output) != {"action", "package_id", "decision", "handled_refs", "evidence_refs", "reason"}
            or not text(output["package_id"], 512)
            or output["decision"] not in ("revised", "no_change", "unresolved")
            or not references(output["handled_refs"], empty=True)
            or not references(output["evidence_refs"], empty=True)
            or not text(output["reason"], 8000)):
        raise ValidationError("Expected bounded assessment decision, handled changes and rationale")


def check_result(result, package):
    records = [o for o in result["outputs"] if o["action"] == "record_assessment"]
    binding = package.get("assessment")
    if binding is None:
        if records:
            raise ValidationError("Assessment requires a task-bound frozen target")
        return None
    if len(records) != 1:
        raise ValidationError("An assessment task requires exactly one assessment record")
    record = records[0]
    prepared = package["prepared_context"]
    if record["package_id"] != prepared["package_id"]:
        raise ValidationError("Assessment package differs from frozen input")
    if not set(record["handled_refs"]) <= set(binding["spec"]["change_refs"]):
        raise ValidationError("Assessment cannot handle changes outside its task")
    if not set(record["evidence_refs"]) <= set(prepared["materials"].get("evidence", {})):
        raise ValidationError("Assessment evidence is outside frozen materials")
    decision = record["decision"]
    proposals = [o for o in result["outputs"] if o["action"] == "create_proposal"]
    if (len(proposals) != (1 if decision == "revised" else 0)
            or len(result["outputs"]) != 1 + len(proposals)):
        raise ValidationError("Only revised assessments may atomically create one proposal")
    if decision == "unresolved":
        if result["outcome"] != "blocked" or record["handled_refs"]:
            raise ValidationError("Unresolved assessment is blocked and establishes no coverage")
    elif (not record["handled_refs"] or not record["evidence_refs"]
          or result["outcome"] == "blocked"):
        raise ValidationError("A decided assessment needs handled changes and evidence")
    if result["outcome"] == "complete" and set(record["handled_refs"]) != set(binding["spec"]["change_refs"]):
        raise ValidationError("Completion must handle the whole declared change set")
    target = binding["target"]
    if decision == "no_change" and target is None:
        raise ValidationError("No-change requires an existing target in this increment")
    if proposals and proposals[0].get("revises_proposal_id") != (target["proposal_id"] if target else None):
        raise ValidationError("Revision must address the task-bound target")
    return record


def check_current(manager, package):
    target = package["assessment"]["target"]
    if target:
        current = manager.store.row("SELECT proposal_hash,state FROM proposals WHERE proposal_id=?",
                                    (target["proposal_id"],))
        if not current or any(current[k] != target[k] for k in ("proposal_hash", "state")):
            raise ConflictError("Assessment target changed after claim")


def saved_record(manager, record, package, domain_objects):
    binding = package["assessment"]
    target = binding["target"]
    if record["decision"] == "revised":
        obj = next(o for o in domain_objects if o["type"] == "proposal")
        target = manager.store.row("SELECT proposal_id,proposal_hash,state FROM proposals WHERE proposal_id=?",
                                   (obj["id"],))
        target = dict(target)
    prepared = package["prepared_context"]
    # Anchors, not a second copy of source material or mutable task state.
    def digest(value):
        return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    return dict(contract="workflow-assessment-record/v1", **record,
                issue_id=package["input_baseline"]["issue_id"],
                target_before=binding["target"], target_after=target,
                policy=binding["spec"]["policy"], purpose=binding["spec"]["purpose"],
                change_hashes={ref: digest(prepared["materials"]["evidence"][ref])
                               for ref in record["handled_refs"]},
                material_digest=digest(prepared["materials"]),
                decision_recorded=True, scientific_acceptance="pending")
