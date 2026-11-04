"""Atomic role-neutral publication and relinquishment using existing workflow history."""

from __future__ import annotations

import hashlib
import json

from . import agent_workflow_assessments as assessments
from . import agent_workflow_relations as relations
from .agent_workflow_contracts import (
    RESULT_CONTRACT_V2,
    validate_result,
)
from .agent_workflow_proposals import check_current, check_source, create
from .errors import ConflictError, PermissionError, ValidationError
from .store import canonical_json, new_id, now


def submit_result(service, attempt_id, *, result, expected_mandate_revision,
                  expected_fence, expected_work_item_revision,
                  expected_issue_working_revision, auth, idempotency_key):
    service._require(auth, "workflow.execute", "workflow.commit")
    result = validate_result(result)
    is_v2 = result["contract"] == RESULT_CONTRACT_V2
    key = service._require_key(idempotency_key)
    fences = dict(expected_mandate_revision=expected_mandate_revision,
                  expected_fence=expected_fence,
                  expected_work_item_revision=expected_work_item_revision)
    payload = dict(attempt_id=attempt_id, result=result, **fences,
                   expected_issue_working_revision=expected_issue_working_revision)
    operation = service._operation("attempt.submit_result", auth)
    store = service.store
    with store.transaction() as conn:
        replay = store.idempotency_lookup(operation, key, payload)
        if replay:
            return {**replay, "idempotent_replay": True}
        attempt, item, mandate = service._assert_live_attempt(
            conn, attempt_id, auth=auth, **fences
        )
        permissions = json.loads(mandate["permissions_json"])
        if (not permissions.get("can_commit")
                or not service._within_scope(mandate, item["issue_id"], item["role"])):
            raise PermissionError("Publication is outside the authorized scope")
        for contribution in result["outputs"]:
            action = contribution["action"]
            if (action not in permissions["allowed_actions"]
                    or action not in json.loads(item["allowed_actions_json"])):
                raise PermissionError("Business action is outside the authorized scope")
            service._require(auth, "workflow.commit" if action in {"record_assessment", "propose_applicability"} else
                             "evidence.write" if action == "add_evidence" else "conclusion.propose")
            if action == "create_verification":
                service._require(auth, "changeset.submit")
        if attempt["issue_working_revision"] != expected_issue_working_revision:
            raise ConflictError("Result baseline differs from the frozen work package")
        package = json.loads(conn.execute(
            "SELECT package_json FROM workflow_work_packages WHERE attempt_id=?", (attempt_id,)
        ).fetchone()[0])
        refs = {m["ref"] for m in package["inputs"]}
        if any(c["source_ref"] not in refs for c in result["outputs"] if c["action"] == "add_evidence"):
            raise ValidationError("Contribution source is outside the frozen inputs")
        assessment = assessments.check_result(result, package)
        related = [c for c in result["outputs"] if "related_evidence" in c]
        for contribution in related:
            if is_v2:
                relations.check_v2(
                    service, contribution, package, permissions, auth,
                    {output["local_ref"] for output in result["outputs"]},
                )
            else:
                relations.check(service, contribution, package, permissions, auth)
        domain_outputs = [c for c in result["outputs"] if c["action"] in {"create_proposal", "create_verification"}]
        for contribution in domain_outputs:
            check_source(contribution, package)
        if (result["outcome"] == "complete" and not result["outputs"]
                and not any(o["business_action"] == "add_evidence"
                            for o in package["prior_outputs"])):
            raise ValidationError("Completion requires at least one saved business contribution")
        current = conn.execute("SELECT working_revision FROM issues WHERE issue_id=?",
                               (item["issue_id"],)).fetchone()[0]
        stale = current != expected_issue_working_revision
        if domain_outputs or assessment or related:
            try:
                check_current(service.manager, package, domain_outputs[0] if domain_outputs else None)
                if assessment:
                    assessments.check_current(service.manager, package)
            except ConflictError:
                stale = True
        exhausted = mandate["commits_used"] >= service._budget(mandate)["max_commits"]
        # Always retain authorized content even when fresh judgment or budget is needed.
        reason = "input_stale" if stale else "max_commits exhausted" if exhausted else None
        published = not stale and not exhausted
        output_ids, evidence_ids = [], []
        domain_objects = []
        assessment_ids = []
        evidence_bindings = []
        relation_ids = []
        timestamp = now()

        def output(body, kind, object_id=None, object_type=None, action=None):
            output_id = new_id("workflow_output")
            conn.execute("INSERT INTO workflow_outputs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
                output_id, mandate["mandate_id"], item["work_item_id"], attempt_id,
                auth.actor_id, auth.run_id, kind, canonical_json(body),
                action, object_type, object_id, timestamp,
            ))
            output_ids.append(output_id)
            return output_id

        if published:
            if is_v2:
                allocated = {
                    contribution["local_ref"]: new_id("ev")
                    for contribution in result["outputs"]
                }
                # Create every Evidence object first so the relation service can
                # validate the complete batch graph, including forward refs.
                for contribution in result["outputs"]:
                    digest = hashlib.sha256(canonical_json(contribution).encode("utf-8")).hexdigest()
                    receipt = service.manager.add_evidence(
                        kind="report", locator=f"workflow://{item['work_item_id']}/{digest}",
                        issue_id=item["issue_id"], description=contribution["body"],
                        quality_status="unknown", actor=auth.actor_id,
                        reason=f"workflow-result/v2 attempt {attempt_id}",
                        idempotency_key=f"workflow-evidence:{item['work_item_id']}:{digest}",
                        _allocated_evidence_id=allocated[contribution["local_ref"]],
                    )
                    evidence_id = receipt["evidence_id"]
                    evidence_ids.append(evidence_id)
                    evidence_bindings.append({
                        "local_ref": contribution["local_ref"],
                        "evidence_id": evidence_id,
                    })
                for contribution in result["outputs"]:
                    consumer_id = allocated[contribution["local_ref"]]
                    for declaration in contribution.get("related_evidence", []):
                        provider_id = (
                            allocated[declaration["provider_local_ref"]]
                            if "provider_local_ref" in declaration
                            else declaration["provider_evidence_id"]
                        )
                        relation = service.manager.evidence_relations.add(
                            consumer_id,
                            provider_id,
                            declaration["relation_type"],
                            rationale=declaration["rationale"],
                            actor=auth.actor_id,
                            run_id=auth.run_id,
                            request_id=attempt_id,
                            conn=conn,
                        )
                        relation_ids.append(relation["relation_id"])
                if related:
                    service.store.fault("workflow.after_evidence_relations")
                for contribution in result["outputs"]:
                    evidence_id = allocated[contribution["local_ref"]]
                    output(contribution, "final" if result["outcome"] == "complete" else "partial",
                           evidence_id, "evidence", "add_evidence")
            else:
                for contribution in result["outputs"]:
                    if contribution["action"] == "record_assessment":
                        continue
                    digest = hashlib.sha256(canonical_json(contribution).encode("utf-8")).hexdigest()
                    if contribution["action"] != "add_evidence":
                        object_type, object_id = create(service.manager, contribution, package, auth,
                                                         f"workflow-domain:{attempt_id}:{digest}")
                        service.store.fault("workflow.after_domain_output")
                        domain_objects.append(dict(type=object_type, id=object_id, state="draft",
                                                   validation_status="not_run", effective=False))
                        output(contribution, "final" if result["outcome"] == "complete" else "partial",
                               object_id, object_type, contribution["action"])
                        continue
                    # A source reference may support several distinct report outputs.
                    receipt = service.manager.add_evidence(
                        kind="report", locator=f"workflow://{item['work_item_id']}/{digest}",
                        issue_id=item["issue_id"], description=contribution["body"],
                        quality_status="unknown", actor=auth.actor_id,
                        reason=f"workflow-result/v1 attempt {attempt_id}",
                        idempotency_key=f"workflow-evidence:{item['work_item_id']}:{digest}",
                        related_evidence=contribution.get("related_evidence", []),
                    )
                    if contribution.get("related_evidence"):
                        service.store.fault("workflow.after_evidence_relations")
                    evidence_ids.append(receipt["evidence_id"])
                    output(contribution, "final" if result["outcome"] == "complete" else "partial",
                           receipt["evidence_id"], "evidence", "add_evidence")
            if assessment:
                record = assessments.saved_record(service.manager, assessment, package, domain_objects)
                assessment_ids.append(output(record, "final" if result["outcome"] == "complete" else "partial",
                                             action="record_assessment"))
                service.store.fault("workflow.after_assessment_output")
        # The complete business response (including waiting conditions) is itself immutable.
        output(result, ("final" if result["outcome"] == "complete" else "partial")
               if published else "draft")
        target = ("ready" if stale else "blocked" if exhausted else
                  {"complete": "completed", "partial": "ready", "blocked": "blocked"}[
                      result["outcome"]])
        attempt_status = "succeeded" if target == "completed" else "rejected" if stale else "failed"
        reason = reason or (result["outcome"] if target != "completed" else None)
        stop_reason = "; ".join(result["remaining"]) if reason in {"partial", "blocked"} else reason
        conn.execute("UPDATE workflow_attempts SET status=?,rejection_code=?,ended_at=? "
                     "WHERE attempt_id=?", (attempt_status, reason, timestamp, attempt_id))
        conn.execute("UPDATE workflow_work_items SET status=?,revision=revision+1,"
                     "acceptance_status='pending',stop_reason=?,updated_at=? WHERE work_item_id=?",
                     (target, stop_reason, timestamp, item["work_item_id"]))
        if published:
            mandate["commits_used"] += 1
            mandate["revision"] += 1
            mandate.update(updated_at=timestamp, updated_by=auth.actor_id)
            conn.execute("UPDATE workflow_mandates SET commits_used=?,revision=?,updated_at=?,"
                         "updated_by=? WHERE mandate_id=?",
                         (mandate["commits_used"], mandate["revision"], timestamp,
                          auth.actor_id, mandate["mandate_id"]))
            service._record_revision(conn, mandate, event_type="workflow_result", auth=auth)
        receipt = dict(attempt_id=attempt_id, work_item_id=item["work_item_id"],
                       outcome=result["outcome"], status=attempt_status, work_item_status=target,
                       acceptance_status="pending", published=published, reason=reason,
                       output_ids=output_ids, evidence_ids=evidence_ids,
                       work_item_revision=item["revision"] + 1, mandate_revision=mandate["revision"])
        if is_v2:
            receipt.update(evidence_bindings=evidence_bindings, relation_ids=relation_ids)
        if domain_outputs:
            receipt.update(domain_objects=domain_objects, conclusion_effective=False)
        if assessment:
            receipt.update(assessment_ids=assessment_ids, conclusion_effective=False)
        receipt["event_id"] = service._event(
            conn, mandate_id=mandate["mandate_id"], work_item_id=item["work_item_id"],
            attempt_id=attempt_id, event_type="attempt.submit_result", auth=auth,
            before_state=attempt["status"], after_state=attempt_status, payload=receipt.copy(),
        )
        store.idempotency_record(conn, operation, key, payload, receipt)
    return receipt
