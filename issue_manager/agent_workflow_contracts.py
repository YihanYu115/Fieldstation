"""Role-neutral, bounded input and atomic result contracts for the workflow API."""

from __future__ import annotations

import json
import re

from .errors import ValidationError

RESULT_CONTRACT = "workflow-result/v1"
RESULT_CONTRACT_V2 = "workflow-result/v2"
_LOCAL_REF = re.compile(r"^[A-Za-z][A-Za-z0-9._-]*$")


def _text(value, limit):
    return isinstance(value, str) and bool(value.strip()) and len(value) <= limit


def validate_inputs(inputs):
    if not isinstance(inputs, list) or len(inputs) > 16:
        raise ValidationError("Expected at most 16 bounded input attachments")
    refs = set()
    for attachment in inputs:
        if (not isinstance(attachment, dict) or set(attachment) != {"ref", "text"}
                or not _text(attachment["ref"], 512) or not _text(attachment["text"], 8000)
                or attachment["ref"] in refs):
            raise ValidationError("Each input needs a unique ref and non-empty text")
        refs.add(attachment["ref"])
    return inputs


def _validate_v1_result(result):
    if not isinstance(result, dict) or set(result) != {
        "contract", "outcome", "outputs", "remaining", "handoff"
    }:
        raise ValidationError("Expected workflow contract, outcome, outputs, remaining and handoff")
    if (result["contract"] != RESULT_CONTRACT or not isinstance(result["outcome"], str)
            or result["outcome"] not in {"complete", "partial", "blocked"}):
        raise ValidationError("Unsupported workflow result contract or outcome")
    outputs, remaining = result["outputs"], result["remaining"]
    if not isinstance(outputs, list) or len(outputs) > 16:
        raise ValidationError("Expected at most 16 bounded business outputs")
    if (not isinstance(remaining, list) or len(remaining) > 16
            or any(not _text(x, 1000) for x in remaining)):
        raise ValidationError("Remaining must list bounded next steps or waiting conditions")
    if (result["outcome"] == "complete") != (not remaining):
        raise ValidationError("Complete requires no remaining work; partial/blocked require a next step")
    if not outputs and result["outcome"] == "partial":
        raise ValidationError("Partial requires an output; use blocked when there is no output")
    seen = set()
    assessment_outputs = [o for o in outputs if isinstance(o, dict) and o.get("action") == "record_assessment"]
    if assessment_outputs and (len(assessment_outputs) != 1 or len(outputs) > 2):
        raise ValidationError("Expected one assessment and at most one proposal")
    for output in outputs:
        if isinstance(output, dict) and output.get("action") == "record_assessment":
            from .agent_workflow_assessments import validate_output

            validate_output(output)
            continue
        if isinstance(output, dict) and output.get("action") in ("create_proposal", "create_verification"):
            validate_proposal_output(output)
            if len(outputs) != 1 and not (assessment_outputs and output["action"] == "create_proposal"):
                raise ValidationError("A proposal delivery must contain exactly one domain output")
            continue
        if (not isinstance(output, dict) or set(output) - {"related_evidence"} != {"action", "source_ref", "body"}
                or output["action"] != "add_evidence"
                or not _text(output["source_ref"], 512) or not _text(output["body"], 32000)):
            raise ValidationError("An output needs add_evidence, source_ref and report body")
        if "related_evidence" in output:
            from .agent_workflow_relations import validate

            validate(output["related_evidence"])
        identity = (output["source_ref"], output["body"])
        if identity in seen:
            raise ValidationError("Duplicate output in one delivery")
        seen.add(identity)
    if not isinstance(result["handoff"], dict):
        raise ValidationError("Handoff must be an opaque JSON object")
    try:
        serialized = json.dumps(result, ensure_ascii=False, allow_nan=False)
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValidationError("Result must contain finite JSON values") from exc
    if len(serialized.encode("utf-8")) > 1_000_000:
        raise ValidationError("Workflow result exceeds the bounded delivery size")
    return result


def _validate_local_ref(value):
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and _LOCAL_REF.fullmatch(value) is not None
    )


def _validate_v2_result(result):
    if not isinstance(result, dict) or set(result) != {
        "contract", "outcome", "outputs", "remaining", "handoff"
    }:
        raise ValidationError("Expected workflow v2 contract, outcome, outputs, remaining and handoff")
    if (result["contract"] != RESULT_CONTRACT_V2 or not isinstance(result["outcome"], str)
            or result["outcome"] not in {"complete", "partial", "blocked"}):
        raise ValidationError("Unsupported workflow result contract or outcome")
    outputs, remaining = result["outputs"], result["remaining"]
    if not isinstance(outputs, list) or len(outputs) > 8:
        raise ValidationError("Expected at most 8 bounded Evidence outputs")
    if (not isinstance(remaining, list) or len(remaining) > 8
            or any(not _text(value, 1000) for value in remaining)):
        raise ValidationError("Remaining must list bounded next steps or waiting conditions")
    if (result["outcome"] == "complete") != (not remaining):
        raise ValidationError("Complete requires no remaining work; partial/blocked require a next step")
    if result["outcome"] == "partial" and not outputs:
        raise ValidationError("Partial requires an output; use blocked when there is no output")
    seen = set()
    for output in outputs:
        if (not isinstance(output, dict)
                or set(output) - {"related_evidence"} != {
                    "action", "local_ref", "source_ref", "body"
                }
                or output["action"] != "add_evidence"
                or not _validate_local_ref(output["local_ref"])
                or not _text(output["source_ref"], 512)
                or not _text(output["body"], 32000)):
            raise ValidationError(
                "A workflow v2 output needs add_evidence, local_ref, source_ref and report body"
            )
        if output["local_ref"] in seen:
            raise ValidationError("local_ref must be unique within one workflow v2 result")
        seen.add(output["local_ref"])
        if "related_evidence" in output:
            from .agent_workflow_relations import validate_v2

            validate_v2(output["related_evidence"])
    if not isinstance(result["handoff"], dict):
        raise ValidationError("Handoff must be an opaque JSON object")
    try:
        serialized = json.dumps(result, ensure_ascii=False, allow_nan=False)
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValidationError("Result must contain finite JSON values") from exc
    if len(serialized.encode("utf-8")) > 1_000_000:
        raise ValidationError("Workflow result exceeds the bounded delivery size")
    return result


def validate_result(result):
    contract = result.get("contract") if isinstance(result, dict) else None
    if contract == RESULT_CONTRACT_V2:
        return _validate_v2_result(result)
    return _validate_v1_result(result)


def validate_proposal_output(output):
    fields = {"action", "package_id", "evidence_refs"}
    fields |= {"content"} if output["action"] == "create_proposal" else {"reason"}
    if output["action"] == "create_proposal" and "revises_proposal_id" in output:
        fields.add("revises_proposal_id")
        if not _text(output["revises_proposal_id"], 512):
            raise ValidationError("Revision source must be a proposal ID")
    if set(output) != fields or not _text(output["package_id"], 512):
        raise ValidationError("Expected a bounded proposal tied to a frozen package")
    refs = output["evidence_refs"]
    if (not isinstance(refs, list) or not 1 <= len(refs) <= 16
            or any(not _text(ref, 512) for ref in refs) or len(set(refs)) != len(refs)):
        raise ValidationError("Expected 1..16 distinct frozen Evidence references")
    if output["action"] == "create_verification":
        if not _text(output["reason"], 8000):
            raise ValidationError("Verification requires a bounded reason")
        return
    content = output["content"]
    if (not isinstance(content, dict) or set(content) != {
            "statement", "change_summary", "applicability", "limitations", "confidence"}
            or any(not _text(content[k], 8000) for k in
                   ("statement", "change_summary", "applicability"))
            or content["confidence"] not in ("low", "medium", "high")
            or not isinstance(content["limitations"], list) or len(content["limitations"]) > 16
            or any(not _text(x, 1000) for x in content["limitations"])):
        raise ValidationError("Expected answer, change reason, applicability, limitations and confidence")
