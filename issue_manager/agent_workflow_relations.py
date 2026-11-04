"""Bounded, opt-in Evidence relations in an atomic workflow delivery."""
from __future__ import annotations

import re

from .errors import PermissionError, ValidationError
from .policy import EVIDENCE_RELATION_TYPES

_LOCAL_REF = re.compile(r"^[A-Za-z][A-Za-z0-9._-]*$")


def validate(relations):
    if not isinstance(relations, list) or not 1 <= len(relations) <= 8:
        raise ValidationError("Expected 1..8 Evidence relations")
    seen = set()
    for relation in relations:
        if (not isinstance(relation, dict)
                or set(relation) != {"provider_evidence_id", "relation_type", "rationale"}
                or not isinstance(relation["provider_evidence_id"], str)
                or not 1 <= len(relation["provider_evidence_id"]) <= 512
                or relation["relation_type"] not in ("challenges", "supports")
                or not isinstance(relation["rationale"], str)
                or not relation["rationale"].strip() or len(relation["rationale"]) > 2000):
            raise ValidationError("Expected frozen Evidence, challenges/supports and rationale")
        identity = relation["provider_evidence_id"]
        if identity in seen:
            raise ValidationError("Only one relation per provider in a contribution")
        seen.add(identity)


def validate_v2(relations):
    if not isinstance(relations, list) or not 1 <= len(relations) <= 8:
        raise ValidationError("Expected 1..8 Evidence relations")
    seen = set()
    for relation in relations:
        if not isinstance(relation, dict):
            raise ValidationError("Expected a bounded Evidence relation")
        provider_keys = {key for key in ("provider_local_ref", "provider_evidence_id")
                         if key in relation}
        if len(provider_keys) != 1 or set(relation) != provider_keys | {"relation_type", "rationale"}:
            raise ValidationError("Each v2 relation needs exactly one provider reference")
        provider_key = next(iter(provider_keys))
        provider = relation[provider_key]
        valid_provider = (
            isinstance(provider, str)
            and 1 <= len(provider) <= (128 if provider_key == "provider_local_ref" else 512)
            and bool(provider.strip())
            and (provider_key != "provider_local_ref" or _LOCAL_REF.fullmatch(provider) is not None)
        )
        if (not valid_provider
                or not isinstance(relation["relation_type"], str)
                or relation["relation_type"] not in EVIDENCE_RELATION_TYPES
                or not isinstance(relation["rationale"], str)
                or not relation["rationale"].strip()
                or len(relation["rationale"]) > 2000):
            raise ValidationError("Expected a finite v2 provider, relation type and rationale")
        identity = (provider_key, provider)
        if identity in seen:
            raise ValidationError("Only one relation per provider in a contribution")
        seen.add(identity)


def check(service, contribution, package, permissions, auth):
    if "related_evidence" not in contribution:
        return
    if ("relate_evidence" not in permissions["allowed_actions"]
            or "relate_evidence" not in package["work_item"]["allowed_actions"]):
        raise PermissionError("Evidence relations require explicit workflow authorization")
    service._require(auth, "context.read", "evidence.relation.write")
    prepared = package.get("prepared_context", {})
    materials = prepared.get("materials", {})
    selected = {item["candidate_id"] for item in materials.get("candidate_states", [])}
    issue_id = package["input_baseline"]["issue_id"]
    for relation in contribution["related_evidence"]:
        provider = relation["provider_evidence_id"]
        service.manager.evidence.require_read_access(provider, auth)
        if provider not in selected or not service.store.row(
                "SELECT 1 FROM issue_evidence WHERE issue_id=? AND evidence_id=?", (issue_id, provider)):
            raise ValidationError("Relation provider is outside frozen Issue Evidence")


def check_v2(service, contribution, package, permissions, auth, local_refs):
    if "related_evidence" not in contribution:
        return
    if ("relate_evidence" not in permissions["allowed_actions"]
            or "relate_evidence" not in package["work_item"]["allowed_actions"]):
        raise PermissionError("Evidence relations require explicit workflow authorization")
    service._require(auth, "context.read", "evidence.relation.write")
    issue_id = package["input_baseline"]["issue_id"]
    prepared = package.get("prepared_context", {})
    materials = prepared.get("materials", {})
    selected = {item["candidate_id"] for item in materials.get("candidate_states", [])}
    for relation in contribution["related_evidence"]:
        if "provider_local_ref" in relation:
            provider = relation["provider_local_ref"]
            if provider not in local_refs or provider == contribution["local_ref"]:
                raise ValidationError("Relation provider_local_ref must reference another output")
            continue
        provider = relation["provider_evidence_id"]
        service.manager.evidence.require_read_access(provider, auth)
        if (provider not in selected or not service.store.row(
                "SELECT 1 FROM issue_evidence WHERE issue_id=? AND evidence_id=?",
                (issue_id, provider))):
            raise ValidationError("Relation provider is outside frozen Issue Evidence")
