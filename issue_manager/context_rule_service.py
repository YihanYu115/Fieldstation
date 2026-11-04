"""The single supported, immutable scoped-v2 runtime contract."""
from __future__ import annotations

import json
from typing import Any

from .context_resolver import normalized_equal
from .context_scoped_rule import SCOPED_V2_RULE_DEFINITION, SCOPED_V2_RULE_ID, scoped_v2_rule_id
from .errors import ConflictError, ValidationError
from .store import canonical_json, now


def runtime_rule_id(definition=None):
    if definition is not None and not normalized_equal(definition, SCOPED_V2_RULE_DEFINITION):
        raise ValidationError("Only the current scoped-v2 rule is supported")
    return scoped_v2_rule_id()


def supported_runtime_rules():
    return {scoped_v2_rule_id(): SCOPED_V2_RULE_DEFINITION}


def rule_descriptor_version(rule_id: str) -> str:
    if rule_id != scoped_v2_rule_id():
        raise ValidationError("Unsupported context rule; initialize a new scoped-v2 project")
    return SCOPED_V2_RULE_ID


def rule_capabilities(rule_id: str) -> dict[str, Any]:
    return {"descriptor_version": rule_descriptor_version(rule_id), "resolver": "scoped-v2",
            "direct_working_conclusion": True, "scoped_projection": True,
            "automatic_assessment_dispatch": False, "current_basis_mode": True}


class ContextRuleService:
    def __init__(self, manager):
        self.manager = manager
        self.store = manager.store

    def active(self, *, state_view=None):
        if state_view is not None and state_view.context_rule is not None:
            return state_view.context_rule
        return self.store.row("SELECT r.* FROM context_rule_selections s JOIN context_rule_versions r USING(rule_id) WHERE s.singleton=1")

    def describe(self):
        active = self.active()
        matches = bool(active and active["rule_id"] == scoped_v2_rule_id() and
                       normalized_equal(json.loads(active["definition_json"]), SCOPED_V2_RULE_DEFINITION))
        return {"active_rule_id": active["rule_id"] if active else None,
                "runtime_rule_id": scoped_v2_rule_id(), "supported_rule_ids": [scoped_v2_rule_id()],
                "runtime_matches_active": matches,
                "capabilities": rule_capabilities(active["rule_id"]) if matches else {}}

    def initialize(self):
        active = self.active()
        if active:
            if not self.describe()["runtime_matches_active"]:
                raise ConflictError("Unsupported context rule; initialize a new scoped-v2 project")
            return
        if self.store.fresh_context_rule != "scoped-v2":
            raise ConflictError("Missing context rule; initialize a new scoped-v2 project")
        identity = scoped_v2_rule_id()
        self.store.conn.execute("INSERT INTO context_rule_versions VALUES (?,?,?)",
                                (identity, canonical_json(SCOPED_V2_RULE_DEFINITION), now()))
        self.store.conn.execute("INSERT INTO context_rule_selections VALUES (1,?)", (identity,))
        self.store.audit(self.store.conn, actor="system", action="context_rule.fresh_initialize",
                         object_type="context_rule", object_id=identity, before_revision=None,
                         after_revision=None, reason="Initialize the scoped-v2 runtime",
                         payload={"context_rule": "scoped-v2"})

    def preview(self, operation, *, state_view=None):
        raise ValidationError("Rule switching is not supported; this release uses scoped-v2 only")

    def activate(self, operation, *, actor):
        raise ValidationError("Rule switching is not supported; this release uses scoped-v2 only")
