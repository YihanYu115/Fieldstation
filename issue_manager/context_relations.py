"""Typed, fixed-version material relationships, including relationship targets."""

from __future__ import annotations

import json

from .errors import ConflictError, NotFoundError, ValidationError
from .relation_contracts import REGISTRY, VERSION_ENDPOINTS
from .store import canonical_json

# Generic typed relations remain domain records; qualification is computed by
# scoped Evidence relations, not by switching to another context evaluator.
ENDPOINTS = VERSION_ENDPOINTS
ROLES = REGISTRY.roles("context")


def endpoint_key(kind, version_id):
    return canonical_json([kind, version_id])


def endpoints_for_active_context_rule(active_rule):
    from .context_scoped_rule import SCOPED_V2_RULE_DEFINITION, scoped_v2_rule_id

    if active_rule is None:
        return {}
    try:
        valid = (active_rule["rule_id"] == scoped_v2_rule_id() and
                 canonical_json(json.loads(active_rule["definition_json"])) == canonical_json(SCOPED_V2_RULE_DEFINITION))
    except (KeyError, TypeError, ValueError):
        return {}
    return VERSION_ENDPOINTS if valid else {}


class ContextRelationService:
    def __init__(self, manager):
        self.manager = manager
        self.store = manager.store

    def _endpoint(self, value, state_view):
        if not isinstance(value, dict) or set(value) != {"kind", "version_id"}:
            raise ValidationError("A material endpoint needs kind and version_id")
        kind, version_id = value["kind"], value["version_id"]
        endpoints = endpoints_for_active_context_rule(
            self.manager.context_rules.active(state_view=state_view)
        )
        if not isinstance(kind, str) or kind not in endpoints or not isinstance(version_id, str):
            raise ValidationError("Unsupported material version endpoint")
        table, column = endpoints[kind]
        exists = state_view.material_version(version_id) if kind == "relation_version" else self.store.row(
            f'SELECT 1 FROM "{table}" WHERE "{column}"=?', (version_id,))
        if not exists:
            raise NotFoundError("Material endpoint version does not exist")
        return endpoint_key(kind, version_id)

    def preview(self, operation, *, state_view=None):
        from .changeset_state import StateView

        view = state_view or StateView(self.manager)
        allowed = {"op", "action", "relation_id", "expected_version_id", "definition", "reason"}
        if set(operation) - allowed:
            raise ValidationError("Unsupported material relation operation fields")
        action, identity = operation.get("action"), operation.get("relation_id")
        if action not in {"add", "replace", "disable", "enable"}:
            raise ValidationError("Unsupported material relation action")
        if not isinstance(identity, str) or not identity.strip():
            raise ValidationError("Material relationship needs an independent identity")
        if not isinstance(operation.get("reason"), str) or not operation["reason"].strip():
            raise ValidationError("Material relationship needs a reason")
        old = view.context_relation(identity)
        head = view.material_head("context", identity)
        if action == "add":
            if old or operation.get("expected_version_id", "") != "":
                raise ConflictError("Material relationship identity already exists or add has a prior version")
        elif not old or not head or head["version_id"] != operation.get("expected_version_id"):
            raise ConflictError("Material relationship version changed or does not exist")
        new = dict(old) if old else {"relation_id": identity, "active": 1}
        if action in {"add", "replace"}:
            definition = operation.get("definition")
            if not isinstance(definition, dict) or set(definition) != {
                "source", "target", "relation_type", "require_currentness"
            }:
                raise ValidationError("Material definition needs source, target, relation_type and require_currentness")
            if definition["relation_type"] not in ROLES or type(definition["require_currentness"]) is not bool:
                raise ValidationError("Invalid material role or currentness selection")
            source, target = self._endpoint(definition["source"], view), self._endpoint(definition["target"], view)
            if source == target:
                raise ValidationError("Material relation endpoints must differ")
            if definition["require_currentness"] and definition["source"]["kind"] != "conclusion_version":
                raise ValidationError("Only a source conclusion version can contribute currentness")
            new.update(source_key=source, target_key=target, relation_type=definition["relation_type"],
                       require_currentness=int(definition["require_currentness"]), rationale=operation["reason"])
        else:
            if "definition" in operation:
                raise ValidationError("Lifecycle operations cannot replace material contents")
            new["active"] = int(action == "enable")
        content = {key: value for key, value in new.items() if key != "active"}
        changed = old is None or content != {key: value for key, value in old.items() if key != "active"}
        number = (head["version_number"] if head else 0) + int(changed)
        return {"before": old, "after": new, "version_id": head["version_id"] if head else None,
                "after_version": {"version_id": f"context:{identity}:{number}", "domain": "context",
                                  "relation_id": identity, "version_number": number,
                                  "contract_version": "context-currentness/v1", "definition_json": canonical_json(content)}}

    def execute(self, operation, *, actor):
        with self.store.transaction() as conn:
            preview = self.preview(operation)
            new = preview["after"]
            if preview["before"] is None:
                columns = list(new)
                conn.execute(f'INSERT INTO context_relations ({",".join(columns)}) VALUES ({",".join("?" for _ in columns)})',
                             tuple(new.values()))
            elif preview["before"] != new:
                fields = [key for key in new if key != "relation_id"]
                conn.execute(f'UPDATE context_relations SET {",".join(key + "=?" for key in fields)} WHERE relation_id=?',
                             (*[new[key] for key in fields], new["relation_id"]))
            head = conn.execute("SELECT version_id FROM managed_relation_heads WHERE domain='context' AND relation_id=?",
                                (new["relation_id"],)).fetchone()[0]
            self.store.audit(conn, actor=actor, action="context_relation." + operation["action"],
                             object_type="relation", object_id=new["relation_id"], before_revision=None,
                             after_revision=None, reason=operation["reason"],
                             payload={"before_version_id": preview["version_id"], "version_id": head,
                                      "source": json.loads(new["source_key"]), "target": json.loads(new["target_key"])})
            return {"relation_id": new["relation_id"], "version_id": head, "active": bool(new["active"])}
