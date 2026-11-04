"""Reviewed changes to independently identified Question material links."""

from typing import Any

from .errors import ConflictError, ValidationError
from .relation_versions import RELATION_RUNTIME_FIELDS
from .store import canonical_json, now


class QuestionRelationService:
    def __init__(self, manager):
        self.manager = manager
        self.store = manager.store

    def preview(self, operation, *, state_view=None):
        from .changeset_state import StateView
        from .question_service import QUESTION_LINK_TYPES

        view = state_view or StateView(self.manager)
        identity = operation["relation_id"]
        if not isinstance(identity, str) or not identity.strip():
            raise ValidationError("Question relationship needs an independent identity")
        action = operation["action"]
        old = view.question_relation(identity)
        head = view.material_head("question", identity)
        if action == "add":
            if old or head or "expected_version_id" in operation or "expected_active" in operation:
                raise ConflictError("Question relationship identity exists or add has prior-state conditions")
        elif not old or not head or head["version_id"] != operation.get("expected_version_id"):
            raise ConflictError("Question relationship version changed or does not exist")
        if action != "add" and (type(operation.get("expected_active")) is not bool or bool(old["active"]) != operation["expected_active"]):
            raise ConflictError("Question relationship activation changed")
        if not operation["reason"].strip():
            raise ValidationError("Question relationship needs a reason")
        new: dict[str, Any] = dict(old) if old else {"relation_id": identity, "active": 1, "rationale": "", "created_at": None, "created_by": None}
        if action in {"add", "replace"}:
            replacement = operation.get("replacement")
            allowed = {"question_id", "evidence_id", "link_type", "rationale"}
            if not isinstance(replacement, dict) or not replacement or set(replacement) - allowed:
                raise ValidationError("Unsupported Question relationship replacement")
            if any(not isinstance(value, str) for value in replacement.values()):
                raise ValidationError("Question relationship fields must be strings")
            new.update(replacement)
            if not {"question_id", "evidence_id", "link_type"} <= set(new):
                raise ValidationError("Question relationship requires question_id, evidence_id and link_type")
            view.question(new["question_id"])
            view.evidence(new["evidence_id"])
            if new["link_type"] not in QUESTION_LINK_TYPES:
                raise ValidationError("Unknown Question relationship role")
        elif action in {"enable", "disable"}:
            if "replacement" in operation:
                raise ValidationError("Lifecycle operations cannot replace relation contents")
            new["active"] = int(action == "enable")
        else:
            raise ValidationError("Unsupported Question relationship action")
        content = {key: value for key, value in new.items() if key not in RELATION_RUNTIME_FIELDS}
        old_content = {key: value for key, value in (old or {}).items() if key not in RELATION_RUNTIME_FIELDS}
        number = (head["version_number"] if head else 0) + int(content != old_content)
        return {"before": old, "after": new, "version_id": head["version_id"] if head else None,
                "after_version": {"version_id": f"question:{identity}:{number}", "domain": "question",
                                  "relation_id": identity, "version_number": number,
                                  "contract_version": "context-currentness/v1", "definition_json": canonical_json(content)}}

    def execute(self, operation, *, actor):
        with self.store.transaction() as conn:
            preview = self.preview(operation)
            new = preview["after"]
            if new == preview["before"]:
                return {"relation_id": new["relation_id"], "version_id": preview["version_id"], "unchanged": True}
            columns = ("question_id", "evidence_id", "link_type", "rationale", "active")
            if preview["before"] is None:
                conn.execute("INSERT INTO issue_question_evidence_links "
                             "(relation_id,question_id,evidence_id,link_type,rationale,active,created_at,created_by) VALUES (?,?,?,?,?,?,?,?)",
                             (new["relation_id"], *[new[key] for key in columns], now(), actor))
            else:
                conn.execute("UPDATE issue_question_evidence_links SET " + ",".join(key + "=?" for key in columns)
                             + " WHERE relation_id=?", (*[new[key] for key in columns], new["relation_id"]))
            self.store.audit(conn, actor=actor, action="question_relation." + operation["action"],
                             object_type="relation", object_id=new["relation_id"], before_revision=None,
                             after_revision=None, reason=operation["reason"],
                             payload={"before": preview["before"], "after": new,
                                      "version_id": preview["after_version"]["version_id"]})
            return {"relation_id": new["relation_id"], "version_id": preview["after_version"]["version_id"],
                    "active": bool(new["active"])}
