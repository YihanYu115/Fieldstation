"""Reviewed current Record material membership, separate from frozen snapshots."""

import json

from .errors import ConflictError, NotFoundError, ValidationError
from .store import canonical_json


class RecordRelationService:
    def __init__(self, manager):
        self.manager = manager
        self.store = manager.store

    def preview(self, operation, *, state_view=None):
        from .changeset_state import StateView

        view = state_view or StateView(self.manager)
        identity = operation["relation_id"]
        if not isinstance(identity, str) or not identity.strip():
            raise ValidationError("Record relationship needs an independent identity")
        action = operation["action"]
        old = view.record_relation(identity)
        head = view.material_head("record", identity)
        if action == "add":
            if identity.startswith("record_origin_"):
                raise ValidationError("Record origin identities are reserved for frozen snapshots")
            if old or head or "expected_version_id" in operation or "expected_active" in operation:
                raise ConflictError("Record relationship identity exists or add has prior-state conditions")
        elif not old or not head or head["version_id"] != operation.get("expected_version_id"):
            raise ConflictError("Record relationship version changed or does not exist")
        if action != "add" and (type(operation.get("expected_active")) is not bool or bool(old["active"]) != operation["expected_active"]):
            raise ConflictError("Record relationship activation changed")
        if not operation["reason"].strip():
            raise ValidationError("Record relationship needs a reason")
        new = dict(old) if old else {"relation_id": identity, "active": 1}
        if action in {"add", "replace"}:
            from .record_service import _fields

            replacement = operation.get("replacement")
            allowed = {"record_revision_id", "field_path", "evidence_id", "proof_id", "relation_role"}
            if not isinstance(replacement, dict) or not replacement or set(replacement) - allowed:
                raise ValidationError("Record replacement accepts references, not caller-supplied snapshot hashes")
            if any(not isinstance(value, str) and not (key == "proof_id" and value is None) for key, value in replacement.items()):
                raise ValidationError("Invalid Record material reference")
            if "evidence_id" in replacement and replacement["evidence_id"] != new.get("evidence_id"):
                new["proof_id"] = None
            new.update(replacement)
            if not {"record_revision_id", "field_path", "evidence_id", "relation_role"} <= set(new):
                raise ValidationError("Record material requires revision, field, Evidence and role")
            revision = self.store.row("SELECT * FROM record_revisions WHERE record_revision_id=?", (new["record_revision_id"],))
            if not revision:
                raise NotFoundError("Record revision not found")
            template = json.loads(revision["template_snapshot_json"])
            profile = json.loads(revision["validation_result_json"]).get("profile", "draft")
            link = {key: new[key] for key in ("field_path", "evidence_id", "relation_role")}
            link["proof_id"] = new.get("proof_id")
            normalized, errors, _ = self.manager.records._normalize_evidence_links(
                {}, _fields(template["definition"]), template["definition"].get("profiles", {}).get(profile, {}), [link], state_view=view)
            if errors or len(normalized) != 1:
                raise ValidationError("Invalid Record material snapshot", details={"field_errors": errors})
            new.update(normalized[0])
        elif action in {"enable", "disable"}:
            if "replacement" in operation:
                raise ValidationError("Lifecycle operations cannot replace Record material contents")
            new["active"] = int(action == "enable")
        else:
            raise ValidationError("Unsupported Record relationship action")
        content = {key: value for key, value in new.items() if key != "active"}
        old_content = {key: value for key, value in (old or {}).items() if key != "active"}
        number = (head["version_number"] if head else 0) + int(content != old_content)
        version = {"version_id": f"record:{identity}:{number}", "domain": "record", "relation_id": identity,
                   "version_number": number, "contract_version": "context-currentness/v1", "definition_json": canonical_json(content)}
        return {"before": old, "after": new, "version_id": head["version_id"] if head else None, "after_version": version}

    def execute(self, operation, *, actor):
        with self.store.transaction() as conn:
            preview = self.preview(operation)
            new = preview["after"]
            if new == preview["before"]:
                return {"relation_id": new["relation_id"], "version_id": preview["version_id"], "unchanged": True}
            columns = list(new)
            if preview["before"] is None:
                conn.execute(f"INSERT INTO record_material_relations ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})", tuple(new.values()))
            else:
                fields = [key for key in columns if key != "relation_id"]
                conn.execute("UPDATE record_material_relations SET " + ",".join(key + "=?" for key in fields) + " WHERE relation_id=?",
                             (*[new[key] for key in fields], new["relation_id"]))
            self.store.audit(conn, actor=actor, action="record_relation." + operation["action"], object_type="relation",
                             object_id=new["relation_id"], before_revision=None, after_revision=None, reason=operation["reason"],
                             payload={"before": preview["before"], "after": new, "version_id": preview["after_version"]["version_id"]})
            return {"relation_id": new["relation_id"], "version_id": preview["after_version"]["version_id"], "active": bool(new["active"])}
