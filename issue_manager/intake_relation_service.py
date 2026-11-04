"""Reviewed lifecycle and content replacement of retained Packet links."""

from .errors import ConflictError, ValidationError
from .relation_versions import RELATION_RUNTIME_FIELDS
from .store import canonical_json, now


class IntakeRelationService:
    def __init__(self, manager):
        self.manager = manager
        self.store = manager.store

    def preview(self, operation, *, state_view=None):
        from .changeset_state import StateView

        view = state_view or StateView(self.manager)
        identity = operation["link_id"]
        if not isinstance(identity, str) or not identity.strip():
            raise ValidationError("Intake relationship needs an independent identity")
        action = operation["action"]
        old = view.intake_relation(identity)
        head = view.material_head("intake", identity)
        if action == "add":
            if old or head or "expected_version_id" in operation or "expected_active" in operation:
                raise ConflictError("Intake relationship identity exists or add has prior-state conditions")
            provenance = operation.get("provenance")
            if not isinstance(provenance, dict) or set(provenance) != {"actor_id", "run_id"}:
                raise ValidationError("Intake add requires authenticated proposer provenance from ChangeSet create")
            if not self.store.row("SELECT 1 FROM agent_runs WHERE run_id=? AND actor_id=?",
                                  (provenance["run_id"], provenance["actor_id"])):
                raise ValidationError("Intake proposer run does not belong to its actor")
        elif not old or not head or head["version_id"] != operation.get("expected_version_id"):
            raise ConflictError("Intake relationship version changed or does not exist")
        if action != "add" and (type(operation.get("expected_active")) is not bool or bool(old["active"]) != operation["expected_active"]):
            raise ConflictError("Intake relationship activation changed")
        if not operation["reason"].strip():
            raise ValidationError("Intake relationship needs a reason")
        new = dict(old) if old else {"link_id": identity, "active": 1, "created_at": None,
                                    "proposed_by": provenance["actor_id"], "proposed_run_id": provenance["run_id"]}
        if action in {"add", "replace"}:
            replacement = operation.get("replacement")
            allowed = {"source_packet_id", "target_packet_id", "link_type", "rationale"}
            if not isinstance(replacement, dict) or not replacement or set(replacement) - allowed:
                raise ValidationError("Unsupported Intake relationship replacement")
            if any(not isinstance(value, str) for value in replacement.values()):
                raise ValidationError("Intake relationship fields must be strings")
            new.update(replacement)
            if not allowed <= set(new):
                raise ValidationError("Intake relationship requires source, target, link_type and rationale")
            for field in ("source_packet_id", "target_packet_id"):
                self.manager.intake.show(new[field])
            if new["source_packet_id"] == new["target_packet_id"]:
                raise ValidationError("A packet cannot link to itself")
            if new["link_type"] not in self.manager.intake.LINK_TYPES:
                raise ValidationError("Unknown packet link type")
            if not new["rationale"].strip():
                raise ValidationError("Packet link rationale is required")
        elif action in {"enable", "disable"}:
            if "replacement" in operation:
                raise ValidationError("Lifecycle operations cannot replace relation contents")
            new["active"] = int(action == "enable")
        else:
            raise ValidationError("Unsupported Intake relationship action")
        content = {key: value for key, value in new.items() if key not in RELATION_RUNTIME_FIELDS}
        old_content = {key: value for key, value in (old or {}).items() if key not in RELATION_RUNTIME_FIELDS}
        number = (head["version_number"] if head else 0) + int(content != old_content)
        return {"before": old, "after": new, "version_id": head["version_id"] if head else None,
                "after_version": {"version_id": f"intake:{identity}:{number}", "domain": "intake",
                                  "relation_id": identity, "version_number": number,
                                  "contract_version": "context-currentness/v1", "definition_json": canonical_json(content)}}

    def execute(self, operation, *, actor):
        with self.store.transaction() as conn:
            preview = self.preview(operation)
            new = preview["after"]
            if new == preview["before"]:
                return {"link_id": new["link_id"], "version_id": preview["version_id"], "unchanged": True}
            fields = ("source_packet_id", "target_packet_id", "link_type", "rationale", "active")
            if preview["before"] is None:
                conn.execute("INSERT INTO intake_packet_links "
                             "(source_packet_id,target_packet_id,link_type,rationale,active,link_id,proposed_by,proposed_run_id,created_at) "
                             "VALUES (?,?,?,?,?,?,?,?,?)", (*[new[key] for key in fields], new["link_id"],
                                                           new["proposed_by"], new["proposed_run_id"], now()))
            else:
                conn.execute("UPDATE intake_packet_links SET " + ",".join(key + "=?" for key in fields)
                             + " WHERE link_id=?", (*[new[key] for key in fields], new["link_id"]))
            self.store.audit(conn, actor=actor, action="intake_relation." + operation["action"],
                             object_type="relation", object_id=new["link_id"], before_revision=None,
                             after_revision=None, reason=operation["reason"],
                             payload={"before": preview["before"], "after": new, "version_id": preview["after_version"]["version_id"]})
            return {"link_id": new["link_id"], "version_id": preview["after_version"]["version_id"], "active": bool(new["active"])}
