"""Schema v18 storage for scoped Evidence applicability decisions.

This module only installs authoritative decision versions and their current
heads. It does not evaluate projections or write currentness state.
"""

from __future__ import annotations

import sqlite3

from .relation_versions import install_context_relation_endpoint_triggers

EVIDENCE_APPLICABILITY_SCHEMA_SQL = r"""
CREATE TABLE evidence_applicability_decision_versions (
    decision_version_id TEXT PRIMARY KEY,
    decision_key TEXT NOT NULL CHECK(length(trim(decision_key)) > 0),
    version_number INTEGER NOT NULL CHECK(version_number >= 1),
    previous_version_id TEXT REFERENCES evidence_applicability_decision_versions(decision_version_id),
    scope_kind TEXT NOT NULL CHECK(scope_kind = 'issue_conclusion'),
    scope_issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    target_binding TEXT NOT NULL CHECK(target_binding = 'fixed'),
    target_evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    target_semantic_revision INTEGER NOT NULL CHECK(target_semantic_revision >= 0),
    target_proof_id TEXT REFERENCES evidence_proofs(proof_id),
    target_manifest_id TEXT REFERENCES evidence_manifests(manifest_id),
    effect TEXT NOT NULL CHECK(effect IN ('include','exclude')),
    basis_json TEXT NOT NULL CHECK(
        json_valid(basis_json)
        AND json_type(basis_json) = 'array'
        AND json_array_length(basis_json) > 0
    ),
    rule_id TEXT NOT NULL CHECK(rule_id = 'evidence-applicability/v1'),
    qualification_json TEXT NOT NULL CHECK(
        json_valid(qualification_json) AND json_type(qualification_json) = 'object'
    ),
    reason TEXT NOT NULL CHECK(length(trim(reason)) > 0),
    changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    UNIQUE(decision_key,version_number),
    UNIQUE(decision_key,decision_version_id),
    CHECK(previous_version_id IS NULL OR previous_version_id <> decision_version_id)
);

CREATE INDEX idx_applicability_versions_scope_target_key_number
ON evidence_applicability_decision_versions(
    scope_issue_id,target_evidence_id,decision_key,version_number
);
CREATE INDEX idx_applicability_versions_target_scope
ON evidence_applicability_decision_versions(target_evidence_id,scope_issue_id);

CREATE TRIGGER validate_applicability_decision_version_insert
BEFORE INSERT ON evidence_applicability_decision_versions BEGIN
    SELECT CASE WHEN NEW.decision_version_id <> (
        'applicability:' || NEW.decision_key || ':' || NEW.version_number
    ) THEN RAISE(ABORT, 'Invalid applicability decision version identity') END;
    SELECT CASE WHEN NEW.version_number <> (
        SELECT COALESCE(MAX(version_number),0)+1
        FROM evidence_applicability_decision_versions
        WHERE decision_key=NEW.decision_key
    ) THEN RAISE(ABORT, 'Applicability decision versions must be consecutive') END;
    SELECT CASE WHEN NEW.version_number=1 AND NEW.previous_version_id IS NOT NULL
        THEN RAISE(ABORT, 'First applicability decision version cannot have a predecessor') END;
    SELECT CASE WHEN NEW.version_number>1 AND NOT EXISTS (
        SELECT 1 FROM evidence_applicability_decision_versions p
        WHERE p.decision_key=NEW.decision_key
          AND p.version_number=NEW.version_number-1
          AND p.decision_version_id=NEW.previous_version_id
    ) THEN RAISE(ABORT, 'Applicability decision predecessor must be the prior version for the same key') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM evidence_refs e
        WHERE e.evidence_id=NEW.target_evidence_id
          AND e.semantic_revision=NEW.target_semantic_revision
          AND e.current_proof_id IS NEW.target_proof_id
          AND e.current_manifest_id IS NEW.target_manifest_id
    ) THEN RAISE(ABORT, 'Applicability target snapshot is not current') END;
    SELECT CASE WHEN NEW.target_proof_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM evidence_proofs p
        WHERE p.proof_id=NEW.target_proof_id
          AND p.evidence_id=NEW.target_evidence_id
          AND p.semantic_revision=NEW.target_semantic_revision
    ) THEN RAISE(ABORT, 'Applicability target proof does not match its Evidence snapshot') END;
    SELECT CASE WHEN NEW.target_manifest_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM evidence_manifests m
        WHERE m.manifest_id=NEW.target_manifest_id
          AND m.evidence_id=NEW.target_evidence_id
    ) THEN RAISE(ABORT, 'Applicability target manifest does not match its Evidence') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM json_each(NEW.basis_json) b
        WHERE json_type(b.value) <> 'object'
           OR COALESCE(json_type(b.value,'$.kind'),'') <> 'text'
           OR COALESCE(json_extract(b.value,'$.kind'),'') NOT IN (
               'evidence_version','conclusion_version','record_version',
               'relation_version','applicability_decision_version'
           )
           OR (json_extract(b.value,'$.kind')='evidence_version' AND (
               COALESCE(json_type(b.value,'$.evidence_id'),'') <> 'text'
               OR COALESCE(json_type(b.value,'$.semantic_revision'),'') <> 'integer'
               OR COALESCE(json_type(b.value,'$.proof_id'),'') NOT IN ('text','null')
               OR COALESCE(json_type(b.value,'$.manifest_id'),'') NOT IN ('text','null')
               OR COALESCE(json_type(b.value,'$.snapshot'),'') <> 'object'
           ))
           OR (json_extract(b.value,'$.kind')='conclusion_version' AND
               COALESCE(json_type(b.value,'$.conclusion_id'),'') <> 'text')
           OR (json_extract(b.value,'$.kind')='record_version' AND
               COALESCE(json_type(b.value,'$.record_revision_id'),'') <> 'text')
           OR (json_extract(b.value,'$.kind')='relation_version' AND
               COALESCE(json_type(b.value,'$.version_id'),'') <> 'text')
           OR (json_extract(b.value,'$.kind')='applicability_decision_version' AND (
               COALESCE(json_type(b.value,'$.decision_version_id'),'') <> 'text'
               OR json_extract(b.value,'$.decision_version_id')=NEW.decision_version_id
           ))
    ) THEN RAISE(ABORT, 'Invalid fixed typed applicability basis') END;
END;

CREATE TRIGGER immutable_applicability_decision_version_update
BEFORE UPDATE ON evidence_applicability_decision_versions BEGIN
    SELECT RAISE(ABORT, 'Immutable applicability decision version');
END;
CREATE TRIGGER immutable_applicability_decision_version_delete
BEFORE DELETE ON evidence_applicability_decision_versions BEGIN
    SELECT RAISE(ABORT, 'Retain applicability decision history');
END;

CREATE TABLE evidence_applicability_decision_heads (
    decision_key TEXT PRIMARY KEY,
    decision_version_id TEXT NOT NULL UNIQUE,
    active INTEGER NOT NULL CHECK(active IN (0,1)),
    head_revision INTEGER NOT NULL CHECK(head_revision >= 1),
    updated_at TEXT NOT NULL CHECK(length(trim(updated_at)) > 0),
    updated_by TEXT NOT NULL REFERENCES actors(actor_id),
    FOREIGN KEY(decision_key,decision_version_id)
        REFERENCES evidence_applicability_decision_versions(decision_key,decision_version_id)
);

CREATE INDEX idx_applicability_heads_version
ON evidence_applicability_decision_heads(decision_version_id);
CREATE INDEX idx_applicability_heads_scope_target
ON evidence_applicability_decision_heads(decision_key,active);

CREATE TRIGGER validate_applicability_head_insert
BEFORE INSERT ON evidence_applicability_decision_heads BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM evidence_applicability_decision_versions v
        WHERE v.decision_key=NEW.decision_key
          AND v.decision_version_id=NEW.decision_version_id
    ) THEN RAISE(ABORT, 'Applicability head key must match its decision version') END;
    SELECT CASE WHEN NEW.head_revision <> 1
        THEN RAISE(ABORT, 'Initial applicability head revision must be one') END;
END;
CREATE TRIGGER validate_applicability_head_update
BEFORE UPDATE ON evidence_applicability_decision_heads BEGIN
    SELECT CASE WHEN NEW.decision_key <> OLD.decision_key
        THEN RAISE(ABORT, 'Applicability head key is stable') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM evidence_applicability_decision_versions v
        WHERE v.decision_key=NEW.decision_key
          AND v.decision_version_id=NEW.decision_version_id
    ) THEN RAISE(ABORT, 'Applicability head key must match its decision version') END;
    SELECT CASE WHEN NEW.head_revision <> OLD.head_revision+1
        THEN RAISE(ABORT, 'Applicability head revision must increase by one') END;
    SELECT CASE WHEN NEW.decision_version_id=OLD.decision_version_id
                    AND NEW.active=OLD.active
        THEN RAISE(ABORT, 'Applicability head update must change version or active state') END;
END;
CREATE TRIGGER retain_applicability_decision_head
BEFORE DELETE ON evidence_applicability_decision_heads BEGIN
    SELECT RAISE(ABORT, 'Retain applicability decision head history');
END;
"""


def install_evidence_applicability_v18(conn: sqlite3.Connection) -> dict[str, str]:
    """Install v18 runtime metadata without activating the v2 context rule."""
    from .context_journal import (
        INPUT_TABLES,
        install_evidence_semantic_revision_journal,
        install_input_journal_tables,
    )
    from .relation_contracts import VERSION_ENDPOINTS

    install_context_relation_endpoint_triggers(
        conn,
        additional_endpoints={
            "applicability_decision_version": VERSION_ENDPOINTS[
                "applicability_decision_version"
            ]
        },
    )
    # The base input journal is installed at v15, before these v18 tables
    # exist. Add their INSERT/UPDATE/DELETE observers only after creation.
    install_input_journal_tables(conn, INPUT_TABLES)
    install_evidence_semantic_revision_journal(conn)
    return {}
