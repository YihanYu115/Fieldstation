"""Capture authoritative input changes inside the transaction that writes them.

Triggers cover every write entry point, including import and ChangeSet paths.
The journal is input history, not a snapshot per affected descendant. Candidate
discovery uses old AND new row fields against indexed range subscriptions.
"""

from __future__ import annotations

import sqlite3

INPUT_TABLES = (
    "issues", "conclusion_revisions", "relations", "working_entries",
    "evidence_refs", "issue_evidence", "evidence_relations", "evidence_proofs",
    "evidence_manifests", "issue_questions", "issue_question_evidence_links",
    "record_instances", "record_revisions", "record_evidence_links", "record_material_relations",
    "issue_rollup_policies", "registry_entries", "intake_packets", "intake_packet_links",
    "basis_receipt_eligibility", "basis_receipt_selections", "conclusion_context_selections",
    "context_relations", "managed_relation_versions",
    "triage_dispositions",
    "context_rule_selections",
    "evidence_applicability_decision_versions",
    "evidence_applicability_decision_heads",
)

# These fields never enter semantic comparisons. Domain-specific observation
# times, scopes, lifecycle and qualifications remain inputs.
NON_SEMANTIC = frozenset({
    "created_at", "created_by", "updated_at", "updated_by", "actor_id", "run_id",
    "request_id", "attached_at", "attached_by", "freshness", "working_revision",
    "semantic_revision", "current_revision", "deactivated_at", "deactivated_by",
    "created_run_id", "proposed_run_id",
})

# The base journal keeps the frozen v1 field normalization. v18 installs a
# narrow supplemental observer for semantic_revision below.
JOURNAL_NON_SEMANTIC = NON_SEMANTIC


def install_input_journal_tables(conn: sqlite3.Connection, tables) -> None:
    """Install idempotent journal triggers for the named tables that exist."""
    for table in tables:
        columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')]
        if not columns:
            continue
        fields = [name for name in columns if name not in JOURNAL_NON_SEMANTIC]
        primary = [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")') if row[5]]
        if not primary or not fields:
            continue
        def row_json(prefix):
            return "json_object(" + ",".join(f"'{name}',{prefix}.\"{name}\"" for name in fields) + ")"
        for operation in ("INSERT", "UPDATE", "DELETE"):
            before = "'{}'" if operation == "INSERT" else row_json("OLD")
            after = "'{}'" if operation == "DELETE" else row_json("NEW")
            prefix = "OLD" if operation == "DELETE" else "NEW"
            identity = "json_array(" + ",".join(f'{prefix}."{name}"' for name in primary) + ")"
            when = f"WHEN {before} IS NOT {after}" if operation == "UPDATE" else ""
            conn.execute(f"""
                CREATE TRIGGER IF NOT EXISTS context_input_{table}_{operation.lower()}
                AFTER {operation} ON "{table}" {when}
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'{table}',{identity},{before},{after}
                    FROM context_input_clock WHERE singleton=1;
                END
            """)
    # Content histories are append-only. Lifecycle fields live separately, or
    # are explicitly excluded here for the legacy combined manifest/packet rows.
    for table, only_fields in (
        ("conclusion_revisions", None), ("working_entries", None), ("record_revisions", None),
        ("triage_dispositions", None),
        ("evidence_proofs", None),
        ("intake_packets", {"packet_id", "packet_version", "packet_json", "packet_hash"}),
        ("evidence_manifests", {"manifest_id", "evidence_id", "manifest_json", "manifest_hash", "manifest_revision"}),
    ):
        columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')]
        fields = columns if only_fields is None else [column for column in columns if column in only_fields]
        changed = " OR ".join(f'OLD."{field}" IS NOT NEW."{field}"' for field in fields)
        conn.execute(f"""CREATE TRIGGER IF NOT EXISTS context_immutable_{table}_update
            BEFORE UPDATE ON "{table}" WHEN {changed}
            BEGIN SELECT RAISE(ABORT, 'Immutable context content version'); END""")
        conn.execute(f"""CREATE TRIGGER IF NOT EXISTS context_immutable_{table}_delete
            BEFORE DELETE ON "{table}"
            BEGIN SELECT RAISE(ABORT, 'Retain immutable context content history'); END""")


def install_input_journal(conn: sqlite3.Connection) -> None:
    """Install the v15 journal and its indexes; later schemas add tables by name."""
    conn.execute("CREATE INDEX IF NOT EXISTS idx_issues_current_conclusion ON issues(current_conclusion_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_context_triage_issue ON triage_dispositions(issue_id)")
    install_input_journal_tables(conn, INPUT_TABLES)


def install_evidence_semantic_revision_journal(conn: sqlite3.Connection) -> None:
    """Replace the v15 Evidence UPDATE trigger with a v18 comparison trigger.

    It keeps the existing trigger name, so no duplicate v15 observer remains,
    and adds semantic_revision only to journal JSON (never to v1 snapshots).
    """
    columns = [row[1] for row in conn.execute('PRAGMA table_info("evidence_refs")')]
    if "semantic_revision" not in columns:
        return
    fields = sorted(set(name for name in columns if name not in JOURNAL_NON_SEMANTIC)
                    | {"semantic_revision"})

    def row_json(prefix, selected):
        return "json_object(" + ",".join(
            f"'{name}',{prefix}.\"{name}\"" for name in selected
        ) + ")"

    changed = f"{row_json('OLD', fields)} IS NOT {row_json('NEW', fields)}"
    before = row_json("OLD", fields)
    after = row_json("NEW", fields)
    conn.execute("DROP TRIGGER IF EXISTS context_input_evidence_refs_update")
    conn.execute(f"""
        CREATE TRIGGER context_input_evidence_refs_update
        AFTER UPDATE ON evidence_refs
        WHEN {changed}
        BEGIN
            UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
            INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
            SELECT revision,'evidence_refs',json_array(NEW.evidence_id),{before},{after}
            FROM context_input_clock WHERE singleton=1;
        END
    """)
