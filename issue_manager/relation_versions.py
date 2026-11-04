"""Versioned relation contents; legacy relation tables are current projections."""

from __future__ import annotations

import re
import sqlite3

RELATION_RUNTIME_FIELDS = frozenset({"active", "created_at", "created_by", "updated_at", "actor_id", "run_id",
                                    "request_id", "proposed_run_id", "deactivated_at", "deactivated_by"})


_CONTEXT_RELATION_ENDPOINTS_V1 = {
    "conclusion_version": ("conclusion_revisions", "conclusion_id"),
    "record_version": ("record_revisions", "record_revision_id"),
    "relation_version": ("managed_relation_versions", "version_id"),
}


def install_context_relation_endpoint_triggers(
    conn: sqlite3.Connection,
    *,
    additional_endpoints: dict[str, tuple[str, str]] | None = None,
) -> None:
    """Install the database half of the typed context-material contract.

    V15 installs its frozen endpoint set. Later migrations may explicitly add
    endpoint kinds while preserving the existing trigger names and behavior.
    """
    endpoints = dict(_CONTEXT_RELATION_ENDPOINTS_V1)
    endpoints.update(additional_endpoints or {})
    for operation in ("INSERT", "UPDATE"):
        trigger_name = f"validate_context_relation_{operation.lower()}"
        conn.execute(f"DROP TRIGGER IF EXISTS {trigger_name}")
        checks = []
        for endpoint in ("source_key", "target_key"):
            value = f"NEW.{endpoint}"
            kind, identity = f"json_extract({value},'$[0]')", f"json_extract({value},'$[1]')"
            exists = " OR ".join(
                f"({kind}='{kind_name}' AND EXISTS(SELECT 1 FROM {table} WHERE {column}={identity}))"
                for kind_name, (table, column) in endpoints.items()
            )
            checks.append(f"""SELECT CASE WHEN
                json_type({value}) <> 'array' OR json_array_length({value}) <> 2
                OR json_type({value},'$[0]') <> 'text' OR json_type({value},'$[1]') <> 'text'
                OR {value} <> json_array({kind},{identity})
                OR NOT ({exists})
                THEN RAISE(ABORT, 'Invalid typed material endpoint') END;""")
        conn.execute(f"""CREATE TRIGGER {trigger_name}
            BEFORE {operation} ON context_relations BEGIN
            {''.join(checks)}
            SELECT CASE WHEN NEW.require_currentness=1 AND json_extract(NEW.source_key,'$[0]') <> 'conclusion_version'
                THEN RAISE(ABORT, 'Currentness requires a source conclusion') END;
            END""")


def install_relation_versions(conn: sqlite3.Connection):
    """Migration requires foreign_keys OFF and an enclosing write transaction."""
    conn.execute("""CREATE TABLE managed_relation_versions (
        version_id TEXT PRIMARY KEY,
        domain TEXT NOT NULL CHECK(domain IN ('issue','evidence','question','intake','record','context')),
        relation_id TEXT NOT NULL,
        version_number INTEGER NOT NULL,
        contract_version TEXT NOT NULL,
        definition_json TEXT NOT NULL CHECK(json_valid(definition_json)),
        UNIQUE(domain,relation_id,version_number)
    )""")
    conn.execute("""CREATE TABLE managed_relation_heads (
        domain TEXT NOT NULL,
        relation_id TEXT NOT NULL,
        version_id TEXT NOT NULL REFERENCES managed_relation_versions(version_id),
        PRIMARY KEY(domain,relation_id)
    )""")
    conn.execute("""CREATE TABLE context_relations (
        relation_id TEXT PRIMARY KEY,
        source_key TEXT NOT NULL CHECK(json_valid(source_key)),
        target_key TEXT NOT NULL CHECK(json_valid(target_key)),
        relation_type TEXT NOT NULL CHECK(relation_type IN
            ('supports','challenges','reproduces','amends','context_for','derived_from','depends_on','duplicates')),
        require_currentness INTEGER NOT NULL CHECK(require_currentness IN (0,1)),
        rationale TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
        CHECK(source_key <> target_key)
    )""")
    conn.execute("CREATE INDEX idx_context_relations_source ON context_relations(source_key,active)")
    conn.execute("CREATE INDEX idx_context_relations_target ON context_relations(target_key,active)")
    install_context_relation_endpoint_triggers(conn)
    # Legacy Question links have no independent identity. Encode their full old
    # key injectively; do not infer multiple historical sources from one row.
    conn.execute("PRAGMA legacy_alter_table=ON")
    conn.execute("ALTER TABLE issue_question_evidence_links RENAME TO question_links_pre_v15")
    conn.execute("""CREATE TABLE issue_question_evidence_links (
        relation_id TEXT PRIMARY KEY,
        question_id TEXT NOT NULL REFERENCES issue_questions(question_id),
        evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
        link_type TEXT NOT NULL CHECK(link_type IN ('addresses','supports','challenges','context')),
        rationale TEXT NOT NULL DEFAULT '',
        active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
        created_at TEXT NOT NULL, created_by TEXT NOT NULL
    )""")
    conn.execute("""INSERT INTO issue_question_evidence_links
        SELECT 'question_legacy_' || hex(CAST(json_array(question_id,evidence_id,link_type) AS BLOB)),
               question_id,evidence_id,link_type,rationale,active,created_at,created_by
        FROM question_links_pre_v15""")
    conn.execute("DROP TABLE question_links_pre_v15")
    conn.execute("CREATE INDEX idx_issue_question_evidence_evidence ON issue_question_evidence_links(evidence_id,active,question_id)")
    conn.execute("CREATE INDEX idx_issue_question_evidence_question ON issue_question_evidence_links(question_id,active)")
    conn.execute("PRAGMA legacy_alter_table=OFF")
    # Frozen Record links remain part of the historical content hash. Current
    # relationship membership lives separately and may change without rewriting
    # that original evidence/proof/manifest snapshot.
    record_sql = conn.execute("SELECT sql FROM sqlite_master WHERE name='record_evidence_links'").fetchone()[0]
    record_sql = record_sql.replace("record_evidence_links", "record_material_relations", 1)
    record_sql = re.sub(r",\s*PRIMARY KEY\(record_revision_id,\s*field_path,\s*evidence_id,\s*relation_role\)", "", record_sql)
    opening = record_sql.index("(") + 1
    record_sql = record_sql[:opening] + "relation_id TEXT PRIMARY KEY, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))," + record_sql[opening:]
    conn.execute(record_sql)
    record_fields = [row[1] for row in conn.execute("PRAGMA table_info(record_evidence_links)")]
    record_columns = ",".join(record_fields)
    def record_identity(prefix):
        keys = ",".join(f'{prefix}."{field}"' for field in ("record_revision_id", "field_path", "evidence_id", "relation_role"))
        return f"'record_origin_' || hex(CAST(json_array({keys}) AS BLOB))"
    conn.execute(f"INSERT INTO record_material_relations (relation_id,{record_columns}) "
                 f"SELECT {record_identity('record_evidence_links')},{record_columns} FROM record_evidence_links")
    conn.execute("CREATE INDEX idx_record_material_revision ON record_material_relations(record_revision_id,active)")
    conn.execute("CREATE INDEX idx_record_material_evidence ON record_material_relations(evidence_id,active)")
    new_fields = ",".join(f'NEW."{field}"' for field in record_fields)
    conn.execute(f"""CREATE TRIGGER record_origin_material AFTER INSERT ON record_evidence_links
        BEGIN INSERT INTO record_material_relations (relation_id,{record_columns})
        VALUES ({record_identity('NEW')},{new_fields}); END""")
    for operation in ("UPDATE", "DELETE"):
        conn.execute(f"""CREATE TRIGGER immutable_record_evidence_snapshot_{operation.lower()}
            BEFORE {operation} ON record_evidence_links
            BEGIN SELECT RAISE(ABORT, 'Immutable Record evidence snapshot'); END""")
    for table, domain in (("relations", "issue"), ("evidence_relations", "evidence"),
                          ("issue_question_evidence_links", "question"),
                          ("intake_packet_links", "intake"),
                          ("record_material_relations", "record"),
                          ("context_relations", "context")):
        identity_column = "link_id" if domain == "intake" else "relation_id"
        sql = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()[0]
        indices = [row[0] for row in conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL", (table,)
        )]
        # Endpoint equality is not relation identity. Preserve every existing ID.
        revised = re.sub(r",\s*UNIQUE\(consumer_(?:issue|evidence)_id,\s*provider_(?:issue|evidence)_id,\s*relation_type\)", "", sql)
        if domain == "intake":
            revised = re.sub(r",\s*UNIQUE\(source_packet_id,\s*target_packet_id,\s*link_type\)", "", sql)
        if revised == sql and domain in {"issue", "evidence", "intake"}:
            raise RuntimeError(f"Expected legacy endpoint uniqueness constraint in {table}")
        if domain in {"issue", "evidence", "intake"}:
            conn.execute("PRAGMA legacy_alter_table=ON")
            conn.execute(f'ALTER TABLE "{table}" RENAME TO "{table}_pre_v15"')
            conn.execute(revised)
            conn.execute(f'INSERT INTO "{table}" SELECT * FROM "{table}_pre_v15"')
            conn.execute(f'DROP TABLE "{table}_pre_v15"')
            for statement in indices:
                conn.execute(statement)
            conn.execute("PRAGMA legacy_alter_table=OFF")
        if domain == "intake":
            conn.execute("ALTER TABLE intake_packet_links ADD COLUMN active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))")
            conn.execute("CREATE INDEX idx_packet_links_source ON intake_packet_links(source_packet_id,active)")
            conn.execute("CREATE INDEX idx_packet_links_target ON intake_packet_links(target_packet_id,active)")
        fields = [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")') if row[1] not in RELATION_RUNTIME_FIELDS]
        def definition(prefix):
            return "json_object(" + ",".join(f"'{name}',{prefix}.\"{name}\"" for name in fields) + ")"
        conn.execute(f"""INSERT INTO managed_relation_versions
            SELECT '{domain}:' || {identity_column} || ':1','{domain}',{identity_column},1,
                   'context-currentness/v1',{definition(table)} FROM "{table}" """)
        conn.execute("INSERT INTO managed_relation_heads SELECT domain,relation_id,version_id "
                     "FROM managed_relation_versions WHERE domain=?", (domain,))
        for operation in ("INSERT", "UPDATE"):
            condition = f"WHEN {definition('OLD')} IS NOT {definition('NEW')}" if operation == "UPDATE" else ""
            conn.execute(f"""CREATE TRIGGER relation_version_{table}_{operation.lower()}
                AFTER {operation} ON "{table}" {condition}
                BEGIN
                    INSERT INTO managed_relation_versions
                    SELECT '{domain}:' || NEW.{identity_column} || ':' || (COALESCE(MAX(version_number),0)+1),
                           '{domain}',NEW.{identity_column},COALESCE(MAX(version_number),0)+1,
                           'context-currentness/v1',{definition('NEW')}
                    FROM managed_relation_versions WHERE domain='{domain}' AND relation_id=NEW.{identity_column};
                    INSERT INTO managed_relation_heads
                    SELECT domain,relation_id,version_id FROM managed_relation_versions
                    WHERE domain='{domain}' AND relation_id=NEW.{identity_column} ORDER BY version_number DESC LIMIT 1
                    ON CONFLICT(domain,relation_id) DO UPDATE SET version_id=excluded.version_id;
                END""")
        conn.execute(f"""CREATE TRIGGER retain_{table}_identity BEFORE DELETE ON "{table}"
            BEGIN SELECT RAISE(ABORT, 'Disable relations instead of deleting identity'); END""")
        conn.execute(f"""CREATE TRIGGER retain_{table}_identity_update BEFORE UPDATE ON "{table}"
            WHEN OLD.{identity_column} IS NOT NEW.{identity_column}
            BEGIN SELECT RAISE(ABORT, 'Retain relation identity'); END""")
    for operation in ("UPDATE", "DELETE"):
        conn.execute(f"""CREATE TRIGGER immutable_relation_version_{operation.lower()}
            BEFORE {operation} ON managed_relation_versions
            BEGIN SELECT RAISE(ABORT, 'Immutable relation version'); END""")
