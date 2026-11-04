PRAGMA foreign_keys = ON;

CREATE TABLE issue_conclusion_rule_versions (
    issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    revision INTEGER NOT NULL CHECK(revision > 0),
    schema_json TEXT NOT NULL,
    schema_hash TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    PRIMARY KEY(issue_id, revision)
);

CREATE TRIGGER issue_conclusion_rule_versions_no_update
BEFORE UPDATE ON issue_conclusion_rule_versions
BEGIN SELECT RAISE(ABORT, 'Immutable conclusion rule version'); END;

CREATE TRIGGER issue_conclusion_rule_versions_no_delete
BEFORE DELETE ON issue_conclusion_rule_versions
BEGIN SELECT RAISE(ABORT, 'Retain conclusion rule history'); END;

CREATE TABLE conclusion_rule_bindings (
    conclusion_id TEXT PRIMARY KEY REFERENCES conclusion_revisions(conclusion_id),
    issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    revision INTEGER NOT NULL CHECK(revision >= 0),
    schema_json TEXT NOT NULL,
    schema_hash TEXT NOT NULL
);

CREATE TRIGGER conclusion_rule_bindings_no_update
BEFORE UPDATE ON conclusion_rule_bindings
BEGIN SELECT RAISE(ABORT, 'Immutable conclusion rule binding'); END;

CREATE TRIGGER conclusion_rule_bindings_no_delete
BEFORE DELETE ON conclusion_rule_bindings
BEGIN SELECT RAISE(ABORT, 'Retain conclusion rule binding'); END;

CREATE TABLE activity_events (
    activity_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    activity_type TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    issue_ids_json TEXT NOT NULL,
    platform_id TEXT,
    summary_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE actor_capabilities (
    actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    capability TEXT NOT NULL,
    granted_at TEXT NOT NULL,
    PRIMARY KEY(actor_id, capability)
);

CREATE TABLE actors (
    actor_id TEXT PRIMARY KEY,
    actor_kind TEXT NOT NULL CHECK(actor_kind IN ('experiment_agent','organizer_agent','review_agent','maintenance_agent')),
    display_name TEXT NOT NULL,
    credential_hash TEXT NOT NULL UNIQUE,
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    created_at TEXT NOT NULL
, principal_kind TEXT, metadata_json TEXT NOT NULL DEFAULT '{}', platform_id TEXT REFERENCES platform_sources(platform_id));

CREATE TABLE adapter_allowlist (
    adapter_kind TEXT NOT NULL CHECK(adapter_kind IN ('import','report')),
    adapter_name TEXT NOT NULL,
    adapter_version TEXT NOT NULL,
    executable_hash TEXT NOT NULL,
    descriptor_json TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
    installed_at TEXT NOT NULL,
    installed_by TEXT NOT NULL REFERENCES actors(actor_id), executable_path TEXT NOT NULL DEFAULT '', descriptor_hash TEXT NOT NULL DEFAULT '', protocol_version TEXT NOT NULL DEFAULT '1', verified_at TEXT, disabled_reason TEXT NOT NULL DEFAULT '', state_revision INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(adapter_kind,adapter_name,adapter_version,executable_hash)
);

CREATE TABLE adapter_install_receipts (
    adapter_install_receipt_id TEXT PRIMARY KEY,
    adapter_kind TEXT NOT NULL CHECK(adapter_kind IN ('import','report')),
    adapter_name TEXT NOT NULL,
    adapter_version TEXT NOT NULL,
    executable_path TEXT NOT NULL,
    executable_hash TEXT NOT NULL,
    descriptor_hash TEXT NOT NULL,
    protocol_version TEXT NOT NULL,
    verification_result_json TEXT NOT NULL,
    installed_at TEXT NOT NULL,
    installed_by TEXT NOT NULL REFERENCES actors(actor_id)
);

CREATE TABLE agent_runs (
    run_id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    parent_run_id TEXT REFERENCES agent_runs(run_id),
    lineage_json TEXT NOT NULL DEFAULT '[]',
    started_at TEXT NOT NULL,
    ended_at TEXT
);

CREATE TABLE analysis_inputs (
    analysis_run_id TEXT NOT NULL REFERENCES analysis_runs(analysis_run_id),
    input_type TEXT NOT NULL,
    input_id TEXT NOT NULL, validated_at TEXT, validation_snapshot TEXT,
    PRIMARY KEY(analysis_run_id, input_type, input_id)
);

CREATE TABLE analysis_methods (
    method_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    script_artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
    source_hash TEXT NOT NULL,
    git_commit TEXT,
    dirty_hash TEXT,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
, scope TEXT NOT NULL DEFAULT 'shared-reviewed'
    CHECK(scope IN ('platform','shared-reviewed')), platform_id TEXT REFERENCES platform_sources(platform_id));

CREATE TABLE analysis_outputs (
    analysis_run_id TEXT NOT NULL REFERENCES analysis_runs(analysis_run_id),
    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
    output_role TEXT NOT NULL,
    PRIMARY KEY(analysis_run_id, artifact_id)
);

CREATE TABLE analysis_runs (
    analysis_run_id TEXT PRIMARY KEY,
    method_id TEXT NOT NULL REFERENCES analysis_methods(method_id),
    config_json TEXT NOT NULL,
    environment_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('registered','frozen')),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    frozen_at TEXT
, platform_id TEXT REFERENCES platform_sources(platform_id), input_manifest_hashes_json TEXT NOT NULL DEFAULT '{}');

CREATE TABLE api_requests (
    request_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL,
    actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    method TEXT NOT NULL,
    route TEXT NOT NULL,
    operation TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('in_progress','succeeded','failed')),
    response_json TEXT,
    error_code TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE(actor_id, run_id, idempotency_key)
);

CREATE TABLE artifact_backup_objects (
    backup_id TEXT NOT NULL REFERENCES artifact_backup_sets(backup_id),
    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    relative_path TEXT NOT NULL,
    PRIMARY KEY(backup_id, artifact_id)
);

CREATE TABLE artifact_backup_sets (
    backup_id TEXT PRIMARY KEY,
    mode TEXT NOT NULL CHECK(mode IN ('metadata','full')),
    manifest_hash TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE artifact_links (
    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    link_role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    PRIMARY KEY(artifact_id, object_type, object_id, link_role)
);

CREATE TABLE artifact_locations (
    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
    locator TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY(artifact_id, locator)
);

CREATE TABLE artifacts (
    artifact_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('scratch','evidence','frozen')),
    mime_type TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    storage_uri TEXT NOT NULL,
    original_locator TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    frozen_at TEXT,
    UNIQUE(sha256)
);

CREATE TABLE audit_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    event_count INTEGER NOT NULL,
    chain_head TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    token_epoch INTEGER NOT NULL,
    signature TEXT NOT NULL
);

CREATE TABLE audit_events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    before_revision INTEGER,
    after_revision INTEGER,
    reason TEXT NOT NULL DEFAULT '',
    payload_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    policy_version INTEGER NOT NULL
, previous_event_hash TEXT, event_hash TEXT);

CREATE TABLE basis_receipt_eligibility (
    receipt_id TEXT PRIMARY KEY REFERENCES basis_receipts(receipt_id),
    eligible INTEGER NOT NULL CHECK(eligible IN (0,1)),
    reason TEXT NOT NULL,
    revision INTEGER NOT NULL
);

CREATE TABLE basis_receipt_selections (
    conclusion_id TEXT PRIMARY KEY REFERENCES conclusion_revisions(conclusion_id),
    receipt_id TEXT NOT NULL,
    FOREIGN KEY(receipt_id,conclusion_id) REFERENCES basis_receipts(receipt_id,conclusion_id)
);

CREATE TABLE basis_receipts (
    receipt_id TEXT PRIMARY KEY,
    conclusion_id TEXT NOT NULL REFERENCES conclusion_revisions(conclusion_id),
    package_id TEXT NOT NULL REFERENCES context_input_packages(package_id),
    identity_json TEXT NOT NULL CHECK(json_valid(identity_json)),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    UNIQUE(receipt_id,conclusion_id)
);

CREATE TABLE capability_profiles (
    profile_name TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE changeset_issue_expectations (
    changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
    issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    expected_working_revision INTEGER,
    expected_conclusion_revision INTEGER,
    PRIMARY KEY(changeset_id, issue_id)
);

CREATE TABLE changeset_operations (
    changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
    ordinal INTEGER NOT NULL,
    operation_json TEXT NOT NULL,
    operation_hash TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK(state IN ('pending','applied','deferred','failed')),
    result_json TEXT,
    PRIMARY KEY(changeset_id, ordinal)
);

CREATE TABLE changeset_partitions (
    parent_changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
    child_changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
    partition_kind TEXT NOT NULL CHECK(partition_kind IN ('immediate','review')),
    PRIMARY KEY(parent_changeset_id, child_changeset_id)
);

CREATE TABLE changeset_review_assignments (
    assignment_id TEXT PRIMARY KEY,
    changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
    reviewer_actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    reviewer_run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    state TEXT NOT NULL CHECK(state IN ('assigned','submitted','released','expired')),
    claimed_at TEXT NOT NULL,
    lease_until TEXT NOT NULL, heartbeat_at TEXT, released_at TEXT, lease_generation INTEGER NOT NULL DEFAULT 1, last_error TEXT,
    UNIQUE(changeset_id, reviewer_run_id)
);

CREATE TABLE changeset_review_decisions (
    review_id TEXT PRIMARY KEY,
    changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
    reviewer_actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    reviewer_run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    decision TEXT NOT NULL CHECK(decision IN ('pass','reject')),
    rationale TEXT NOT NULL,
    changeset_hash TEXT NOT NULL,
    risk_snapshot_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(changeset_id, reviewer_run_id)
);

CREATE TABLE changeset_risk_assessments (
    assessment_id TEXT PRIMARY KEY,
    changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
    risk_tier TEXT NOT NULL,
    reasons_json TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    assessed_at TEXT NOT NULL
);

CREATE TABLE changesets (
    changeset_id TEXT PRIMARY KEY,
    parent_changeset_id TEXT REFERENCES changesets(changeset_id),
    changeset_version INTEGER NOT NULL,
    intent TEXT NOT NULL,
    source_packet_ids_json TEXT NOT NULL DEFAULT '[]',
    changeset_json TEXT NOT NULL,
    changeset_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN
        ('draft','validated','awaiting_review','applying','applied','failed','rejected')),
    risk_tier TEXT NOT NULL CHECK(risk_tier IN ('T0','T1','T2','T3')),
    risk_reasons_json TEXT NOT NULL DEFAULT '[]',
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    applied_at TEXT,
    last_error TEXT
);

CREATE TABLE conclusion_basis (
    conclusion_id TEXT NOT NULL REFERENCES conclusion_revisions(conclusion_id),
    provider_issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    provider_revision INTEGER NOT NULL,
    provider_conclusion_id TEXT NOT NULL REFERENCES conclusion_revisions(conclusion_id), basis_mode TEXT NOT NULL DEFAULT 'current', historical_reason TEXT,
    PRIMARY KEY(conclusion_id, provider_issue_id)
);

CREATE TABLE conclusion_context_selections (
    conclusion_id TEXT PRIMARY KEY REFERENCES conclusion_revisions(conclusion_id),
    descriptor_id TEXT NOT NULL REFERENCES context_descriptors(descriptor_id)
);

CREATE TABLE conclusion_currentness (
    conclusion_id TEXT PRIMARY KEY REFERENCES conclusion_revisions(conclusion_id),
    local_mismatch INTEGER NOT NULL CHECK(local_mismatch IN (0,1)),
    needs_update INTEGER NOT NULL CHECK(needs_update IN (0,1)),
    maintenance_state TEXT NOT NULL CHECK(maintenance_state IN ('ready','pending','failed')),
    computed_revision INTEGER NOT NULL,
    reason_json TEXT NOT NULL CHECK(json_valid(reason_json))
);

CREATE TABLE conclusion_evidence_uses (
    conclusion_id TEXT NOT NULL REFERENCES conclusion_revisions(conclusion_id),
    evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    use_role TEXT NOT NULL CHECK(use_role IN
        ('support','challenge','context','calibration','alternative')),
    fitness TEXT NOT NULL CHECK(fitness IN
        ('fit_for_use','limited_for_use','unusable_for_use','unknown_for_use')),
    verification_level_snapshot TEXT NOT NULL,
    verification_state_snapshot TEXT NOT NULL,
    quality_snapshot TEXT NOT NULL,
    applicability TEXT,
    limitations_json TEXT NOT NULL DEFAULT '[]',
    source_packet_ids_json TEXT NOT NULL DEFAULT '[]', proof_id TEXT REFERENCES evidence_proofs(proof_id), proof_hash TEXT, evidence_semantic_revision INTEGER, manifest_id TEXT REFERENCES evidence_manifests(manifest_id), manifest_hash TEXT,
    PRIMARY KEY(conclusion_id, evidence_id, use_role)
);

CREATE TABLE conclusion_revisions (
    conclusion_id TEXT PRIMARY KEY,
    issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    revision_number INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('draft','provisional','accepted','canonical','disputed','superseded','retracted')),
    statement TEXT NOT NULL,
    structured_outputs_json TEXT NOT NULL DEFAULT '{}',
    confidence TEXT,
    applicability TEXT,
    limitations_json TEXT NOT NULL DEFAULT '[]',
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    change_summary TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    approved_by TEXT,
    previous_conclusion_id TEXT REFERENCES conclusion_revisions(conclusion_id),
    policy_version INTEGER NOT NULL, transition_type TEXT, proposal_id TEXT, issue_type_registration_id TEXT
    REFERENCES registry_entries(registration_id), issue_type_semantic_hash TEXT NOT NULL DEFAULT '', issue_type_semantic_snapshot_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(issue_id, revision_number)
);

CREATE TABLE conclusion_supersessions (
    old_conclusion_id TEXT PRIMARY KEY REFERENCES conclusion_revisions(conclusion_id),
    new_conclusion_id TEXT NOT NULL REFERENCES conclusion_revisions(conclusion_id),
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE context_descriptors (
    descriptor_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL REFERENCES context_rule_versions(rule_id),
    definition_json TEXT NOT NULL CHECK(json_valid(definition_json)),
    content_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE context_input_clock (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    revision INTEGER NOT NULL
);

CREATE TABLE context_input_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    revision INTEGER NOT NULL,
    object_kind TEXT NOT NULL,
    object_id TEXT NOT NULL,
    before_json TEXT NOT NULL CHECK(json_valid(before_json)),
    after_json TEXT NOT NULL CHECK(json_valid(after_json))
);

CREATE TABLE context_input_packages (
    package_id TEXT PRIMARY KEY,
    descriptor_id TEXT NOT NULL REFERENCES context_descriptors(descriptor_id),
    actual_input_json TEXT NOT NULL CHECK(json_valid(actual_input_json)),
    semantic_context_json TEXT NOT NULL CHECK(json_valid(semantic_context_json)),
    semantic_hash TEXT NOT NULL,
    input_revision INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE context_maintenance_checkpoint (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    event_id INTEGER NOT NULL
);

CREATE TABLE context_maintenance_outbox (
    job_id INTEGER PRIMARY KEY AUTOINCREMENT,
    input_revision INTEGER NOT NULL,
    scope_key TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','running','completed','failed')),
    error TEXT,
    UNIQUE(input_revision,scope_key)
);

CREATE TABLE context_relations (
        relation_id TEXT PRIMARY KEY,
        source_key TEXT NOT NULL CHECK(json_valid(source_key)),
        target_key TEXT NOT NULL CHECK(json_valid(target_key)),
        relation_type TEXT NOT NULL CHECK(relation_type IN
            ('supports','challenges','reproduces','amends','context_for','derived_from','depends_on','duplicates')),
        require_currentness INTEGER NOT NULL CHECK(require_currentness IN (0,1)),
        rationale TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
        CHECK(source_key <> target_key)
    );

CREATE TABLE context_rule_selections (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    rule_id TEXT NOT NULL REFERENCES context_rule_versions(rule_id)
);

CREATE TABLE context_rule_versions (
    rule_id TEXT PRIMARY KEY,
    definition_json TEXT NOT NULL CHECK(json_valid(definition_json)),
    created_at TEXT NOT NULL
);

CREATE TABLE context_subscriptions (
    conclusion_id TEXT NOT NULL REFERENCES conclusion_revisions(conclusion_id),
    subscription_key TEXT NOT NULL,
    descriptor_json TEXT NOT NULL CHECK(json_valid(descriptor_json)),
    PRIMARY KEY(conclusion_id,subscription_key)
);

CREATE TABLE context_workflow_obligation_events (
    event_id TEXT PRIMARY KEY,
    obligation_id TEXT NOT NULL REFERENCES context_workflow_obligations(obligation_id),
    revision INTEGER NOT NULL,
    state TEXT NOT NULL,
    actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    reason TEXT NOT NULL,
    reviewers_json TEXT NOT NULL CHECK(json_valid(reviewers_json)),
    changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
    created_at TEXT NOT NULL,
    UNIQUE(obligation_id,revision)
);

CREATE TABLE context_workflow_obligations (
    obligation_id TEXT PRIMARY KEY,
    conclusion_id TEXT NOT NULL REFERENCES conclusion_revisions(conclusion_id),
    kind TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('open','completed','cancelled')),
    details_json TEXT NOT NULL CHECK(json_valid(details_json)),
    blocks_publication INTEGER NOT NULL CHECK(blocks_publication IN (0,1)),
    revision INTEGER NOT NULL DEFAULT 0 CHECK(revision>=0),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE currentness_edge_contributions (
    provider_conclusion_id TEXT NOT NULL REFERENCES conclusion_revisions(conclusion_id),
    consumer_conclusion_id TEXT NOT NULL REFERENCES conclusion_revisions(conclusion_id),
    contribution_id TEXT NOT NULL,
    PRIMARY KEY(provider_conclusion_id,consumer_conclusion_id,contribution_id)
);

CREATE TABLE delegation_edges (
    parent_run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    child_run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY(parent_run_id, child_run_id)
);

CREATE TABLE evidence_assessments (
    assessment_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    quality_status TEXT NOT NULL CHECK(quality_status IN ('unknown','usable','questionable','unusable_for_purpose')),
    rationale TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE evidence_attestations (
    attestation_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    manifest_id TEXT REFERENCES evidence_manifests(manifest_id),
    attestation_type TEXT NOT NULL CHECK(attestation_type IN
        ('existence','metadata','content','snapshot','reproduction')),
    platform_id TEXT NOT NULL REFERENCES platform_sources(platform_id),
    actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    method TEXT NOT NULL,
    input_snapshot_json TEXT NOT NULL,
    result_json TEXT NOT NULL,
    result_hash TEXT NOT NULL,
    artifact_ids_json TEXT NOT NULL DEFAULT '[]',
    analysis_run_id TEXT REFERENCES analysis_runs(analysis_run_id),
    state TEXT NOT NULL CHECK(state IN ('valid','conflict','superseded','revoked')),
    created_at TEXT NOT NULL,
    supersedes_attestation_id TEXT REFERENCES evidence_attestations(attestation_id)
, attestation_role TEXT NOT NULL DEFAULT 'source'
    CHECK(attestation_role IN ('source','independent','resolution')), qualified_manifest_id TEXT
    REFERENCES evidence_manifests(manifest_id), qualified_manifest_hash TEXT, proof_eligible INTEGER NOT NULL DEFAULT 0
    CHECK(proof_eligible IN (0,1)), invalidated_at TEXT, invalidation_reason TEXT);

CREATE TABLE evidence_events (
    evidence_event_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    issue_id TEXT REFERENCES issues(issue_id),
    event_type TEXT NOT NULL CHECK(event_type IN ('attached','detached','voided','reassessed')),
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE evidence_identity_ambiguities (
    ambiguity_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    ambiguity_type TEXT NOT NULL CHECK(ambiguity_type IN
        ('multi_platform_l0','multiple_raw_locators','identity_key_collision',
         'source_candidate_conflict')),
    candidate_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('open','resolved','waived','superseded')),
    rationale TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    resolved_at TEXT,
    resolved_by TEXT REFERENCES actors(actor_id),
    reviewed_changeset_id TEXT REFERENCES changesets(changeset_id),
    review_ids_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE evidence_identity_migrations (
    evidence_id TEXT PRIMARY KEY REFERENCES evidence_refs(evidence_id),
    previous_identity_key TEXT NOT NULL,
    identity_key TEXT NOT NULL,
    previous_normalized_locator TEXT NOT NULL,
    identity_locator TEXT NOT NULL,
    search_locator TEXT NOT NULL,
    locator_identity_version INTEGER NOT NULL,
    migrated_at TEXT NOT NULL
);

CREATE TABLE evidence_manifests (
    manifest_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    manifest_revision INTEGER NOT NULL,
    manifest_version INTEGER NOT NULL,
    platform_id TEXT NOT NULL REFERENCES platform_sources(platform_id),
    source_packet_id TEXT REFERENCES intake_packets(packet_id),
    source_actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    source_run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    observed_at TEXT,
    sample_session_ref TEXT,
    content_identity_json TEXT NOT NULL,
    data_profile_json TEXT NOT NULL,
    execution_json TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    manifest_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    supersedes_manifest_id TEXT REFERENCES evidence_manifests(manifest_id), semantic_fingerprint TEXT NOT NULL DEFAULT '', change_class TEXT NOT NULL DEFAULT 'initial'
    CHECK(change_class IN
        ('initial','content_changed','provenance_changed','metadata_changed',
         'summary_only','exact_replay')), superseded_at TEXT,
    UNIQUE(evidence_id, manifest_revision),
    UNIQUE(evidence_id, manifest_hash)
);

CREATE TABLE evidence_proofs (
    proof_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    semantic_revision INTEGER NOT NULL,
    manifest_id TEXT REFERENCES evidence_manifests(manifest_id),
    manifest_hash TEXT,
    source_platform_id TEXT REFERENCES platform_sources(platform_id),
    verification_level TEXT NOT NULL CHECK(verification_level IN
        ('declared','source_verified','snapshot_verified','reproduced')),
    verification_state TEXT NOT NULL CHECK(verification_state IN
        ('active','verification_requested','conflict','unavailable','superseded')),
    source_attestation_ids_json TEXT NOT NULL,
    independent_attestation_ids_json TEXT NOT NULL,
    artifact_snapshots_json TEXT NOT NULL,
    analysis_run_snapshots_json TEXT NOT NULL,
    reason_codes_json TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    proof_json TEXT NOT NULL,
    proof_hash TEXT NOT NULL UNIQUE,
    supersedes_proof_id TEXT REFERENCES evidence_proofs(proof_id),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id)
);

CREATE TABLE evidence_publication_impacts (
    publication_impact_id TEXT PRIMARY KEY,
    semantic_event_id TEXT NOT NULL REFERENCES evidence_semantic_events(semantic_event_id),
    evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    conclusion_id TEXT NOT NULL REFERENCES conclusion_revisions(conclusion_id),
    conclusion_status TEXT NOT NULL,
    issue_type TEXT NOT NULL,
    use_role TEXT NOT NULL,
    stored_proof_id TEXT REFERENCES evidence_proofs(proof_id),
    stored_proof_hash TEXT,
    current_proof_id TEXT REFERENCES evidence_proofs(proof_id),
    current_proof_hash TEXT,
    selected_freshness TEXT NOT NULL CHECK(selected_freshness IN
        ('none','notify','impact_review','stale','blocked')),
    refresh_reason TEXT,
    priority INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE "evidence_refs" (
    evidence_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN
        ('datavault_dataset','bridge_job','artifact','script','report','external')),
    locator TEXT NOT NULL,
    normalized_locator TEXT NOT NULL,
    identity_key TEXT NOT NULL UNIQUE,
    identity_namespace TEXT NOT NULL
        CHECK(identity_namespace IN ('platform','legacy','conflict')),
    target_scope TEXT,
    short_description TEXT NOT NULL DEFAULT '',
    quality_status TEXT NOT NULL DEFAULT 'unknown'
        CHECK (quality_status IN ('unknown','usable','questionable','unusable_for_purpose')),
    content_hash TEXT,
    declared_source_locator TEXT CHECK(declared_source_locator IS NULL OR length(declared_source_locator) > 0),
    lifecycle_status TEXT NOT NULL DEFAULT 'active'
        CHECK (lifecycle_status IN ('active','void')),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    verification_level TEXT NOT NULL DEFAULT 'declared'
        CHECK(verification_level IN
            ('declared','source_verified','snapshot_verified','reproduced')),
    verification_state TEXT NOT NULL DEFAULT 'active'
        CHECK(verification_state IN
            ('active','verification_requested','conflict','unavailable','superseded')),
    mutable_source INTEGER NOT NULL DEFAULT 0 CHECK(mutable_source IN (0,1)),
    semantic_revision INTEGER NOT NULL DEFAULT 0,
    current_manifest_id TEXT REFERENCES evidence_manifests(manifest_id),
    current_proof_id TEXT REFERENCES evidence_proofs(proof_id)
, identity_locator TEXT NOT NULL DEFAULT '', search_locator TEXT NOT NULL DEFAULT '', locator_identity_version INTEGER NOT NULL DEFAULT 2
    CHECK(locator_identity_version = 2));

CREATE TRIGGER evidence_declared_source_immutable
BEFORE UPDATE OF declared_source_locator ON evidence_refs
WHEN OLD.declared_source_locator IS NOT NEW.declared_source_locator
BEGIN
    SELECT RAISE(ABORT, 'declared source locator is immutable');
END;

CREATE TABLE evidence_relation_events (
    relation_event_id TEXT PRIMARY KEY,
    relation_id TEXT NOT NULL REFERENCES evidence_relations(relation_id),
    event_type TEXT NOT NULL CHECK(event_type IN
        ('create','deactivate','reactivate','reclassify','amend')),
    before_json TEXT NOT NULL DEFAULT '{}',
    after_json TEXT NOT NULL DEFAULT '{}',
    reason TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE evidence_relation_impacts (
    impact_id TEXT PRIMARY KEY,
    source_event_type TEXT NOT NULL,
    source_event_id TEXT,
    relation_id TEXT NOT NULL REFERENCES evidence_relations(relation_id),
    provider_evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    consumer_evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    affected_issue_id TEXT REFERENCES issues(issue_id),
    affected_conclusion_id TEXT REFERENCES conclusion_revisions(conclusion_id),
    refresh_task_id TEXT REFERENCES refresh_tasks(refresh_task_id),
    impact_policy TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK(disposition IN
        ('recorded','refresh_enqueued','publication_blocked','review_required')),
    details_json TEXT NOT NULL DEFAULT '{}',
    impact_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE evidence_relations (
    relation_id TEXT PRIMARY KEY,
    consumer_evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    provider_evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    relation_type TEXT NOT NULL CHECK(relation_type IN
        ('depends_on','derived_from','reproduces','supports','challenges','amends',
         'duplicates','context_for')),
    impact_policy TEXT NOT NULL CHECK(impact_policy IN
        ('hard','soft','informational')),
    rationale TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    provider_snapshot_hash TEXT NOT NULL,
    consumer_snapshot_hash TEXT NOT NULL,
    template_registration_id TEXT REFERENCES registry_entries(registration_id),
    template_content_hash TEXT,
    actor_id TEXT NOT NULL,
    run_id TEXT,
    request_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(consumer_evidence_id <> provider_evidence_id)
);

CREATE TABLE evidence_request_events (
    request_event_id TEXT PRIMARY KEY,
    evidence_request_id TEXT NOT NULL REFERENCES evidence_requests(evidence_request_id),
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE evidence_requests (
    evidence_request_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    platform_id TEXT NOT NULL REFERENCES platform_sources(platform_id),
    issue_id TEXT REFERENCES issues(issue_id),
    proposal_id TEXT REFERENCES proposals(proposal_id),
    source_packet_id TEXT REFERENCES intake_packets(packet_id),
    request_version INTEGER NOT NULL,
    request_type TEXT NOT NULL CHECK(request_type IN
        ('metadata','existence','preview','statistics','reanalysis')),
    question TEXT NOT NULL,
    requested_outputs_json TEXT NOT NULL,
    method_constraints_json TEXT NOT NULL,
    priority INTEGER NOT NULL CHECK(priority BETWEEN 0 AND 100),
    state TEXT NOT NULL CHECK(state IN
        ('pending','claimed','running','answered','failed','cancelled','expired')),
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    claimed_by TEXT REFERENCES actors(actor_id),
    claimed_run_id TEXT REFERENCES agent_runs(run_id),
    lease_until TEXT,
    lease_generation INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deadline_at TEXT,
    last_error TEXT
, request_role TEXT NOT NULL DEFAULT 'source_verification'
    CHECK(request_role IN
        ('source_verification','independent_verification','conflict_resolution')), requested_manifest_id TEXT
    REFERENCES evidence_manifests(manifest_id), requested_manifest_hash TEXT);

CREATE TABLE evidence_responses (
    evidence_response_id TEXT PRIMARY KEY,
    evidence_request_id TEXT NOT NULL REFERENCES evidence_requests(evidence_request_id),
    request_version INTEGER NOT NULL,
    platform_id TEXT NOT NULL REFERENCES platform_sources(platform_id),
    responder_actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    responder_run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    response_type TEXT NOT NULL,
    statement TEXT NOT NULL,
    input_snapshot_json TEXT NOT NULL,
    result_json TEXT NOT NULL,
    artifact_ids_json TEXT NOT NULL,
    output_hashes_json TEXT NOT NULL,
    analysis_run_id TEXT REFERENCES analysis_runs(analysis_run_id),
    lease_generation INTEGER NOT NULL,
    token_epoch INTEGER NOT NULL,
    response_hash TEXT NOT NULL,
    created_at TEXT NOT NULL, request_role TEXT NOT NULL DEFAULT 'source_verification', qualified_manifest_id TEXT
    REFERENCES evidence_manifests(manifest_id), qualified_manifest_hash TEXT, artifact_platform_snapshot_json TEXT NOT NULL DEFAULT '{}', analysis_platform_snapshot_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(evidence_request_id, response_hash)
);

CREATE TABLE evidence_semantic_events (
    semantic_event_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    from_semantic_revision INTEGER NOT NULL,
    to_semantic_revision INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    trigger_object_type TEXT NOT NULL,
    trigger_object_id TEXT NOT NULL,
    before_proof_id TEXT REFERENCES evidence_proofs(proof_id),
    after_proof_id TEXT REFERENCES evidence_proofs(proof_id),
    impact_class TEXT NOT NULL CHECK(impact_class IN
        ('none','notify','impact_review','stale','blocked')),
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL
, cause_json TEXT NOT NULL DEFAULT '{}');

CREATE TABLE evidence_source_binding_events (
    binding_event_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    before_json TEXT NOT NULL,
    after_json TEXT NOT NULL,
    event_type TEXT NOT NULL,
    reason TEXT NOT NULL,
    actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    created_at TEXT NOT NULL
, reviewed_changeset_id TEXT, review_ids_json TEXT NOT NULL DEFAULT '[]');

CREATE TABLE evidence_source_bindings (
    evidence_id TEXT PRIMARY KEY REFERENCES evidence_refs(evidence_id),
    source_platform_id TEXT REFERENCES platform_sources(platform_id),
    binding_state TEXT NOT NULL CHECK(binding_state IN
        ('bound','legacy_unbound','inferred','binding_conflict','retired')),
    source_key TEXT,
    binding_revision INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    reviewed_at TEXT,
    reviewed_by TEXT REFERENCES actors(actor_id),
    reason TEXT NOT NULL
);

CREATE TABLE evidence_verification_events (
    verification_event_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    event_type TEXT NOT NULL,
    before_json TEXT NOT NULL,
    after_json TEXT NOT NULL,
    trigger_object_type TEXT NOT NULL,
    trigger_object_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    created_at TEXT NOT NULL
);

CREATE TABLE extension_bundles (
    bundle_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    bundle_format TEXT NOT NULL,
    core_api_range TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    content_hash TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK(state IN
        ('installed','active','deprecated','disabled','retired')),
    installed_at TEXT NOT NULL,
    installed_by TEXT NOT NULL REFERENCES actors(actor_id),
    activated_at TEXT,
    disabled_reason TEXT NOT NULL DEFAULT '',
    lock_snapshot_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE(namespace,name,version)
);

CREATE TABLE external_mapping_targets (
    source_object_mapping_id TEXT NOT NULL
        REFERENCES external_object_mappings(source_object_mapping_id),
    internal_object_type TEXT NOT NULL,
    internal_object_id TEXT NOT NULL,
    internal_revision_id TEXT,
    linked_at TEXT NOT NULL,
    PRIMARY KEY(source_object_mapping_id,internal_object_type,internal_object_id)
);

CREATE TABLE external_object_mappings (
    source_object_mapping_id TEXT PRIMARY KEY,
    source_namespace TEXT NOT NULL,
    source_owner TEXT NOT NULL,
    external_object_type TEXT NOT NULL,
    external_object_id TEXT NOT NULL,
    mapping_role TEXT NOT NULL,
    first_import_job_id TEXT NOT NULL REFERENCES import_jobs(import_job_id),
    latest_import_job_id TEXT NOT NULL REFERENCES import_jobs(import_job_id),
    external_content_hash TEXT NOT NULL,
    mapping_profile_registration_id TEXT REFERENCES registry_entries(registration_id),
    mapping_profile_content_hash TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(source_namespace,source_owner,external_object_type,external_object_id,mapping_role)
);

CREATE TABLE field_bundle_attachments (
    field_bundle_id TEXT NOT NULL REFERENCES field_bundles(field_bundle_id),
    attachment_path TEXT NOT NULL,
    expected_sha256 TEXT NOT NULL,
    expected_size INTEGER,
    mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    artifact_id TEXT REFERENCES artifacts(artifact_id),
    upload_token_hash TEXT,
    upload_state TEXT NOT NULL CHECK(upload_state IN
        ('missing','uploading','verified','failed')),
    received_bytes INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    verified_at TEXT,
    PRIMARY KEY(field_bundle_id,attachment_path)
);

CREATE TABLE field_bundle_event_actions (
    field_bundle_event_action_id TEXT PRIMARY KEY,
    field_bundle_event_id TEXT NOT NULL REFERENCES field_bundle_events(field_bundle_event_id),
    action_index INTEGER NOT NULL,
    action_type TEXT NOT NULL,
    action_json TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN
        ('planned','ready','applied','rejected','failed','replayed','conflicted','needs_triage')),
    result_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    target_issue_id TEXT REFERENCES issues(issue_id),
    target_record_instance_id TEXT REFERENCES record_instances(record_instance_id),
    base_record_revision_id TEXT REFERENCES record_revisions(record_revision_id),
    record_template_registration_id TEXT REFERENCES registry_entries(registration_id),
    record_template_content_hash TEXT,
    conflict_policy TEXT CHECK(conflict_policy IS NULL OR conflict_policy='create_conflict'),
    validation_state TEXT NOT NULL,
    UNIQUE(field_bundle_event_id,action_index),
    UNIQUE(field_bundle_event_id,action_hash),
    CHECK(
        action_type <> 'record_revise' OR state='needs_triage' OR
        (target_record_instance_id IS NOT NULL AND base_record_revision_id IS NOT NULL
         AND conflict_policy='create_conflict')
    )
);

CREATE TABLE field_bundle_events (
    field_bundle_event_id TEXT PRIMARY KEY,
    field_bundle_id TEXT NOT NULL REFERENCES field_bundles(field_bundle_id),
    event_index INTEGER NOT NULL,
    event_type TEXT NOT NULL CHECK(event_type IN
        ('question','action','observation','interpretation','alternative','decision',
         'next_action','evidence_locator','record_patch','relationship_hint')),
    event_json TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    processing_state TEXT NOT NULL CHECK(processing_state IN
        ('pending','staged','ready','applied','needs_triage','rejected','failed','replayed')),
    result_json TEXT NOT NULL,
    target_object_type TEXT,
    target_object_id TEXT,
    target_revision_id TEXT,
    state_revision INTEGER NOT NULL DEFAULT 0,
    UNIQUE(field_bundle_id,event_index),
    UNIQUE(field_bundle_id,event_hash)
);

CREATE TABLE field_bundle_receipts (
    field_bundle_receipt_id TEXT PRIMARY KEY,
    field_bundle_id TEXT NOT NULL REFERENCES field_bundles(field_bundle_id),
    content_hash TEXT NOT NULL,
    result_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE,
    context_cursor INTEGER,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id)
);

CREATE TABLE field_bundles (
    field_bundle_id TEXT PRIMARY KEY,
    bundle_version TEXT NOT NULL,
    source_namespace TEXT NOT NULL,
    source_owner TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN
        ('received','validated','staged','routing','ready','applying','applied',
         'needs_triage','failed')),
    base_activity_cursor INTEGER,
    parent_bundle_id TEXT REFERENCES field_bundles(field_bundle_id),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    uploaded_at TEXT NOT NULL,
    routing_state_revision INTEGER NOT NULL DEFAULT 0,
    apply_cursor INTEGER NOT NULL DEFAULT 0,
    last_error_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(field_bundle_id,content_hash)
);

CREATE TABLE governed_conflict_resolution_receipts (
    receipt_id TEXT PRIMARY KEY,
    conflict_domain TEXT NOT NULL CHECK(conflict_domain IN ('field_bundle','import')),
    conflict_id TEXT NOT NULL REFERENCES integration_conflicts(integration_conflict_id),
    changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
    changeset_hash TEXT NOT NULL,
    operation_ordinal INTEGER NOT NULL,
    operation_hash TEXT NOT NULL,
    target_object_type TEXT NOT NULL,
    target_object_id TEXT NOT NULL,
    expected_current_revision_id TEXT,
    candidate_hash TEXT NOT NULL,
    resolution_action TEXT NOT NULL,
    resolution_payload_hash TEXT NOT NULL,
    review_ids_json TEXT NOT NULL,
    result_object_id TEXT,
    result_revision_id TEXT,
    result_hash TEXT NOT NULL,
    applied_at TEXT NOT NULL,
    applied_by TEXT NOT NULL REFERENCES actors(actor_id),
    event_id TEXT NOT NULL REFERENCES audit_events(event_id),
    UNIQUE(conflict_domain,conflict_id),
    UNIQUE(changeset_id,operation_ordinal),
    FOREIGN KEY(changeset_id,operation_ordinal)
        REFERENCES changeset_operations(changeset_id,ordinal)
);

CREATE TABLE import_item_errors (
    import_error_id TEXT PRIMARY KEY,
    import_item_id TEXT NOT NULL REFERENCES import_items(import_item_id),
    field_path TEXT NOT NULL,
    error_code TEXT NOT NULL,
    message TEXT NOT NULL,
    details_json TEXT NOT NULL
);

CREATE TABLE import_items (
    import_item_id TEXT PRIMARY KEY,
    import_job_id TEXT NOT NULL REFERENCES import_jobs(import_job_id),
    item_index INTEGER NOT NULL,
    external_object_type TEXT NOT NULL,
    external_object_id TEXT NOT NULL,
    raw_location TEXT NOT NULL,
    raw_fragment_json TEXT NOT NULL,
    raw_fragment_hash TEXT NOT NULL,
    mapped_data_json TEXT NOT NULL,
    extensions_json TEXT NOT NULL,
    migration_level TEXT NOT NULL CHECK(migration_level IN
        ('index','structure','evidence_backfill')),
    validation_state TEXT NOT NULL CHECK(validation_state IN
        ('pending','valid','invalid','possible_duplicate','conflict','applied','replayed')),
    target_issue_id TEXT REFERENCES issues(issue_id),
    target_template_registration_id TEXT REFERENCES registry_entries(registration_id),
    applied_object_type TEXT,
    applied_object_id TEXT,
    UNIQUE(import_job_id,item_index),
    UNIQUE(import_job_id,external_object_type,external_object_id)
);

CREATE TABLE import_jobs (
    import_job_id TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK(state IN
        ('created','inspected','staged','needs_mapping','needs_input','validated',
         'review_required','ready','applying','applied','partially_applied',
         'failed','cancelled')),
    source_namespace TEXT NOT NULL,
    source_owner TEXT NOT NULL,
    source_system TEXT NOT NULL,
    source_exported_at TEXT,
    source_timezone TEXT,
    adapter_name TEXT NOT NULL,
    adapter_version TEXT NOT NULL,
    adapter_hash TEXT NOT NULL,
    mapping_registration_id TEXT REFERENCES registry_entries(registration_id),
    mapping_content_hash TEXT,
    source_files_json TEXT NOT NULL,
    bundle_json TEXT NOT NULL,
    bundle_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    updated_at TEXT NOT NULL,
    reviewed_changeset_id TEXT REFERENCES changesets(changeset_id),
    apply_cursor INTEGER NOT NULL DEFAULT 0,
    UNIQUE(source_namespace,source_owner,bundle_hash)
);

CREATE TABLE import_manifest_candidates (
    import_manifest_candidate_id TEXT PRIMARY KEY,
    import_job_id TEXT NOT NULL REFERENCES import_jobs(import_job_id),
    import_item_id TEXT NOT NULL REFERENCES import_items(import_item_id),
    evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    source_namespace TEXT NOT NULL,
    source_owner TEXT NOT NULL,
    source_system TEXT NOT NULL,
    raw_fragment_hash TEXT NOT NULL,
    candidate_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending_review','materialized','rejected')),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    UNIQUE(import_item_id)
);

CREATE TABLE import_receipts (
    import_receipt_id TEXT PRIMARY KEY,
    import_job_id TEXT NOT NULL REFERENCES import_jobs(import_job_id),
    chunk_index INTEGER NOT NULL,
    from_cursor INTEGER NOT NULL,
    to_cursor INTEGER NOT NULL,
    result_json TEXT NOT NULL,
    result_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    UNIQUE(import_job_id,chunk_index)
);

CREATE TABLE intake_answers (
    answer_id TEXT PRIMARY KEY,
    question_id TEXT NOT NULL REFERENCES intake_questions(question_id),
    packet_id TEXT NOT NULL REFERENCES intake_packets(packet_id),
    answer_json TEXT NOT NULL,
    answered_by TEXT NOT NULL REFERENCES actors(actor_id),
    answered_run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    created_at TEXT NOT NULL
);

CREATE TABLE intake_evidence (
    packet_id TEXT NOT NULL REFERENCES intake_packets(packet_id),
    ordinal INTEGER NOT NULL,
    kind TEXT NOT NULL,
    locator TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    evidence_id TEXT REFERENCES evidence_refs(evidence_id),
    PRIMARY KEY(packet_id, ordinal)
);

CREATE TABLE intake_group_members (
    group_id TEXT NOT NULL REFERENCES intake_groups(group_id),
    packet_id TEXT NOT NULL REFERENCES intake_packets(packet_id),
    projection_key TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(group_id, packet_id, projection_key)
);

CREATE TABLE intake_groups (
    group_id TEXT PRIMARY KEY,
    group_kind TEXT NOT NULL CHECK(group_kind IN ('group','split','merge')),
    episode_issue_id TEXT REFERENCES issues(issue_id),
    plan_json TEXT NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    created_at TEXT NOT NULL
);

CREATE TABLE intake_packet_links (
    link_id TEXT PRIMARY KEY,
    source_packet_id TEXT NOT NULL REFERENCES intake_packets(packet_id),
    target_packet_id TEXT NOT NULL REFERENCES intake_packets(packet_id),
    link_type TEXT NOT NULL CHECK(link_type IN
        ('followup_of','tests_hypothesis_of','challenges','amends','duplicates',
         'grouped_with','split_from')),
    proposed_by TEXT NOT NULL REFERENCES actors(actor_id),
    proposed_run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    rationale TEXT NOT NULL,
    created_at TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    CHECK(source_packet_id <> target_packet_id)
);

CREATE TABLE intake_packets (
    packet_id TEXT PRIMARY KEY,
    packet_version INTEGER NOT NULL,
    request_id TEXT NOT NULL UNIQUE,
    packet_json TEXT NOT NULL,
    packet_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending','claimed','attached','needs_input','completed','rejected','merged')),
    submitted_by TEXT NOT NULL REFERENCES actors(actor_id),
    submitted_run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    attached_issue_id TEXT REFERENCES issues(issue_id),
    merged_into_packet_id TEXT REFERENCES intake_packets(packet_id)
, routing_state TEXT NOT NULL DEFAULT 'unresolved', last_triage_error TEXT, routing_snapshot_json TEXT NOT NULL DEFAULT '{}', routing_policy_version INTEGER);

CREATE TABLE intake_questions (
    question_id TEXT PRIMARY KEY,
    packet_id TEXT NOT NULL REFERENCES intake_packets(packet_id),
    question TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('open','answered','closed')),
    asked_by TEXT NOT NULL REFERENCES actors(actor_id),
    asked_run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    created_at TEXT NOT NULL,
    answered_at TEXT
);

CREATE TABLE integration_conflict_resolutions (
    integration_conflict_resolution_id TEXT PRIMARY KEY,
    integration_conflict_id TEXT NOT NULL REFERENCES integration_conflicts(integration_conflict_id),
    from_revision INTEGER NOT NULL,
    to_revision INTEGER NOT NULL,
    action TEXT NOT NULL,
    reason TEXT NOT NULL,
    details_json TEXT NOT NULL,
    reviewed_changeset_id TEXT REFERENCES changesets(changeset_id),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    UNIQUE(integration_conflict_id,to_revision)
);

CREATE TABLE integration_conflicts (
    integration_conflict_id TEXT PRIMARY KEY,
    source_kind TEXT NOT NULL CHECK(source_kind IN ('import','field_bundle')),
    source_job_id TEXT NOT NULL,
    source_item_id TEXT NOT NULL,
    source_namespace TEXT NOT NULL,
    source_owner TEXT NOT NULL,
    external_object_type TEXT NOT NULL,
    external_object_id TEXT NOT NULL,
    existing_mapping_id TEXT,
    existing_internal_revision_id TEXT,
    previous_external_hash TEXT,
    candidate_external_hash TEXT NOT NULL,
    raw_fragment_json TEXT NOT NULL,
    mapped_candidate_json TEXT NOT NULL,
    mapping_registration_id TEXT,
    mapping_content_hash TEXT,
    state TEXT NOT NULL CHECK(state IN
        ('open','needs_more_information','resolved','cancelled')),
    state_revision INTEGER NOT NULL DEFAULT 0,
    resolution_action TEXT,
    resolution_reason TEXT NOT NULL DEFAULT '',
    detected_at TEXT NOT NULL,
    detected_by TEXT NOT NULL REFERENCES actors(actor_id),
    resolved_at TEXT,
    resolved_by TEXT REFERENCES actors(actor_id),
    UNIQUE(source_kind,source_item_id,candidate_external_hash)
);

CREATE TABLE integrity_quarantines (
    quarantine_id TEXT PRIMARY KEY,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    subject_hash TEXT NOT NULL,
    finding_id TEXT NOT NULL REFERENCES migration_findings(finding_id),
    scope_json TEXT NOT NULL,
    scope_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('active','released')),
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    released_at TEXT,
    released_by TEXT REFERENCES actors(actor_id),
    release_receipt_id TEXT REFERENCES migration_finding_resolution_receipts(receipt_id),
    event_id TEXT NOT NULL REFERENCES audit_events(event_id),
    CHECK(
        (state='active' AND released_at IS NULL AND released_by IS NULL
         AND release_receipt_id IS NULL) OR
        (state='released' AND released_at IS NOT NULL AND released_by IS NOT NULL
         AND release_receipt_id IS NOT NULL)
    )
);

CREATE TABLE issue_aliases (
    issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    alias TEXT NOT NULL,
    normalized_alias TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    PRIMARY KEY(issue_id, normalized_alias)
);

CREATE TABLE issue_evidence (
    issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    attached_at TEXT NOT NULL,
    attached_by TEXT NOT NULL,
    PRIMARY KEY(issue_id, evidence_id)
);

CREATE TABLE issue_question_events (
    question_event_id TEXT PRIMARY KEY,
    question_id TEXT NOT NULL REFERENCES issue_questions(question_id),
    event_type TEXT NOT NULL CHECK(event_type IN
        ('create','edit','start','block','answer','reopen','defer','cancel','attach_evidence')),
    from_status TEXT,
    to_status TEXT,
    revision_number INTEGER NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE issue_question_evidence_links (
        relation_id TEXT PRIMARY KEY,
        question_id TEXT NOT NULL REFERENCES issue_questions(question_id),
        evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
        link_type TEXT NOT NULL CHECK(link_type IN ('addresses','supports','challenges','context')),
        rationale TEXT NOT NULL DEFAULT '',
        active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
        created_at TEXT NOT NULL, created_by TEXT NOT NULL
    );

CREATE TABLE issue_question_revisions (
    question_id TEXT NOT NULL REFERENCES issue_questions(question_id),
    revision_number INTEGER NOT NULL CHECK(revision_number >= 1),
    prompt TEXT NOT NULL,
    motivation TEXT NOT NULL,
    question_kind TEXT NOT NULL,
    status TEXT NOT NULL,
    priority INTEGER NOT NULL,
    expected_evidence_json TEXT NOT NULL,
    answer_conclusion_id TEXT REFERENCES conclusion_revisions(conclusion_id),
    status_reason TEXT NOT NULL,
    snapshot_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    PRIMARY KEY(question_id,revision_number)
);

CREATE TABLE issue_questions (
    question_id TEXT PRIMARY KEY,
    issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    question_key TEXT,
    prompt TEXT NOT NULL,
    motivation TEXT NOT NULL DEFAULT '',
    question_kind TEXT NOT NULL CHECK(question_kind IN
        ('experiment','analysis','data_gap','conflict','verification','decision')),
    status TEXT NOT NULL CHECK(status IN
        ('open','in_progress','blocked','answered','deferred','cancelled')),
    priority INTEGER NOT NULL DEFAULT 50 CHECK(priority BETWEEN 0 AND 100),
    expected_evidence_json TEXT NOT NULL DEFAULT '[]',
    source_kind TEXT,
    source_id TEXT,
    answer_conclusion_id TEXT REFERENCES conclusion_revisions(conclusion_id),
    current_revision INTEGER NOT NULL DEFAULT 1 CHECK(current_revision >= 1),
    template_registration_id TEXT REFERENCES registry_entries(registration_id),
    template_content_hash TEXT,
    template_snapshot_json TEXT NOT NULL DEFAULT '{}',
    status_reason TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);

CREATE TABLE issue_rollup_policies (
    issue_id TEXT PRIMARY KEY REFERENCES issues(issue_id),
    policy_version TEXT NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN
        ('local_only','explicit_providers','direct_children','subtree_conclusions',
         'manual_explicit')),
    policy_json TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    source_registration_id TEXT REFERENCES registry_entries(registration_id),
    source_content_hash TEXT,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE issue_tags (
    issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    tag TEXT NOT NULL,
    normalized_tag TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    PRIMARY KEY(issue_id, normalized_tag)
);

CREATE TABLE issues (
    issue_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    issue_type TEXT NOT NULL,
    scope_json TEXT NOT NULL DEFAULT '{}',
    parent_issue_id TEXT REFERENCES issues(issue_id),
    work_status TEXT NOT NULL DEFAULT 'open'
        CHECK (work_status IN ('open','monitoring','resolved','archived','void')),
    conclusion_status TEXT NOT NULL DEFAULT 'none'
        CHECK (conclusion_status IN ('none','draft','provisional','accepted','canonical','disputed','superseded','retracted')),
    working_revision INTEGER NOT NULL DEFAULT 0,
    conclusion_revision INTEGER NOT NULL DEFAULT 0,
    current_conclusion_id TEXT,
    freshness TEXT NOT NULL DEFAULT 'fresh'
        CHECK (freshness IN ('fresh','stale','impact_review','descendant_dirty','blocked','canonical_gap')),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    policy_version INTEGER NOT NULL
, normalized_scope_key TEXT, topic TEXT, canonical_alias TEXT, issue_type_registration_id TEXT
    REFERENCES registry_entries(registration_id), issue_type_content_hash TEXT NOT NULL DEFAULT '', issue_type_snapshot_json TEXT NOT NULL DEFAULT '{}', issue_type_semantic_hash TEXT NOT NULL DEFAULT '');

CREATE TABLE legacy_v14_candidates (
    candidate_id TEXT PRIMARY KEY,
    candidate_kind TEXT NOT NULL CHECK(candidate_kind IN
        ('legacy_question','legacy_packet_relation','hard_provider_missing_conclusion',
         'rollup_mismatch')),
    source_object_type TEXT NOT NULL,
    source_object_id TEXT NOT NULL,
    issue_id TEXT REFERENCES issues(issue_id),
    candidate_json TEXT NOT NULL,
    candidate_hash TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL DEFAULT 'pending_review' CHECK(state IN
        ('pending_review','accepted','ignored','merged')),
    created_at TEXT NOT NULL
);

CREATE TABLE managed_relation_heads (
        domain TEXT NOT NULL,
        relation_id TEXT NOT NULL,
        version_id TEXT NOT NULL REFERENCES managed_relation_versions(version_id),
        PRIMARY KEY(domain,relation_id)
    );

CREATE TABLE managed_relation_versions (
        version_id TEXT PRIMARY KEY,
        domain TEXT NOT NULL CHECK(domain IN ('issue','evidence','question','intake','record','context')),
        relation_id TEXT NOT NULL,
        version_number INTEGER NOT NULL,
        contract_version TEXT NOT NULL,
        definition_json TEXT NOT NULL CHECK(json_valid(definition_json)),
        UNIQUE(domain,relation_id,version_number)
    );

CREATE TABLE manager_metadata (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    active_generation TEXT NOT NULL,
    token_epoch INTEGER NOT NULL DEFAULT 1,
    maintenance_mode INTEGER NOT NULL DEFAULT 0 CHECK(maintenance_mode IN (0,1)),
    updated_at TEXT NOT NULL
);

CREATE TABLE migration_finding_resolution_attempts (
    attempt_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES migration_findings(finding_id),
    finding_code TEXT NOT NULL,
    finding_subject_hash TEXT NOT NULL,
    action TEXT NOT NULL,
    resolution_json TEXT NOT NULL,
    resolution_hash TEXT NOT NULL,
    validator_id TEXT NOT NULL,
    validator_version INTEGER NOT NULL,
    validation_result_json TEXT NOT NULL,
    validation_result_hash TEXT NOT NULL,
    accepted INTEGER NOT NULL CHECK(accepted IN (0,1)),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    event_id TEXT REFERENCES audit_events(event_id)
);

CREATE TABLE migration_finding_resolution_receipts (
    receipt_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL UNIQUE REFERENCES migration_findings(finding_id),
    accepted_attempt_id TEXT NOT NULL UNIQUE
        REFERENCES migration_finding_resolution_attempts(attempt_id),
    subject_before_hash TEXT NOT NULL,
    subject_after_hash TEXT NOT NULL,
    invariant_id TEXT NOT NULL,
    invariant_version INTEGER NOT NULL,
    resolved_at TEXT NOT NULL,
    resolved_by TEXT NOT NULL REFERENCES actors(actor_id),
    event_id TEXT NOT NULL REFERENCES audit_events(event_id)
, resolution_hash TEXT NOT NULL DEFAULT '', dependency_snapshot_hash TEXT NOT NULL DEFAULT '', invariant_parameters_json TEXT NOT NULL DEFAULT '{}', invariant_parameters_hash TEXT NOT NULL DEFAULT '', postcondition_json TEXT NOT NULL DEFAULT '{}', postcondition_hash TEXT NOT NULL DEFAULT '', proof_hash TEXT NOT NULL DEFAULT '', proof_format TEXT NOT NULL DEFAULT 'migration-resolution-proof/v1');

CREATE TABLE migration_findings (
    finding_id TEXT PRIMARY KEY,
    migration_version INTEGER NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    classification TEXT NOT NULL CHECK(classification IN
        ('safe_auto_migration','requires_reprepare','requires_triage',
         'requires_policy_mapping','historical_json_finding','blocking_corruption')),
    code TEXT NOT NULL,
    details_json TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'open' CHECK(state IN ('open','resolved','waived')),
    resolved_at TEXT,
    resolved_by TEXT REFERENCES actors(actor_id),
    resolution_json TEXT, resolution_receipt_id TEXT
    REFERENCES migration_finding_resolution_receipts(receipt_id),
    UNIQUE(migration_version,object_type,object_id,code)
);

CREATE TABLE migration_policy_repairs (
    repair_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES migration_findings(finding_id),
    source_bundle_id TEXT NOT NULL REFERENCES extension_bundles(bundle_id),
    source_bundle_hash TEXT NOT NULL,
    source_policy_hash TEXT NOT NULL,
    finding_fingerprint_json TEXT NOT NULL,
    finding_fingerprint_hash TEXT NOT NULL,
    repair_mode TEXT NOT NULL CHECK(repair_mode IN
        ('replacement_policy_snapshot','replacement_feature_bundle')),
    replacement_policy_json TEXT,
    replacement_policy_hash TEXT,
    replacement_bundle_json TEXT,
    replacement_bundle_hash TEXT,
    prepared_bundle_json TEXT NOT NULL,
    prepared_bundle_hash TEXT NOT NULL,
    reference_locks_json TEXT NOT NULL,
    reference_locks_hash TEXT NOT NULL,
    issue_binding_map_json TEXT NOT NULL,
    issue_binding_map_hash TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    plan_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN
        ('draft','validated','applied','rejected','stale','superseded')),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    validated_at TEXT,
    applied_at TEXT,
    superseded_at TEXT
);

CREATE TABLE migration_resolution_dependencies (
    receipt_id TEXT NOT NULL REFERENCES migration_finding_resolution_receipts(receipt_id),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    dependency_type TEXT NOT NULL CHECK(dependency_type IN
        ('extension_bundle','registry_registration','policy_repair_candidate',
         'record_template_snapshot','issue_type_semantic_snapshot','record_revision',
         'conclusion_revision','artifact','changeset_operation','integrity_quarantine')),
    dependency_id TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    state TEXT NOT NULL,
    required_states_json TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    snapshot_hash TEXT NOT NULL,
    PRIMARY KEY(receipt_id,ordinal),
    UNIQUE(receipt_id,dependency_type,dependency_id)
);

CREATE TABLE migration_resolution_replays (
    replay_id TEXT PRIMARY KEY,
    receipt_id TEXT NOT NULL REFERENCES migration_finding_resolution_receipts(receipt_id),
    proof_key TEXT NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN ('default','full')),
    result_json TEXT NOT NULL,
    result_hash TEXT NOT NULL,
    valid INTEGER NOT NULL CHECK(valid IN (0,1)),
    replayed_at TEXT NOT NULL,
    replayed_by TEXT NOT NULL,
    UNIQUE(receipt_id,proof_key,mode,result_hash)
);

CREATE TABLE platform_sources (
    platform_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active','disabled','retired')),
    capabilities_json TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE policy_snapshots (
    policy_version INTEGER PRIMARY KEY,
    policy_json TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE TABLE principal_profile_assignments (
    actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    profile_name TEXT NOT NULL REFERENCES capability_profiles(profile_name),
    assigned_at TEXT NOT NULL,
    assigned_by TEXT NOT NULL,
    PRIMARY KEY(actor_id, profile_name)
);

CREATE TABLE profile_capabilities (
    profile_name TEXT NOT NULL REFERENCES capability_profiles(profile_name),
    capability TEXT NOT NULL,
    PRIMARY KEY(profile_name, capability)
);

CREATE TABLE proposal_basis (
    proposal_id TEXT NOT NULL REFERENCES proposals(proposal_id),
    provider_issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    provider_revision INTEGER NOT NULL,
    provider_conclusion_id TEXT NOT NULL REFERENCES conclusion_revisions(conclusion_id),
    basis_mode TEXT NOT NULL CHECK(basis_mode IN ('current','historical')),
    historical_reason TEXT,
    PRIMARY KEY(proposal_id, provider_issue_id)
);

CREATE TABLE proposals (
    proposal_id TEXT PRIMARY KEY,
    issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    target_status TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('draft','validated','under_review','review_passed','review_rejected','applied','expired')),
    proposal_json TEXT NOT NULL,
    proposal_hash TEXT NOT NULL,
    basis_snapshot_token TEXT NOT NULL,
    proposer_actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    proposer_run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    required_reviews INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    applied_conclusion_id TEXT REFERENCES conclusion_revisions(conclusion_id),
    rejection_reason TEXT
, source_changeset_id TEXT REFERENCES changesets(changeset_id), risk_tier TEXT NOT NULL DEFAULT 'T1', risk_reasons_json TEXT NOT NULL DEFAULT '[]');

CREATE TABLE publication_waivers (
    waiver_id TEXT PRIMARY KEY,
    issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    scope TEXT NOT NULL,
    reason TEXT NOT NULL,
    proposal_id TEXT REFERENCES proposals(proposal_id),
    source_changeset_id TEXT REFERENCES changesets(changeset_id),
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    CHECK(proposal_id IS NOT NULL OR source_changeset_id IS NOT NULL)
);

CREATE TABLE record_evidence_links (
    record_revision_id TEXT NOT NULL REFERENCES record_revisions(record_revision_id),
    field_path TEXT NOT NULL,
    evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    proof_id TEXT REFERENCES evidence_proofs(proof_id),
    relation_role TEXT NOT NULL CHECK(relation_role IN
        ('produced_by','supports','contradicts','calibration','context')), proof_hash TEXT, manifest_id TEXT
    REFERENCES evidence_manifests(manifest_id), manifest_hash TEXT, evidence_semantic_revision INTEGER, verification_level_snapshot TEXT, verification_state_snapshot TEXT,
    PRIMARY KEY(record_revision_id,field_path,evidence_id,relation_role)
);

CREATE TABLE record_instances (
    record_instance_id TEXT PRIMARY KEY,
    issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    record_template_registration_id TEXT NOT NULL REFERENCES registry_entries(registration_id),
    record_template_snapshot_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    current_revision_id TEXT,
    lifecycle_status TEXT NOT NULL CHECK(lifecycle_status IN
        ('active','archived','void')),
    UNIQUE(issue_id,record_template_registration_id,record_instance_id)
);

CREATE TABLE record_material_relations (relation_id TEXT PRIMARY KEY, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    record_revision_id TEXT NOT NULL REFERENCES record_revisions(record_revision_id),
    field_path TEXT NOT NULL,
    evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    proof_id TEXT REFERENCES evidence_proofs(proof_id),
    relation_role TEXT NOT NULL CHECK(relation_role IN
        ('produced_by','supports','contradicts','calibration','context')), proof_hash TEXT, manifest_id TEXT
    REFERENCES evidence_manifests(manifest_id), manifest_hash TEXT, evidence_semantic_revision INTEGER, verification_level_snapshot TEXT, verification_state_snapshot TEXT
);

CREATE TABLE record_revisions (
    record_revision_id TEXT PRIMARY KEY,
    record_instance_id TEXT NOT NULL REFERENCES record_instances(record_instance_id),
    revision_number INTEGER NOT NULL,
    template_content_hash TEXT NOT NULL,
    template_snapshot_json TEXT NOT NULL,
    data_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    recorded_by TEXT NOT NULL REFERENCES actors(actor_id),
    source_mode TEXT NOT NULL CHECK(source_mode IN
        ('native','imported','field_bundle','migrated')),
    source_object_mapping_id TEXT,
    supersedes_revision_id TEXT REFERENCES record_revisions(record_revision_id),
    validation_profile TEXT NOT NULL,
    validation_result_json TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    UNIQUE(record_instance_id,revision_number),
    UNIQUE(record_instance_id,content_hash)
);

CREATE TABLE record_validation_findings (
    record_validation_finding_id TEXT PRIMARY KEY,
    record_revision_id TEXT NOT NULL REFERENCES record_revisions(record_revision_id),
    field_path TEXT NOT NULL,
    finding_code TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('open','resolved','superseded')),
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE TABLE record_value_index (
    record_revision_id TEXT NOT NULL REFERENCES record_revisions(record_revision_id),
    field_path TEXT NOT NULL,
    value_type TEXT NOT NULL,
    number_value REAL,
    text_value TEXT,
    boolean_value INTEGER CHECK(boolean_value IN (0,1)),
    unit_code TEXT,
    observed_at TEXT,
    quality_state TEXT,
    PRIMARY KEY(record_revision_id,field_path)
);

CREATE TABLE refresh_task_events (
    task_event_id TEXT PRIMARY KEY,
    refresh_task_id TEXT NOT NULL REFERENCES refresh_tasks(refresh_task_id),
    trigger_issue_id TEXT REFERENCES issues(issue_id),
    from_revision INTEGER,
    to_revision INTEGER,
    reason_type TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE refresh_tasks (
    refresh_task_id TEXT PRIMARY KEY,
    issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    reason_type TEXT NOT NULL CHECK (reason_type IN ('child_changed','dependency_changed','retracted','manual','report_build')),
    trigger_issue_id TEXT REFERENCES issues(issue_id),
    from_revision INTEGER,
    to_revision INTEGER,
    priority INTEGER NOT NULL DEFAULT 50,
    state TEXT NOT NULL CHECK (state IN ('pending','blocked','ready','proposed','awaiting_approval','applied','failed','cancelled')),
    coalesced_events INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
, claimed_by TEXT, lease_until TEXT, attempt_count INTEGER NOT NULL DEFAULT 0, last_error TEXT);

CREATE TABLE registry_bindings (
    binding_id TEXT PRIMARY KEY,
    binding_scope_type TEXT NOT NULL CHECK(binding_scope_type IN
        ('global','issue_subtree','issue')),
    binding_scope_id TEXT NOT NULL DEFAULT '',
    registration_id TEXT NOT NULL REFERENCES registry_entries(registration_id),
    is_default INTEGER NOT NULL DEFAULT 0 CHECK(is_default IN (0,1)),
    bound_at TEXT NOT NULL,
    bound_by TEXT NOT NULL REFERENCES actors(actor_id),
    reviewed_changeset_id TEXT REFERENCES changesets(changeset_id),
    UNIQUE(binding_scope_type,binding_scope_id,registration_id)
);

CREATE TABLE registry_dependencies (
    dependency_id TEXT PRIMARY KEY,
    bundle_id TEXT NOT NULL REFERENCES extension_bundles(bundle_id),
    dependency_namespace TEXT NOT NULL,
    dependency_name TEXT NOT NULL,
    declared_range TEXT NOT NULL,
    resolved_bundle_id TEXT NOT NULL REFERENCES extension_bundles(bundle_id),
    resolved_version TEXT NOT NULL,
    resolved_content_hash TEXT NOT NULL,
    UNIQUE(bundle_id,dependency_namespace,dependency_name)
);

CREATE TABLE registry_entries (
    registration_id TEXT PRIMARY KEY,
    bundle_id TEXT NOT NULL REFERENCES extension_bundles(bundle_id),
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN
        ('issue_type','issue_template','record_template','report_template',
         'routing_profile','mapping_profile','unit_catalog','import_adapter',
         'report_renderer','evidence_intake_template','question_template',
         'conclusion_summary_template')),
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    api_version TEXT NOT NULL,
    definition_json TEXT NOT NULL,
    content_hash TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK(state IN
        ('installed','active','deprecated','disabled','retired')),
    created_at TEXT NOT NULL,
    UNIQUE(namespace,kind,name,version)
);

CREATE TABLE registry_reference_locks (
    owner_registration_id TEXT NOT NULL REFERENCES registry_entries(registration_id),
    json_pointer TEXT NOT NULL,
    target_registration_id TEXT NOT NULL REFERENCES registry_entries(registration_id),
    target_kind TEXT NOT NULL,
    target_content_hash TEXT NOT NULL,
    resolution_source TEXT NOT NULL CHECK(resolution_source IN
        ('same_bundle','dependency_lock','explicit_full_ref')),
    created_at TEXT NOT NULL,
    PRIMARY KEY(owner_registration_id,json_pointer)
);

CREATE TABLE relation_events (
    relation_event_id TEXT PRIMARY KEY,
    relation_id TEXT NOT NULL REFERENCES relations(relation_id),
    event_type TEXT NOT NULL CHECK(event_type IN ('created','deactivated','reactivated','impact_changed')),
    before_json TEXT NOT NULL,
    after_json TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE relations (
    relation_id TEXT PRIMARY KEY,
    consumer_issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    provider_issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    relation_type TEXT NOT NULL CHECK (relation_type IN ('rolls_up_from','depends_on','related_to')),
    impact_policy TEXT NOT NULL CHECK (impact_policy IN ('hard','soft','notify','none')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    policy_version INTEGER NOT NULL, deactivated_at TEXT, deactivated_by TEXT, superseded_relation_id TEXT,
    CHECK (consumer_issue_id <> provider_issue_id)
);

CREATE TABLE report_build_inputs (
    report_build_id TEXT NOT NULL REFERENCES report_builds(report_build_id),
    input_order INTEGER NOT NULL,
    object_type TEXT NOT NULL CHECK(object_type IN
        ('record_revision','conclusion','proof','manifest')),
    object_id TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    PRIMARY KEY(report_build_id,input_order)
);

CREATE TABLE report_builds (
    report_build_id TEXT PRIMARY KEY,
    report_template_registration_id TEXT NOT NULL REFERENCES registry_entries(registration_id),
    report_template_content_hash TEXT NOT NULL,
    report_template_snapshot_json TEXT NOT NULL,
    renderer_name TEXT NOT NULL,
    renderer_version TEXT NOT NULL,
    renderer_hash TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    normalized_scope_json TEXT NOT NULL,
    normalized_scope_hash TEXT NOT NULL,
    query_json TEXT NOT NULL,
    report_model_json TEXT NOT NULL,
    report_model_hash TEXT NOT NULL,
    basis_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN
        ('prepared','built','published','stale','stale_requires_reprepare','blocked','failed')),
    output_format TEXT NOT NULL,
    output_artifact_id TEXT REFERENCES artifacts(artifact_id),
    output_hash TEXT,
    output_path TEXT,
    prepared_at TEXT NOT NULL,
    built_at TEXT,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    renderer_kind TEXT NOT NULL CHECK(renderer_kind IN ('builtin','adapter')),
    renderer_registration_id TEXT REFERENCES registry_entries(registration_id),
    renderer_registration_hash TEXT,
    renderer_snapshot_json TEXT NOT NULL,
    adapter_name TEXT,
    adapter_version TEXT,
    adapter_executable_hash TEXT,
    adapter_descriptor_hash TEXT,
    adapter_protocol_version TEXT,
    adapter_state_revision INTEGER,
    renderer_config_json TEXT NOT NULL DEFAULT '{}',
    renderer_config_hash TEXT NOT NULL,
    output_media_type TEXT NOT NULL,
    output_extension TEXT NOT NULL,
    render_receipt_json TEXT NOT NULL DEFAULT '{}'
, adapter_limits_json TEXT NOT NULL DEFAULT '{}', adapter_limits_hash TEXT NOT NULL DEFAULT '');

CREATE TABLE request_idempotency (
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    stored_response TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(operation, idempotency_key)
);

CREATE TABLE review_assignments (
    assignment_id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL REFERENCES proposals(proposal_id),
    reviewer_actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    reviewer_run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    state TEXT NOT NULL CHECK(state IN ('assigned','submitted','released','expired')),
    claimed_at TEXT NOT NULL,
    lease_until TEXT, heartbeat_at TEXT, attempt_count INTEGER NOT NULL DEFAULT 1, last_error TEXT, lease_generation INTEGER NOT NULL DEFAULT 1, released_at TEXT,
    UNIQUE(proposal_id, reviewer_run_id)
);

CREATE TABLE review_decisions (
    review_id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL REFERENCES proposals(proposal_id),
    reviewer_actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    reviewer_run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    decision TEXT NOT NULL CHECK(decision IN ('pass','reject')),
    rationale TEXT NOT NULL,
    evidence_sufficiency TEXT NOT NULL,
    proposal_hash TEXT NOT NULL,
    basis_snapshot_json TEXT NOT NULL,
    created_at TEXT NOT NULL, changeset_hash TEXT, policy_risk_snapshot TEXT NOT NULL DEFAULT '{}',
    UNIQUE(proposal_id, reviewer_run_id)
);

CREATE TABLE schema_identity (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    version INTEGER NOT NULL CHECK(version=10),
    created_at TEXT NOT NULL
);

CREATE TABLE service_tokens (
    token_id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    nonce TEXT NOT NULL UNIQUE,
    capabilities_json TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
, token_epoch INTEGER NOT NULL DEFAULT 1, platform_id TEXT REFERENCES platform_sources(platform_id));

CREATE TABLE triage_dispositions (
    packet_id TEXT PRIMARY KEY REFERENCES intake_packets(packet_id),
    disposition TEXT NOT NULL CHECK(disposition IN
        ('no_impact','supports_current','challenges_current','amends_previous',
         'proposal_created','duplicate','rejected','needs_input','evidence_requested')),
    issue_id TEXT REFERENCES issues(issue_id),
    conclusion_id TEXT REFERENCES conclusion_revisions(conclusion_id),
    proposal_id TEXT REFERENCES proposals(proposal_id),
    evidence_request_id TEXT REFERENCES evidence_requests(evidence_request_id),
    reason TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    created_at TEXT NOT NULL
);

CREATE TABLE triage_events (
    triage_event_id TEXT PRIMARY KEY,
    triage_task_id TEXT NOT NULL REFERENCES triage_tasks(triage_task_id),
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE triage_tasks (
    triage_task_id TEXT PRIMARY KEY,
    packet_id TEXT NOT NULL UNIQUE REFERENCES intake_packets(packet_id),
    state TEXT NOT NULL CHECK(state IN ('pending','claimed','proposed','awaiting_review','applied','needs_input','failed','retry','completed','rejected')),
    claimed_by TEXT REFERENCES actors(actor_id),
    claimed_run_id TEXT REFERENCES agent_runs(run_id),
    lease_until TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    question TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE working_entries (
    entry_id TEXT PRIMARY KEY,
    issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    entry_type TEXT NOT NULL CHECK (entry_type IN ('observation','run_link','analysis','note','question','decision_candidate','amendment')),
    body TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    policy_version INTEGER NOT NULL
, amends_entry_id TEXT REFERENCES working_entries(entry_id), source_packet_id TEXT);

CREATE INDEX idx_activity_issue_time ON activity_events(activity_sequence, created_at);

CREATE INDEX idx_activity_platform ON activity_events(platform_id, activity_sequence);

CREATE INDEX idx_api_requests_state ON api_requests(state, created_at);

CREATE INDEX idx_audit_checkpoints_count ON audit_checkpoints(event_count);

CREATE INDEX idx_audit_object ON audit_events(object_type, object_id, timestamp);

CREATE INDEX idx_basis_provider ON conclusion_basis(provider_issue_id, provider_revision);

CREATE UNIQUE INDEX idx_changeset_review_actor_once
ON changeset_review_decisions(changeset_id, reviewer_actor_id);

CREATE INDEX idx_changesets_state ON changesets(state, created_at);

CREATE UNIQUE INDEX idx_conclusion_proposal_unique
ON conclusion_revisions(proposal_id) WHERE proposal_id IS NOT NULL;

CREATE INDEX idx_context_events_revision ON context_input_events(revision);

CREATE INDEX idx_context_obligations_conclusion ON context_workflow_obligations(conclusion_id,state,blocks_publication);

CREATE INDEX idx_context_package_hash ON context_input_packages(semantic_hash);

CREATE INDEX idx_context_relations_source ON context_relations(source_key,active);

CREATE INDEX idx_context_relations_target ON context_relations(target_key,active);

CREATE INDEX idx_context_subscription_key
ON context_subscriptions(subscription_key,conclusion_id);

CREATE INDEX idx_context_triage_issue ON triage_dispositions(issue_id);

CREATE INDEX idx_currentness_edge_consumer
ON currentness_edge_contributions(consumer_conclusion_id,provider_conclusion_id);

CREATE INDEX idx_currentness_state ON conclusion_currentness(maintenance_state,needs_update);

CREATE INDEX idx_evidence_attestations_evidence
ON evidence_attestations(evidence_id, state, created_at);

CREATE INDEX idx_evidence_identity_ambiguities_state
ON evidence_identity_ambiguities(state,ambiguity_type,evidence_id);

CREATE INDEX idx_evidence_identity_locator
ON evidence_refs(kind,identity_locator,identity_namespace);

CREATE INDEX idx_evidence_identity_lookup ON evidence_refs(identity_namespace,identity_key,lifecycle_status);

CREATE INDEX idx_evidence_locator_distribution ON evidence_refs(kind,normalized_locator,identity_namespace);

CREATE INDEX idx_evidence_manifests_evidence
ON evidence_manifests(evidence_id, manifest_revision DESC);

CREATE INDEX idx_evidence_manifests_platform
ON evidence_manifests(platform_id, created_at);

CREATE INDEX idx_evidence_proofs_evidence
ON evidence_proofs(evidence_id,semantic_revision,created_at);

CREATE INDEX idx_evidence_publication_impacts_event
ON evidence_publication_impacts(semantic_event_id,issue_id,conclusion_id);

CREATE INDEX idx_evidence_relation_events_relation
ON evidence_relation_events(relation_id,created_at);

CREATE INDEX idx_evidence_relation_impacts_conclusion
ON evidence_relation_impacts(affected_conclusion_id,created_at);

CREATE INDEX idx_evidence_relation_impacts_issue
ON evidence_relation_impacts(affected_issue_id,created_at);

CREATE INDEX idx_evidence_relation_impacts_source
ON evidence_relation_impacts(source_event_type,source_event_id);

CREATE INDEX idx_evidence_relations_consumer
ON evidence_relations(consumer_evidence_id,active,impact_policy);

CREATE INDEX idx_evidence_relations_provider
ON evidence_relations(provider_evidence_id,active,impact_policy);

CREATE INDEX idx_evidence_request_events
ON evidence_request_events(evidence_request_id, created_at);

CREATE INDEX idx_evidence_requests_claim
ON evidence_requests(platform_id, state, priority DESC, created_at);

CREATE INDEX idx_evidence_requests_evidence
ON evidence_requests(evidence_id, state, created_at);

CREATE INDEX idx_evidence_search_locator
ON evidence_refs(kind,search_locator);

CREATE INDEX idx_evidence_semantic_events_evidence
ON evidence_semantic_events(evidence_id,to_semantic_revision,created_at);

CREATE INDEX idx_evidence_source_bindings_platform
ON evidence_source_bindings(source_platform_id,binding_state,evidence_id);

CREATE UNIQUE INDEX idx_evidence_source_key_active
ON evidence_source_bindings(source_key)
WHERE source_key IS NOT NULL AND binding_state IN ('bound','inferred');

CREATE INDEX idx_evidence_verification_events
ON evidence_verification_events(evidence_id, created_at);

CREATE INDEX idx_extension_bundles_state
ON extension_bundles(state,namespace,name,version);

CREATE INDEX idx_field_bundle_attachments_hash
ON field_bundle_attachments(expected_sha256,upload_state);

CREATE INDEX idx_governed_conflict_receipt_target
ON governed_conflict_resolution_receipts(target_object_type,target_object_id);

CREATE INDEX idx_import_items_job_state
ON import_items(import_job_id,validation_state,item_index);

CREATE INDEX idx_import_jobs_state ON import_jobs(state,created_at);

CREATE INDEX idx_import_manifest_candidates_job_state
ON import_manifest_candidates(import_job_id,state,created_at);

CREATE INDEX idx_intake_status ON intake_packets(status, created_at);

CREATE INDEX idx_integration_conflicts_job_state
ON integration_conflicts(source_kind,source_job_id,state);

CREATE UNIQUE INDEX idx_integrity_quarantine_active_object
ON integrity_quarantines(object_type,object_id) WHERE state='active';

CREATE INDEX idx_integrity_quarantines_finding
ON integrity_quarantines(finding_id,state,created_at);

CREATE INDEX idx_issue_question_events_question
ON issue_question_events(question_id,created_at);

CREATE INDEX idx_issue_question_evidence_evidence ON issue_question_evidence_links(evidence_id,active,question_id);

CREATE INDEX idx_issue_question_evidence_question ON issue_question_evidence_links(question_id,active);

CREATE UNIQUE INDEX idx_issue_question_key
ON issue_questions(issue_id,question_key) WHERE question_key IS NOT NULL;

CREATE INDEX idx_issue_questions_answer
ON issue_questions(answer_conclusion_id);

CREATE INDEX idx_issue_questions_issue_status_priority
ON issue_questions(issue_id,status,priority DESC,created_at);

CREATE INDEX idx_issue_questions_source
ON issue_questions(source_kind,source_id);

CREATE INDEX idx_issue_rollup_policy_mode ON issue_rollup_policies(mode);

CREATE INDEX idx_issue_tags_tag ON issue_tags(normalized_tag);

CREATE INDEX idx_issues_current_conclusion ON issues(current_conclusion_id);

CREATE INDEX idx_issues_freshness ON issues(freshness);

CREATE INDEX idx_issues_parent ON issues(parent_issue_id);

CREATE INDEX idx_issues_scope_topic ON issues(normalized_scope_key, topic);

CREATE INDEX idx_legacy_v14_candidates_issue_state
ON legacy_v14_candidates(issue_id,state,candidate_kind);

CREATE INDEX idx_migration_findings_version_state
ON migration_findings(migration_version,state,classification);

CREATE UNIQUE INDEX idx_migration_policy_repairs_applied
ON migration_policy_repairs(finding_id) WHERE state='applied';

CREATE INDEX idx_migration_policy_repairs_finding_state
ON migration_policy_repairs(finding_id,state,created_at);

CREATE INDEX idx_migration_resolution_attempt_finding
ON migration_finding_resolution_attempts(finding_id,created_at);

CREATE UNIQUE INDEX idx_migration_resolution_attempt_idempotency
ON migration_finding_resolution_attempts(
    finding_id,finding_subject_hash,resolution_hash,accepted
);

CREATE INDEX idx_migration_resolution_dependencies_identity
ON migration_resolution_dependencies(dependency_type,dependency_id,receipt_id);

CREATE INDEX idx_migration_resolution_replays_receipt
ON migration_resolution_replays(receipt_id,replayed_at);

CREATE UNIQUE INDEX idx_one_open_refresh_per_issue
ON refresh_tasks(issue_id)
WHERE state IN ('pending','blocked','ready','proposed','awaiting_approval');

CREATE INDEX idx_packet_links_source ON intake_packet_links(source_packet_id,active);

CREATE INDEX idx_packet_links_target ON intake_packet_links(target_packet_id,active);

CREATE INDEX idx_proposals_state ON proposals(state, created_at);

CREATE INDEX idx_record_instances_issue
ON record_instances(issue_id,lifecycle_status,record_template_registration_id);

CREATE INDEX idx_record_material_evidence ON record_material_relations(evidence_id,active);

CREATE INDEX idx_record_material_revision ON record_material_relations(record_revision_id,active);

CREATE INDEX idx_record_revisions_instance
ON record_revisions(record_instance_id,revision_number);

CREATE INDEX idx_record_value_number
ON record_value_index(field_path,unit_code,number_value);

CREATE INDEX idx_record_value_text
ON record_value_index(field_path,text_value);

CREATE INDEX idx_registry_bindings_scope
ON registry_bindings(binding_scope_type,binding_scope_id,is_default,registration_id);

CREATE INDEX idx_registry_entries_lookup
ON registry_entries(namespace,kind,name,state,version);

CREATE INDEX idx_registry_reference_locks_target
ON registry_reference_locks(target_registration_id,owner_registration_id);

CREATE INDEX idx_rel_consumer ON relations(consumer_issue_id, active, impact_policy);

CREATE INDEX idx_rel_provider ON relations(provider_issue_id, active, impact_policy);

CREATE INDEX idx_report_builds_template_state
ON report_builds(report_template_registration_id,state,prepared_at);

CREATE UNIQUE INDEX idx_review_actor_once
ON review_decisions(proposal_id, reviewer_actor_id);

CREATE INDEX idx_service_tokens_active ON service_tokens(actor_id, expires_at, revoked_at);

CREATE INDEX idx_working_issue ON working_entries(issue_id, created_at);

CREATE TRIGGER context_immutable_conclusion_revisions_delete
            BEFORE DELETE ON "conclusion_revisions"
            BEGIN SELECT RAISE(ABORT, 'Retain immutable context content history'); END;

CREATE TRIGGER context_immutable_conclusion_revisions_update
            BEFORE UPDATE ON "conclusion_revisions" WHEN OLD."conclusion_id" IS NOT NEW."conclusion_id" OR OLD."issue_id" IS NOT NEW."issue_id" OR OLD."revision_number" IS NOT NEW."revision_number" OR OLD."status" IS NOT NEW."status" OR OLD."statement" IS NOT NEW."statement" OR OLD."structured_outputs_json" IS NOT NEW."structured_outputs_json" OR OLD."confidence" IS NOT NEW."confidence" OR OLD."applicability" IS NOT NEW."applicability" OR OLD."limitations_json" IS NOT NEW."limitations_json" OR OLD."evidence_refs_json" IS NOT NEW."evidence_refs_json" OR OLD."change_summary" IS NOT NEW."change_summary" OR OLD."created_at" IS NOT NEW."created_at" OR OLD."created_by" IS NOT NEW."created_by" OR OLD."approved_by" IS NOT NEW."approved_by" OR OLD."previous_conclusion_id" IS NOT NEW."previous_conclusion_id" OR OLD."policy_version" IS NOT NEW."policy_version" OR OLD."transition_type" IS NOT NEW."transition_type" OR OLD."proposal_id" IS NOT NEW."proposal_id" OR OLD."issue_type_registration_id" IS NOT NEW."issue_type_registration_id" OR OLD."issue_type_semantic_hash" IS NOT NEW."issue_type_semantic_hash" OR OLD."issue_type_semantic_snapshot_json" IS NOT NEW."issue_type_semantic_snapshot_json"
            BEGIN SELECT RAISE(ABORT, 'Immutable context content version'); END;

CREATE TRIGGER context_immutable_evidence_manifests_delete
            BEFORE DELETE ON "evidence_manifests"
            BEGIN SELECT RAISE(ABORT, 'Retain immutable context content history'); END;

CREATE TRIGGER context_immutable_evidence_manifests_update
            BEFORE UPDATE ON "evidence_manifests" WHEN OLD."manifest_id" IS NOT NEW."manifest_id" OR OLD."evidence_id" IS NOT NEW."evidence_id" OR OLD."manifest_revision" IS NOT NEW."manifest_revision" OR OLD."manifest_json" IS NOT NEW."manifest_json" OR OLD."manifest_hash" IS NOT NEW."manifest_hash"
            BEGIN SELECT RAISE(ABORT, 'Immutable context content version'); END;

CREATE TRIGGER context_immutable_evidence_proofs_delete
            BEFORE DELETE ON "evidence_proofs"
            BEGIN SELECT RAISE(ABORT, 'Retain immutable context content history'); END;

CREATE TRIGGER context_immutable_evidence_proofs_update
            BEFORE UPDATE ON "evidence_proofs" WHEN OLD."proof_id" IS NOT NEW."proof_id" OR OLD."evidence_id" IS NOT NEW."evidence_id" OR OLD."semantic_revision" IS NOT NEW."semantic_revision" OR OLD."manifest_id" IS NOT NEW."manifest_id" OR OLD."manifest_hash" IS NOT NEW."manifest_hash" OR OLD."source_platform_id" IS NOT NEW."source_platform_id" OR OLD."verification_level" IS NOT NEW."verification_level" OR OLD."verification_state" IS NOT NEW."verification_state" OR OLD."source_attestation_ids_json" IS NOT NEW."source_attestation_ids_json" OR OLD."independent_attestation_ids_json" IS NOT NEW."independent_attestation_ids_json" OR OLD."artifact_snapshots_json" IS NOT NEW."artifact_snapshots_json" OR OLD."analysis_run_snapshots_json" IS NOT NEW."analysis_run_snapshots_json" OR OLD."reason_codes_json" IS NOT NEW."reason_codes_json" OR OLD."policy_version" IS NOT NEW."policy_version" OR OLD."proof_json" IS NOT NEW."proof_json" OR OLD."proof_hash" IS NOT NEW."proof_hash" OR OLD."supersedes_proof_id" IS NOT NEW."supersedes_proof_id" OR OLD."created_at" IS NOT NEW."created_at" OR OLD."created_by" IS NOT NEW."created_by"
            BEGIN SELECT RAISE(ABORT, 'Immutable context content version'); END;

CREATE TRIGGER context_immutable_intake_packets_delete
            BEFORE DELETE ON "intake_packets"
            BEGIN SELECT RAISE(ABORT, 'Retain immutable context content history'); END;

CREATE TRIGGER context_immutable_intake_packets_update
            BEFORE UPDATE ON "intake_packets" WHEN OLD."packet_id" IS NOT NEW."packet_id" OR OLD."packet_version" IS NOT NEW."packet_version" OR OLD."packet_json" IS NOT NEW."packet_json" OR OLD."packet_hash" IS NOT NEW."packet_hash"
            BEGIN SELECT RAISE(ABORT, 'Immutable context content version'); END;

CREATE TRIGGER context_immutable_record_revisions_delete
            BEFORE DELETE ON "record_revisions"
            BEGIN SELECT RAISE(ABORT, 'Retain immutable context content history'); END;

CREATE TRIGGER context_immutable_record_revisions_update
            BEFORE UPDATE ON "record_revisions" WHEN OLD."record_revision_id" IS NOT NEW."record_revision_id" OR OLD."record_instance_id" IS NOT NEW."record_instance_id" OR OLD."revision_number" IS NOT NEW."revision_number" OR OLD."template_content_hash" IS NOT NEW."template_content_hash" OR OLD."template_snapshot_json" IS NOT NEW."template_snapshot_json" OR OLD."data_json" IS NOT NEW."data_json" OR OLD."recorded_at" IS NOT NEW."recorded_at" OR OLD."recorded_by" IS NOT NEW."recorded_by" OR OLD."source_mode" IS NOT NEW."source_mode" OR OLD."source_object_mapping_id" IS NOT NEW."source_object_mapping_id" OR OLD."supersedes_revision_id" IS NOT NEW."supersedes_revision_id" OR OLD."validation_profile" IS NOT NEW."validation_profile" OR OLD."validation_result_json" IS NOT NEW."validation_result_json" OR OLD."content_hash" IS NOT NEW."content_hash"
            BEGIN SELECT RAISE(ABORT, 'Immutable context content version'); END;

CREATE TRIGGER context_immutable_triage_dispositions_delete
            BEFORE DELETE ON "triage_dispositions"
            BEGIN SELECT RAISE(ABORT, 'Retain immutable context content history'); END;

CREATE TRIGGER context_immutable_triage_dispositions_update
            BEFORE UPDATE ON "triage_dispositions" WHEN OLD."packet_id" IS NOT NEW."packet_id" OR OLD."disposition" IS NOT NEW."disposition" OR OLD."issue_id" IS NOT NEW."issue_id" OR OLD."conclusion_id" IS NOT NEW."conclusion_id" OR OLD."proposal_id" IS NOT NEW."proposal_id" OR OLD."evidence_request_id" IS NOT NEW."evidence_request_id" OR OLD."reason" IS NOT NEW."reason" OR OLD."created_by" IS NOT NEW."created_by" OR OLD."created_run_id" IS NOT NEW."created_run_id" OR OLD."created_at" IS NOT NEW."created_at"
            BEGIN SELECT RAISE(ABORT, 'Immutable context content version'); END;

CREATE TRIGGER context_immutable_working_entries_delete
            BEFORE DELETE ON "working_entries"
            BEGIN SELECT RAISE(ABORT, 'Retain immutable context content history'); END;

CREATE TRIGGER context_immutable_working_entries_update
            BEFORE UPDATE ON "working_entries" WHEN OLD."entry_id" IS NOT NEW."entry_id" OR OLD."issue_id" IS NOT NEW."issue_id" OR OLD."entry_type" IS NOT NEW."entry_type" OR OLD."body" IS NOT NEW."body" OR OLD."evidence_refs_json" IS NOT NEW."evidence_refs_json" OR OLD."created_at" IS NOT NEW."created_at" OR OLD."created_by" IS NOT NEW."created_by" OR OLD."policy_version" IS NOT NEW."policy_version" OR OLD."amends_entry_id" IS NOT NEW."amends_entry_id" OR OLD."source_packet_id" IS NOT NEW."source_packet_id"
            BEGIN SELECT RAISE(ABORT, 'Immutable context content version'); END;

CREATE TRIGGER context_input_basis_receipt_eligibility_delete
                AFTER DELETE ON "basis_receipt_eligibility" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'basis_receipt_eligibility',json_array(OLD."receipt_id"),json_object('receipt_id',OLD."receipt_id",'eligible',OLD."eligible",'reason',OLD."reason",'revision',OLD."revision"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_basis_receipt_eligibility_insert
                AFTER INSERT ON "basis_receipt_eligibility" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'basis_receipt_eligibility',json_array(NEW."receipt_id"),'{}',json_object('receipt_id',NEW."receipt_id",'eligible',NEW."eligible",'reason',NEW."reason",'revision',NEW."revision")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_basis_receipt_eligibility_update
                AFTER UPDATE ON "basis_receipt_eligibility" WHEN json_object('receipt_id',OLD."receipt_id",'eligible',OLD."eligible",'reason',OLD."reason",'revision',OLD."revision") IS NOT json_object('receipt_id',NEW."receipt_id",'eligible',NEW."eligible",'reason',NEW."reason",'revision',NEW."revision")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'basis_receipt_eligibility',json_array(NEW."receipt_id"),json_object('receipt_id',OLD."receipt_id",'eligible',OLD."eligible",'reason',OLD."reason",'revision',OLD."revision"),json_object('receipt_id',NEW."receipt_id",'eligible',NEW."eligible",'reason',NEW."reason",'revision',NEW."revision")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_basis_receipt_selections_delete
                AFTER DELETE ON "basis_receipt_selections" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'basis_receipt_selections',json_array(OLD."conclusion_id"),json_object('conclusion_id',OLD."conclusion_id",'receipt_id',OLD."receipt_id"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_basis_receipt_selections_insert
                AFTER INSERT ON "basis_receipt_selections" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'basis_receipt_selections',json_array(NEW."conclusion_id"),'{}',json_object('conclusion_id',NEW."conclusion_id",'receipt_id',NEW."receipt_id")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_basis_receipt_selections_update
                AFTER UPDATE ON "basis_receipt_selections" WHEN json_object('conclusion_id',OLD."conclusion_id",'receipt_id',OLD."receipt_id") IS NOT json_object('conclusion_id',NEW."conclusion_id",'receipt_id',NEW."receipt_id")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'basis_receipt_selections',json_array(NEW."conclusion_id"),json_object('conclusion_id',OLD."conclusion_id",'receipt_id',OLD."receipt_id"),json_object('conclusion_id',NEW."conclusion_id",'receipt_id',NEW."receipt_id")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_conclusion_context_selections_delete
                AFTER DELETE ON "conclusion_context_selections" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'conclusion_context_selections',json_array(OLD."conclusion_id"),json_object('conclusion_id',OLD."conclusion_id",'descriptor_id',OLD."descriptor_id"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_conclusion_context_selections_insert
                AFTER INSERT ON "conclusion_context_selections" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'conclusion_context_selections',json_array(NEW."conclusion_id"),'{}',json_object('conclusion_id',NEW."conclusion_id",'descriptor_id',NEW."descriptor_id")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_conclusion_context_selections_update
                AFTER UPDATE ON "conclusion_context_selections" WHEN json_object('conclusion_id',OLD."conclusion_id",'descriptor_id',OLD."descriptor_id") IS NOT json_object('conclusion_id',NEW."conclusion_id",'descriptor_id',NEW."descriptor_id")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'conclusion_context_selections',json_array(NEW."conclusion_id"),json_object('conclusion_id',OLD."conclusion_id",'descriptor_id',OLD."descriptor_id"),json_object('conclusion_id',NEW."conclusion_id",'descriptor_id',NEW."descriptor_id")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_conclusion_revisions_delete
                AFTER DELETE ON "conclusion_revisions" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'conclusion_revisions',json_array(OLD."conclusion_id"),json_object('conclusion_id',OLD."conclusion_id",'issue_id',OLD."issue_id",'revision_number',OLD."revision_number",'status',OLD."status",'statement',OLD."statement",'structured_outputs_json',OLD."structured_outputs_json",'confidence',OLD."confidence",'applicability',OLD."applicability",'limitations_json',OLD."limitations_json",'evidence_refs_json',OLD."evidence_refs_json",'change_summary',OLD."change_summary",'approved_by',OLD."approved_by",'previous_conclusion_id',OLD."previous_conclusion_id",'policy_version',OLD."policy_version",'transition_type',OLD."transition_type",'proposal_id',OLD."proposal_id",'issue_type_registration_id',OLD."issue_type_registration_id",'issue_type_semantic_hash',OLD."issue_type_semantic_hash",'issue_type_semantic_snapshot_json',OLD."issue_type_semantic_snapshot_json"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_conclusion_revisions_insert
                AFTER INSERT ON "conclusion_revisions" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'conclusion_revisions',json_array(NEW."conclusion_id"),'{}',json_object('conclusion_id',NEW."conclusion_id",'issue_id',NEW."issue_id",'revision_number',NEW."revision_number",'status',NEW."status",'statement',NEW."statement",'structured_outputs_json',NEW."structured_outputs_json",'confidence',NEW."confidence",'applicability',NEW."applicability",'limitations_json',NEW."limitations_json",'evidence_refs_json',NEW."evidence_refs_json",'change_summary',NEW."change_summary",'approved_by',NEW."approved_by",'previous_conclusion_id',NEW."previous_conclusion_id",'policy_version',NEW."policy_version",'transition_type',NEW."transition_type",'proposal_id',NEW."proposal_id",'issue_type_registration_id',NEW."issue_type_registration_id",'issue_type_semantic_hash',NEW."issue_type_semantic_hash",'issue_type_semantic_snapshot_json',NEW."issue_type_semantic_snapshot_json")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_conclusion_revisions_update
                AFTER UPDATE ON "conclusion_revisions" WHEN json_object('conclusion_id',OLD."conclusion_id",'issue_id',OLD."issue_id",'revision_number',OLD."revision_number",'status',OLD."status",'statement',OLD."statement",'structured_outputs_json',OLD."structured_outputs_json",'confidence',OLD."confidence",'applicability',OLD."applicability",'limitations_json',OLD."limitations_json",'evidence_refs_json',OLD."evidence_refs_json",'change_summary',OLD."change_summary",'approved_by',OLD."approved_by",'previous_conclusion_id',OLD."previous_conclusion_id",'policy_version',OLD."policy_version",'transition_type',OLD."transition_type",'proposal_id',OLD."proposal_id",'issue_type_registration_id',OLD."issue_type_registration_id",'issue_type_semantic_hash',OLD."issue_type_semantic_hash",'issue_type_semantic_snapshot_json',OLD."issue_type_semantic_snapshot_json") IS NOT json_object('conclusion_id',NEW."conclusion_id",'issue_id',NEW."issue_id",'revision_number',NEW."revision_number",'status',NEW."status",'statement',NEW."statement",'structured_outputs_json',NEW."structured_outputs_json",'confidence',NEW."confidence",'applicability',NEW."applicability",'limitations_json',NEW."limitations_json",'evidence_refs_json',NEW."evidence_refs_json",'change_summary',NEW."change_summary",'approved_by',NEW."approved_by",'previous_conclusion_id',NEW."previous_conclusion_id",'policy_version',NEW."policy_version",'transition_type',NEW."transition_type",'proposal_id',NEW."proposal_id",'issue_type_registration_id',NEW."issue_type_registration_id",'issue_type_semantic_hash',NEW."issue_type_semantic_hash",'issue_type_semantic_snapshot_json',NEW."issue_type_semantic_snapshot_json")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'conclusion_revisions',json_array(NEW."conclusion_id"),json_object('conclusion_id',OLD."conclusion_id",'issue_id',OLD."issue_id",'revision_number',OLD."revision_number",'status',OLD."status",'statement',OLD."statement",'structured_outputs_json',OLD."structured_outputs_json",'confidence',OLD."confidence",'applicability',OLD."applicability",'limitations_json',OLD."limitations_json",'evidence_refs_json',OLD."evidence_refs_json",'change_summary',OLD."change_summary",'approved_by',OLD."approved_by",'previous_conclusion_id',OLD."previous_conclusion_id",'policy_version',OLD."policy_version",'transition_type',OLD."transition_type",'proposal_id',OLD."proposal_id",'issue_type_registration_id',OLD."issue_type_registration_id",'issue_type_semantic_hash',OLD."issue_type_semantic_hash",'issue_type_semantic_snapshot_json',OLD."issue_type_semantic_snapshot_json"),json_object('conclusion_id',NEW."conclusion_id",'issue_id',NEW."issue_id",'revision_number',NEW."revision_number",'status',NEW."status",'statement',NEW."statement",'structured_outputs_json',NEW."structured_outputs_json",'confidence',NEW."confidence",'applicability',NEW."applicability",'limitations_json',NEW."limitations_json",'evidence_refs_json',NEW."evidence_refs_json",'change_summary',NEW."change_summary",'approved_by',NEW."approved_by",'previous_conclusion_id',NEW."previous_conclusion_id",'policy_version',NEW."policy_version",'transition_type',NEW."transition_type",'proposal_id',NEW."proposal_id",'issue_type_registration_id',NEW."issue_type_registration_id",'issue_type_semantic_hash',NEW."issue_type_semantic_hash",'issue_type_semantic_snapshot_json',NEW."issue_type_semantic_snapshot_json")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_context_relations_delete
                AFTER DELETE ON "context_relations" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'context_relations',json_array(OLD."relation_id"),json_object('relation_id',OLD."relation_id",'source_key',OLD."source_key",'target_key',OLD."target_key",'relation_type',OLD."relation_type",'require_currentness',OLD."require_currentness",'rationale',OLD."rationale",'active',OLD."active"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_context_relations_insert
                AFTER INSERT ON "context_relations" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'context_relations',json_array(NEW."relation_id"),'{}',json_object('relation_id',NEW."relation_id",'source_key',NEW."source_key",'target_key',NEW."target_key",'relation_type',NEW."relation_type",'require_currentness',NEW."require_currentness",'rationale',NEW."rationale",'active',NEW."active")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_context_relations_update
                AFTER UPDATE ON "context_relations" WHEN json_object('relation_id',OLD."relation_id",'source_key',OLD."source_key",'target_key',OLD."target_key",'relation_type',OLD."relation_type",'require_currentness',OLD."require_currentness",'rationale',OLD."rationale",'active',OLD."active") IS NOT json_object('relation_id',NEW."relation_id",'source_key',NEW."source_key",'target_key',NEW."target_key",'relation_type',NEW."relation_type",'require_currentness',NEW."require_currentness",'rationale',NEW."rationale",'active',NEW."active")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'context_relations',json_array(NEW."relation_id"),json_object('relation_id',OLD."relation_id",'source_key',OLD."source_key",'target_key',OLD."target_key",'relation_type',OLD."relation_type",'require_currentness',OLD."require_currentness",'rationale',OLD."rationale",'active',OLD."active"),json_object('relation_id',NEW."relation_id",'source_key',NEW."source_key",'target_key',NEW."target_key",'relation_type',NEW."relation_type",'require_currentness',NEW."require_currentness",'rationale',NEW."rationale",'active',NEW."active")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_context_rule_selections_delete
                AFTER DELETE ON "context_rule_selections" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'context_rule_selections',json_array(OLD."singleton"),json_object('singleton',OLD."singleton",'rule_id',OLD."rule_id"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_context_rule_selections_insert
                AFTER INSERT ON "context_rule_selections" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'context_rule_selections',json_array(NEW."singleton"),'{}',json_object('singleton',NEW."singleton",'rule_id',NEW."rule_id")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_context_rule_selections_update
                AFTER UPDATE ON "context_rule_selections" WHEN json_object('singleton',OLD."singleton",'rule_id',OLD."rule_id") IS NOT json_object('singleton',NEW."singleton",'rule_id',NEW."rule_id")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'context_rule_selections',json_array(NEW."singleton"),json_object('singleton',OLD."singleton",'rule_id',OLD."rule_id"),json_object('singleton',NEW."singleton",'rule_id',NEW."rule_id")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_evidence_manifests_delete
                AFTER DELETE ON "evidence_manifests" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'evidence_manifests',json_array(OLD."manifest_id"),json_object('manifest_id',OLD."manifest_id",'evidence_id',OLD."evidence_id",'manifest_revision',OLD."manifest_revision",'manifest_version',OLD."manifest_version",'platform_id',OLD."platform_id",'source_packet_id',OLD."source_packet_id",'source_actor_id',OLD."source_actor_id",'source_run_id',OLD."source_run_id",'observed_at',OLD."observed_at",'sample_session_ref',OLD."sample_session_ref",'content_identity_json',OLD."content_identity_json",'data_profile_json',OLD."data_profile_json",'execution_json',OLD."execution_json",'summary_json',OLD."summary_json",'manifest_json',OLD."manifest_json",'manifest_hash',OLD."manifest_hash",'supersedes_manifest_id',OLD."supersedes_manifest_id",'semantic_fingerprint',OLD."semantic_fingerprint",'change_class',OLD."change_class",'superseded_at',OLD."superseded_at"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_evidence_manifests_insert
                AFTER INSERT ON "evidence_manifests" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'evidence_manifests',json_array(NEW."manifest_id"),'{}',json_object('manifest_id',NEW."manifest_id",'evidence_id',NEW."evidence_id",'manifest_revision',NEW."manifest_revision",'manifest_version',NEW."manifest_version",'platform_id',NEW."platform_id",'source_packet_id',NEW."source_packet_id",'source_actor_id',NEW."source_actor_id",'source_run_id',NEW."source_run_id",'observed_at',NEW."observed_at",'sample_session_ref',NEW."sample_session_ref",'content_identity_json',NEW."content_identity_json",'data_profile_json',NEW."data_profile_json",'execution_json',NEW."execution_json",'summary_json',NEW."summary_json",'manifest_json',NEW."manifest_json",'manifest_hash',NEW."manifest_hash",'supersedes_manifest_id',NEW."supersedes_manifest_id",'semantic_fingerprint',NEW."semantic_fingerprint",'change_class',NEW."change_class",'superseded_at',NEW."superseded_at")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_evidence_manifests_update
                AFTER UPDATE ON "evidence_manifests" WHEN json_object('manifest_id',OLD."manifest_id",'evidence_id',OLD."evidence_id",'manifest_revision',OLD."manifest_revision",'manifest_version',OLD."manifest_version",'platform_id',OLD."platform_id",'source_packet_id',OLD."source_packet_id",'source_actor_id',OLD."source_actor_id",'source_run_id',OLD."source_run_id",'observed_at',OLD."observed_at",'sample_session_ref',OLD."sample_session_ref",'content_identity_json',OLD."content_identity_json",'data_profile_json',OLD."data_profile_json",'execution_json',OLD."execution_json",'summary_json',OLD."summary_json",'manifest_json',OLD."manifest_json",'manifest_hash',OLD."manifest_hash",'supersedes_manifest_id',OLD."supersedes_manifest_id",'semantic_fingerprint',OLD."semantic_fingerprint",'change_class',OLD."change_class",'superseded_at',OLD."superseded_at") IS NOT json_object('manifest_id',NEW."manifest_id",'evidence_id',NEW."evidence_id",'manifest_revision',NEW."manifest_revision",'manifest_version',NEW."manifest_version",'platform_id',NEW."platform_id",'source_packet_id',NEW."source_packet_id",'source_actor_id',NEW."source_actor_id",'source_run_id',NEW."source_run_id",'observed_at',NEW."observed_at",'sample_session_ref',NEW."sample_session_ref",'content_identity_json',NEW."content_identity_json",'data_profile_json',NEW."data_profile_json",'execution_json',NEW."execution_json",'summary_json',NEW."summary_json",'manifest_json',NEW."manifest_json",'manifest_hash',NEW."manifest_hash",'supersedes_manifest_id',NEW."supersedes_manifest_id",'semantic_fingerprint',NEW."semantic_fingerprint",'change_class',NEW."change_class",'superseded_at',NEW."superseded_at")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'evidence_manifests',json_array(NEW."manifest_id"),json_object('manifest_id',OLD."manifest_id",'evidence_id',OLD."evidence_id",'manifest_revision',OLD."manifest_revision",'manifest_version',OLD."manifest_version",'platform_id',OLD."platform_id",'source_packet_id',OLD."source_packet_id",'source_actor_id',OLD."source_actor_id",'source_run_id',OLD."source_run_id",'observed_at',OLD."observed_at",'sample_session_ref',OLD."sample_session_ref",'content_identity_json',OLD."content_identity_json",'data_profile_json',OLD."data_profile_json",'execution_json',OLD."execution_json",'summary_json',OLD."summary_json",'manifest_json',OLD."manifest_json",'manifest_hash',OLD."manifest_hash",'supersedes_manifest_id',OLD."supersedes_manifest_id",'semantic_fingerprint',OLD."semantic_fingerprint",'change_class',OLD."change_class",'superseded_at',OLD."superseded_at"),json_object('manifest_id',NEW."manifest_id",'evidence_id',NEW."evidence_id",'manifest_revision',NEW."manifest_revision",'manifest_version',NEW."manifest_version",'platform_id',NEW."platform_id",'source_packet_id',NEW."source_packet_id",'source_actor_id',NEW."source_actor_id",'source_run_id',NEW."source_run_id",'observed_at',NEW."observed_at",'sample_session_ref',NEW."sample_session_ref",'content_identity_json',NEW."content_identity_json",'data_profile_json',NEW."data_profile_json",'execution_json',NEW."execution_json",'summary_json',NEW."summary_json",'manifest_json',NEW."manifest_json",'manifest_hash',NEW."manifest_hash",'supersedes_manifest_id',NEW."supersedes_manifest_id",'semantic_fingerprint',NEW."semantic_fingerprint",'change_class',NEW."change_class",'superseded_at',NEW."superseded_at")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_evidence_proofs_delete
                AFTER DELETE ON "evidence_proofs" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'evidence_proofs',json_array(OLD."proof_id"),json_object('proof_id',OLD."proof_id",'evidence_id',OLD."evidence_id",'manifest_id',OLD."manifest_id",'manifest_hash',OLD."manifest_hash",'source_platform_id',OLD."source_platform_id",'verification_level',OLD."verification_level",'verification_state',OLD."verification_state",'source_attestation_ids_json',OLD."source_attestation_ids_json",'independent_attestation_ids_json',OLD."independent_attestation_ids_json",'artifact_snapshots_json',OLD."artifact_snapshots_json",'analysis_run_snapshots_json',OLD."analysis_run_snapshots_json",'reason_codes_json',OLD."reason_codes_json",'policy_version',OLD."policy_version",'proof_json',OLD."proof_json",'proof_hash',OLD."proof_hash",'supersedes_proof_id',OLD."supersedes_proof_id"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_evidence_proofs_insert
                AFTER INSERT ON "evidence_proofs" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'evidence_proofs',json_array(NEW."proof_id"),'{}',json_object('proof_id',NEW."proof_id",'evidence_id',NEW."evidence_id",'manifest_id',NEW."manifest_id",'manifest_hash',NEW."manifest_hash",'source_platform_id',NEW."source_platform_id",'verification_level',NEW."verification_level",'verification_state',NEW."verification_state",'source_attestation_ids_json',NEW."source_attestation_ids_json",'independent_attestation_ids_json',NEW."independent_attestation_ids_json",'artifact_snapshots_json',NEW."artifact_snapshots_json",'analysis_run_snapshots_json',NEW."analysis_run_snapshots_json",'reason_codes_json',NEW."reason_codes_json",'policy_version',NEW."policy_version",'proof_json',NEW."proof_json",'proof_hash',NEW."proof_hash",'supersedes_proof_id',NEW."supersedes_proof_id")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_evidence_proofs_update
                AFTER UPDATE ON "evidence_proofs" WHEN json_object('proof_id',OLD."proof_id",'evidence_id',OLD."evidence_id",'manifest_id',OLD."manifest_id",'manifest_hash',OLD."manifest_hash",'source_platform_id',OLD."source_platform_id",'verification_level',OLD."verification_level",'verification_state',OLD."verification_state",'source_attestation_ids_json',OLD."source_attestation_ids_json",'independent_attestation_ids_json',OLD."independent_attestation_ids_json",'artifact_snapshots_json',OLD."artifact_snapshots_json",'analysis_run_snapshots_json',OLD."analysis_run_snapshots_json",'reason_codes_json',OLD."reason_codes_json",'policy_version',OLD."policy_version",'proof_json',OLD."proof_json",'proof_hash',OLD."proof_hash",'supersedes_proof_id',OLD."supersedes_proof_id") IS NOT json_object('proof_id',NEW."proof_id",'evidence_id',NEW."evidence_id",'manifest_id',NEW."manifest_id",'manifest_hash',NEW."manifest_hash",'source_platform_id',NEW."source_platform_id",'verification_level',NEW."verification_level",'verification_state',NEW."verification_state",'source_attestation_ids_json',NEW."source_attestation_ids_json",'independent_attestation_ids_json',NEW."independent_attestation_ids_json",'artifact_snapshots_json',NEW."artifact_snapshots_json",'analysis_run_snapshots_json',NEW."analysis_run_snapshots_json",'reason_codes_json',NEW."reason_codes_json",'policy_version',NEW."policy_version",'proof_json',NEW."proof_json",'proof_hash',NEW."proof_hash",'supersedes_proof_id',NEW."supersedes_proof_id")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'evidence_proofs',json_array(NEW."proof_id"),json_object('proof_id',OLD."proof_id",'evidence_id',OLD."evidence_id",'manifest_id',OLD."manifest_id",'manifest_hash',OLD."manifest_hash",'source_platform_id',OLD."source_platform_id",'verification_level',OLD."verification_level",'verification_state',OLD."verification_state",'source_attestation_ids_json',OLD."source_attestation_ids_json",'independent_attestation_ids_json',OLD."independent_attestation_ids_json",'artifact_snapshots_json',OLD."artifact_snapshots_json",'analysis_run_snapshots_json',OLD."analysis_run_snapshots_json",'reason_codes_json',OLD."reason_codes_json",'policy_version',OLD."policy_version",'proof_json',OLD."proof_json",'proof_hash',OLD."proof_hash",'supersedes_proof_id',OLD."supersedes_proof_id"),json_object('proof_id',NEW."proof_id",'evidence_id',NEW."evidence_id",'manifest_id',NEW."manifest_id",'manifest_hash',NEW."manifest_hash",'source_platform_id',NEW."source_platform_id",'verification_level',NEW."verification_level",'verification_state',NEW."verification_state",'source_attestation_ids_json',NEW."source_attestation_ids_json",'independent_attestation_ids_json',NEW."independent_attestation_ids_json",'artifact_snapshots_json',NEW."artifact_snapshots_json",'analysis_run_snapshots_json',NEW."analysis_run_snapshots_json",'reason_codes_json',NEW."reason_codes_json",'policy_version',NEW."policy_version",'proof_json',NEW."proof_json",'proof_hash',NEW."proof_hash",'supersedes_proof_id',NEW."supersedes_proof_id")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_evidence_refs_delete
                AFTER DELETE ON "evidence_refs" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'evidence_refs',json_array(OLD."evidence_id"),json_object('evidence_id',OLD."evidence_id",'kind',OLD."kind",'locator',OLD."locator",'normalized_locator',OLD."normalized_locator",'identity_key',OLD."identity_key",'identity_namespace',OLD."identity_namespace",'target_scope',OLD."target_scope",'short_description',OLD."short_description",'quality_status',OLD."quality_status",'content_hash',OLD."content_hash",'declared_source_locator',OLD."declared_source_locator",'lifecycle_status',OLD."lifecycle_status",'verification_level',OLD."verification_level",'verification_state',OLD."verification_state",'mutable_source',OLD."mutable_source",'current_manifest_id',OLD."current_manifest_id",'current_proof_id',OLD."current_proof_id",'identity_locator',OLD."identity_locator",'search_locator',OLD."search_locator",'locator_identity_version',OLD."locator_identity_version"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_evidence_refs_insert
                AFTER INSERT ON "evidence_refs" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'evidence_refs',json_array(NEW."evidence_id"),'{}',json_object('evidence_id',NEW."evidence_id",'kind',NEW."kind",'locator',NEW."locator",'normalized_locator',NEW."normalized_locator",'identity_key',NEW."identity_key",'identity_namespace',NEW."identity_namespace",'target_scope',NEW."target_scope",'short_description',NEW."short_description",'quality_status',NEW."quality_status",'content_hash',NEW."content_hash",'declared_source_locator',NEW."declared_source_locator",'lifecycle_status',NEW."lifecycle_status",'verification_level',NEW."verification_level",'verification_state',NEW."verification_state",'mutable_source',NEW."mutable_source",'current_manifest_id',NEW."current_manifest_id",'current_proof_id',NEW."current_proof_id",'identity_locator',NEW."identity_locator",'search_locator',NEW."search_locator",'locator_identity_version',NEW."locator_identity_version")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_evidence_refs_update
                AFTER UPDATE ON "evidence_refs" WHEN json_object('evidence_id',OLD."evidence_id",'kind',OLD."kind",'locator',OLD."locator",'normalized_locator',OLD."normalized_locator",'identity_key',OLD."identity_key",'identity_namespace',OLD."identity_namespace",'target_scope',OLD."target_scope",'short_description',OLD."short_description",'quality_status',OLD."quality_status",'content_hash',OLD."content_hash",'declared_source_locator',OLD."declared_source_locator",'lifecycle_status',OLD."lifecycle_status",'verification_level',OLD."verification_level",'verification_state',OLD."verification_state",'mutable_source',OLD."mutable_source",'current_manifest_id',OLD."current_manifest_id",'current_proof_id',OLD."current_proof_id",'identity_locator',OLD."identity_locator",'search_locator',OLD."search_locator",'locator_identity_version',OLD."locator_identity_version") IS NOT json_object('evidence_id',NEW."evidence_id",'kind',NEW."kind",'locator',NEW."locator",'normalized_locator',NEW."normalized_locator",'identity_key',NEW."identity_key",'identity_namespace',NEW."identity_namespace",'target_scope',NEW."target_scope",'short_description',NEW."short_description",'quality_status',NEW."quality_status",'content_hash',NEW."content_hash",'declared_source_locator',NEW."declared_source_locator",'lifecycle_status',NEW."lifecycle_status",'verification_level',NEW."verification_level",'verification_state',NEW."verification_state",'mutable_source',NEW."mutable_source",'current_manifest_id',NEW."current_manifest_id",'current_proof_id',NEW."current_proof_id",'identity_locator',NEW."identity_locator",'search_locator',NEW."search_locator",'locator_identity_version',NEW."locator_identity_version")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'evidence_refs',json_array(NEW."evidence_id"),json_object('evidence_id',OLD."evidence_id",'kind',OLD."kind",'locator',OLD."locator",'normalized_locator',OLD."normalized_locator",'identity_key',OLD."identity_key",'identity_namespace',OLD."identity_namespace",'target_scope',OLD."target_scope",'short_description',OLD."short_description",'quality_status',OLD."quality_status",'content_hash',OLD."content_hash",'declared_source_locator',OLD."declared_source_locator",'lifecycle_status',OLD."lifecycle_status",'verification_level',OLD."verification_level",'verification_state',OLD."verification_state",'mutable_source',OLD."mutable_source",'current_manifest_id',OLD."current_manifest_id",'current_proof_id',OLD."current_proof_id",'identity_locator',OLD."identity_locator",'search_locator',OLD."search_locator",'locator_identity_version',OLD."locator_identity_version"),json_object('evidence_id',NEW."evidence_id",'kind',NEW."kind",'locator',NEW."locator",'normalized_locator',NEW."normalized_locator",'identity_key',NEW."identity_key",'identity_namespace',NEW."identity_namespace",'target_scope',NEW."target_scope",'short_description',NEW."short_description",'quality_status',NEW."quality_status",'content_hash',NEW."content_hash",'declared_source_locator',NEW."declared_source_locator",'lifecycle_status',NEW."lifecycle_status",'verification_level',NEW."verification_level",'verification_state',NEW."verification_state",'mutable_source',NEW."mutable_source",'current_manifest_id',NEW."current_manifest_id",'current_proof_id',NEW."current_proof_id",'identity_locator',NEW."identity_locator",'search_locator',NEW."search_locator",'locator_identity_version',NEW."locator_identity_version")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_evidence_relations_delete
                AFTER DELETE ON "evidence_relations" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'evidence_relations',json_array(OLD."relation_id"),json_object('relation_id',OLD."relation_id",'consumer_evidence_id',OLD."consumer_evidence_id",'provider_evidence_id',OLD."provider_evidence_id",'relation_type',OLD."relation_type",'impact_policy',OLD."impact_policy",'rationale',OLD."rationale",'active',OLD."active",'provider_snapshot_hash',OLD."provider_snapshot_hash",'consumer_snapshot_hash',OLD."consumer_snapshot_hash",'template_registration_id',OLD."template_registration_id",'template_content_hash',OLD."template_content_hash"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_evidence_relations_insert
                AFTER INSERT ON "evidence_relations" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'evidence_relations',json_array(NEW."relation_id"),'{}',json_object('relation_id',NEW."relation_id",'consumer_evidence_id',NEW."consumer_evidence_id",'provider_evidence_id',NEW."provider_evidence_id",'relation_type',NEW."relation_type",'impact_policy',NEW."impact_policy",'rationale',NEW."rationale",'active',NEW."active",'provider_snapshot_hash',NEW."provider_snapshot_hash",'consumer_snapshot_hash',NEW."consumer_snapshot_hash",'template_registration_id',NEW."template_registration_id",'template_content_hash',NEW."template_content_hash")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_evidence_relations_update
                AFTER UPDATE ON "evidence_relations" WHEN json_object('relation_id',OLD."relation_id",'consumer_evidence_id',OLD."consumer_evidence_id",'provider_evidence_id',OLD."provider_evidence_id",'relation_type',OLD."relation_type",'impact_policy',OLD."impact_policy",'rationale',OLD."rationale",'active',OLD."active",'provider_snapshot_hash',OLD."provider_snapshot_hash",'consumer_snapshot_hash',OLD."consumer_snapshot_hash",'template_registration_id',OLD."template_registration_id",'template_content_hash',OLD."template_content_hash") IS NOT json_object('relation_id',NEW."relation_id",'consumer_evidence_id',NEW."consumer_evidence_id",'provider_evidence_id',NEW."provider_evidence_id",'relation_type',NEW."relation_type",'impact_policy',NEW."impact_policy",'rationale',NEW."rationale",'active',NEW."active",'provider_snapshot_hash',NEW."provider_snapshot_hash",'consumer_snapshot_hash',NEW."consumer_snapshot_hash",'template_registration_id',NEW."template_registration_id",'template_content_hash',NEW."template_content_hash")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'evidence_relations',json_array(NEW."relation_id"),json_object('relation_id',OLD."relation_id",'consumer_evidence_id',OLD."consumer_evidence_id",'provider_evidence_id',OLD."provider_evidence_id",'relation_type',OLD."relation_type",'impact_policy',OLD."impact_policy",'rationale',OLD."rationale",'active',OLD."active",'provider_snapshot_hash',OLD."provider_snapshot_hash",'consumer_snapshot_hash',OLD."consumer_snapshot_hash",'template_registration_id',OLD."template_registration_id",'template_content_hash',OLD."template_content_hash"),json_object('relation_id',NEW."relation_id",'consumer_evidence_id',NEW."consumer_evidence_id",'provider_evidence_id',NEW."provider_evidence_id",'relation_type',NEW."relation_type",'impact_policy',NEW."impact_policy",'rationale',NEW."rationale",'active',NEW."active",'provider_snapshot_hash',NEW."provider_snapshot_hash",'consumer_snapshot_hash',NEW."consumer_snapshot_hash",'template_registration_id',NEW."template_registration_id",'template_content_hash',NEW."template_content_hash")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_intake_packet_links_delete
                AFTER DELETE ON "intake_packet_links" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'intake_packet_links',json_array(OLD."link_id"),json_object('link_id',OLD."link_id",'source_packet_id',OLD."source_packet_id",'target_packet_id',OLD."target_packet_id",'link_type',OLD."link_type",'proposed_by',OLD."proposed_by",'rationale',OLD."rationale",'active',OLD."active"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_intake_packet_links_insert
                AFTER INSERT ON "intake_packet_links" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'intake_packet_links',json_array(NEW."link_id"),'{}',json_object('link_id',NEW."link_id",'source_packet_id',NEW."source_packet_id",'target_packet_id',NEW."target_packet_id",'link_type',NEW."link_type",'proposed_by',NEW."proposed_by",'rationale',NEW."rationale",'active',NEW."active")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_intake_packet_links_update
                AFTER UPDATE ON "intake_packet_links" WHEN json_object('link_id',OLD."link_id",'source_packet_id',OLD."source_packet_id",'target_packet_id',OLD."target_packet_id",'link_type',OLD."link_type",'proposed_by',OLD."proposed_by",'rationale',OLD."rationale",'active',OLD."active") IS NOT json_object('link_id',NEW."link_id",'source_packet_id',NEW."source_packet_id",'target_packet_id',NEW."target_packet_id",'link_type',NEW."link_type",'proposed_by',NEW."proposed_by",'rationale',NEW."rationale",'active',NEW."active")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'intake_packet_links',json_array(NEW."link_id"),json_object('link_id',OLD."link_id",'source_packet_id',OLD."source_packet_id",'target_packet_id',OLD."target_packet_id",'link_type',OLD."link_type",'proposed_by',OLD."proposed_by",'rationale',OLD."rationale",'active',OLD."active"),json_object('link_id',NEW."link_id",'source_packet_id',NEW."source_packet_id",'target_packet_id',NEW."target_packet_id",'link_type',NEW."link_type",'proposed_by',NEW."proposed_by",'rationale',NEW."rationale",'active',NEW."active")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_intake_packets_delete
                AFTER DELETE ON "intake_packets" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'intake_packets',json_array(OLD."packet_id"),json_object('packet_id',OLD."packet_id",'packet_version',OLD."packet_version",'packet_json',OLD."packet_json",'packet_hash',OLD."packet_hash",'status',OLD."status",'submitted_by',OLD."submitted_by",'submitted_run_id',OLD."submitted_run_id",'attached_issue_id',OLD."attached_issue_id",'merged_into_packet_id',OLD."merged_into_packet_id",'routing_state',OLD."routing_state",'last_triage_error',OLD."last_triage_error",'routing_snapshot_json',OLD."routing_snapshot_json",'routing_policy_version',OLD."routing_policy_version"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_intake_packets_insert
                AFTER INSERT ON "intake_packets" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'intake_packets',json_array(NEW."packet_id"),'{}',json_object('packet_id',NEW."packet_id",'packet_version',NEW."packet_version",'packet_json',NEW."packet_json",'packet_hash',NEW."packet_hash",'status',NEW."status",'submitted_by',NEW."submitted_by",'submitted_run_id',NEW."submitted_run_id",'attached_issue_id',NEW."attached_issue_id",'merged_into_packet_id',NEW."merged_into_packet_id",'routing_state',NEW."routing_state",'last_triage_error',NEW."last_triage_error",'routing_snapshot_json',NEW."routing_snapshot_json",'routing_policy_version',NEW."routing_policy_version")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_intake_packets_update
                AFTER UPDATE ON "intake_packets" WHEN json_object('packet_id',OLD."packet_id",'packet_version',OLD."packet_version",'packet_json',OLD."packet_json",'packet_hash',OLD."packet_hash",'status',OLD."status",'submitted_by',OLD."submitted_by",'submitted_run_id',OLD."submitted_run_id",'attached_issue_id',OLD."attached_issue_id",'merged_into_packet_id',OLD."merged_into_packet_id",'routing_state',OLD."routing_state",'last_triage_error',OLD."last_triage_error",'routing_snapshot_json',OLD."routing_snapshot_json",'routing_policy_version',OLD."routing_policy_version") IS NOT json_object('packet_id',NEW."packet_id",'packet_version',NEW."packet_version",'packet_json',NEW."packet_json",'packet_hash',NEW."packet_hash",'status',NEW."status",'submitted_by',NEW."submitted_by",'submitted_run_id',NEW."submitted_run_id",'attached_issue_id',NEW."attached_issue_id",'merged_into_packet_id',NEW."merged_into_packet_id",'routing_state',NEW."routing_state",'last_triage_error',NEW."last_triage_error",'routing_snapshot_json',NEW."routing_snapshot_json",'routing_policy_version',NEW."routing_policy_version")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'intake_packets',json_array(NEW."packet_id"),json_object('packet_id',OLD."packet_id",'packet_version',OLD."packet_version",'packet_json',OLD."packet_json",'packet_hash',OLD."packet_hash",'status',OLD."status",'submitted_by',OLD."submitted_by",'submitted_run_id',OLD."submitted_run_id",'attached_issue_id',OLD."attached_issue_id",'merged_into_packet_id',OLD."merged_into_packet_id",'routing_state',OLD."routing_state",'last_triage_error',OLD."last_triage_error",'routing_snapshot_json',OLD."routing_snapshot_json",'routing_policy_version',OLD."routing_policy_version"),json_object('packet_id',NEW."packet_id",'packet_version',NEW."packet_version",'packet_json',NEW."packet_json",'packet_hash',NEW."packet_hash",'status',NEW."status",'submitted_by',NEW."submitted_by",'submitted_run_id',NEW."submitted_run_id",'attached_issue_id',NEW."attached_issue_id",'merged_into_packet_id',NEW."merged_into_packet_id",'routing_state',NEW."routing_state",'last_triage_error',NEW."last_triage_error",'routing_snapshot_json',NEW."routing_snapshot_json",'routing_policy_version',NEW."routing_policy_version")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_issue_evidence_delete
                AFTER DELETE ON "issue_evidence" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'issue_evidence',json_array(OLD."issue_id",OLD."evidence_id"),json_object('issue_id',OLD."issue_id",'evidence_id',OLD."evidence_id"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_issue_evidence_insert
                AFTER INSERT ON "issue_evidence" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'issue_evidence',json_array(NEW."issue_id",NEW."evidence_id"),'{}',json_object('issue_id',NEW."issue_id",'evidence_id',NEW."evidence_id")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_issue_evidence_update
                AFTER UPDATE ON "issue_evidence" WHEN json_object('issue_id',OLD."issue_id",'evidence_id',OLD."evidence_id") IS NOT json_object('issue_id',NEW."issue_id",'evidence_id',NEW."evidence_id")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'issue_evidence',json_array(NEW."issue_id",NEW."evidence_id"),json_object('issue_id',OLD."issue_id",'evidence_id',OLD."evidence_id"),json_object('issue_id',NEW."issue_id",'evidence_id',NEW."evidence_id")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_issue_question_evidence_links_delete
                AFTER DELETE ON "issue_question_evidence_links" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'issue_question_evidence_links',json_array(OLD."relation_id"),json_object('relation_id',OLD."relation_id",'question_id',OLD."question_id",'evidence_id',OLD."evidence_id",'link_type',OLD."link_type",'rationale',OLD."rationale",'active',OLD."active"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_issue_question_evidence_links_insert
                AFTER INSERT ON "issue_question_evidence_links" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'issue_question_evidence_links',json_array(NEW."relation_id"),'{}',json_object('relation_id',NEW."relation_id",'question_id',NEW."question_id",'evidence_id',NEW."evidence_id",'link_type',NEW."link_type",'rationale',NEW."rationale",'active',NEW."active")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_issue_question_evidence_links_update
                AFTER UPDATE ON "issue_question_evidence_links" WHEN json_object('relation_id',OLD."relation_id",'question_id',OLD."question_id",'evidence_id',OLD."evidence_id",'link_type',OLD."link_type",'rationale',OLD."rationale",'active',OLD."active") IS NOT json_object('relation_id',NEW."relation_id",'question_id',NEW."question_id",'evidence_id',NEW."evidence_id",'link_type',NEW."link_type",'rationale',NEW."rationale",'active',NEW."active")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'issue_question_evidence_links',json_array(NEW."relation_id"),json_object('relation_id',OLD."relation_id",'question_id',OLD."question_id",'evidence_id',OLD."evidence_id",'link_type',OLD."link_type",'rationale',OLD."rationale",'active',OLD."active"),json_object('relation_id',NEW."relation_id",'question_id',NEW."question_id",'evidence_id',NEW."evidence_id",'link_type',NEW."link_type",'rationale',NEW."rationale",'active',NEW."active")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_issue_questions_delete
                AFTER DELETE ON "issue_questions" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'issue_questions',json_array(OLD."question_id"),json_object('question_id',OLD."question_id",'issue_id',OLD."issue_id",'question_key',OLD."question_key",'prompt',OLD."prompt",'motivation',OLD."motivation",'question_kind',OLD."question_kind",'status',OLD."status",'priority',OLD."priority",'expected_evidence_json',OLD."expected_evidence_json",'source_kind',OLD."source_kind",'source_id',OLD."source_id",'answer_conclusion_id',OLD."answer_conclusion_id",'template_registration_id',OLD."template_registration_id",'template_content_hash',OLD."template_content_hash",'template_snapshot_json',OLD."template_snapshot_json",'status_reason',OLD."status_reason"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_issue_questions_insert
                AFTER INSERT ON "issue_questions" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'issue_questions',json_array(NEW."question_id"),'{}',json_object('question_id',NEW."question_id",'issue_id',NEW."issue_id",'question_key',NEW."question_key",'prompt',NEW."prompt",'motivation',NEW."motivation",'question_kind',NEW."question_kind",'status',NEW."status",'priority',NEW."priority",'expected_evidence_json',NEW."expected_evidence_json",'source_kind',NEW."source_kind",'source_id',NEW."source_id",'answer_conclusion_id',NEW."answer_conclusion_id",'template_registration_id',NEW."template_registration_id",'template_content_hash',NEW."template_content_hash",'template_snapshot_json',NEW."template_snapshot_json",'status_reason',NEW."status_reason")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_issue_questions_update
                AFTER UPDATE ON "issue_questions" WHEN json_object('question_id',OLD."question_id",'issue_id',OLD."issue_id",'question_key',OLD."question_key",'prompt',OLD."prompt",'motivation',OLD."motivation",'question_kind',OLD."question_kind",'status',OLD."status",'priority',OLD."priority",'expected_evidence_json',OLD."expected_evidence_json",'source_kind',OLD."source_kind",'source_id',OLD."source_id",'answer_conclusion_id',OLD."answer_conclusion_id",'template_registration_id',OLD."template_registration_id",'template_content_hash',OLD."template_content_hash",'template_snapshot_json',OLD."template_snapshot_json",'status_reason',OLD."status_reason") IS NOT json_object('question_id',NEW."question_id",'issue_id',NEW."issue_id",'question_key',NEW."question_key",'prompt',NEW."prompt",'motivation',NEW."motivation",'question_kind',NEW."question_kind",'status',NEW."status",'priority',NEW."priority",'expected_evidence_json',NEW."expected_evidence_json",'source_kind',NEW."source_kind",'source_id',NEW."source_id",'answer_conclusion_id',NEW."answer_conclusion_id",'template_registration_id',NEW."template_registration_id",'template_content_hash',NEW."template_content_hash",'template_snapshot_json',NEW."template_snapshot_json",'status_reason',NEW."status_reason")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'issue_questions',json_array(NEW."question_id"),json_object('question_id',OLD."question_id",'issue_id',OLD."issue_id",'question_key',OLD."question_key",'prompt',OLD."prompt",'motivation',OLD."motivation",'question_kind',OLD."question_kind",'status',OLD."status",'priority',OLD."priority",'expected_evidence_json',OLD."expected_evidence_json",'source_kind',OLD."source_kind",'source_id',OLD."source_id",'answer_conclusion_id',OLD."answer_conclusion_id",'template_registration_id',OLD."template_registration_id",'template_content_hash',OLD."template_content_hash",'template_snapshot_json',OLD."template_snapshot_json",'status_reason',OLD."status_reason"),json_object('question_id',NEW."question_id",'issue_id',NEW."issue_id",'question_key',NEW."question_key",'prompt',NEW."prompt",'motivation',NEW."motivation",'question_kind',NEW."question_kind",'status',NEW."status",'priority',NEW."priority",'expected_evidence_json',NEW."expected_evidence_json",'source_kind',NEW."source_kind",'source_id',NEW."source_id",'answer_conclusion_id',NEW."answer_conclusion_id",'template_registration_id',NEW."template_registration_id",'template_content_hash',NEW."template_content_hash",'template_snapshot_json',NEW."template_snapshot_json",'status_reason',NEW."status_reason")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_issue_rollup_policies_delete
                AFTER DELETE ON "issue_rollup_policies" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'issue_rollup_policies',json_array(OLD."issue_id"),json_object('issue_id',OLD."issue_id",'policy_version',OLD."policy_version",'mode',OLD."mode",'policy_json',OLD."policy_json",'policy_hash',OLD."policy_hash",'source_registration_id',OLD."source_registration_id",'source_content_hash',OLD."source_content_hash"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_issue_rollup_policies_insert
                AFTER INSERT ON "issue_rollup_policies" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'issue_rollup_policies',json_array(NEW."issue_id"),'{}',json_object('issue_id',NEW."issue_id",'policy_version',NEW."policy_version",'mode',NEW."mode",'policy_json',NEW."policy_json",'policy_hash',NEW."policy_hash",'source_registration_id',NEW."source_registration_id",'source_content_hash',NEW."source_content_hash")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_issue_rollup_policies_update
                AFTER UPDATE ON "issue_rollup_policies" WHEN json_object('issue_id',OLD."issue_id",'policy_version',OLD."policy_version",'mode',OLD."mode",'policy_json',OLD."policy_json",'policy_hash',OLD."policy_hash",'source_registration_id',OLD."source_registration_id",'source_content_hash',OLD."source_content_hash") IS NOT json_object('issue_id',NEW."issue_id",'policy_version',NEW."policy_version",'mode',NEW."mode",'policy_json',NEW."policy_json",'policy_hash',NEW."policy_hash",'source_registration_id',NEW."source_registration_id",'source_content_hash',NEW."source_content_hash")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'issue_rollup_policies',json_array(NEW."issue_id"),json_object('issue_id',OLD."issue_id",'policy_version',OLD."policy_version",'mode',OLD."mode",'policy_json',OLD."policy_json",'policy_hash',OLD."policy_hash",'source_registration_id',OLD."source_registration_id",'source_content_hash',OLD."source_content_hash"),json_object('issue_id',NEW."issue_id",'policy_version',NEW."policy_version",'mode',NEW."mode",'policy_json',NEW."policy_json",'policy_hash',NEW."policy_hash",'source_registration_id',NEW."source_registration_id",'source_content_hash',NEW."source_content_hash")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_issues_delete
                AFTER DELETE ON "issues" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'issues',json_array(OLD."issue_id"),json_object('issue_id',OLD."issue_id",'title',OLD."title",'issue_type',OLD."issue_type",'scope_json',OLD."scope_json",'parent_issue_id',OLD."parent_issue_id",'work_status',OLD."work_status",'conclusion_status',OLD."conclusion_status",'conclusion_revision',OLD."conclusion_revision",'current_conclusion_id',OLD."current_conclusion_id",'policy_version',OLD."policy_version",'normalized_scope_key',OLD."normalized_scope_key",'topic',OLD."topic",'canonical_alias',OLD."canonical_alias",'issue_type_registration_id',OLD."issue_type_registration_id",'issue_type_content_hash',OLD."issue_type_content_hash",'issue_type_snapshot_json',OLD."issue_type_snapshot_json",'issue_type_semantic_hash',OLD."issue_type_semantic_hash"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_issues_insert
                AFTER INSERT ON "issues" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'issues',json_array(NEW."issue_id"),'{}',json_object('issue_id',NEW."issue_id",'title',NEW."title",'issue_type',NEW."issue_type",'scope_json',NEW."scope_json",'parent_issue_id',NEW."parent_issue_id",'work_status',NEW."work_status",'conclusion_status',NEW."conclusion_status",'conclusion_revision',NEW."conclusion_revision",'current_conclusion_id',NEW."current_conclusion_id",'policy_version',NEW."policy_version",'normalized_scope_key',NEW."normalized_scope_key",'topic',NEW."topic",'canonical_alias',NEW."canonical_alias",'issue_type_registration_id',NEW."issue_type_registration_id",'issue_type_content_hash',NEW."issue_type_content_hash",'issue_type_snapshot_json',NEW."issue_type_snapshot_json",'issue_type_semantic_hash',NEW."issue_type_semantic_hash")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_issues_update
                AFTER UPDATE ON "issues" WHEN json_object('issue_id',OLD."issue_id",'title',OLD."title",'issue_type',OLD."issue_type",'scope_json',OLD."scope_json",'parent_issue_id',OLD."parent_issue_id",'work_status',OLD."work_status",'conclusion_status',OLD."conclusion_status",'conclusion_revision',OLD."conclusion_revision",'current_conclusion_id',OLD."current_conclusion_id",'policy_version',OLD."policy_version",'normalized_scope_key',OLD."normalized_scope_key",'topic',OLD."topic",'canonical_alias',OLD."canonical_alias",'issue_type_registration_id',OLD."issue_type_registration_id",'issue_type_content_hash',OLD."issue_type_content_hash",'issue_type_snapshot_json',OLD."issue_type_snapshot_json",'issue_type_semantic_hash',OLD."issue_type_semantic_hash") IS NOT json_object('issue_id',NEW."issue_id",'title',NEW."title",'issue_type',NEW."issue_type",'scope_json',NEW."scope_json",'parent_issue_id',NEW."parent_issue_id",'work_status',NEW."work_status",'conclusion_status',NEW."conclusion_status",'conclusion_revision',NEW."conclusion_revision",'current_conclusion_id',NEW."current_conclusion_id",'policy_version',NEW."policy_version",'normalized_scope_key',NEW."normalized_scope_key",'topic',NEW."topic",'canonical_alias',NEW."canonical_alias",'issue_type_registration_id',NEW."issue_type_registration_id",'issue_type_content_hash',NEW."issue_type_content_hash",'issue_type_snapshot_json',NEW."issue_type_snapshot_json",'issue_type_semantic_hash',NEW."issue_type_semantic_hash")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'issues',json_array(NEW."issue_id"),json_object('issue_id',OLD."issue_id",'title',OLD."title",'issue_type',OLD."issue_type",'scope_json',OLD."scope_json",'parent_issue_id',OLD."parent_issue_id",'work_status',OLD."work_status",'conclusion_status',OLD."conclusion_status",'conclusion_revision',OLD."conclusion_revision",'current_conclusion_id',OLD."current_conclusion_id",'policy_version',OLD."policy_version",'normalized_scope_key',OLD."normalized_scope_key",'topic',OLD."topic",'canonical_alias',OLD."canonical_alias",'issue_type_registration_id',OLD."issue_type_registration_id",'issue_type_content_hash',OLD."issue_type_content_hash",'issue_type_snapshot_json',OLD."issue_type_snapshot_json",'issue_type_semantic_hash',OLD."issue_type_semantic_hash"),json_object('issue_id',NEW."issue_id",'title',NEW."title",'issue_type',NEW."issue_type",'scope_json',NEW."scope_json",'parent_issue_id',NEW."parent_issue_id",'work_status',NEW."work_status",'conclusion_status',NEW."conclusion_status",'conclusion_revision',NEW."conclusion_revision",'current_conclusion_id',NEW."current_conclusion_id",'policy_version',NEW."policy_version",'normalized_scope_key',NEW."normalized_scope_key",'topic',NEW."topic",'canonical_alias',NEW."canonical_alias",'issue_type_registration_id',NEW."issue_type_registration_id",'issue_type_content_hash',NEW."issue_type_content_hash",'issue_type_snapshot_json',NEW."issue_type_snapshot_json",'issue_type_semantic_hash',NEW."issue_type_semantic_hash")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_managed_relation_versions_delete
                AFTER DELETE ON "managed_relation_versions" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'managed_relation_versions',json_array(OLD."version_id"),json_object('version_id',OLD."version_id",'domain',OLD."domain",'relation_id',OLD."relation_id",'version_number',OLD."version_number",'contract_version',OLD."contract_version",'definition_json',OLD."definition_json"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_managed_relation_versions_insert
                AFTER INSERT ON "managed_relation_versions" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'managed_relation_versions',json_array(NEW."version_id"),'{}',json_object('version_id',NEW."version_id",'domain',NEW."domain",'relation_id',NEW."relation_id",'version_number',NEW."version_number",'contract_version',NEW."contract_version",'definition_json',NEW."definition_json")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_managed_relation_versions_update
                AFTER UPDATE ON "managed_relation_versions" WHEN json_object('version_id',OLD."version_id",'domain',OLD."domain",'relation_id',OLD."relation_id",'version_number',OLD."version_number",'contract_version',OLD."contract_version",'definition_json',OLD."definition_json") IS NOT json_object('version_id',NEW."version_id",'domain',NEW."domain",'relation_id',NEW."relation_id",'version_number',NEW."version_number",'contract_version',NEW."contract_version",'definition_json',NEW."definition_json")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'managed_relation_versions',json_array(NEW."version_id"),json_object('version_id',OLD."version_id",'domain',OLD."domain",'relation_id',OLD."relation_id",'version_number',OLD."version_number",'contract_version',OLD."contract_version",'definition_json',OLD."definition_json"),json_object('version_id',NEW."version_id",'domain',NEW."domain",'relation_id',NEW."relation_id",'version_number',NEW."version_number",'contract_version',NEW."contract_version",'definition_json',NEW."definition_json")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_record_evidence_links_delete
                AFTER DELETE ON "record_evidence_links" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'record_evidence_links',json_array(OLD."record_revision_id",OLD."field_path",OLD."evidence_id",OLD."relation_role"),json_object('record_revision_id',OLD."record_revision_id",'field_path',OLD."field_path",'evidence_id',OLD."evidence_id",'proof_id',OLD."proof_id",'relation_role',OLD."relation_role",'proof_hash',OLD."proof_hash",'manifest_id',OLD."manifest_id",'manifest_hash',OLD."manifest_hash",'evidence_semantic_revision',OLD."evidence_semantic_revision",'verification_level_snapshot',OLD."verification_level_snapshot",'verification_state_snapshot',OLD."verification_state_snapshot"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_record_evidence_links_insert
                AFTER INSERT ON "record_evidence_links" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'record_evidence_links',json_array(NEW."record_revision_id",NEW."field_path",NEW."evidence_id",NEW."relation_role"),'{}',json_object('record_revision_id',NEW."record_revision_id",'field_path',NEW."field_path",'evidence_id',NEW."evidence_id",'proof_id',NEW."proof_id",'relation_role',NEW."relation_role",'proof_hash',NEW."proof_hash",'manifest_id',NEW."manifest_id",'manifest_hash',NEW."manifest_hash",'evidence_semantic_revision',NEW."evidence_semantic_revision",'verification_level_snapshot',NEW."verification_level_snapshot",'verification_state_snapshot',NEW."verification_state_snapshot")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_record_evidence_links_update
                AFTER UPDATE ON "record_evidence_links" WHEN json_object('record_revision_id',OLD."record_revision_id",'field_path',OLD."field_path",'evidence_id',OLD."evidence_id",'proof_id',OLD."proof_id",'relation_role',OLD."relation_role",'proof_hash',OLD."proof_hash",'manifest_id',OLD."manifest_id",'manifest_hash',OLD."manifest_hash",'evidence_semantic_revision',OLD."evidence_semantic_revision",'verification_level_snapshot',OLD."verification_level_snapshot",'verification_state_snapshot',OLD."verification_state_snapshot") IS NOT json_object('record_revision_id',NEW."record_revision_id",'field_path',NEW."field_path",'evidence_id',NEW."evidence_id",'proof_id',NEW."proof_id",'relation_role',NEW."relation_role",'proof_hash',NEW."proof_hash",'manifest_id',NEW."manifest_id",'manifest_hash',NEW."manifest_hash",'evidence_semantic_revision',NEW."evidence_semantic_revision",'verification_level_snapshot',NEW."verification_level_snapshot",'verification_state_snapshot',NEW."verification_state_snapshot")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'record_evidence_links',json_array(NEW."record_revision_id",NEW."field_path",NEW."evidence_id",NEW."relation_role"),json_object('record_revision_id',OLD."record_revision_id",'field_path',OLD."field_path",'evidence_id',OLD."evidence_id",'proof_id',OLD."proof_id",'relation_role',OLD."relation_role",'proof_hash',OLD."proof_hash",'manifest_id',OLD."manifest_id",'manifest_hash',OLD."manifest_hash",'evidence_semantic_revision',OLD."evidence_semantic_revision",'verification_level_snapshot',OLD."verification_level_snapshot",'verification_state_snapshot',OLD."verification_state_snapshot"),json_object('record_revision_id',NEW."record_revision_id",'field_path',NEW."field_path",'evidence_id',NEW."evidence_id",'proof_id',NEW."proof_id",'relation_role',NEW."relation_role",'proof_hash',NEW."proof_hash",'manifest_id',NEW."manifest_id",'manifest_hash',NEW."manifest_hash",'evidence_semantic_revision',NEW."evidence_semantic_revision",'verification_level_snapshot',NEW."verification_level_snapshot",'verification_state_snapshot',NEW."verification_state_snapshot")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_record_instances_delete
                AFTER DELETE ON "record_instances" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'record_instances',json_array(OLD."record_instance_id"),json_object('record_instance_id',OLD."record_instance_id",'issue_id',OLD."issue_id",'record_template_registration_id',OLD."record_template_registration_id",'record_template_snapshot_json',OLD."record_template_snapshot_json",'current_revision_id',OLD."current_revision_id",'lifecycle_status',OLD."lifecycle_status"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_record_instances_insert
                AFTER INSERT ON "record_instances" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'record_instances',json_array(NEW."record_instance_id"),'{}',json_object('record_instance_id',NEW."record_instance_id",'issue_id',NEW."issue_id",'record_template_registration_id',NEW."record_template_registration_id",'record_template_snapshot_json',NEW."record_template_snapshot_json",'current_revision_id',NEW."current_revision_id",'lifecycle_status',NEW."lifecycle_status")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_record_instances_update
                AFTER UPDATE ON "record_instances" WHEN json_object('record_instance_id',OLD."record_instance_id",'issue_id',OLD."issue_id",'record_template_registration_id',OLD."record_template_registration_id",'record_template_snapshot_json',OLD."record_template_snapshot_json",'current_revision_id',OLD."current_revision_id",'lifecycle_status',OLD."lifecycle_status") IS NOT json_object('record_instance_id',NEW."record_instance_id",'issue_id',NEW."issue_id",'record_template_registration_id',NEW."record_template_registration_id",'record_template_snapshot_json',NEW."record_template_snapshot_json",'current_revision_id',NEW."current_revision_id",'lifecycle_status',NEW."lifecycle_status")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'record_instances',json_array(NEW."record_instance_id"),json_object('record_instance_id',OLD."record_instance_id",'issue_id',OLD."issue_id",'record_template_registration_id',OLD."record_template_registration_id",'record_template_snapshot_json',OLD."record_template_snapshot_json",'current_revision_id',OLD."current_revision_id",'lifecycle_status',OLD."lifecycle_status"),json_object('record_instance_id',NEW."record_instance_id",'issue_id',NEW."issue_id",'record_template_registration_id',NEW."record_template_registration_id",'record_template_snapshot_json',NEW."record_template_snapshot_json",'current_revision_id',NEW."current_revision_id",'lifecycle_status',NEW."lifecycle_status")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_record_material_relations_delete
                AFTER DELETE ON "record_material_relations" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'record_material_relations',json_array(OLD."relation_id"),json_object('relation_id',OLD."relation_id",'active',OLD."active",'record_revision_id',OLD."record_revision_id",'field_path',OLD."field_path",'evidence_id',OLD."evidence_id",'proof_id',OLD."proof_id",'relation_role',OLD."relation_role",'proof_hash',OLD."proof_hash",'manifest_id',OLD."manifest_id",'manifest_hash',OLD."manifest_hash",'evidence_semantic_revision',OLD."evidence_semantic_revision",'verification_level_snapshot',OLD."verification_level_snapshot",'verification_state_snapshot',OLD."verification_state_snapshot"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_record_material_relations_insert
                AFTER INSERT ON "record_material_relations" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'record_material_relations',json_array(NEW."relation_id"),'{}',json_object('relation_id',NEW."relation_id",'active',NEW."active",'record_revision_id',NEW."record_revision_id",'field_path',NEW."field_path",'evidence_id',NEW."evidence_id",'proof_id',NEW."proof_id",'relation_role',NEW."relation_role",'proof_hash',NEW."proof_hash",'manifest_id',NEW."manifest_id",'manifest_hash',NEW."manifest_hash",'evidence_semantic_revision',NEW."evidence_semantic_revision",'verification_level_snapshot',NEW."verification_level_snapshot",'verification_state_snapshot',NEW."verification_state_snapshot")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_record_material_relations_update
                AFTER UPDATE ON "record_material_relations" WHEN json_object('relation_id',OLD."relation_id",'active',OLD."active",'record_revision_id',OLD."record_revision_id",'field_path',OLD."field_path",'evidence_id',OLD."evidence_id",'proof_id',OLD."proof_id",'relation_role',OLD."relation_role",'proof_hash',OLD."proof_hash",'manifest_id',OLD."manifest_id",'manifest_hash',OLD."manifest_hash",'evidence_semantic_revision',OLD."evidence_semantic_revision",'verification_level_snapshot',OLD."verification_level_snapshot",'verification_state_snapshot',OLD."verification_state_snapshot") IS NOT json_object('relation_id',NEW."relation_id",'active',NEW."active",'record_revision_id',NEW."record_revision_id",'field_path',NEW."field_path",'evidence_id',NEW."evidence_id",'proof_id',NEW."proof_id",'relation_role',NEW."relation_role",'proof_hash',NEW."proof_hash",'manifest_id',NEW."manifest_id",'manifest_hash',NEW."manifest_hash",'evidence_semantic_revision',NEW."evidence_semantic_revision",'verification_level_snapshot',NEW."verification_level_snapshot",'verification_state_snapshot',NEW."verification_state_snapshot")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'record_material_relations',json_array(NEW."relation_id"),json_object('relation_id',OLD."relation_id",'active',OLD."active",'record_revision_id',OLD."record_revision_id",'field_path',OLD."field_path",'evidence_id',OLD."evidence_id",'proof_id',OLD."proof_id",'relation_role',OLD."relation_role",'proof_hash',OLD."proof_hash",'manifest_id',OLD."manifest_id",'manifest_hash',OLD."manifest_hash",'evidence_semantic_revision',OLD."evidence_semantic_revision",'verification_level_snapshot',OLD."verification_level_snapshot",'verification_state_snapshot',OLD."verification_state_snapshot"),json_object('relation_id',NEW."relation_id",'active',NEW."active",'record_revision_id',NEW."record_revision_id",'field_path',NEW."field_path",'evidence_id',NEW."evidence_id",'proof_id',NEW."proof_id",'relation_role',NEW."relation_role",'proof_hash',NEW."proof_hash",'manifest_id',NEW."manifest_id",'manifest_hash',NEW."manifest_hash",'evidence_semantic_revision',NEW."evidence_semantic_revision",'verification_level_snapshot',NEW."verification_level_snapshot",'verification_state_snapshot',NEW."verification_state_snapshot")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_record_revisions_delete
                AFTER DELETE ON "record_revisions" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'record_revisions',json_array(OLD."record_revision_id"),json_object('record_revision_id',OLD."record_revision_id",'record_instance_id',OLD."record_instance_id",'revision_number',OLD."revision_number",'template_content_hash',OLD."template_content_hash",'template_snapshot_json',OLD."template_snapshot_json",'data_json',OLD."data_json",'recorded_at',OLD."recorded_at",'recorded_by',OLD."recorded_by",'source_mode',OLD."source_mode",'source_object_mapping_id',OLD."source_object_mapping_id",'supersedes_revision_id',OLD."supersedes_revision_id",'validation_profile',OLD."validation_profile",'validation_result_json',OLD."validation_result_json",'content_hash',OLD."content_hash"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_record_revisions_insert
                AFTER INSERT ON "record_revisions" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'record_revisions',json_array(NEW."record_revision_id"),'{}',json_object('record_revision_id',NEW."record_revision_id",'record_instance_id',NEW."record_instance_id",'revision_number',NEW."revision_number",'template_content_hash',NEW."template_content_hash",'template_snapshot_json',NEW."template_snapshot_json",'data_json',NEW."data_json",'recorded_at',NEW."recorded_at",'recorded_by',NEW."recorded_by",'source_mode',NEW."source_mode",'source_object_mapping_id',NEW."source_object_mapping_id",'supersedes_revision_id',NEW."supersedes_revision_id",'validation_profile',NEW."validation_profile",'validation_result_json',NEW."validation_result_json",'content_hash',NEW."content_hash")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_record_revisions_update
                AFTER UPDATE ON "record_revisions" WHEN json_object('record_revision_id',OLD."record_revision_id",'record_instance_id',OLD."record_instance_id",'revision_number',OLD."revision_number",'template_content_hash',OLD."template_content_hash",'template_snapshot_json',OLD."template_snapshot_json",'data_json',OLD."data_json",'recorded_at',OLD."recorded_at",'recorded_by',OLD."recorded_by",'source_mode',OLD."source_mode",'source_object_mapping_id',OLD."source_object_mapping_id",'supersedes_revision_id',OLD."supersedes_revision_id",'validation_profile',OLD."validation_profile",'validation_result_json',OLD."validation_result_json",'content_hash',OLD."content_hash") IS NOT json_object('record_revision_id',NEW."record_revision_id",'record_instance_id',NEW."record_instance_id",'revision_number',NEW."revision_number",'template_content_hash',NEW."template_content_hash",'template_snapshot_json',NEW."template_snapshot_json",'data_json',NEW."data_json",'recorded_at',NEW."recorded_at",'recorded_by',NEW."recorded_by",'source_mode',NEW."source_mode",'source_object_mapping_id',NEW."source_object_mapping_id",'supersedes_revision_id',NEW."supersedes_revision_id",'validation_profile',NEW."validation_profile",'validation_result_json',NEW."validation_result_json",'content_hash',NEW."content_hash")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'record_revisions',json_array(NEW."record_revision_id"),json_object('record_revision_id',OLD."record_revision_id",'record_instance_id',OLD."record_instance_id",'revision_number',OLD."revision_number",'template_content_hash',OLD."template_content_hash",'template_snapshot_json',OLD."template_snapshot_json",'data_json',OLD."data_json",'recorded_at',OLD."recorded_at",'recorded_by',OLD."recorded_by",'source_mode',OLD."source_mode",'source_object_mapping_id',OLD."source_object_mapping_id",'supersedes_revision_id',OLD."supersedes_revision_id",'validation_profile',OLD."validation_profile",'validation_result_json',OLD."validation_result_json",'content_hash',OLD."content_hash"),json_object('record_revision_id',NEW."record_revision_id",'record_instance_id',NEW."record_instance_id",'revision_number',NEW."revision_number",'template_content_hash',NEW."template_content_hash",'template_snapshot_json',NEW."template_snapshot_json",'data_json',NEW."data_json",'recorded_at',NEW."recorded_at",'recorded_by',NEW."recorded_by",'source_mode',NEW."source_mode",'source_object_mapping_id',NEW."source_object_mapping_id",'supersedes_revision_id',NEW."supersedes_revision_id",'validation_profile',NEW."validation_profile",'validation_result_json',NEW."validation_result_json",'content_hash',NEW."content_hash")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_registry_entries_delete
                AFTER DELETE ON "registry_entries" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'registry_entries',json_array(OLD."registration_id"),json_object('registration_id',OLD."registration_id",'bundle_id',OLD."bundle_id",'namespace',OLD."namespace",'kind',OLD."kind",'name',OLD."name",'version',OLD."version",'api_version',OLD."api_version",'definition_json',OLD."definition_json",'content_hash',OLD."content_hash",'state',OLD."state"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_registry_entries_insert
                AFTER INSERT ON "registry_entries" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'registry_entries',json_array(NEW."registration_id"),'{}',json_object('registration_id',NEW."registration_id",'bundle_id',NEW."bundle_id",'namespace',NEW."namespace",'kind',NEW."kind",'name',NEW."name",'version',NEW."version",'api_version',NEW."api_version",'definition_json',NEW."definition_json",'content_hash',NEW."content_hash",'state',NEW."state")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_registry_entries_update
                AFTER UPDATE ON "registry_entries" WHEN json_object('registration_id',OLD."registration_id",'bundle_id',OLD."bundle_id",'namespace',OLD."namespace",'kind',OLD."kind",'name',OLD."name",'version',OLD."version",'api_version',OLD."api_version",'definition_json',OLD."definition_json",'content_hash',OLD."content_hash",'state',OLD."state") IS NOT json_object('registration_id',NEW."registration_id",'bundle_id',NEW."bundle_id",'namespace',NEW."namespace",'kind',NEW."kind",'name',NEW."name",'version',NEW."version",'api_version',NEW."api_version",'definition_json',NEW."definition_json",'content_hash',NEW."content_hash",'state',NEW."state")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'registry_entries',json_array(NEW."registration_id"),json_object('registration_id',OLD."registration_id",'bundle_id',OLD."bundle_id",'namespace',OLD."namespace",'kind',OLD."kind",'name',OLD."name",'version',OLD."version",'api_version',OLD."api_version",'definition_json',OLD."definition_json",'content_hash',OLD."content_hash",'state',OLD."state"),json_object('registration_id',NEW."registration_id",'bundle_id',NEW."bundle_id",'namespace',NEW."namespace",'kind',NEW."kind",'name',NEW."name",'version',NEW."version",'api_version',NEW."api_version",'definition_json',NEW."definition_json",'content_hash',NEW."content_hash",'state',NEW."state")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_relations_delete
                AFTER DELETE ON "relations" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'relations',json_array(OLD."relation_id"),json_object('relation_id',OLD."relation_id",'consumer_issue_id',OLD."consumer_issue_id",'provider_issue_id',OLD."provider_issue_id",'relation_type',OLD."relation_type",'impact_policy',OLD."impact_policy",'active',OLD."active",'reason',OLD."reason",'policy_version',OLD."policy_version",'superseded_relation_id',OLD."superseded_relation_id"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_relations_insert
                AFTER INSERT ON "relations" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'relations',json_array(NEW."relation_id"),'{}',json_object('relation_id',NEW."relation_id",'consumer_issue_id',NEW."consumer_issue_id",'provider_issue_id',NEW."provider_issue_id",'relation_type',NEW."relation_type",'impact_policy',NEW."impact_policy",'active',NEW."active",'reason',NEW."reason",'policy_version',NEW."policy_version",'superseded_relation_id',NEW."superseded_relation_id")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_relations_update
                AFTER UPDATE ON "relations" WHEN json_object('relation_id',OLD."relation_id",'consumer_issue_id',OLD."consumer_issue_id",'provider_issue_id',OLD."provider_issue_id",'relation_type',OLD."relation_type",'impact_policy',OLD."impact_policy",'active',OLD."active",'reason',OLD."reason",'policy_version',OLD."policy_version",'superseded_relation_id',OLD."superseded_relation_id") IS NOT json_object('relation_id',NEW."relation_id",'consumer_issue_id',NEW."consumer_issue_id",'provider_issue_id',NEW."provider_issue_id",'relation_type',NEW."relation_type",'impact_policy',NEW."impact_policy",'active',NEW."active",'reason',NEW."reason",'policy_version',NEW."policy_version",'superseded_relation_id',NEW."superseded_relation_id")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'relations',json_array(NEW."relation_id"),json_object('relation_id',OLD."relation_id",'consumer_issue_id',OLD."consumer_issue_id",'provider_issue_id',OLD."provider_issue_id",'relation_type',OLD."relation_type",'impact_policy',OLD."impact_policy",'active',OLD."active",'reason',OLD."reason",'policy_version',OLD."policy_version",'superseded_relation_id',OLD."superseded_relation_id"),json_object('relation_id',NEW."relation_id",'consumer_issue_id',NEW."consumer_issue_id",'provider_issue_id',NEW."provider_issue_id",'relation_type',NEW."relation_type",'impact_policy',NEW."impact_policy",'active',NEW."active",'reason',NEW."reason",'policy_version',NEW."policy_version",'superseded_relation_id',NEW."superseded_relation_id")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_triage_dispositions_delete
                AFTER DELETE ON "triage_dispositions" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'triage_dispositions',json_array(OLD."packet_id"),json_object('packet_id',OLD."packet_id",'disposition',OLD."disposition",'issue_id',OLD."issue_id",'conclusion_id',OLD."conclusion_id",'proposal_id',OLD."proposal_id",'evidence_request_id',OLD."evidence_request_id",'reason',OLD."reason"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_triage_dispositions_insert
                AFTER INSERT ON "triage_dispositions" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'triage_dispositions',json_array(NEW."packet_id"),'{}',json_object('packet_id',NEW."packet_id",'disposition',NEW."disposition",'issue_id',NEW."issue_id",'conclusion_id',NEW."conclusion_id",'proposal_id',NEW."proposal_id",'evidence_request_id',NEW."evidence_request_id",'reason',NEW."reason")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_triage_dispositions_update
                AFTER UPDATE ON "triage_dispositions" WHEN json_object('packet_id',OLD."packet_id",'disposition',OLD."disposition",'issue_id',OLD."issue_id",'conclusion_id',OLD."conclusion_id",'proposal_id',OLD."proposal_id",'evidence_request_id',OLD."evidence_request_id",'reason',OLD."reason") IS NOT json_object('packet_id',NEW."packet_id",'disposition',NEW."disposition",'issue_id',NEW."issue_id",'conclusion_id',NEW."conclusion_id",'proposal_id',NEW."proposal_id",'evidence_request_id',NEW."evidence_request_id",'reason',NEW."reason")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'triage_dispositions',json_array(NEW."packet_id"),json_object('packet_id',OLD."packet_id",'disposition',OLD."disposition",'issue_id',OLD."issue_id",'conclusion_id',OLD."conclusion_id",'proposal_id',OLD."proposal_id",'evidence_request_id',OLD."evidence_request_id",'reason',OLD."reason"),json_object('packet_id',NEW."packet_id",'disposition',NEW."disposition",'issue_id',NEW."issue_id",'conclusion_id',NEW."conclusion_id",'proposal_id',NEW."proposal_id",'evidence_request_id',NEW."evidence_request_id",'reason',NEW."reason")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_working_entries_delete
                AFTER DELETE ON "working_entries" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'working_entries',json_array(OLD."entry_id"),json_object('entry_id',OLD."entry_id",'issue_id',OLD."issue_id",'entry_type',OLD."entry_type",'body',OLD."body",'evidence_refs_json',OLD."evidence_refs_json",'policy_version',OLD."policy_version",'amends_entry_id',OLD."amends_entry_id",'source_packet_id',OLD."source_packet_id"),'{}'
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_working_entries_insert
                AFTER INSERT ON "working_entries" 
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'working_entries',json_array(NEW."entry_id"),'{}',json_object('entry_id',NEW."entry_id",'issue_id',NEW."issue_id",'entry_type',NEW."entry_type",'body',NEW."body",'evidence_refs_json',NEW."evidence_refs_json",'policy_version',NEW."policy_version",'amends_entry_id',NEW."amends_entry_id",'source_packet_id',NEW."source_packet_id")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER context_input_working_entries_update
                AFTER UPDATE ON "working_entries" WHEN json_object('entry_id',OLD."entry_id",'issue_id',OLD."issue_id",'entry_type',OLD."entry_type",'body',OLD."body",'evidence_refs_json',OLD."evidence_refs_json",'policy_version',OLD."policy_version",'amends_entry_id',OLD."amends_entry_id",'source_packet_id',OLD."source_packet_id") IS NOT json_object('entry_id',NEW."entry_id",'issue_id',NEW."issue_id",'entry_type',NEW."entry_type",'body',NEW."body",'evidence_refs_json',NEW."evidence_refs_json",'policy_version',NEW."policy_version",'amends_entry_id',NEW."amends_entry_id",'source_packet_id',NEW."source_packet_id")
                BEGIN
                    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
                    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
                    SELECT revision,'working_entries',json_array(NEW."entry_id"),json_object('entry_id',OLD."entry_id",'issue_id',OLD."issue_id",'entry_type',OLD."entry_type",'body',OLD."body",'evidence_refs_json',OLD."evidence_refs_json",'policy_version',OLD."policy_version",'amends_entry_id',OLD."amends_entry_id",'source_packet_id',OLD."source_packet_id"),json_object('entry_id',NEW."entry_id",'issue_id',NEW."issue_id",'entry_type',NEW."entry_type",'body',NEW."body",'evidence_refs_json',NEW."evidence_refs_json",'policy_version',NEW."policy_version",'amends_entry_id',NEW."amends_entry_id",'source_packet_id',NEW."source_packet_id")
                    FROM context_input_clock WHERE singleton=1;
                END;

CREATE TRIGGER immutable_basis_receipts_delete
BEFORE DELETE ON basis_receipts
BEGIN
    SELECT RAISE(ABORT, 'immutable context history');
END;
CREATE TRIGGER immutable_basis_receipts_update
BEFORE UPDATE ON basis_receipts
BEGIN
    SELECT RAISE(ABORT, 'immutable context history');
END;

CREATE TRIGGER immutable_context_descriptors_delete
BEFORE DELETE ON context_descriptors
BEGIN
    SELECT RAISE(ABORT, 'immutable context history');
END;

CREATE TRIGGER immutable_context_descriptors_update
BEFORE UPDATE ON context_descriptors
BEGIN
    SELECT RAISE(ABORT, 'immutable context history');
END;

CREATE TRIGGER immutable_context_input_events_delete
BEFORE DELETE ON context_input_events
BEGIN
    SELECT RAISE(ABORT, 'immutable context history');
END;

CREATE TRIGGER immutable_context_input_events_update
BEFORE UPDATE ON context_input_events
BEGIN
    SELECT RAISE(ABORT, 'immutable context history');
END;

CREATE TRIGGER immutable_context_input_packages_delete
BEFORE DELETE ON context_input_packages
BEGIN
    SELECT RAISE(ABORT, 'immutable context history');
END;

CREATE TRIGGER immutable_context_input_packages_update
BEFORE UPDATE ON context_input_packages
BEGIN
    SELECT RAISE(ABORT, 'immutable context history');
END;

CREATE TRIGGER immutable_context_obligation_definition BEFORE UPDATE ON context_workflow_obligations
WHEN NEW.obligation_id IS NOT OLD.obligation_id OR NEW.conclusion_id IS NOT OLD.conclusion_id
 OR NEW.kind IS NOT OLD.kind OR NEW.details_json IS NOT OLD.details_json
 OR NEW.blocks_publication IS NOT OLD.blocks_publication OR NEW.created_at IS NOT OLD.created_at
 OR NEW.created_by IS NOT OLD.created_by
BEGIN SELECT RAISE(ABORT, 'Immutable review obligation definition'); END;

CREATE TRIGGER immutable_context_rule_versions_delete
BEFORE DELETE ON context_rule_versions
BEGIN
    SELECT RAISE(ABORT, 'immutable context history');
END;

CREATE TRIGGER immutable_context_rule_versions_update
BEFORE UPDATE ON context_rule_versions
BEGIN
    SELECT RAISE(ABORT, 'immutable context history');
END;

CREATE TRIGGER immutable_context_workflow_obligation_events_delete
BEFORE DELETE ON context_workflow_obligation_events
BEGIN
    SELECT RAISE(ABORT, 'immutable context history');
END;

CREATE TRIGGER immutable_context_workflow_obligation_events_update
BEFORE UPDATE ON context_workflow_obligation_events
BEGIN
    SELECT RAISE(ABORT, 'immutable context history');
END;

CREATE TRIGGER immutable_record_evidence_snapshot_delete
            BEFORE DELETE ON record_evidence_links
            BEGIN SELECT RAISE(ABORT, 'Immutable Record evidence snapshot'); END;

CREATE TRIGGER immutable_record_evidence_snapshot_update
            BEFORE UPDATE ON record_evidence_links
            BEGIN SELECT RAISE(ABORT, 'Immutable Record evidence snapshot'); END;

CREATE TRIGGER immutable_relation_version_delete
            BEFORE DELETE ON managed_relation_versions
            BEGIN SELECT RAISE(ABORT, 'Immutable relation version'); END;

CREATE TRIGGER immutable_relation_version_update
            BEFORE UPDATE ON managed_relation_versions
            BEGIN SELECT RAISE(ABORT, 'Immutable relation version'); END;

CREATE TRIGGER record_origin_material AFTER INSERT ON record_evidence_links
        BEGIN INSERT INTO record_material_relations (relation_id,record_revision_id,field_path,evidence_id,proof_id,relation_role,proof_hash,manifest_id,manifest_hash,evidence_semantic_revision,verification_level_snapshot,verification_state_snapshot)
        VALUES ('record_origin_' || hex(CAST(json_array(NEW."record_revision_id",NEW."field_path",NEW."evidence_id",NEW."relation_role") AS BLOB)),NEW."record_revision_id",NEW."field_path",NEW."evidence_id",NEW."proof_id",NEW."relation_role",NEW."proof_hash",NEW."manifest_id",NEW."manifest_hash",NEW."evidence_semantic_revision",NEW."verification_level_snapshot",NEW."verification_state_snapshot"); END;

CREATE TRIGGER relation_version_context_relations_insert
                AFTER INSERT ON "context_relations" 
                BEGIN
                    INSERT INTO managed_relation_versions
                    SELECT 'context:' || NEW.relation_id || ':' || (COALESCE(MAX(version_number),0)+1),
                           'context',NEW.relation_id,COALESCE(MAX(version_number),0)+1,
                           'context-currentness/v1',json_object('relation_id',NEW."relation_id",'source_key',NEW."source_key",'target_key',NEW."target_key",'relation_type',NEW."relation_type",'require_currentness',NEW."require_currentness",'rationale',NEW."rationale")
                    FROM managed_relation_versions WHERE domain='context' AND relation_id=NEW.relation_id;
                    INSERT INTO managed_relation_heads
                    SELECT domain,relation_id,version_id FROM managed_relation_versions
                    WHERE domain='context' AND relation_id=NEW.relation_id ORDER BY version_number DESC LIMIT 1
                    ON CONFLICT(domain,relation_id) DO UPDATE SET version_id=excluded.version_id;
                END;

CREATE TRIGGER relation_version_context_relations_update
                AFTER UPDATE ON "context_relations" WHEN json_object('relation_id',OLD."relation_id",'source_key',OLD."source_key",'target_key',OLD."target_key",'relation_type',OLD."relation_type",'require_currentness',OLD."require_currentness",'rationale',OLD."rationale") IS NOT json_object('relation_id',NEW."relation_id",'source_key',NEW."source_key",'target_key',NEW."target_key",'relation_type',NEW."relation_type",'require_currentness',NEW."require_currentness",'rationale',NEW."rationale")
                BEGIN
                    INSERT INTO managed_relation_versions
                    SELECT 'context:' || NEW.relation_id || ':' || (COALESCE(MAX(version_number),0)+1),
                           'context',NEW.relation_id,COALESCE(MAX(version_number),0)+1,
                           'context-currentness/v1',json_object('relation_id',NEW."relation_id",'source_key',NEW."source_key",'target_key',NEW."target_key",'relation_type',NEW."relation_type",'require_currentness',NEW."require_currentness",'rationale',NEW."rationale")
                    FROM managed_relation_versions WHERE domain='context' AND relation_id=NEW.relation_id;
                    INSERT INTO managed_relation_heads
                    SELECT domain,relation_id,version_id FROM managed_relation_versions
                    WHERE domain='context' AND relation_id=NEW.relation_id ORDER BY version_number DESC LIMIT 1
                    ON CONFLICT(domain,relation_id) DO UPDATE SET version_id=excluded.version_id;
                END;

CREATE TRIGGER relation_version_evidence_relations_insert
                AFTER INSERT ON "evidence_relations" 
                BEGIN
                    INSERT INTO managed_relation_versions
                    SELECT 'evidence:' || NEW.relation_id || ':' || (COALESCE(MAX(version_number),0)+1),
                           'evidence',NEW.relation_id,COALESCE(MAX(version_number),0)+1,
                           'context-currentness/v1',json_object('relation_id',NEW."relation_id",'consumer_evidence_id',NEW."consumer_evidence_id",'provider_evidence_id',NEW."provider_evidence_id",'relation_type',NEW."relation_type",'impact_policy',NEW."impact_policy",'rationale',NEW."rationale",'provider_snapshot_hash',NEW."provider_snapshot_hash",'consumer_snapshot_hash',NEW."consumer_snapshot_hash",'template_registration_id',NEW."template_registration_id",'template_content_hash',NEW."template_content_hash")
                    FROM managed_relation_versions WHERE domain='evidence' AND relation_id=NEW.relation_id;
                    INSERT INTO managed_relation_heads
                    SELECT domain,relation_id,version_id FROM managed_relation_versions
                    WHERE domain='evidence' AND relation_id=NEW.relation_id ORDER BY version_number DESC LIMIT 1
                    ON CONFLICT(domain,relation_id) DO UPDATE SET version_id=excluded.version_id;
                END;

CREATE TRIGGER relation_version_evidence_relations_update
                AFTER UPDATE ON "evidence_relations" WHEN json_object('relation_id',OLD."relation_id",'consumer_evidence_id',OLD."consumer_evidence_id",'provider_evidence_id',OLD."provider_evidence_id",'relation_type',OLD."relation_type",'impact_policy',OLD."impact_policy",'rationale',OLD."rationale",'provider_snapshot_hash',OLD."provider_snapshot_hash",'consumer_snapshot_hash',OLD."consumer_snapshot_hash",'template_registration_id',OLD."template_registration_id",'template_content_hash',OLD."template_content_hash") IS NOT json_object('relation_id',NEW."relation_id",'consumer_evidence_id',NEW."consumer_evidence_id",'provider_evidence_id',NEW."provider_evidence_id",'relation_type',NEW."relation_type",'impact_policy',NEW."impact_policy",'rationale',NEW."rationale",'provider_snapshot_hash',NEW."provider_snapshot_hash",'consumer_snapshot_hash',NEW."consumer_snapshot_hash",'template_registration_id',NEW."template_registration_id",'template_content_hash',NEW."template_content_hash")
                BEGIN
                    INSERT INTO managed_relation_versions
                    SELECT 'evidence:' || NEW.relation_id || ':' || (COALESCE(MAX(version_number),0)+1),
                           'evidence',NEW.relation_id,COALESCE(MAX(version_number),0)+1,
                           'context-currentness/v1',json_object('relation_id',NEW."relation_id",'consumer_evidence_id',NEW."consumer_evidence_id",'provider_evidence_id',NEW."provider_evidence_id",'relation_type',NEW."relation_type",'impact_policy',NEW."impact_policy",'rationale',NEW."rationale",'provider_snapshot_hash',NEW."provider_snapshot_hash",'consumer_snapshot_hash',NEW."consumer_snapshot_hash",'template_registration_id',NEW."template_registration_id",'template_content_hash',NEW."template_content_hash")
                    FROM managed_relation_versions WHERE domain='evidence' AND relation_id=NEW.relation_id;
                    INSERT INTO managed_relation_heads
                    SELECT domain,relation_id,version_id FROM managed_relation_versions
                    WHERE domain='evidence' AND relation_id=NEW.relation_id ORDER BY version_number DESC LIMIT 1
                    ON CONFLICT(domain,relation_id) DO UPDATE SET version_id=excluded.version_id;
                END;

CREATE TRIGGER relation_version_intake_packet_links_insert
                AFTER INSERT ON "intake_packet_links" 
                BEGIN
                    INSERT INTO managed_relation_versions
                    SELECT 'intake:' || NEW.link_id || ':' || (COALESCE(MAX(version_number),0)+1),
                           'intake',NEW.link_id,COALESCE(MAX(version_number),0)+1,
                           'context-currentness/v1',json_object('link_id',NEW."link_id",'source_packet_id',NEW."source_packet_id",'target_packet_id',NEW."target_packet_id",'link_type',NEW."link_type",'proposed_by',NEW."proposed_by",'rationale',NEW."rationale")
                    FROM managed_relation_versions WHERE domain='intake' AND relation_id=NEW.link_id;
                    INSERT INTO managed_relation_heads
                    SELECT domain,relation_id,version_id FROM managed_relation_versions
                    WHERE domain='intake' AND relation_id=NEW.link_id ORDER BY version_number DESC LIMIT 1
                    ON CONFLICT(domain,relation_id) DO UPDATE SET version_id=excluded.version_id;
                END;

CREATE TRIGGER relation_version_intake_packet_links_update
                AFTER UPDATE ON "intake_packet_links" WHEN json_object('link_id',OLD."link_id",'source_packet_id',OLD."source_packet_id",'target_packet_id',OLD."target_packet_id",'link_type',OLD."link_type",'proposed_by',OLD."proposed_by",'rationale',OLD."rationale") IS NOT json_object('link_id',NEW."link_id",'source_packet_id',NEW."source_packet_id",'target_packet_id',NEW."target_packet_id",'link_type',NEW."link_type",'proposed_by',NEW."proposed_by",'rationale',NEW."rationale")
                BEGIN
                    INSERT INTO managed_relation_versions
                    SELECT 'intake:' || NEW.link_id || ':' || (COALESCE(MAX(version_number),0)+1),
                           'intake',NEW.link_id,COALESCE(MAX(version_number),0)+1,
                           'context-currentness/v1',json_object('link_id',NEW."link_id",'source_packet_id',NEW."source_packet_id",'target_packet_id',NEW."target_packet_id",'link_type',NEW."link_type",'proposed_by',NEW."proposed_by",'rationale',NEW."rationale")
                    FROM managed_relation_versions WHERE domain='intake' AND relation_id=NEW.link_id;
                    INSERT INTO managed_relation_heads
                    SELECT domain,relation_id,version_id FROM managed_relation_versions
                    WHERE domain='intake' AND relation_id=NEW.link_id ORDER BY version_number DESC LIMIT 1
                    ON CONFLICT(domain,relation_id) DO UPDATE SET version_id=excluded.version_id;
                END;

CREATE TRIGGER relation_version_issue_question_evidence_links_insert
                AFTER INSERT ON "issue_question_evidence_links" 
                BEGIN
                    INSERT INTO managed_relation_versions
                    SELECT 'question:' || NEW.relation_id || ':' || (COALESCE(MAX(version_number),0)+1),
                           'question',NEW.relation_id,COALESCE(MAX(version_number),0)+1,
                           'context-currentness/v1',json_object('relation_id',NEW."relation_id",'question_id',NEW."question_id",'evidence_id',NEW."evidence_id",'link_type',NEW."link_type",'rationale',NEW."rationale")
                    FROM managed_relation_versions WHERE domain='question' AND relation_id=NEW.relation_id;
                    INSERT INTO managed_relation_heads
                    SELECT domain,relation_id,version_id FROM managed_relation_versions
                    WHERE domain='question' AND relation_id=NEW.relation_id ORDER BY version_number DESC LIMIT 1
                    ON CONFLICT(domain,relation_id) DO UPDATE SET version_id=excluded.version_id;
                END;

CREATE TRIGGER relation_version_issue_question_evidence_links_update
                AFTER UPDATE ON "issue_question_evidence_links" WHEN json_object('relation_id',OLD."relation_id",'question_id',OLD."question_id",'evidence_id',OLD."evidence_id",'link_type',OLD."link_type",'rationale',OLD."rationale") IS NOT json_object('relation_id',NEW."relation_id",'question_id',NEW."question_id",'evidence_id',NEW."evidence_id",'link_type',NEW."link_type",'rationale',NEW."rationale")
                BEGIN
                    INSERT INTO managed_relation_versions
                    SELECT 'question:' || NEW.relation_id || ':' || (COALESCE(MAX(version_number),0)+1),
                           'question',NEW.relation_id,COALESCE(MAX(version_number),0)+1,
                           'context-currentness/v1',json_object('relation_id',NEW."relation_id",'question_id',NEW."question_id",'evidence_id',NEW."evidence_id",'link_type',NEW."link_type",'rationale',NEW."rationale")
                    FROM managed_relation_versions WHERE domain='question' AND relation_id=NEW.relation_id;
                    INSERT INTO managed_relation_heads
                    SELECT domain,relation_id,version_id FROM managed_relation_versions
                    WHERE domain='question' AND relation_id=NEW.relation_id ORDER BY version_number DESC LIMIT 1
                    ON CONFLICT(domain,relation_id) DO UPDATE SET version_id=excluded.version_id;
                END;

CREATE TRIGGER relation_version_record_material_relations_insert
                AFTER INSERT ON "record_material_relations" 
                BEGIN
                    INSERT INTO managed_relation_versions
                    SELECT 'record:' || NEW.relation_id || ':' || (COALESCE(MAX(version_number),0)+1),
                           'record',NEW.relation_id,COALESCE(MAX(version_number),0)+1,
                           'context-currentness/v1',json_object('relation_id',NEW."relation_id",'record_revision_id',NEW."record_revision_id",'field_path',NEW."field_path",'evidence_id',NEW."evidence_id",'proof_id',NEW."proof_id",'relation_role',NEW."relation_role",'proof_hash',NEW."proof_hash",'manifest_id',NEW."manifest_id",'manifest_hash',NEW."manifest_hash",'evidence_semantic_revision',NEW."evidence_semantic_revision",'verification_level_snapshot',NEW."verification_level_snapshot",'verification_state_snapshot',NEW."verification_state_snapshot")
                    FROM managed_relation_versions WHERE domain='record' AND relation_id=NEW.relation_id;
                    INSERT INTO managed_relation_heads
                    SELECT domain,relation_id,version_id FROM managed_relation_versions
                    WHERE domain='record' AND relation_id=NEW.relation_id ORDER BY version_number DESC LIMIT 1
                    ON CONFLICT(domain,relation_id) DO UPDATE SET version_id=excluded.version_id;
                END;

CREATE TRIGGER relation_version_record_material_relations_update
                AFTER UPDATE ON "record_material_relations" WHEN json_object('relation_id',OLD."relation_id",'record_revision_id',OLD."record_revision_id",'field_path',OLD."field_path",'evidence_id',OLD."evidence_id",'proof_id',OLD."proof_id",'relation_role',OLD."relation_role",'proof_hash',OLD."proof_hash",'manifest_id',OLD."manifest_id",'manifest_hash',OLD."manifest_hash",'evidence_semantic_revision',OLD."evidence_semantic_revision",'verification_level_snapshot',OLD."verification_level_snapshot",'verification_state_snapshot',OLD."verification_state_snapshot") IS NOT json_object('relation_id',NEW."relation_id",'record_revision_id',NEW."record_revision_id",'field_path',NEW."field_path",'evidence_id',NEW."evidence_id",'proof_id',NEW."proof_id",'relation_role',NEW."relation_role",'proof_hash',NEW."proof_hash",'manifest_id',NEW."manifest_id",'manifest_hash',NEW."manifest_hash",'evidence_semantic_revision',NEW."evidence_semantic_revision",'verification_level_snapshot',NEW."verification_level_snapshot",'verification_state_snapshot',NEW."verification_state_snapshot")
                BEGIN
                    INSERT INTO managed_relation_versions
                    SELECT 'record:' || NEW.relation_id || ':' || (COALESCE(MAX(version_number),0)+1),
                           'record',NEW.relation_id,COALESCE(MAX(version_number),0)+1,
                           'context-currentness/v1',json_object('relation_id',NEW."relation_id",'record_revision_id',NEW."record_revision_id",'field_path',NEW."field_path",'evidence_id',NEW."evidence_id",'proof_id',NEW."proof_id",'relation_role',NEW."relation_role",'proof_hash',NEW."proof_hash",'manifest_id',NEW."manifest_id",'manifest_hash',NEW."manifest_hash",'evidence_semantic_revision',NEW."evidence_semantic_revision",'verification_level_snapshot',NEW."verification_level_snapshot",'verification_state_snapshot',NEW."verification_state_snapshot")
                    FROM managed_relation_versions WHERE domain='record' AND relation_id=NEW.relation_id;
                    INSERT INTO managed_relation_heads
                    SELECT domain,relation_id,version_id FROM managed_relation_versions
                    WHERE domain='record' AND relation_id=NEW.relation_id ORDER BY version_number DESC LIMIT 1
                    ON CONFLICT(domain,relation_id) DO UPDATE SET version_id=excluded.version_id;
                END;

CREATE TRIGGER relation_version_relations_insert
                AFTER INSERT ON "relations" 
                BEGIN
                    INSERT INTO managed_relation_versions
                    SELECT 'issue:' || NEW.relation_id || ':' || (COALESCE(MAX(version_number),0)+1),
                           'issue',NEW.relation_id,COALESCE(MAX(version_number),0)+1,
                           'context-currentness/v1',json_object('relation_id',NEW."relation_id",'consumer_issue_id',NEW."consumer_issue_id",'provider_issue_id',NEW."provider_issue_id",'relation_type',NEW."relation_type",'impact_policy',NEW."impact_policy",'reason',NEW."reason",'policy_version',NEW."policy_version",'superseded_relation_id',NEW."superseded_relation_id")
                    FROM managed_relation_versions WHERE domain='issue' AND relation_id=NEW.relation_id;
                    INSERT INTO managed_relation_heads
                    SELECT domain,relation_id,version_id FROM managed_relation_versions
                    WHERE domain='issue' AND relation_id=NEW.relation_id ORDER BY version_number DESC LIMIT 1
                    ON CONFLICT(domain,relation_id) DO UPDATE SET version_id=excluded.version_id;
                END;

CREATE TRIGGER relation_version_relations_update
                AFTER UPDATE ON "relations" WHEN json_object('relation_id',OLD."relation_id",'consumer_issue_id',OLD."consumer_issue_id",'provider_issue_id',OLD."provider_issue_id",'relation_type',OLD."relation_type",'impact_policy',OLD."impact_policy",'reason',OLD."reason",'policy_version',OLD."policy_version",'superseded_relation_id',OLD."superseded_relation_id") IS NOT json_object('relation_id',NEW."relation_id",'consumer_issue_id',NEW."consumer_issue_id",'provider_issue_id',NEW."provider_issue_id",'relation_type',NEW."relation_type",'impact_policy',NEW."impact_policy",'reason',NEW."reason",'policy_version',NEW."policy_version",'superseded_relation_id',NEW."superseded_relation_id")
                BEGIN
                    INSERT INTO managed_relation_versions
                    SELECT 'issue:' || NEW.relation_id || ':' || (COALESCE(MAX(version_number),0)+1),
                           'issue',NEW.relation_id,COALESCE(MAX(version_number),0)+1,
                           'context-currentness/v1',json_object('relation_id',NEW."relation_id",'consumer_issue_id',NEW."consumer_issue_id",'provider_issue_id',NEW."provider_issue_id",'relation_type',NEW."relation_type",'impact_policy',NEW."impact_policy",'reason',NEW."reason",'policy_version',NEW."policy_version",'superseded_relation_id',NEW."superseded_relation_id")
                    FROM managed_relation_versions WHERE domain='issue' AND relation_id=NEW.relation_id;
                    INSERT INTO managed_relation_heads
                    SELECT domain,relation_id,version_id FROM managed_relation_versions
                    WHERE domain='issue' AND relation_id=NEW.relation_id ORDER BY version_number DESC LIMIT 1
                    ON CONFLICT(domain,relation_id) DO UPDATE SET version_id=excluded.version_id;
                END;

CREATE TRIGGER retain_context_obligation BEFORE DELETE ON context_workflow_obligations
BEGIN SELECT RAISE(ABORT, 'Retain review obligation history'); END;

CREATE TRIGGER retain_context_relations_identity BEFORE DELETE ON "context_relations"
            BEGIN SELECT RAISE(ABORT, 'Disable relations instead of deleting identity'); END;

CREATE TRIGGER retain_context_relations_identity_update BEFORE UPDATE ON "context_relations"
            WHEN OLD.relation_id IS NOT NEW.relation_id
            BEGIN SELECT RAISE(ABORT, 'Retain relation identity'); END;

CREATE TRIGGER retain_evidence_relations_identity BEFORE DELETE ON "evidence_relations"
            BEGIN SELECT RAISE(ABORT, 'Disable relations instead of deleting identity'); END;

CREATE TRIGGER retain_evidence_relations_identity_update BEFORE UPDATE ON "evidence_relations"
            WHEN OLD.relation_id IS NOT NEW.relation_id
            BEGIN SELECT RAISE(ABORT, 'Retain relation identity'); END;

CREATE TRIGGER retain_intake_packet_links_identity BEFORE DELETE ON "intake_packet_links"
            BEGIN SELECT RAISE(ABORT, 'Disable relations instead of deleting identity'); END;

CREATE TRIGGER retain_intake_packet_links_identity_update BEFORE UPDATE ON "intake_packet_links"
            WHEN OLD.link_id IS NOT NEW.link_id
            BEGIN SELECT RAISE(ABORT, 'Retain relation identity'); END;

CREATE TRIGGER retain_issue_question_evidence_links_identity BEFORE DELETE ON "issue_question_evidence_links"
            BEGIN SELECT RAISE(ABORT, 'Disable relations instead of deleting identity'); END;

CREATE TRIGGER retain_issue_question_evidence_links_identity_update BEFORE UPDATE ON "issue_question_evidence_links"
            WHEN OLD.relation_id IS NOT NEW.relation_id
            BEGIN SELECT RAISE(ABORT, 'Retain relation identity'); END;

CREATE TRIGGER retain_record_material_relations_identity BEFORE DELETE ON "record_material_relations"
            BEGIN SELECT RAISE(ABORT, 'Disable relations instead of deleting identity'); END;

CREATE TRIGGER retain_record_material_relations_identity_update BEFORE UPDATE ON "record_material_relations"
            WHEN OLD.relation_id IS NOT NEW.relation_id
            BEGIN SELECT RAISE(ABORT, 'Retain relation identity'); END;

CREATE TRIGGER retain_relations_identity BEFORE DELETE ON "relations"
            BEGIN SELECT RAISE(ABORT, 'Disable relations instead of deleting identity'); END;

CREATE TRIGGER retain_relations_identity_update BEFORE UPDATE ON "relations"
            WHEN OLD.relation_id IS NOT NEW.relation_id
            BEGIN SELECT RAISE(ABORT, 'Retain relation identity'); END;

CREATE TRIGGER validate_context_relation_insert
            BEFORE INSERT ON context_relations BEGIN
            SELECT CASE WHEN
                json_type(NEW.source_key) <> 'array' OR json_array_length(NEW.source_key) <> 2
                OR json_type(NEW.source_key,'$[0]') <> 'text' OR json_type(NEW.source_key,'$[1]') <> 'text'
                OR NEW.source_key <> json_array(json_extract(NEW.source_key,'$[0]'),json_extract(NEW.source_key,'$[1]'))
                OR NOT ((json_extract(NEW.source_key,'$[0]')='conclusion_version' AND EXISTS(SELECT 1 FROM conclusion_revisions WHERE conclusion_id=json_extract(NEW.source_key,'$[1]'))) OR (json_extract(NEW.source_key,'$[0]')='record_version' AND EXISTS(SELECT 1 FROM record_revisions WHERE record_revision_id=json_extract(NEW.source_key,'$[1]'))) OR (json_extract(NEW.source_key,'$[0]')='relation_version' AND EXISTS(SELECT 1 FROM managed_relation_versions WHERE version_id=json_extract(NEW.source_key,'$[1]'))))
                THEN RAISE(ABORT, 'Invalid typed material endpoint') END;SELECT CASE WHEN
                json_type(NEW.target_key) <> 'array' OR json_array_length(NEW.target_key) <> 2
                OR json_type(NEW.target_key,'$[0]') <> 'text' OR json_type(NEW.target_key,'$[1]') <> 'text'
                OR NEW.target_key <> json_array(json_extract(NEW.target_key,'$[0]'),json_extract(NEW.target_key,'$[1]'))
                OR NOT ((json_extract(NEW.target_key,'$[0]')='conclusion_version' AND EXISTS(SELECT 1 FROM conclusion_revisions WHERE conclusion_id=json_extract(NEW.target_key,'$[1]'))) OR (json_extract(NEW.target_key,'$[0]')='record_version' AND EXISTS(SELECT 1 FROM record_revisions WHERE record_revision_id=json_extract(NEW.target_key,'$[1]'))) OR (json_extract(NEW.target_key,'$[0]')='relation_version' AND EXISTS(SELECT 1 FROM managed_relation_versions WHERE version_id=json_extract(NEW.target_key,'$[1]'))))
                THEN RAISE(ABORT, 'Invalid typed material endpoint') END;
            SELECT CASE WHEN NEW.require_currentness=1 AND json_extract(NEW.source_key,'$[0]') <> 'conclusion_version'
                THEN RAISE(ABORT, 'Currentness requires a source conclusion') END;
            END;

CREATE TRIGGER validate_context_relation_update
            BEFORE UPDATE ON context_relations BEGIN
            SELECT CASE WHEN
                json_type(NEW.source_key) <> 'array' OR json_array_length(NEW.source_key) <> 2
                OR json_type(NEW.source_key,'$[0]') <> 'text' OR json_type(NEW.source_key,'$[1]') <> 'text'
                OR NEW.source_key <> json_array(json_extract(NEW.source_key,'$[0]'),json_extract(NEW.source_key,'$[1]'))
                OR NOT ((json_extract(NEW.source_key,'$[0]')='conclusion_version' AND EXISTS(SELECT 1 FROM conclusion_revisions WHERE conclusion_id=json_extract(NEW.source_key,'$[1]'))) OR (json_extract(NEW.source_key,'$[0]')='record_version' AND EXISTS(SELECT 1 FROM record_revisions WHERE record_revision_id=json_extract(NEW.source_key,'$[1]'))) OR (json_extract(NEW.source_key,'$[0]')='relation_version' AND EXISTS(SELECT 1 FROM managed_relation_versions WHERE version_id=json_extract(NEW.source_key,'$[1]'))))
                THEN RAISE(ABORT, 'Invalid typed material endpoint') END;SELECT CASE WHEN
                json_type(NEW.target_key) <> 'array' OR json_array_length(NEW.target_key) <> 2
                OR json_type(NEW.target_key,'$[0]') <> 'text' OR json_type(NEW.target_key,'$[1]') <> 'text'
                OR NEW.target_key <> json_array(json_extract(NEW.target_key,'$[0]'),json_extract(NEW.target_key,'$[1]'))
                OR NOT ((json_extract(NEW.target_key,'$[0]')='conclusion_version' AND EXISTS(SELECT 1 FROM conclusion_revisions WHERE conclusion_id=json_extract(NEW.target_key,'$[1]'))) OR (json_extract(NEW.target_key,'$[0]')='record_version' AND EXISTS(SELECT 1 FROM record_revisions WHERE record_revision_id=json_extract(NEW.target_key,'$[1]'))) OR (json_extract(NEW.target_key,'$[0]')='relation_version' AND EXISTS(SELECT 1 FROM managed_relation_versions WHERE version_id=json_extract(NEW.target_key,'$[1]'))))
                THEN RAISE(ABORT, 'Invalid typed material endpoint') END;
            SELECT CASE WHEN NEW.require_currentness=1 AND json_extract(NEW.source_key,'$[0]') <> 'conclusion_version'
                THEN RAISE(ABORT, 'Currentness requires a source conclusion') END;
            END;

INSERT INTO context_input_clock(singleton,revision) VALUES (1,0);

INSERT INTO context_maintenance_checkpoint(singleton,event_id) VALUES (1,0);

INSERT INTO manager_metadata(singleton,active_generation,token_epoch,maintenance_mode,updated_at) VALUES (1,'active',1,0,CURRENT_TIMESTAMP);

INSERT INTO schema_identity(singleton,version,created_at) VALUES (1,10,CURRENT_TIMESTAMP);

-- This records provenance only; it does not attest the original or imply a
-- scoped dependency. A platform's access to its own child remains contingent
-- on its current access to the source.
CREATE TABLE direct_split_origins (
    child_evidence_id TEXT PRIMARY KEY REFERENCES evidence_refs(evidence_id),
    source_evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    split_id TEXT NOT NULL,
    part_index INTEGER NOT NULL CHECK(part_index >= 0),
    content_kind TEXT NOT NULL CHECK(content_kind IN ('observation','interpretation')),
    source_binding_json TEXT NOT NULL CHECK(json_valid(source_binding_json)),
    source_binding_token TEXT NOT NULL,
    actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    platform_id TEXT REFERENCES platform_sources(platform_id),
    created_at TEXT NOT NULL,
    UNIQUE(split_id, part_index),
    CHECK(child_evidence_id <> source_evidence_id)
);
CREATE INDEX idx_direct_split_origins_source ON direct_split_origins(source_evidence_id, child_evidence_id);
CREATE TRIGGER immutable_direct_split_origins_update BEFORE UPDATE ON direct_split_origins
BEGIN SELECT RAISE(ABORT, 'Split origins are immutable'); END;
CREATE TRIGGER immutable_direct_split_origins_delete BEFORE DELETE ON direct_split_origins
BEGIN SELECT RAISE(ABORT, 'Split origins are immutable'); END;



CREATE TABLE workflow_mandates (
    mandate_id TEXT PRIMARY KEY,
    goal TEXT NOT NULL,
    autonomy_mode TEXT NOT NULL
        CHECK (autonomy_mode IN ('advise_only','assigned_only','bounded_autonomy')),
    scope_json TEXT NOT NULL,
    permissions_json TEXT NOT NULL,
    budget_json TEXT NOT NULL,
    stop_conditions_json TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('draft','active','paused','taken_over','blocked','completed','cancelled')),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    fence INTEGER NOT NULL CHECK (fence >= 1),
    activation_epoch INTEGER NOT NULL CHECK (activation_epoch >= 0),
    work_items_created INTEGER NOT NULL DEFAULT 0 CHECK (work_items_created >= 0),
    attempts_started INTEGER NOT NULL DEFAULT 0 CHECK (attempts_started >= 0),
    commits_used INTEGER NOT NULL DEFAULT 0 CHECK (commits_used >= 0),
    runtime_seconds_used INTEGER NOT NULL DEFAULT 0 CHECK (runtime_seconds_used >= 0),
    context_bytes_used INTEGER NOT NULL DEFAULT 0 CHECK (context_bytes_used >= 0),
    stop_reason TEXT,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);

CREATE INDEX idx_workflow_mandates_status
ON workflow_mandates(status, updated_at, mandate_id);

CREATE TABLE workflow_mandate_revisions (
    revision_id TEXT PRIMARY KEY,
    mandate_id TEXT NOT NULL REFERENCES workflow_mandates(mandate_id),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    event_type TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(mandate_id, revision)
);

CREATE TABLE workflow_work_items (
    work_item_id TEXT PRIMARY KEY,
    mandate_id TEXT NOT NULL REFERENCES workflow_mandates(mandate_id),
    dedupe_key TEXT NOT NULL,
    issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    role TEXT NOT NULL CHECK (role IN (
        'material_curator','local_researcher','conclusion_maintainer','scope_planner','reviewer'
    )),
    objective TEXT NOT NULL,
    acceptance_json TEXT NOT NULL,
    allowed_actions_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'proposed','ready','running','checkpointed','human_owned','completed','blocked','cancelled'
    )),
    acceptance_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (acceptance_status IN ('pending','passed','failed','waived')),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    proposed_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    stop_reason TEXT,
    UNIQUE(mandate_id, dedupe_key)
);

CREATE INDEX idx_workflow_items_dispatch
ON workflow_work_items(mandate_id, status, created_at, work_item_id);

CREATE TABLE workflow_attempts (
    attempt_id TEXT PRIMARY KEY,
    work_item_id TEXT NOT NULL REFERENCES workflow_work_items(work_item_id),
    mandate_id TEXT NOT NULL REFERENCES workflow_mandates(mandate_id),
    attempt_number INTEGER NOT NULL CHECK (attempt_number >= 1),
    status TEXT NOT NULL CHECK (status IN (
        'claimed','running','submitted','succeeded','rejected','failed','invalidated','expired'
    )),
    actor_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    mandate_revision INTEGER NOT NULL,
    mandate_fence INTEGER NOT NULL,
    work_item_revision INTEGER NOT NULL,
    issue_working_revision INTEGER NOT NULL,
    lease_until TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    runtime_seconds_used INTEGER NOT NULL DEFAULT 0 CHECK (runtime_seconds_used >= 0),
    context_bytes_used INTEGER NOT NULL DEFAULT 0 CHECK (context_bytes_used >= 0),
    rejection_code TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    UNIQUE(work_item_id, attempt_number)
);

CREATE UNIQUE INDEX idx_workflow_attempt_active_slot
ON workflow_attempts(work_item_id)
WHERE status IN ('claimed','running','submitted');

CREATE INDEX idx_workflow_attempt_holder
ON workflow_attempts(actor_id, run_id, status, lease_until);

CREATE TABLE workflow_work_packages (
    package_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL UNIQUE REFERENCES workflow_attempts(attempt_id),
    package_json TEXT NOT NULL,
    package_hash TEXT NOT NULL,
    byte_count INTEGER NOT NULL CHECK (byte_count >= 0),
    created_at TEXT NOT NULL
);

CREATE TABLE workflow_outputs (
    output_id TEXT PRIMARY KEY,
    mandate_id TEXT NOT NULL REFERENCES workflow_mandates(mandate_id),
    work_item_id TEXT NOT NULL REFERENCES workflow_work_items(work_item_id),
    attempt_id TEXT REFERENCES workflow_attempts(attempt_id),
    author_actor_id TEXT NOT NULL,
    author_run_id TEXT NOT NULL,
    contribution_kind TEXT NOT NULL CHECK (contribution_kind IN ('draft','partial','final','review')),
    body TEXT NOT NULL,
    business_action TEXT,
    business_object_type TEXT,
    business_object_id TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_workflow_outputs_item
ON workflow_outputs(work_item_id, created_at, output_id);

CREATE TABLE workflow_events (
    event_id TEXT PRIMARY KEY,
    mandate_id TEXT NOT NULL REFERENCES workflow_mandates(mandate_id),
    work_item_id TEXT REFERENCES workflow_work_items(work_item_id),
    attempt_id TEXT REFERENCES workflow_attempts(attempt_id),
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    before_state TEXT,
    after_state TEXT,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_workflow_events_mandate
ON workflow_events(mandate_id, created_at, event_id);

CREATE TRIGGER immutable_workflow_mandate_revisions_update BEFORE UPDATE ON workflow_mandate_revisions
BEGIN SELECT RAISE(ABORT, 'Immutable workflow history'); END;

CREATE TRIGGER immutable_workflow_mandate_revisions_delete BEFORE DELETE ON workflow_mandate_revisions
BEGIN SELECT RAISE(ABORT, 'Immutable workflow history'); END;

CREATE TRIGGER immutable_workflow_work_packages_update BEFORE UPDATE ON workflow_work_packages
BEGIN SELECT RAISE(ABORT, 'Immutable workflow history'); END;

CREATE TRIGGER immutable_workflow_work_packages_delete BEFORE DELETE ON workflow_work_packages
BEGIN SELECT RAISE(ABORT, 'Immutable workflow history'); END;

CREATE TRIGGER immutable_workflow_outputs_update BEFORE UPDATE ON workflow_outputs
BEGIN SELECT RAISE(ABORT, 'Immutable workflow history'); END;

CREATE TRIGGER immutable_workflow_outputs_delete BEFORE DELETE ON workflow_outputs
BEGIN SELECT RAISE(ABORT, 'Immutable workflow history'); END;

CREATE TRIGGER immutable_workflow_events_update BEFORE UPDATE ON workflow_events
BEGIN SELECT RAISE(ABORT, 'Immutable workflow history'); END;

CREATE TRIGGER immutable_workflow_events_delete BEFORE DELETE ON workflow_events
BEGIN SELECT RAISE(ABORT, 'Immutable workflow history'); END;


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

-- Field inbox is a receipt and identity layer. It does not create Evidence or
-- scoped relations; those remain explicit later domain actions.
CREATE TABLE field_packets (
    packet_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    content TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    request_payload_sha256 TEXT NOT NULL,
    sources_json TEXT NOT NULL,
    attachment_refs_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id)
);
CREATE INDEX idx_field_packets_issue_created
ON field_packets(issue_id, created_at DESC, packet_id DESC);

CREATE TABLE field_facts (
    fact_ref TEXT PRIMARY KEY,
    packet_id TEXT NOT NULL REFERENCES field_packets(packet_id),
    issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    description TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('observation','interpretation')),
    origin_json TEXT NOT NULL,
    source_locator TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    UNIQUE(fact_ref, issue_id)
);
CREATE INDEX idx_field_facts_packet ON field_facts(packet_id, fact_ref);

CREATE TABLE field_packet_curation_heads (
    packet_id TEXT PRIMARY KEY REFERENCES field_packets(packet_id),
    version INTEGER NOT NULL CHECK(version >= 0),
    updated_at TEXT NOT NULL
);
CREATE TABLE field_packet_reviews (
    review_id TEXT PRIMARY KEY,
    packet_id TEXT NOT NULL REFERENCES field_packets(packet_id),
    version INTEGER NOT NULL CHECK(version >= 1),
    handled_fact_refs_json TEXT NOT NULL,
    unresolved_json TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    request_id TEXT NOT NULL UNIQUE,
    UNIQUE(packet_id, version)
);
CREATE TRIGGER validate_field_packet_curation_head_update
BEFORE UPDATE ON field_packet_curation_heads BEGIN
    SELECT CASE WHEN NEW.packet_id <> OLD.packet_id OR NEW.version <> OLD.version + 1
        THEN RAISE(ABORT, 'Field packet curation head must advance by one') END;
END;
CREATE TRIGGER retain_field_packet_curation_head
BEFORE DELETE ON field_packet_curation_heads BEGIN
    SELECT RAISE(ABORT, 'Retain field packet curation head');
END;
CREATE TRIGGER immutable_field_packet_review_update
BEFORE UPDATE ON field_packet_reviews BEGIN
    SELECT RAISE(ABORT, 'Field packet review is immutable');
END;
CREATE TRIGGER retain_field_packet_review_delete
BEFORE DELETE ON field_packet_reviews BEGIN
    SELECT RAISE(ABORT, 'Retain field packet review history');
END;

-- Append-only mapping history and a separate current head make future
-- corrections explicit without rewriting prior receipts.
CREATE TABLE field_fact_mapping_versions (
    mapping_id TEXT PRIMARY KEY,
    fact_ref TEXT NOT NULL REFERENCES field_facts(fact_ref),
    version INTEGER NOT NULL CHECK(version >= 1),
    evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    request_id TEXT NOT NULL UNIQUE,
    UNIQUE(fact_ref, version),
    UNIQUE(evidence_id)
);
CREATE TABLE field_fact_mapping_heads (
    fact_ref TEXT PRIMARY KEY REFERENCES field_facts(fact_ref),
    mapping_id TEXT NOT NULL UNIQUE REFERENCES field_fact_mapping_versions(mapping_id),
    version INTEGER NOT NULL CHECK(version >= 1),
    updated_at TEXT NOT NULL,
    FOREIGN KEY(fact_ref, version)
        REFERENCES field_fact_mapping_versions(fact_ref, version)
);
CREATE TRIGGER validate_field_fact_mapping_head_insert
BEFORE INSERT ON field_fact_mapping_heads BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM field_fact_mapping_versions v
        WHERE v.mapping_id=NEW.mapping_id
          AND v.fact_ref=NEW.fact_ref
          AND v.version=NEW.version
    ) THEN RAISE(ABORT, 'Field mapping head must match its mapping version') END;
END;
CREATE TRIGGER validate_field_fact_mapping_head_update
BEFORE UPDATE ON field_fact_mapping_heads BEGIN
    SELECT CASE WHEN NEW.fact_ref <> OLD.fact_ref
        THEN RAISE(ABORT, 'Field mapping head fact_ref is stable') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM field_fact_mapping_versions v
        WHERE v.mapping_id=NEW.mapping_id
          AND v.fact_ref=NEW.fact_ref
          AND v.version=NEW.version
    ) THEN RAISE(ABORT, 'Field mapping head must match its mapping version') END;
END;
CREATE TRIGGER retain_field_fact_mapping_head
BEFORE DELETE ON field_fact_mapping_heads BEGIN
    SELECT RAISE(ABORT, 'Retain field fact mapping history');
END;

CREATE TRIGGER immutable_field_packet_update
BEFORE UPDATE ON field_packets BEGIN
    SELECT RAISE(ABORT, 'Field packet receipt is immutable');
END;
CREATE TRIGGER retain_field_packet_delete
BEFORE DELETE ON field_packets BEGIN
    SELECT RAISE(ABORT, 'Retain field packet receipt history');
END;
CREATE TRIGGER immutable_field_fact_update
BEFORE UPDATE ON field_facts BEGIN
    SELECT RAISE(ABORT, 'Field fact identity is immutable');
END;
CREATE TRIGGER retain_field_fact_delete
BEFORE DELETE ON field_facts BEGIN
    SELECT RAISE(ABORT, 'Retain field fact identity history');
END;
CREATE TRIGGER immutable_field_mapping_version_update
BEFORE UPDATE ON field_fact_mapping_versions BEGIN
    SELECT RAISE(ABORT, 'Field fact mapping version is immutable');
END;
CREATE TRIGGER retain_field_mapping_version_delete
BEFORE DELETE ON field_fact_mapping_versions BEGIN
    SELECT RAISE(ABORT, 'Retain field fact mapping history');
END;


CREATE TABLE scoped_evidence_relation_versions (
    version_id TEXT PRIMARY KEY,
    relation_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision >= 1),
    previous_version_id TEXT,
    contract_id TEXT NOT NULL CHECK(contract_id = 'scoped-evidence-relation/v1'),
    scope_issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    source_evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    target_evidence_id TEXT NOT NULL REFERENCES evidence_refs(evidence_id),
    relation_type TEXT NOT NULL CHECK(relation_type IN
        ('depends_on','derived_from','reproduces','supports','challenges','amends',
         'duplicates','context_for','refutes')),
    impact_policy TEXT NOT NULL CHECK(impact_policy IN ('hard','soft','informational')),
    source_binding_json TEXT NOT NULL,
    target_binding_json TEXT NOT NULL,
    source_binding_token TEXT NOT NULL,
    target_binding_token TEXT NOT NULL,
    active INTEGER NOT NULL CHECK(active IN (0,1)),
    rationale TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    run_id TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(relation_id, revision),
    UNIQUE(relation_id, version_id),
    FOREIGN KEY(relation_id, previous_version_id)
        REFERENCES scoped_evidence_relation_versions(relation_id, version_id),
    CHECK((revision = 1 AND previous_version_id IS NULL) OR
          (revision > 1 AND previous_version_id IS NOT NULL))
);
CREATE INDEX idx_scoped_relation_versions_scope
    ON scoped_evidence_relation_versions(scope_issue_id, relation_id, revision);
CREATE INDEX idx_scoped_relation_versions_source
    ON scoped_evidence_relation_versions(source_evidence_id, relation_type, relation_id, revision);
CREATE INDEX idx_scoped_relation_versions_target
    ON scoped_evidence_relation_versions(target_evidence_id, relation_type, relation_id, revision);
CREATE INDEX idx_scoped_relation_versions_relation
    ON scoped_evidence_relation_versions(relation_id, revision);

CREATE TABLE scoped_evidence_relation_heads (
    relation_id TEXT PRIMARY KEY,
    current_version_id TEXT NOT NULL,
    FOREIGN KEY(relation_id, current_version_id)
        REFERENCES scoped_evidence_relation_versions(relation_id, version_id)
);

CREATE TRIGGER scoped_relation_versions_immutable_update
BEFORE UPDATE ON scoped_evidence_relation_versions
BEGIN
    SELECT RAISE(ABORT, 'scoped relation versions are immutable');
END;

CREATE TRIGGER scoped_relation_versions_immutable_delete
BEFORE DELETE ON scoped_evidence_relation_versions
BEGIN
    SELECT RAISE(ABORT, 'scoped relation versions are immutable');
END;

CREATE TRIGGER scoped_relation_version_chain_guard
BEFORE INSERT ON scoped_evidence_relation_versions
BEGIN
    SELECT CASE
        WHEN NEW.revision = 1 AND NEW.previous_version_id IS NOT NULL
            THEN RAISE(ABORT, 'initial scoped relation version cannot have a predecessor')
        WHEN NEW.revision > 1 AND NEW.previous_version_id IS NULL
            THEN RAISE(ABORT, 'successor scoped relation version requires a predecessor')
        WHEN NEW.revision > 1 AND NOT EXISTS (
            SELECT 1 FROM scoped_evidence_relation_versions p
            WHERE p.relation_id = NEW.relation_id
              AND p.version_id = NEW.previous_version_id
              AND p.revision = NEW.revision - 1
              AND p.scope_issue_id = NEW.scope_issue_id
              AND p.source_evidence_id = NEW.source_evidence_id
              AND p.target_evidence_id = NEW.target_evidence_id
              AND p.relation_type = NEW.relation_type
        ) THEN RAISE(ABORT, 'scoped relation version chain is not a legal successor')
    END;
END;

CREATE TRIGGER scoped_relation_heads_insert_guard
BEFORE INSERT ON scoped_evidence_relation_heads
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM scoped_evidence_relation_versions v
        WHERE v.relation_id = NEW.relation_id AND v.version_id = NEW.current_version_id
          AND v.revision = 1
    ) THEN RAISE(ABORT, 'scoped relation head must start at revision one') END;
END;

CREATE TRIGGER scoped_relation_heads_update_guard
BEFORE UPDATE OF current_version_id ON scoped_evidence_relation_heads
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM scoped_evidence_relation_versions v
        JOIN scoped_evidence_relation_versions old
          ON old.relation_id = OLD.relation_id AND old.version_id = OLD.current_version_id
        WHERE v.relation_id = NEW.relation_id AND v.version_id = NEW.current_version_id
          AND v.revision = old.revision + 1
          AND v.previous_version_id = old.version_id
    ) THEN RAISE(ABORT, 'scoped relation head must advance to the immediate successor') END;
END;


CREATE TABLE context_package_views (
    view_id TEXT PRIMARY KEY,
    package_id TEXT NOT NULL REFERENCES context_input_packages(package_id),
    issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    rule_id TEXT NOT NULL REFERENCES context_rule_versions(rule_id),
    presentation_rule_id TEXT NOT NULL,
    budget_bytes INTEGER NOT NULL CHECK(budget_bytes > 0 AND budget_bytes <= 131072),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_context_package_views_identity
ON context_package_views(package_id,presentation_rule_id,budget_bytes,created_by);
CREATE INDEX idx_context_package_views_package ON context_package_views(package_id);

CREATE TRIGGER context_scoped_relation_head_insert_journal
AFTER INSERT ON scoped_evidence_relation_heads
BEGIN
    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
    SELECT cic.revision,'scoped_evidence_relation_heads',json_array(NEW.relation_id),'{}',
           json_object('relation_id',NEW.relation_id,'current_version_id',NEW.current_version_id,
                       'scope_issue_id',v.scope_issue_id,'source_evidence_id',v.source_evidence_id,
                       'target_evidence_id',v.target_evidence_id)
    FROM context_input_clock cic,scoped_evidence_relation_versions v
    WHERE v.relation_id=NEW.relation_id AND v.version_id=NEW.current_version_id;
END;
CREATE TRIGGER context_scoped_relation_head_update_journal
AFTER UPDATE OF current_version_id ON scoped_evidence_relation_heads
BEGIN
    UPDATE context_input_clock SET revision=revision+1 WHERE singleton=1;
    INSERT INTO context_input_events(revision,object_kind,object_id,before_json,after_json)
    SELECT cic.revision,'scoped_evidence_relation_heads',json_array(NEW.relation_id),
           json_object('relation_id',OLD.relation_id,'current_version_id',OLD.current_version_id),
           json_object('relation_id',NEW.relation_id,'current_version_id',NEW.current_version_id,
                       'scope_issue_id',v.scope_issue_id,'source_evidence_id',v.source_evidence_id,
                       'target_evidence_id',v.target_evidence_id)
    FROM context_input_clock cic,scoped_evidence_relation_versions v
    WHERE v.relation_id=NEW.relation_id AND v.version_id=NEW.current_version_id;
END;

-- End of authoritative fresh-only schema.


-- Project instructions are not evidence or context inputs. No scientific invalidation triggers.
CREATE TABLE project_original_access_versions (
    root_issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    contract_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    document_json TEXT NOT NULL CHECK(json_valid(document_json)),
    actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(root_issue_id, contract_id, revision)
);
CREATE TABLE project_original_access_heads (
    root_issue_id TEXT NOT NULL,
    contract_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    PRIMARY KEY(root_issue_id, contract_id),
    FOREIGN KEY(root_issue_id, contract_id, revision)
        REFERENCES project_original_access_versions(root_issue_id, contract_id, revision)
);
CREATE TRIGGER project_original_access_versions_no_update
BEFORE UPDATE ON project_original_access_versions BEGIN
    SELECT RAISE(ABORT, 'original-access history is immutable');
END;
CREATE TRIGGER project_original_access_versions_no_delete
BEFORE DELETE ON project_original_access_versions BEGIN
    SELECT RAISE(ABORT, 'original-access history is immutable');
END;


CREATE TABLE project_original_access_bindings (
    binding_id TEXT PRIMARY KEY,
    root_issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    evidence_id TEXT REFERENCES evidence_refs(evidence_id),
    packet_id TEXT REFERENCES field_packets(packet_id),
    reference TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('bound','missing','ambiguous','internal','legacy_unbound','catalog_too_large')),
    contract_id TEXT,
    revision INTEGER,
    inherited_from TEXT REFERENCES project_original_access_bindings(binding_id),
    candidates_json TEXT NOT NULL CHECK(json_valid(candidates_json)),
    candidate_count INTEGER NOT NULL CHECK(candidate_count>=0),
    created_at TEXT NOT NULL,
    CHECK((evidence_id IS NULL) != (packet_id IS NULL)),
    CHECK((status='bound' AND contract_id IS NOT NULL AND revision IS NOT NULL)
        OR (status!='bound' AND contract_id IS NULL AND revision IS NULL)),
    UNIQUE(root_issue_id,evidence_id,reference),
    UNIQUE(packet_id,reference),
    FOREIGN KEY(root_issue_id,contract_id,revision)
        REFERENCES project_original_access_versions(root_issue_id,contract_id,revision)
);
CREATE INDEX original_access_packet ON project_original_access_bindings(packet_id);
CREATE TRIGGER original_access_bindings_no_update
BEFORE UPDATE ON project_original_access_bindings BEGIN
    SELECT RAISE(ABORT, 'original-access binding is immutable');
END;
CREATE TRIGGER original_access_bindings_no_delete
BEFORE DELETE ON project_original_access_bindings BEGIN
    SELECT RAISE(ABORT, 'original-access binding is immutable');
END;

-- Facts are emitted by the same SQLite transaction as their domain row. No role,
-- request queue, consumer cursor, model binding or scheduling decision belongs here.
CREATE TABLE domain_event_stream (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    stream_id TEXT NOT NULL UNIQUE
);
INSERT INTO domain_event_stream VALUES(1,lower(hex(randomblob(16))));
CREATE TABLE domain_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    object_version INTEGER NOT NULL CHECK(object_version>=1),
    occurred_at TEXT NOT NULL,
    UNIQUE(event_type,object_type,object_id,object_version)
);
CREATE INDEX domain_events_issue_sequence ON domain_events(issue_id,sequence);
CREATE TRIGGER domain_events_no_update BEFORE UPDATE ON domain_events
BEGIN SELECT RAISE(ABORT,'domain events are append-only'); END;
CREATE TRIGGER domain_events_no_delete BEFORE DELETE ON domain_events
BEGIN SELECT RAISE(ABORT,'domain events are append-only'); END;
CREATE TRIGGER domain_event_packet AFTER INSERT ON field_packets
BEGIN
    INSERT INTO domain_events(event_id,event_type,issue_id,object_type,object_id,object_version,occurred_at)
    VALUES('evt_'||lower(hex(randomblob(16))),'packet.received',NEW.issue_id,'field_packet',NEW.packet_id,1,NEW.created_at);
END;
CREATE TRIGGER domain_event_fact AFTER INSERT ON field_facts
BEGIN
    INSERT INTO domain_events(event_id,event_type,issue_id,object_type,object_id,object_version,occurred_at)
    VALUES('evt_'||lower(hex(randomblob(16))),'packet.curated',NEW.issue_id,'field_fact',NEW.fact_ref,1,NEW.created_at);
END;
CREATE TRIGGER domain_event_review AFTER INSERT ON field_packet_reviews
BEGIN
    INSERT INTO domain_events(event_id,event_type,issue_id,object_type,object_id,object_version,occurred_at)
    VALUES('evt_'||lower(hex(randomblob(16))),'packet.reviewed',(SELECT issue_id FROM field_packets WHERE packet_id=NEW.packet_id),'field_review',NEW.review_id,NEW.version,NEW.created_at);
END;
CREATE TRIGGER domain_event_conclusion AFTER INSERT ON conclusion_revisions
BEGIN
    INSERT INTO domain_events(event_id,event_type,issue_id,object_type,object_id,object_version,occurred_at)
    VALUES('evt_'||lower(hex(randomblob(16))),'conclusion.recorded',NEW.issue_id,'conclusion',NEW.conclusion_id,NEW.revision_number,NEW.created_at);
END;
