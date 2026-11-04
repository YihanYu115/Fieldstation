# Field Inbox HTTP contract

[English documentation](README.md) · [Chinese original](../FIELD_INBOX_API_CONTRACT.md)

This page describes Field Inbox's HTTP endpoints, original records, curation, and source bindings.

Field Inbox stores immutable field packets, curator-created `fact_ref` values, initial mappings, explicit scoped relations, and append-only review handoffs. Intake creates no Evidence, relations, or currentness changes. The kernel owns authoritative state; orchestration uses only public HTTP.

## Identity and write requests

All writes use `Authorization: Bearer ...`, a host-stable `X-Request-ID`, and `Idempotency-Key`. Replaying the same identity and body returns the original domain receipt marked `idempotent_replay: true`; a different body conflicts. On failure, domain writes roll back together. The Manager's general API request ledger still enforces outer request-ID and idempotency-key constraints.

## Intake of original field text

`POST /v1/field-packets` requires `intake.submit`. The host injects the Issue ID; the field tool requires only `content`. Sources and attachment declarations may be omitted.

```json
{
  "issue_id": "ISSUE-42",
  "content": "Curve A shows a plateau. Parameters used produced load calculation B=2.50 s. I suspect the input load affects judgment H, but can only raise a question for now.",
  "sources": [{"locator": "run://P1/curve-A", "provided_text": "Curve A shows a plateau."}],
  "attachment_refs": ["sha256:declared-reference"]
}
```

`content` is 1–80,000 characters; the full normalized request is at most 200,000 UTF-8 bytes. There can be at most 16 `sources`, each with a nonempty `locator` and `provided_text`, and at most 128 attachment references. Unknown fields, including v3 `facts`, `references`, and `kind`, are rejected. Attachment strings are stored as declarations, not validated content.

`content` is the submitter's own record for this session and may include observations, judgments, clarifications, and open questions; it need not reproduce the host's input verbatim. `sources[].provided_text` preserves externally sourced text as declared by the submitter; packet reads return `created_by` to distinguish the submitter's text from declared sources. Neither automatically constitutes a verified fact. The curator decides which items can be independently entered based on source anchors and content boundaries; procedural notes can remain in the packet without being promoted to Evidence.

The receipt is only:

```json
{"status":"received","packet_id":"fp_…","content_sha256":"…","idempotent_replay":false}
```

Packet text, sources, and attachments are immutable. Empty sources do not mean the source has been verified. Intake does not generate a fact_ref, Evidence, mapping, or relation.

## Lossless contract for attachment references

`attachment_refs[]` and an attachment origin's `attachment_ref` are the original strings declared by the project, not all whitespace, at most 2048 Unicode code points, and encodable as UTF-8. Registration and contribution use the same locator control-character rules: reject NUL and Cc characters other than tab. Preserve leading/trailing and repeated spaces, case, combining characters, non-BMP characters, backslashes, percent encoding, query, and fragment; do not trim, fold, normalize Unicode, decode URLs, or resolve paths. New registrations reject invalid control characters that previously might have been received but could not be entered as a source; old packets are not migrated.

Windows/UNC/POSIX/project-relative paths, file/HTTP(S)/object-storage URIs, project-specific identifiers, content/version identifiers, and archive-member references are supported; there is no scheme allowlist. References in contributions and reviews must equal registered packet values character for character. Different slashes, Unicode forms, or queries are different declarations and cannot be fuzzily matched.

```json
{"type":"attachment","attachment_ref":"project-record:run-17/raw-data","part_locator":"CSV rows 2-3","quoted_text":"Optional verbatim declared excerpt\\r\\n"}
```

`part_locator` must not be all whitespace, is at most 2048 code points, and uses the same UTF-8/locator control-character validation. If supplied, optional `quoted_text` must not be all whitespace, is at most 4000 code points, preserves Unicode/CRLF, and is checked for UTF-8 encoding. The contribution's source_locator and Evidence's declared_source_locator save the exact attachment reference; the Evidence internal locator remains an independent domain identity. Two parts of the same address may create distinct fact/Evidence items.

`local_position_verified` is emitted only by the server when reading an attachment source, with value `false`; supplying true, false, 0, or null in a public write is rejected as an unknown field. The API uses a normalized in-process kernel type for handoff, and the transaction rechecks every anchor against the authoritative packet; ordinary JSON cannot manufacture that type. Inferred starts for body/source_text and old idempotent payloads retain their original format; no schema upgrade is needed.

IM does not open files, shares, archives, or URLs, or check original existence, access, hashes, or quote authenticity. The project/host provides original access; successful access and source admission are validated separately. An inaccessible registered attachment can still retain declarations and review gaps; admission is not upload or scientific verification. Intake remains subject to the 200,000 normalized UTF-8-byte and 128 attachment-reference budgets.

Attachment-field rejection includes `details.origin_contract=field-origin/v1` and bounded `fields[].path/rule`, without echoing addresses, queries, content, credentials, or stacks. MCP forwards only recognized bounded paths/rules (at most eight), preserving code/layer/operation/effect/phase/delivery_id. 401/403 require host handling; 408/425/429/5xx and lost responses remain unknown and are recovered under the original identity. A confirmed rejected journal remains rejected; corrections use a new intent.

## Atomically curating one item

`POST /v1/field-packets/{packet_id}/curated-items` requires `evidence.write`; formal relations also require `evidence.relation.write`. A curator submits:

```json
{
  "issue_id":"ISSUE-42",
  "expected_curation_version":0,
  "description":"Curve A showed a plateau in this measurement",
  "kind":"observation",
  "origin":{"type":"packet_text","quoted_text":"Curve A shows a plateau."},
  "reason":"Extract an independently checkable observation from the field text",
  "related_evidence":[]
}
```

`kind` permits only `observation` and `interpretation`, describing content form rather than truth or confidence. `description` should retain field qualifications and uncertainty. `related_evidence` has at most eight items, each explicitly declaring a readable target, relation type, and reason. Targets may be Evidence IDs or a `fact_ref` with an existing mapping; registration in the same Issue as the packet is not required. The relation's `scope_issue_id` is the declaration/management location of the new contribution; it does not change eligibility graph selection within the same ledger. The program does not infer relations from text.

Three bounded origin-anchor shapes are supported:

- `packet_text`: `quoted_text` must be a nonempty contiguous substring of the packet; a Unicode-code-point `start` may be supplied, otherwise only a unique match is accepted.
- `source_text`: additionally provide this packet's `source_index`; the quote must exactly match its `provided_text`. A code-point `start` may be supplied, otherwise only a unique match is accepted.
- `attachment`: `attachment_ref` must belong to this packet and `part_locator` must be nonempty and bounded. It proves only attachment membership; the local position is the curator's declaration, not machine-verified.

One transaction creates the immutable fact, Evidence, initial `fact_ref→Evidence` mapping, explicit scoped relations, audit, and incremented packet curation version. Any failure rolls back all of them. The receipt includes `fact_ref`, Evidence ID, mapping ID, relation IDs, source anchor/locator, `curation_version`, and `atomic:true`. The host assembles `expected_curation_version` from the latest read; after a CAS conflict reread and decide again.

## Review handoff

`POST /v1/field-packets/{packet_id}/reviews` requires `evidence.write`. `handled_fact_refs` must belong to that packet; `unresolved` stores validated original-text/source/attachment anchors and gap reasons. Each array has at most 100 entries; text is bounded. An empty gap list is permitted but does not prove the original has no omissions. A review receipt contains author, time, and version in append-only immutable history; it advances only the packet curation head and does not write Evidence, relationships, or currentness.

## Reads, pagination, and permissions

All reads require `context.read`:

- `GET /v1/field-packets?issue_id=…&limit=20&after_packet_id=…`: bounded listing.
- `GET /v1/field-packets/{packet_id}`: original text, declared sources and attachments, `curation_version`, curated count, and most recent review summary; no unbounded embedded item history.
- `GET /v1/field-packets/{packet_id}/curated-items?limit=20&after_fact_ref=…`: bounded item pagination.
- `GET /v1/field-packets/{packet_id}/reviews?limit=20&before_version=…`: bounded review history.
- `GET /v1/field-facts/{fact_ref}` and `/mappings?limit=20&before_version=…`: exact provenance and mapping history.
- `GET /v1/field-packets/{packet_id}/summary?review_id=…`: packet hash, source catalog, fact/current-mapping and kind counts, and curation version; optional immutable-review statistics are aggregated in the same read-only transaction. Counts distinguish all facts from current mappings and do not interpret natural-language reviews.
- `GET /v1/field-packets/{packet_id}/text?source_index=…&start=…&max_bytes=…&content_sha256=…`: one page of packet_text (omit source_index) or a registered source's `provided_text`. Default page budget is 8 KiB, range 256 B–16 KiB; start/next_cursor are Python Unicode code-point positions, and the content hash fixes the source's complete content.
- `GET /v1/field-packets/{packet_id}/locate?source_index=…&quoted_text=…&after_start=…&limit=…`: search the complete selected source by code-point position, allowing overlapping matches; at most eight candidates per page. Report unique only after all candidates are read and exactly one matches.
- `GET /v1/field-packets/{packet_id}/review?review_id=…&after_handled=…&after_unresolved=…&max_bytes=…&expected_curation_version=…`: paginate handled and unresolved collections of an immutable review by byte budget, each with its own cursor and count; reject continuation if the expected version changes.
- `GET /v1/field-packets/{packet_id}/facts/{fact_ref}`: find the fact only within the packet in the path; do not first fetch hidden content through a global fact ID.
- curated-items supports `max_bytes` 256 B–16 KiB; long descriptions return an explicitly incomplete summary and a `read_field_fact` reference.

## Reading current scoped relations for one source

`GET /v1/scoped-evidence-relations?scope_issue_id=…&source_evidence_id=…&limit=…&max_bytes=…&cursor=…&expected_snapshot=…` is a bounded single-source query of the general relation service. Scope and source are required; `limit` is 1–8 and `max_bytes` is 256–16384 UTF-8 bytes, with out-of-range values returning 400. `cursor` is an opaque server snapshot cursor; continuation may also supply `expected_snapshot`. Do not guess replacements for cursor, snapshot, source, or scope.

Responses are sorted by relation ID, reading each current head and including active and inactive records, without concatenating historical versions. Each item includes relation/version ID, revision, scope, source/target Evidence ID, relation type, complete rationale, active, source/target binding identity, and `binding_current`. Binding changes do not filter the record. The snapshot covers the current relation set, current versions, and both bindings; changes to any cause continuation conflict and require restarting from page one. A single-source scan is limited to 5000 records. If the response budget is insufficient, return a single-relation reference usable by bounded Field Inbox read-only tools; do not truncate rationale or mark incomplete results complete.

Reads require `context.read`, and the server checks source and target Evidence permissions individually; if any target is unreadable the entire page is rejected without leaking relation metadata. This API does not read target bodies, scan the relation graph, or change relations, bindings, or scoped-v2 eligibility. `binding_current` only means the stored endpoint identities still match current endpoint states.

`read_field_fact` attaches the first `relation_page` to the original fact/mapping response. `read_field_fact_relations(packet_id, fact_ref, ...)` continues using the current mapping of a host-visible packet and does not accept a user-specified scope or source Evidence. It first reads the current fact/mapping via packet-scoped HTTP, calls the general API above, then rereads the mapping; independent HTTP requests are not a cross-request transaction. The cursor binds packet, fact, mapping ID/version/Evidence ID, relation snapshot, and server cursor. Changes reject mixed pagination. `state=unmapped`, `state=unavailable`, and an empty successful relation set are distinct; failure never masquerades as an empty array. If the combined fact and first relation page exceed the existing 64 KiB MCP output limit, retain the fact and return a separate relation-read reference.

This read verifies management records; it does not mean an original was opened or verified, does not establish scientific conclusion validity, and does not change a historical write receipt's `current_state_verified=false` to true.

The field token has only `intake.submit`; the read token only reads; curator writes do not include intake permission. The server checks the Issue, packet, anchor, relation target, and permission individually. Orchestration curation sessions also enforce the host-bound list of visible packet IDs for list and detail calls.

## Structure and recovery

**Translation note:** the Chinese source calls the database “schema v8” here, whereas the public version identifies the current schema as 10. The sentence below preserves the source wording pending reconciliation.

The current database schema v8 is fresh-only; old ledgers are not migrated or dual-written. Independent `field_packet_curation_heads` manages CAS; packet rows are not updated by curation; reviews are append-only. `field_facts` creates origin, source locator, author, and time during curation; mapping versions/heads retain one-fact-to-one-Evidence and history constraints.

The orchestration delivery journal is outside the repository and stores only normalized delivery intents and receipts. Each intake/curation/review first persists a monotonic sequence number, request ID, idempotency key, and original HTTP body. When the result is unknown, reconcile through `get_delivery_status` or recover the original identity/body with `recover_delivery(delivery_id)`. Receipts have stable delivery_id; replaying a successful intent returns the historical receipt without creating duplicate Evidence. Confirmed rejection remains recorded; corrections use a new intent. After CAS conflict, first read the new IM state.

## MCP v2 adapter contract

Submit, read, and curate connections each expose `get_connection_info`. Submit also exposes delivery status/recovery; read/curate add `read_field_source`, `locate_field_excerpt`, `read_field_fact`, `read_field_review`, and `get_field_summary`. The read/curate packet allowlist is checked before any HTTP request; packet-scoped HTTP routes then reconfirm Issue and ownership.

Every tool declares an outputSchema; every result includes `contract_version: workflow-mcp/v2`. Errors return `isError=true` with consistent code, operation, layer, JSON Pointer fields, retry_policy, and effect. The connection manifest SHA-256 covers the name, description, inputSchema, and outputSchema of every tool in the complete public tools/list, serialized as compact UTF-8 JSON with sorted keys; dynamic enums are included. Authentication checks, stdio handshake, and actual HTTP reads are reported separately.

