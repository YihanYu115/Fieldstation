# Project original-access descriptions

[English documentation](README.md) · [Chinese original](../PROJECT_ORIGINAL_ACCESS.md)

Projects and trusted hosts provide access to originals; IM stores access descriptions and related bindings.

IM tools query original-access descriptions for the project actually containing the Issue. Each action selects its actual target; a new authorized target is a new action and cannot rewrite the identity of an original action being recovered.

## Minimal design and boundaries

IM stores independently maintainable project read descriptions. The root Issue identifies a project; all child Issues inherit the same descriptions. There is no subtree override or cross-root inheritance. A root may register multiple contracts. Consistent with existing general capabilities, non-platform identities with `context.read` may read; `issue.write` plus `context.read` is required for registration or revision. No new role judgment or project ACL is introduced.

`project_original_access_versions` and `project_original_access_heads` store descriptions; `project_original_access_bindings` records selections when a reference first enters a project. Description versions and reference bindings are append-only; heads advance transactionally using `expected_revision`, with audit and head in the same transaction. HTTP request logging retains request identity, idempotency, and recovery rules. Descriptions and bindings are not scientific Evidence inputs and do not change saved sources, frozen packages, conclusions, or eligibility.

Read methods are **untrusted data**. IM and orchestration do not open URLs, read local files, execute commands, parse original formats, or automatically bind tools. `capability` is a logical name only; the host binds actual tool names, endpoints, executable paths, credentials, and permissions. Business descriptions must not hold secrets; the structure has no credential, endpoint, or command field. Free text cannot reliably identify every secret, so before registration the host must ensure contents are suitable for project readers.

## HTTP

| Operation | Endpoint | Required content |
| --- | --- | --- |
| Register/revise | `POST /v1/original-access` | Bearer, `X-Request-ID`, `Idempotency-Key`; body as below |
| Discover | `GET /v1/original-access/discover` | `issue_id`; optional `reference`, `contract_id`, `limit`, `cursor`, `expected_snapshot` |
| Read | `GET /v1/original-access/read` | `issue_id` and either `evidence_id` or `contract_id+revision`; optional `max_bytes`; select an exact `reference` for multi-reference Evidence |

`GET /v1/context?issue=…`, browse Issue details, and `GET /v1/issues/overview?root=…` return `original_access` containing project root, contract count, HTTP entry points, and tool pointers. If no descriptions exist the count is zero but entry points remain available. Roles can call the general discovery tool without first knowing the contract ID.

Discovery has three purposes:

- Without `reference/contract_id`: a short catalog of current contracts; returned revisions are current heads, not a selected interpretation for a historical original.
- With `contract_id`: a catalog of all historical versions of that contract.
- With an exact `reference`: exact-string prefix matching across **all historical versions**, without restricting URI schemes or parsing paths/JSON. `contract_id` can additionally select an author-specified contract family.

`match_status` is `catalog`, `missing`, `matched`, `version_required`, or `ambiguous`. One matching version is matched; multiple versions of one family require a version; multiple matching families are ambiguous. Longest-prefix priority, automatically selecting latest, and cross-root fallback are prohibited. Status is based on the entire candidate set before pagination, even if the first page has only one result.

Pages contain 1–50 entries, default 20. Collection reads are limited to 10,000 entries and explicitly reject larger sets; catalog responses are at most 60 KiB and the limit may be reduced. Cursors bind the query, identity, and actual catalog contents; changes return 409 and require restarting at page one. Missing descriptions or matches do not trigger an external tool.

Each version contains the following nonempty text, totaling at most 32768 UTF-8 bytes of JSON:

| Field | Meaning/limit |
| --- | --- |
| `reference_prefix` | Exact applicable prefix, at most 512 bytes; not a regular expression. |
| `summary` | Short summary, at most 512 bytes. |
| `capability` | Logical capability to bind at the host; ASCII identifier, at most 128 bytes. |
| `parameters` | Parameters, reference composition, and local location method needed for the first read. |
| `example` | One explicit call example; must not require reading the original first to discover the method. |
| `semantics` | Local selection, pagination/slicing, complete/truncated responses, and available checks; unsupported abilities stated honestly. |
| `failures` | Meaning of missing bindings, denial, missing objects, range/budget/verification failures. |
| `change_impact` | `initial` for the first revision, `editorial` or `interpretation` later. |
| `impact_note` | Actual effect and required review; “no impact” alone must not conceal interpretive change. |

Each of the latter six free-text fields is limited to 8192 bytes; `change_impact` has its own enum. Complete reads do not silently truncate; default budget is 65536 bytes and may be set to 1024–65536. Over budget returns 409 and `required_bytes`; reread with a sufficient budget. Descriptions have independent byte limits, so this version has no body-pagination protocol for descriptions. The project tool defines pagination of originals themselves.

## Automatic binding and history

A description version is identified by `(root_issue_id, contract_id, revision)`. Direct contract reads require the exact revision; Evidence reads use the version fixed when that Evidence was admitted, not the newest one at read time. Old description versions remain readable forever and reference strings are not rewritten.

Ordinary submissions add no mandatory field and do not require authors to declare versions in prose. In the atomic admission transaction, IM matches current heads using project root and exact reference: a unique match stores the specific contract_id/revision; no match records missing; multiple active matches record ambiguous. This matches active heads, unlike discovery by original reference, which matches all historical versions. Even later editorial revision does not reselect old bindings.

A binding records the read description selected at admission; it does not certify the author read the original, used that tool version, or produced scientifically correct content. The ordinary entry point uses automatic rules and adds no manual version-selection override for historical import.

Bindings are exact to project and reference. The same Evidence registered in different projects fixes each project's selection on first registration; repeat registration in the same project does not reselect. General add_evidence, scoped contribution, ChangeSet attachment, and old Intake transfer into an Issue all record consistently. Prototype Intake/Manifest without project scope does not guess a project; default selection first applies on entry into one.

Field Inbox fixes selections per source and attachment_ref when a packet is received. Curated Evidence inherits the source packet's bindings, including missing/ambiguous gaps; delayed curation does not select a newer revision. Explicit internal sources such as packet_text are internal and require no external-read contract. Bindings, contributions, and existing relations are saved in one transaction; replay retains the original receipt and binding; failure leaves no partial record.

Evidence details, individual Field facts, and packet detail/summary expose a short original_access field; bound entries include exact-version read pointers. Frozen-material displays provide a stable read entry by evidence_id, without adding descriptions or binding tables to scientific frozen inputs or comparison fingerprints. `read_original_access` can accept evidence_id directly to obtain its fixed description, avoiding discovery and manual version entry.

If there is no binding record, return unrecorded; do not backfill today's latest. A multi-reference item with no reference selected returns multiple_references. Missing descriptions, ambiguity, and oversized catalogs return explicit states and preserve contributions. No historical binding backfill, revision, or rebind interface is provided; after a description is added, new contributions can bind normally, but old gaps need explicit handling and reads cannot silently rewrite history. Gap reads are also subject to UTF-8 budgets. At most 50 ambiguous candidate identities and the actual total count are saved, without sending full candidate texts to roles.

When changes affect referenced objects, location, or interpretation, write `interpretation` and an explicit `impact_note`; the author/host arranges necessary scientific review. This feature saves a change declaration only: it does not infer which conclusions to revise or automatically update depends_on. The current catalog shows change type and details retain review instructions.

## Role MCP and host bindings

The IM profile can select `discover_original_access` and `read_original_access`. The latter supports a fixed Evidence binding or an explicit contract version; actual server and Evidence-read permission checks remain independent. See [IM tools](../../orchestration/IM_TOOLS.md) for entry points and profile fields.

The trusted host specifies endpoint, token environment variable name, default Issue, and an external journal; the tool does not read credential files or the IM database. The host separately binds actual project-provided storage and read capabilities and confirms authorization, reference formats, retention, and availability after restart. Registration or tool visibility alone does not prove those capabilities are available. The project tool is responsible for saving actual results as referable versions, returning exact references, and reading by those references; the project contract defines durability, integrity, and scope. Roles save returned result references as sources and relate them to inputs and other contributions according to meaning. Input references, local paths, or description bindings cannot stand in for result references.

Handoff steps:

1. For admitted contributions, prefer the original_access pointer, or call read_original_access with evidence_id.
2. For an exact original reference not yet admitted, use discover_original_access; choose a version explicitly when historical interpretations differ rather than guessing.
3. Verify the host has bound the logical capability required by the description, then use the external tool to read the required part.
4. Save local contributions and exact original references through existing delivery entry points; the server binds versions by default. Report precise gaps for missing tools, permissions, or matches.

IM returns `external_binding=host_required` and does not claim the current session can already read. Without an external tool it can only return this definite binding gap; whether a model understands and reports it correctly requires separate real-role validation.

## Compatibility and project packages

The database follows fresh-only policy: old schemas are rejected before enabling WAL or making automatic changes; automatic upgrade, bypass tables, and merely relabeling versions are not provided. Complete project packages also validate the current schema.

Whether an old project can be opened depends on its actual schema, not the name of a historical environment. Accessing an old ledger requires separate assessment of migration or faithful reconstruction while retaining scientific history; this contract does not authorize modification of existing environments.

Backups and project packages enumerate descriptions, heads, bindings, and inheritance chains across the kernel database. Import rebuilds authentication and isolates execution; descriptions do not contain external originals, tools, or tool credentials.

