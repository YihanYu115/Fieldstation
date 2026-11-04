# Independent IM and Inbox tools

Browse results may expose optional reads for actual returned Issue and Evidence
IDs. Continued browse pages retain the query and returned snapshot; a changed
snapshot requires a fresh read. Restricted records are not offered as readable
Evidence. Original-access reads retain the service's actual frozen binding.

`workflow-tools mcp --profile D:/run/im-profile.json --registry D:/run/im-sessions.json --port 18113 --token-env MCP_IM_ACCESS` exposes the existing IM HTTP
API without Queue, Board, Trigger, an execution host, tasks or run IDs. The
installed console entry is `workflow-tools`; `surface` selects a finite module.
Omitted `surface` or `queue` retains the accepted Queue behavior.

```json
{
  "surface": "im",
  "connection": {"endpoint": "http://127.0.0.1:18103", "token_env": "IM_TOKEN"},
  "default_issue_id": "A",
  "tools": ["submit_field_packet", "list_field_packets", "read_field_packet", "read_field_source", "get_field_summary", "curate_field_item", "list_curated_field_items", "read_field_fact", "create_issue", "list_issue_types", "inspect_issue", "list_child_issues", "read_conclusion_rule", "list_conclusion_history", "set_conclusion_rule", "save_working_conclusion", "read_evidence", "read_evidence_neighbors", "read_split_origins", "split_evidence", "save_contribution", "get_delivery_status", "recover_delivery"],
  "journal_path": "D:/run/im-actions.json"
}
```

The host injects the token into the named environment variable. The package does
not read credential files or the IM ledger. Use a new outside-checkout journal;
old Inbox/direct/workflow journals are not migrated. The profile's unique,
nonempty tool list can select any subset of the catalog below. Tool visibility
and the default Issue grant no permission. Explicitly select another permitted
Issue for new work; packet curation without `issue_id` uses the actual packet's
Issue. An explicitly conflicting Issue is refused.

Browse known Issues and Evidence by their IDs, including parents and other projects.
IM's existing bearer capabilities and Evidence read checks remain authoritative.
Original-access instructions use the actual project's frozen binding.
Conclusion rule versions, supported schema fields and history semantics are documented in
[Conclusion rules](CONCLUSION_RULES.md).

| Tools | Business input and behavior |
| --- | --- |
| `create_issue` | Explicit new `issue_id`, `issue_type`, and `title`; optionally `parent_issue_id`, `scope`, type registration ID and reason. Omit parent for a root. IM requires `issue.write` and checks the parent's registered child types. Add this tool explicitly to the profile; visibility does not grant permission. Recover an uncertain original with `recover_delivery`. |
| `submit_field_packet` | `content`, optional `attachment_refs`, `sources`, `issue_id`. Preserves packet validation: 80,000 content characters, at most 16 sources and 128 attachment references, 200,000 canonical UTF-8 bytes including defaults and target. Errors include fields and numerical budget when applicable. |
| `list_field_packets` | Optional Issue, limit 1..50, `after_packet_id`. Actual IM index, newest first. `next_read` continues the original Issue/filter; no released/visible packet list is required. |
| `read_field_packet`, `get_field_summary` | Packet ID; metadata, a 500-character preview, actual curation version/counts, source read entrances. When reference metadata exceeds the response budget, either tool returns reference pages and `next_read` until all sources, attachments and original-access bindings are available. Summary optionally accepts review ID. |
| `read_field_source`, `locate_field_excerpt` | Packet ID, optional source index; Unicode `start`, content hash and byte budget 256..16384; locator accepts exact quote, candidate limit 1..8 and `after_start`. No external file fetch. |
| `curate_field_item` | Packet ID, kind, description, exact origin, reason, optional actual Issue and related Evidence/fact refs. Reads the current version once and stores it before POST. Evidence, fact, origin mapping and relationships commit atomically in IM. |
| `list_curated_field_items`, `read_field_fact` | Read real persisted mappings to continue after interruption. List returns a version-bound `next_read`; fact returns source and current mapping. Expand Evidence relationships with `read_evidence_neighbors`. |
| `record_field_review` | Actual packet ID, explicitly selected `handled_fact_refs` (may be empty), reason, optional unresolved origin/reason entries. No automatic review or claim that all material was read. |
| `list_field_reviews`, `read_field_review` | Actual immutable review history; bounded pages and original reason. Review paging returns `next_read`. |
| `inspect_issue`, `list_child_issues`, `list_issue_evidence` | Current Issue/project browse and bounded cursor/snapshot pages. |
| `read_evidence`, `read_evidence_neighbors` | Evidence ID, actual current body/source or paged bidirectional relations with layer/version. |
| `split_evidence`, `read_split_origins` | Split a readable Evidence into 2–16 independently identified parts attached to explicitly chosen Issues. Each optional relation decision withdraws an existing direct scoped relation or replaces the source endpoint with the selected zero-based part. Unselected relations stay as they were; optional new scoped relations retain their stated direction. Origins are paged and link a child to its source and its original Evidence version binding, source to children, or source to actual fact/packet mappings. The child-to-source entry reports whether the original binding is still current. These links do not assert original verification. |
| `discover_original_access`, `read_original_access` | Existing project original-reading instructions and fixed historical bindings. Read by Evidence, or explicit contract/revision; these instructions do not grant external tool access. |
| `save_contribution` | Kind, source locator, text, reason, optional Issue and related Evidence with relation type/rationale. Existing atomic contribution API; the participant chooses content and dependencies. |
| `create_relation`, `withdraw_relation`, `restore_relation` | Business endpoints/type/reason. Program captures original endpoint tokens or relation version; IM authorization and CAS apply. No participant-written action ID. |
| `list_issue_types`, `read_conclusion_rule`, `list_conclusion_history`, `set_conclusion_rule` | Discover active types and defaults; read the current or an exact historical rule and paged conclusion history, including each version's actual currentness; replace one Issue's rule for future conclusions with a reason. Writes require `issue.write` and `context.read`, use the observed rule revision, and preserve uncertain delivery for recovery. The type snapshot is unchanged. |
| `save_working_conclusion` | Statement, explicitly chosen Evidence roots, reason, confidence, optional Issue/applicability/limitations and `structured_outputs`. `inspect_issue` returns the current `conclusion_rule.schema`; required values are checked by IM. Captures the conclusion head and rule version, persists prepare/view/conclusion HTTP identities and reuses the original frozen package. No automatic scientific basis selection. |
| `get_delivery_status`, `recover_delivery` | Original returned delivery ID only. Read historical local intent/receipt or replay its original HTTP writes. |

`split_evidence` requires `context.read` and `evidence.write`, and additionally
`evidence.relation.write` when relations are changed or created. Each part has
an explicit Issue, `kind` and text. For a withdrawal set `part_index` to null;
for a replacement select the affected part index. New relation endpoints are
objects containing either `part_index` or an existing `evidence_id`. The IM
checks the bounded direct boundary and resolver-relevant directed dependencies,
and requires access to each Evidence actually selected for a relation change.
Oversized boundaries fail rather than return a partial inventory. For inspection use `read_evidence`,
`read_evidence_neighbors`, and `read_split_origins` as needed; origin pages
contain at most eight entries and have an explicit byte bound. A source
with inaccessible children still exposes its readable entries, plus a redacted
marker with no child identity. When splitting is enabled, Evidence and relation
reads atomically capture a boundary and the relation versions actually shown;
the bound journal retains those observations, including across restarts. A later
detail read does not replace previously observed relation versions. Reread a
changed relation before making a new choice. If there was no prior observation,
the wrapper captures a boundary at submission; inspection is not mandatory.
If the split boundary exceeds its limit, ordinary Evidence and relation reads
still return their readable results with a `split_observation_notice`. The
journal records that no usable observation was obtained: splitting is refused
until the boundary can be observed within its limit and a fresh read is made.
A source relationship is not automatically a `depends_on` relation. The journal fixes
the captured versions, exact body, target, connection and HTTP identities
before POST; on an unknown response use `recover_delivery` for that action.
Conflicts require a new decision; recovery never refreshes the old versions.

The retired split-specific ChangeSet prepare/compile/apply flow and its old
unresolved requests are not recovered by this contract. Schema 9 and older
ledgers are rejected without migration or automatic takeover. Preserve the old
runtime and its original request/ChangeSet identifiers for separate inspection.

An Inbox report can preserve actual inputs, method, conditions, results, failures,
references and open questions. Make distinct findings and their conditions clear
enough to be independently questioned; the sender need not pre-split them into
Evidence. A curator may structure existing material and its actual relationships.
`verification_level=declared` does not establish verification or make an item
incorrect or automatically unusable; `quality_status=unknown` does not mean
invalid or require a curator's approval. Consider the content, relations,
refutations and applicable rules, and retain uncertainty. Graph eligibility is
not a scientific correctness certificate.

Every new save call creates a fresh delivery, even when text is identical.
Choose related Evidence using IDs actually returned by tools such as
`list_issue_evidence` or `read_evidence_neighbors`; do not invent IDs. Preserve
the real meaning and direction of each relationship.
For `save_contribution`, provide one actual source locator in `source`, not
multiple references concatenated into a single string. For an original, use the
exact reference accepted by its reading tool; put hashes, verification results
and other commentary in `text`, not after the reference. When a contribution needs
multiple sources, participants can preserve separate source contributions and
express the necessary relationships using `related_evidence`. An original-access
binding identifies the reading instructions selected for a reference; it does
not verify that the external object exists or can be read.
When preserving an actual output, consult the target project's original-access
instructions and use the project capability to obtain a readable, versioned
reference. Shared workspaces are useful for temporary work; their paths alone do
not guarantee retention or versions. The save tools describe the discovery tool
when it is enabled in the profile, or identify a host configuration gap otherwise.
No reference is invented and missing archive access does not prevent saving other
available material.
Successful packet submission returns `packet_ref`, a directly usable `read`
entrance, and the actual IM receipt. `received` means material was received; it
does not mean curated, scientifically correct, adopted, accepted or completed.
Raw data/scripts remain at their declared references.

For example, save a failed experiment, then let a fresh curator list the actual
Issue index, open source pages and save an observation. Save an interpretation
with its actual necessary relationship when the evidence warrants one. After
interruption, read existing mappings before contributing the remaining material.
No Queue claim or review is a prerequisite.

```json
{"name":"submit_field_packet","arguments":{"content":"Measurement failed at 20 mK; no fitted result.","attachment_refs":["archive:trace.csv","git:analysis-script@revision"]}}
{"name":"list_field_packets","arguments":{"issue_id":"A","limit":20}}
{"name":"read_field_source","arguments":{"packet_id":"<returned packet ID>"}}
{"name":"curate_field_item","arguments":{"packet_id":"<returned packet ID>","kind":"observation","description":"Measurement failed at 20 mK; no fit was obtained.","origin":{"type":"packet_text","quoted_text":"Measurement failed at 20 mK; no fitted result."},"reason":"Preserve the negative observation and its conditions."}}
```

Recovery uses IM's original `X-Request-ID` and `Idempotency-Key`, original body,
Issue/packet/endpoint, credential fingerprint and token environment binding.
There is no Queue `operation_id` in the IM body. The journal atomically persists
an intent/send marker before HTTP and each receipt afterward. A lost response or
failed receipt write is unknown; replay returns the original IM object, not a
second contribution. Another independent legal contribution remains possible.
Temporary HTTP 408/425/429, 5xx, unreadable or unrecognized response bodies keep
POST outcomes unknown and pending, even if a gateway says the retry was not
forwarded. They cannot disprove a previous commit. Invalid response JSON is
`invalid_response`, never a participant input error. Each explicit recovery makes
one attempt with the saved original identity; no automatic retry loop is added.
A recognized IM 4xx parameter/permission/source/CAS rejection remains definitive
(excluding 408/425/429). First-attempt permission rejection can be retained;
authentication failure after a previous send keeps the original outcome unknown.
A definitive rejection remains historical; corrected content is a new call.
CAS recovery never refreshes the old expected version. Conclusion preparation
and view creation are finite technical steps, each with a persisted original
HTTP identity; they are not a client-side substitute for domain transactions.

The host can recover one original delivery using the installed command:

```text
workflow-tools recover --profile D:/run/im-profile.json --operation-id im-...
```

MCP startup attempts only pending originals before accepting new calls. Per-action
errors retain the original recovery ID. The local journal's checksums detect
changed targets/content/IDs; it is host-owned data, not a signature or an ACL.

**Identity limit:** existing IM HTTP provides no persistent ledger UUID or
verified subject handshake. Endpoint + exact credential fingerprint + environment
source are bound locally. This does not detect swapping a ledger behind the same
endpoint or server-side reassignment of an unchanged credential. No new IM
identity route or kernel change was introduced. Queue's stronger identity
handshake is unchanged. Token rotation requires a new journal for new actions;
original recovery retains the original binding.

Verification: `orchestration/tests/test_im_tools.py` uses isolated real IM service
processes, actual HTTP forwarding with lost responses, independent MCP restarts,
partial curation, origins/relationships, actual permission and CAS rejection,
original-access reads and general contributions/conclusions. It supports the same
`WORKFLOW_TEST_CLI`, `WORKFLOW_TEST_PYTHON`, `WORKFLOW_STEP_RUNTIME` host conventions
as the Queue suite. Installation is tested outside source cwd with no source
PYTHONPATH for service consumers. These synthetic program tests do not establish
model attention, scientific validity, real cross-machine deployment or instrument
operation.
