# Independent Board tools

Reading ordinary information may return an optional `reply` draft with its actual
message ID and Issue. Supply the text; explicitly choose another Issue for a
cross-Issue reply if intended. A visible tool or draft does not prove permission.
Parent reads also remain subject to service authorization. Requests use
`answer_handoff` and ordinary information does not create a request.

`workflow-tools serve --services board --config D:/run/board-service.json` serves
ordinary information/replies, explicit recipient requests/exact answers, and
human instructions. Use `workflow-tools mcp --profile D:/run/board-profile.json --registry D:/run/board-sessions.json --port 18112 --token-env MCP_BOARD_ACCESS`
with `surface=board`. Queue, execution hosts, Trigger and models can be offline.
IM can also be offline except when querying an Issue subtree. Board has its own store and port; combined Queue/Board service is not
provided by this entry. Omitted surface/queue and surface=im keep their existing
protocols. The old Board/dispatch/Trigger entry points have been retired; this surface
uses only the current modules.

## Host configuration

UTF-8 JSON without tokens. The host injects each token environment value. Use a
new absolute database path outside the checkout. Unknown/old schemas are refused,
without initialization, migration or repair. A new store has a persistent UUID;
restarts retain it and clients refuse a replacement store at the same URL.

```json
{
  "database_path": "D:/run/board.sqlite",
  "listen": {"host": "127.0.0.1", "port": 18104},
  "principals": [
    {"principal_id": "researcher", "token_env": "BOARD_RESEARCHER_TOKEN",
     "kind": "service", "recipient": "researcher",
     "allowed_recipients": ["scientist"],
     "actions": ["post_message", "get_message", "list_messages", "post_handoff", "get_handoff", "list_handoffs", "answer_handoff", "get_board_instruction", "list_board_instructions", "list_board_instruction_events"]},
    {"principal_id": "scientist", "token_env": "BOARD_SCIENTIST_TOKEN",
     "kind": "service", "recipient": "scientist",
     "allowed_recipients": ["researcher"],
     "actions": ["post_message", "get_message", "list_messages", "post_handoff", "get_handoff", "list_handoffs", "answer_handoff", "get_board_instruction", "list_board_instructions", "list_board_instruction_events"]},
    {"principal_id": "owner", "token_env": "BOARD_OWNER_TOKEN", "kind": "human",
     "recipient": "owner", "allowed_recipients": ["scientist"],
     "actions": ["post_message", "get_message", "list_messages", "post_handoff", "get_handoff", "list_handoffs", "answer_handoff", "create_board_instruction", "get_board_instruction", "list_board_instructions", "revoke_board_instruction", "list_board_instruction_events"]}
  ]
}
```

Action permissions are explicit; Issue identifies the work and is not an authorization list.
`kind` and `recipient` are authenticated host bindings, never participant inputs.
Multiple trusted principals may share a recipient mailbox only when the host
intentionally configures that access. `allowed_recipients` controls outgoing
requests, not ordinary information. A handoff is readable only by its actual
sender (ID/kind/mailbox) or bound recipient, and requires the action grant.
The recipient alone may answer. Knowing an ID never grants read or write access.
A default Issue is a convenience and grants nothing. HTTP(S) origins can be
remote; listen/network/TLS termination is host deployment configuration.

## MCP profile and short usage

```json
{
  "surface": "board",
  "connection": {"endpoint": "http://127.0.0.1:18104", "token_env": "BOARD_RESEARCHER_TOKEN"},
  "default_issue_id": "A",
  "tools": ["post_message", "get_message", "list_messages", "post_handoff", "get_handoff", "list_handoffs", "answer_handoff", "get_board_instruction", "list_board_instructions", "list_board_instruction_events"],
  "journal_path": "D:/run/board-actions.json"
}
```

For `list_messages` subtree queries, add `"tree_connection": {"endpoint": "http://127.0.0.1:18103", "token_env": "IM_TREE_TOKEN"}` to the Board MCP profile. The IM credential must permit the public Issue overview. Use `include_descendants: true` with the root Issue. IM caps an overview at 128 nodes and 256 KiB; an exceeded limit is an error, never a partial tree. Single-Issue and all-Issue reads do not contact IM. The subtree is read before and after each Board page, and the continuation binds its snapshot and root. Changes to the tree or Board collection reject continuation with `snapshot_changed`; restart the query. Pages scan the Board collection in sequence, so a filtered page may be empty while `next_read` is present. The two services do not provide a shared atomic snapshot.

Select any nonempty unique subset of the twelve tools. Add the two human write
tools to a human profile when wanted. Even if a service profile exposes them,
the real HTTP service still refuses a service principal. No actor, operation ID,
expected revision, endpoint or credential is accepted from the participant.

The four list tools accept `all_issues: true` to query all Issues. It cannot be
combined with `issue_id`. Otherwise the configured default applies; without a
default, the service queries all Issues. `query_scope` describes the request and `next_read` retains its scope.
Handoff recipient visibility and snapshot checks remain in the Board service.

| Tool | Business input / effect |
| --- | --- |
| post_message | `text`, optional `issue_id` default and `reply_to`. Immutable ordinary information. Returns full message, actual sequence/author/kind/time and read path. |
| get_message / list_messages | `message_id`, or optional Issue/all_issues/include_descendants/after_sequence/cursor/limit. Ordinary information only. Subtree continuation uses the returned `next_read`, including `expected_tree_snapshot`. Lists preview 1024 characters, mark `text_complete`, and provide a complete `get_message` entrance. |
| post_handoff | `text`, `recipient`, optional Issue default. Explicit request, revision 1, pending. No automatic activation. |
| get_handoff / list_handoffs | Original message ID, or optional Issue/status/after_sequence/cursor/limit. Sender/recipient visibility, full exact answer in reads. No read receipt or state mutation. |
| answer_handoff | Original `message_id`, real `answer`, `reason`, optional `result_refs`. Program captures the current revision once. Only the bound recipient can move pending to handled. |
| create_board_instruction | Readable human `source_message_id`, `kind` priority/scope/budget/constraint, finite object `payload`. Host-authenticated human with actual source read and action permission only. |
| get_board_instruction / list_board_instructions | Original instruction ID, or optional Issue/include_revoked/after_sequence/cursor/limit. Active by default; explicit revoked history retains original payload/reason. |
| revoke_board_instruction | Original `instruction_id`, real `reason`. Human operation permission, program-captured CAS; revision 2 and immutable event. |
| list_board_instruction_events | Optional original instruction ID/Issue/after_sequence/cursor/limit. Immutable created/revoked event history. |

Ordinary replies require all actual ancestors to exist, be ordinary information
and be readable under the authenticated `get_message` permission. The
`post_message` permission is checked separately. A maximum of 16 reply links
is accepted; cycles/inconsistent chains are refused. Cross-Issue replies are
permitted with those explicit read/write grants.
Use answer_handoff for a request instead of replying through ordinary information.

Examples:

```json
{"name":"post_message","arguments":{"text":"The fit failed; the raw trace is preserved."}}
{"name":"post_message","arguments":{"text":"I checked the original trace.","reply_to":"msg-returned-id"}}
{"name":"post_handoff","arguments":{"recipient":"scientist","text":"Which uncertainty remains unresolved?"}}
{"name":"answer_handoff","arguments":{"message_id":"msg-returned-request-id","answer":"The calibration uncertainty is still unresolved.","reason":"No valid reference measurement exists.","result_refs":["archive:failed-trace"]}}
```

Handled records a real answer, including negative or unresolved content. It does
not certify scientific success, completion, acceptance or adoption. A service
reminder remains ordinary information and never becomes an instruction. These
tools do not execute budget/scope requirements, mark messages read, create
successors, install subscriptions or wake roles. No edit, ordinary withdrawal,
request forwarding/wait chain, instruction inheritance or global ACL is provided.

## Finite HTTP and pagination

Every route requires host-bound Bearer authentication. `GET /v1/identity` returns
`service_id`, `modules=["board"]`, `principal_id`, `kind`, `recipient` and a
`principal_binding` digest covering all configured permissions and recipient
bindings. Bound client requests/responses check service, principal and that digest
to protect the identity-read/POST gap. Credentials are never returned or stored in
journals. Redirects are refused.

| Route | Body / query |
| --- | --- |
| POST /v1/board/messages | operation_id, issue_id, text, optional reply_to |
| GET /v1/board/messages | issue_id, after_sequence, cursor, limit, optional `scope_tag` for binding a caller's composed query to its cursor; it does not filter messages |
| GET /v1/board/messages/{id} | Complete ordinary message |
| POST /v1/board/handoffs | operation_id, issue_id, text, recipient |
| GET /v1/board/handoffs | issue_id, status pending/handled, after_sequence, cursor, limit |
| GET /v1/board/handoffs/{id} | Complete request, recipient, revision and exact answer |
| POST /v1/board/handoffs/{id}/answer | operation_id, expected_revision, answer, reason, optional result_refs |
| POST /v1/board/instructions | operation_id, source_message_id, kind, payload |
| GET /v1/board/instructions | issue_id, include_revoked true/false, after_sequence, cursor, limit |
| GET /v1/board/instructions/{id} | Complete instruction and revocation |
| POST /v1/board/instructions/{id}/revoke | operation_id, expected_revision, reason |
| GET /v1/board/instructions/{id}/events | after_sequence, cursor, limit, optional issue_id |
| GET /v1/board/instruction-events | instruction_id, issue_id, after_sequence, cursor, limit |

Unknown/duplicate JSON/query fields are refused. Text preserves original Unicode
and whitespace (up to 16000 characters); answer/reason up to 8192 characters,
instruction payload up to 8192 canonical UTF-8 bytes, result_refs up to 30 strings
of 2048 characters. POST bodies are bounded to 131072 bytes. Limits are explicit:
list defaults to 20, rejects outside 1..50; after_sequence is a nonnegative signed
64-bit integer. Results are ascending sequence order, with `next_cursor`,
`next_read`, `next_sequence`, `has_more` and actual `service_id`. Follow `next_read`
with its original filters. A cursor binds service, principal permissions, action,
filters and a Board-history watermark. Concurrent Board writes invalidate snapshot
paging with snapshot_changed; restart the list. An incremental observer may start
a fresh ordinary-message query with after_sequence. Reads create no writes.

## Per-action original recovery

Every new write, even identical text, gets a fresh internal operation ID. The
client saves an immutable checksummed intent and send marker before POST. The
service writes records, answer/instruction events and original receipt in one
local transaction. Replaying the same operation/body/target/principal returns
its original receipt even after a later revision; changed content/target/identity
is idempotency_conflict. New answers/revocations cannot overwrite existing history.
The journal is a host-owned atomic JSON document with a format shared by the
finite journal helper; Board uses its own connection binding and intent checksums.
Checksums detect accidental edits, not hostile replacement by the journal owner.

```text
workflow-tools recover --profile D:/run/board-profile.json --operation-id op-original-id
```

Or use BoardClient.from_connection(connection, journal_path).recover(original_id).
The MCP process attempts pending originals before serving genuinely new calls.
A pending action does not block other legal independent messages. Version reads
are never repeated during original recovery to refresh CAS. Recovery fixes the
original endpoint, persistent store UUID, token source/fingerprint, human/service,
recipient and permissions, target, body, action, ID and captured original version.
Changed bindings or intent checksums refuse recovery; restore the original host
binding and intent rather than reset a journal or change IDs.

A journal failure before send causes zero service writes. Lost responses or local
receipt-persistence failures are unknown and retain the original pending intent.
HTTP 408/425/429, 5xx, HTML, malformed or unrecognized success/error responses
cannot establish noncommit. Recognized authoritative permission/input/CAS errors
with matching service/subject response headers retain their real not_committed
meaning; authentication/permission loss after a previous send cannot disprove that
send. A recover call makes one original POST attempt, without a retry scheduler.
IM's flat envelope is not used as the Board protocol. Queue/IM transports and their
existing journals are not rewritten or migrated.

## Verification scope

The Board tests exercise real separate service/MCP/CLI and HTTP fault-proxy
processes, synthetic human/recipient grants, transaction counts, races, full
reads and actual later pages. Loss/transient-error sequences preserve exact
original requests; only transport or local journal persistence is injected.
The process host records PID plus OS creation identity and closes/waits its own
handles. WORKFLOW_STEP_RUNTIME, WORKFLOW_TEST_CLI and WORKFLOW_TEST_PYTHON select
the outside-checkout runtime and actual installed consumers. Existing Python
system/user-site dependencies may be reused; this is not full dependency
isolation. Same-machine multiple ports prove protocol paths only. Real model
attention/scientific quality, cross-physical-machine deployment, instruments,
subsequent host/Trigger steps, push and deployment remain outside this step.
