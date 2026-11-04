# Read-only listeners and user Python scripts (step 5)

Install the orchestration wheel. Inject tokens for connections actually used.
Connections JSON contains only `connections: {name: {endpoint, token_env}}`.
HTTP(S) origins may be on different machines; each service owns its database.
Script and Host source names must refer to the same actual service, though reader
and worker tokens may differ. State is an absolute directory outside the checkout.

```text
workflow-tools discover --once --connections D:/run/connections.json --state D:/run/listener --watch queue-work --kind queue.task --connection queue-b --issue A
workflow-tools discover --once --connections D:/run/connections.json --state D:/run/listener --watch new-information --kind board.message --connection board-b --issue A --initial from_start
workflow-tools trigger --script D:/run/policy.py --connections D:/run/connections.json --state D:/run/listener
```

`discover` prints scans followed by one candidate per JSON line and exits nonzero
on scan errors. It never loads a script or connects to Host. The same state/watch
can later be used by TriggerTools; discovery is not admission. Imports are
`workflow_orchestrator.listener.Listener` and
`workflow_orchestrator.trigger_tools.TriggerTools`, constructed with
`(connections, state, page_size=50, max_pages=20, timeout=5)`. Connections accepts
the dictionary above or a UTF-8 JSON path. Only used authentication is resolved.

The trusted UTF-8 script defines `run(tools)` and runs once. Ordinary imports,
neighboring helpers, functions, loops, sorting and branches work. The script
controls repetition through `for scans in tools.poll(every=5)` and can break/return.
Scan errors appear explicitly in scans. Path/encoding/syntax/import/missing-run/
runtime failures exit nonzero with the actual file/traceback; no automatic script
rerun occurs. Finally closes tool resources; edits take effect on restart.

Runnable examples: [Queue/Inbox](examples/python_queue_inbox.py),
[Board combination](examples/python_board_combination.py), and
[connections](examples/python_connections.json). They are explicit examples, not
a default role order. Scripts can import existing read clients for more context.
The optional [role-event example](examples/python_role_events.py) selects actual
Queue tasks, explicitly configured Inbox material, and handoffs addressed to the
manager or scientist. It needs the named connections, profiles and permissions;
it neither synthesizes quiet-time triggers nor declares a project complete.

## Role events are project policy

Queue tasks can activate their configured role; a project may choose a new Inbox
packet as a curator opportunity, and an explicit request can activate its intended
recipient. A curator preserves and normalizes what was actually supplied; packet
arrival does not itself prove curation is needed, complete, or scientifically valid.
A project may separately arrange conclusion updates when relevant Evidence changes,
but a changed record does not by itself prove that a conclusion should change.
The participant reads the actual Evidence and decides what it supports.

For projects that choose manager-directed conclusions, configure a new Inbox packet
as a curator opportunity and use a Board handoff addressed to the conclusion role
when the manager decides to summarize. Do not activate the conclusion role merely
because a packet arrived, Evidence changed, or a curator process exited. A handoff
is an immediate request: its text does not make the Host wait for future material.
Manager wakeups remain a separate policy based on actual sources; this arrangement
does not automatically notify or start the manager after curation.

A scientist may be invited when an explicit request or a project-chosen work
milestone calls for direction. An empty Queue or zero active runs is only an
observation within the queried scope and Host: neither establishes that all work
is finished or that scientific judgment is required. If a project chooses a quiet
period as a signal, its trusted script must define scope, evidence, waiting,
deduplication, and an actual supported source for activation. TriggerTools does
not synthesize a source event from elapsed time or expose a generic timer launch;
absence of such a source is a configuration gap, not a reason to fabricate a task
or message. Ordinary Board messages remain passive unless a project deliberately
selects one as an activation source; no fixed role sequence is implied.

| Method | Effect |
| --- | --- |
| listen(watch_key, kind=..., connection=..., issue_id=..., initial=...) | Stable named source/filter, no remote subscription. Kinds: queue.task, board.message, board.handoff, inbox.packet. |
| scan_once() | Finite read-only scan per watch; TriggerTools first recovers persisted unknown originals. |
| poll(every=5) | Yields scans, sleeps .05..3600 seconds between rounds; script chooses all new actions. |
| pending(watch_key, action_key=None) | Paginated iterator of ordinary {watch_key,source,record} dictionaries. All unselected/busy/rejected candidates remain reachable. TriggerTools filters accepted receipts for this action. |
| host_status(host_name) | TriggerTools only: real this_host counts. Failures propagate; absent roles do not mean idle. |
| activate(candidate, host=..., role_profile=..., model_profile=..., conditions=..., action_key=None) | TriggerTools only: freeze one request and use HostClient. Queue uses its experimenter configuration without role or model overrides; non-Queue needs a role. Only existing idle_roles can be sent as conditions. |

Queue includes existing unclaimed tasks; initial=new_only is refused. Board/Inbox
default new_only, with explicit from_start for history. This applies once, even
for an empty successful baseline. The boundary is successful baseline establishment,
not the exact process start. Board pages retain original filters/after_sequence;
candidate persistence and sequence advancement are atomic. Snapshot changes
restart from the saved sequence. Handoffs are filtered to the authenticated
recipient, excluding visible outgoing requests. Queue snapshot changes restart
the current unclaimed set and deduplicate task IDs. Inbox reads newest-first,
following older pages to the previous complete head before advancing it. Random
packet IDs are not ordered; partial crawls resume after restart/failure, and the
next crawl catches arrivals during the prior crawl. Curation/review changes never
create new packet activations. max_pages retains a continuation, not a truncation.
Records are bounded source previews, not IM authority. Accepted records may remain
for deduplication; no retention/cleanup platform is introduced.

The default action_key is watch_key. For genuinely independent activations of
one candidate, use distinct explicit keys consistently in pending and activate.
No registration/sealing is needed. Script hash, polling interval and unrelated
connection entries never change an action. Original source/filter/service/subject/
endpoint/credential changes are refused. Use a new watch for a genuinely new source.
Original Host/role/model/conditions are frozen; changed bodies require a deliberate
new action_key. Queue/Board use actual service identities. IM has no persistent
ledger/subject UUID: omit service_id, bind endpoint/credential source/fingerprint
and packet ID. Swapping IM behind the same address/credential remains undetectable.

SQLite stores cursors/candidates and action-to-Host-journal associations. Existing
HostClient journal alone stores original request/body/send/receipt. Associations
persist before launch; HostClient saves the body before POST. Unsent associations
are not automatically sent. busy retries require another script selection. Unknown
sent originals are queried/replayed in the next scan/poll even if the selecting
branch/watch is removed. Accepted receipts are returned/filtered without a new run.
On a repeat of an already accepted action, unchanged request and local bindings
are checked before contacting either service. A temporary connection failure or
unusable response returns the original receipt with `current_state_verified=false` and
`verification_errors` identifying the failed checks; the stored run data is
historical, not a fresh observation. A definite binding/permission refusal stays
rejected and includes `original_receipt` to preserve the earlier admission fact.
Both services are checked independently when available; no activation POST is
sent for the cached receipt. To observe the current run, query the original Host.
Clear rejections retain diagnostics and stay available for explicit selection;
avoid tight retry loops. HostClient clears old busy/rejection receipts before a
subsequent POST so lost replies stay recoverable. Initial handshake failures leave
the candidate unrequested. Local OS locks/transactions coordinate processes sharing
state; existing Host idempotency protects actual claim/start. Lock timeout is an
explicit error, never permission to replace an identity.

Python's other side effects are not transactional/exactly once. Activation followed
by an exception remains real and is not duplicated on restart. Stopping/editing
scripts does not stop accepted runs or release occupancy. Failed/exited runs are
not redispatched. Host owns permission/profile checks, capacity, final idle_roles,
Queue claim, preparation and process observation. Listener never claims, answers,
curates or marks read. Multi-source Python conditions are observations; Host cannot
atomically guarantee all cross-service conditions at startup.

This step adds no JSON policy engine, sandbox/approval/registration, model review,
fixed role chain, completion/acceptance, migration or deployment. Old entry points have been retired; the only console is `workflow-tools`. Same-machine multi-address synthetic tests do not prove
model attention, scientific quality, physical cross-host or instrument behavior.
