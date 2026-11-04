# Independent Queue tools

Task lists can include an optional `get_task` entrance; a task read can include
reply and reply-list entrances when enabled by the host. Supply the actual reply
text. These entrances do not claim a task or prove write authorization.

A published task must select an `experimenter_profile`. The Queue does not contact a Host or prove that the profile exists or is authorized. The target Host checks its Queue capability and caller permissions before claiming. Direct Queue claims remain governed by Queue principal permissions.

This module provides an immutable task Queue: publish, list/read, atomic single claim,
and append-only short replies. It works with IM, Board, automation, execution hosts,
and models stopped. Completion and scientific judgments belong to actual work and
its evidence. There is no completion/acceptance status, round, attempt, lease,
release, automatic reassignment, or built-in role sequence.

The old Queue/Trigger/composition entry points have been retired. The only
console is `workflow-tools`; it imports the current modules and OS file lock,
without importing the IM Python package. [IM/Inbox](IM_TOOLS.md),
[Board](BOARD_TOOLS.md), [Host](HOST_TOOLS.md) and [Python listeners](PYTHON_TRIGGER.md)
are separate capabilities. Program validation does not establish actual model
attention or physical cross-machine deployment.

## Installation and commands

Install the `orchestration` Python package with its `mcp` extra in an environment
where the MCP dependencies are available. No model installation is needed.

```text
python -m pip install 'issue-workflow-orchestrator[mcp]'
workflow-tools serve --services queue --config D:/run/queue-service.json
workflow-tools mcp --profile D:/run/queue-profile.json --registry D:/run/queue-sessions.json --port 18111 --token-env MCP_QUEUE_ACCESS
```

For a checkout build, build a wheel from an outside-checkout copy using
`python -m build --wheel --no-isolation --outdir D:/run/dist`, then install that
wheel. Keep build/cache/runtime files outside the checkout. The source debug
entry is `python -m workflow_orchestrator.tools_cli`; acceptance uses the installed
console script from an outside-checkout working directory without PYTHONPATH.

## Host service configuration

UTF-8 JSON, with no inline tokens. The host injects each token environment value
before starting the service. The example names and paths are illustrative.

```json
{
  "database_path": "D:/run/queue.sqlite",
  "listen": {"host": "127.0.0.1", "port": 18101},
  "principals": [
    {"principal_id": "manager", "token_env": "QUEUE_MANAGER_TOKEN",
     "actions": ["publish_task", "list_tasks", "get_task", "claim_task", "reply_task", "list_task_replies"]},
    {"principal_id": "experimenter", "token_env": "QUEUE_WORKER_TOKEN",
     "actions": ["list_tasks", "get_task", "claim_task", "reply_task", "list_task_replies"]}
  ]
}
```

The six operation names are the service permission names. The service
checks the authenticated principal and action on every operation,
including replay. A default Issue, a role/model profile name, and tool visibility
never grant permission. Principal/profile/operation IDs use finite name references
(`[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}`). Role/model names are saved as references;
the service does not inspect remote model configuration or require a model online.

The database must be an absolute path outside the package checkout. A new store
gets a persistent UUID service identity. Existing unrelated/old databases are
rejected, without initialization, migration or repair. A missing original store
is never transparently taken over by a bound client. Each process owns only its
own store; clients receive no server SQLite/credential paths. Listen explicitly
on the required host interface when using another machine; endpoints may be HTTP
or HTTPS. HTTPS termination/network access is deployment configuration, not a new
service discovery or access management system.

## Queue-only MCP profile

```json
{
  "connection": {"endpoint": "http://127.0.0.1:18101", "token_env": "QUEUE_MANAGER_TOKEN"},
  "default_issue_id": "A",
  "tools": ["publish_task", "list_tasks", "get_task", "claim_task", "reply_task", "list_task_replies"],
  "journal_path": "D:/run/queue-actions.json"
}
```

The journal is an atomically replaced UTF-8 JSON document (not JSONL), containing
one bound connection and independent action intents/receipts. Its extension is
not interpreted. `default_task_id` is optional for `reply_task` and
`list_task_replies`; explicit targets still use actual server permissions.

List responses include `next_read` with the resolved target and original filters;
the last page returns null. If the snapshot changes, restart with the same filters.
For an unscoped `list_tasks` query the continuation carries `issue_id: null`, so a
later profile default cannot silently change the query.
The profile may choose any nonempty subset of the six tools. `default_issue_id`
is used only when publish/list omits the Issue. Any actual Issue may be used when the action is permitted. Tool arguments contain business inputs, never an
actor, bearer token, endpoint, database path, operation ID, round or run proof.

Typical calls:

```json
{"name":"publish_task","arguments":{"instructions":"Inspect the unresolved shift; preserve negative results.","experimenter_profile":"experimenter","input_refs":["im:observation:seed"]}}
{"name":"list_tasks","arguments":{"claimed":false}}
{"name":"get_task","arguments":{"task_id":"task-..."}}
{"name":"claim_task","arguments":{"task_id":"task-..."}}
{"name":"reply_task","arguments":{"task_id":"task-...","text":"Measurement failed; raw trace preserved.","refs":["file:trace.csv"]}}
{"name":"list_task_replies","arguments":{"task_id":"task-..."}}
```

A claim is a permanent record of who claimed it, not start/completion proof.
A new claim by the same principal also fails with `already_claimed`. Replies
retain real author/time, never change the original instructions or claim and do
not release runtime resources or create handling obligations.

## HTTP and Python client

All routes require one host-bound `Authorization: Bearer ...` header.

| Route | Input |
| --- | --- |
| GET `/v1/identity` | Persistent `service_id`, `modules`, authenticated `principal_id` |
| POST `/v1/queue/tasks` | `operation_id`, `issue_id`, `instructions`, `experimenter_profile`, optional `input_refs` |
| GET `/v1/queue/tasks` | Optional `issue_id`, `claimed=true/false`, `cursor`, `limit` |
| GET `/v1/queue/tasks/{task_id}` | Full immutable task and `claim=null` or actual claim |
| POST `/v1/queue/tasks/{task_id}/claim` | `operation_id` |
| POST `/v1/queue/tasks/{task_id}/replies` | `operation_id`, `text`, optional `refs` |
| GET `/v1/queue/tasks/{task_id}/replies` | Optional `cursor`, `limit` |

Unknown/duplicate fields are rejected. Instructions are limited to 16,000
characters; replies to 2,000; refs to 30 strings of at most 2,048 characters each;
POST bodies to 65,536 bytes. JSON must be finite UTF-8, without duplicate keys.
No edit/cancel/finish route exists. A list with no Issue filters to the principal's
explicit Issue set. Reads do not write receipts, claims or read/handled markers.

Pages default to 20 and **reject** limits outside 1..50. Results are in ascending
local sequence order and return `items`, `limit`, `next_cursor`, `service_id`.
The authenticated cursor binds service, principal, operation, target and the
requested Issue filter. Task publication or claim changes invalidate task-list cursors;
appending a reply invalidates that task's reply cursor. `snapshot_changed` asks
the caller to restart pagination; no silent skipping or query rebinding occurs.
A page size may change without changing the query. References remain opaque data.

```python
from workflow_orchestrator.tools_client import ToolsClient
client = ToolsClient.from_connection(profile["connection"], profile["journal_path"])
receipt = client.write("publish_task", issue_id="A", instructions="Inspect shift",
                       experimenter_profile="experimenter")
tasks = client.read("list_tasks", issue_id="A", claimed=False)
```

The client binds endpoint/service/principal through real HTTP and persistent
journal metadata. Every call verifies identity; requests and responses also
carry expected service/principal identity headers, protecting the gap between
identity read and POST. Redirects never forward credentials to another target.

Each new write call generates a fresh internal operation ID, persists an intent
and send marker before POST, and saves its receipt. SQLite business write and
receipt commit together under one transaction; claims use a single unique row.
The same operation ID with changed principal/action/target/canonical body returns
`idempotency_conflict`. The original POST returns its original receipt even after
restart (`replayed=true`). Repeated genuine calls with identical content create
separate contributions.

Errors are `{"error":{"code":"...","message":"...","effect":"not_committed|unknown"}}`.
Write errors include the original `operation_id` when known. An unavailable POST
response or failed local receipt persistence is `unknown`; it never asserts that
the service did not write. Pending operations remain recoverable individually.
No pending action prevents another independent legal write.

For host recovery, use `client.recover(original_operation_id)`, which reads and
replays the saved original POST, or the installed command:

```text
workflow-tools recover --profile D:/run/queue-profile.json --operation-id op-...
```

MCP startup attempts each original pending action before serving new calls. The
journal stores original content, target and binding, not bearer tokens. Changing
the endpoint, service store or principal blocks original recovery. Restore the
original binding and recover it; never edit the journal into a different request.
Changing tool defaults does not change saved intents. Independent new MCP calls
always create new operation identities.

## Verification scope

`orchestration/tests/test_queue_tools.py` uses real independent service/MCP
processes, two clients racing a claim, actual HTTP response-loss forwarding,
restart/replay, operation refusals, pagination, journal write failures,
malformed HTTP and unrelated-store preservation. `queue_tools_harness.py` records
PID plus OS creation identity and checks the original handle before cleanup.
The same tests can target an installed console script using `WORKFLOW_TEST_CLI`
and `WORKFLOW_TEST_PYTHON`; `WORKFLOW_STEP_RUNTIME` binds all evidence to the
step's outside-checkout runtime directory. Program tests are distinct from actual
model attention, scientific content and real multi-machine deployment acceptance.
