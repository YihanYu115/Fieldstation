# Finite reliable foreground launch host

Install the orchestration wheel and its existing `mcp` dependencies, then run:

```text
workflow-tools host --config D:/run/host.json
```

Queue, Board and IM tools still work independently when this host is offline.
This host accepts explicitly requested sessions. It does not discover sources,
read trigger policies, schedule roles, judge scientific results, complete tasks,
release claims, reassign work or manage arbitrary external jobs. The [Python tools](PYTHON_TRIGGER.md) handle discovery and script selection;
Host continues to own admission, claim and execution through these same routes.
The old runtime/registered entry points have been retired.

## Trusted host configuration

UTF-8 JSON, no inline tokens. Inject each `token_env` into the host process.
Use a new absolute runtime/store outside the checkout; old/unrelated schemas are
refused. The persistent store binds the exact profiles, connections, credential
sources/fingerprints, principal grants, runtime location, model environment sources
and capacity. Restart with those original bindings. Listen address/port can change;
clients separately retain their original origin. Changing a binding requires a new
store for new actions, never replacement of an existing run's configuration.

```json
{
  "database_path": "D:/run/host.sqlite",
  "runtime_path": "D:/run/host-sessions",
  "listen": {"host": "127.0.0.1", "port": 18104},
  "max_active_runs": 2,
  "principals": [
    {"principal_id": "manual-caller", "token_env": "HOST_CALLER_TOKEN",
     "actions": ["launch", "query", "status", "catalog"],
     "role_profiles": ["experimenter"], "connections": ["queue-b", "board-b", "im-d"]}
  ],
  "connections": {
    "queue-b": {"endpoint": "http://127.0.0.1:18101", "token_env": "QUEUE_WORKER_TOKEN"},
    "board-b": {"endpoint": "http://127.0.0.1:18102", "token_env": "BOARD_WORKER_TOKEN"},
    "im-d": {"endpoint": "http://127.0.0.1:18103", "token_env": "IM_EXPERIMENTER_TOKEN"}
  },
  "model_profiles": {
    "synthetic": {
      "command": ["C:/path/to/codex.exe", "exec", "Inspect the session input"],
      "cwd": "D:/run",
      "adapter": "codex",
      "env_names": ["EXPLICIT_TEST_SETTING"]
    }
  },
  "role_profiles": {
    "experimenter": {
      "role": "experimenter", "model_profile": "synthetic",
      "catalog": {"role_name": "Experimenter", "responsibility": "Perform experimental work",
                  "profile_name": "Synthetic", "purpose": "Local program checks",
                  "model_description": "Synthetic test model", "queue_consumer": true},
      "prompt": "Complete the actual work and preserve results, conditions, sources and unresolved points. When an output needs retention, use the project's original-access contract and capability to obtain its reference.",
      "mcp": [
        {"surface": "queue", "connection": "queue-b", "http_url": "http://127.0.0.1:18111/mcp", "http_token_env": "MCP_QUEUE_ACCESS", "tools": ["get_task", "reply_task", "list_task_replies"]},
        {"surface": "im", "connection": "im-d", "http_url": "http://127.0.0.1:18113/mcp", "http_token_env": "MCP_IM_ACCESS",
         "tools": ["list_field_packets", "read_field_packet", "submit_field_packet", "discover_original_access", "read_original_access"]}
      ]
    },
    "scientist": {"role": "scientist", "model_profile": "synthetic",
                  "catalog": {"role_name": "Scientist", "responsibility": "Assess scientific material",
                              "profile_name": "Synthetic scientist", "purpose": "Local program checks",
                              "model_description": "Synthetic test model", "queue_consumer": false},
                  "prompt": "When asked for direction, assess the relevant material and provide grounded choices, questions and limitations.", "mcp": []}
  }
}
```

Profile names/role labels are finite references, not installed model registrations.
For separately configurable session prompts and catalog responsibilities, see
[role guidance fragments](examples/host_role_guidance.json) and [role usage](ROLE_USAGE.md).
The fragments need actual model and MCP bindings; neither they nor this document
modify existing Host configurations. External participants can use MCP tools
without receiving this Host's session prompt. Server instructions reach a model
only when its client actually delivers them.
This example does not bind a project original-storage tool; that separate capability
and its credentials must actually be supplied by the trusted project host. It also
does not grant the scientist profile a source connection or caller permission.
The example does not install a CLI or model. `command` is a trusted argument array
with an absolute executable and explicit existing absolute cwd; no shell, task-text
interpolation or caller-supplied argv/env is used. Windows foreground executables
are the verified contract. Use the actual session executable, not a short-lived
launcher that detaches an unobserved worker. Arbitrary background descendants,
instruments, model-specific launchers and external jobs need their own future
adapter; CLI exit proves only this configured foreground session exited.

A child receives Windows/Python runtime environment necessities, explicitly named
model `env_names`, and derived per-session MCP bearer variables. Downstream service
tokens remain in the independently managed MCP process. Windows variable matching is case-insensitive. Host caller tokens and
other source credentials are not inherited unless the trusted configuration
explicitly names them. Keep credentials out of prompts, argv, reports and logs.
MCP visibility/defaults grant no permission; the actual source service checks each
operation. There are no profile CRUD, arbitrary proxy or administrative release APIs.

## Four finite authenticated HTTP routes

All routes require one Bearer token. Unknown fields/duplicate JSON are refused;
launch JSON is bounded to 16384 bytes. Callers cannot select an actor or increase
capacity. Bound requests/responses use `X-Workflow-Service-ID`,
`X-Workflow-Principal-ID` and `X-Workflow-Host-Binding`.

| Route | Result |
| --- | --- |
| GET `/v1/identity` | Persistent `service_id`, `modules=["host"]`, actual `principal_id`, permission/credential-source `principal_binding` |
| POST `/v1/launches` | The finite request below; durable `accepted` and original `run_id`, pre-admission `busy`, explicit `rejected`, or `unknown` on an unconfirmed response |
| GET `/v1/launches/by-request/{request_id}` | Owner-authorized original request/run, claim receipt, spawn intent, PID + Windows creation FILETIME, technical observation/error |
| GET `/v1/status` | `scope="this_host"`, `max_active_runs`, actual `active_runs`, and `by_role` counts; no prompts or credentials |

```json
{"request_id":"req-original-fixed-before-send","rule_id":"manual-inspection","source":{"connection":"queue-b","service_id":"actual-queue-uuid","kind":"queue.task","item_id":"actual-task-id","issue_id":"A"},"role_profile":"experimenter","conditions":{"idle_roles":["scientist"]}}
```

Only `queue.task`, `board.message`, `board.handoff`, `inbox.packet` are supported.
Queue/Board `service_id` comes from their real public identity. Inbox omits it:
IM has no persistent ledger UUID/subject handshake. IM binds the fixed connection,
endpoint, token source/fingerprint and actual packet ID. Swapping IM's backend at
the same URL or reassigning an unchanged token cannot be detected; this host does
not claim otherwise. Optional explicit `revision` must match the source. The host
reads the real item and verifies its type/ID/Issue, permissions and original
content/identity before starting. Reads of Board/Inbox never answer, curate or
publish tasks. No source database is opened by the host.

Queue role/model come from the actual immutable task; a missing task model uses
the configured role default. Explicit mismatches are rejected. For Board/Inbox,
use an allowed explicit role and its configured default model. `conditions` is
optional; its only field is `idle_roles`, an explicit list of configured role
labels (empty is legal). This is a start-time condition, not permanent mutual
exclusion. No fixed role sequence or global machine/other-host idleness is inferred.

## HostClient and original-request recovery

```python
from workflow_orchestrator.host_client import HostClient

client = HostClient.from_connection(
    {"endpoint": "http://127.0.0.1:18104", "token_env": "HOST_CALLER_TOKEN"},
    "D:/run/caller-originals.json",
)
result = client.launch(request)   # caller fixed request_id BEFORE this call
same = client.replay(request["request_id"])
observed = client.by_request(request["request_id"])
status = client.status()
```

The client atomically persists the normalized original body/checksum and send
marker before POST. Rebuild it with the same connection/journal to query or replay.
Changing the body, host store, subject, connection or credential source refuses
transparent recovery. Repeated same content with a deliberately different ID is
a new activation, not recovery. `rule_id` is a caller correlation, not a registry.
A query does not create a run or replay a claim. A replay of an accepted preparation
can resume its original claim/preparation; the host also continues already accepted
preparations itself at startup and in bounded background passes (0.5-second delay
between passes, plus finite source HTTP timeouts). Callers need no additional POST
after conditions clear or the original claim transport recovers. Each pass reuses
the original run, claim and per-run lock; it rechecks the original source/authority
and start conditions. GET remains observation only. Busy originals have no run and
are never admitted by this background mechanism. It does not discover new sources
or apply trigger policy. Existing spawn intents only observe their original execution,
including an intent without durable PID/creation identity; it never retries creation.

| Outcome | Meaning |
| --- | --- |
| `accepted` + request_id/run_id/run | Admission is durable; the run may currently be accepted/running/exited/failed/unknown. It is not a business success. Replays return the same run. |
| `busy` + request_id/reason | No run/claim was created. Original caller/body remains bound, and the same request can be retried later. |
| `rejected` + request_id/error | Explicit pre-admission configuration, authority or identity rejection; no accepted run is disguised as this result. |
| `unknown` + request_id/error | An HTTP or local receipt result is unconfirmed. Query/replay the original identity; do not create a replacement request. |

HTTP rejected requests use their real 4xx status. Temporary errors, HTML, malformed
responses, missing identity headers and lost responses cannot prove no admission
or claim. Accepted-run failures remain visible under the original run. A refused
verification GET before a first POST creates no admission; a previous send retains
its uncertainty when identity/authentication later becomes unavailable. After any
previous send, a failed verification GET (network, temporary/unrecognized response,
authentication or changed identity) retains unknown; that GET cannot establish
whether the earlier POST was accepted. Definitive original-request/POST refusals
and first verification failures before any POST retain their actual meanings.

## Persistence and process facts

Local `BEGIN IMMEDIATE` serializes admission/capacity and start-time conditions.
Accepted/running/unknown records occupy slots, including a spawn intent with no
confirmed process identity. Busy originals have no active run. Conditions are
rechecked immediately before persisting the once-only spawn intent, excluding
that run itself. An intervening role can leave the same accepted run in
`waiting_conditions`; the host's background pass continues that same run when the
condition clears. Explicit original replay and startup share the same safe path.

For Queue the original run persists `claim.body.operation_id`, exact claim path,
source service/subject/body and send marker BEFORE calling the existing finite
claim route. It uses a small host-only HTTP adapter because ToolsClient.write
would generate/send an ID before the run could save it. No Queue protocol, route,
business state or old journal is changed. A lost claim response replays that exact
operation and stores the original receipt. Another claim by the same actor is
`already_claimed`, never ownership proof. Claim failure prevents spawning. A known
claim followed by failed startup stays claimed; no release/reassignment is invented.

Only the execution winning a durable spawn intent can call Popen. An intent with
no PID/creation identity after a crash is `unknown` and is never spawned again.
Known CreateProcess failure is `failed`; a process created but not durably recorded
remains unknown. Foreground PIDs include Windows creation FILETIME. Permission
errors/unreadable OS identity are unknown, not exit. Verified PID reuse or absence
proves the original process is gone but may leave its exit code unknown. A live
owned handle gives the actual code; process signaling also handles code 259
without mistaking it for liveness. Linux/other OS observation is explicitly
unsupported/unknown in this version.

Session `input.json` preserves the original source, work prompt, role/model and
MCP URLs. The host registers an immutable per-run context with each independently
managed MCP service and verifies its downstream endpoint and credential binding.
For Queue sources, this preparation happens after source verification and before
the claim. An unavailable MCP retains the accepted original run for retry without
claiming; a binding mismatch also prevents a new claim. If an earlier attempt
already sent a claim without receiving its receipt, later MCP validation failures
leave that original claim outcome unknown and preserve its operation ID.
The `codex` adapter appends `-c mcp_servers.<surface>=...` to the configured
command and passes per-session bearer values in the child environment. For
`codex exec` it also supplies `--ignore-user-config`; explicitly configure needed
model settings. Trusted project/system configuration may still contribute settings;
check the effective tools in the intended environment. `mcp.toml` records the
non-secret settings for inspection; writing that file alone does not connect Codex.
The caller must arrange for the prompt to consume `WORKFLOW_SESSION_INPUT` if needed.
See [HTTP MCP](HTTP_MCP.md) for startup, recovery and limits.

## Verification scope

`test_launch_host.py` and `test_host_edges.py` use independent Queue/Board/IM/host,
real public HTTP, installed MCP, direct synthetic foreground workers and bounded
persistence/network/OS-observation injections. Test code never substitutes an
in-memory authority, fakes a successful claim/spawn, changes CAS or edits a journal
to make recovery pass. A worker really survives a host stop/restart with the same
creation identity; missing-PID intents remain conservative. Test-only fault wrappers
are not a product API/config option. Every owned process is recorded/closed by
original creation identity; unknown observations are kept separate from paired
cleanup records. Source fixtures initialize only their new isolated test libraries.

Actual model attention, scientific correctness, instruments/external jobs,
cross-physical-machine deployment, push/deployment and Trigger are not verified
by these same-machine multi-address synthetic tests. Existing system/user-site
Python dependencies may be reused; this is not complete dependency isolation.

## Resource catalog

Configure a `catalog` object on each role profile with `role_name`, `responsibility`, `profile_name`, `purpose`, `model_description`, and boolean `queue_consumer`. Text must be bounded and contain no secrets. A principal needs the separate `catalog` action and only sees its allowed `role_profiles`. `GET /v1/catalog` and `/v1/catalog/queue` return this Host’s identity and the complete visible selection; neither grants launch or IM access. The `host` MCP surface can expose `list_host_catalog` through its fixed trusted connection.

Queue tasks fix `experimenter_profile`; a Queue launch cannot override its model. Queue schema 2 and old Listener/Host bindings are not migrated; preserve the original program and state for recovery.
