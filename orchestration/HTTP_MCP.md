# Independently managed Streamable HTTP MCP

Install the `mcp` extra. For each trusted downstream principal and surface, start
one long-lived service from a supervisor outside Codex. Keep its action journal,
session registry and session journals outside the checkout. For example:

```text
workflow-tools mcp --profile D:/run/queue-profile.json --registry D:/run/queue-sessions.json --host 127.0.0.1 --port 18111 --token-env MCP_QUEUE_ACCESS
```

The supervisor injects `MCP_QUEUE_ACCESS` and the downstream token named in the
profile. A standard Streamable HTTP MCP client connects to `http://127.0.0.1:18111/mcp`
with the bearer token. Use high-entropy, distinct access tokens, registries and journals for
different surfaces and principals. The listener only accepts loopback IPs; a remote
trusted host requires an independently configured HTTPS proxy and access controls.
Do not place credentials in the profile, prompt, command line, Git or logs. Stopping
a client does not stop this service.

For the read-only Host catalog, use a separate `host` surface with a fixed trusted
connection and a downstream principal authorized for `catalog`:

```json
{"surface":"host", "connection":{"endpoint":"http://127.0.0.1:18104", "token_env":"HOST_CATALOG_TOKEN"},
 "tools":["list_host_catalog"], "journal_path":"D:/run/catalog-unused-actions.json"}
```

The same session registration mechanism may select `list_host_catalog`; the tool
accepts only an optional boolean `queue_only`, never an endpoint or credential.
It performs read-only requests without creating an action journal. An unavailable
Host is an error, not an empty or global catalog. A single role may bind multiple
`host` MCP entries. Give each a distinct trusted `name`, connection, MCP URL,
and access-token environment name; the name becomes the session's MCP server
name. For example:

```json
{"surface":"host", "name":"host_a", "connection":"catalog_a", "tools":["list_host_catalog"], "http_url":"http://127.0.0.1:18114/mcp", "http_token_env":"MCP_HOST_A"}
```

Add a second entry with a different name and trusted connection for Host B. Each
service must be independently configured and authorized; identify returned
catalogs by `service_id`. One Host failing does not turn its result into an empty
catalog or establish the availability of another Host.

The base endpoint exposes exactly the configured surface and tool subset with its
configured defaults. Host can register a narrower subset with a fixed Issue and,
for Queue, a task. Each registered context gets its own derived bearer token and
journal. Registration is immutable for the same session ID and survives service
restart. The service profile and registry bindings must remain unchanged for
original recovery; use a new runtime for new bindings. The downstream service still
checks the actual principal, permission, version and scope on every action.

When the downstream connection is unavailable, initialization or a call may fail.
Reads can be retried. For an uncertain write with a returned original operation
or delivery ID, use the existing journal recovery path; do not submit new identical
content as a substitute. Queue and Board can be recovered by a trusted operator with
`workflow-tools recover --profile <original-profile> --operation-id <original-id>`;
for Host sessions supply the original service profile, registry, access-token
variable and session ID (the Host run ID followed by `-queue` or `-board`):

```text
workflow-tools recover --profile D:/run/queue-profile.json --operation-id ORIGINAL_ID --registry D:/run/queue-sessions.json --session-id ORIGINAL_RUN_ID-queue --token-env MCP_QUEUE_ACCESS
```

The command resolves the original session journal; it does not create a new action.
IM also exposes `recover_delivery` when allowed in the profile. Restarting and reconnecting to the same bound session
attempts recovery of pending journal entries; a temporary failure is preserved.

A client disconnect does not establish that a submitted write failed. The service
lets a started handler finish and the journal retains actions that reached it, but a
lost client response cannot always be correlated uniquely with a particular call.
An unavailable journal, abrupt service termination before an intent was durably
recorded, and changed bindings must not be treated as proof of success or failure.
Identical body text is never a deduplication key. IM does not provide a persistent
ledger identity; replacement behind the same address and credentials is not
necessarily detectable. No manual identity verification is added as a condition of
the existing IM original-action recovery.

These interfaces do not establish real model attention, scientific quality,
physical cross-machine operation or deployment. The service does not install or
start a model, and the Host does not turn a successful claim into business completion.
