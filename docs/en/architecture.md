# Code architecture and maintenance boundaries

[English documentation](README.md) · [Chinese original](../WORKFLOW_ARCHITECTURE.md)

The current versions are IM `0.9.0rc11` / schema **10** / `scoped-v2` and the independent orchestration package `0.13.8`. See [workflow tools](orchestration.md) for entry points.

IM is authoritative for identity, authorization, Issues, Evidence, relationships, versions, domain transactions, and history. The orchestration package uses IM only via public HTTP: it does not import the kernel or read the IM SQLite database, ledger, or credentials file. The host binds endpoints and authentication; runtime directories are outside the source tree.

Queue records the explicitly selected experimenter profile, tasks, claims, and short replies. Host's restricted catalog displays role responsibilities and configurations according to principal permissions; visibility does not grant launch or IM permissions. Board stores ordinary communications, explicit requests and answers, and instructions from real humans. Inbox and curation history belong to IM. These are independently usable without listening or launch services. Claims, contributions, judgments, and execution state are recorded separately; message delivery does not equal business completion.

When browsing known IM objects the service checks actual read permissions rather than using a single browsing root. Original-access descriptions are resolved according to the actual project and frozen versions. Queue, Board, and Host do not use Issue allowlists for authorization. Board messages can be queried for one Issue, an Issue subtree via IM's public interface, or all Issues. Subtree pagination binds the IM snapshot and Board watermark and rejects continuation if they change; Queue lists return continuation entries preserving query filters.

A read-only Listener discovers Queue, Board, or Inbox records; a trusted ordinary Python script selects conditions and decides whether to request activation. Host verifies bindings, source, permissions, capacity, and optional local-idle conditions, fixes the original claim intent, and starts at most one foreground session. Unknown original actions retain their identity for recovery; known busy does not constitute admission. Cross-service conditions are observations, not cross-service atomic guarantees.

IM writes remain protected by authorization, scope, CAS, transactions, and idempotency. New contributions use new action identities; recovery cannot change the original body, target, or request. Services at different addresses communicate through bounded HTTP rather than sharing databases. `workflow-tools` is the sole orchestration console; MCP provides bounded business tools, not an arbitrary proxy. A trusted host independently runs Streamable HTTP MCP; Host registers restricted session context and assembles the URL and credential environment variable name into the Codex command. The existing client journal handles original-action recovery; unknown responses are not deduplicated by body.

The project package supports IM-only export, preflight, and installation into a new directory; authentication is rebuilt and execution isolated. Old QueueStore components, dashboard, and old host runtime directories are not migrated or taken over. See [project packages](project-package.md).

Long-term outcomes in real research, model and device connections, physical cross-machine operation, and deployment require separate validation.

