# Workflow tools

[English documentation](README.md) · [Chinese original](../../orchestration/README.md)

See the [design summary](orchestration-design.md) for responsibilities and boundaries.

The sole command for `issue-workflow-orchestrator` 0.13.8 is `workflow-tools`. Start with `workflow-tools --help` for `serve`, `mcp`, `recover`, `host`, `discover`, and `trigger`. The trusted host stores state, logs, and credentials outside the repository. Install `.[mcp]` for MCP dependencies.

- [Queue](../../orchestration/QUEUE_TOOLS.md): publish, read, claim, reply, and paginate; claiming is not completion.
- [Board](../../orchestration/BOARD_TOOLS.md): ordinary messages and replies, explicit requests, and human instructions.
- [IM and Inbox](../../orchestration/IM_TOOLS.md): save multiple materials, search, and curate through public IM HTTP.
- [Host](../../orchestration/HOST_TOOLS.md): claim and start foreground sessions using trusted profiles, protecting original launch identity.
- [Python listeners](../../orchestration/PYTHON_TRIGGER.md): read-only discovery and ordinary Python condition composition; independent HTTP addresses are supported.
- [Role usage](role-usage.md): optional capabilities and cross-Issue contributions.

MCP is independently started and managed by a trusted host; it does not exit with a Codex session. See [HTTP MCP](../../orchestration/HTTP_MCP.md) for configuration and recovery.

Each MCP surface provides brief module principles in standard Server Instructions; whether these reach the model depends on the client and must be verified in the actual client. Tool lists and server authorization remain separate.

Services can be used independently; ordinary reads and writes do not require a configured trigger or Host. User Python scripts are trusted host code, not configuration authority granted to a model. Historical QueueStore, registered workflows, old role plugins, dashboard, and orchestration snapshots in project packages are unsupported and old environments are not migrated. Successful start or process exit does not prove role attention, scientific conclusions, or external jobs have been validated.

Wheel installation places this page, tool descriptions, and examples under the Python installation prefix's `share/issue-workflow-orchestrator/`. Configure example connection information for the actual services and let the host inject credentials.

