# Project maintenance guidance

[English documentation](README.md) · [Chinese original](../../AGENTS.md)

Read [architecture](architecture.md), [evidence management](evidence.md), and the [calculation contract](calculation-contract.md), plus relevant module documentation for the task.

- Save text as UTF-8 without BOM and preserve existing user changes.
- IM owns domain authorization, versions, transactions, idempotency, and history; orchestration accesses IM only through public HTTP.
- Distinguish authorization, work delegation, contributions, business judgment, and process state. Queue, Board, and Inbox are usable without automatic launch.
- Interface changes should check definitions, clients, MCP, configuration examples, and usage together; retain permission, concurrency, transaction, and original-action recovery protections.
- Keep project data, credentials, runtime databases, and build outputs outside the source tree. Do not commit keys or real business data.

