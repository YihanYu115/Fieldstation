# Contributing

[English documentation](README.md) · [Full Chinese source](../../CONTRIBUTING.md)

Fieldstation is a research prototype. Read the [architecture](architecture.md), [evidence management](evidence.md), and [calculation contract](calculation-contract.md), and consult the corresponding [tool documentation](orchestration.md) for the modules involved.

Keep domain authorization, versions, transactions, and history in IM; orchestration accesses IM through public HTTP. Queue, Board, and Inbox remain usable independently. Distinguish authorization, work delegation, contributions, business judgments, and process state.

Use Python 3.11 or newer and UTF-8 without BOM for new text. Keep project data, credentials, runtime databases, and build output outside the source tree. Do not commit secrets or real project data. When changing interfaces, review definitions, clients, MCP, configuration examples, documentation, and relevant tests.

