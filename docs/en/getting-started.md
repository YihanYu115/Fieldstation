# Getting started

[English documentation](README.md) · [Full Chinese source](../START_HERE.md)

Issue Manager `0.9.0rc11` uses schema 10 and `scoped-v2`; the separate orchestration package is `0.13.8`.

1. Create or connect an IM ledger as described in [operations](operations.md).
2. Install the orchestration package if needed and configure [IM tools](../../orchestration/IM_TOOLS.md) and [HTTP MCP](../../orchestration/HTTP_MCP.md).
3. Record observations with sources and explicit necessary relations. Select actual evidence roots when saving a conclusion; Inbox can receive material for later curation.
4. Use [Queue](../../orchestration/QUEUE_TOOLS.md) and [Board](../../orchestration/BOARD_TOOLS.md) as needed. No fixed call sequence is required.
5. For optional automatic session launch, configure a trusted [Python listener script](../../orchestration/PYTHON_TRIGGER.md) and [Host](../../orchestration/HOST_TOOLS.md).

`derived_from` records provenance, `depends_on` a necessary premise, and `refutes` an explicit refutation. Conclusion currentness is not a verdict on scientific truth.

