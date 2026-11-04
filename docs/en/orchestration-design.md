# Lightweight orchestration design summary

[English documentation](README.md) · [Chinese original](../../orchestration/DESIGN.md)

This page describes orchestration module responsibilities, composition, and boundaries.

The goal is to help roles record, retrieve, communicate, and continue work. Programs perform reliable mechanical operations; participants make business judgments using evidence. There is no fixed role order and no requirement that every work item form an automatic closed loop.

| Capability | Purpose |
| --- | --- |
| [Queue](../../orchestration/QUEUE_TOOLS.md) | Publish, read, atomically claim, and briefly reply; does not record completion, formal judgment, or acceptance. |
| [Board](../../orchestration/BOARD_TOOLS.md) | Ordinary communication and related replies; explicit requests, answers, and real-human instructions. |
| [IM / Inbox](../../orchestration/IM_TOOLS.md) | Independently submit material, search, expand sources, and curate admission; failures and incomplete results can be saved. |
| [Listener / Python](../../orchestration/PYTHON_TRIGGER.md) | Read-only discovery; the user's trusted ordinary Python script combines conditions and chooses activation. |
| [Host](../../orchestration/HOST_TOOLS.md) | Bounded HTTP admission, source and permission checks, claiming, and foreground process protection. |
| MCP | Wrap existing capabilities and handle defaults, internal action identity, technical retries, and bounded responses. |

Queue, Board, and IM can be used without trigger or Host. Inbox requires no prior Queue task. A session may save multiple times and search or contribute to other Issues within existing permissions; the current focus is a default target and grants no authorization.

New contributions use new action identities. Recover a lost response for the same action using the original target, body, request, and journal. Roles need not create, append, or seal result sets. An unknown action does not generally block other lawful contributions; an unknown process cannot be treated as released.

A script on host A can listen to B over HTTP and request C's Host. Services own their own stores; orchestration accesses IM only by public HTTP and does not read the IM database or credential files. Host state covers only itself; conditions combining sources are observations, not cross-service atomic guarantees. JSON holds static connections, not another policy engine.

A claim proves neither launch nor completion. Host protects original admission, claim, and single foreground launch. Known busy is not admission; unknown recovers the original request. Business completion is traced through IM materials and participant judgments; no automatic unclaim, reassignment, global idle proof, or responsibility settlement is provided.

Actual tool permissions are determined by service and host bindings; profile names, body text, and visible tools cannot expand them. A trusted host injects authentication; do not put credentials in prompts, Git, or reports.

Host is for foreground sessions and does not take over arbitrary background jobs detached from the parent process.

See the [entry point](orchestration.md) and [role usage](role-usage.md). These are optional capabilities, not steps required every session.

