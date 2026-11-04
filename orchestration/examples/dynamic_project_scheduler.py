"""Example project policy: discover Queue, Inbox and addressed Board requests."""

import hashlib
from datetime import datetime


def tree_issue_ids(client, root, max_nodes=128):
    result = []
    pending = [root]
    seen = set()
    while pending:
        issue = pending.pop(0)
        if issue in seen:
            continue
        seen.add(issue)
        result.append(issue)
        if len(result) > max_nodes:
            raise RuntimeError("issue tree exceeds discovery budget; no partial scan")
        cursor = None
        snapshot = None
        while True:
            query = {"limit": 50}
            if cursor is not None:
                query.update(cursor=cursor, expected_snapshot=snapshot)
            page = client.browse_children(issue, **query)
            if snapshot is None:
                snapshot = page.get("snapshot")
            elif page.get("snapshot") != snapshot:
                raise RuntimeError("issue tree page changed; retry from a fresh scan")
            for item in page.get("items", []):
                child = item.get("issue_id") or item.get("issue", {}).get("issue_id")
                if not isinstance(child, str) or not child:
                    raise RuntimeError("child record missing issue_id")
                pending.append(child)
            if not page.get("has_more"):
                break
            cursor = page.get("next_cursor")
            if not cursor or not snapshot:
                raise RuntimeError("incomplete child pagination")
    return result


def watch_key(kind, role, issue):
    return kind + "-" + role + "-" + hashlib.sha256(issue.encode("utf-8")).hexdigest()[:20]


def watch_human_research(tools, issue):
    """Explicit project policy: new human research messages start a scientist."""
    key = "human-research"
    tools.listen(
        key, kind="board.message", connection="board-scientist", issue_id=issue, initial="new_only"
    )
    return key


def human_research_activation(host="host"):
    """Arguments for the original activation; recover with the same action key."""
    return {"host": host, "role_profile": "scientist", "action_key": "initial-scientist"}


def install_watches(tools, issue_ids, worker_roles):
    result = []
    for issue in issue_ids:
        key = watch_key("q", "experimenter", issue)
        tools.listen(key, kind="queue.task", connection="queue-experimenter", issue_id=issue)
        result.append((key, "queue", "experimenter", issue))
        key = watch_key("i", "curator", issue)
        tools.listen(
            key, kind="inbox.packet", connection="im-curator", issue_id=issue, initial="from_start"
        )
        result.append((key, "inbox", "curator", issue))
        for role in ["manager"] + list(worker_roles):
            key = watch_key("h", role, issue)
            tools.listen(
                key,
                kind="board.handoff",
                connection="board-" + role,
                issue_id=issue,
                initial="from_start",
            )
            result.append((key, "handoff", role, issue))
    return result


def candidates(tools, watches):
    out = []
    for key, kind, role, issue in watches:
        for candidate in tools.pending(key, action_key="delivery"):
            record = candidate.get("record", {})
            timestamp = record.get("created_at") or record.get("received_at")
            if not isinstance(timestamp, str):
                raise RuntimeError("candidate lacks source timestamp")
            created = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if created.utcoffset() is None:
                raise RuntimeError("candidate timestamp lacks timezone")
            out.append((created.timestamp(), candidate["source"]["item_id"], kind, role, candidate))
    # Select pending Inbox before other candidates.
    return sorted(out, key=lambda x: (x[2] != "inbox", x[0], x[1], x[2]))
