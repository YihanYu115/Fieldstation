"""Pure impact planning for the Evidence relation graph.

The planner intentionally knows nothing about persistence, governance, review,
HTTP, or orchestration.  Callers provide a frozen relation graph and the
already-resolved Issue/Conclusion targets for each consumer Evidence.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Iterable, Mapping


def plan_change(
    provider_evidence_id: str,
    *,
    relations: Iterable[Mapping[str, Any]],
    affected_targets: Mapping[str, Iterable[Mapping[str, Any]]],
    provider_issue_ids: Mapping[str, str | None],
    source_event_type: str,
    source_event_id: str | None = None,
    delta_relation: Mapping[str, Any] | None = None,
    maximum_nodes: int = 200,
) -> list[dict[str, Any]]:
    """Return deterministic impact facts for one Evidence change.

    ``relations`` and ``affected_targets`` are treated as immutable snapshots.
    Hard edges extend the provider-to-consumer traversal; soft edges produce a
    direct impact only and informational edges are not propagation edges.
    """

    delta_id = str(delta_relation["relation_id"]) if delta_relation else None
    by_provider: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for relation in relations:
        if delta_id and str(relation["relation_id"]) == delta_id:
            continue
        if not relation.get("active") or relation.get("impact_policy") not in {
            "hard",
            "soft",
        }:
            continue
        by_provider[str(relation["provider_evidence_id"])].append(relation)
    for candidates in by_provider.values():
        candidates.sort(key=lambda row: str(row["relation_id"]))

    impacts: list[dict[str, Any]] = []
    queue: deque[str] = deque()
    seen: set[str] = set()

    def visit(provider_id: str, relation: Mapping[str, Any]) -> None:
        consumer_id = str(relation["consumer_evidence_id"])
        targets = list(affected_targets.get(consumer_id, ()))
        if not targets:
            targets = [{"issue_id": None, "conclusion_id": None}]
        targets.sort(
            key=lambda target: (
                str(target.get("issue_id") or ""),
                str(target.get("conclusion_id") or ""),
            )
        )
        for target in targets:
            impacts.append(
                {
                    "source_event_type": source_event_type,
                    "source_event_id": source_event_id,
                    "relation_id": str(relation["relation_id"]),
                    "provider_evidence_id": provider_id,
                    "consumer_evidence_id": consumer_id,
                    "affected_issue_id": target.get("issue_id"),
                    "affected_conclusion_id": target.get("conclusion_id"),
                    "trigger_issue_id": provider_issue_ids.get(provider_id),
                    "impact_policy": str(relation["impact_policy"]),
                    "relation_type": str(relation["relation_type"]),
                    "rationale": str(relation.get("rationale", "")),
                }
            )
        if relation["impact_policy"] == "hard":
            queue.append(consumer_id)

    if delta_relation is not None:
        if not delta_relation.get("active"):
            raise ValueError("Lifecycle delta relation must be active in the planning snapshot")
        if str(delta_relation["provider_evidence_id"]) != provider_evidence_id:
            raise ValueError("Lifecycle delta provider does not match the propagation root")
        if delta_relation.get("impact_policy") in {"hard", "soft"}:
            visit(provider_evidence_id, delta_relation)
    else:
        queue.append(provider_evidence_id)

    while queue:
        provider_id = queue.popleft()
        if provider_id in seen:
            continue
        seen.add(provider_id)
        if len(seen) > maximum_nodes:
            raise ValueError(
                f"Evidence propagation exceeds maximum closure of {maximum_nodes} nodes"
            )
        for relation in by_provider.get(provider_id, ()):
            visit(provider_id, relation)
    return impacts
