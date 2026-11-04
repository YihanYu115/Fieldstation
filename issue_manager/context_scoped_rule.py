"""Immutable definitions for the scoped currentness contracts."""

from __future__ import annotations

import hashlib

from .store import canonical_json

SCOPED_V2_RULE_ID = "context-currentness/scoped-v2"

SCOPED_V2_RULE_DEFINITION = {
    "version": SCOPED_V2_RULE_ID,
    "binding": "evidence-binding/v1",
    "truth_values": ["T", "F", "?"],
    "base_state_source": "domain-lifecycle-and-binding-validation",
    "graph_selection": "same-ledger-root-relevant-closure;scope-issue-is-declaration-location",
    "relations": {
        "depends_on": "necessary-and",
        "derived_from": "provenance-only",
        "refutes": "mixed-fixed-point-attacker",
        "challenges": "related-diagnostic-only",
    },
    "mismatched_dependency": "explicit-unknown-obligation",
    "mismatched_refutation": "diagnostic-without-rebind",
    "projection": "basis-support-qualification-discovery/v1",
    "comparison": "scoped-currentness/v2",
    "empty_scope": "subscribe-to-scope-head",
    "resource_limits": {"max_nodes": 1000, "max_relations": 5000,
                         "default_page_bytes": 32768, "max_page_bytes": 131072},
}


def scoped_v2_rule_id() -> str:
    return SCOPED_V2_RULE_ID + ":" + hashlib.sha256(
        canonical_json(SCOPED_V2_RULE_DEFINITION).encode("utf-8")
    ).hexdigest()
