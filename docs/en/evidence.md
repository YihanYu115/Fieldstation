# Evidence and current basis

[English documentation](README.md) · [Chinese original](../EVIDENCE_MANAGEMENT.md)

Evidence is a small contribution that can be independently traced, challenged, replaced, and reused. It can be an observation, calculation, interpretation, theoretical derivation, source material, suggestion, negative result, or open question. Large original data remains on the experimental platform; the ledger stores provenance, bindings, and necessary artifacts.

| Relationship | Current meaning |
| --- | --- |
| `derived_from` | Provenance; source text is not included in full as conclusion evidence by default. |
| `depends_on` | Necessary premise; multiple premises must all be satisfied. |
| `refutes` | An effective source can refute its target; the source participates in the same mixed solve. |
| `challenges` | Entry point to a relevant dispute; does not by itself automatically exclude its target. |

Relations preserve where they were declared and exact endpoint bindings. Within one IM ledger, eligibility is calculated from adopted roots along necessary premises, refuters pointing to targets, and their relevant closure; it is not cut off by the Issue where a relationship was declared. Separate ledgers remain isolated. An expired necessary binding leaves a gap; the consumer cannot be considered valid merely because the mismatched edge no longer takes effect. Cycles remain deterministically undecided; a winner cannot be chosen arbitrarily.

The current conclusion's explicit adopted list R does not accumulate historical references. B(R) is the necessary closure; the body includes only S(R), the closure of valid roots. Failed roots and their causes enter a short gap summary and can be expanded on demand using frozen handles. Still-valid premises cannot masquerade as independently adopted roots.

The appearance of D means only that it is discoverable; D is adopted only after it is explicitly frozen and a new conclusion is saved. Restoring the eligibility of ABC does not overwrite a later conclusion. Ordinary contributions, records of human judgments, and old relationship types do not change current R for you.

Existing Evidence may be split directly within actual authorization: the original and existing packet/fact mappings remain, children have independent identities, and the system records immutable split provenance from each child to the original with the original Evidence version binding. This provenance does not prove that the original was verified or imply a necessary dependency. A curator may explicitly withdraw an original scoped relation, replace it with one targeting a child, or add a relation; unselected relations remain unchanged. Provenance queries distinguish current and historical versions of actual mappings; they do not fabricate facts for children. Platform principals inherit access to children they created only while they can still read the original; independent authorization remains governed by existing rules and other platform principals gain no origin access. Actual evidence changes are handled by existing currentness maintenance; if impact resolution cannot be completed, the entire split rolls back.

New installations use schema 10. The old split-specific ChangeSet interface is retired. Schema 9 and earlier installations are not migrated or automatically taken over; retain the original environment and request/ChangeSet identifiers for unresolved old actions rather than using a new action to impersonate recovery. Unknown responses under the new contract are recovered using the original journal and request identity. See [IM tools](../../orchestration/IM_TOOLS.md) for tools and limits.

Split concurrency checks fix the original's direct relationships and directed dependencies actually used by the resolver. Inability to read unrelated multi-hop nodes does not automatically prohibit a split; permissions are checked for each relation selected for modification. Relation versions read through the tools bind the curator's subsequent choices; if they change, reread and decide again. Provenance queries retain readable items and use an identity-free marker for inaccessible children.

See [unified semantics](calculation-contract.md) for rules and limits and [MCP](mcp.md) for tool access.

