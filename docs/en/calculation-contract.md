# Unified management semantics: refutation, necessary dependencies, and conclusion material packages

[English documentation](README.md) · [Chinese original](../UNIFIED_MANAGEMENT_SEMANTICS.md)

This document describes the current scoped-v2 calculation contract for evidence eligibility, relationships, and projections of conclusion materials. Participants judge the meaning of evidence and declare relationships; the system calculates according to rules and does not determine scientific truth.

## 1. A single source of truth and four distinctions

Authoritative facts comprise versioned Evidence, relationships within a Scope, references adopted by conclusions, frozen snapshots, and operation history. Participants judge the meaning of content; the kernel maintains projections deterministically. Orchestration and MCP may use only public HTTP and do not create another management ledger or reasoning engine.

Four distinctions matter:

1. **Provenance versus necessary premise:** an analysis having read A does not necessarily mean it requires A to be correct.
2. **Unavailable versus false:** losing a basis can make an argument unavailable, but does not automatically prove the opposite proposition.
3. **Valid versus adopted:** C's record of an instrument fault may be valid but not necessarily needed by a new conclusion that adopts D.
4. **Complete ledger versus default material package:** history remains traceable; this does not mean all history is sent to an Agent each time.

There are no new manually maintained include/exclude, handled, obsolete, restored, or default-hidden labels. Eligibility, reasons, default display placement, and change notices are calculated by the rules below. Results may be cached, but cannot become a second independently editable source of truth.

## 2. Precise definitions of relationships and objects

The following meanings apply only to scoped Evidence relationships under the new rule identity; they do not directly rewrite other domain relationships with the same names or interpretations under old rules.

| Declaration | Precise meaning | Automatic effect |
| --- | --- | --- |
| `B derived_from A` | A is a source used to generate or analyze B. | Preserves provenance; does not by itself require A to be correct or cause refutation. |
| `B depends_on A` | For B's argument to be usable as evidence, A must be currently valid and version-matched. | If A is unavailable, B is unavailable; if A is undecided, B cannot become available on that basis alone. |
| `C refutes A` | C explicitly refutes A. | A is determinately excluded only when C is available. |
| `C challenges A` | C raises a dispute about A that is not yet an explicit refutation. | The relevant dispute is discoverable; A is not directly determined unavailable. |
| `B supports A` | B provides a supporting opinion about A. | Does not automatically cancel a refutation, count as a vote, or become a necessary premise. |
| Other relations | Existing business descriptions such as replication, revision, background, or duplication. | They are not silently promoted to necessary dependencies or refutations. |
| Conclusion.`evidence_refs` | Direct evidence roots R explicitly adopted by the author. | Determines the current conclusion's evidence closure; it is not all material attached to an Issue. |

`impact_policy=hard/soft/informational` remains a measure of maintenance propagation strength; it cannot determine logical truth, necessity, or reviewer count. In particular, not every hard relationship can be treated as `depends_on`. Current code uses both `derived_from` and `depends_on` for discovery closure; the new semantics must distinguish provenance navigation from the necessary-evidence closure.

In the instrument example, express `B derived_from A` and also declare `B depends_on A`. Recording only `derived_from` cannot tell software whether B is an ordinary analysis or a diagnosis that found A unreliable. C may derive from A's instrument log without depending on the validity of A's measurement; C must not therefore be incorrectly declared `depends_on A`.

Multiple `depends_on` relations always mean AND: all are necessary. Two independent arguments B1/B2 should be separated into independently manageable Evidence items, either of which the author can adopt. The first version adds no OR label, does not automatically search for a minimal support set, and does not automatically switch to another argument when one fails. Adopting multiple pieces of evidence means all those references are part of the conclusion's saved basis; any relevant change requires comparison again.

## 3. Snapshots, eligibility graphs, and input completeness

Fix one IM ledger, a finite immutable snapshot X, and the new rule identity. Issues organize discovery and adopted roots. Nodes are argument or observation units bound to precise versions; relations also have fixed identities and versions. A relation's `scope_issue_id` records where it is declared and managed; it does not truncate the eligibility closure from adopted roots within the same ledger. Independent IM ledgers do not query one another.

Notation:

- `Att(x)`: sources y of all structurally valid `y refutes x` relations.
- `Req(x)`: necessary premises explicitly declared by x, in the direction `x depends_on p`.
- `base(x)∈{T,F,?}`: base eligibility calculated from domain lifecycle and binding validation; not a new manual label.

Normal, complete, verifiable current material has base=T; material explicitly disallowed as a current basis has base=F; cases requiring renewed judgment, such as a known expired necessary binding, have base=?. Domain validation determines the mapping; a business Agent cannot fill it in itself.

When an active necessary dependency has mismatched endpoint versions, the obligation that a necessary premise remains unsatisfied must be preserved. The corresponding dependency port may be treated as ?, but the edge cannot simply be dropped to make B an IN node with no premises. Revising or removing a necessary dependency is an explicit business modification with a reason, identity, and version check; it cannot automatically be removed on the user's behalf in the name of system repair. Content versions and necessary dependency declarations must remain atomically consistent.

A mismatched `refutes` relation cannot attack a new version. Return a mismatch diagnostic and stop the old edge from taking effect; do not automatically rebind it. Withdrawing a relationship withdraws a declaration and is distinct from the system calculating that its source is temporarily unavailable. The latter must not alter the relationship's active history.

Missing references, lack of permission to read required inputs, snapshot read failures, and exceeded budgets make the calculation incomplete. The operation must fail closed or return an explicit uncertifiable diagnostic; missing input must not be treated as an empty set to conclude there is “no counterexample.” Report undecided states in a normal graph separately from system failures.

## 4. Unified three-valued least-information fixed point

I means available, O unavailable, and Q undecided. An O node can be directly refuted or have a failed necessary basis; it does not mean its proposition is false.

Starting from `I₀=∅, O₀=∅`, iterate synchronously:

```text
Iₖ₊₁ = Iₖ ∪ {x | base(x)=T ∧ Req(x)⊆Iₖ ∧ Att(x)⊆Oₖ}
Oₖ₊₁ = Oₖ ∪ {x | base(x)=F ∨ Req(x)∩Oₖ≠∅ ∨ Att(x)∩Iₖ≠∅}
Q = V \ (I ∪ O)             # after stabilization
```

Equivalently, in three-valued logic:

```text
usable(x) = base(x) AND (AND usable(p), p∈Req(x))
                      AND (AND NOT usable(a), a∈Att(x))
```

An empty AND is T; NOT ?=?; F AND anything=F; T AND ?=?. Starting with everything unknown, compute the least-information fixed point rather than arbitrarily picking a winner among self-consistent interpretations. Necessity and refutation are solved together: refuter eligibility cannot be fixed first and dependency propagation run separately afterward.

### Properties and limits of the proof

Under the information partial order `?≤T, ?≤F`, the operator is monotone. On a finite graph, starting from all unknowns, it only determines unknowns as T or F; it does not repeatedly reverse decisions within the same snapshot. Each round that makes progress determines at least one node, so there are at most |V| progress-making rounds. The equivalent I/O iteration keeps the sets disjoint. The result is the unique least-information fixed point; other self-consistent but unsupported guesses are not adopted.

The result therefore does not depend on input order, node names, or historical traversal order. Dependency cycles cannot establish their own validity; a winner cannot be arbitrarily chosen in a refutation cycle. External information may determine some or all nodes in a cycle; the entire strongly connected component is not permanently marked undecided.

This guarantees determinism for a fixed snapshot, not that new evidence can never change the result. After an edge is removed or restored, the new snapshot must be solved again. An incremental implementation must be equivalent to a full solve and must not retain old states that have lost their basis. This document does not prove that all business operations are reversible.

## 5. Explanation rules: calculate reasons, do not maintain reason labels

For an O node, return the actual set of reasons: base unavailability, direct refutation by an IN node, and necessary premises that are O. Reasons can coexist; do not discard information by selecting only one. For Q, return unsatisfied necessary bindings, undecided premises or refuters, and relevant cycle entry points.

Determinate states have a solve round and reasons established earlier, permitting finite explanation certificates. Explanation expansion deduplicates node and relationship versions and uses bounded pagination; it does not enumerate exponentially many paths. Cycles are shown as explicit circular references. Reasons are derived server output, not independently editable “invalid/history” labels.

## 6. Three material projections and the current evidence closure

### 6.1 Declared evidence closure B(R) and valid support body S(R)

For a particular conclusion version, the author specifies R=`evidence_refs`. Define:

```text
B(R) = the smallest S such that R⊆S and
       (x∈S and x depends_on p) ⇒ p∈S
```

This is the necessary basis declared by the current conclusion, not all candidate material. It does not automatically expand into a full-text package along `supports`, `derived_from`, or `refutes`. Further define `R_valid=R∩I` and the valid support body `S(R)=B(R_valid)`. Even if a failed root's premises remain independently valid, they cannot thereby masquerade as independently adopted roots supporting the conclusion. Unavailable or undecided roots `R\I` enter the current bounded gap summary, with details expanded on demand; their entire chains are not placed in the valid support body.

When saving a new reliable basis, R and its necessary closure must be IN. New facts after saving can make some roots unavailable; on read, display them in the partitions above and report `needs_update`. Ordinary contributions can record undecided findings; support must not be fabricated merely to pass validation. Old frozen packages do not change with current eligibility.

### 6.2 Eligibility calculation and relevant disputes P(R)

Starting from B(R), recursively collect necessary premises and all sources of `refutes` until closure, yielding the eligibility calculation region V_R. Attach active `challenges` pointing into this region and their explainable provenance and eligibility information to form the relevant-dispute projection. Refutations of refuters must also be included; traversal cannot stop after one level.

The valid support body shows only S(R); current relevant refutations, disputes, and reasons for loss of evidence are provided separately through bounded summaries and expansion entries. Eligibility calculation still starts from the declared closure B(R); detection of recovery cannot stop because a root is temporarily unavailable. The internal calculation graph read to establish eligibility is not sent in full to the model body. `derived_from` provides provenance links; historical source text is not added to the evidence closure by default.

If a counterexample targets a conclusion rather than selected data, it must point to Evidence representing that conclusion's argument or testable claim, so it is included in the relevant-dispute graph. The first version does not infer a target from free-text conclusions; additional claims not registered in conclusion text are outside the automatic completeness guarantee. Selecting only D cannot hide a counterexample explicitly directed at the adopted argument.

### 6.3 Change-handling packages and history

The frozen snapshot saved with a conclusion is the comparison baseline. When the current evidence/dispute projection differs from that baseline, generate bounded differences and causal explanations pointing to the changed object versions. After switching to a new conclusion and new R, its new snapshot becomes the default baseline. Old differences remain in the old conclusion's history and are not permanently copied to the new default package.

Other valid but unadopted material enters a queryable discovery catalog; it is not automatically included in the evidence body and does not automatically make the current conclusion `needs_update`. A new relevant attack or dependency must not be missed because it was absent from the earlier projection. Subscriptions may conservatively cover Scope events; when an event arrives, recalculate the current relevant projection. Only a relevant semantic change alters currentness.

If there is no current conclusion or R has not been specified, provide only a bounded discovery catalog and explicit selection of working materials. The system must not independently treat “all valid material” as the current conclusion's basis.

### 6.4 Sufficiency of current state and independence from history paths

The current material projection depends only on the current authoritative state X, R declared by the current conclusion version, and the rule identity; R is not the union of all historical conclusion references. X must include precise evidence bindings, current active relationships, and obligations for unsatisfied necessary bindings; retaining only IN material is insufficient. If two operation histories produce the same inputs, their current support body, eligibility, and gap projections must be the same. Log order, previous session conversations, and old caches cannot participate in the decision. Audit events and operation receipts themselves may differ.

A change summary also explicitly depends on the frozen baseline X₀ saved with the current conclusion. That baseline is currently readable persistent state, not a memory reconstructed temporarily from conversations or operation history. Comparison of change summaries for the same current state must also fix the same baseline. Historical audits and reproduction of old packages are separate queries; their contents are not merged into the default current package.

If D appears but has not yet been adopted by the current conclusion, D only enters the discovery catalog and the current root remains B. When C has made A/B unavailable, the valid support body is empty. By default, return a short summary that “the currently adopted B lost its basis because of A's instrument fault,” with ABC expansion references. ABC leaves the default relevant diagnostics only after a new conclusion explicitly changes to independent D. These steps are calculated entirely from current state; no intelligent curator is required to hide history.

## 7. Complete rules for the ABC→D scenario

1. Old conclusion K1 adopts B: `R1={B}`; B depends_on A, so the body is `{B,A}`.
2. C records an instrument fault in A's experiment; C refutes A. C is IN, A is O/direct_refutation, and B is O/necessary_basis_failed. K1 becomes `needs_update`; the change summary explains C→A→B; the original frozen package is unchanged.
3. The author forms K2 from independent D, explicitly setting `R2={D}`. If D does not depend on ABC and ABC does not refute D or its adopted argument, the body is `{D}`; ABC is absent from default relevant disputes and change summaries, but history remains queryable.
4. Later changes only to unrelated ABC relationships should not invalidate K2. If C refutes D is added, it is automatically included again in the relevant projection and affects K2; it cannot be hidden by saying it “entered history.”
5. If E validly refutes C, A and B can regain eligibility, but the system does not automatically switch K2 back to K1 or force ABC back into D's body. Whether to adopt B again is a new content judgment.

This preserves all history while displaying only material necessary for the current conclusion, without requiring an intelligent curator repeatedly to move or hide items.

## 8. Versions, currentness, and atomic handoff

Define conclusion comparison projection `K_R(X)` to include the new rule identity, conclusion target, R, bindings in B(R), the necessary/refutation subgraph and states that determine eligibility, versioned summaries of relevant disputes, and exact upstream bindings already required to be retained. Serialization order is normalized. Unrelated Scope content, display pages or budgets, and the current conclusion head pointing to itself are not part of this evidence fingerprint.

After snapshot X₀ is saved, local mismatch is caused by `K_R(X) != K_R(X₀)` or inability to calculate the complete projection. Cross-Issue propagation continues to use `Dirty=Reach_G(L)`. Broad Scope subscriptions only discover possible impacts; not every Scope write can directly be equated with a conclusion mismatch.

Do not reduce the fingerprint to a hash of body IDs alone: changes in an undisplayed attack chain can also change evidence eligibility. It is permissible to conservatively trigger rechecks for changes in the relevant projection, but unrelated historical updates to ABC must not permanently restart processing for D.

A request to freeze materials must explicitly distinguish discovery from an evidence freeze with R. The `evidence_refs` saved for a conclusion must equal R in the frozen descriptor; checking only that they are a subset of a larger package is insufficient. Atomic submission verifies that package, view, Issue, rule, and version still match, then saves the new conclusion, receipt, and head. When changing to D, the comparison baseline frozen for ABC cannot be reused.

Reuse freeze_id, action_id, CAS, idempotency, permissions, and history mechanisms. Preparing a new action performs no domain write; repeated intent does not change the saved conclusion head. Old packages are read under their old rule identity. The new rule uses `context-currentness/scoped-v2`; its semantics are not silently substituted under the scoped-v1 name.

## 9. Rule examples and invariants

| ID | Case | Required result |
| --- | --- | --- |
| U01 | Pure refutation chain C→B→A | A/C IN, B O; the same algorithm handles longer chains. |
| U02 | Multiple independent counterexamples; only one is defeated | Remaining IN counterexamples continue to exclude the target. |
| U03 | Refutation cycle, odd cycle, self-loop | Undecided and terminating; an external valid counterexample can break the cycle. |
| U04 | B necessarily depends on A; C refutes A | A/B unavailable; B's reason is loss of basis. |
| U05 | In U04, B refutes D | B no longer excludes D. |
| U06 | Add E refutes C to U04 | A/B recover; later conclusion choices are not overwritten. |
| U07 | B depends on A1 and A2; A1 fails | The AND premises are unsatisfied; B is unavailable. |
| U08 | B only derived_from A; A fails | The provenance relation alone does not directly make B unavailable. |
| U09 | A/B necessary-dependency cycle; mixed self-argument cycle | Cannot establish IN by itself; conservatively undecided. |
| U10 | Necessary premise binding has expired | Cannot promote the consumer to IN by dropping the mismatched edge. |
| U11 | ABC→D, later ABC changes, and a new attack targets D | Default body contains only D; unrelated updates do not invalidate it; the new attack must be discoverable. |
| U12 | Reordering, duplicate facts, withdrawal and restoration, unrelated ledgers, or materials outside the adopted-root relevant closure | Results are deterministic and each effect is restored appropriately; ledger and closure boundaries isolate material, while Issue placement does not isolate same-ledger eligibility. |
| U13 | Large-graph budget exhaustion, missing references, or lack of permission | Do not produce a falsely complete package or overwrite an old valid snapshot. |
| U14 | HTTP/MCP atomic submission, replay, or old freeze_id | Preserve permissions, CAS, idempotency, atomicity, and old snapshots. |
| U15 | Different operation histories reach the same current semantic state, R, rule, and frozen baseline | Support body, eligibility, gaps, and change projections are the same; audit logs may differ. |
| U16 | C refutes A, B depends on A; D is absent or present but unadopted | The support body is empty; provide only a bounded gap summary and expansion entry for current failed roots, without dumping all ABC text or history. |
| U17 | A root fails but some premises remain valid | Those premises cannot masquerade as independently supporting roots; when another adopted root remains valid, show only its necessary closure. |

## 10. Explicit exclusions

The system does not infer the truth of natural language, automatically choose an optimal conclusion, or decide by counting supporting votes. It does not automatically turn `derived_from` into a necessary dependency, implement arbitrary AND/OR formulas or automatic argument search, or add manual status labels, automatic review roles, or a general-purpose proxy.

For implementation responsibilities, see [architecture](architecture.md); validate changes as described in [contributing](contributing.md).

