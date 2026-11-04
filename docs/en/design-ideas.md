# Fieldstation design ideas

Author: Yi-Han Yu

Scientific research can continue for a long time while participants, directions, and conclusions change. Fieldstation explores how people and AI agents can leave contributions that others can pick up across bounded work sessions, without relying on one participant to retain the entire project context.

## Design principles

- **Keep research work continuable.** Issues organize research questions; observations, analyses, sources, and open questions can accumulate. Inbox allows materials to be saved before they are curated.
- **Make evidence relationships and their effects explicit.** Participants declare provenance, necessary dependencies, refutations, or challenges. The system applies explicit rules to calculate evidence eligibility and identify affected conclusions. People and agents remain responsible for judging relationships and scientific conclusions.
- **Keep collaboration tools independently usable.** Queue records tasks, claims, and brief replies; Board holds communication and requests. Ordinary contributions require neither a fixed role sequence nor automation.
- **Make automatic progression optional.** Listener discovers read-only; trusted Python scripts select trigger conditions; Host handles session launches within its configuration and permissions. A claim, a launch, and actual completion are distinct facts.
- **Separate work focus from authorization.** An Issue can organize current context, but does not itself grant or restrict permissions. Participants may contribute to other Issues within their actual permissions.

## Status and limits

Fieldstation is an early research prototype. Its record and calculation mechanisms do not replace scientific judgment. Long-term research outcomes, agent role performance, real device integration, and production deployment remain to be validated. See the [architecture](architecture.md), [evidence documentation](evidence.md), and [calculation contract](calculation-contract.md) for implementation details and limits.

To cite the project, use [CITATION.cff](../../CITATION.cff) in the repository root.
