# Structured conclusion rules for Issues

[English documentation](README.md) · Chinese originals: [IM](../CONCLUSION_RULES.md), [orchestration](../../orchestration/CONCLUSION_RULES.md)

Each Issue's initial rule is `structured_outputs_schema` in the Issue-type snapshot fixed when the Issue was created, numbered revision 0. Use `list_issue_types` before creation to see available types and default rules. A non-platform-restricted principal with `context.read` and `issue.write` may set a complete new rule on an existing Issue; it affects that Issue only and does not modify the type registry, the type snapshot, or other Issues.

For example:

```json
{
  "type": "object",
  "properties": {
    "result": {"type": "string", "description": "Actual result"},
    "count": {"type": "integer", "minimum": 0}
  },
  "required": ["result"],
  "additionalProperties": false
}
```

The rule must have an object root and use the finite JSON Schema subset supported by the kernel: `type`, `required`, `properties`, `additionalProperties`, `items`, `enum`, `minimum`, `maximum`, `minItems`, `maxItems`, and `description`. Unsupported keywords are rejected; the canonical JSON rule must be at most 32 KiB. The body, Evidence basis, and structured fields are saved together in the conclusion; required fields cannot be omitted.

The `conclusion_rule` returned by `inspect_issue` is the currently effective rule; the type snapshot remains the original default. `set_conclusion_rule` saves a complete replacement and a reason; the server performs concurrency checks against the expected rule revision. The tool reads the current revision and then fixes the original action. After a conflict, reread and make a new business decision; if the response is unknown, use `recover_delivery` to recover the original delivery without changing target, body, or identity.

The rule applies to new conclusions submitted after it takes effect. Each conclusion binds its own rule revision and content hash; existing conclusions, Evidence relations, and type snapshots are not rewritten. `current_rule_comparison` in `inspect_issue` compares the current conclusion against the current rule; it is not a judgment of historical integrity or scientific quality. `list_conclusion_history` returns historical conclusions and their revisions; `read_conclusion_rule` reads a particular revision.

Direct HTTP: `GET /v1/conclusion-rules/types` lists types with pagination; `GET /v1/conclusion-rules/issue/{issue_id}` reads the current rule, and `?revision=N` reads a fixed revision; `POST` to the same path submits `expected_revision`, `schema`, and `reason`. Writes require the original request ID and idempotency key. Working-conclusion writes use `expected_rule_revision`; omission means revision 0. A rule change produces a conflict. A committed original action whose response was lost is recovered under the original identity. Conclusion history is paged through `GET /v1/browse/conclusions?id=...`.

Program validation does not evaluate the scientific correctness of a conclusion.

