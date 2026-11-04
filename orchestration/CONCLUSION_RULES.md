# Issue 结构化结论规则

每个 Issue 的初始规则是创建时固定的 Issue 类型快照中的 `structured_outputs_schema`，编号为 0。可通过 `list_issue_types` 在创建前查看实际可创建类型和默认规则。获得 `context.read` 与 `issue.write` 的非平台受限主体可为已有 Issue 设置完整的新规则；它只影响该 Issue，不修改类型注册、类型快照或其他 Issue。

例如规则可以是：

```json
{
  "type": "object",
  "properties": {
    "result": {"type": "string", "description": "实际结果"},
    "count": {"type": "integer", "minimum": 0}
  },
  "required": ["result"],
  "additionalProperties": false
}
```

规则必须是对象根，使用内核支持的有限 JSON Schema 子集：`type`、`required`、`properties`、`additionalProperties`、`items`、`enum`、`minimum`、`maximum`、`minItems`、`maxItems` 和 `description`。不支持的关键字被拒绝；规则的规范 JSON 不超过 32 KiB。正文、Evidence 依据和结构化字段一起写入结论，规则要求的字段不能省略。

`inspect_issue` 的 `conclusion_rule` 是当前有效规则，类型快照仍是原始默认规则。`set_conclusion_rule` 保存完整替换规则和理由，服务端按预期规则版本进行并发检查。工具从服务读取当前版本后固定原动作；冲突后先读取再作新的业务决定，响应未知时用 `recover_delivery` 恢复原交付，不改变目标、正文或身份。

规则生效从其提交后的新结论开始。每份结论绑定自己的规则版本及内容哈希，已有结论、Evidence 关系和类型快照不改写。`inspect_issue` 的 `current_rule_comparison` 是当前结论对当前规则的比较，不是历史完整性或科学质量判断。`list_conclusion_history` 返回历史结论及其使用的版本；`read_conclusion_rule` 可读取该版本的规则。

直接 HTTP：`GET /v1/conclusion-rules/types` 分页列出类型；`GET /v1/conclusion-rules/issue/{issue_id}` 读取当前规则，可用 `?revision=N` 读取固定版本；`POST` 同一路径提交 `expected_revision`、`schema` 和 `reason`。写入需要原请求 ID 和幂等键。工作结论写入使用 `expected_rule_revision`，省略表示版本 0；规则变化返回冲突。已提交但响应丢失的原动作按原身份恢复。结论历史由 `GET /v1/browse/conclusions?id=...` 分页提供。

程序校验不评价结论的科学正确性。
