# Field Inbox HTTP 契约

本文介绍 Field Inbox 的 HTTP 入口、原文记录、整理入账与来源绑定。

Field Inbox 保存现场不可变 packet、整理员创建的 `fact_ref`、初版映射、显式 scoped 关系和追加式复核交接。收件不创建 Evidence、关系或 currentness 变化。内核独占权威状态，编排层仅通过公开 HTTP 调用。

## 身份与写请求

所有写请求使用 `Authorization: Bearer ...`、宿主稳定的 `X-Request-ID` 和 `Idempotency-Key`。相同身份与 body 重放原领域回执并标记 `idempotent_replay: true`；不同 body 冲突。失败时领域写入整体回滚。Manager 通用 API 请求账本仍负责 request ID 与幂等键的外层约束。

## 收取现场原文

`POST /v1/field-packets` 需要 `intake.submit`。Issue ID 由宿主注入；现场工具只要求 `content`。来源和附件声明可省略。

```json
{
  "issue_id": "ISSUE-42",
  "content": "曲线 A 出现平台。按本次参数得到加载计算 B=2.50 s。我怀疑输入负载影响了判断 H，但目前只能提出疑问。",
  "sources": [{"locator": "run://P1/curve-A", "provided_text": "曲线 A 出现平台。"}],
  "attachment_refs": ["sha256:declared-reference"]
}
```

`content` 为 1–80,000 字符；整个规范化请求最多 200,000 UTF-8 字节。`sources` 最多 16 项，每项必须提供非空 `locator` 与 `provided_text`；附件引用最多 128 项。未知字段（包括 v3 的 `facts`、`references`、`kind`）明确拒绝。附件字符串只作为声明保存，不代表内容校验。

`content` 是现场提交者本轮写下的记录，可包含其新观察、判断、补充说明与未决点，不要求与宿主给出的原料逐字相同。`sources[].provided_text` 保留提交者声明的外部原文；读取 packet 时返回 `created_by`，以便整理员区分 packet 提交者的表述与声明来源。两者均不自动构成已核验事实。整理员按来源锚点和内容边界决定哪些项可独立入账，流程说明可以留在 packet 而不必升为 Evidence。

回执仅为：

```json
{"status":"received","packet_id":"fp_…","content_sha256":"…","idempotent_replay":false}
```

packet 原文、来源与附件不可变。空来源不表示来源已核验。收件阶段不生成 fact_ref、Evidence、mapping 或关系。

## 附件引用的无损契约

`attachment_refs[]` 与 attachment origin 的 `attachment_ref` 是项目声明的原字符串，非全空白，最多2048 Unicode码点，必须可编码为UTF-8。登记与贡献使用同样的 locator 控制字符规则：拒绝 NUL 和除 tab 之外的 Cc 字符。保留前后/连续空格、大小写、组合字符、非BMP、反斜杠、百分号编码、query和fragment；不trim、折叠、Unicode规范化、解码URL或resolve路径。新登记会拒绝此前可能收件但无法作为来源入账的非法控制字符；不迁移旧packet。

支持Windows/UNC/POSIX/项目相对路径、file/HTTP(S)/对象存储URI、项目自定义标识、内容/版本标识及归档成员引用；没有scheme白名单。贡献和review中的引用必须与本packet登记值逐字符相等。不同斜杠、Unicode形式或query是不同声明，不能模糊匹配。

```json
{"type":"attachment","attachment_ref":"project-record:run-17/raw-data","part_locator":"CSV rows 2-3","quoted_text":"可选的原样声明引文\r\n"}
```

`part_locator` 非全空白，最多2048码点，使用同样的UTF-8/locator控制字符校验。可选`quoted_text`提供时非全空白，最多4000码点，保留Unicode/CRLF并检查UTF-8编码。贡献的source_locator及Evidence的declared_source_locator保存精确附件引用；Evidence内部locator保持独立的领域身份。同一地址的两个片段可以创建不同fact/Evidence。

`local_position_verified`仅由服务器在读回附件来源中产出`false`；公开写入提供true、false、0、null或其他值均按未知字段拒绝。API使用内核进程内的规范化类型交接，事务重新按权威packet核对全部锚点；普通JSON不能制造该类型。正文/source_text的推断start和旧幂等payload保持原格式，不需要schema升级。

IM不打开文件、共享盘、归档或URL，不检查原件存在性、访问权限、hash或引文真实性。项目/宿主提供原件读取；读取成功与来源入账分别验收。无法读取的已登记附件仍可保存声明与review缺口，入账不等于上传或科学核验。收件仍受200000规范化UTF-8字节及128附件引用的预算限制。

附件字段拒绝含`details.origin_contract=field-origin/v1`及有界`fields[].path/rule`，不回显地址、query、正文、凭据或堆栈。MCP仅转发识别的有限路径/规则（最多8项），保留code/layer/operation/effect/phase/delivery_id。401/403需要宿主处理；408/425/429/5xx和丢响应仍为unknown，按原身份恢复。确认拒绝的旧journal仍是拒绝，更正需要新意图。

## 整理单项并原子入账

`POST /v1/field-packets/{packet_id}/curated-items` 需要 `evidence.write`；存在正式关系时还需 `evidence.relation.write`。整理员提交：

```json
{
  "issue_id":"ISSUE-42",
  "expected_curation_version":0,
  "description":"曲线 A 在本次测量中出现平台",
  "kind":"observation",
  "origin":{"type":"packet_text","quoted_text":"曲线 A 出现平台。"},
  "reason":"按现场原文拆出可独立核查的观察",
  "related_evidence":[]
}
```

`kind` 只允许 `observation`、`interpretation`，表示内容形态而非真伪或置信度。`description` 应保留现场限定与不确定措辞。`related_evidence` 最多 8 项，每项显式声明可读取目标、关系类型和理由；目标可为 Evidence ID 或已有映射的 `fact_ref`，不要求与 packet 同 Issue 登记。关系 `scope_issue_id` 是新贡献的声明/管理位置，不改变同一账本内的资格图选择。程序不从原文推断关系。

来源锚点支持三种有限形状：

- `packet_text`：`quoted_text` 必须是 packet 原文的非空连续子串；可提交 Unicode 码点 `start`，否则只接受唯一匹配。
- `source_text`：额外提交本 packet 的 `source_index`；引文必须在对应 `provided_text` 中精确匹配。可提交 Unicode 码点 `start`，否则只接受唯一匹配。
- `attachment`：`attachment_ref` 必须属于本 packet，`part_locator` 非空且有界。它只证明附件归属，局部位置是整理员声明，不表示机器核验。

同一事务创建不可变 fact、Evidence、初版 `fact_ref→Evidence` 映射、显式 scoped 关系、审计与递增后的 packet curation version。任一失败整体回滚。回执包含 `fact_ref`、Evidence ID、mapping ID、关系 ID、来源锚点/locator、`curation_version` 和 `atomic:true`。`expected_curation_version` 由宿主根据最新读取值装配；CAS 冲突后必须重读并重新判断。

## 复核交接

`POST /v1/field-packets/{packet_id}/reviews` 需要 `evidence.write`。`handled_fact_refs` 必须属于该 packet；`unresolved` 保存经同样校验的原文/来源/附件锚点与缺口原因。两数组最多 100 项，文本有界。允许空缺口列表，但不证明原文无遗漏。复核回执带作者、时间和版本，追加不可变历史；仅推进 packet curation head，不写 Evidence、关系或 currentness。

## 读取、分页与权限

读取均需要 `context.read`：

- `GET /v1/field-packets?issue_id=…&limit=20&after_packet_id=…`：有界列举。
- `GET /v1/field-packets/{packet_id}`：原文、声明来源与附件、`curation_version`、已整理数量和最近复核摘要；不内嵌无界条目历史。
- `GET /v1/field-packets/{packet_id}/curated-items?limit=20&after_fact_ref=…`：有界条目分页。
- `GET /v1/field-packets/{packet_id}/reviews?limit=20&before_version=…`：有界复核历史。
- `GET /v1/field-facts/{fact_ref}` 与 `/mappings?limit=20&before_version=…`：读取精确来源和映射历史。
- `GET /v1/field-packets/{packet_id}/summary?review_id=…`：返回 packet 内容 hash、source 目录、fact/current mapping 计数、kind 计数和 curation version；可选的不可变 review 统计在同一只读事务内聚合。统计口径明确区分所有 fact 与当前映射，不解释 review 自然语言。
- `GET /v1/field-packets/{packet_id}/text?source_index=…&start=…&max_bytes=…&content_sha256=…`：读取 packet_text（省略 source_index）或登记的 source `provided_text` 的一页。页预算默认为 8 KiB、范围 256 B–16 KiB；start/next_cursor 是 Python Unicode 码点位置，正文 hash 固定本来源完整内容。
- `GET /v1/field-packets/{packet_id}/locate?source_index=…&quoted_text=…&after_start=…&limit=…`：在完整选定来源内按码点位置查找，允许重叠命中；候选最多 8 项/页。只有全部候选已读且恰有一个命中时才报告 unique。
- `GET /v1/field-packets/{packet_id}/review?review_id=…&after_handled=…&after_unresolved=…&max_bytes=…&expected_curation_version=…`：按字节预算分页读取不可变 review 的 handled 与 unresolved 两个集合，各自返回游标和数量；expected version 变化时拒绝续页。
- `GET /v1/field-packets/{packet_id}/facts/{fact_ref}`：只在路径指定 packet 内查找 fact，禁止通过全局 fact ID 先取回隐藏内容。
- curated-items 支持 `max_bytes` 256 B–16 KiB；长描述返回标明不完整的摘要与 `read_field_fact` 引用。

## 单来源当前 scoped relation 读取

`GET /v1/scoped-evidence-relations?scope_issue_id=…&source_evidence_id=…&limit=…&max_bytes=…&cursor=…&expected_snapshot=…` 是通用关系服务的有界单源查询。scope 与 source 必填；`limit` 为 1–8，`max_bytes` 为 256–16384 UTF-8 字节，超限直接返回 400。`cursor` 是服务端不透明快照游标；续页也可传 `expected_snapshot`。游标、快照、source 或 scope 不接受替代猜测。

响应按 relation ID 排序，读取每条关系当前 head，包含启用和停用记录；不拼接历史版本。每项含 relation/version ID、revision、scope、source/target Evidence ID、relation type、完整 rationale、active、source/target binding 身份和 `binding_current`。绑定变化不会过滤掉该记录。快照覆盖当前关系集合、当前版本及两端 binding；关系集合、版本或任一端 binding 改变后，续页返回 conflict，要求从首屏重读。单源扫描最多 5000 条；响应预算不足时返回可由 Field Inbox 有限只读工具执行的单关系引用，不能截断 rationale 或把不完整结果标作 complete。

读取要求 `context.read`，服务端逐项检查 source 与 target 的 Evidence 读取权限；任一 target 不可读时整页拒绝，不泄露关系元数据。此 API 不读取 target 正文、不扫描关系图，也不改变关系、binding 或 scoped-v2 资格。`binding_current` 只表示关系保存的端点身份仍匹配当前端点状态。

`read_field_fact` 在原 fact/mapping 响应外附 `relation_page` 首屏；`read_field_fact_relations(packet_id, fact_ref, ...)` 续页固定使用宿主可见 packet 的当前 mapping，不接受用户指定 scope 或 source Evidence。它先经 packet-scoped HTTP 读当前 fact/mapping，再调用上面的通用 API，最后重读 mapping；服务端的独立 HTTP 请求不是跨请求事务。页游标绑定 packet、fact、mapping ID/version/Evidence ID、关系快照及服务端游标。发生变化时拒绝混页。`state=unmapped`、`state=unavailable` 和空但成功的关系集合分别表达；失败从不伪装为空数组。若 fact 与首屏关系合并超过现有 64 KiB MCP 输出上限，保留 fact 并返回单独关系读取引用。

这一读取是管理记录核对。它不表示原件已打开或核验，不表示科学结论有效，也不将历史 write receipt 的 `current_state_verified=false` 改成 true。

现场 token 只有 `intake.submit`；read token 只能读；整理员写入不含 intake 权限。服务端逐项核对 Issue、packet、锚点、关系目标和权限。编排整理会话还按宿主绑定的 packet 可见 ID 清单执行列表与详情 fence。

## 结构与恢复

当前数据库 schema v8 为 fresh-only，不提供旧账本迁移或双写。独立 `field_packet_curation_heads` 管理 CAS，packet 行不因整理更新；复核只追加。`field_facts` 在整理时创建 origin、source locator、作者和时间；映射版本/head 保留一事实一 Evidence 与历史约束。

编排交付 journal 位于仓库外，只保存规范化交付意图和回执。每次收件/整理/复核先持久化单调序号、request ID、幂等键及原始 HTTP body；结果不明时通过 `get_delivery_status` 对账或以 `recover_delivery(delivery_id)` 恢复原身份/body。回执带稳定 delivery_id；成功意图重放返回历史回执，不重复创建 Evidence。确认拒绝会保留拒绝记录；更正用新意图，CAS 冲突需先读取 IM 新状态。

## MCP v2 适配契约

submit、read、curate 每个连接都公开 `get_connection_info`。submit 还公开 delivery 状态/恢复；read/curate 增加 `read_field_source`、`locate_field_excerpt`、`read_field_fact`、`read_field_review` 和 `get_field_summary`。read/curate 的 packet 白名单在任何 HTTP 请求前检查，随后由 packet-scoped HTTP 路由再次确认 Issue 和归属。

每个工具声明 outputSchema；所有结果含 `contract_version: workflow-mcp/v2`。错误用 `isError=true` 返回一致的 code、operation、layer、JSON Pointer fields、retry_policy 与 effect。连接 manifest 的 SHA-256 对完整公开 tools/list 中每个工具的 name、description、inputSchema、outputSchema 做 UTF-8、键排序、紧凑 JSON 序列化；动态 enum 纳入 hash。认证检查、stdio 握手和实际 HTTP 读取分别报告。
