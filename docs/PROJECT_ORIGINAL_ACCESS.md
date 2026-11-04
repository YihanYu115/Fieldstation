# 项目原件访问说明

原件的访问方式由项目和可信宿主提供，IM 保存访问说明及相关绑定。

IM 工具按实际 Issue 所属项目查询原件说明。实际目标由每次动作选择，授权内新目标是新动作，不能改写原恢复身份。

## 最小设计与边界

IM 保存可独立维护的项目读取说明。顶层 Issue 是项目身份，所有子 Issue 继承同一组说明；不提供子树覆盖或跨根继承。同一根可登记多个契约。与已有通用能力一致，非平台身份的 `context.read` 可读，`issue.write` 加 `context.read` 可登记/修订；没有新增岗位判断或项目 ACL。

`project_original_access_versions` 和 `project_original_access_heads` 保存说明，`project_original_access_bindings` 保存引用首次进入项目时的选择。说明版本和引用绑定只追加，head 在事务内按 `expected_revision` 推进，审计与 head 同事务。HTTP 请求日志沿用既有请求身份、幂等键和失败恢复规则。说明与绑定不作为科学 Evidence 输入，不改变已保存来源、冻结材料包、结论或资格。

读取方法是**不可信数据**。IM 与编排不会打开说明中的 URL、读取本机文件、执行命令、解析原件格式或自动绑定工具。`capability` 仅为逻辑名称；真实工具名、endpoint、可执行路径、认证和权限由宿主绑定。业务说明不能用来保存密钥；结构中不设认证、endpoint 或命令字段。自由文本无法可靠识别所有秘密，宿主登记前必须保证内容适合项目读者公开。

## HTTP

| 操作 | 入口 | 必要内容 |
| --- | --- | --- |
| 登记/修订 | `POST /v1/original-access` | Bearer、`X-Request-ID`、`Idempotency-Key`；body 见下文 |
| 发现 | `GET /v1/original-access/discover` | `issue_id`；可选 `reference`、`contract_id`、`limit`、`cursor`、`expected_snapshot` |
| 读取 | `GET /v1/original-access/read` | `issue_id`，及 `evidence_id` 或 `contract_id+revision`；可选 `max_bytes`；多引用Evidence可用`reference`精确选择 |

`GET /v1/context?issue=…`、browse 的 Issue 详情和 `GET /v1/issues/overview?root=…` 返回 `original_access`，包含项目根、契约数量、HTTP 入口及工具指针。说明缺失时数量为零，入口仍可用。岗位也可直接调用通用发现工具，无需先知道契约 ID。

发现有三种用途：

- 不带 `reference/contract_id`：当前契约短目录；返回的 revision 是目录当前 head，不是替某份历史原件选定的解释。
- 带 `contract_id`：该契约全部历史版本的目录。
- 带准确 `reference`：按原样字符串前缀匹配**全部历史版本**，不限定 URI scheme、不解析路径或 JSON。可同时带 `contract_id` 表示作者已明确选择的契约家族。

`match_status` 为 `catalog`、`missing`、`matched`、`version_required` 或 `ambiguous`。匹配只有一个版本时为 matched；同家族多个版本为 version_required；多家族匹配为 ambiguous。禁止最长前缀优先、自动最新版或跨根回退。状态基于分页前的整个候选集合，即使首页只显示一项也不能冒充唯一匹配。

每页 1–50 项，默认 20。集合读取最多 10000 项，超过时明确拒绝；目录响应最多 60 KiB，可减小 limit。游标绑定查询、身份和实际目录内容；集合改变则 409，重新从首页读取。无说明/无匹配不自动尝试外部工具。

每版包含以下非空文本，JSON 总计最多 32768 UTF-8 字节：

| 字段 | 含义/限制 |
| --- | --- |
| `reference_prefix` | 准确适用前缀，最多512字节；非正则表达式 |
| `summary` | 短摘要，最多512字节 |
| `capability` | 宿主需绑定的逻辑能力，ASCII 标识符，最多128字节 |
| `parameters` | 第一次读取所需参数、引用组成和局部定位方法 |
| `example` | 一次明确的调用示例；不得要求先读原件才能获得方法 |
| `semantics` | 局部选择、分页/切片、完整/截断与可用校验的语义；不支持的能力如实说明 |
| `failures` | 缺绑定、权限拒绝、对象缺失、范围/预算/校验失败的含义 |
| `change_impact` | 首版 initial，后版 editorial 或 interpretation |
| `impact_note` | 实际影响及所需复核说明，不能只填“无影响”掩盖解释变化 |

后六个自由文本各最多8192字节；`change_impact` 另受枚举约束。完整读取不静默截断，默认预算65536字节，可指定1024–65536。超预算返回409及 `required_bytes`，按足够预算重读。说明有独立字节上限，因此本版不增加说明正文分页协议。原件本身的分页由项目工具定义。

## 自动绑定与历史

一版说明的身份为 `(root_issue_id, contract_id, revision)`。直接按契约读取需指定准确版本；按Evidence读取使用其入账时已固定的版本，不在读取时挑最新版。访问说明更新后旧版永久可读，原件引用字符串不会被重写。

普通提交不增加必填字段，也无需作者在正文声明版本。IM在原子入账事务中，以项目根和准确引用匹配当前heads：唯一匹配则保存具体contract_id/revision；无匹配记missing，多份生效契约匹配记ambiguous。这里只匹配生效head，与原始引用发现时的全历史匹配不同。即使后续只是editorial修订，也不重选旧绑定。

绑定记录的是入账时选定的读取说明，不认证作者实际读过原件或使用过该版工具，也不证明科学内容正确。本版普通入口采用自动规则，未新增历史导入的手动选版覆盖参数。

绑定精确到项目和引用：同一个Evidence登记到不同项目时，各自固定该项目首次登记时的契约；重复登记到同一项目不重新选择。通用add_evidence、scoped贡献、ChangeSet挂接和旧Intake转入Issue的登记路径统一记录。尚未有项目范围的原型Intake/Manifest不猜测项目；首次进入项目时才有默认选择依据。

Field Inbox在packet收件时为sources和attachment_refs逐引用固定选择。整理形成Evidence时继承其来源的packet绑定，包括missing/ambiguous缺口；不会因整理延迟而改选新版。packet_text等明确的账本内部来源记internal，无需外部读取契约。绑定、贡献及现有关系在同一事务内保存，重放沿用原回执和原绑定；失败不留半份记录。

Evidence详情、单条Field fact和packet详情/摘要提供简短original_access字段，bound项含准确版本读取指针。冻结材料展示提供按evidence_id读取的稳定入口，不将说明或绑定表加入科学冻结输入和比较指纹。read_original_access传evidence_id可直接取得已固定说明，省去发现和手填版本。

没有绑定记录时返回unrecorded，不回填今天的最新版；多引用未指定哪一条时返回multiple_references；缺说明、歧义和目录过大均返回明确状态并保留贡献。当前实现不提供历史绑定补写、修订或重绑接口；补好说明后，新贡献可正常绑定，旧缺口仍需明确处理，不能通过读操作暗改历史。缺口回读同样受UTF-8预算约束。歧义候选最多保存50个身份及真实总数，不把候选全文发给岗位。

说明变更影响引用对象、定位或内容解释时，写入 `interpretation` 和明确的 `impact_note`，由作者/宿主安排必要科学复核。本功能只保存变更声明，不替作者推断哪些结论需要修订，也不自动更新 depends_on。当前目录会给出变更类型，详情保留复核说明。

## 岗位 MCP 与宿主绑定

IM profile 可选择 `discover_original_access` 与 `read_original_access`。后者支持 Evidence 固定绑定或明确契约版本；实际服务端权限和 Evidence 读取检查仍分别生效。入口与 profile 字段见 [IM 工具](../orchestration/IM_TOOLS.md)。

可信宿主指定 endpoint、token 环境变量名、默认 Issue 和仓库外 journal；工具不读取凭据文件或 IM 数据库。宿主另行绑定项目实际提供的原件保存与读取能力，并确认授权、引用格式、保留和重启后的可用性；登记说明或工具可见本身不证明这些能力可用。项目工具负责将实际成果保存为可引用的版本并返回准确引用，也负责按该引用读取；其持久性、完整性和范围由项目契约定义。岗位将返回的成果引用作为来源保存，并按实际含义关联输入与其他贡献；输入引用、本机路径或说明绑定不能代替成果引用。

接手步骤：

1. 已入账贡献优先按其original_access指针读取，也可直接用read_original_access传evidence_id。
2. 未入账的准确原件引用用discover_original_access查找；涉及多种历史解释时明确版本，不猜测。
3. 核对说明要求的逻辑能力是否已由宿主绑定，并使用外部工具按参数取得所需局部内容。
4. 用已有交付入口保存局部贡献和准确原件引用，版本由服务端默认绑定。缺工具/权限/匹配时交回准确缺口。

IM 返回 `external_binding=host_required`，不会声称当前会话已经具备读取能力。没有外部工具时，程序只能交付这个确定的绑定缺口；模型能否正确理解并报告，须单独做真实岗位验收。

## 兼容与项目包

数据库采用 fresh-only 策略：旧 schema 在开启 WAL 或自动修改前拒绝；不提供自动升级、旁路表或仅重标版本的操作。完整项目包同样按当前 schema 校验。

旧项目是否可打开取决于其实际 schema，不能依据历史现场名称推断。旧库接入需另行评估迁移或保真重建并保留科学历史；本契约不授权修改任何已有现场。

备份和项目包按内核全库枚举携带说明、head、绑定和继承链。导入重建认证并隔离执行；说明不携带外部原件、工具或工具认证。

实际登记与绑定以本文契约和 API schema 为准。
