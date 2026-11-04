"""Model-facing scoped relation vocabulary shared by the public MCP adapters."""

SCOPED_RELATION_TYPES = (
    "depends_on", "derived_from", "reproduces", "supports", "challenges",
    "amends", "duplicates", "context_for", "refutes",
)

SCOPED_RELATION_DESCRIPTION = (
    "关系属于本次新贡献，方向为新贡献→目标条目；"
    "不能把‘请登记某关系’的工作指令另建为 Evidence，再让指令去指向目标。"
    "derived_from=生成/分析来源，不传播失效；"
    "depends_on=必要前提，前提不可用会使本条不可用；"
    "refutes=明确反驳，可排除目标；"
    "challenges=尚未明确推翻的质疑，不直接排除目标；"
    "supports=支持意见，不计票或抵消反驳；"
    "reproduces/amends/duplicates/context_for=复现/修订/重复/背景说明，"
    "不自动成为必要前提或反驳。"
    "同一目标可同时是来源与必要前提，含义明确时分别声明 derived_from 和 depends_on。"
    "例如误差超标判断以结果行与参考值为必要依据；只记录出处不能维护这些前提的失效。"
    "先保存前提并复制真实引用，再保存依赖它的判断；必要性不明时记录具体缺口，不猜关系。"
)
