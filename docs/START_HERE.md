# 从这里开始

IM `0.9.0rc11` 使用 schema **10** 和 `scoped-v2`；独立编排为 `0.13.8`。

1. 按[运维说明](OPERATIONS.md)创建或连接 IM 账本。
2. 按[编排工具说明](../orchestration/README.md)安装独立编排包；按需配置 [IM 工具](../orchestration/IM_TOOLS.md)与 [HTTP MCP](../orchestration/HTTP_MCP.md)。
3. 通过 IM 保存带来源的观察、明确必要关系，并在形成结论时选择实际依据。也可先通过 Inbox 提交待整理材料。
4. 根据需要使用 [Queue](../orchestration/QUEUE_TOOLS.md) 安排待办、[Board](../orchestration/BOARD_TOOLS.md)交流；不要求固定调用顺序。
5. 需要自动启动会话时，再配置可信 [Python 监听脚本](../orchestration/PYTHON_TRIGGER.md)与 [Host](../orchestration/HOST_TOOLS.md)。

`derived_from` 表示来源，`depends_on` 表示必要前提，`refutes` 表示明确反驳；结论当前性不是科学真伪。见[证据计算契约](UNIFIED_MANAGEMENT_SEMANTICS.md)与[系统架构](WORKFLOW_ARCHITECTURE.md)。

