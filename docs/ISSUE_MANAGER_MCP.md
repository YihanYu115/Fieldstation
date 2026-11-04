# IM MCP 使用

编排包入口为 `workflow-tools`。可信宿主配置 IM endpoint、认证环境变量名、可选默认 Issue 和仓库外 journal，并独立启动 Streamable HTTP MCP；客户端连接该服务。启动参数、监听地址及恢复方法见 [HTTP MCP](../orchestration/HTTP_MCP.md)，IM profile 和工具见 [IM 工具](../orchestration/IM_TOOLS.md)。Queue 和 Board 各使用对应 profile；凭据通过宿主注入，服务端逐次检查权限。

IM 是领域权威；编排不读取内核库或凭据。结论工具要求参与者明确选择证据根，原动作未知时使用原身份恢复。
