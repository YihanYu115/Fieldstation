# Workflow tools

设计与使用边界见[职责与机制摘要](DESIGN.md)。

`issue-workflow-orchestrator` 0.13.8 的唯一命令是 `workflow-tools`。先使用 `workflow-tools --help` 查看 `serve`、`mcp`、`recover`、`host`、`discover` 和 `trigger`。状态、日志和凭据由可信宿主放在源码仓库外。安装 `.[mcp]` 提供 MCP 依赖。

- [Queue](QUEUE_TOOLS.md)：发布、读取、领取、回复与分页；领取不等于完成。
- [Board](BOARD_TOOLS.md)：普通消息与回复、明确请求及人类指令。
- [IM 和 Inbox](IM_TOOLS.md)：通过公开 IM HTTP 保存多次材料、检索和整理。
- [Host](HOST_TOOLS.md)：根据可信 profile 领取并启动前台会话，保护原启动身份。
- [Python 监听脚本](PYTHON_TRIGGER.md)：只读发现和普通 Python 条件组合；可连接独立 HTTP 地址。
- [岗位用法](ROLE_USAGE.md)：可选能力与跨 Issue 贡献。

MCP 由可信宿主独立启动并管理，不随 Codex 会话退出；配置与恢复见 [HTTP MCP](HTTP_MCP.md)。

各 MCP surface 在标准 Server Instructions 中提供对应模块的简短原则；是否将其传给模型取决于客户端，须在实际客户端中验证。工具列表和服务端授权仍分别生效。

各服务独立可用；未配置触发器或 Host 时普通读写不依赖它们。用户 Python 脚本是可信宿主代码，不是模型生成的配置权限。历史 QueueStore、注册 workflow、旧岗位插件、dashboard 与项目包中的编排快照不受支持，不迁移旧现场。启动成功或程序退出不代表岗位注意力、科学结论或外部作业已经验证。

wheel 安装将本页、工具说明及示例放在 Python 安装前缀的 `share/issue-workflow-orchestrator/`。示例中的连接信息需要按实际服务配置并由宿主注入凭据。
