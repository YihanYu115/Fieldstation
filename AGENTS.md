# 项目维护指引

阅读 [系统架构](docs/WORKFLOW_ARCHITECTURE.md)、[证据管理](docs/EVIDENCE_MANAGEMENT.md)和[计算契约](docs/UNIFIED_MANAGEMENT_SEMANTICS.md)，并根据任务查看相应模块说明。

- 使用 UTF-8 无 BOM 编码保存文本；保留已有用户改动。
- IM 负责领域权限、版本、事务、幂等与历史；编排只通过公开 HTTP 使用 IM。
- 区分授权、工作委托、贡献、业务判断与进程状态。Queue、Board 和 Inbox 不依赖自动启动才能使用。
- 接口变更应同步检查定义、客户端、MCP、配置示例与用法；保留权限、并发、事务和原动作恢复保护。
- 项目数据、凭据、运行库和构建产物放在源码目录外；不要提交密钥或真实业务数据。

