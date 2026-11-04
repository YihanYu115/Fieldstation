# 参与开发

Fieldstation 是研究原型。请先阅读[系统架构](docs/WORKFLOW_ARCHITECTURE.md)、[证据管理](docs/EVIDENCE_MANAGEMENT.md)和[计算契约](docs/UNIFIED_MANAGEMENT_SEMANTICS.md)，涉及具体模块时再阅读对应的[工具说明](orchestration/README.md)。

修改时请保持各服务的职责与权限边界：IM 维护领域权限、版本、事务和历史；编排通过公开 HTTP 使用 IM；Queue、Board 和 Inbox 可以独立使用。工作焦点、授权、贡献、业务判断及执行状态分别表达。

安装和运行请使用独立环境，并将项目数据、凭据、运行库与构建产物保存在源码目录外。项目要求 Python 3.11 或更高版本。不要提交密钥、真实业务数据或运行数据库；新增文本使用 UTF-8 无 BOM。

修改接口时同步检查 API、客户端、MCP、配置示例与文档。根据变更运行相关测试；程序检查不代替科学判断或真实环境中的验证。

