# 代码架构与维护边界

当前版本为 IM `0.9.0rc11` / schema **10** / `scoped-v2`；独立编排包 `0.13.8`。工具入口见 [workflow-tools](../orchestration/README.md)。

IM 是身份、授权、Issue、Evidence、关系、版本、领域事务与历史的权威；编排包只通过公开 HTTP 使用 IM，不导入内核、不读取 IM SQLite、账本或凭据文件。宿主绑定 endpoint 和认证，运行目录位于源码仓库外。

Queue 记录明确选择的实验员配置、待办、领取与简短回复；Host 的受限目录按主体权限展示岗位职责和配置，目录可见不授予启动或 IM 权限。Board 保存普通交流、明确请求/答案和真实人指令；Inbox 及整理历史属于 IM。各自独立可用，不需要监听或启动服务。领取、业务贡献、判断和执行状态分别记录，消息到达不等于业务完成。

IM 浏览已知对象时由服务检查现有读取权限，不使用单一浏览根；原件说明按实际项目与冻结版本定位。Queue、Board、Host 不按 Issue 白名单授权；Board 留言可查询单个 Issue、通过 IM 公开接口查询子树，或查询全部 Issue。子树分页绑定 IM 快照与 Board 水位，变化时拒绝续页；Queue 列表返回保留查询条件的续页入口。

只读 Listener 发现 Queue、Board 或 Inbox；可信普通 Python 脚本决定条件及是否请求激活。Host 校验绑定、来源、权限、容量及可选本机空闲条件，固定原领取意图并最多启动一次前台会话。未知原动作保留身份并恢复，已知 busy 不构成接纳。跨服务条件是观察，不承诺跨服务原子性。

IM 写入仍受授权、scope、CAS、事务与幂等保护；新贡献使用新动作身份，原动作恢复不能更换正文、目标或请求。不同地址的服务通过有限 HTTP 交接，不共享数据库。`workflow-tools` 是编排唯一 console；MCP 提供有限业务工具而非任意代理。 MCP 由可信宿主独立运行 Streamable HTTP；Host 注册受限会话上下文，并把 URL 和凭据环境变量名装配到 Codex 命令。现有客户端 journal 继续负责原动作恢复，未知响应不按正文去重。

项目包仅支持 IM-only 导出、预检和新目录安装；重建认证并隔离执行，旧 QueueStore 组件、dashboard 和旧宿主运行目录不迁移或接管。见 [项目包](WORKFLOW_PROJECT_PACKAGE_USAGE.md)。

真实科研中的长期效果、模型和设备接入、物理跨机运行及部署能力需要分别验证。
