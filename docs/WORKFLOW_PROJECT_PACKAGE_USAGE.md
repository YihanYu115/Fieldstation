# 项目包：IM-only 使用与恢复

适用 IM `0.9.0rc11`、schema **10**、`scoped-v2` 和编排 `0.13.8`。`im-project-host` 支持 IM-only 导出、预检和安装；`issuectl project` 是内核单组件入口。导入创建新目录、重建认证并隔离执行，保留 IM 业务历史；不能覆盖或合并项目。

可信宿主提供本机 IM component endpoint、`IM_PROJECT_TOKEN`、默认根、独立仓库外 runtime 和项目父目录。先在 IM 服务端启用 project component；具体权限与启动见 [运维](OPERATIONS.md)。

```powershell
im-project-host --endpoint http://127.0.0.1:8765 --root PROJECT --runtime D:/IssueRuntime/project-host --project-parent D:/IssueProjects export --request-id export-1
im-project-host --endpoint http://127.0.0.1:8765 --root PROJECT --runtime D:/IssueRuntime/project-host --project-parent D:/IssueProjects inspect --file D:/IssueRuntime/export.improjectpkg
im-project-host --endpoint http://127.0.0.1:8765 --root PROJECT --runtime D:/IssueRuntime/project-host --project-parent D:/IssueProjects install --upload-id <upload-id> --preflight-hash <hash> --name new-project --operation-id install-1
```

export 回执中的 job ID 对应 host runtime 的 `exports/<job_id>.improjectpkg`；inspect 提供 upload ID 和 preflight hash。安装失败或响应未知时保留相同 upload ID、hash、名称和 operation ID 重试，不能用新身份掩盖原操作。导入后由宿主重新绑定新认证；原运行不自动续跑。

本版不导出、导入、升级或恢复旧 QueueStore/Board 组件；含旧编排组件的项目包明确拒绝。旧 dashboard、`serve`、`--queue` 和 `--include-orchestration` 均不支持。旧 host runtime 不接管、迁移或清理；本版使用新的专用 runtime，同版原操作可恢复。新 TaskQueue、Listener 和 Host 数据库不能冒充旧快照。

真实跨机、模型、仪器和生产部署不由项目包程序测试证明。归档不下载外部原件；认证由宿主注入，不应写入脚本或报告。
