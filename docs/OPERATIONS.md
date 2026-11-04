# 运行、备份与恢复

适用：IM `0.9.0rc11`、fresh-only schema **10**、`scoped-v2`；独立编排 `0.13.8`。项目、凭据、运行库、日志、备份和构建产物放在源码仓库外。

## 启动与关闭

```powershell
$ledger = 'D:\IssueProjects\my-project\im'
issuectl --ledger $ledger init
issuectl --ledger $ledger status
issuectl --ledger $ledger serve --host 127.0.0.1 --port 8765
```

`init` 只用于新项目。已有项目从 `status` 开始。通过 HTTP 连接服务，不跨机器共享 SQLite/WAL 文件。停止服务前先暂停编排并确认原执行状态；模型、实验和租约未知时保留占用，不重复启动。

## 选择数据操作

| 需求 | 操作 | 数据与执行语义 |
| --- | --- | --- |
| 恢复原 IM 账本 | `issuectl backup` | 保留原账本历史与本机认证材料；恢复增加审计并更新服务 token epoch |
| 交换 IM 组件 | `issuectl project` | 新目录安装、重建认证、执行隔离 |
| 交换 IM 项目包 | `im-project-host` | 仅 IM 组件；同操作恢复、重建认证 |
| 升级旧数据库 | 当前无此入口 | 不重标 schema、不覆盖旧库 |

IM 备份不包含编排 Queue/Board、Trigger 运行库、交付 journal 或外部科研原件。整套部署备份需先停止相应写入，分别保存各服务自己的数据、宿主配置和原件，并记录时间与绑定；不能从两个独立快照推断跨库原子一致。

## 创建与校验备份

```powershell
# metadata 是默认值：数据库、策略、认证及附件 manifest，不复制附件对象。
issuectl --ledger $ledger backup create --label 'before-maintenance' --mode metadata
# full 另包含 IM 管理的附件对象，并校验大小和 SHA-256。
issuectl --ledger $ledger backup create --label 'full-copy' --mode full
issuectl --ledger $ledger backup list
issuectl --ledger $ledger backup verify '<返回的 backup_id>'
```

备份写入 `$ledger/backups/<backup_id>`，SQLite 使用一致 backup 快照，manifest 记录数据库、文件和对象校验值。备份包含 `.ledger_secret` 与本机凭据，应按原账本的访问权限保存；共享给他人时使用便携项目包的认证重建流程。

`verify` 输出 JSON，调用程序必须检查 `ok`；命令成功返回 JSON 不等于校验通过。metadata 的 `ok=true` 只证明备份自身完整，恢复仍依赖当前账本中对应附件对象存在且校验一致。需要找回丢失附件时使用此前有效的 full 备份。URL、实验平台及其他外部原件只保留引用，不自动下载。

## 恢复原账本

1. 暂停编排，确认执行状态，关闭访问该 IM 账本的服务和写入进程。
2. 运行 `backup verify` 并确认 `ok=true`、schema 为 10。
3. 恢复同一账本中的准确备份：

```powershell
issuectl --ledger $ledger backup restore '<backup_id>'
issuectl --ledger $ledger status
```

4. 检查恢复回执中的 `doctor.ok`、`pre_restore_backup_id` 与 `pre_restore_backup_degraded`，再由宿主核对并重新绑定服务认证、队列和 journal。

恢复先保存当前状态的安全备份，在暂存区验证、重建附件 manifest，然后切换并运行 doctor；失败尝试回滚，进度保存在 `$ledger/runtime/restore_journal.json`。full 恢复遇到当前附件缺损时允许降级为 metadata 安全备份，回执明确标记；该安全备份不能承诺找回原先就已丢失的对象。

恢复会推进服务 token epoch 并撤销既有服务 token；备份中已有的本机 actor 凭据可能恢复，备份后新建的认证和授权不能假定仍有效。恢复 IM 不回滚编排库或旧 journal；重新启动前须核对绑定和原执行，不能直接重放后来产生的交付。

可信本机宿主丢失 bootstrap maintenance 凭据时，可使用 `issuectl --ledger $ledger recover-bootstrap-credential --reason '<原因>'` 重新签发，操作保留审计。它不用于新增能力或突破权限。

## 项目包、配置与验证

[项目包说明](WORKFLOW_PROJECT_PACKAGE_USAGE.md)包含 IM-only CLI、预检和同 ID 恢复。旧 QueueStore 组件和 dashboard 不支持。`issuectl project` 操作 IM 单组件；`im-project-host` 操作外层包。导入保留业务历史，但重建认证、隔离执行，不能当作自动续跑或旧版本迁移。

[IM 工具](../orchestration/IM_TOOLS.md)、[Queue](../orchestration/QUEUE_TOOLS.md)与[Python 监听](../orchestration/PYTHON_TRIGGER.md)分别说明宿主连接。普通配置与凭据代填遵循 [AGENTS.md](../AGENTS.md)，密钥不放入业务提示词或 Git。

有限 CLI 没有 `doctor` 子命令；内核 `IssueManager.doctor()` 及恢复和安装契约执行诊断。
