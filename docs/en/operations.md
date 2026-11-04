# Operations, backup, and recovery

[English documentation](README.md) · [Chinese original](../OPERATIONS.md)

Applies to IM `0.9.0rc11`, fresh-only schema **10**, `scoped-v2`, and independent orchestration `0.13.8`. Keep projects, credentials, runtime databases, logs, backups, and build outputs outside the source tree.

## Starting and stopping

```powershell
$ledger = 'D:\IssueProjects\my-project\im'
issuectl --ledger $ledger init
issuectl --ledger $ledger status
issuectl --ledger $ledger serve --host 127.0.0.1 --port 8765
```

Use `init` only for a new project. For an existing project, begin with `status`. Connect to the service over HTTP; do not share SQLite/WAL files across machines. Before stopping a service, pause orchestration and confirm the original execution state. When the model, experiment, or lease state is unknown, retain the occupancy and do not start a duplicate.

## Choosing a data operation

| Need | Operation | Data and execution semantics |
| --- | --- | --- |
| Restore the original IM ledger | `issuectl backup` | Preserves the original ledger history and local authentication material; recovery adds an audit and updates the service token epoch. |
| Exchange an IM component | `issuectl project` | Installs into a new directory, rebuilds authentication, and isolates execution. |
| Exchange an IM project package | `im-project-host` | IM component only; original-operation recovery and rebuilt authentication. |
| Upgrade an old database | No current entry point | Do not relabel the schema or overwrite the old database. |

IM backups exclude orchestration Queue/Board and Trigger runtime stores, delivery journals, and external research originals. For a full deployment backup, first stop relevant writes; separately save each service's data, host configuration, and originals, recording times and bindings. Two independent snapshots do not imply cross-database atomic consistency.

## Creating and verifying backups

```powershell
# metadata is the default: database, policy, authentication, and attachment manifest; attachment objects are not copied.
issuectl --ledger $ledger backup create --label 'before-maintenance' --mode metadata
# full also includes IM-managed attachment objects and checks their size and SHA-256.
issuectl --ledger $ledger backup create --label 'full-copy' --mode full
issuectl --ledger $ledger backup list
issuectl --ledger $ledger backup verify '<returned backup_id>'
```

Backups are written to `$ledger/backups/<backup_id>`. SQLite uses a consistent backup snapshot; the manifest records checksums for the database, files, and objects. Backups contain `.ledger_secret` and local credentials and must be protected like the original ledger. To share with others, use the portable project-package process that rebuilds authentication.

`verify` returns JSON; callers must check `ok`. A successful JSON response is not proof of successful verification. For metadata, `ok=true` proves only the backup's own integrity; restoration still depends on corresponding attachment objects in the current ledger existing and matching checksums. Use a previously valid full backup to recover missing attachments. URLs, experimental-platform objects, and other external originals are referenced only, not automatically downloaded.

## Restoring the original ledger

1. Pause orchestration, confirm execution state, and stop services and writers accessing the IM ledger.
2. Run `backup verify` and confirm `ok=true` and schema 10.
3. Restore the exact backup from the same ledger:

```powershell
issuectl --ledger $ledger backup restore '<backup_id>'
issuectl --ledger $ledger status
```

4. Inspect `doctor.ok`, `pre_restore_backup_id`, and `pre_restore_backup_degraded` in the receipt; the host must then check and rebind service authentication, queues, and journals.

Restore first saves a safety backup of the current state, validates in staging, rebuilds the attachment manifest, switches state, and runs doctor. On failure it attempts rollback; progress is kept in `$ledger/runtime/restore_journal.json`. If current attachments are missing or damaged during full restore, the safety backup may degrade to metadata, explicitly marked in the receipt. That safety backup cannot promise recovery of objects already missing.

Restore advances the service token epoch and revokes existing service tokens. Local actor credentials already in the backup may be restored; authentication and authorizations created after the backup cannot be assumed to remain valid. Restoring IM does not roll back orchestration stores or old journals. Before restarting, check bindings and original executions; do not directly replay deliveries created later.

If the trusted local host loses the bootstrap maintenance credential, `issuectl --ledger $ledger recover-bootstrap-credential --reason '<reason>'` can reissue it with an audit. This is not for adding capabilities or bypassing permissions.

## Project packages, configuration, and validation

[Project packages](project-package.md) describes IM-only CLI, preflight, and recovery with the same ID. Old QueueStore components and dashboard are unsupported. `issuectl project` handles a single IM component; `im-project-host` handles the outer package. Import preserves business history but rebuilds authentication and isolates execution; it is not automatic resumption or old-version migration.

[IM tools](../../orchestration/IM_TOOLS.md), [Queue](../../orchestration/QUEUE_TOOLS.md), and [Python listeners](../../orchestration/PYTHON_TRIGGER.md) describe host connections. Ordinary configuration and credential handling follow [AGENTS.md](../../AGENTS.md); do not put keys in business prompts or Git.

The bounded CLI has no `doctor` subcommand; the kernel's `IssueManager.doctor()` and the restore/install contracts perform diagnostics.

