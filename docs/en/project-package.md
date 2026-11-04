# Project packages: IM-only use and recovery

[English documentation](README.md) · [Chinese original](../WORKFLOW_PROJECT_PACKAGE_USAGE.md)

Applies to IM `0.9.0rc11`, schema **10**, `scoped-v2`, and orchestration `0.13.8`. `im-project-host` supports IM-only export, preflight, and installation; `issuectl project` is the kernel's single-component entry point. Import creates a new directory, rebuilds authentication, isolates execution, and retains IM business history; it cannot overwrite or merge a project.

The trusted host provides the local IM component endpoint, `IM_PROJECT_TOKEN`, default root, an independent runtime outside the repository, and project parent directory. Enable the project component on the IM service first; see [operations](operations.md) for permissions and startup.

```powershell
im-project-host --endpoint http://127.0.0.1:8765 --root PROJECT --runtime D:/IssueRuntime/project-host --project-parent D:/IssueProjects export --request-id export-1
im-project-host --endpoint http://127.0.0.1:8765 --root PROJECT --runtime D:/IssueRuntime/project-host --project-parent D:/IssueProjects inspect --file D:/IssueRuntime/export.improjectpkg
im-project-host --endpoint http://127.0.0.1:8765 --root PROJECT --runtime D:/IssueRuntime/project-host --project-parent D:/IssueProjects install --upload-id <upload-id> --preflight-hash <hash> --name new-project --operation-id install-1
```

The job ID in the export receipt corresponds to `exports/<job_id>.improjectpkg` in the host runtime; inspect returns an upload ID and preflight hash. If installation fails or the response is unknown, retry with the same upload ID, hash, name, and operation ID; do not mask the original action with a new identity. After import the host rebinds new authentication; the original execution does not automatically resume.

This version does not export, import, upgrade, or restore old QueueStore/Board components; project packages containing old orchestration components are explicitly rejected. Old dashboard, `serve`, `--queue`, and `--include-orchestration` are unsupported. Old host runtimes are not taken over, migrated, or cleaned; this version uses a new dedicated runtime, while original actions under the same version can be recovered. New TaskQueue, Listener, and Host databases cannot stand in for old snapshots.

Project-package program tests do not prove actual cross-machine operation, models, instruments, or production deployment. Archives do not download external originals. Credentials are injected by the host and should not be written into scripts or reports.

