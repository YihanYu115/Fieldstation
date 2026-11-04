# IM MCP usage

[English documentation](README.md) · [Full Chinese source](../ISSUE_MANAGER_MCP.md) · [HTTP MCP](../../orchestration/HTTP_MCP.md) · [IM tools](../../orchestration/IM_TOOLS.md)

The orchestration entry point is `workflow-tools`. A trusted host configures the IM endpoint, credential environment variable, optional default Issue, and journal outside the repository. It independently runs the Streamable HTTP MCP service for clients. Queue and Board each use their respective profiles; the host injects credentials and the server checks permissions on each request.

IM is the domain authority; orchestration does not read the kernel database or credentials. Conclusion tools require participants to select evidence roots explicitly. When an original action's outcome is unknown, recover it using its original identity.

