# Fieldstation read-only console

[English documentation](README.md) · [Chinese original](../../fieldstation_console/README.md)

The first version provides a local HTML interface using explicitly labeled fictional sample data by default. After switching to “live connection,” the console reads through the services' public read-only HTTP interfaces; IM requires a known Issue ID. The console does not write or launch role sessions.

With Python 3.11+, run from the source directory:

```powershell
python .\fieldstation_console\server.py
```

Alternatively, after installing an Issue Manager wheel built from this project, run `fieldstation-console`.

Open <http://127.0.0.1:18765/>. The server listens only on the local host by default; stop with Ctrl+C. Set `FIELDSTATION_CONSOLE_PORT` to select a port. Live connections are injected through environment variables in the server process; each service can be configured separately:

```powershell
$env:FIELDSTATION_IM_URL = 'http://127.0.0.1:18103'
$env:FIELDSTATION_IM_TOKEN = '<injected by trusted host>'
$env:FIELDSTATION_BOARD_URL = 'http://127.0.0.1:18104'
$env:FIELDSTATION_BOARD_TOKEN = '<injected by trusted host>'
$env:FIELDSTATION_QUEUE_URL = 'http://127.0.0.1:18105'
$env:FIELDSTATION_QUEUE_TOKEN = '<injected by trusted host>'
$env:FIELDSTATION_HOST_URL = 'http://127.0.0.1:18106'
$env:FIELDSTATION_HOST_TOKEN = '<injected by trusted host>'
```

Addresses illustrate the format only. Tokens are not sent to the browser or written to console files. Each service checks actual authorization; Host's catalog returns only configurations the principal may view. The console process is a trusted host and should be used locally by the same trusted user; it has no multi-user session isolation. Do not reverse-proxy or expose it to the network.

IM currently supports expanding sub-Issues from a known Issue and viewing current conclusions and status, Evidence, and directed relations. Board supports lists of communications, requests, and instructions; Queue supports task lists and claim-status filters; Host supports a restricted role catalog. Lists support continuation returned by services; record details retain raw public-interface fields. When a real service is unconfigured, sample data is not presented as real data.

The Evidence graph uses a circular layout for currently loaded items and each item's loaded direct relationships; arrows and types come from IM. Materials and relationships can both be paginated, and the interface indicates when more needs to load, reading failed, or access is restricted. Node colors represent IM quality status; withdrawn lifecycle status takes precedence, and external nodes without loaded details are unknown. Large graphs scroll and edges may cross.

