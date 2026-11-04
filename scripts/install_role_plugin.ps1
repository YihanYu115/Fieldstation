param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z][a-z0-9_-]*$')]
    [string]$Plugin,
    [Parameter(Mandatory = $true)]
    [string]$PackagesPath
)

$ErrorActionPreference = 'Stop'
$packages = (Resolve-Path -LiteralPath $PackagesPath).Path
$manifestPath = Join-Path $packages '.agents/plugins/marketplace.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw 'PackagesPath must name a generated marketplace.'
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.name -notmatch '^[a-z][a-z0-9_-]*$') { throw 'Invalid marketplace identity.' }
$entries = @($manifest.plugins | Where-Object { $_.name -ceq $Plugin })
if ($entries.Count -ne 1) { throw 'Plugin must select one exact generated marketplace entry.' }
$entry = $entries[0]
if ($entry.source.source -cne 'local' -or $entry.source.path -notmatch '^\./[a-z][a-z0-9_-]*$') {
    throw 'Expected one local generated package directory.'
}
$pluginPath = (Resolve-Path -LiteralPath (Join-Path $packages $entry.source.path)).Path
if (-not $pluginPath.StartsWith($packages + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Plugin directory escapes PackagesPath.'
}
$pluginManifest = Get-Content -LiteralPath (Join-Path $pluginPath 'plugin.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ($pluginManifest.name -cne $Plugin) { throw 'Plugin identity differs from marketplace.' }
Get-Command codex -ErrorAction Stop | Out-Null
& codex plugin marketplace add $packages --json
if ($LASTEXITCODE -ne 0) { throw 'Codex could not register the marketplace.' }
& codex plugin add ($Plugin + '@' + $manifest.name) --json
if ($LASTEXITCODE -ne 0) { throw 'Codex could not install the selected plugin.' }
Write-Output "Installed $Plugin. The host binds this session's connection, execution and authorization before use."
