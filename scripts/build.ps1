$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'bootstrap-env.ps1')
$context = Initialize-BootstrapEnvironment -RepoRoot $repoRoot
$restoreConfig = $context.NuGetConfigPath

$solution = Join-Path $repoRoot 'WireguardSplitTunnel.sln'
& dotnet build $solution -m:1 -p:RestoreConfigFile=$restoreConfig @args
exit $LASTEXITCODE
