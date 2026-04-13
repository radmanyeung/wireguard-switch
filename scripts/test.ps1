$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'bootstrap-env.ps1')
$context = Initialize-BootstrapEnvironment -RepoRoot $repoRoot
$restoreConfig = $context.NuGetConfigPath

$testProject = Join-Path $repoRoot 'tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj'
& dotnet test $testProject -p:RestoreConfigFile=$restoreConfig @args
exit $LASTEXITCODE
