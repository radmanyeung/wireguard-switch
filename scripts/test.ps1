$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'bootstrap-env.ps1')
$context = Initialize-BootstrapEnvironment -RepoRoot $repoRoot
$restoreConfig = $context.NuGetConfigPath

$testProject = Join-Path $repoRoot 'tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj'
$windowsUpdateTestProject = Join-Path $repoRoot 'tests\WireguardSplitTunnel.WindowsUpdate.Tests\WireguardSplitTunnel.WindowsUpdate.Tests.csproj'
$isWindowsHost = $PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows
$isMacHost = -not $isWindowsHost -and $IsMacOS
$coreFilter = if ($isMacHost) {
    'FullyQualifiedName~Mac'
}
else {
    'FullyQualifiedName!~Mac'
}

& dotnet test $testProject `
    -p:RestoreConfigFile=$restoreConfig `
    --filter $coreFilter `
    @args
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

if ($isWindowsHost) {
    & dotnet test $windowsUpdateTestProject `
        -p:RestoreConfigFile=$restoreConfig `
        @args
    exit $LASTEXITCODE
}

exit 0
