param(
    [Parameter(Mandatory = $true)][string]$RepoRoot,
    [switch]$DescribeContract
)

$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot 'WindowsRelease.psm1'
if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
    throw "Fixed Release bootstrap module is missing: $modulePath"
}

Import-Module $modulePath -Force
if ($DescribeContract) {
    Get-WgstFixedReleaseContract |
        ConvertTo-Json -Depth 4 -Compress
    return
}

$publishDir = Join-Path $RepoRoot 'WireguardSplitTunnel'
$publishedExe = Join-Path $publishDir 'WireguardSplitTunnel.App.exe'
if (Test-Path -LiteralPath $publishedExe -PathType Leaf) {
    Write-Output $publishedExe
    return
}

$downloaded = Invoke-WgstBootstrapRelease -RepoRoot $RepoRoot
if ([string]::IsNullOrWhiteSpace($downloaded) -or
    -not (Test-Path -LiteralPath $downloaded -PathType Leaf)) {
    throw 'Validated fixed-repository bootstrap did not produce the application executable.'
}
Write-Output $downloaded
