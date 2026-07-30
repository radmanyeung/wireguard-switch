param(
    [Parameter(Mandatory = $true)][string]$PackageRoot,
    [Parameter(Mandatory = $true)][string]$Props,
    [Parameter(Mandatory = $true)][string]$ExpectedTag
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\release-package.ps1')
[void](Test-WgstReleasePackage `
    -PackageRoot $PackageRoot `
    -Props $Props `
    -ExpectedTag $ExpectedTag)
