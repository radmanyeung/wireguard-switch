$ErrorActionPreference = 'Stop'

function Get-WgstInstallMode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][bool]$HasManifest,
        [Parameter(Mandatory = $true)][bool]$HasBundledExecutable,
        [Parameter(Mandatory = $true)][bool]$HasSourceProject,
        [Parameter(Mandatory = $true)][bool]$HasProps,
        [Parameter(Mandatory = $true)][bool]$HasSdk,
        [Parameter(Mandatory = $true)][bool]$SkipPublish,
        [Parameter(Mandatory = $true)][bool]$ForcePublish
    )

    if ($ForcePublish) {
        if (-not $HasSourceProject -or -not $HasProps) {
            throw 'ForcePublish requires the source project and Directory.Build.props.'
        }

        return 'PublishSource'
    }

    if ($SkipPublish) {
        if (-not $HasBundledExecutable) {
            throw 'SkipPublish requires a bundled executable.'
        }

        return 'BundledRelease'
    }

    if ($HasManifest -and $HasBundledExecutable) {
        return 'BundledRelease'
    }

    if ($HasSourceProject -and $HasProps) {
        return 'PublishSource'
    }

    throw 'No valid bundled Release or publishable source checkout was found.'
}

function Get-WgstReleaseToolProject {
    [CmdletBinding()]
    param()

    $repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $project = Join-Path $repositoryRoot 'tools\WireguardSplitTunnel.ReleaseTool\WireguardSplitTunnel.ReleaseTool.csproj'
    if (-not (Test-Path -LiteralPath $project -PathType Leaf)) {
        throw "Release tool project is missing: $project"
    }

    return $project
}

function Invoke-WgstReleaseTool {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $project = Get-WgstReleaseToolProject
    $dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($null -eq $dotnet) {
        throw '.NET SDK is required for Release package generation and validation.'
    }

    & $dotnet.Source run `
        --project $project `
        -c Release `
        --no-launch-profile `
        -- @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Release tool failed with exit code $LASTEXITCODE."
    }
}

function New-WgstReleaseManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [Parameter(Mandatory = $true)][string]$Props,
        [Parameter(Mandatory = $true)][string]$ExpectedTag
    )

    Invoke-WgstReleaseTool -Arguments @(
        'generate-manifest',
        '--package-root', $PackageRoot,
        '--props', $Props,
        '--expected-tag', $ExpectedTag
    )
}

function Test-WgstReleasePackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [Parameter(Mandatory = $true)][string]$Props,
        [Parameter(Mandatory = $true)][string]$ExpectedTag
    )

    Invoke-WgstReleaseTool -Arguments @(
        'validate-package',
        '--package-root', $PackageRoot,
        '--props', $Props,
        '--expected-tag', $ExpectedTag
    )
    return $true
}

function Get-WgstSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $stream = [System.IO.File]::Open(
        $resolved,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $digest = $sha.ComputeHash($stream)
            return (($digest | ForEach-Object {
                $_.ToString('x2')
            }) -join '')
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}
