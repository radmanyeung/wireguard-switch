param(
    [Parameter(Mandatory = $true)][string]$Tag,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [string]$RepositoryRoot =
        (Split-Path -Parent $PSScriptRoot),
    [string]$AppPublishRoot =
        (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts\publish-app'),
    [string]$UpdaterPublishRoot =
        (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts\publish-updater'),
    [string]$Props =
        (Join-Path (Split-Path -Parent $PSScriptRoot) 'Directory.Build.props')
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\release-package.ps1')

$rootFiles = @(
    'install.cmd',
    'start.cmd',
    'start-admin.cmd',
    'start-safe.cmd',
    'test.cmd',
    'diagnose.cmd',
    'fix-dns.cmd',
    'reset-network.cmd',
    'README.md'
)
$runtimeScripts = @(
    'bootstrap-env.ps1',
    'diagnose-status.ps1',
    'ensure-prebuilt.ps1',
    'fix-dns.ps1',
    'install.ps1',
    'reset-network.ps1',
    'start.ps1',
    'test.ps1',
    'update-launcher.ps1',
    'WindowsRelease.psm1'
)
$runtimeLibraryScripts = @(
    'release-package.ps1'
)
$forbiddenPublishNames = @(
    '.pdb',
    '.xml'
)

function Assert-PlainDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Unsafe directory: $Path"
    }
}

function Get-ContainedRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $prefix = $rootFull + [IO.Path]::DirectorySeparatorChar
    $pathFull = [IO.Path]::GetFullPath($Path)
    if (-not $pathFull.StartsWith(
            $prefix,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes its declared root: $Path"
    }
    return $pathFull.Substring($prefix.Length)
}

function Copy-RequiredFile {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "Required Release file is missing: $Source"
    }

    $item = Get-Item -LiteralPath $Source -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Release file cannot be a reparse point: $Source"
    }

    $parent = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination
}

function Copy-CleanPublish {
    param(
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$DestinationRoot
    )

    if (-not (Test-Path -LiteralPath $SourceRoot -PathType Container)) {
        throw "Publish output is missing: $SourceRoot"
    }

    Assert-PlainDirectory $SourceRoot
    $sourceFull = [IO.Path]::GetFullPath($SourceRoot)
    foreach ($file in Get-ChildItem -LiteralPath $SourceRoot -Recurse -File -Force |
        Sort-Object FullName) {
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Publish output contains a reparse point: $($file.FullName)"
        }

        $relative = Get-ContainedRelativePath `
            -Root $sourceFull `
            -Path $file.FullName
        $segments = $relative -split '[\\/]'
        if ($segments -contains 'bin' -or $segments -contains 'obj') {
            throw "Publish output contains a build directory: $relative"
        }

        if ($file.Name -match '(?i)tests?' -or
            $forbiddenPublishNames -contains $file.Extension.ToLowerInvariant()) {
            continue
        }

        $target = Join-Path $DestinationRoot $relative
        if (Test-Path -LiteralPath $target -PathType Leaf) {
            $left = Get-WgstSha256 -Path $file.FullName
            $right = Get-WgstSha256 -Path $target
            if ($left -ne $right) {
                throw "Publish outputs collide with different bytes: $relative"
            }
            continue
        }

        Copy-RequiredFile -Source $file.FullName -Destination $target
    }
}

function New-DeterministicZip {
    param(
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$ArchivePath
    )

    Add-Type -AssemblyName System.IO.Compression
    $stream = [IO.File]::Open(
        $ArchivePath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
    try {
        $zip = [IO.Compression.ZipArchive]::new(
            $stream,
            [IO.Compression.ZipArchiveMode]::Create,
            $false,
            [Text.Encoding]::UTF8)
        try {
            $sourceFull = [IO.Path]::GetFullPath($SourceRoot)
            $files = Get-ChildItem -LiteralPath $SourceRoot -Recurse -File |
                ForEach-Object {
                    [pscustomobject]@{
                        FullName = $_.FullName
                        Relative = (Get-ContainedRelativePath `
                            -Root $sourceFull `
                            -Path $_.FullName).Replace('\', '/')
                    }
                } |
                Sort-Object @{ Expression = { $_.Relative.ToLowerInvariant() } },
                    @{ Expression = { $_.Relative } }
            foreach ($file in $files) {
                $entry = $zip.CreateEntry(
                    $file.Relative,
                    [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime =
                    [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
                $input = [IO.File]::OpenRead($file.FullName)
                $output = $entry.Open()
                try {
                    $input.CopyTo($output)
                }
                finally {
                    $output.Dispose()
                    $input.Dispose()
                }
            }
        }
        finally {
            $zip.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

$repositoryFull = [IO.Path]::GetFullPath($RepositoryRoot)
$outputFull = [IO.Path]::GetFullPath($OutputRoot)
if ($outputFull -eq $repositoryFull -or
    $repositoryFull.StartsWith(
        $outputFull + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputRoot cannot be the repository root or its parent.'
}

if (Test-Path -LiteralPath $outputFull) {
    Assert-PlainDirectory $outputFull
    if (@(Get-ChildItem -LiteralPath $outputFull -Force).Count -ne 0) {
        throw 'OutputRoot must be newly empty.'
    }
}
else {
    New-Item -ItemType Directory -Path $outputFull | Out-Null
}

$packageRoot = Join-Path $outputFull 'package'
$packageScripts = Join-Path $packageRoot 'scripts'
$packagePayload = Join-Path $packageRoot 'WireguardSplitTunnel'
New-Item -ItemType Directory -Path $packageScripts | Out-Null
New-Item -ItemType Directory -Path $packagePayload | Out-Null

foreach ($relative in $rootFiles) {
    Copy-RequiredFile `
        -Source (Join-Path $repositoryFull $relative) `
        -Destination (Join-Path $packageRoot $relative)
}
foreach ($relative in $runtimeScripts) {
    Copy-RequiredFile `
        -Source (Join-Path (Join-Path $repositoryFull 'scripts') $relative) `
        -Destination (Join-Path $packageScripts $relative)
}
foreach ($relative in $runtimeLibraryScripts) {
    Copy-RequiredFile `
        -Source (Join-Path (Join-Path $repositoryFull 'scripts\lib') $relative) `
        -Destination (Join-Path (Join-Path $packageScripts 'lib') $relative)
}

Copy-CleanPublish `
    -SourceRoot $AppPublishRoot `
    -DestinationRoot $packagePayload
Copy-CleanPublish `
    -SourceRoot $UpdaterPublishRoot `
    -DestinationRoot $packagePayload

foreach ($requiredExecutable in @(
    'WireguardSplitTunnel.App.exe',
    'WireguardSplitTunnel.Updater.exe')) {
    if (-not (Test-Path -LiteralPath (
        Join-Path $packagePayload $requiredExecutable) -PathType Leaf)) {
        throw "Clean publish output is missing $requiredExecutable."
    }
}

New-WgstReleaseManifest `
    -PackageRoot $packageRoot `
    -Props $Props `
    -ExpectedTag $Tag
[void](Test-WgstReleasePackage `
    -PackageRoot $packageRoot `
    -Props $Props `
    -ExpectedTag $Tag)

$archive = Join-Path $outputFull 'wireguard-split-tunnel-win-x64.zip'
$sidecar = "$archive.sha256"
New-DeterministicZip -SourceRoot $packageRoot -ArchivePath $archive
$digest = Get-WgstSha256 -Path $archive
[IO.File]::WriteAllText(
    $sidecar,
    "$digest  wireguard-split-tunnel-win-x64.zip`n",
    [Text.UTF8Encoding]::new($false))

Write-Output $packageRoot
Write-Output $archive
Write-Output $sidecar
