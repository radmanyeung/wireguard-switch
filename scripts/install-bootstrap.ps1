param(
    [Parameter(Mandatory = $true)][string]$InstallerRoot,
    [string]$ForwardedArguments
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$minimumInstallerVersion = [version]'0.2.10'
$archiveName = 'wireguard-split-tunnel-win-x64.zip'
$checksumName = 'wireguard-split-tunnel-win-x64.zip.sha256'
$apiUri = 'https://api.github.com/repos/radmanyeung/wireguard-switch/releases/latest'
$maximumRedirects = 5
$maximumArchiveBytes = 256MB
$allowedDownloadHosts = @(
    'api.github.com',
    'github.com',
    'objects.githubusercontent.com',
    'release-assets.githubusercontent.com'
)
$requiredFiles = @(
    'release-manifest.json',
    'scripts\install.ps1',
    'scripts\WindowsRelease.psm1',
    'scripts\lib\release-package.ps1',
    'WireguardSplitTunnel\WireguardSplitTunnel.App.exe',
    'WireguardSplitTunnel\WireguardSplitTunnel.Updater.exe'
)

function Get-WgstForwardedInstallArguments {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @{} }
    $allowed = @('NoDesktopShortcut', 'NoPostInstallSelfTest', 'RepairBlockedUpdate', 'SkipPublish')
    $result = @{}
    $remaining = $Text.Trim()
    foreach ($match in [regex]::Matches($remaining, '(?<!\S)-([A-Za-z][A-Za-z0-9]*)')) {
        $name = $match.Groups[1].Value
        if ($name -notin $allowed) { throw "Unsupported install.cmd option: -$name" }
        $result[$name] = $true
        $remaining = $remaining.Replace($match.Value, '').Trim()
    }
    if (-not [string]::IsNullOrWhiteSpace($remaining)) {
        throw "Unsupported install.cmd arguments: $remaining"
    }
    return $result
}

function New-WgstBootstrapHttpClient {
    Add-Type -AssemblyName System.Net.Http
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromMinutes(15)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd(
        'WireguardSplitTunnel-Installer/0.2.10')
    return $client
}

function Invoke-WgstBootstrapHttpGet {
    param(
        [Parameter(Mandatory = $true)][Net.Http.HttpClient]$Client,
        [Parameter(Mandatory = $true)][Uri]$Uri,
        [Parameter(Mandatory = $true)][long]$MaximumBytes,
        [string]$OutputPath
    )

    $current = $Uri
    for ($redirect = 0; $redirect -le $maximumRedirects; $redirect++) {
        if ($current.Scheme -cne 'https' -or
            $current.Host -notin $allowedDownloadHosts -or
            -not [string]::IsNullOrEmpty($current.UserInfo)) {
            throw "Release download URI is not allowed: $current"
        }
        $response = $Client.GetAsync(
            $current,
            [Net.Http.HttpCompletionOption]::ResponseHeadersRead
        ).GetAwaiter().GetResult()
        try {
            $status = [int]$response.StatusCode
            if ($status -ge 300 -and $status -lt 400) {
                if ($redirect -eq $maximumRedirects -or
                    $null -eq $response.Headers.Location) {
                    throw 'Release download exceeded its redirect policy.'
                }
                $current = [Uri]::new($current, $response.Headers.Location)
                continue
            }
            if (-not $response.IsSuccessStatusCode) {
                throw "Release download returned HTTP $status."
            }
            $declaredLength = $response.Content.Headers.ContentLength
            if ($null -ne $declaredLength -and
                ([long]$declaredLength -lt 0 -or
                 [long]$declaredLength -gt $MaximumBytes)) {
                throw 'Release download exceeds its byte limit.'
            }
            $input = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $output = if ([string]::IsNullOrWhiteSpace($OutputPath)) {
                [IO.MemoryStream]::new()
            }
            else {
                [IO.File]::Open(
                    $OutputPath,
                    [IO.FileMode]::CreateNew,
                    [IO.FileAccess]::Write,
                    [IO.FileShare]::None)
            }
            try {
                $buffer = New-Object byte[] 81920
                [long]$total = 0
                while ($true) {
                    $readTimeout = [Threading.CancellationTokenSource]::new()
                    try {
                        $readTimeout.CancelAfter([TimeSpan]::FromSeconds(60))
                        $read = $input.ReadAsync(
                            $buffer,
                            0,
                            $buffer.Length,
                            $readTimeout.Token).GetAwaiter().GetResult()
                    }
                    finally {
                        $readTimeout.Dispose()
                    }
                    if ($read -le 0) { break }
                    $total += $read
                    if ($total -gt $MaximumBytes) {
                        throw 'Release download exceeds its byte limit.'
                    }
                    $output.Write($buffer, 0, $read)
                }
                $output.Flush()
                if ($output -is [IO.MemoryStream]) {
                    return ,$output.ToArray()
                }
                return $OutputPath
            }
            catch {
                if (-not [string]::IsNullOrWhiteSpace($OutputPath) -and
                    (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
                    $output.Dispose()
                    Remove-Item -LiteralPath $OutputPath -Force
                    $output = $null
                }
                throw
            }
            finally {
                if ($null -ne $output) { $output.Dispose() }
                $input.Dispose()
            }
        }
        finally {
            $response.Dispose()
        }
    }
    throw 'Release download exceeded its redirect policy.'
}

function Test-WgstSafeRelativePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains('\') -or
        $Path.Contains(':') -or $Path.StartsWith('/') -or $Path.EndsWith('/')) {
        return $false
    }
    foreach ($segment in $Path.Split('/')) {
        if ([string]::IsNullOrWhiteSpace($segment) -or $segment -in @('.', '..') -or
            $segment.EndsWith('.') -or $segment.EndsWith(' ')) { return $false }
    }
    return $true
}

function Get-WgstBootstrapSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString(
            $sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Test-WgstCompleteLocalRelease {
    param([string]$Root)
    try {
        $canonicalRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
        foreach ($required in $requiredFiles) {
            if (-not [IO.File]::Exists((Join-Path $canonicalRoot $required))) { throw "required file is missing: $required" }
        }
        $manifestPath = Join-Path $canonicalRoot 'release-manifest.json'
        if ((Get-Item -LiteralPath $manifestPath).Length -gt 2MB) { throw 'manifest exceeds its byte limit' }
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if ([string]$manifest.version -cnotmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -or
            [version]$manifest.version -lt $minimumInstallerVersion) { throw 'manifest version is unsupported' }
        $seen = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($file in @($manifest.files)) {
            $relative = [string]$file.path
            if (-not (Test-WgstSafeRelativePath $relative) -or -not $seen.Add($relative)) { throw "manifest path is unsafe or duplicated: $relative" }
            $path = Join-Path $canonicalRoot ($relative.Replace('/', '\'))
            if (-not [IO.File]::Exists($path)) { throw "manifest payload is missing: $relative" }
            $item = Get-Item -LiteralPath $path -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                $item.Length -ne [long]$file.length -or
                (Get-WgstBootstrapSha256 -Path $path) -cne
                    [string]$file.sha256) { throw "manifest payload changed: $relative" }
        }
        foreach ($required in $requiredFiles | Where-Object {
                $_ -cne 'release-manifest.json'
            }) {
            if (-not $seen.Contains($required.Replace('\', '/'))) { throw "required file is not manifest-bound: $required" }
        }
        foreach ($item in Get-ChildItem -LiteralPath $canonicalRoot -Recurse -Force -File) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'local package contains a reparse point' }
            $relative = $item.FullName.Substring($canonicalRoot.Length + 1).Replace('\', '/')
            if ($relative -ceq 'release-manifest.json' -or
                $seen.Contains($relative) -or
                $relative.StartsWith('logs/', [StringComparison]::OrdinalIgnoreCase) -or
                $relative -in @('runtime.log', 'install.status.txt', 'WireguardSplitTunnel/runtime.log')) {
                continue
            }
            throw "local package contains an undeclared file: $relative"
        }
        return $true
    }
    catch {
        Write-Host "[INSTALL] Local Release rejected: $($_.Exception.Message)"
        return $false
    }
}

function Expand-WgstSafeReleaseArchive {
    param([string]$Archive, [string]$Destination)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [void][IO.Directory]::CreateDirectory($Destination)
    $root = [IO.Path]::GetFullPath($Destination).TrimEnd('\')
    $prefix = $root + '\'
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        if ($zip.Entries.Count -gt 4096) { throw 'Release archive contains too many entries.' }
        [long]$expanded = 0
        foreach ($entry in $zip.Entries) {
            $relative = $entry.FullName.Replace('\', '/')
            $isDirectory = $relative.EndsWith('/')
            $candidate = if ($isDirectory) { $relative.TrimEnd('/') } else { $relative }
            if (-not (Test-WgstSafeRelativePath $candidate)) {
                throw "Release archive contains an unsafe path: $relative"
            }
            if ((($entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000) {
                throw "Release archive contains a symbolic link: $relative"
            }
            $target = [IO.Path]::GetFullPath((Join-Path $root $candidate.Replace('/', '\')))
            if (-not $target.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Release archive path escapes extraction root: $relative"
            }
            if ($isDirectory) { [void][IO.Directory]::CreateDirectory($target); continue }
            if ($entry.Length -gt 512MB -or
                ($entry.CompressedLength -eq 0 -and $entry.Length -gt 0) -or
                ($entry.CompressedLength -gt 0 -and
                 ([double]$entry.Length / [double]$entry.CompressedLength) -gt 200.0)) {
                throw "Release archive entry exceeds its expansion policy: $relative"
            }
            $expanded += $entry.Length
            if ($expanded -gt 1GB) { throw 'Release archive expands beyond its byte limit.' }
            [void][IO.Directory]::CreateDirectory((Split-Path -Parent $target))
            $input = $entry.Open()
            $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $input.CopyTo($output) } finally { $output.Dispose(); $input.Dispose() }
        }
    }
    finally { $zip.Dispose() }
}

function Get-WgstOfficialRelease {
    param([string]$WorkingRoot)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $client = New-WgstBootstrapHttpClient
    try {
        $releaseBytes = Invoke-WgstBootstrapHttpGet -Client $client -Uri ([Uri]$apiUri) -MaximumBytes 2MB
        $releaseText = [Text.UTF8Encoding]::new($false, $true).GetString($releaseBytes)
        $release = $releaseText | ConvertFrom-Json
        if ($release.draft -or $release.prerelease -or
            [string]$release.tag_name -cnotmatch '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
            throw 'GitHub latest Release is not a stable normalized version.'
        }
        $version = [version]([string]$release.tag_name).Substring(1)
        if ($version -lt $minimumInstallerVersion) {
            throw "Latest stable Release $($release.tag_name) predates the standalone installer floor v$minimumInstallerVersion."
        }
        $archives = @($release.assets | Where-Object { [string]$_.name -ceq $archiveName })
        $sidecars = @($release.assets | Where-Object { [string]$_.name -ceq $checksumName })
        if ($archives.Count -ne 1 -or $sidecars.Count -ne 1) {
            throw 'Latest stable Release does not contain one exact Windows archive and checksum.'
        }
        $archive = Join-Path $WorkingRoot $archiveName
        $sidecar = Join-Path $WorkingRoot $checksumName
        [void](Invoke-WgstBootstrapHttpGet -Client $client -Uri ([Uri]$sidecars[0].browser_download_url) -MaximumBytes 4KB -OutputPath $sidecar)
        [void](Invoke-WgstBootstrapHttpGet -Client $client -Uri ([Uri]$archives[0].browser_download_url) -MaximumBytes $maximumArchiveBytes -OutputPath $archive)
        $checksumText = [Text.UTF8Encoding]::new($false, $true).GetString([IO.File]::ReadAllBytes($sidecar))
        if ($checksumText -cnotmatch '^([0-9a-f]{64})  wireguard-split-tunnel-win-x64\.zip\n$') {
            throw 'Release checksum sidecar is not canonical.'
        }
        $expectedDigest = $Matches[1]
        $digest = Get-WgstBootstrapSha256 -Path $archive
        if ($digest -cne $expectedDigest) { throw 'Downloaded Release archive does not match its checksum.' }
        $package = Join-Path $WorkingRoot 'package'
        Expand-WgstSafeReleaseArchive -Archive $archive -Destination $package
        if (-not (Test-WgstCompleteLocalRelease $package)) {
            throw 'Downloaded Release package failed complete manifest validation.'
        }
        return $package
    }
    finally { $client.Dispose() }
}

$root = [IO.Path]::GetFullPath($InstallerRoot)
$downloadRoot = $null
$arguments = Get-WgstForwardedInstallArguments $ForwardedArguments
try {
    Write-Output "[INSTALL] Bootstrap root: $root"
    if (Test-WgstCompleteLocalRelease $root) {
        Write-Output "[INSTALL] Using complete local Release: $root"
        $packageRoot = $root
    }
    else {
        $localData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
        if ([string]::IsNullOrWhiteSpace($localData)) { throw 'Local application-data directory is unavailable.' }
        $downloadRoot = Join-Path $localData ('WireguardSplitTunnel\installer\' + [Guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($downloadRoot)
        Write-Output '[INSTALL] Local package is incomplete or is source; downloading the complete official Release...'
        $packageRoot = Get-WgstOfficialRelease -WorkingRoot $downloadRoot
    }
    $arguments['LauncherLogPath'] = Join-Path (
        [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) (
        'WireguardSplitTunnel\logs\install.ps1.log')
    & (Join-Path $packageRoot 'scripts\install.ps1') @arguments
    if (-not $?) { throw 'The protected installer returned failure.' }
}
finally {
    if (-not [string]::IsNullOrWhiteSpace($downloadRoot) -and (Test-Path -LiteralPath $downloadRoot)) {
        $installerBase = [IO.Path]::GetFullPath((Join-Path (
            [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) (
            'WireguardSplitTunnel\installer'))).TrimEnd('\') + '\'
        $resolved = [IO.Path]::GetFullPath($downloadRoot)
        if ($resolved.StartsWith($installerBase, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolved -Recurse -Force
        }
    }
}
