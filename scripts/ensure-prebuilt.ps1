param(
    [Parameter(Mandatory = $true)][string]$RepoRoot,
    [string]$Repository = $(if ([string]::IsNullOrWhiteSpace($env:WGST_RELEASE_REPO)) { 'radmanyeung/wireguard-switch' } else { $env:WGST_RELEASE_REPO }),
    [string]$AssetUrl = $env:WGST_RELEASE_ASSET_URL
)

$ErrorActionPreference = 'Stop'

function Resolve-DownloadAsset {
    param(
        [Parameter(Mandatory = $true)][string]$Repo,
        [string]$DirectAssetUrl
    )

    if (-not [string]::IsNullOrWhiteSpace($DirectAssetUrl)) {
        $name = [System.IO.Path]::GetFileName(($DirectAssetUrl -split '\?')[0])
        if ([string]::IsNullOrWhiteSpace($name)) {
            $name = 'WireguardSplitTunnel-release.zip'
        }

        return [pscustomobject]@{
            Name = $name
            Url = $DirectAssetUrl
            Source = 'direct-url'
        }
    }

    if ([string]::IsNullOrWhiteSpace($Repo) -or -not $Repo.Contains('/')) {
        throw "Invalid GitHub repository format: $Repo"
    }

    $releaseApi = "https://api.github.com/repos/$Repo/releases/latest"
    $headers = @{ 'User-Agent' = 'WireguardSplitTunnelInstaller/1.0' }

    try {
        $release = Invoke-RestMethod -Uri $releaseApi -Headers $headers -Method Get
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '404' -or $msg -match 'Not Found') {
            throw "No latest release found for $Repo. Please create a GitHub Release with a prebuilt .zip/.exe asset, or set WGST_RELEASE_ASSET_URL."
        }

        throw "Failed to query GitHub Releases for ${Repo}: $msg"
    }

    if ($null -eq $release -or $null -eq $release.assets -or $release.assets.Count -eq 0) {
        throw "Latest release in $Repo has no assets. Upload a prebuilt .zip/.exe file."
    }

    $assets = @($release.assets)

    $zipAsset = $assets |
        Where-Object {
            $_.name -match '(?i)wireguard.*(split|tunnel|switch)' -and $_.name -match '(?i)\.zip$'
        } |
        Select-Object -First 1

    if ($null -eq $zipAsset) {
        $zipAsset = $assets |
            Where-Object { $_.name -match '(?i)\.zip$' } |
            Select-Object -First 1
    }

    $exeAsset = $assets |
        Where-Object {
            $_.name -match '(?i)wireguard.*(split|tunnel|switch)' -and $_.name -match '(?i)\.exe$'
        } |
        Select-Object -First 1

    if ($null -eq $exeAsset) {
        $exeAsset = $assets |
            Where-Object { $_.name -match '(?i)\.exe$' } |
            Select-Object -First 1
    }

    $asset = if ($null -ne $zipAsset) { $zipAsset } else { $exeAsset }
    if ($null -eq $asset) {
        $names = ($assets | ForEach-Object { $_.name }) -join ', '
        throw "No suitable .zip/.exe release asset found. Available: $names"
    }

    return [pscustomobject]@{
        Name = $asset.name
        Url = $asset.browser_download_url
        Source = 'github-release'
    }
}

$publishDir = Join-Path $RepoRoot 'WireguardSplitTunnel'
$publishedExe = Join-Path $publishDir 'WireguardSplitTunnel.App.exe'
if (Test-Path $publishedExe) {
    Write-Output $publishedExe
    return
}

$asset = Resolve-DownloadAsset -Repo $Repository -DirectAssetUrl $AssetUrl

$tempRoot = Join-Path $env:TEMP 'wgst-release-download'
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
$downloadPath = Join-Path $tempRoot $asset.Name
$headers = @{ 'User-Agent' = 'WireguardSplitTunnelInstaller/1.0' }
Invoke-WebRequest -Uri $asset.Url -OutFile $downloadPath -UseBasicParsing -Headers $headers

New-Item -ItemType Directory -Path $publishDir -Force | Out-Null

if ($downloadPath -match '(?i)\.zip$') {
    $extractDir = Join-Path $tempRoot ("extract-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
    Expand-Archive -LiteralPath $downloadPath -DestinationPath $extractDir -Force

    $exe = Get-ChildItem -Path $extractDir -Recurse -File -Filter 'WireguardSplitTunnel.App.exe' | Select-Object -First 1
    if ($null -eq $exe) {
        throw "Downloaded ZIP does not contain WireguardSplitTunnel.App.exe"
    }

    $sourceDir = Split-Path -Parent $exe.FullName
    Copy-Item -Path (Join-Path $sourceDir '*') -Destination $publishDir -Recurse -Force
}
else {
    Copy-Item -Path $downloadPath -Destination $publishedExe -Force
}

if (-not (Test-Path $publishedExe)) {
    throw "Prebuilt download completed but WireguardSplitTunnel.App.exe not found at $publishedExe"
}

Write-Output $publishedExe

