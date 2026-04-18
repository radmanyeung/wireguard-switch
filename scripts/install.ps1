param(
    [switch]$SkipPublish,
    [switch]$NoDesktopShortcut,
    [switch]$NoPostInstallSelfTest,
    [switch]$Elevated,
    [string]$LauncherLogPath
)

$ErrorActionPreference = 'Stop'

function Write-LauncherLog {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($LauncherLogPath)) {
        return
    }

    $directory = Split-Path -Parent $LauncherLogPath
    if (-not [string]::IsNullOrWhiteSpace($directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $line = "[{0}] [INSTALL.PS1] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff zzz'), $Message
    Add-Content -Path $LauncherLogPath -Value $line
}

function Write-Step {
    param([string]$Message)
    Write-Host "[INSTALL] $Message"
    Write-LauncherLog $Message
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Administrator {
    if (Test-IsAdministrator) {
        return
    }

    if ($Elevated) {
        throw 'Failed to acquire Administrator rights. Please re-run install.cmd and approve the UAC prompt.'
    }

    $self = $PSCommandPath
    $argList = @('-ExecutionPolicy', 'Bypass', '-File', "`"$self`"", '-Elevated')
    if ($SkipPublish) { $argList += '-SkipPublish' }
    if ($NoDesktopShortcut) { $argList += '-NoDesktopShortcut' }
    if ($NoPostInstallSelfTest) { $argList += '-NoPostInstallSelfTest' }
    if (-not [string]::IsNullOrWhiteSpace($LauncherLogPath)) {
        $argList += '-LauncherLogPath'
        $argList += "`"$LauncherLogPath`""
    }

    Start-Process -FilePath 'powershell' -Verb RunAs -ArgumentList $argList
    Write-Step 'ELEVATION_REQUESTED'
    exit 0
}

function New-DesktopShortcut {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$TargetPath,
        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory
    )

    $desktop = [Environment]::GetFolderPath('Desktop')
    $shortcutPath = Join-Path $desktop ("$Name.lnk")

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $TargetPath
    $shortcut.WorkingDirectory = $WorkingDirectory
    $shortcut.Save()

    return $shortcutPath
}

function Get-DotnetCommand {
    $dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($null -ne $dotnet) {
        return $dotnet.Source
    }

    $fallback = Join-Path $env:ProgramFiles 'dotnet\dotnet.exe'
    if (Test-Path $fallback) {
        return $fallback
    }

    return $null
}

function Get-DotnetSdkCount {
    param([string]$DotnetPath)

    if ([string]::IsNullOrWhiteSpace($DotnetPath)) {
        return 0
    }

    $output = & $DotnetPath --list-sdks 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $output) {
        return 0
    }

    return @($output | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
}

function Get-WireGuardCliPath {
    $wg = Get-Command wireguard -ErrorAction SilentlyContinue
    if ($null -ne $wg) {
        return $wg.Source
    }

    $candidates = @(
        (Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'WireGuard\wireguard.exe')
    )

    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path $candidate)) {
            return $candidate
        }
    }

    return $null
}

function Install-WithWinget {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($null -eq $winget) {
        return $false
    }

    Write-Step "Auto-installing $Name via winget..."
    & $winget.Source install --id $Id --exact --accept-package-agreements --accept-source-agreements --silent
    return $LASTEXITCODE -eq 0
}

function Invoke-DownloadAndRun {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $tempRoot = Join-Path $env:TEMP 'wgst-bootstrap'
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    $installer = Join-Path $tempRoot $FileName

    Write-Step "Downloading $FileName ..."
    Invoke-WebRequest -Uri $Url -OutFile $installer -UseBasicParsing

    Write-Step "Running $FileName ..."
    $proc = Start-Process -FilePath $installer -ArgumentList $Arguments -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        throw "Installer failed: $FileName (exit $($proc.ExitCode))"
    }
}

function Ensure-DotnetSdk8 {
    param([bool]$Needed)

    if (-not $Needed) {
        return
    }

    if (Install-WithWinget -Id 'Microsoft.DotNet.SDK.8' -Name '.NET 8 SDK') {
        return
    }

    Write-Step 'winget not available or failed, fallback to direct .NET SDK installer.'
    Invoke-DownloadAndRun `
        -Url 'https://aka.ms/dotnet/8.0/dotnet-sdk-win-x64.exe' `
        -FileName 'dotnet-sdk-8-win-x64.exe' `
        -Arguments @('/install', '/quiet', '/norestart')
}

function Ensure-WireGuard {
    if (Install-WithWinget -Id 'WireGuard.WireGuard' -Name 'WireGuard') {
        return
    }

    Write-Step 'winget not available or failed, fallback to direct WireGuard installer.'
    Invoke-DownloadAndRun `
        -Url 'https://download.wireguard.com/windows-client/wireguard-installer.exe' `
        -FileName 'wireguard-installer.exe' `
        -Arguments @('/S')
}

Write-LauncherLog "Startup. elevated=$Elevated skipPublish=$SkipPublish noDesktopShortcut=$NoDesktopShortcut noPostInstallSelfTest=$NoPostInstallSelfTest"

Ensure-Administrator

$repoRoot = Split-Path -Parent $PSScriptRoot
$projectPath = Join-Path $repoRoot 'src\WireguardSplitTunnel.App\WireguardSplitTunnel.App.csproj'
$publishDir = Join-Path $repoRoot 'WireguardSplitTunnel'
$publishedExe = Join-Path $publishDir 'WireguardSplitTunnel.App.exe'

Write-Step "Repo root: $repoRoot"
Write-Step 'Checking prerequisites...'

$dotnetPath = Get-DotnetCommand
$sdkCount = Get-DotnetSdkCount -DotnetPath $dotnetPath
$hasSdk = $sdkCount -gt 0

if ((-not $SkipPublish) -and (-not $hasSdk) -and (-not (Test-Path $publishedExe))) {
    $ensurePrebuiltScript = Join-Path $PSScriptRoot 'ensure-prebuilt.ps1'
    if (Test-Path $ensurePrebuiltScript) {
        try {
            Write-Step 'No SDK + no local prebuilt. Downloading latest prebuilt from GitHub Releases...'
            $downloadedExe = & $ensurePrebuiltScript -RepoRoot $repoRoot
            if (-not [string]::IsNullOrWhiteSpace($downloadedExe) -and (Test-Path $downloadedExe)) {
                Write-Step "Prebuilt downloaded: $downloadedExe"
            }
        }
        catch {
            Write-LauncherLog "GitHub prebuilt download failed: $($_.Exception.Message)"
            Write-Warning "GitHub prebuilt download failed: $($_.Exception.Message)"
        }
    }
}

$needSdkForPublish = (-not $SkipPublish) -and (-not $hasSdk) -and (-not (Test-Path $publishedExe))

if ($needSdkForPublish) {
    Ensure-DotnetSdk8 -Needed $true
    $dotnetPath = Get-DotnetCommand
    $sdkCount = Get-DotnetSdkCount -DotnetPath $dotnetPath
    $hasSdk = $sdkCount -gt 0
    if (-not $hasSdk) {
        throw '.NET SDK install completed but SDK is still not detected. Re-open terminal and run install.cmd again.'
    }
}

$wireGuardPath = Get-WireGuardCliPath
if ([string]::IsNullOrWhiteSpace($wireGuardPath)) {
    Ensure-WireGuard
    $wireGuardPath = Get-WireGuardCliPath
    if ([string]::IsNullOrWhiteSpace($wireGuardPath)) {
        throw 'WireGuard install completed but wireguard.exe is still not detected.'
    }
}

Write-Step 'Preparing folders...'
$dataDir = Join-Path $env:LOCALAPPDATA 'WireguardSplitTunnel'
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null

$runtimeLog = Join-Path $repoRoot 'runtime.log'
if (-not (Test-Path $runtimeLog)) {
    New-Item -ItemType File -Path $runtimeLog -Force | Out-Null
}

if (-not $SkipPublish) {
    if ($hasSdk) {
        Write-Step 'Publishing app (Release, win-x64, self-contained)...'
        New-Item -ItemType Directory -Path $publishDir -Force | Out-Null

        & $dotnetPath publish $projectPath `
            -c Release `
            -r win-x64 `
            --self-contained true `
            -p:PublishSingleFile=true `
            -o $publishDir

        if ($LASTEXITCODE -ne 0) {
            throw "dotnet publish failed with exit code $LASTEXITCODE"
        }

        if (-not (Test-Path $publishedExe)) {
            throw 'Publish completed but app exe not found in WireguardSplitTunnel folder.'
        }
    }
    elseif (Test-Path $publishedExe) {
        Write-LauncherLog 'No .NET SDK detected. Skipping publish and using bundled prebuilt EXE.'
        Write-Warning 'No .NET SDK detected. Skipping publish and using bundled prebuilt EXE.'
    }
    else {
        throw 'No .NET SDK found and prebuilt EXE is missing. Please package from a build machine first.'
    }
}

if (-not $NoDesktopShortcut) {
    Write-Step 'Creating desktop shortcuts...'
    $startShortcut = New-DesktopShortcut -Name 'Wireguard Split Tunnel' -TargetPath (Join-Path $repoRoot 'start.cmd') -WorkingDirectory $repoRoot
    $testShortcut = New-DesktopShortcut -Name 'Wireguard Split Tunnel Test' -TargetPath (Join-Path $repoRoot 'test.cmd') -WorkingDirectory $repoRoot
    Write-Step "Shortcut created: $startShortcut"
    Write-Step "Shortcut created: $testShortcut"
}

Write-Step 'Writing install marker...'
$markerPath = Join-Path $repoRoot 'install.status.txt'
$lines = @(
    "InstalledAt=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')",
    'RepoRoot=.',
    'PublishDir=.\\WireguardSplitTunnel',
    'PublishedExe=.\\WireguardSplitTunnel\\WireguardSplitTunnel.App.exe',
    "DotnetDetected=$([string]::IsNullOrWhiteSpace($dotnetPath) -eq $false)",
    "DotnetSdkCount=$sdkCount",
    "WireGuardDetected=$([string]::IsNullOrWhiteSpace($wireGuardPath) -eq $false)",
    'SelfContained=true',
    "Admin=$(Test-IsAdministrator)"
)
Set-Content -Path $markerPath -Value $lines -Encoding UTF8

Write-Step 'Install completed.'

if (-not $NoPostInstallSelfTest) {
    Write-Step 'Launching app for post-install self test...'
    $startScript = Join-Path $PSScriptRoot 'start.ps1'
    $argList = @(
        '-ExecutionPolicy', 'Bypass',
        '-File', "`"$startScript`"",
        '-PostInstallSelfTest'
    )
    if (-not [string]::IsNullOrWhiteSpace($LauncherLogPath)) {
        $startLogPath = Join-Path (Split-Path -Parent $LauncherLogPath) 'start.ps1.log'
        $argList += '-LauncherLogPath'
        $argList += "`"$startLogPath`""
    }
    Start-Process -FilePath 'powershell' -ArgumentList $argList
}

Write-Step 'Next: app will show self test dialogs. If blocked by UAC, approve prompt.'


