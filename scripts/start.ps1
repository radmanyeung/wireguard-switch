param(
    [switch]$DryRun,
    [switch]$Elevated,
    [switch]$PostInstallSelfTest,
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

    $line = "[{0}] [START.PS1] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff zzz'), $Message
    Add-Content -Path $LauncherLogPath -Value $line
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Unblock-AppFile {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path $Path)) {
        return
    }

    try {
        Unblock-File -LiteralPath $Path -ErrorAction Stop
        Write-LauncherLog "Unblocked app file: $Path"
    }
    catch {
        Write-LauncherLog "Unblock skipped for app file ($Path): $($_.Exception.Message)"
    }
}

function Get-ExpectedAppVersion {
    param([string]$RepoRoot)

    $propsPath = Join-Path $RepoRoot 'Directory.Build.props'
    if (-not (Test-Path $propsPath)) {
        return $null
    }

    try {
        $content = Get-Content -LiteralPath $propsPath -Raw
        $match = [regex]::Match($content, '<VersionPrefix>\s*([^<]+?)\s*</VersionPrefix>')
        if ($match.Success) {
            return $match.Groups[1].Value.Trim().TrimStart('v')
        }
    }
    catch {
        Write-LauncherLog "Unable to read expected app version: $($_.Exception.Message)"
    }

    return $null
}

function Normalize-VersionText {
    param([string]$VersionText)

    if ([string]::IsNullOrWhiteSpace($VersionText)) {
        return $null
    }

    $value = $VersionText.Trim().TrimStart('v')
    $metadataIndex = $value.IndexOf('+')
    if ($metadataIndex -ge 0) {
        $value = $value.Substring(0, $metadataIndex)
    }

    if ($value -match '^(\d+)\.(\d+)\.(\d+)\.0$') {
        return "$($Matches[1]).$($Matches[2]).$($Matches[3])"
    }

    return $value
}

function Get-AppFileVersionInfo {
    param([System.IO.FileInfo]$File)

    $versionText = $null
    $versionKey = [version]'0.0.0.0'
    try {
        $fileVersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
        $versionText = Normalize-VersionText $fileVersionInfo.ProductVersion
        if ([string]::IsNullOrWhiteSpace($versionText)) {
            $versionText = Normalize-VersionText $fileVersionInfo.FileVersion
        }
        if (-not [string]::IsNullOrWhiteSpace($versionText)) {
            [version]$parsed = $versionText
            $versionKey = $parsed
        }
    }
    catch {
        Write-LauncherLog "Unable to read app version for $($File.FullName): $($_.Exception.Message)"
    }

    [pscustomobject]@{
        FullName = $File.FullName
        LastWriteTime = $File.LastWriteTime
        VersionText = $versionText
        VersionKey = $versionKey
    }
}

try {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Write-LauncherLog "Startup. repoRoot=$repoRoot elevated=$Elevated dryRun=$DryRun postInstallSelfTest=$PostInstallSelfTest"

    $project = Join-Path $repoRoot 'src\WireguardSplitTunnel.App\WireguardSplitTunnel.App.csproj'
    $dotnetArguments = "run --project `"$project`""
    if ($PostInstallSelfTest) {
        $dotnetArguments += ' -- --post-install-self-test'
    }

    $expectedAppVersion = Normalize-VersionText (Get-ExpectedAppVersion -RepoRoot $repoRoot)
    if ($expectedAppVersion) {
        Write-LauncherLog "Expected app version from Directory.Build.props: $expectedAppVersion"
    }

    $appCandidates = @(
        (Join-Path $repoRoot 'WireguardSplitTunnel\WireguardSplitTunnel.App.exe'),
        (Join-Path $repoRoot 'src\WireguardSplitTunnel.App\bin\Release\net8.0-windows\WireguardSplitTunnel.App.exe'),
        (Join-Path $repoRoot 'src\WireguardSplitTunnel.App\bin\Release\net8.0-windows\win-x64\publish\WireguardSplitTunnel.App.exe'),
        (Join-Path $repoRoot 'src\WireguardSplitTunnel.App\bin\Debug\net8.0-windows\WireguardSplitTunnel.App.exe')
    )
    Write-LauncherLog ("App candidates: " + ($appCandidates -join '; '))
    $appCandidateFiles = $appCandidates |
        Where-Object { Test-Path $_ } |
        ForEach-Object { Get-AppFileVersionInfo -File (Get-Item -LiteralPath $_) }
    if ($appCandidateFiles) {
        Write-LauncherLog ("Existing app candidates: " + (($appCandidateFiles | ForEach-Object { "$($_.FullName) version=$($_.VersionText) ($($_.LastWriteTime.ToString('s')))" }) -join '; '))
    }

    $selectableCandidates = $appCandidateFiles
    if ($expectedAppVersion) {
        $selectableCandidates = $appCandidateFiles | Where-Object { $_.VersionText -eq $expectedAppVersion }
        if (-not $selectableCandidates) {
            Write-LauncherLog "No local exe matched expected version $expectedAppVersion. Falling back to dotnet/latest prebuilt path."
        }
    }

    $appExe = $selectableCandidates |
        Sort-Object @{ Expression = { $_.VersionKey }; Descending = $true }, @{ Expression = { $_.LastWriteTime }; Descending = $true } |
        Select-Object -First 1 -ExpandProperty FullName
    if ($appExe) {
        Write-LauncherLog "Resolved app exe: $appExe"
    }

    if (-not $appExe) {
        $ensurePrebuiltScript = Join-Path $PSScriptRoot 'ensure-prebuilt.ps1'
        if (Test-Path $ensurePrebuiltScript) {
            try {
                Write-LauncherLog 'No local exe found. Attempting ensure-prebuilt.ps1.'
                $downloadedExe = & $ensurePrebuiltScript -RepoRoot $repoRoot
                if (-not [string]::IsNullOrWhiteSpace($downloadedExe) -and (Test-Path $downloadedExe)) {
                    $downloadedInfo = Get-AppFileVersionInfo -File (Get-Item -LiteralPath $downloadedExe)
                    if (-not $expectedAppVersion -or $downloadedInfo.VersionText -eq $expectedAppVersion) {
                        $appExe = $downloadedExe
                        Write-LauncherLog "Prebuilt downloaded: $appExe"
                        Write-Output "PREBUILT_DOWNLOADED $appExe"
                    }
                    else {
                        Write-LauncherLog "Downloaded prebuilt version $($downloadedInfo.VersionText) did not match expected $expectedAppVersion."
                    }
                }
            }
            catch {
                Write-LauncherLog "Prebuilt download failed: $($_.Exception.Message)"
                Write-Warning "Prebuilt download failed: $($_.Exception.Message)"
            }
        }
    }

    if ($DryRun) {
        Write-LauncherLog 'Dry run requested.'
        if ($appExe) {
            if ($PostInstallSelfTest) {
                Write-Output "exe $appExe --post-install-self-test"
            }
            else {
                Write-Output "exe $appExe"
            }
        }
        else {
            Write-Output "dotnet $dotnetArguments"
        }

        exit 0
    }

    if (-not (Test-IsAdministrator)) {
        if ($Elevated) {
            Write-LauncherLog 'Elevation failed after rerun.'
            throw 'Failed to acquire Administrator rights. Please run start-admin.cmd and approve the UAC prompt.'
        }

        $scriptPath = Join-Path $PSScriptRoot 'start.ps1'
        $argList = @(
            '-ExecutionPolicy', 'Bypass',
            '-File', "`"$scriptPath`"",
            '-Elevated'
        )

        if ($PostInstallSelfTest) {
            $argList += '-PostInstallSelfTest'
        }
        if (-not [string]::IsNullOrWhiteSpace($LauncherLogPath)) {
            $argList += '-LauncherLogPath'
            $argList += "`"$LauncherLogPath`""
        }

        Write-LauncherLog "Requesting elevation via powershell. args=$($argList -join ' ')"
        Start-Process -FilePath 'powershell' -Verb RunAs -ArgumentList $argList
        Write-Output 'ELEVATION_REQUESTED'
        exit 0
    }

    if ($appExe) {
        $appArgs = if ($PostInstallSelfTest) { '--post-install-self-test' } else { '' }
        Unblock-AppFile -Path $appExe
        Write-LauncherLog "Launching exe. path=$appExe args=$appArgs"
        if ([string]::IsNullOrWhiteSpace($appArgs)) {
            Start-Process -FilePath $appExe -WorkingDirectory (Split-Path -Parent $appExe)
        }
        else {
            Start-Process -FilePath $appExe -ArgumentList $appArgs -WorkingDirectory (Split-Path -Parent $appExe)
        }

        if ($PostInstallSelfTest) {
            Write-Output "STARTED_EXE $appExe --post-install-self-test"
        }
        else {
            Write-Output "STARTED_EXE $appExe"
        }

        exit 0
    }

    $dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($null -eq $dotnet) {
        Write-LauncherLog 'No published app found and dotnet is unavailable.'
        throw 'No published app found and dotnet SDK is not installed. Run install.cmd first.'
    }

    $sdkOutput = (& dotnet --list-sdks 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $sdkOutput) {
        Write-LauncherLog 'No published app found and .NET SDK is unavailable.'
        throw 'No published app found and .NET SDK is not available. Please copy the prebuilt WireguardSplitTunnel folder from build machine, or install .NET 8 SDK.'
    }

    Write-LauncherLog "Launching dotnet fallback. args=$dotnetArguments"
    Start-Process -FilePath dotnet -ArgumentList $dotnetArguments -WorkingDirectory $repoRoot
    Write-Output 'STARTED_DOTNET'
}
catch {
    Write-LauncherLog "ERROR: $($_.Exception.Message)"
    throw
}
