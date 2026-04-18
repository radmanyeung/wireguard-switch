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

try {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Write-LauncherLog "Startup. repoRoot=$repoRoot elevated=$Elevated dryRun=$DryRun postInstallSelfTest=$PostInstallSelfTest"

    $project = Join-Path $repoRoot 'src\WireguardSplitTunnel.App\WireguardSplitTunnel.App.csproj'
    $dotnetArguments = "run --project `"$project`""
    if ($PostInstallSelfTest) {
        $dotnetArguments += ' -- --post-install-self-test'
    }

    $appCandidates = @(
        (Join-Path $repoRoot 'WireguardSplitTunnel\WireguardSplitTunnel.App.exe'),
        (Join-Path $repoRoot 'src\WireguardSplitTunnel.App\bin\Release\net8.0-windows\win-x64\publish\WireguardSplitTunnel.App.exe'),
        (Join-Path $repoRoot 'src\WireguardSplitTunnel.App\bin\Debug\net8.0-windows\WireguardSplitTunnel.App.exe')
    )
    Write-LauncherLog ("App candidates: " + ($appCandidates -join '; '))
    $appExe = $appCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
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
                    $appExe = $downloadedExe
                    Write-LauncherLog "Prebuilt downloaded: $appExe"
                    Write-Output "PREBUILT_DOWNLOADED $appExe"
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
