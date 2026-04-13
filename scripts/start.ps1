param(
    [switch]$DryRun,
    [switch]$Elevated,
    [switch]$PostInstallSelfTest
)

$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$repoRoot = Split-Path -Parent $PSScriptRoot

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
$appExe = $appCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($DryRun) {
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

    Start-Process -FilePath 'powershell' -Verb RunAs -ArgumentList $argList
    Write-Output 'ELEVATION_REQUESTED'
    exit 0
}

if ($appExe) {
    $appArgs = if ($PostInstallSelfTest) { '--post-install-self-test' } else { '' }
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
    throw 'No published app found and dotnet SDK is not installed. Run install.cmd first.'
}

$sdkOutput = (& dotnet --list-sdks 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $sdkOutput) {
    throw 'No published app found and .NET SDK is not available. Please copy the prebuilt WireguardSplitTunnel folder from build machine, or install .NET 8 SDK.'
}

Start-Process -FilePath dotnet -ArgumentList $dotnetArguments -WorkingDirectory $repoRoot
Write-Output 'STARTED_DOTNET'

