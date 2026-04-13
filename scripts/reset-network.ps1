param(
    [switch]$Elevated
)

$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator) -and -not $Elevated) {
    Start-Process -FilePath 'powershell' -Verb RunAs -ArgumentList @(
        '-ExecutionPolicy', 'Bypass',
        '-File', "`"$PSCommandPath`"",
        '-Elevated'
    )
    Write-Host '[RESET] ELEVATION_REQUESTED'
    exit 0
}

Write-Host '[RESET] Removing app firewall rules...'
Get-NetFirewallRule -DisplayName 'WGST-Software-*' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue

Write-Host '[RESET] Removing WireGuard half-default routes (0.0.0.0/1, 128.0.0.0/1)...'
route delete 0.0.0.0 mask 128.0.0.0 | Out-Null
route delete 128.0.0.0 mask 128.0.0.0 | Out-Null

Write-Host '[RESET] Removing stale host routes managed by app...'
$stateCandidates = @(
    (Join-Path $env:LOCALAPPDATA 'WireguardSplitTunnel\state.json'),
    (Join-Path (Split-Path -Parent $PSScriptRoot) 'WireguardSplitTunnel\state.json')
)

foreach ($statePath in $stateCandidates) {
    if (-not (Test-Path $statePath)) { continue }

    try {
        $json = Get-Content -Raw $statePath | ConvertFrom-Json
        if ($null -eq $json.ManagedRouteSnapshot) { continue }

        foreach ($entry in $json.ManagedRouteSnapshot) {
            $ip = [string]$entry.IpAddress
            if ([string]::IsNullOrWhiteSpace($ip)) { continue }
            route delete $ip mask 255.255.255.255 | Out-Null
        }
    }
    catch {
        Write-Host "[RESET] Skip invalid state file: $statePath"
    }
}

Write-Host '[RESET] Done. Please reconnect WireGuard manually if needed.'
