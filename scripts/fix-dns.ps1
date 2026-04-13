param(
    [string]$AdapterName = 'SG',
    [string[]]$DnsServers = @('8.8.8.8','1.1.1.1'),
    [switch]$Elevated
)

$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-WireGuardAdapterName {
    param([string]$Preferred)

    if (-not [string]::IsNullOrWhiteSpace($Preferred)) {
        $exact = Get-NetAdapter -Name $Preferred -ErrorAction SilentlyContinue
        if ($null -ne $exact) { return $exact.Name }
    }

    $candidate = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Status -eq 'Up' -and (
                $_.Name -match 'wireguard' -or
                $_.InterfaceDescription -match 'WireGuard' -or
                $_.Name -eq 'SG'
            )
        } |
        Select-Object -First 1

    if ($null -ne $candidate) { return $candidate.Name }
    return $null
}

if (-not (Test-IsAdministrator)) {
    if ($Elevated) {
        throw 'Elevation failed. Please right-click fix-dns.cmd and run as administrator.'
    }

    $argList = @(
        '-ExecutionPolicy', 'Bypass',
        '-File', "`"$PSCommandPath`"",
        '-Elevated',
        '-AdapterName', "`"$AdapterName`""
    )

    foreach ($dns in $DnsServers) {
        $argList += @('-DnsServers', "`"$dns`"")
    }

    Start-Process -FilePath 'powershell' -Verb RunAs -ArgumentList $argList
    Write-Host '[DNSFIX] ELEVATION_REQUESTED'
    exit 0
}

$target = Resolve-WireGuardAdapterName -Preferred $AdapterName
if ([string]::IsNullOrWhiteSpace($target)) {
    throw 'WireGuard adapter not found. Please connect tunnel first and rerun fix-dns.cmd.'
}

if ($DnsServers.Count -lt 1) {
    throw 'At least one DNS server is required.'
}

Write-Host "[DNSFIX] Target adapter: $target"
Write-Host "[DNSFIX] Setting DNS: $($DnsServers -join ', ')"

$primary = $DnsServers[0]
netsh interface ip set dns name="$target" static $primary primary | Out-Null

for ($i = 1; $i -lt $DnsServers.Count; $i++) {
    $dns = $DnsServers[$i]
    $idx = $i + 1
    netsh interface ip add dns name="$target" $dns index=$idx | Out-Null
}

ipconfig /flushdns | Out-Null

Write-Host '[DNSFIX] DNS cache flushed.'
Write-Host '[DNSFIX] Verify: Resolve-DnsName www.google.com -Type A'

try {
    $result = Resolve-DnsName www.google.com -Type A -ErrorAction Stop |
        Select-Object -ExpandProperty IPAddress -First 3
    Write-Host "[DNSFIX] google -> $($result -join ', ')"
}
catch {
    Write-Host "[DNSFIX] Resolve check failed: $($_.Exception.Message)"
}