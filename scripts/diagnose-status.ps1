$ErrorActionPreference = 'Stop'

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "=== $Title ==="
}

function Get-AppState {
    $statePath = Join-Path $env:LOCALAPPDATA 'WireguardSplitTunnel\state.json'
    if (-not (Test-Path $statePath)) {
        return [PSCustomObject]@{
            Path = $statePath
            Exists = $false
            Data = $null
        }
    }

    $data = Get-Content $statePath -Raw | ConvertFrom-Json
    return [PSCustomObject]@{
        Path = $statePath
        Exists = $true
        Data = $data
    }
}

function Get-DefaultLikeRoutes {
    $output = route print -4
    $routes = @()
    foreach ($line in $output) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        $parts = $trimmed -split '\s+'
        if ($parts.Count -lt 5) { continue }

        $destination = $parts[0]
        $netmask = $parts[1]
        $isDefaultLike =
            (($destination -eq '0.0.0.0') -and ($netmask -eq '0.0.0.0')) -or
            (($destination -eq '0.0.0.0') -and ($netmask -eq '128.0.0.0')) -or
            (($destination -eq '128.0.0.0') -and ($netmask -eq '128.0.0.0'))

        if (-not $isDefaultLike) { continue }
        $routes += [PSCustomObject]@{
            Destination = $destination
            Netmask = $netmask
            Gateway = $parts[2]
            InterfaceIp = $parts[3]
            Metric = [int]$parts[4]
        }
    }

    return $routes
}

function Get-WireGuardInfo {
    $nic = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
        Where-Object {
            $_.OperationalStatus -eq [System.Net.NetworkInformation.OperationalStatus]::Up -and
            ($_.Name.ToLowerInvariant().Contains('wireguard') -or $_.Description.ToLowerInvariant().Contains('wireguard'))
        } |
        Select-Object -First 1

    if ($null -eq $nic) {
        return [PSCustomObject]@{
            Found = $false
            Name = ''
            IPv4 = @()
        }
    }

    $ips = $nic.GetIPProperties().UnicastAddresses |
        Where-Object { $_.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
        ForEach-Object { $_.Address.ToString() }

    return [PSCustomObject]@{
        Found = $true
        Name = $nic.Name
        IPv4 = $ips
    }
}

function Get-FirewallRulesSummary {
    try {
        $rules = Get-NetFirewallRule -DisplayName 'WGST-Software-*' -ErrorAction Stop
        return [PSCustomObject]@{
            Available = $true
            Count = @($rules).Count
            Names = @($rules | Select-Object -ExpandProperty DisplayName)
            Error = ''
        }
    }
    catch {
        return [PSCustomObject]@{
            Available = $false
            Count = -1
            Names = @()
            Error = $_.Exception.Message
        }
    }
}

$state = Get-AppState
$wg = Get-WireGuardInfo
$defaults = Get-DefaultLikeRoutes
$fw = Get-FirewallRulesSummary

Write-Section 'App State'
Write-Host "State file: $($state.Path)"
Write-Host "Exists: $($state.Exists)"
if ($state.Exists) {
    $data = $state.Data
    $domainRules = @($data.DomainRules | Where-Object { $_.Enabled -eq $true })
    $softwareRules = @($data.SoftwareRules | Where-Object { $_.Enabled -eq $true })
    Write-Host "DomainGlobalDefaultMode: $($data.DomainGlobalDefaultMode)"
    Write-Host "SoftwareGlobalDefaultMode: $($data.SoftwareGlobalDefaultMode)"
    Write-Host "Enabled domain rules: $($domainRules.Count)"
    Write-Host "Enabled software rules: $($softwareRules.Count)"
    if ($softwareRules.Count -gt 0) {
        $softwareRules | ForEach-Object {
            Write-Host "  - $($_.ProcessName) | path=$($_.ExecutablePath)"
        }
    }
}

Write-Section 'WireGuard Interface'
Write-Host "Found: $($wg.Found)"
if ($wg.Found) {
    Write-Host "Name: $($wg.Name)"
    Write-Host "IPv4: $([string]::Join(', ', $wg.IPv4))"
}

Write-Section 'Default-like Routes'
if ($defaults.Count -eq 0) {
    Write-Host "No default-like routes found."
}
else {
    $defaults | Sort-Object Destination, Metric | Format-Table Destination, Netmask, Gateway, InterfaceIp, Metric -AutoSize
    if ($wg.Found -and $wg.IPv4.Count -gt 0) {
        $wgHalf = @($defaults | Where-Object { $_.Netmask -eq '128.0.0.0' -and $wg.IPv4 -contains $_.InterfaceIp })
        Write-Host "WireGuard /1 routes present: $($wgHalf.Count -gt 0)"
    }
}

Write-Section 'Domain Host Routes'
if ($state.Exists) {
    $managed = @($state.Data.ManagedRouteSnapshot)
    Write-Host "ManagedRouteSnapshot count: $($managed.Count)"
    foreach ($entry in $managed) {
        $present = route print -4 | Select-String -SimpleMatch $entry.IpAddress
        Write-Host "  - $($entry.Domain) => $($entry.IpAddress) | present=$($null -ne $present)"
    }
}

Write-Section 'Software Firewall Rules'
if ($fw.Available) {
    Write-Host "WGST-Software rule count: $($fw.Count)"
    if ($fw.Count -gt 0) {
        $fw.Names | Sort-Object | ForEach-Object { Write-Host "  - $_" }
    }
}
else {
    Write-Host "Cannot query firewall rules in current permission context."
    Write-Host "Error: $($fw.Error)"
}

Write-Section 'Summary'
if ($state.Exists) {
    $sameMode = $state.Data.DomainGlobalDefaultMode -eq $state.Data.SoftwareGlobalDefaultMode
    Write-Host "Domain/Software mode unified: $sameMode"
}
Write-Host "Done."
