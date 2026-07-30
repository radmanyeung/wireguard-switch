[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$DnsRepairPayload,
    [switch]$Elevated,
    [switch]$LibraryOnly
)

$ErrorActionPreference = 'Stop'

function Initialize-WgstProtectedPowerShellEnvironment {
    $systemDirectory = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::System)
    if ([string]::IsNullOrWhiteSpace($systemDirectory)) {
        throw 'The protected Windows PowerShell module root could not be resolved.'
    }

    $powerShellHome = [IO.Path]::Combine(
        $systemDirectory,
        'WindowsPowerShell',
        'v1.0')
    $modulesDirectory = [IO.Path]::Combine(
        $powerShellHome,
        'Modules')
    foreach ($directory in @(
            $systemDirectory,
            [IO.Path]::Combine($systemDirectory, 'WindowsPowerShell'),
            $powerShellHome,
            $modulesDirectory)) {
        try {
            $attributes = [IO.File]::GetAttributes($directory)
            if (($attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
                ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'unsafe_module_root'
            }
        }
        catch {
            throw 'The protected Windows PowerShell module root is unsafe.'
        }
    }

    $coreModules = @(
        'Microsoft.PowerShell.Management',
        'Microsoft.PowerShell.Utility',
        'Microsoft.PowerShell.Security'
    )
    $manifests = @()
    foreach ($moduleName in $coreModules) {
        $moduleDirectory = [IO.Path]::Combine(
            $modulesDirectory,
            $moduleName)
        $manifest = [IO.Path]::Combine(
            $moduleDirectory,
            "$moduleName.psd1")
        try {
            $directoryAttributes = [IO.File]::GetAttributes(
                $moduleDirectory)
            $fileAttributes = [IO.File]::GetAttributes($manifest)
            if (($directoryAttributes -band
                    [IO.FileAttributes]::Directory) -eq 0 -or
                ($directoryAttributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($fileAttributes -band
                    [IO.FileAttributes]::Directory) -ne 0 -or
                ($fileAttributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'unsafe_core_module'
            }
        }
        catch {
            throw "The protected Windows PowerShell module is unsafe: $moduleName"
        }

        $manifests += [IO.Path]::GetFullPath($manifest)
    }

    $env:PSModulePath = [IO.Path]::GetFullPath($modulesDirectory)
    $global:PSModuleAutoLoadingPreference = 'None'
    foreach ($moduleName in $coreModules) {
        Microsoft.PowerShell.Core\Remove-Module `
            -Name $moduleName `
            -Force `
            -ErrorAction SilentlyContinue
    }
    foreach ($manifest in $manifests) {
        Microsoft.PowerShell.Core\Import-Module `
            -Name $manifest `
            -Global `
            -Force `
            -ErrorAction Stop
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-WgstPlainExistingPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$Directory
    )

    try {
        $fullPath = [IO.Path]::GetFullPath($Path)
        $attributes = [IO.File]::GetAttributes($fullPath)
        $isDirectory = (
            $attributes -band [IO.FileAttributes]::Directory) -ne 0
        if ([bool]$Directory -ne $isDirectory) {
            return $false
        }

        return (
            $attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0
    }
    catch {
        return $false
    }
}

function Test-WgstProtectedInstallParentAuthority {
    param(
        [Parameter(Mandatory = $true)][string]$ProgramFilesPath
    )

    try {
        $programFiles = [IO.Path]::GetFullPath(
            $ProgramFilesPath).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        $driveRoot = [IO.Path]::GetPathRoot($programFiles)
        if ([string]::IsNullOrWhiteSpace($driveRoot) -or
            $programFiles.StartsWith(
                '\\',
                [StringComparison]::Ordinal) -or
            [IO.DriveInfo]::new($driveRoot).DriveType -ne
                [IO.DriveType]::Fixed) {
            return $false
        }

        $current = $programFiles
        while (-not [string]::IsNullOrWhiteSpace($current)) {
            if (-not (Test-WgstPlainExistingPath `
                    -Path $current `
                    -Directory)) {
                return $false
            }

            $parent = [IO.Directory]::GetParent($current)
            if ($null -eq $parent) {
                break
            }

            $current = $parent.FullName
        }

        $security = [IO.DirectoryInfo]::new(
            $programFiles).GetAccessControl()
        if (-not $security.AreAccessRulesProtected -or
            -not $security.AreAccessRulesCanonical) {
            return $false
        }

        $descriptor =
            [Security.AccessControl.RawSecurityDescriptor]::new(
                $security.GetSecurityDescriptorBinaryForm(),
                0)
        if ($null -eq $descriptor.Owner -or
            $null -eq $descriptor.DiscretionaryAcl) {
            return $false
        }

        $trusted = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        foreach ($sid in @(
                'S-1-5-18',
                'S-1-5-32-544',
                'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')) {
            [void]$trusted.Add($sid)
        }
        if (-not $trusted.Contains($descriptor.Owner.Value)) {
            return $false
        }

        $dangerousMask = 0x00000002 -bor
            0x00000004 -bor
            0x00000040 -bor
            0x00010000 -bor
            0x00040000 -bor
            0x00080000 -bor
            0x10000000 -bor
            0x40000000
        foreach ($genericAce in $descriptor.DiscretionaryAcl) {
            if ($genericAce -isnot
                    [Security.AccessControl.CommonAce]) {
                return $false
            }

            $ace = [Security.AccessControl.CommonAce]$genericAce
            if ($ace.IsCallback -or
                $ace.OpaqueLength -ne 0 -or
                $null -eq $ace.SecurityIdentifier) {
                return $false
            }

            if (([int]$ace.AceFlags -band
                    [int][Security.AccessControl.AceFlags]::InheritOnly) -ne
                0) {
                continue
            }

            if ($ace.AceQualifier -eq
                    [Security.AccessControl.AceQualifier]::AccessAllowed -and
                -not $trusted.Contains(
                    $ace.SecurityIdentifier.Value) -and
                ($ace.AccessMask -band $dangerousMask) -ne 0) {
                return $false
            }
        }

        return $true
    }
    catch {
        return $false
    }
}

function Test-WgstExactInstalledAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$Directory,
        [Parameter(Mandatory = $true)][bool]$Root
    )

    try {
        if (-not (Test-WgstPlainExistingPath `
                -Path $Path `
                -Directory:$Directory)) {
            return $false
        }

        $item = if ($Directory) {
            [IO.DirectoryInfo]::new([IO.Path]::GetFullPath($Path))
        }
        else {
            [IO.FileInfo]::new([IO.Path]::GetFullPath($Path))
        }
        $security = $item.GetAccessControl()
        $sidType = [Security.Principal.SecurityIdentifier]
        $system = [Security.Principal.SecurityIdentifier]::new(
            [Security.Principal.WellKnownSidType]::LocalSystemSid,
            $null)
        if (-not $system.Equals($security.GetOwner($sidType)) -or
            $security.AreAccessRulesProtected -ne $Root -or
            -not $security.AreAccessRulesCanonical) {
            return $false
        }

        $descriptor =
            [Security.AccessControl.RawSecurityDescriptor]::new(
                $security.GetSecurityDescriptorBinaryForm(),
                0)
        $daclPresent =
            [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent
        $daclProtected =
            [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
        if (($descriptor.ControlFlags -band $daclPresent) -eq 0 -or
            ((($descriptor.ControlFlags -band $daclProtected) -ne 0) -ne
                $Root) -or
            $descriptor.Owner -isnot $sidType -or
            -not $system.Equals($descriptor.Owner) -or
            $null -eq $descriptor.DiscretionaryAcl -or
            $descriptor.DiscretionaryAcl.Count -ne 3) {
            return $false
        }

        $expectedFlags = if ($Root) {
            [Security.AccessControl.AceFlags](
                [int][Security.AccessControl.AceFlags]::ContainerInherit -bor
                [int][Security.AccessControl.AceFlags]::ObjectInherit)
        }
        elseif ($Directory) {
            [Security.AccessControl.AceFlags](
                [int][Security.AccessControl.AceFlags]::ContainerInherit -bor
                [int][Security.AccessControl.AceFlags]::ObjectInherit -bor
                [int][Security.AccessControl.AceFlags]::Inherited)
        }
        else {
            [Security.AccessControl.AceFlags]::Inherited
        }
        $expected =
            [Collections.Generic.Dictionary[string, int]]::new(
                [StringComparer]::Ordinal)
        $expected.Add(
            'S-1-5-18',
            [int][Security.AccessControl.FileSystemRights]::FullControl)
        $expected.Add(
            'S-1-5-32-544',
            [int][Security.AccessControl.FileSystemRights]::FullControl)
        $expected.Add(
            'S-1-5-32-545',
            [int](
                [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
                [Security.AccessControl.FileSystemRights]::Synchronize))
        foreach ($genericAce in $descriptor.DiscretionaryAcl) {
            if ($genericAce -isnot
                    [Security.AccessControl.CommonAce]) {
                return $false
            }

            $ace = [Security.AccessControl.CommonAce]$genericAce
            if ($ace.IsCallback -or
                $ace.AceQualifier -ne
                    [Security.AccessControl.AceQualifier]::AccessAllowed -or
                $ace.AceFlags -ne $expectedFlags -or
                $ace.OpaqueLength -ne 0 -or
                $null -eq $ace.SecurityIdentifier -or
                -not $expected.ContainsKey(
                    $ace.SecurityIdentifier.Value) -or
                $ace.AccessMask -ne
                    $expected[$ace.SecurityIdentifier.Value]) {
                return $false
            }

            [void]$expected.Remove($ace.SecurityIdentifier.Value)
        }

        return $expected.Count -eq 0
    }
    catch {
        return $false
    }
}

function Test-WgstInstalledReleaseScriptRoot {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$ScriptRelativePath,
        [string]$ProgramFilesPath = [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::ProgramFiles),
        [scriptblock]$ParentAuthorityValidator,
        [scriptblock]$AclValidator
    )

    try {
        if (-not (Test-WgstExactProtectedScriptRoot `
                -RepositoryRoot $RepositoryRoot `
                -ProgramFilesPath $ProgramFilesPath)) {
            return $false
        }

        $root = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        $parentAccepted = if ($null -eq $ParentAuthorityValidator) {
            Test-WgstProtectedInstallParentAuthority `
                -ProgramFilesPath $ProgramFilesPath
        }
        else {
            & $ParentAuthorityValidator $ProgramFilesPath
        }
        if (-not $parentAccepted) {
            return $false
        }

        $releaseModulePath = [IO.Path]::Combine(
            $root,
            'scripts',
            'WindowsRelease.psm1')
        $initialItems = @(
            [pscustomobject]@{ Path = $root; Directory = $true; Root = $true },
            [pscustomobject]@{ Path = [IO.Path]::Combine($root, 'scripts'); Directory = $true; Root = $false },
            [pscustomobject]@{ Path = [IO.Path]::Combine($root, $ScriptRelativePath); Directory = $false; Root = $false },
            [pscustomobject]@{ Path = [IO.Path]::Combine($root, 'release-manifest.json'); Directory = $false; Root = $false },
            [pscustomobject]@{ Path = $releaseModulePath; Directory = $false; Root = $false }
        )
        foreach ($item in $initialItems) {
            if (-not (Test-WgstPlainExistingPath `
                    -Path $item.Path `
                    -Directory:([bool]$item.Directory))) {
                return $false
            }

            $aclAccepted = if ($null -eq $AclValidator) {
                Test-WgstExactInstalledAcl `
                    -Path $item.Path `
                    -Directory ([bool]$item.Directory) `
                    -Root ([bool]$item.Root)
            }
            else {
                & $AclValidator `
                    $item.Path `
                    ([bool]$item.Directory) `
                    ([bool]$item.Root)
            }
            if (-not $aclAccepted) {
                return $false
            }
        }

        Initialize-WgstProtectedPowerShellEnvironment
        $releaseModule = Microsoft.PowerShell.Core\Import-Module `
            -Name $releaseModulePath `
            -Global `
            -Force `
            -PassThru `
            -ErrorAction Stop
        $plan = & $releaseModule {
            param($PackageRoot)
            Get-WgstAuthenticatedBundledReleaseAclPlan `
                -PackageRoot $PackageRoot `
                -AllowInstalledExtras
        } $root
        if ($null -eq $plan -or
            $plan.Root -ine $root -or
            $null -eq $plan.Directories -or
            $null -eq $plan.Files) {
            return $false
        }

        $requiredManagedFiles = @(
            'release-manifest.json',
            'scripts/install.ps1',
            'scripts/start.ps1',
            'scripts/update-launcher.ps1',
            'scripts/fix-dns.ps1',
            'scripts/reset-network.ps1',
            'scripts/WindowsRelease.psm1',
            'WireguardSplitTunnel/WireguardSplitTunnel.App.exe',
            'WireguardSplitTunnel/WireguardSplitTunnel.Updater.exe'
        )
        $managedPaths = @($plan.Files | ForEach-Object {
                ([string]$_.RelativePath).Replace('\', '/')
            })
        foreach ($required in $requiredManagedFiles) {
            if ($managedPaths -cnotcontains $required) {
                return $false
            }
        }

        foreach ($directory in @($plan.Directories)) {
            $isRoot = [string]$directory.Scope -ceq 'RootDirectory'
            if (-not (Test-WgstPlainExistingPath `
                    -Path ([string]$directory.FullPath) `
                    -Directory)) {
                return $false
            }

            $aclAccepted = if ($null -eq $AclValidator) {
                Test-WgstExactInstalledAcl `
                    -Path ([string]$directory.FullPath) `
                    -Directory $true `
                    -Root $isRoot
            }
            else {
                & $AclValidator `
                    ([string]$directory.FullPath) `
                    $true `
                    $isRoot
            }
            if (-not $aclAccepted) {
                return $false
            }
        }

        foreach ($file in @($plan.Files)) {
            if (-not (Test-WgstPlainExistingPath `
                    -Path ([string]$file.FullPath))) {
                return $false
            }

            $aclAccepted = if ($null -eq $AclValidator) {
                Test-WgstExactInstalledAcl `
                    -Path ([string]$file.FullPath) `
                    -Directory $false `
                    -Root $false
            }
            else {
                & $AclValidator `
                    ([string]$file.FullPath) `
                    $false `
                    $false
            }
            if (-not $aclAccepted) {
                return $false
            }
        }

        $parentAccepted = if ($null -eq $ParentAuthorityValidator) {
            Test-WgstProtectedInstallParentAuthority `
                -ProgramFilesPath $ProgramFilesPath
        }
        else {
            & $ParentAuthorityValidator $ProgramFilesPath
        }
        if (-not $parentAccepted) {
            return $false
        }

        $revalidatedPlan = & $releaseModule {
            param($PackageRoot)
            Get-WgstAuthenticatedBundledReleaseAclPlan `
                -PackageRoot $PackageRoot `
                -AllowInstalledExtras
        } $root
        return $null -ne $revalidatedPlan -and
            $revalidatedPlan.Root -ieq $root
    }
    catch {
        return $false
    }
}

function Get-WgstProtectedSystemDirectory {
    $systemDirectory = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::System)
    if ([string]::IsNullOrWhiteSpace($systemDirectory) -or
        -not (Test-WgstPlainExistingPath `
            -Path $systemDirectory `
            -Directory)) {
        throw 'The protected Windows system directory could not be resolved.'
    }

    return [IO.Path]::GetFullPath($systemDirectory)
}

function Get-WgstProtectedWindowsPowerShellPath {
    $systemDirectory = Get-WgstProtectedSystemDirectory
    $windowsPowerShellDirectory = Join-Path `
        $systemDirectory `
        'WindowsPowerShell'
    $versionDirectory = Join-Path $windowsPowerShellDirectory 'v1.0'

    $powerShellPath = Join-Path $versionDirectory 'powershell.exe'
    if (-not (Test-WgstPlainExistingPath `
            -Path $windowsPowerShellDirectory `
            -Directory) -or
        -not (Test-WgstPlainExistingPath `
            -Path $versionDirectory `
            -Directory) -or
        -not (Test-WgstPlainExistingPath -Path $powerShellPath)) {
        throw 'The protected Windows PowerShell executable is missing.'
    }

    return [IO.Path]::GetFullPath($powerShellPath)
}

function Get-WgstProtectedSystemExecutablePath {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('ipconfig.exe')]
        [string]$FileName
    )

    $executablePath = Join-Path `
        (Get-WgstProtectedSystemDirectory) `
        $FileName
    if (-not (Test-WgstPlainExistingPath -Path $executablePath)) {
        throw "The protected system executable is missing: $FileName"
    }

    return [IO.Path]::GetFullPath($executablePath)
}

function Import-WgstProtectedSystemModule {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('NetAdapter', 'DnsClient')]
        [string]$ModuleName
    )

    $systemDirectory = Get-WgstProtectedSystemDirectory
    $windowsPowerShellDirectory = Join-Path `
        $systemDirectory `
        'WindowsPowerShell'
    $versionDirectory = Join-Path $windowsPowerShellDirectory 'v1.0'
    $modulesDirectory = Join-Path `
        $systemDirectory `
        'WindowsPowerShell\v1.0\Modules'
    $moduleDirectory = Join-Path $modulesDirectory $ModuleName
    $manifestPath = Join-Path $moduleDirectory "$ModuleName.psd1"

    foreach ($directory in @(
            $windowsPowerShellDirectory,
            $versionDirectory,
            $modulesDirectory,
            $moduleDirectory)) {
        if (-not (Test-WgstPlainExistingPath `
                -Path $directory `
                -Directory)) {
            throw "The protected system module is missing: $ModuleName"
        }
    }

    if (-not (Test-WgstPlainExistingPath -Path $manifestPath)) {
        throw "The protected system module is missing: $ModuleName"
    }

    Microsoft.PowerShell.Core\Import-Module `
        -Name ([IO.Path]::GetFullPath($manifestPath)) `
        -Force `
        -ErrorAction Stop
}

function Test-WgstExactProtectedScriptRoot {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [string]$ProgramFilesPath = [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::ProgramFiles)
    )

    try {
        if ([string]::IsNullOrWhiteSpace($ProgramFilesPath)) {
            return $false
        }

        $root = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        $expected = [IO.Path]::GetFullPath(
            (Join-Path $ProgramFilesPath 'WireguardSplitTunnel')).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        return $root -ieq $expected
    }
    catch {
        return $false
    }
}

function Assert-WgstProtectedElevationRoot {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [string]$ProgramFilesPath = [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::ProgramFiles),
        [string]$ScriptPath = $PSCommandPath,
        [scriptblock]$InstalledReleaseValidator
    )

    if (-not (Test-WgstExactProtectedScriptRoot `
            -RepositoryRoot $RepositoryRoot `
            -ProgramFilesPath $ProgramFilesPath)) {
        throw (
            'DNS repair can request Administrator rights only from the ' +
            'fixed Program Files installation. Run install.cmd first.')
    }

    $root = [IO.Path]::GetFullPath($RepositoryRoot)
    $scriptsDirectory = Join-Path $root 'scripts'
    $expectedScript = Join-Path $scriptsDirectory 'fix-dns.ps1'
    try {
        $actualScript = [IO.Path]::GetFullPath($ScriptPath)
    }
    catch {
        $actualScript = $null
    }

    if ($actualScript -ine $expectedScript -or
        -not (Test-WgstPlainExistingPath -Path $root -Directory) -or
        -not (Test-WgstPlainExistingPath `
            -Path $scriptsDirectory `
            -Directory) -or
        -not (Test-WgstPlainExistingPath -Path $expectedScript)) {
        throw (
            'DNS repair can request Administrator rights only from a ' +
            'plain, fixed Program Files installation. Run install.cmd first.')
    }

    $installedReleaseAccepted = if (
        $null -eq $InstalledReleaseValidator) {
        Test-WgstInstalledReleaseScriptRoot `
            -RepositoryRoot $root `
            -ProgramFilesPath $ProgramFilesPath `
            -ScriptRelativePath 'scripts\fix-dns.ps1'
    }
    else {
        & $InstalledReleaseValidator $root $expectedScript
    }
    if (-not $installedReleaseAccepted) {
        throw (
            'DNS repair requires a complete SYSTEM-owned installed ' +
            'Release. Run install.cmd first.')
    }
}

$script:WgstApprovedDnsServers = [string[]]@(
    '8.8.8.8',
    '1.1.1.1'
)

function Assert-WgstApprovedDnsServers {
    param(
        [Parameter(Mandatory = $true)][string[]]$Servers
    )

    if ($null -eq $Servers -or
        $Servers.Count -ne $script:WgstApprovedDnsServers.Count) {
        throw 'DNS repair accepts only the exact approved DNS pair.'
    }

    for ($i = 0; $i -lt $script:WgstApprovedDnsServers.Count; $i++) {
        if ([string]$Servers[$i] -cne
            $script:WgstApprovedDnsServers[$i]) {
            throw 'DNS repair accepts only the exact approved DNS pair.'
        }
    }

    return [string[]]@($script:WgstApprovedDnsServers)
}

function ConvertTo-WgstCanonicalInterfaceGuid {
    param(
        [Parameter(Mandatory = $true)][object]$InterfaceGuid
    )

    $text = [string]$InterfaceGuid
    $format = if ($text.Length -eq 36) {
        'D'
    }
    elseif ($text.Length -eq 38) {
        'B'
    }
    else {
        throw 'The adapter InterfaceGuid is invalid.'
    }
    $parsed = [Guid]::Empty
    if ([string]::IsNullOrWhiteSpace($text) -or
        -not [Guid]::TryParseExact($text, $format, [ref]$parsed) -or
        $parsed -eq [Guid]::Empty) {
        throw 'The adapter InterfaceGuid is invalid.'
    }

    return $parsed.ToString('D')
}

function Test-WgstVerifiedActiveWireGuardAdapter {
    param(
        [Parameter(Mandatory = $true)][object]$Adapter
    )

    try {
        if ($null -eq $Adapter -or
            [string]$Adapter.Status -ine 'Up') {
            return $false
        }

        [void](ConvertTo-WgstCanonicalInterfaceGuid `
            -InterfaceGuid $Adapter.InterfaceGuid)
        $name = [string]$Adapter.Name
        $interfaceIndex = 0
        if (-not [int]::TryParse(
                [string]$Adapter.InterfaceIndex,
                [ref]$interfaceIndex) -or
            $interfaceIndex -lt 1) {
            return $false
        }
        if ([string]::IsNullOrWhiteSpace($name) -or
            $name.Length -gt 128 -or
            $name -match '[\x00-\x1f]') {
            return $false
        }

        $interfaceDescription = [string]$Adapter.InterfaceDescription
        $driverDescription = [string]$Adapter.DriverDescription
        $driverProvider = [string]$Adapter.DriverProvider
        $driverFileNameValue = [string]$Adapter.DriverFileName
        $driverFileName = [IO.Path]::GetFileName($driverFileNameValue)
        if ($driverFileNameValue -ine $driverFileName) {
            return $false
        }
        $descriptionPattern =
            '^(?:WireGuard(?: Tunnel)?|Wintun(?: Userspace)? Tunnel)$'
        if ($interfaceDescription -notmatch $descriptionPattern -or
            $driverDescription -notmatch $descriptionPattern -or
            $driverProvider -ine 'WireGuard LLC' -or
            @('wireguard.sys', 'wintun.sys') -inotcontains
                $driverFileName) {
            return $false
        }

        return $true
    }
    catch {
        return $false
    }
}

function ConvertTo-WgstVerifiedAdapterSnapshot {
    param(
        [Parameter(Mandatory = $true)][object]$Adapter
    )

    if (-not (Test-WgstVerifiedActiveWireGuardAdapter `
            -Adapter $Adapter)) {
        throw (
            'The selected adapter status or WireGuard/Wintun provenance ' +
            'is invalid.')
    }

    $interfaceIndex = 0
    if (-not [int]::TryParse(
            [string]$Adapter.InterfaceIndex,
            [ref]$interfaceIndex)) {
        throw 'The selected adapter InterfaceIndex is invalid.'
    }

    return [pscustomobject]@{
        InterfaceGuid = ConvertTo-WgstCanonicalInterfaceGuid `
            -InterfaceGuid $Adapter.InterfaceGuid
        Name = [string]$Adapter.Name
        Status = [string]$Adapter.Status
        InterfaceIndex = $interfaceIndex
        InterfaceDescription = [string]$Adapter.InterfaceDescription
        DriverDescription = [string]$Adapter.DriverDescription
        DriverProvider = [string]$Adapter.DriverProvider
        DriverFileName = [string]$Adapter.DriverFileName
    }
}

function Get-WgstNetAdapterSnapshot {
    param(
        [scriptblock]$AdapterQuery
    )

    if ($null -ne $AdapterQuery) {
        return [object[]]@(& $AdapterQuery)
    }

    return [object[]]@(
        NetAdapter\Get-NetAdapter `
            -IncludeHidden `
            -ErrorAction Stop)
}

function New-WgstDefaultDnsRepairRequest {
    param(
        [scriptblock]$AdapterQuery
    )

    $verified = @(
        Get-WgstNetAdapterSnapshot -AdapterQuery $AdapterQuery |
            Where-Object {
                Test-WgstVerifiedActiveWireGuardAdapter -Adapter $_
            })
    $preferred = @($verified | Where-Object {
            [string]$_.Name -ieq 'SG'
        })
    if ($preferred.Count -gt 1) {
        throw 'Verified active SG adapter selection is ambiguous.'
    }

    $selected = if ($preferred.Count -eq 1) {
        $preferred[0]
    }
    elseif ($verified.Count -eq 1) {
        $verified[0]
    }
    elseif ($verified.Count -eq 0) {
        throw (
            'No verified active WireGuard/Wintun adapter was found. ' +
            'Connect the tunnel and retry.')
    }
    else {
        throw 'Verified active WireGuard/Wintun adapter selection is ambiguous.'
    }

    return [pscustomobject]@{
        InterfaceGuid = ConvertTo-WgstCanonicalInterfaceGuid `
            -InterfaceGuid $selected.InterfaceGuid
    }
}

function ConvertTo-WgstDnsRepairPayload {
    param(
        [Parameter(Mandatory = $true)][object]$InterfaceGuid
    )

    $canonicalGuid = ConvertTo-WgstCanonicalInterfaceGuid `
        -InterfaceGuid $InterfaceGuid
    $encoding = [Text.UTF8Encoding]::new($false, $true)
    $bytes = $encoding.GetBytes($canonicalGuid)
    if ($bytes.Length -gt 96) {
        throw 'The DNS repair payload is too large.'
    }

    return [Convert]::ToBase64String($bytes)
}

function ConvertFrom-WgstCanonicalBase64 {
    param(
        [Parameter(Mandatory = $true)][string]$Payload
    )

    if ([string]::IsNullOrWhiteSpace($Payload) -or
        $Payload.Length -gt 128 -or
        $Payload -cnotmatch '\A[A-Za-z0-9+/]+={0,2}\z') {
        throw 'The DNS repair payload is invalid.'
    }

    try {
        $bytes = [Convert]::FromBase64String($Payload)
        if ($Payload -cne [Convert]::ToBase64String($bytes)) {
            throw 'noncanonical Base64'
        }
    }
    catch {
        if ($_.Exception.Message -ceq 'noncanonical Base64') {
            throw 'The DNS repair payload contains noncanonical Base64.'
        }

        throw 'The DNS repair payload is invalid.'
    }

    return ,$bytes
}

function ConvertFrom-WgstDnsRepairPayload {
    param(
        [Parameter(Mandatory = $true)][string]$Payload
    )

    try {
        $bytes = ConvertFrom-WgstCanonicalBase64 -Payload $Payload
        if ($bytes.Length -lt 1 -or $bytes.Length -gt 96) {
            throw 'payload_size'
        }

        $encoding = [Text.UTF8Encoding]::new($false, $true)
        $text = $encoding.GetString([byte[]]$bytes)
        $canonicalGuid = ConvertTo-WgstCanonicalInterfaceGuid `
            -InterfaceGuid $text
        if ($text -cne $canonicalGuid) {
            throw 'payload_canonicalization'
        }

        return [pscustomobject]@{
            InterfaceGuid = $canonicalGuid
        }
    }
    catch {
        throw 'The DNS repair payload is invalid.'
    }
}

function Resolve-WgstElevatedDnsRepairAdapter {
    param(
        [Parameter(Mandatory = $true)][object]$InterfaceGuid,
        [scriptblock]$AdapterQuery
    )

    $canonicalGuid = ConvertTo-WgstCanonicalInterfaceGuid `
        -InterfaceGuid $InterfaceGuid
    $matches = @()
    foreach ($adapter in @(
            Get-WgstNetAdapterSnapshot -AdapterQuery $AdapterQuery)) {
        try {
            $candidateGuid = ConvertTo-WgstCanonicalInterfaceGuid `
                -InterfaceGuid $adapter.InterfaceGuid
            if ($candidateGuid -ceq $canonicalGuid) {
                $matches += $adapter
            }
        }
        catch {
            continue
        }
    }

    if ($matches.Count -eq 0) {
        throw (
            'The selected adapter is absent or was replaced after ' +
            'authorization.')
    }
    if ($matches.Count -gt 1) {
        throw 'The selected adapter InterfaceGuid is ambiguous.'
    }

    try {
        return ConvertTo-WgstVerifiedAdapterSnapshot `
            -Adapter $matches[0]
    }
    catch {
        throw (
            'The selected adapter status or WireGuard/Wintun provenance ' +
            'changed after authorization.')
    }
}

function Assert-WgstAdapterSnapshotUnchanged {
    param(
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][object]$Observed,
        [Parameter(Mandatory = $true)]
        [ValidateSet('before', 'after')]
        [string]$Phase
    )

    foreach ($propertyName in @(
            'InterfaceGuid',
            'Name',
            'Status',
            'InterfaceIndex',
            'InterfaceDescription',
            'DriverDescription',
            'DriverProvider',
            'DriverFileName')) {
        $unchanged = if ($propertyName -ceq 'InterfaceIndex') {
            [int]$Expected.$propertyName -eq
                [int]$Observed.$propertyName
        }
        else {
            [string]$Expected.$propertyName -ceq
                [string]$Observed.$propertyName
        }
        if (-not $unchanged) {
            throw "The selected adapter changed $Phase DNS mutation."
        }
    }
}

function Invoke-WgstApprovedDnsMutation {
    param(
        [Parameter(Mandatory = $true)][object]$AuthorizedAdapter,
        [scriptblock]$AdapterQuery,
        [scriptblock]$DnsSetter,
        [scriptblock]$DnsReader,
        [scriptblock]$CacheFlusher
    )

    $authorized = ConvertTo-WgstVerifiedAdapterSnapshot `
        -Adapter $AuthorizedAdapter
    try {
        $before = Resolve-WgstElevatedDnsRepairAdapter `
            -InterfaceGuid $authorized.InterfaceGuid `
            -AdapterQuery $AdapterQuery
    }
    catch {
        throw 'The selected adapter changed before DNS mutation.'
    }
    Assert-WgstAdapterSnapshotUnchanged `
        -Expected $authorized `
        -Observed $before `
        -Phase 'before'

    [string[]]$approvedServers = @(
        Assert-WgstApprovedDnsServers `
            -Servers ([string[]]@($script:WgstApprovedDnsServers)))
    $interfaceIndex = [int]$before.InterfaceIndex
    if ($null -eq $DnsSetter) {
        DnsClient\Set-DnsClientServerAddress `
            -InterfaceIndex $interfaceIndex `
            -ServerAddresses $approvedServers `
            -ErrorAction Stop |
            Out-Null
    }
    else {
        & $DnsSetter $interfaceIndex $approvedServers | Out-Null
    }

    try {
        $after = Resolve-WgstElevatedDnsRepairAdapter `
            -InterfaceGuid $before.InterfaceGuid `
            -AdapterQuery $AdapterQuery
    }
    catch {
        throw 'The selected adapter changed after DNS mutation.'
    }
    Assert-WgstAdapterSnapshotUnchanged `
        -Expected $before `
        -Observed $after `
        -Phase 'after'

    $dnsRecords = @(
        if ($null -eq $DnsReader) {
            DnsClient\Get-DnsClientServerAddress `
                -InterfaceIndex $interfaceIndex `
                -AddressFamily IPv4 `
                -ErrorAction Stop
        }
        else {
            & $DnsReader $interfaceIndex
        }
    )
    if ($dnsRecords.Count -ne 1) {
        throw 'DNS mutation post-verification returned an unexpected record count.'
    }

    [string[]]$actualServers = @(
        $dnsRecords[0].ServerAddresses |
            ForEach-Object { [string]$_ })
    if ($actualServers.Count -ne $approvedServers.Count) {
        throw 'DNS mutation post-verification did not match the approved DNS pair.'
    }
    for ($i = 0; $i -lt $approvedServers.Count; $i++) {
        if ($actualServers[$i] -cne $approvedServers[$i]) {
            throw 'DNS mutation post-verification did not match the approved DNS pair.'
        }
    }

    $flushExitCode = if ($null -eq $CacheFlusher) {
        $ipconfigPath = Get-WgstProtectedSystemExecutablePath `
            -FileName 'ipconfig.exe'
        & $ipconfigPath '/flushdns' | Out-Null
        if ($null -eq $LASTEXITCODE) {
            throw 'DNS cache flush did not return an exit code.'
        }

        [int]$LASTEXITCODE
    }
    else {
        $flushResults = @(& $CacheFlusher)
        if ($flushResults.Count -ne 1) {
            throw 'DNS cache flush did not return exactly one exit code.'
        }

        $parsedExitCode = 0
        if (-not [int]::TryParse(
                [string]$flushResults[0],
                [ref]$parsedExitCode)) {
            throw 'DNS cache flush returned an invalid exit code.'
        }

        $parsedExitCode
    }
    if ($flushExitCode -ne 0) {
        throw "DNS cache flush failed with exit code $flushExitCode."
    }

    return $after
}

if ($LibraryOnly) {
    return
}

Initialize-WgstProtectedPowerShellEnvironment
$repositoryRoot = Split-Path -Parent $PSScriptRoot
Assert-WgstProtectedElevationRoot `
    -RepositoryRoot $repositoryRoot `
    -ScriptPath $PSCommandPath
Import-WgstProtectedSystemModule -ModuleName 'NetAdapter'

$repairRequest = if ($Elevated) {
    if (-not $PSBoundParameters.ContainsKey('DnsRepairPayload') -or
        [string]::IsNullOrWhiteSpace($DnsRepairPayload)) {
        throw 'The elevated DNS repair child requires its bound payload.'
    }

    ConvertFrom-WgstDnsRepairPayload -Payload $DnsRepairPayload
}
else {
    if ($PSBoundParameters.ContainsKey('DnsRepairPayload')) {
        throw 'The DNS repair payload is reserved for the elevated child.'
    }

    New-WgstDefaultDnsRepairRequest
}

if (-not (Test-IsAdministrator)) {
    if ($Elevated) {
        throw 'Elevation failed. Please right-click fix-dns.cmd and run as administrator.'
    }

    $powerShellPath = Get-WgstProtectedWindowsPowerShellPath

    $repairPayload = ConvertTo-WgstDnsRepairPayload `
        -InterfaceGuid $repairRequest.InterfaceGuid

    $argList = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', "`"$PSCommandPath`"",
        '-Elevated',
        '-DnsRepairPayload', "`"$repairPayload`""
    )

    Assert-WgstProtectedElevationRoot `
        -RepositoryRoot $repositoryRoot `
        -ScriptPath $PSCommandPath
    Initialize-WgstProtectedPowerShellEnvironment
    Start-Process `
        -FilePath $powerShellPath `
        -Verb RunAs `
        -ArgumentList $argList
    Write-Host '[DNSFIX] ELEVATION_REQUESTED'
    exit 0
}

Import-WgstProtectedSystemModule -ModuleName 'DnsClient'
$effectiveDnsServers = @(Assert-WgstApprovedDnsServers `
    -Servers ([string[]]@($script:WgstApprovedDnsServers)))
$authorizedAdapter = Resolve-WgstElevatedDnsRepairAdapter `
    -InterfaceGuid $repairRequest.InterfaceGuid

Write-Host "[DNSFIX] Target adapter: $($authorizedAdapter.Name)"
Write-Host "[DNSFIX] Setting DNS: $($effectiveDnsServers -join ', ')"
$target = Invoke-WgstApprovedDnsMutation `
    -AuthorizedAdapter $authorizedAdapter

Write-Host '[DNSFIX] DNS cache flushed.'
Write-Host '[DNSFIX] Verify: Resolve-DnsName www.google.com -Type A'

try {
    $result = DnsClient\Resolve-DnsName `
        'www.google.com' `
        -Type A `
        -ErrorAction Stop |
        Select-Object -ExpandProperty IPAddress -First 3
    Write-Host "[DNSFIX] google -> $($result -join ', ')"
}
catch {
    Write-Host "[DNSFIX] Resolve check failed: $($_.Exception.Message)"
}
