param(
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
        [ValidateSet('route.exe')]
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
        [ValidateSet('NetSecurity')]
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
            'Network reset can request Administrator rights only from the ' +
            'fixed Program Files installation. Run install.cmd first.')
    }

    $root = [IO.Path]::GetFullPath($RepositoryRoot)
    $scriptsDirectory = Join-Path $root 'scripts'
    $expectedScript = Join-Path $scriptsDirectory 'reset-network.ps1'
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
            'Network reset can request Administrator rights only from a ' +
            'plain, fixed Program Files installation. Run install.cmd first.')
    }

    $installedReleaseAccepted = if (
        $null -eq $InstalledReleaseValidator) {
        Test-WgstInstalledReleaseScriptRoot `
            -RepositoryRoot $root `
            -ProgramFilesPath $ProgramFilesPath `
            -ScriptRelativePath 'scripts\reset-network.ps1'
    }
    else {
        & $InstalledReleaseValidator $root $expectedScript
    }
    if (-not $installedReleaseAccepted) {
        throw (
            'Network reset requires a complete SYSTEM-owned installed ' +
            'Release. Run install.cmd first.')
    }
}

function Read-WgstManagedRouteSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [long]$MaximumBytes = (8 * 1024 * 1024),
        [int]$MaximumEntries = 8192
    )

    try {
        $fullPath = [IO.Path]::GetFullPath($Path)
        $info = [IO.FileInfo]::new($fullPath)
        $info.Refresh()
        if (-not $info.Exists -or
            $info.Length -le 0 -or
            $info.Length -gt $MaximumBytes -or
            ($info.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'unsafe_state_file'
        }

        $bytes = [IO.File]::ReadAllBytes($fullPath)
        if ($bytes.Length -le 0 -or
            $bytes.Length -gt $MaximumBytes -or
            ($bytes.Length -ge 3 -and
                $bytes[0] -eq 0xEF -and
                $bytes[1] -eq 0xBB -and
                $bytes[2] -eq 0xBF)) {
            throw 'invalid_state_encoding'
        }

        $encoding = [Text.UTF8Encoding]::new($false, $true)
        $text = $encoding.GetString($bytes)
        $json = $text | ConvertFrom-Json
        if ($null -eq $json -or
            $json -is [Array] -or
            $json -is [string] -or
            $json -is [ValueType]) {
            throw 'invalid_state_root'
        }

        $allowedRootProperties = @(
            'DomainRules',
            'LastKnownResolvedIps',
            'ManagedRouteSnapshot',
            'SelectedTunnelConfigPath',
            'AutoEnableTunnel',
            'SoftwareRules',
            'DomainGlobalDefaultMode',
            'SoftwareGlobalDefaultMode',
            'RestoreNormalRoutingOnExit',
            'LastKnownResolvedIpDetails',
            'MacTunnelProfiles',
            'MacSoftwareRules',
            'MacDomainProfileAssignments',
            'ActiveRawTunnelName',
            'ActiveSplitTunnelConfigPath',
            'RawTunnelDnsCleanupDebt',
            'AutoUpdateEnabled'
        )
        $rootProperties = @($json.PSObject.Properties)
        foreach ($property in $rootProperties) {
            if ($allowedRootProperties -cnotcontains $property.Name) {
                throw 'invalid_state_property'
            }
        }

        $snapshotProperty = @($rootProperties | Where-Object {
                $_.Name -ceq 'ManagedRouteSnapshot'
            })
        if ($snapshotProperty.Count -ne 1 -or
            $null -eq $snapshotProperty[0].Value) {
            throw 'invalid_route_snapshot'
        }

        $snapshot = @($snapshotProperty[0].Value)
        if ($snapshot.Count -gt $MaximumEntries) {
            throw 'route_snapshot_too_large'
        }

        $seen = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        $canonicalIps = @()
        foreach ($entry in $snapshot) {
            if ($null -eq $entry -or
                $entry -is [Array] -or
                $entry -is [string] -or
                $entry -is [ValueType]) {
                throw 'invalid_route_entry'
            }

            $properties = @($entry.PSObject.Properties)
            $names = @($properties | ForEach-Object Name)
            if ($names.Count -lt 2 -or
                $names.Count -gt 3 -or
                $names -cnotcontains 'Domain' -or
                $names -cnotcontains 'IpAddress' -or
                ($names.Count -eq 3 -and
                    $names -cnotcontains 'InterfaceName')) {
                throw 'invalid_route_entry_shape'
            }

            foreach ($name in $names) {
                if ($name -cnotin @(
                        'Domain',
                        'IpAddress',
                        'InterfaceName')) {
                    throw 'invalid_route_entry_shape'
                }
            }

            $domain = [string]$entry.Domain
            if ([string]::IsNullOrWhiteSpace($domain) -or
                $domain.Length -gt 253 -or
                $domain -match '[\x00-\x1f\x7f]') {
                throw 'invalid_route_domain'
            }

            if ($names -ccontains 'InterfaceName' -and
                $null -ne $entry.InterfaceName) {
                $interfaceName = [string]$entry.InterfaceName
                if ([string]::IsNullOrWhiteSpace($interfaceName) -or
                    $interfaceName.Length -gt 256 -or
                    $interfaceName -match '[\x00-\x1f\x7f]') {
                    throw 'invalid_route_interface'
                }
            }

            $ip = [string]$entry.IpAddress
            $parsed = $null
            if ([string]::IsNullOrWhiteSpace($ip) -or
                $ip.Length -gt 15 -or
                -not [Net.IPAddress]::TryParse($ip, [ref]$parsed) -or
                $parsed.AddressFamily -ne
                    [Net.Sockets.AddressFamily]::InterNetwork -or
                $parsed.ToString() -cne $ip) {
                throw 'invalid_route_ip'
            }

            if ($seen.Add($ip)) {
                $canonicalIps += $ip
            }
        }

        return [string[]]$canonicalIps
    }
    catch {
        throw 'The route state file is invalid.'
    }
}

if ($LibraryOnly) {
    return
}

Initialize-WgstProtectedPowerShellEnvironment
$repositoryRoot = Split-Path -Parent $PSScriptRoot
Assert-WgstProtectedElevationRoot `
    -RepositoryRoot $repositoryRoot `
    -ScriptPath $PSCommandPath

if (-not (Test-IsAdministrator)) {
    if ($Elevated) {
        throw 'Elevation failed. Run reset-network.cmd from the installed copy and approve UAC.'
    }

    $powerShellPath = Get-WgstProtectedWindowsPowerShellPath
    Assert-WgstProtectedElevationRoot `
        -RepositoryRoot $repositoryRoot `
        -ScriptPath $PSCommandPath
    Initialize-WgstProtectedPowerShellEnvironment
    Start-Process -FilePath $powerShellPath -Verb RunAs -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', "`"$PSCommandPath`"",
        '-Elevated'
    )
    Write-Host '[RESET] ELEVATION_REQUESTED'
    exit 0
}

Import-WgstProtectedSystemModule -ModuleName 'NetSecurity'
$routePath = Get-WgstProtectedSystemExecutablePath -FileName 'route.exe'

Write-Host '[RESET] Removing app firewall rules...'
NetSecurity\Get-NetFirewallRule `
    -DisplayName 'WGST-Software-*' `
    -ErrorAction SilentlyContinue |
    NetSecurity\Remove-NetFirewallRule -ErrorAction SilentlyContinue

Write-Host '[RESET] Removing WireGuard half-default routes (0.0.0.0/1, 128.0.0.0/1)...'
& $routePath 'delete' '0.0.0.0' 'mask' '128.0.0.0' | Out-Null
& $routePath 'delete' '128.0.0.0' 'mask' '128.0.0.0' | Out-Null

Write-Host '[RESET] Removing stale host routes managed by app...'
$localApplicationData = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::LocalApplicationData)
if (-not [string]::IsNullOrWhiteSpace($localApplicationData)) {
    $statePath = Join-Path `
        $localApplicationData `
        'WireguardSplitTunnel\state.json'
}
if (-not [string]::IsNullOrWhiteSpace($statePath) -and
    [IO.File]::Exists($statePath)) {
    try {
        $managedRouteIps = @(Read-WgstManagedRouteSnapshot `
            -Path $statePath)
        foreach ($ip in $managedRouteIps) {
            & $routePath `
                'delete' `
                $ip `
                'mask' `
                '255.255.255.255' | Out-Null
        }
    }
    catch {
        Write-Host "[RESET] Skip invalid state file: $statePath"
    }
}

Write-Host '[RESET] Done. Please reconnect WireGuard manually if needed.'
