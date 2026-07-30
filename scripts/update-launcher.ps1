param(
    [switch]$LibraryOnly
)

$ErrorActionPreference = 'Stop'

$script:WgstUpdaterSuccess = 0
$script:WgstUpdaterLaunchHandled = 10
$script:WgstUpdaterExistingCandidate = 20
$script:WgstUpdaterRecoveryBlocked = 30
$script:WgstUpdaterFailed = 70

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

function Assert-WgstUpdateLauncherRoot {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [string]$ProgramFilesPath = [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::ProgramFiles),
        [scriptblock]$InstalledReleaseValidator
    )

    try {
        if ([string]::IsNullOrWhiteSpace($ProgramFilesPath)) {
            throw 'Program Files could not be resolved.'
        }

        $root = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        $expected = [IO.Path]::GetFullPath(
            (Join-Path $ProgramFilesPath 'WireguardSplitTunnel')).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        $accepted = if ($null -eq $InstalledReleaseValidator) {
            Test-WgstInstalledReleaseScriptRoot `
                -RepositoryRoot $root `
                -ProgramFilesPath $ProgramFilesPath `
                -ScriptRelativePath 'scripts\update-launcher.ps1'
        }
        else {
            & $InstalledReleaseValidator $root
        }
        if ($root -ieq $expected -and $accepted) {
            return
        }
    }
    catch {
        throw 'Protected update recovery requires the fixed Program Files installation.'
    }

    throw 'Protected update recovery requires the fixed Program Files installation.'
}

function New-WgstUpdateLauncherResult {
    param(
        [Parameter(Mandatory = $true)][bool]$Handled,
        [Parameter(Mandatory = $true)][bool]$Blocked,
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $result = [pscustomobject]@{
        Handled = $Handled
        Blocked = $Blocked
        ExitCode = $ExitCode
        Message = $Message
    }
    $result.PSObject.TypeNames.Insert(
        0,
        'WireguardSplitTunnel.UpdateLauncherResult')
    return $result
}

function New-WgstContinueNormalLaunchResult {
    New-WgstUpdateLauncherResult `
        -Handled $false `
        -Blocked $false `
        -ExitCode $script:WgstUpdaterSuccess `
        -Message 'ContinueNormalLaunch'
}

function New-WgstRecoveryBlockedResult {
    param(
        [int]$ExitCode = $script:WgstUpdaterFailed,
        [string]$Reason = 'validation_failed'
    )

    $safeReason = if ($Reason -match '^[a-z0-9_]{1,48}$') {
        $Reason
    }
    else {
        'validation_failed'
    }
    New-WgstUpdateLauncherResult `
        -Handled $false `
        -Blocked $true `
        -ExitCode $ExitCode `
        -Message "Update recovery is blocked ($safeReason). Review %LOCALAPPDATA%\WireguardSplitTunnel\logs\updater.log and run install.cmd -RepairBlockedUpdate."
}

function Test-WgstExactJsonProperties {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string[]]$Expected
    )

    if ($null -eq $Object) {
        return $false
    }

    $actual = @($Object.PSObject.Properties | ForEach-Object Name)
    if ($actual.Count -ne $Expected.Count) {
        return $false
    }

    foreach ($name in $Expected) {
        if (-not ($actual -ccontains $name)) {
            return $false
        }
    }

    return $true
}

function Read-WgstStrictUtf8Json {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][long]$MaximumBytes
    )

    $info = Get-Item -LiteralPath $Path -Force
    if ($info.PSIsContainer -or
        $info.Length -le 0 -or
        $info.Length -gt $MaximumBytes -or
        (($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'unsafe_json_file'
    }

    $bytes = [IO.File]::ReadAllBytes($info.FullName)
    if ($bytes.Length -ge 3 -and
        $bytes[0] -eq 0xEF -and
        $bytes[1] -eq 0xBB -and
        $bytes[2] -eq 0xBF) {
        throw 'json_bom'
    }

    $encoding = [Text.UTF8Encoding]::new($false, $true)
    $text = $encoding.GetString($bytes)
    return [pscustomobject]@{
        Bytes = $bytes
        Text = $text
        Json = ($text | ConvertFrom-Json)
    }
}

function Test-WgstPlainPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$Directory
    )

    try {
        $full = [IO.Path]::GetFullPath($Path)
        if (-not [string]::Equals(
                $full,
                $Path,
                [StringComparison]::OrdinalIgnoreCase) -or
            $full.StartsWith('\\', [StringComparison]::Ordinal)) {
            return $false
        }

        $item = Get-Item -LiteralPath $full -Force
        return $item.PSIsContainer -eq $Directory -and
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)
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
            if (-not (Test-WgstPlainPath `
                    -Path $current `
                    -Directory $true)) {
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

function Test-WgstCanonicalDescendant {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    try {
        $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd(
            [IO.Path]::DirectorySeparatorChar)
        $pathFull = [IO.Path]::GetFullPath($Path)
        return $pathFull.StartsWith(
            $rootFull + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)
    }
    catch {
        return $false
    }
}

function Test-WgstExactProtectedSecurityDescriptor {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Descriptor,
        [Parameter(Mandatory = $true)][bool]$Directory
    )

    try {
        if ($null -eq $Descriptor -or $Descriptor.Length -le 0) {
            return $false
        }

        $raw = [Security.AccessControl.RawSecurityDescriptor]::new(
            $Descriptor,
            0)
        $security = if ($Directory) {
            [Security.AccessControl.DirectorySecurity]::new()
        }
        else {
            [Security.AccessControl.FileSecurity]::new()
        }
        $security.SetSecurityDescriptorBinaryForm($Descriptor)
        $sidType = [Security.Principal.SecurityIdentifier]
        $owner = $security.GetOwner($sidType)
        $system = [Security.Principal.SecurityIdentifier]::new(
            [Security.Principal.WellKnownSidType]::LocalSystemSid,
            $null)
        $administrators = [Security.Principal.SecurityIdentifier]::new(
            [Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,
            $null)
        $controlFlags = [int]$raw.ControlFlags
        $daclProtected = [int][Security.AccessControl.ControlFlags]::
            DiscretionaryAclProtected
        $daclPresent = [int][Security.AccessControl.ControlFlags]::
            DiscretionaryAclPresent
        if (-not $system.Equals($owner) -or
            -not $security.AreAccessRulesProtected -or
            -not $security.AreAccessRulesCanonical -or
            (($controlFlags -band $daclProtected) -eq 0) -or
            (($controlFlags -band $daclPresent) -eq 0) -or
            $null -eq $raw.DiscretionaryAcl -or
            $raw.DiscretionaryAcl.Count -ne 2 -or
            $raw.Owner -isnot $sidType -or
            -not $system.Equals($raw.Owner)) {
            return $false
        }

        $expectedFlags = if ($Directory) {
            $combined = (
                [int][Security.AccessControl.AceFlags]::ContainerInherit
            ) -bor (
                [int][Security.AccessControl.AceFlags]::ObjectInherit
            )
            [Security.AccessControl.AceFlags]$combined
        }
        else {
            [Security.AccessControl.AceFlags]::None
        }
        $seen = @{}
        foreach ($genericAce in $raw.DiscretionaryAcl) {
            if ($genericAce -isnot
                    [Security.AccessControl.CommonAce]) {
                return $false
            }

            $ace = [Security.AccessControl.CommonAce]$genericAce
            $identity = $ace.SecurityIdentifier
            if ($ace.IsCallback -or
                $ace.AceQualifier -ne
                    [Security.AccessControl.AceQualifier]::AccessAllowed -or
                $ace.AccessMask -ne
                    [int][Security.AccessControl.FileSystemRights]::
                        FullControl -or
                $ace.AceFlags -ne $expectedFlags -or
                $ace.OpaqueLength -ne 0 -or
                $identity -isnot $sidType -or
                (-not $system.Equals($identity) -and
                    -not $administrators.Equals($identity)) -or
                $seen.ContainsKey($identity.Value)) {
                return $false
            }

            $seen[$identity.Value] = $true
        }

        return $seen.Count -eq 2 -and
            $seen.ContainsKey($system.Value) -and
            $seen.ContainsKey($administrators.Value)
    }
    catch {
        return $false
    }
}

function Test-WgstExactProtectedAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$Directory
    )

    try {
        if (-not (Test-WgstPlainPath -Path $Path -Directory $Directory)) {
            return $false
        }

        $descriptor = (Get-Acl -LiteralPath $Path).
            GetSecurityDescriptorBinaryForm()
        return Test-WgstExactProtectedSecurityDescriptor `
            -Descriptor $descriptor `
            -Directory $Directory
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
        if (-not (Test-WgstPlainPath `
                -Path $Path `
                -Directory $Directory)) {
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
        if ([string]::IsNullOrWhiteSpace($ProgramFilesPath)) {
            return $false
        }

        $root = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        $expectedRoot = [IO.Path]::GetFullPath(
            [IO.Path]::Combine(
                $ProgramFilesPath,
                'WireguardSplitTunnel')).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        if ($root -ine $expectedRoot) {
            return $false
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
            if (-not (Test-WgstPlainPath `
                    -Path $item.Path `
                    -Directory ([bool]$item.Directory))) {
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
            if (-not (Test-WgstPlainPath `
                    -Path ([string]$directory.FullPath) `
                    -Directory $true)) {
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
            if (-not (Test-WgstPlainPath `
                    -Path ([string]$file.FullPath) `
                    -Directory $false)) {
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

function Get-WgstFileSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            return -join ($sha.ComputeHash($stream) |
                ForEach-Object { $_.ToString('x2') })
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-WgstExecutableProductVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    return [Diagnostics.FileVersionInfo]::GetVersionInfo($Path).ProductVersion
}

function Invoke-WgstUpdaterProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    & $FilePath @Arguments | ForEach-Object { }
    return [int]$LASTEXITCODE
}

function Test-WgstProtectedPathSet {
    param(
        [Parameter(Mandatory = $true)][string]$ProductRoot,
        [Parameter(Mandatory = $true)][string]$TransactionsRoot,
        [Parameter(Mandatory = $true)][string]$ActivePointerPath,
        [Parameter(Mandatory = $true)][string]$TransactionRoot,
        [Parameter(Mandatory = $true)][string]$TransactionRecordPath,
        [Parameter(Mandatory = $true)][string]$HelperRoot,
        [Parameter(Mandatory = $true)][string]$HelperPath,
        [Parameter(Mandatory = $true)][scriptblock]$AclValidator
    )

    $items = @(
        [pscustomobject]@{ Path = $ProductRoot; Directory = $true },
        [pscustomobject]@{ Path = $TransactionsRoot; Directory = $true },
        [pscustomobject]@{ Path = $ActivePointerPath; Directory = $false },
        [pscustomobject]@{ Path = $TransactionRoot; Directory = $true },
        [pscustomobject]@{ Path = $TransactionRecordPath; Directory = $false },
        [pscustomobject]@{ Path = $HelperRoot; Directory = $true },
        [pscustomobject]@{ Path = $HelperPath; Directory = $false }
    )
    foreach ($item in $items) {
        if (-not (Test-WgstCanonicalDescendant `
                -Root $ProductRoot `
                -Path $item.Path) -and
            -not [string]::Equals(
                $item.Path,
                $ProductRoot,
                [StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }

        if (-not (Test-WgstPlainPath `
                -Path $item.Path `
                -Directory $item.Directory) -or
            -not (& $AclValidator $item.Path $item.Directory)) {
            return $false
        }
    }

    return $true
}

function Invoke-WgstProtectedUpdateRecoveryCore {
    param(
        [Parameter(Mandatory = $true)][string]$ProtectedProductRoot,
        [scriptblock]$AclValidator = {
            param($Path, [bool]$Directory)
            Test-WgstExactProtectedAcl -Path $Path -Directory $Directory
        },
        [scriptblock]$ProductVersionReader = {
            param($Path)
            Get-WgstExecutableProductVersion -Path $Path
        },
        [scriptblock]$ProcessInvoker = {
            param($FilePath, $Arguments)
            Invoke-WgstUpdaterProcess `
                -FilePath $FilePath `
                -Arguments $Arguments
        }
    )

    try {
        $productRoot = ([IO.Path]::GetFullPath(
                $ProtectedProductRoot)).TrimEnd(
            [IO.Path]::DirectorySeparatorChar)
        $transactionsRoot = Join-Path $productRoot 'UpdateTransactions'
        $activePointerPath = Join-Path `
            $transactionsRoot `
            'active-transaction.json'

        if (-not (Test-Path -LiteralPath $activePointerPath -PathType Leaf)) {
            return New-WgstContinueNormalLaunchResult
        }

        if (-not (Test-WgstPlainPath `
                -Path $productRoot `
                -Directory $true) -or
            -not (Test-WgstPlainPath `
                -Path $transactionsRoot `
                -Directory $true) -or
            -not (Test-WgstPlainPath `
                -Path $activePointerPath `
                -Directory $false) -or
            -not (& $AclValidator $productRoot $true) -or
            -not (& $AclValidator $transactionsRoot $true) -or
            -not (& $AclValidator $activePointerPath $false)) {
            return New-WgstRecoveryBlockedResult -Reason 'pointer_security'
        }

        $pointer = Read-WgstStrictUtf8Json `
            -Path $activePointerPath `
            -MaximumBytes 256
        if (-not (Test-WgstExactJsonProperties `
                -Object $pointer.Json `
                -Expected @('schemaVersion', 'transactionId')) -or
            $pointer.Json.schemaVersion -ne 1) {
            return New-WgstRecoveryBlockedResult -Reason 'pointer_invalid'
        }

        if ($null -eq $pointer.Json.transactionId) {
            if ($pointer.Text -cne
                '{"schemaVersion":1,"transactionId":null}') {
                return New-WgstRecoveryBlockedResult -Reason 'pointer_invalid'
            }

            return New-WgstContinueNormalLaunchResult
        }

        $transactionId = [string]$pointer.Json.transactionId
        if ($transactionId -cnotmatch '^[0-9a-f]{32}$' -or
            $pointer.Text -cne
                ('{"schemaVersion":1,"transactionId":"' +
                    $transactionId + '"}')) {
            return New-WgstRecoveryBlockedResult -Reason 'pointer_invalid'
        }

        $transactionRoot = Join-Path $transactionsRoot $transactionId
        $transactionRecordPath = Join-Path `
            $transactionRoot `
            'transaction.json'
        $helperRoot = Join-Path $transactionRoot 'helper'
        $helperPath = Join-Path `
            $helperRoot `
            'WireguardSplitTunnel.Updater.exe'
        if (-not (Test-WgstProtectedPathSet `
                -ProductRoot $productRoot `
                -TransactionsRoot $transactionsRoot `
                -ActivePointerPath $activePointerPath `
                -TransactionRoot $transactionRoot `
                -TransactionRecordPath $transactionRecordPath `
                -HelperRoot $helperRoot `
                -HelperPath $helperPath `
                -AclValidator $AclValidator)) {
            return New-WgstRecoveryBlockedResult -Reason 'transaction_security'
        }

        $record = Read-WgstStrictUtf8Json `
            -Path $transactionRecordPath `
            -MaximumBytes (4 * 1024 * 1024)
        $recordProperties = @(
            'schemaVersion',
            'transactionId',
            'version',
            'source',
            'installedRelease',
            'candidate',
            'helperSha256',
            'phase',
            'authorizedProcess',
            'journal'
        )
        if (-not (Test-WgstExactJsonProperties `
                -Object $record.Json `
                -Expected $recordProperties) -or
            $record.Json.schemaVersion -ne 1 -or
            [string]$record.Json.transactionId -cne $transactionId) {
            return New-WgstRecoveryBlockedResult -Reason 'record_invalid'
        }

        $version = [string]$record.Json.version
        $helperSha256 = [string]$record.Json.helperSha256
        $phase = [string]$record.Json.phase
        if ($version -cnotmatch
                '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -or
            $helperSha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $phase -cnotin @(
                'ProtectedStaged',
                'CloseAuthorized',
                'Prepared',
                'BackingUp',
                'Applying',
                'AppliedAwaitingHealth',
                'Committed',
                'RollingBack',
                'RolledBack',
                'RecoveryBlocked')) {
            return New-WgstRecoveryBlockedResult -Reason 'record_invalid'
        }

        if ($phase -ceq 'ProtectedStaged') {
            return New-WgstContinueNormalLaunchResult
        }
        if ($phase -ceq 'RecoveryBlocked') {
            return New-WgstRecoveryBlockedResult `
                -ExitCode $script:WgstUpdaterRecoveryBlocked `
                -Reason 'recovery_blocked'
        }

        $observedHash = Get-WgstFileSha256 -Path $helperPath
        $observedVersion = [string](& $ProductVersionReader $helperPath)
        if ($observedHash -cne $helperSha256 -or
            $observedVersion -cne $version) {
            return New-WgstRecoveryBlockedResult -Reason 'helper_identity'
        }

        # Repeat every path, ACL, hash, and ProductVersion check immediately
        # before process creation. Persisted child paths are never accepted.
        if (-not (Test-WgstProtectedPathSet `
                -ProductRoot $productRoot `
                -TransactionsRoot $transactionsRoot `
                -ActivePointerPath $activePointerPath `
                -TransactionRoot $transactionRoot `
                -TransactionRecordPath $transactionRecordPath `
                -HelperRoot $helperRoot `
                -HelperPath $helperPath `
                -AclValidator $AclValidator) -or
            (Get-WgstFileSha256 -Path $helperPath) -cne
                $helperSha256 -or
            [string](& $ProductVersionReader $helperPath) -cne
                $version) {
            return New-WgstRecoveryBlockedResult -Reason 'helper_revalidation'
        }

        $arguments = @(
            '--mode',
            'recover-and-launch',
            '--transaction',
            $transactionRecordPath
        )
        $exitCode = [int](& $ProcessInvoker $helperPath $arguments)
        switch ($exitCode) {
            $script:WgstUpdaterSuccess {
                return New-WgstContinueNormalLaunchResult
            }
            $script:WgstUpdaterLaunchHandled {
                return New-WgstUpdateLauncherResult `
                    -Handled $true `
                    -Blocked $false `
                    -ExitCode $exitCode `
                    -Message 'LaunchHandled'
            }
            $script:WgstUpdaterExistingCandidate {
                return New-WgstUpdateLauncherResult `
                    -Handled $true `
                    -Blocked $false `
                    -ExitCode $exitCode `
                    -Message 'ExistingCandidate'
            }
            $script:WgstUpdaterRecoveryBlocked {
                return New-WgstRecoveryBlockedResult `
                    -ExitCode $exitCode `
                    -Reason 'recovery_blocked'
            }
            default {
                return New-WgstRecoveryBlockedResult `
                    -ExitCode $exitCode `
                    -Reason 'helper_failed'
            }
        }
    }
    catch {
        return New-WgstRecoveryBlockedResult -Reason 'validation_failed'
    }
}

if (-not $LibraryOnly) {
    Initialize-WgstProtectedPowerShellEnvironment
    $repositoryRoot = Split-Path -Parent $PSScriptRoot
    Assert-WgstUpdateLauncherRoot -RepositoryRoot $repositoryRoot
    $protectedProductRoot = Join-Path `
        ([Environment]::GetFolderPath(
            [Environment+SpecialFolder]::CommonApplicationData)) `
        'WireguardSplitTunnel'
    Invoke-WgstProtectedUpdateRecoveryCore `
        -ProtectedProductRoot $protectedProductRoot
}
