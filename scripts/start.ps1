param(
    [switch]$DryRun,
    [switch]$Elevated,
    [switch]$PostInstallSelfTest,
    [string]$LauncherLogPath,
    [switch]$LibraryOnly
)

$ErrorActionPreference = 'Stop'

function Initialize-WgstProtectedPowerShellEnvironment {
    $systemDirectory = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::System)
    if ([string]::IsNullOrWhiteSpace($systemDirectory)) {
        throw 'The protected Windows PowerShell module root could not be resolved.'
    }

    $trustedDirectories = @($systemDirectory)
    if ([string]$PSVersionTable.PSEdition -ceq 'Core') {
        $programFiles = [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::ProgramFiles)
        if ([string]::IsNullOrWhiteSpace($programFiles) -or
            [string]::IsNullOrWhiteSpace($PSHOME) -or
            [string]::IsNullOrWhiteSpace([Environment]::ProcessPath)) {
            throw 'The protected PowerShell Core module root could not be resolved.'
        }

        $programFiles = [IO.Path]::GetFullPath($programFiles).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        $powerShellRoot = [IO.Path]::Combine(
            $programFiles,
            'PowerShell')
        $powerShellHome = [IO.Path]::GetFullPath($PSHOME).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        $processPath = [IO.Path]::GetFullPath(
            [Environment]::ProcessPath)
        $expectedProcessPath = [IO.Path]::Combine(
            $powerShellHome,
            'pwsh.exe')
        if ([IO.Path]::GetDirectoryName($powerShellHome) -ine
                $powerShellRoot -or
            $processPath -ine $expectedProcessPath) {
            throw 'PowerShell Core must run from the protected Program Files installation.'
        }

        $modulesDirectory = [IO.Path]::Combine(
            $powerShellHome,
            'Modules')
        $trustedDirectories += @(
            $programFiles,
            $powerShellRoot,
            $powerShellHome,
            $modulesDirectory)
        try {
            $processAttributes = [IO.File]::GetAttributes(
                $processPath)
            if (($processAttributes -band
                    [IO.FileAttributes]::Directory) -ne 0 -or
                ($processAttributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'unsafe_powershell_core'
            }
        }
        catch {
            throw 'The protected PowerShell Core executable is unsafe.'
        }
    }
    else {
        $powerShellHome = [IO.Path]::Combine(
            $systemDirectory,
            'WindowsPowerShell',
            'v1.0')
        $modulesDirectory = [IO.Path]::Combine(
            $powerShellHome,
            'Modules')
        $trustedDirectories += @(
            [IO.Path]::Combine(
                $systemDirectory,
                'WindowsPowerShell'),
            $powerShellHome,
            $modulesDirectory)
    }

    foreach ($directory in $trustedDirectories) {
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

    # A RunAs child inherits this process environment. Keep only the fixed,
    # edition-matched protected module root and make every later import explicit.
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

function Test-WgstPlainInstalledPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$Directory
    )

    try {
        $fullPath = [IO.Path]::GetFullPath($Path)
        if ($fullPath.StartsWith('\\', [StringComparison]::Ordinal)) {
            return $false
        }

        $attributes = [IO.File]::GetAttributes($fullPath)
        $isDirectory = (
            $attributes -band [IO.FileAttributes]::Directory) -ne 0
        return $isDirectory -eq $Directory -and
            ($attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0
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
            if (-not (Test-WgstPlainInstalledPath `
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

function Test-WgstExactInstalledAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$Directory,
        [Parameter(Mandatory = $true)][bool]$Root
    )

    try {
        if (-not (Test-WgstPlainInstalledPath `
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
            if (-not (Test-WgstPlainInstalledPath `
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
            if (-not (Test-WgstPlainInstalledPath `
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
            if (-not (Test-WgstPlainInstalledPath `
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

if ($Elevated) {
    # Never let a medium-integrity caller choose an Administrator write target.
    $LauncherLogPath = $null
}

function Write-LauncherLog {
    param([string]$Message)

    if ($DryRun -or
        (Test-IsAdministrator) -or
        [string]::IsNullOrWhiteSpace($LauncherLogPath)) {
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

function Get-WgstWindowsPowerShellPath {
    $systemDirectory = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::System)
    if ([string]::IsNullOrWhiteSpace($systemDirectory)) {
        throw 'The protected Windows PowerShell path could not be resolved.'
    }

    $powerShellPath = Join-Path `
        $systemDirectory `
        'WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $powerShellPath -PathType Leaf)) {
        throw 'The protected Windows PowerShell executable is missing.'
    }

    return [IO.Path]::GetFullPath($powerShellPath)
}

function Get-WgstLauncherTrust {
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
        $protectedRoot = [IO.Path]::GetFullPath(
            (Join-Path $ProgramFilesPath 'WireguardSplitTunnel')).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        if ($root -ieq $protectedRoot) {
            $installedReleaseAccepted = if (
                $null -eq $InstalledReleaseValidator) {
                Test-WgstInstalledReleaseScriptRoot `
                    -RepositoryRoot $root `
                    -ProgramFilesPath $ProgramFilesPath `
                    -ScriptRelativePath 'scripts\start.ps1'
            }
            else {
                & $InstalledReleaseValidator $root
            }
            if (-not $installedReleaseAccepted) {
                throw 'The installed Release failed security validation.'
            }

            return [pscustomobject]@{
                Supported = $true
                ElevationAllowed = $true
                RecoveryAllowed = $true
                Kind = 'ProtectedInstall'
            }
        }

        $releaseManifest = Join-Path $root 'release-manifest.json'
        if (Test-Path -LiteralPath $releaseManifest -PathType Leaf) {
            return [pscustomobject]@{
                Supported = $false
                ElevationAllowed = $false
                RecoveryAllowed = $false
                Kind = 'Unsupported'
            }
        }

        $project = Join-Path `
            $root `
            'src\WireguardSplitTunnel.App\WireguardSplitTunnel.App.csproj'
        $props = Join-Path $root 'Directory.Build.props'
        if ((Test-Path -LiteralPath $project -PathType Leaf) -and
            (Test-Path -LiteralPath $props -PathType Leaf)) {
            return [pscustomobject]@{
                Supported = $true
                ElevationAllowed = $false
                RecoveryAllowed = $false
                Kind = 'DeveloperSource'
            }
        }
    }
    catch {
        # Unsupported roots fail closed below.
    }

    return [pscustomobject]@{
        Supported = $false
        ElevationAllowed = $false
        RecoveryAllowed = $false
        Kind = 'Unsupported'
    }
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

function Resolve-WgstAppExecutable {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [string]$ExpectedAppVersion,
        [ValidateSet('ProtectedInstall', 'DeveloperSource')]
        [string]$LauncherKind = 'DeveloperSource'
    )

    $installedApplication = Join-Path `
        $RepoRoot `
        'WireguardSplitTunnel\WireguardSplitTunnel.App.exe'
    $appCandidates = if ($LauncherKind -ceq 'ProtectedInstall') {
        @($installedApplication)
    }
    else {
        @(
            $installedApplication,
            (Join-Path $RepoRoot 'src\WireguardSplitTunnel.App\bin\Release\net8.0-windows\WireguardSplitTunnel.App.exe'),
            (Join-Path $RepoRoot 'src\WireguardSplitTunnel.App\bin\Release\net8.0-windows\win-x64\publish\WireguardSplitTunnel.App.exe'),
            (Join-Path $RepoRoot 'src\WireguardSplitTunnel.App\bin\Debug\net8.0-windows\WireguardSplitTunnel.App.exe')
        )
    }
    Write-LauncherLog ("App candidates: " + ($appCandidates -join '; '))
    $appCandidateFiles = $appCandidates |
        Where-Object { Test-Path $_ } |
        ForEach-Object {
            Get-AppFileVersionInfo -File (Get-Item -LiteralPath $_)
        }
    if ($appCandidateFiles) {
        Write-LauncherLog (
            "Existing app candidates: " +
            (($appCandidateFiles | ForEach-Object {
                "$($_.FullName) version=$($_.VersionText) ($($_.LastWriteTime.ToString('s')))"
            }) -join '; '))
    }

    $selectableCandidates = $appCandidateFiles
    if ($ExpectedAppVersion) {
        $selectableCandidates = $appCandidateFiles |
            Where-Object { $_.VersionText -eq $ExpectedAppVersion }
        if (-not $selectableCandidates) {
            Write-LauncherLog "No local exe matched expected version $ExpectedAppVersion. Falling back to dotnet/latest prebuilt path."
        }
    }

    $resolved = $selectableCandidates |
        Sort-Object `
            @{ Expression = { $_.VersionKey }; Descending = $true }, `
            @{ Expression = { $_.LastWriteTime }; Descending = $true } |
        Select-Object -First 1 -ExpandProperty FullName
    if ($resolved) {
        Write-LauncherLog "Resolved app exe: $resolved"
    }
    return $resolved
}

function Invoke-WgstStartupGate {
    param(
        [Parameter(Mandatory = $true)][bool]$DryRun,
        [Parameter(Mandatory = $true)][bool]$PostInstallSelfTest,
        [Parameter(Mandatory = $true)][bool]$IsAdministrator,
        [Parameter(Mandatory = $true)][bool]$AlreadyElevated,
        [bool]$SupportedLauncherRoot = $true,
        [bool]$ElevationAllowed = $true,
        [bool]$RecoveryAllowed = $true,
        [Parameter(Mandatory = $true)][scriptblock]$ElevationAction,
        [Parameter(Mandatory = $true)][scriptblock]$RecoveryAction
    )

    if ($DryRun) {
        return [pscustomobject]@{
            Action = 'ContinueNormalLaunch'
            Recovery = $null
        }
    }

    if (-not $SupportedLauncherRoot) {
        throw (
            'Privileged startup is allowed only from the installed protected ' +
            'copy or an explicit developer source checkout. Run install.cmd ' +
            'before starting a bundled Release.')
    }

    if (-not $IsAdministrator) {
        if ($AlreadyElevated) {
            throw 'Failed to acquire Administrator rights. Please run start-admin.cmd and approve the UAC prompt.'
        }

        if (-not $ElevationAllowed) {
            return [pscustomobject]@{
                Action = 'ContinueNormalLaunch'
                Recovery = $null
            }
        }

        & $ElevationAction | Out-Null
        return [pscustomobject]@{
            Action = 'ElevationRequested'
            Recovery = $null
        }
    }

    if ($PostInstallSelfTest) {
        return [pscustomobject]@{
            Action = 'ContinueNormalLaunch'
            Recovery = $null
        }
    }

    if (-not $RecoveryAllowed) {
        return [pscustomobject]@{
            Action = 'ContinueNormalLaunch'
            Recovery = $null
        }
    }

    $recovery = & $RecoveryAction
    return [pscustomobject]@{
        Action = 'Recovery'
        Recovery = $recovery
    }
}

function Invoke-WgstMissingAppFallback {
    param(
        [Parameter(Mandatory = $true)][string]$LauncherKind,
        [Parameter(Mandatory = $true)][bool]$IsAdministrator,
        [Parameter(Mandatory = $true)]
        [scriptblock]$EnsurePrebuiltAction,
        [Parameter(Mandatory = $true)]
        [scriptblock]$DotnetFallbackAction
    )

    if ($LauncherKind -cne 'DeveloperSource' -or $IsAdministrator) {
        throw (
            'The protected installation is incomplete and cannot use ' +
            'developer download or dotnet fallbacks. Run install.cmd to ' +
            'repair or reinstall the protected copy.')
    }

    $candidate = & $EnsurePrebuiltAction
    if (-not [string]::IsNullOrWhiteSpace([string]$candidate)) {
        return [pscustomobject]@{
            Action = 'Executable'
            ExecutablePath = [string]$candidate
        }
    }

    & $DotnetFallbackAction | Out-Null
    return [pscustomobject]@{
        Action = 'Dotnet'
        ExecutablePath = $null
    }
}

if ($LibraryOnly) {
    return
}

try {
    Initialize-WgstProtectedPowerShellEnvironment
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

    if ($DryRun) {
        $appExe = Resolve-WgstAppExecutable `
            -RepoRoot $repoRoot `
            -ExpectedAppVersion $expectedAppVersion
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

    $launcherTrust = Get-WgstLauncherTrust -RepositoryRoot $repoRoot
    Write-LauncherLog (
        "Launcher trust. supported=$($launcherTrust.Supported) " +
        "elevationAllowed=$($launcherTrust.ElevationAllowed) " +
        "recoveryAllowed=$($launcherTrust.RecoveryAllowed) " +
        "kind=$($launcherTrust.Kind)")

    $scriptPath = Join-Path $PSScriptRoot 'start.ps1'
    $powerShellPath = Get-WgstWindowsPowerShellPath
    $argList = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', "`"$scriptPath`"",
        '-Elevated'
    )
    if ($PostInstallSelfTest) {
        $argList += '-PostInstallSelfTest'
    }

    $startupGate = Invoke-WgstStartupGate `
        -DryRun $false `
        -PostInstallSelfTest ([bool]$PostInstallSelfTest) `
        -IsAdministrator (Test-IsAdministrator) `
        -AlreadyElevated ([bool]$Elevated) `
        -SupportedLauncherRoot ([bool]$launcherTrust.Supported) `
        -ElevationAllowed ([bool]$launcherTrust.ElevationAllowed) `
        -RecoveryAllowed ([bool]$launcherTrust.RecoveryAllowed) `
        -ElevationAction {
            Write-LauncherLog 'Requesting launcher elevation.'
            $elevationTrust = Get-WgstLauncherTrust `
                -RepositoryRoot $repoRoot
            if (-not $elevationTrust.ElevationAllowed -or
                $elevationTrust.Kind -cne 'ProtectedInstall') {
                throw 'The installed Release changed before elevation.'
            }

            Initialize-WgstProtectedPowerShellEnvironment
            Start-Process `
                -FilePath $powerShellPath `
                -Verb RunAs `
                -ArgumentList $argList
        } `
        -RecoveryAction {
            $updateLauncher = Join-Path $PSScriptRoot 'update-launcher.ps1'
            if (-not (Test-Path -LiteralPath $updateLauncher -PathType Leaf)) {
                throw 'Protected update launcher is missing.'
            }

            & $updateLauncher
        }

    if ($startupGate.Action -eq 'ElevationRequested') {
        Write-Output 'ELEVATION_REQUESTED'
        exit 0
    }

    if ($startupGate.Action -eq 'Recovery') {
        $recovery = $startupGate.Recovery
        if ($null -eq $recovery -or
            $null -eq $recovery.Handled -or
            $null -eq $recovery.Blocked -or
            $null -eq $recovery.ExitCode -or
            [string]::IsNullOrWhiteSpace([string]$recovery.Message)) {
            throw 'Protected update recovery returned an invalid result.'
        }

        Write-LauncherLog (
            "Protected recovery result. handled=$($recovery.Handled) " +
            "blocked=$($recovery.Blocked) exitCode=$($recovery.ExitCode) " +
            "message=$($recovery.Message)")
        if ([bool]$recovery.Blocked) {
            throw [string]$recovery.Message
        }
        if ([bool]$recovery.Handled) {
            Write-Output "UPDATE_LAUNCH_HANDLED $($recovery.Message)"
            exit 0
        }
        if ([int]$recovery.ExitCode -ne 0 -or
            [string]$recovery.Message -cne 'ContinueNormalLaunch') {
            throw 'Protected update recovery did not authorize normal launch.'
        }
    }

    # Recovery can replace the installed application. Resolve the executable
    # only after recovery has reached a stable decision so selection cannot be
    # based on the pre-recovery file set.
    $appExe = Resolve-WgstAppExecutable `
        -RepoRoot $repoRoot `
        -ExpectedAppVersion $expectedAppVersion `
        -LauncherKind ([string]$launcherTrust.Kind)

    if (-not $appExe) {
        $fallback = Invoke-WgstMissingAppFallback `
            -LauncherKind ([string]$launcherTrust.Kind) `
            -IsAdministrator (Test-IsAdministrator) `
            -EnsurePrebuiltAction {
                $candidate = $null
                $ensurePrebuiltScript = Join-Path `
                    $PSScriptRoot `
                    'ensure-prebuilt.ps1'
                if (Test-Path `
                        -LiteralPath $ensurePrebuiltScript `
                        -PathType Leaf) {
                    try {
                        Write-LauncherLog (
                            'No local exe found. Attempting ' +
                            'ensure-prebuilt.ps1.')
                        $downloadedExe = & $ensurePrebuiltScript `
                            -RepoRoot $repoRoot
                        if (-not [string]::IsNullOrWhiteSpace(
                                [string]$downloadedExe) -and
                            (Test-Path `
                                -LiteralPath $downloadedExe `
                                -PathType Leaf)) {
                            $downloadedInfo = Get-AppFileVersionInfo `
                                -File (Get-Item `
                                    -LiteralPath $downloadedExe)
                            if (-not $expectedAppVersion -or
                                $downloadedInfo.VersionText -eq
                                    $expectedAppVersion) {
                                $candidate = [string]$downloadedExe
                                Write-LauncherLog (
                                    "Prebuilt downloaded: $candidate")
                            }
                            else {
                                Write-LauncherLog (
                                    'Downloaded prebuilt version ' +
                                    "$($downloadedInfo.VersionText) did " +
                                    'not match expected ' +
                                    "$expectedAppVersion.")
                            }
                        }
                    }
                    catch {
                        Write-LauncherLog (
                            'Prebuilt download failed: ' +
                            $_.Exception.Message)
                        Write-Warning (
                            'Prebuilt download failed: ' +
                            $_.Exception.Message)
                    }
                }

                return $candidate
            } `
            -DotnetFallbackAction {
                $dotnet = Get-Command `
                    'dotnet' `
                    -CommandType Application `
                    -ErrorAction SilentlyContinue
                if ($null -eq $dotnet) {
                    Write-LauncherLog (
                        'No published app found and dotnet is ' +
                        'unavailable.')
                    throw (
                        'No published app found and dotnet SDK is not ' +
                        'installed. Run install.cmd first.')
                }

                $dotnetPath = [string]$dotnet.Source
                $sdkOutput = (& $dotnetPath --list-sdks 2>$null)
                if ($LASTEXITCODE -ne 0 -or -not $sdkOutput) {
                    Write-LauncherLog (
                        'No published app found and .NET SDK is ' +
                        'unavailable.')
                    throw (
                        'No published app found and .NET SDK is not ' +
                        'available. Install .NET 8 SDK or run ' +
                        'install.cmd from a trusted Release bundle.')
                }

                Write-LauncherLog (
                    "Launching dotnet fallback. args=$dotnetArguments")
                Start-Process `
                    -FilePath $dotnetPath `
                    -ArgumentList $dotnetArguments `
                    -WorkingDirectory $repoRoot
            }

        if ($fallback.Action -ceq 'Executable') {
            $appExe = [string]$fallback.ExecutablePath
            Write-Output "PREBUILT_DOWNLOADED $appExe"
        }
        elseif ($fallback.Action -ceq 'Dotnet') {
            Write-Output 'STARTED_DOTNET'
            exit 0
        }
        else {
            throw 'The missing-app fallback returned an invalid result.'
        }
    }

    if ($appExe) {
        if ($launcherTrust.Kind -ceq 'ProtectedInstall') {
            $preLaunchTrust = Get-WgstLauncherTrust `
                -RepositoryRoot $repoRoot
            if (-not $preLaunchTrust.Supported -or
                -not $preLaunchTrust.ElevationAllowed -or
                $preLaunchTrust.Kind -cne 'ProtectedInstall') {
                throw 'The installed Release changed before app launch.'
            }

            $expectedProtectedApp = [IO.Path]::GetFullPath(
                (Join-Path `
                    $repoRoot `
                    'WireguardSplitTunnel\WireguardSplitTunnel.App.exe'))
            $revalidatedApp = Resolve-WgstAppExecutable `
                -RepoRoot $repoRoot `
                -ExpectedAppVersion $expectedAppVersion `
                -LauncherKind 'ProtectedInstall'
            if ([string]::IsNullOrWhiteSpace($revalidatedApp) -or
                [IO.Path]::GetFullPath($revalidatedApp) -ine
                    $expectedProtectedApp -or
                [IO.Path]::GetFullPath($appExe) -ine
                    $expectedProtectedApp) {
                throw 'The installed application changed before launch.'
            }

            $appExe = $revalidatedApp
        }

        $appArgs = if ($PostInstallSelfTest) { '--post-install-self-test' } else { '' }
        if ($launcherTrust.Kind -ceq 'DeveloperSource') {
            Unblock-AppFile -Path $appExe
        }
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

}
catch {
    Write-LauncherLog "ERROR: $($_.Exception.Message)"
    throw
}
