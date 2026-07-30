param(
    [switch]$SkipPublish,
    [switch]$ForcePublish,
    [switch]$RepairBlockedUpdate,
    [switch]$NoDesktopShortcut,
    [switch]$NoPostInstallSelfTest,
    [switch]$Elevated,
    [switch]$ProtectedInstalledCopy,
    [switch]$ProtectedRepairBootstrap,
    [string]$LauncherLogPath
)

$ErrorActionPreference = 'Stop'
$PSModuleAutoLoadingPreference = 'None'
$trustedWindows = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::Windows)
if ([string]::IsNullOrWhiteSpace($trustedWindows)) {
    throw 'The trusted Windows directory could not be resolved.'
}
$trustedWindowsPowerShell = [IO.Path]::GetFullPath(
    [IO.Path]::Combine(
        $trustedWindows,
        'System32',
        'WindowsPowerShell',
        'v1.0'))
$trustedModuleRoot = [IO.Path]::Combine(
    $trustedWindowsPowerShell,
    'Modules')
if (-not [IO.Directory]::Exists($trustedModuleRoot) -or
    ([IO.File]::GetAttributes($trustedModuleRoot) -band
        [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The trusted Windows PowerShell module root is unsafe.'
}
$env:PSModulePath = $trustedModuleRoot
foreach ($trustedModuleName in @(
        'Microsoft.PowerShell.Management',
        'Microsoft.PowerShell.Utility')) {
    $trustedModuleDirectory = [IO.Path]::Combine(
        $trustedModuleRoot,
        $trustedModuleName)
    $trustedModuleManifest = [IO.Path]::Combine(
        $trustedModuleDirectory,
        "$trustedModuleName.psd1")
    if (-not [IO.Directory]::Exists($trustedModuleDirectory) -or
        -not [IO.File]::Exists($trustedModuleManifest) -or
        ([IO.File]::GetAttributes($trustedModuleDirectory) -band
            [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        ([IO.File]::GetAttributes($trustedModuleManifest) -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'A trusted Windows PowerShell core module is unsafe.'
    }
    Microsoft.PowerShell.Core\Import-Module `
        -Name $trustedModuleManifest `
        -Force `
        -ErrorAction Stop
}
if ($Elevated -or $ProtectedInstalledCopy) {
    $LauncherLogPath = $null
}

function Get-WgstSystemPowerShellPath {
    $windows = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::Windows)
    if ([string]::IsNullOrWhiteSpace($windows)) {
        throw 'The trusted Windows directory could not be resolved.'
    }
    $powershell = Join-Path $windows (
        'System32\WindowsPowerShell\v1.0\powershell.exe')
    if (-not (Test-Path -LiteralPath $powershell -PathType Leaf)) {
        throw 'The trusted Windows PowerShell executable is missing.'
    }
    return [IO.Path]::GetFullPath($powershell)
}

function Write-LauncherLog {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($LauncherLogPath)) {
        return
    }

    $directory = Split-Path -Parent $LauncherLogPath
    if (-not [string]::IsNullOrWhiteSpace($directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $line = "[{0}] [INSTALL.PS1] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff zzz'), $Message
    Add-Content -Path $LauncherLogPath -Value $line
}

function Write-Step {
    param([string]$Message)
    Write-Host "[INSTALL] $Message"
    Write-LauncherLog $Message
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Administrator {
    if (Test-IsAdministrator) {
        return
    }

    if ($ProtectedInstalledCopy) {
        throw (
            'The authenticated bundled Release bootstrap did not acquire ' +
            'Administrator rights. Re-run install.cmd and approve the UAC prompt.')
    }
    throw (
        'Developer-source installation will not elevate a mutable script. ' +
        'Open the trusted developer checkout in an Administrator terminal ' +
        'and run scripts\install.ps1 again.')
}

function New-DesktopShortcut {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$TargetPath,
        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory
    )

    $desktop = [Environment]::GetFolderPath('Desktop')
    $shortcutPath = Join-Path $desktop ("$Name.lnk")

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $TargetPath
    $shortcut.WorkingDirectory = $WorkingDirectory
    $shortcut.Save()

    return $shortcutPath
}

function Get-DotnetCommand {
    $programFiles = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFiles)
    if ([string]::IsNullOrWhiteSpace($programFiles)) {
        return $null
    }
    $dotnet = Join-Path $programFiles 'dotnet\dotnet.exe'
    if (Test-Path -LiteralPath $dotnet -PathType Leaf) {
        $item = Get-Item -LiteralPath $dotnet -Force
        if (($item.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -eq 0) {
            return $item.FullName
        }
    }

    return $null
}

function Get-DotnetSdkCount {
    param([string]$DotnetPath)

    if ([string]::IsNullOrWhiteSpace($DotnetPath)) {
        return 0
    }

    $output = & $DotnetPath --list-sdks 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $output) {
        return 0
    }

    return @($output | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
}

function Get-WireGuardCliPath {
    $programFiles = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFiles)
    $programFilesX86 = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFilesX86)
    $candidates = @(
        (Join-Path $programFiles 'WireGuard\wireguard.exe'),
        (Join-Path $programFilesX86 'WireGuard\wireguard.exe')
    )

    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and
            (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            $item = Get-Item -LiteralPath $candidate -Force
            if (($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -eq 0) {
                return $item.FullName
            }
        }
    }

    return $null
}

function Read-WgstExactBoundBytes {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][long]$ExpectedLength,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )

    if ($ExpectedLength -lt 1 -or
        $ExpectedLength -gt 16MB -or
        $ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Bound bootstrap file identity is invalid.'
    }
    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        if ($stream.Length -ne $ExpectedLength) {
            throw 'Bound bootstrap file length changed.'
        }
        $bytes = New-Object byte[] ([int]$ExpectedLength)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read(
                $bytes,
                $offset,
                $bytes.Length - $offset)
            if ($read -le 0) {
                throw 'Bound bootstrap file ended early.'
            }
            $offset += $read
        }
        if ($stream.ReadByte() -ne -1 -or
            $stream.Length -ne $ExpectedLength) {
            throw 'Bound bootstrap file changed while it was read.'
        }
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $actual = [BitConverter]::ToString(
                $sha.ComputeHash($bytes)).Replace('-', '').
                    ToLowerInvariant()
        }
        finally {
            $sha.Dispose()
        }
        if ($actual -cne $ExpectedSha256) {
            throw 'Bound bootstrap file hash changed.'
        }
        return ,$bytes
    }
    finally {
        $stream.Dispose()
    }
}

function Import-WgstAuthenticatedBundleModule {
    param([Parameter(Mandatory = $true)][string]$PackageRoot)

    $root = [IO.Path]::GetFullPath($PackageRoot)
    $manifestPath = Join-Path $root 'release-manifest.json'
    $manifestStream = [IO.File]::Open(
        $manifestPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        if ($manifestStream.Length -lt 1 -or
            $manifestStream.Length -gt 2MB) {
            throw 'Bundled Release manifest size is invalid.'
        }
        $manifestBytes = New-Object byte[] ([int]$manifestStream.Length)
        $offset = 0
        while ($offset -lt $manifestBytes.Length) {
            $read = $manifestStream.Read(
                $manifestBytes,
                $offset,
                $manifestBytes.Length - $offset)
            if ($read -le 0) {
                throw 'Bundled Release manifest ended early.'
            }
            $offset += $read
        }
        if ($manifestStream.ReadByte() -ne -1) {
            throw 'Bundled Release manifest changed while it was read.'
        }
    }
    finally {
        $manifestStream.Dispose()
    }
    $manifestText =
        [Text.UTF8Encoding]::new($false, $true).GetString(
            $manifestBytes)
    $manifest = $manifestText | ConvertFrom-Json
    $moduleEntries = @($manifest.files | Where-Object {
        [string]$_.path -ceq 'scripts/WindowsRelease.psm1'
    })
    if ($moduleEntries.Count -ne 1) {
        throw 'Bundled Release module identity is missing or ambiguous.'
    }
    $moduleEntry = $moduleEntries[0]
    $modulePath = Join-Path $root 'scripts\WindowsRelease.psm1'
    $moduleBytes = Read-WgstExactBoundBytes `
        -Path $modulePath `
        -ExpectedLength ([long]$moduleEntry.length) `
        -ExpectedSha256 ([string]$moduleEntry.sha256)
    $moduleText =
        [Text.UTF8Encoding]::new($false, $true).GetString(
            $moduleBytes)
    $module = New-Module `
        -ScriptBlock ([ScriptBlock]::Create($moduleText))
    Microsoft.PowerShell.Core\Import-Module $module -Force
    $binding = & $module {
        param($Root)
        Get-WgstAuthenticatedBundledReleaseBinding `
            -PackageRoot $Root
    } $root
    return [pscustomobject]@{
        Module = $module
        Binding = $binding
        ModulePath = $modulePath
        ModuleLength = [long]$moduleEntry.length
        ModuleSha256 = [string]$moduleEntry.sha256
    }
}

function Invoke-WgstBoundBundledReleaseBootstrap {
    param([Parameter(Mandatory = $true)][string]$PackageRoot)

    $authenticated = Import-WgstAuthenticatedBundleModule `
        -PackageRoot $PackageRoot
    $binding = $authenticated.Binding
    $payload = [ordered]@{
        packageRoot = [string]$binding.packageRoot
        modulePath = [string]$authenticated.ModulePath
        moduleLength = [long]$authenticated.ModuleLength
        moduleSha256 = [string]$authenticated.ModuleSha256
        volumeSerialNumber = [uint32]$binding.volumeSerialNumber
        fileIndex = [uint64]$binding.fileIndex
        manifestLength = [long]$binding.manifestLength
        manifestSha256 = [string]$binding.manifestSha256
        skipPublish = [bool]$SkipPublish
        forcePublish = [bool]$ForcePublish
        repairBlockedUpdate = [bool]$RepairBlockedUpdate
        noDesktopShortcut = [bool]$NoDesktopShortcut
        noPostInstallSelfTest = [bool]$NoPostInstallSelfTest
    } | ConvertTo-Json -Compress
    $payloadBase64 = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes($payload))
$bootstrapTemplate = @'
$ErrorActionPreference = 'Stop'
$PSModuleAutoLoadingPreference = 'None'
$trustedWindows = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::Windows)
if ([string]::IsNullOrWhiteSpace($trustedWindows)) {
    throw 'The trusted Windows directory could not be resolved.'
}
$trustedWindowsPowerShell = [IO.Path]::GetFullPath(
    [IO.Path]::Combine(
        $trustedWindows,
        'System32',
        'WindowsPowerShell',
        'v1.0'))
$trustedModuleRoot = [IO.Path]::Combine(
    $trustedWindowsPowerShell,
    'Modules')
if (-not [IO.Directory]::Exists($trustedModuleRoot) -or
    ([IO.File]::GetAttributes($trustedModuleRoot) -band
        [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The trusted Windows PowerShell module root is unsafe.'
}
$env:PSModulePath = $trustedModuleRoot
foreach ($trustedModuleName in @(
        'Microsoft.PowerShell.Management',
        'Microsoft.PowerShell.Utility')) {
    $trustedModuleDirectory = [IO.Path]::Combine(
        $trustedModuleRoot,
        $trustedModuleName)
    $trustedModuleManifest = [IO.Path]::Combine(
        $trustedModuleDirectory,
        "$trustedModuleName.psd1")
    if (-not [IO.Directory]::Exists($trustedModuleDirectory) -or
        -not [IO.File]::Exists($trustedModuleManifest) -or
        ([IO.File]::GetAttributes($trustedModuleDirectory) -band
            [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        ([IO.File]::GetAttributes($trustedModuleManifest) -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'A trusted Windows PowerShell core module is unsafe.'
    }
    Microsoft.PowerShell.Core\Import-Module `
        -Name $trustedModuleManifest `
        -Force `
        -ErrorAction Stop
}
$payloadText = [Text.UTF8Encoding]::new($false, $true).GetString(
    [Convert]::FromBase64String('__PAYLOAD__'))
$payload = $payloadText | ConvertFrom-Json
$stream = [IO.File]::Open(
    [string]$payload.modulePath,
    [IO.FileMode]::Open,
    [IO.FileAccess]::Read,
    [IO.FileShare]::Read)
try {
    $expectedLength = [long]$payload.moduleLength
    if ($expectedLength -lt 1 -or
        $expectedLength -gt 16MB -or
        $stream.Length -ne $expectedLength) {
        throw 'Bound Release module length changed before elevation.'
    }
    $moduleBytes = New-Object byte[] ([int]$expectedLength)
    $offset = 0
    while ($offset -lt $moduleBytes.Length) {
        $read = $stream.Read(
            $moduleBytes,
            $offset,
            $moduleBytes.Length - $offset)
        if ($read -le 0) {
            throw 'Bound Release module ended early.'
        }
        $offset += $read
    }
    if ($stream.ReadByte() -ne -1 -or
        $stream.Length -ne $expectedLength) {
        throw 'Bound Release module changed while it was read.'
    }
}
finally {
    $stream.Dispose()
}
$sha = [Security.Cryptography.SHA256]::Create()
try {
    $moduleSha256 = [BitConverter]::ToString(
        $sha.ComputeHash($moduleBytes)).Replace('-', '').ToLowerInvariant()
}
finally {
    $sha.Dispose()
}
if ($moduleSha256 -cne [string]$payload.moduleSha256) {
    throw 'Bound Release module hash changed before elevation.'
}
$moduleText = [Text.UTF8Encoding]::new($false, $true).GetString(
    $moduleBytes)
$module = New-Module -ScriptBlock ([ScriptBlock]::Create($moduleText))
Microsoft.PowerShell.Core\Import-Module $module -Force
$repairBootstrap = [bool]$payload.repairBlockedUpdate
$installedRoot = & $module {
    param($Payload, [bool]$RepairBootstrap)
    Install-WgstAuthenticatedBundledReleaseToProtectedAnchor `
        -PackageRoot ([string]$Payload.packageRoot) `
        -ExpectedVolumeSerialNumber ([uint32]$Payload.volumeSerialNumber) `
        -ExpectedFileIndex ([uint64]$Payload.fileIndex) `
        -ExpectedManifestLength ([long]$Payload.manifestLength) `
        -ExpectedManifestSha256 ([string]$Payload.manifestSha256) `
        -RepairBootstrap:$RepairBootstrap
} $payload $repairBootstrap
$installedScript = Join-Path $installedRoot 'scripts\install.ps1'
try {
    $childArguments = @('-Elevated', '-ProtectedInstalledCopy')
    if ([bool]$payload.skipPublish) {
        $childArguments += '-SkipPublish'
    }
    if ([bool]$payload.forcePublish) {
        $childArguments += '-ForcePublish'
    }
    if ([bool]$payload.repairBlockedUpdate) {
        $childArguments += @(
            '-RepairBlockedUpdate',
            '-ProtectedRepairBootstrap')
    }
    if ([bool]$payload.noDesktopShortcut) {
        $childArguments += '-NoDesktopShortcut'
    }
    if ([bool]$payload.noPostInstallSelfTest) {
        $childArguments += '-NoPostInstallSelfTest'
    }
    & $installedScript @childArguments
    if (-not $?) {
        throw 'Protected installed Release installer failed.'
    }
}
finally {
    if ($repairBootstrap) {
        & $module {
            param($StagingRoot)
            Remove-WgstProtectedInstallStaging `
                -InstallRoot (Get-WgstProtectedInstallRoot) `
                -StagingRoot $StagingRoot
        } $installedRoot
    }
}
'@
    $bootstrapSource = $bootstrapTemplate.Replace(
        '__PAYLOAD__',
        $payloadBase64)
    $encodedCommand = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($bootstrapSource))

    if (Test-IsAdministrator) {
        & ([ScriptBlock]::Create($bootstrapSource))
        return
    }

    Write-Step 'Requesting authenticated bundled Release elevation.'
    $process = Start-Process `
        -FilePath (Get-WgstSystemPowerShellPath) `
        -Verb RunAs `
        -ArgumentList @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-EncodedCommand', $encodedCommand) `
        -Wait `
        -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Protected installer failed with exit code $($process.ExitCode)."
    }
}

function Unblock-ReleaseFiles {
    param([Parameter(Mandatory = $true)][string]$RootPath)

    if (-not (Test-Path $RootPath)) {
        return
    }

    $targets = @($RootPath) + @(Get-ChildItem -LiteralPath $RootPath -Recurse -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    $count = 0

    foreach ($target in $targets) {
        try {
            Unblock-File -LiteralPath $target -ErrorAction Stop
            $count++
        }
        catch {
            # Ignore files without Zone.Identifier or unsupported filesystems.
        }
    }

    Write-Step "Unblock scan completed. Files processed: $count"
}

Write-LauncherLog "Startup. elevated=$Elevated protectedInstalledCopy=$ProtectedInstalledCopy skipPublish=$SkipPublish forcePublish=$ForcePublish repairBlockedUpdate=$RepairBlockedUpdate noDesktopShortcut=$NoDesktopShortcut noPostInstallSelfTest=$NoPostInstallSelfTest"

$repoRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$projectPath = Join-Path $repoRoot 'src\WireguardSplitTunnel.App\WireguardSplitTunnel.App.csproj'
$propsPath = Join-Path $repoRoot 'Directory.Build.props'
$publishDir = Join-Path $repoRoot 'WireguardSplitTunnel'
$publishedExe = Join-Path $publishDir 'WireguardSplitTunnel.App.exe'
$publishedUpdater = Join-Path $publishDir 'WireguardSplitTunnel.Updater.exe'
$releaseManifest = Join-Path $repoRoot 'release-manifest.json'
$releaseModulePath = Join-Path $PSScriptRoot 'WindowsRelease.psm1'
$releaseLibraryPath = Join-Path $PSScriptRoot 'lib\release-package.ps1'
$hasSourceProject = Test-Path -LiteralPath $projectPath -PathType Leaf
$hasProps = Test-Path -LiteralPath $propsPath -PathType Leaf
$hasReleaseManifest =
    Test-Path -LiteralPath $releaseManifest -PathType Leaf
$hasBundledApplication =
    Test-Path -LiteralPath $publishedExe -PathType Leaf
$hasBundledUpdater =
    Test-Path -LiteralPath $publishedUpdater -PathType Leaf
$hasBundledReleaseMarker =
    $hasReleaseManifest -or
    $hasBundledApplication -or
    $hasBundledUpdater
$isSourceCheckout =
    -not $hasBundledReleaseMarker -and
    $hasSourceProject -and
    $hasProps

if (-not $ProtectedInstalledCopy) {
    if ($hasBundledReleaseMarker) {
        foreach ($required in @(
                $releaseManifest,
                $releaseModulePath,
                $releaseLibraryPath,
                $publishedExe,
                $publishedUpdater)) {
            if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
                throw (
                    'This packaged Release is incomplete and will not be ' +
                    'elevated. Download a fresh Release and run install.cmd.')
            }
        }
        Invoke-WgstBoundBundledReleaseBootstrap -PackageRoot $repoRoot
        return
    }
    if (-not $isSourceCheckout) {
        throw (
            'This installer root is neither a complete packaged Release ' +
            'nor an explicit developer-source checkout.')
    }
}

if ($RepairBlockedUpdate -and -not $ProtectedInstalledCopy) {
    throw 'RepairBlockedUpdate must enter through a packaged Release bootstrap.'
}

Ensure-Administrator

if (-not (Test-Path -LiteralPath $releaseModulePath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $releaseLibraryPath -PathType Leaf)) {
    throw 'Release validation scripts are missing.'
}
$releaseModule = Microsoft.PowerShell.Core\Import-Module `
    -Name $releaseModulePath `
    -Force `
    -PassThru
. $releaseLibraryPath

if ($ProtectedInstalledCopy) {
    $protectedExecutionRoot = & $releaseModule {
        param($Root, [bool]$RepairBootstrap)
        $expected = Get-WgstProtectedInstallRoot
        $canonical = [IO.Path]::GetFullPath($Root).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        $validLocation = if ($RepairBootstrap) {
            (Split-Path -Parent $canonical) -ieq
                (Split-Path -Parent $expected) -and
            (Split-Path -Leaf $canonical).StartsWith(
                'WireguardSplitTunnel.install-',
                [StringComparison]::Ordinal)
        }
        else {
            $canonical -ieq $expected
        }
        if (-not $validLocation -or
            -not (Test-WgstProtectedInstallParentAuthority `
                -InstallRoot $expected)) {
            return $false
        }
        try {
            $plan = Get-WgstAuthenticatedBundledReleaseAclPlan `
                -PackageRoot $canonical
            return Test-WgstInstalledReleaseAclPlanExact -Plan $plan
        }
        catch {
            return $false
        }
    } $repoRoot ([bool]$ProtectedRepairBootstrap)
    if (-not $protectedExecutionRoot) {
        throw 'Installer execution root is not an exact protected installed Release.'
    }
}

Write-Step "Repo root: $repoRoot"
Write-Step 'Removing Windows download block from release files...'
Unblock-ReleaseFiles -RootPath $repoRoot
$hasBundledExecutable =
    (Test-Path -LiteralPath $publishedExe -PathType Leaf) -and
    (Test-Path -LiteralPath $publishedUpdater -PathType Leaf)
$validBundledRelease = $false
if ((Test-Path -LiteralPath $releaseManifest -PathType Leaf) -and
    $hasBundledExecutable) {
    $validBundledRelease = Test-WgstBundledRelease -PackageRoot $repoRoot
    if (-not $validBundledRelease) {
        throw 'Bundled Release manifest/package validation failed.'
    }
}

$dotnetPath = $null
$sdkCount = 0
$hasSdk = $false
if ($isSourceCheckout) {
    $dotnetPath = Get-DotnetCommand
    $sdkCount = Get-DotnetSdkCount -DotnetPath $dotnetPath
    $hasSdk = $sdkCount -gt 0
}

$installMode = Get-WgstInstallMode `
    -HasManifest $validBundledRelease `
    -HasBundledExecutable $hasBundledExecutable `
    -HasSourceProject $hasSourceProject `
    -HasProps $hasProps `
    -HasSdk $hasSdk `
    -SkipPublish ([bool]$SkipPublish) `
    -ForcePublish ([bool]$ForcePublish)

if ($RepairBlockedUpdate) {
    if (-not $ProtectedInstalledCopy -or
        -not $validBundledRelease) {
        throw (
            'RepairBlockedUpdate requires an exact protected, fully ' +
            'validated bundled Release root.')
    }
    $commonData = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::CommonApplicationData)
    if ([string]::IsNullOrWhiteSpace($commonData)) {
        throw 'The protected application-data directory could not be resolved.'
    }
    $protectedRoot = Join-Path $commonData 'WireguardSplitTunnel'
    [void](Invoke-WgstAuthenticatedBlockedRepair `
        -BundledPackageRoot $repoRoot `
        -ProtectedRoot $protectedRoot)
    Write-Step 'RecoveryBlocked pointer repaired; transaction evidence was preserved.'
    return
}

if ($installMode -eq 'PublishSource' -and -not $hasSdk) {
    throw (
        '.NET 8 SDK was not found at the protected Program Files path. ' +
        'Install it from https://dotnet.microsoft.com/download/dotnet/8.0 ' +
        'and run install.cmd again.')
}

$wireGuardPath = Get-WireGuardCliPath
if ([string]::IsNullOrWhiteSpace($wireGuardPath)) {
    throw (
        'WireGuard for Windows was not found under Program Files. ' +
        'Install it from https://www.wireguard.com/install/ and run ' +
        'install.cmd again.')
}

Write-Step 'Preparing folders...'
$localData = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::LocalApplicationData)
if ([string]::IsNullOrWhiteSpace($localData)) {
    throw 'The per-user application-data directory could not be resolved.'
}
$dataDir = Join-Path $localData 'WireguardSplitTunnel'
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null

if ($installMode -eq 'PublishSource') {
    if ($hasSdk) {
        Write-Step 'Publishing app (Release, win-x64, self-contained)...'
        New-Item -ItemType Directory -Path $publishDir -Force | Out-Null

        & $dotnetPath publish $projectPath `
            -c Release `
            -r win-x64 `
            --self-contained true `
            -p:PublishSingleFile=true `
            -o $publishDir

        if ($LASTEXITCODE -ne 0) {
            throw "dotnet publish failed with exit code $LASTEXITCODE"
        }

        if (-not (Test-Path $publishedExe)) {
            throw 'Publish completed but app exe not found in WireguardSplitTunnel folder.'
        }
    }
    else {
        throw 'PublishSource was selected but no .NET SDK is available.'
    }
}
else {
    Write-Step 'Using the validated bundled Release; source publishing is skipped.'
}

if (-not $NoDesktopShortcut) {
    Write-Step 'Creating desktop shortcuts...'
    $startShortcut = New-DesktopShortcut -Name 'Wireguard Split Tunnel' -TargetPath (Join-Path $repoRoot 'start.cmd') -WorkingDirectory $repoRoot
    $testShortcut = New-DesktopShortcut -Name 'Wireguard Split Tunnel Test' -TargetPath (Join-Path $repoRoot 'test.cmd') -WorkingDirectory $repoRoot
    Write-Step "Shortcut created: $startShortcut"
    Write-Step "Shortcut created: $testShortcut"
}

Write-Step 'Writing install marker...'
$markerPath = Join-Path $repoRoot 'install.status.txt'
$lines = @(
    "InstalledAt=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')",
    'RepoRoot=.',
    'PublishDir=.\\WireguardSplitTunnel',
    'PublishedExe=.\\WireguardSplitTunnel\\WireguardSplitTunnel.App.exe',
    "DotnetDetected=$([string]::IsNullOrWhiteSpace($dotnetPath) -eq $false)",
    "DotnetSdkCount=$sdkCount",
    "WireGuardDetected=$([string]::IsNullOrWhiteSpace($wireGuardPath) -eq $false)",
    'SelfContained=true',
    "Admin=$(Test-IsAdministrator)"
)
Set-Content -Path $markerPath -Value $lines -Encoding UTF8

if ($installMode -eq 'BundledRelease') {
    Write-Step 'Revalidating the exact installed Release security policy...'
    [void](Set-WgstAuthenticatedBundledReleaseAcl `
        -PackageRoot $repoRoot)
    if (-not (Test-WgstBundledRelease -PackageRoot $repoRoot)) {
        throw 'Bundled Release validation failed after ACL revalidation.'
    }
    Write-Step 'Installed Release security policy validated.'
}

Write-Step 'Install completed.'

if (-not $NoPostInstallSelfTest) {
    Write-Step 'Launching app for post-install self test...'
    $startScript = Join-Path $PSScriptRoot 'start.ps1'
    $argList = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', "`"$startScript`"",
        '-PostInstallSelfTest'
    )
    Start-Process `
        -FilePath (Get-WgstSystemPowerShellPath) `
        -ArgumentList $argList
}

Write-Step 'Next: app will show self test dialogs. If blocked by UAC, approve prompt.'


