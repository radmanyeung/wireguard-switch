using System.Diagnostics;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class PrivilegedEntrypointGuardTests : IDisposable
{
    private readonly string repositoryRoot = FindRepositoryRoot();
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "wgst-privileged-entry-tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public void StartPolicy_AllowsProtectedInstallAndExplicitDeveloperSourceOnly()
    {
        var programFiles = Path.Combine(root, "Program Files");
        var protectedRoot = Path.Combine(
            programFiles,
            "WireguardSplitTunnel");
        var developerRoot = Path.Combine(root, "developer");
        var mutableBundle = Path.Combine(
            root,
            "Downloads",
            "wireguard-split-tunnel");
        Directory.CreateDirectory(Path.Combine(
            developerRoot,
            "src",
            "WireguardSplitTunnel.App"));
        File.WriteAllText(
            Path.Combine(developerRoot, "Directory.Build.props"),
            "<Project />");
        File.WriteAllText(
            Path.Combine(
                developerRoot,
                "src",
                "WireguardSplitTunnel.App",
                "WireguardSplitTunnel.App.csproj"),
            "<Project />");
        Directory.CreateDirectory(mutableBundle);
        File.WriteAllText(
            Path.Combine(mutableBundle, "release-manifest.json"),
            "{}");
        Directory.CreateDirectory(Path.Combine(
            mutableBundle,
            "src",
            "WireguardSplitTunnel.App"));
        File.WriteAllText(
            Path.Combine(mutableBundle, "Directory.Build.props"),
            "<Project />");
        File.WriteAllText(
            Path.Combine(
                mutableBundle,
                "src",
                "WireguardSplitTunnel.App",
                "WireguardSplitTunnel.App.csproj"),
            "<Project />");

        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(StartScript)}}' -LibraryOnly
            @(
                Get-WgstLauncherTrust `
                    -RepositoryRoot '{{Escape(protectedRoot)}}' `
                    -ProgramFilesPath '{{Escape(programFiles)}}' `
                    -InstalledReleaseValidator { $true }
                Get-WgstLauncherTrust `
                    -RepositoryRoot '{{Escape(developerRoot)}}' `
                    -ProgramFilesPath '{{Escape(programFiles)}}'
                Get-WgstLauncherTrust `
                    -RepositoryRoot '{{Escape(mutableBundle)}}' `
                    -ProgramFilesPath '{{Escape(programFiles)}}'
            ) | ConvertTo-Json -Compress
            """);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        var policies = JsonSerializer.Deserialize<LauncherTrust[]>(
            result.StandardOutput.Trim(),
            JsonOptions)!;
        policies.Should().Equal(
            new LauncherTrust(true, true, true, "ProtectedInstall"),
            new LauncherTrust(true, false, false, "DeveloperSource"),
            new LauncherTrust(false, false, false, "Unsupported"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void StartGate_UnsupportedBundleInvokesNeitherElevationNorRecovery(
        bool isAdministrator)
    {
        var elevationMarker = Path.Combine(
            root,
            $"elevation-{isAdministrator}.marker");
        var recoveryMarker = Path.Combine(
            root,
            $"recovery-{isAdministrator}.marker");
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(StartScript)}}' -LibraryOnly
            Invoke-WgstStartupGate `
                -DryRun $false `
                -PostInstallSelfTest $false `
                -IsAdministrator {{Ps(isAdministrator)}} `
                -AlreadyElevated {{Ps(isAdministrator)}} `
                -SupportedLauncherRoot $false `
                -ElevationAllowed $false `
                -RecoveryAllowed $false `
                -ElevationAction {
                    [IO.File]::WriteAllText(
                        '{{Escape(elevationMarker)}}',
                        'called')
                } `
                -RecoveryAction {
                    [IO.File]::WriteAllText(
                        '{{Escape(recoveryMarker)}}',
                        'called')
                }
            """);

        result.ExitCode.Should().NotBe(0);
        result.CombinedOutput.Should().Contain(
            "installed protected copy");
        File.Exists(elevationMarker).Should().BeFalse();
        File.Exists(recoveryMarker).Should().BeFalse();
    }

    [Fact]
    public void StartGate_DryRunBypassesPrivilegeAndRecoveryGuards()
    {
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(StartScript)}}' -LibraryOnly
            $result = Invoke-WgstStartupGate `
                -DryRun $true `
                -PostInstallSelfTest $false `
                -IsAdministrator $false `
                -AlreadyElevated $false `
                -SupportedLauncherRoot $false `
                -ElevationAllowed $false `
                -RecoveryAllowed $false `
                -ElevationAction { throw 'must not elevate' } `
                -RecoveryAction { throw 'must not recover' }
            $result | ConvertTo-Json -Compress
            """);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        result.StandardOutput.Should().Contain(
            "\"Action\":\"ContinueNormalLaunch\"");
    }

    [Fact]
    public void StartGate_DeveloperSourceNeverReopensScriptWithRunAs()
    {
        var elevationMarker = Path.Combine(
            root,
            "developer-elevation.marker");
        var recoveryMarker = Path.Combine(
            root,
            "developer-recovery.marker");
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(StartScript)}}' -LibraryOnly
            $result = Invoke-WgstStartupGate `
                -DryRun $false `
                -PostInstallSelfTest $false `
                -IsAdministrator $false `
                -AlreadyElevated $false `
                -SupportedLauncherRoot $true `
                -ElevationAllowed $false `
                -RecoveryAllowed $false `
                -ElevationAction {
                    [IO.File]::WriteAllText(
                        '{{Escape(elevationMarker)}}',
                        'called')
                } `
                -RecoveryAction {
                    [IO.File]::WriteAllText(
                        '{{Escape(recoveryMarker)}}',
                        'called')
                }
            $result | ConvertTo-Json -Compress
            """);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        result.StandardOutput.Should().Contain(
            "\"Action\":\"ContinueNormalLaunch\"");
        File.Exists(elevationMarker).Should().BeFalse();
        File.Exists(recoveryMarker).Should().BeFalse();
    }

    [Fact]
    public void StartMissingAppFallback_ProtectedInstallInvokesNeitherHook()
    {
        var ensureMarker = Path.Combine(
            root,
            "hostile-ensure.marker");
        var dotnetMarker = Path.Combine(
            root,
            "hostile-dotnet.marker");
        var source = File.ReadAllText(StartScript);
        var helperDefinition = source.IndexOf(
            "function Invoke-WgstMissingAppFallback",
            StringComparison.Ordinal);
        var productionCall = source.LastIndexOf(
            "Invoke-WgstMissingAppFallback",
            StringComparison.Ordinal);
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(StartScript)}}' -LibraryOnly
            Invoke-WgstMissingAppFallback `
                -LauncherKind 'ProtectedInstall' `
                -IsAdministrator $true `
                -EnsurePrebuiltAction {
                    [IO.File]::WriteAllText(
                        '{{Escape(ensureMarker)}}',
                        'called')
                    return 'hostile.exe'
                } `
                -DotnetFallbackAction {
                    [IO.File]::WriteAllText(
                        '{{Escape(dotnetMarker)}}',
                        'called')
                }
            """);

        helperDefinition.Should().BeGreaterThanOrEqualTo(0);
        productionCall.Should().BeGreaterThan(helperDefinition);
        result.ExitCode.Should().NotBe(0);
        result.CombinedOutput.Should().MatchRegex(
            "(?i)repair|reinstall");
        File.Exists(ensureMarker).Should().BeFalse();
        File.Exists(dotnetMarker).Should().BeFalse();
    }

    [Fact]
    public void StartElevation_DoesNotForwardCallerSelectedLogPath()
    {
        var source = File.ReadAllText(StartScript);

        var elevatedGuard = source.IndexOf(
            "if ($Elevated)",
            StringComparison.Ordinal);
        var callerPathClear = source.IndexOf(
            "$LauncherLogPath = $null",
            elevatedGuard,
            StringComparison.Ordinal);
        var logger = source.IndexOf(
            "function Write-LauncherLog",
            StringComparison.Ordinal);
        elevatedGuard.Should().BeGreaterThanOrEqualTo(0);
        callerPathClear.Should().BeGreaterThan(elevatedGuard);
        callerPathClear.Should().BeLessThan(logger);
        source.Should().NotContain(
            "$argList += '-LauncherLogPath'");
        source.Should().NotContain(
            "$argList += \"`\"$LauncherLogPath`\"\"");
        source.Should().Contain(
            "[Environment+SpecialFolder]::System");
        source.Should().NotContain(
            "-FilePath 'powershell'");
    }

    [Fact]
    public void StartLogging_ElevatedCallerCannotChooseAWritePath()
    {
        var marker = Path.Combine(
            root,
            "elevated-caller.log");
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(StartScript)}}' `
                -LibraryOnly `
                -LauncherLogPath '{{Escape(marker)}}'
            function Test-IsAdministrator { return $true }
            Write-LauncherLog 'must-not-write'
            """);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        File.Exists(marker).Should().BeFalse();
    }

    [Fact]
    public void UpdateLauncher_NormalModeGuardsBeforeProtectedRecovery()
    {
        var source = ReadRepositoryFile(
            "scripts/update-launcher.ps1");
        var normalMode = source.LastIndexOf(
            "if (-not $LibraryOnly)",
            StringComparison.Ordinal);
        var guard = source.IndexOf(
            "Assert-WgstUpdateLauncherRoot",
            normalMode,
            StringComparison.Ordinal);
        var recovery = source.IndexOf(
            "Invoke-WgstProtectedUpdateRecoveryCore",
            guard,
            StringComparison.Ordinal);

        normalMode.Should().BeGreaterThanOrEqualTo(0);
        guard.Should().BeGreaterThan(normalMode);
        recovery.Should().BeGreaterThan(guard);
        source[..normalMode].Should().Contain(
            "function Assert-WgstUpdateLauncherRoot");
    }

    [Theory]
    [InlineData("scripts/fix-dns.ps1")]
    [InlineData("scripts/reset-network.ps1")]
    public void NetworkRepairScripts_RequestUacOnlyFromProtectedInstall(
        string relativePath)
    {
        var scriptPath = ReadRepositoryPath(relativePath);
        var source = File.ReadAllText(scriptPath);
        var main = source.IndexOf(
            "if ($LibraryOnly)",
            StringComparison.Ordinal);
        var guard = source.IndexOf(
            "Assert-WgstProtectedElevationRoot",
            main,
            StringComparison.Ordinal);
        var adminBranch = source.LastIndexOf(
            "if (-not (Test-IsAdministrator))",
            StringComparison.Ordinal);
        var runAs = source.LastIndexOf(
            "Start-Process",
            StringComparison.Ordinal);

        source.Should().Contain("[switch]$LibraryOnly");
        main.Should().BeGreaterThanOrEqualTo(0);
        guard.Should().BeGreaterThan(main);
        adminBranch.Should().BeGreaterThan(guard);
        runAs.Should().BeGreaterThan(adminBranch);
        source.Should().Contain(
            "[Environment+SpecialFolder]::System");
        source.Should().Contain("ReparsePoint");
        source.Should().NotContain(
            "-FilePath 'powershell'");

        var programFiles = Path.Combine(root, "Program Files");
        var protectedRoot = Path.Combine(
            programFiles,
            "WireguardSplitTunnel");
        var downloadsRoot = Path.Combine(
            root,
            "Downloads",
            "WireguardSplitTunnel");
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(scriptPath)}}' -LibraryOnly
            @(
                Test-WgstExactProtectedScriptRoot `
                    -RepositoryRoot '{{Escape(protectedRoot)}}' `
                    -ProgramFilesPath '{{Escape(programFiles)}}'
                Test-WgstExactProtectedScriptRoot `
                    -RepositoryRoot '{{Escape(downloadsRoot)}}' `
                    -ProgramFilesPath '{{Escape(programFiles)}}'
            ) | ConvertTo-Json -Compress
            """);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        result.StandardOutput.Trim().Should().Be("[true,false]");
    }

    [Theory]
    [InlineData("scripts/fix-dns.ps1")]
    [InlineData("scripts/reset-network.ps1")]
    public void NetworkRepairScripts_AlreadyElevatedMutableRootIsRejected(
        string relativePath)
    {
        var scriptPath = ReadRepositoryPath(relativePath);
        var programFiles = Path.Combine(root, "Program Files");
        var downloadsRoot = Path.Combine(
            root,
            "Downloads",
            "WireguardSplitTunnel");
        var mutableScript = Path.Combine(
            downloadsRoot,
            "scripts",
            Path.GetFileName(relativePath));
        Directory.CreateDirectory(Path.GetDirectoryName(mutableScript)!);
        File.WriteAllText(mutableScript, "# mutable test script");

        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(scriptPath)}}' -LibraryOnly
            Assert-WgstProtectedElevationRoot `
                -RepositoryRoot '{{Escape(downloadsRoot)}}' `
                -ProgramFilesPath '{{Escape(programFiles)}}' `
                -ScriptPath '{{Escape(mutableScript)}}'
            """);

        result.ExitCode.Should().NotBe(0);
        result.CombinedOutput.Should().Contain("fixed Program Files");
    }

    [Theory]
    [InlineData("scripts/fix-dns.ps1")]
    [InlineData("scripts/reset-network.ps1")]
    public void NetworkRepairScripts_UseOnlyProtectedSystemCommandsAndModules(
        string relativePath)
    {
        var source = ReadRepositoryFile(relativePath);

        source.Should().Contain(@"WindowsPowerShell\v1.0\Modules");
        if (relativePath.EndsWith(
                "fix-dns.ps1",
                StringComparison.Ordinal))
        {
            source.Should().Contain("NetAdapter\\Get-NetAdapter");
            source.Should().Contain("DnsClient\\Resolve-DnsName");
            source.Should().Contain(
                "DnsClient\\Set-DnsClientServerAddress");
            source.Should().Contain(
                "DnsClient\\Get-DnsClientServerAddress");
            source.Should().Contain("& $ipconfigPath");
            source.Should().Contain("$LASTEXITCODE");
            source.Should().NotMatchRegex(
                @"(?m)^\s*Get-NetAdapter\b");
            source.Should().NotMatchRegex(
                @"(?m)^\s*Resolve-DnsName\b");
            source.Should().NotMatchRegex(@"(?m)^\s*netsh\b");
            source.Should().NotMatchRegex(@"(?m)^\s*ipconfig\b");
        }
        else
        {
            source.Should().Contain(
                "NetSecurity\\Get-NetFirewallRule");
            source.Should().Contain(
                "NetSecurity\\Remove-NetFirewallRule");
            source.Should().Contain("& $routePath");
            source.Should().NotMatchRegex(
                @"(?m)^\s*Get-NetFirewallRule\b");
            source.Should().NotMatchRegex(
                @"(?m)^\s*Remove-NetFirewallRule\b");
            source.Should().NotMatchRegex(@"(?m)^\s*route\b");
        }
    }

    [Theory]
    [InlineData("scripts/start.ps1")]
    [InlineData("scripts/update-launcher.ps1")]
    [InlineData("scripts/fix-dns.ps1")]
    [InlineData("scripts/reset-network.ps1")]
    public void PrivilegedScripts_SanitizeInheritedPowerShellModulePath(
        string relativePath)
    {
        var scriptPath = ReadRepositoryPath(relativePath);
        var maliciousModules = Path.Combine(
            root,
            "malicious-modules");
        var maliciousModule = Path.Combine(
            maliciousModules,
            "Microsoft.PowerShell.Management");
        var marker = Path.Combine(root, "malicious-module.marker");
        Directory.CreateDirectory(maliciousModule);
        File.WriteAllText(
            Path.Combine(
                maliciousModule,
                "Microsoft.PowerShell.Management.psd1"),
            "@{ RootModule = 'Microsoft.PowerShell.Management.psm1'; "
            + "ModuleVersion = '1.0.0.0'; "
            + "GUID = '11111111-1111-1111-1111-111111111111' }");
        File.WriteAllText(
            Path.Combine(
                maliciousModule,
                "Microsoft.PowerShell.Management.psm1"),
            $"[IO.File]::WriteAllText('{Escape(marker)}', 'loaded')");

        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            $env:PSModulePath = '{{Escape(maliciousModules)}}'
            . '{{Escape(scriptPath)}}' -LibraryOnly
            Initialize-WgstProtectedPowerShellEnvironment
            [pscustomobject]@{
                ModulePath = $env:PSModulePath
                AutoLoading = [string]$global:PSModuleAutoLoadingPreference
                MarkerExists = [IO.File]::Exists('{{Escape(marker)}}')
            } | ConvertTo-Json -Compress
            """);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        var observed = JsonSerializer.Deserialize<PowerShellEnvironment>(
            result.StandardOutput.Trim(),
            JsonOptions)!;
        var expectedModules = Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.System),
            "WindowsPowerShell",
            "v1.0",
            "Modules");
        Path.GetFullPath(observed.ModulePath).Should().BeEquivalentTo(
            Path.GetFullPath(expectedModules));
        observed.AutoLoading.Should().Be("None");
        observed.MarkerExists.Should().BeFalse();
    }

    [Theory]
    [InlineData("scripts/start.ps1")]
    [InlineData("scripts/update-launcher.ps1")]
    [InlineData("scripts/fix-dns.ps1")]
    [InlineData("scripts/reset-network.ps1")]
    public void PrivilegedScriptGuards_RejectNonexistentWeakAndReparseRoots(
        string relativePath)
    {
        var programFiles = Path.Combine(root, "Program Files");
        var installedRoot = Path.Combine(
            programFiles,
            "WireguardSplitTunnel");

        ProbeInstalledGuard(
            relativePath,
            programFiles,
            installedRoot).Should().BeFalse();

        CreateWeakInstalledLayout(installedRoot, relativePath);
        ProbeInstalledGuard(
            relativePath,
            programFiles,
            installedRoot).Should().BeFalse();

        Directory.Delete(installedRoot, recursive: true);
        var junctionTarget = Path.Combine(root, "junction-target");
        CreateWeakInstalledLayout(junctionTarget, relativePath);
        CreateJunction(installedRoot, junctionTarget);
        (File.GetAttributes(installedRoot)
            & FileAttributes.ReparsePoint).Should().NotBe(0);
        ProbeInstalledGuard(
            relativePath,
            programFiles,
            installedRoot).Should().BeFalse();
        Directory.Delete(installedRoot);
    }

    [Fact]
    public void InstalledReleaseValidation_AuthenticatesEveryManagedPayloadAndAuthority()
    {
        using var fixture = new ReleaseScriptFixture();
        File.Copy(
            ReadRepositoryPath("scripts/WindowsRelease.psm1"),
            Path.Combine(
                fixture.RepositoryRoot,
                "scripts",
                "WindowsRelease.psm1"),
            overwrite: true);
        var packaged = fixture.Package();
        packaged.ExitCode.Should().Be(0, packaged.CombinedOutput);

        var programFiles = Path.Combine(
            fixture.Root,
            "Program Files");
        var installedRoot = Path.Combine(
            programFiles,
            "WireguardSplitTunnel");
        Directory.CreateDirectory(programFiles);
        Directory.Move(fixture.PackageRoot, installedRoot);
        var weakScript = Path.Combine(
            installedRoot,
            "scripts",
            "update-launcher.ps1");
        var preservedCustomExecutable = Path.Combine(
            installedRoot,
            "src",
            "WireguardSplitTunnel.App",
            "bin",
            "Release",
            "net8.0-windows",
            "WireguardSplitTunnel.App.exe");
        Directory.CreateDirectory(
            Path.GetDirectoryName(preservedCustomExecutable)!);
        File.Copy(
            Path.Combine(
                installedRoot,
                UpdateReleaseContract.WindowsApplicationPath.Replace(
                    '/',
                    Path.DirectorySeparatorChar)),
            preservedCustomExecutable);

        var policy = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(StartScript)}}' -LibraryOnly
            Initialize-WgstProtectedPowerShellEnvironment
            [pscustomobject]@{
                Valid = Test-WgstInstalledReleaseScriptRoot `
                    -RepositoryRoot '{{Escape(installedRoot)}}' `
                    -ProgramFilesPath '{{Escape(programFiles)}}' `
                    -ScriptRelativePath 'scripts\start.ps1' `
                    -ParentAuthorityValidator { $true } `
                    -AclValidator { $true }
                WeakScript = Test-WgstInstalledReleaseScriptRoot `
                    -RepositoryRoot '{{Escape(installedRoot)}}' `
                    -ProgramFilesPath '{{Escape(programFiles)}}' `
                    -ScriptRelativePath 'scripts\start.ps1' `
                    -ParentAuthorityValidator { $true } `
                    -AclValidator {
                        param($Path, $Directory, $Root)
                        $Path -ine '{{Escape(weakScript)}}'
                    }
                WeakParent = Test-WgstInstalledReleaseScriptRoot `
                    -RepositoryRoot '{{Escape(installedRoot)}}' `
                    -ProgramFilesPath '{{Escape(programFiles)}}' `
                    -ScriptRelativePath 'scripts\start.ps1' `
                    -AclValidator { $true }
            } | ConvertTo-Json -Compress
            """);

        policy.ExitCode.Should().Be(0, policy.CombinedOutput);
        var observed = JsonSerializer.Deserialize<InstalledReleasePolicy>(
            policy.StandardOutput.Trim(),
            JsonOptions)!;
        observed.Valid.Should().BeTrue();
        observed.WeakScript.Should().BeFalse();
        observed.WeakParent.Should().BeFalse();

        foreach (var privilegedScript in new[]
                 {
                     "scripts/update-launcher.ps1",
                     "scripts/fix-dns.ps1",
                     "scripts/reset-network.ps1"
                 })
        {
            var parity = RunInlinePowerShell($$"""
                $ErrorActionPreference = 'Stop'
                . '{{Escape(ReadRepositoryPath(privilegedScript))}}' -LibraryOnly
                Initialize-WgstProtectedPowerShellEnvironment
                Test-WgstInstalledReleaseScriptRoot `
                    -RepositoryRoot '{{Escape(installedRoot)}}' `
                    -ProgramFilesPath '{{Escape(programFiles)}}' `
                    -ScriptRelativePath '{{privilegedScript.Replace('/', '\\')}}' `
                    -ParentAuthorityValidator { $true } `
                    -AclValidator { $true }
                """);
            parity.ExitCode.Should().Be(0, parity.CombinedOutput);
            parity.StandardOutput.Trim().Should().Be(
                "True",
                $"{privilegedScript} must share locator-quality validation");
        }

        File.AppendAllText(weakScript, "# corrupt payload\r\n");
        var corrupt = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(StartScript)}}' -LibraryOnly
            Initialize-WgstProtectedPowerShellEnvironment
            Test-WgstInstalledReleaseScriptRoot `
                -RepositoryRoot '{{Escape(installedRoot)}}' `
                -ProgramFilesPath '{{Escape(programFiles)}}' `
                -ScriptRelativePath 'scripts\start.ps1' `
                -ParentAuthorityValidator { $true } `
                -AclValidator { $true }
            """);

        corrupt.ExitCode.Should().Be(0, corrupt.CombinedOutput);
        corrupt.StandardOutput.Trim().Should().Be("False");
    }

    [Fact]
    public void ProtectedInstallResolver_NeverSelectsCustomDeveloperBinExecutable()
    {
        var installedRoot = Path.Combine(root, "installed");
        var custom = Path.Combine(
            installedRoot,
            "src",
            "WireguardSplitTunnel.App",
            "bin",
            "Release",
            "net8.0-windows",
            "WireguardSplitTunnel.App.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(custom)!);
        File.WriteAllBytes(custom, [0x4d, 0x5a]);

        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(StartScript)}}' -LibraryOnly
            [pscustomobject]@{
                Protected = [string](Resolve-WgstAppExecutable `
                    -RepoRoot '{{Escape(installedRoot)}}' `
                    -LauncherKind 'ProtectedInstall')
                Developer = [string](Resolve-WgstAppExecutable `
                    -RepoRoot '{{Escape(installedRoot)}}' `
                    -LauncherKind 'DeveloperSource')
            } | ConvertTo-Json -Compress
            """);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        var observed = JsonSerializer.Deserialize<ResolverPolicy>(
            result.StandardOutput.Trim(),
            JsonOptions)!;
        observed.Protected.Should().BeNullOrEmpty();
        Path.GetFullPath(observed.Developer).Should().BeEquivalentTo(
            Path.GetFullPath(custom));
    }

    [Fact]
    public void ProtectedInstall_RevalidatesAfterRecoveryBeforeAppLaunch()
    {
        var source = File.ReadAllText(StartScript);
        var recoveryResult = source.IndexOf(
            "if ($startupGate.Action -eq 'Recovery')",
            StringComparison.Ordinal);
        var finalAppLaunch = source.LastIndexOf(
            "Start-Process -FilePath $appExe",
            StringComparison.Ordinal);
        var finalTrust = source.LastIndexOf(
            "Get-WgstLauncherTrust",
            finalAppLaunch,
            StringComparison.Ordinal);

        recoveryResult.Should().BeGreaterThanOrEqualTo(0);
        finalAppLaunch.Should().BeGreaterThan(recoveryResult);
        finalTrust.Should().BeGreaterThan(recoveryResult);
        finalTrust.Should().BeLessThan(finalAppLaunch);
    }

    [Theory]
    [InlineData("scripts/start.ps1")]
    [InlineData("scripts/update-launcher.ps1")]
    [InlineData("scripts/fix-dns.ps1")]
    [InlineData("scripts/reset-network.ps1")]
    public void InstalledReleaseGuards_UseAuthenticatedManifestAndExactTreeAcl(
        string relativePath)
    {
        var source = ReadRepositoryFile(relativePath);

        source.Should().Contain(
            "Test-WgstProtectedInstallParentAuthority");
        source.Should().Contain(
            "Get-WgstAuthenticatedBundledReleaseAclPlan");
        source.Should().Contain("-AllowInstalledExtras");
        source.Should().Contain("$plan.Directories");
        source.Should().Contain("$plan.Files");
        source.Should().Contain("scripts/update-launcher.ps1");
        source.Should().Contain("scripts/WindowsRelease.psm1");
        source.Should().Contain(
            "WireguardSplitTunnel/WireguardSplitTunnel.App.exe");
        source.Should().Contain("$revalidatedPlan");
    }

    [Theory]
    [InlineData("scripts/start.ps1", "Get-WgstLauncherTrust")]
    [InlineData("scripts/fix-dns.ps1", "Assert-WgstProtectedElevationRoot")]
    [InlineData("scripts/reset-network.ps1", "Assert-WgstProtectedElevationRoot")]
    public void RunAsPaths_RevalidateInstalledReleaseImmediatelyBeforeUac(
        string relativePath,
        string guardName)
    {
        var source = ReadRepositoryFile(relativePath);
        var runAsVerb = source.LastIndexOf(
            "-Verb RunAs",
            StringComparison.Ordinal);
        var runAs = source.LastIndexOf(
            "Start-Process",
            runAsVerb,
            StringComparison.Ordinal);
        var revalidation = source.LastIndexOf(
            guardName,
            runAs,
            StringComparison.Ordinal);

        runAsVerb.Should().BeGreaterThanOrEqualTo(0);
        runAs.Should().BeGreaterThanOrEqualTo(0);
        revalidation.Should().BeGreaterThanOrEqualTo(0);
        revalidation.Should().BeLessThan(runAs);
        source[revalidation..runAs].Should().Contain(
            "Initialize-WgstProtectedPowerShellEnvironment");
    }

    [Fact]
    public void FixDns_TransportsOnlyGuidThroughOneBoundPayload()
    {
        var scriptPath = ReadRepositoryPath("scripts/fix-dns.ps1");
        var interfaceGuid = Guid.NewGuid();
        var encoded = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(scriptPath)}}' -LibraryOnly
            ConvertTo-WgstDnsRepairPayload `
                -InterfaceGuid '{{interfaceGuid:D}}'
            """);
        encoded.ExitCode.Should().Be(0, encoded.CombinedOutput);
        var payload = encoded.StandardOutput.Trim();

        var bound = RunInlinePowerShell(
            $$"""
            param([string]$DnsRepairPayload)
            $ErrorActionPreference = 'Stop'
            $boundPayload = $DnsRepairPayload
            . '{{Escape(scriptPath)}}' -LibraryOnly
            ConvertFrom-WgstDnsRepairPayload `
                -Payload $boundPayload |
                ConvertTo-Json -Compress
            """,
            "-DnsRepairPayload",
            payload);

        bound.ExitCode.Should().Be(0, bound.CombinedOutput);
        using var document = JsonDocument.Parse(
            bound.StandardOutput.Trim());
        document.RootElement.GetProperty("InterfaceGuid")
            .GetString().Should().Be(interfaceGuid.ToString("D"));
        document.RootElement.TryGetProperty(
            "InterfaceIndex",
            out _).Should().BeFalse();
        document.RootElement.TryGetProperty(
            "DnsServers",
            out _).Should().BeFalse();

        var source = File.ReadAllText(scriptPath);
        source.Should().Contain("'-DnsRepairPayload'");
        source.Should().NotContain("'-AdapterName'");
        source.Should().NotContain("@('-DnsServers',");
    }

    [Fact]
    public void ResetNetwork_StateReaderIsBoundedStrictAndCanonicalIpv4Only()
    {
        var scriptPath = ReadRepositoryPath(
            "scripts/reset-network.ps1");
        var valid = Path.Combine(root, "valid-state.json");
        Directory.CreateDirectory(root);
        File.WriteAllText(
            valid,
            "{\"ManagedRouteSnapshot\":["
            + "{\"Domain\":\"a.example\",\"IpAddress\":\"198.51.100.7\"},"
            + "{\"Domain\":\"b.example\",\"IpAddress\":\"203.0.113.8\","
            + "\"InterfaceName\":\"SG\"}]}");
        var invalidPaths = new[]
        {
            WriteState(
                "injected-state.json",
                "{\"ManagedRouteSnapshot\":[{\"Domain\":\"a.example\","
                + "\"IpAddress\":\"198.51.100.7 & whoami\"}]}"),
            WriteState(
                "noncanonical-state.json",
                "{\"ManagedRouteSnapshot\":[{\"Domain\":\"a.example\","
                + "\"IpAddress\":\"127.1\"}]}"),
            WriteState(
                "ipv6-state.json",
                "{\"ManagedRouteSnapshot\":[{\"Domain\":\"a.example\","
                + "\"IpAddress\":\"2001:db8::1\"}]}"),
            WriteState(
                "extra-shape-state.json",
                "{\"ManagedRouteSnapshot\":[{\"Domain\":\"a.example\","
                + "\"IpAddress\":\"198.51.100.7\",\"Command\":\"whoami\"}]}"),
            WriteState(
                "oversized-state.json",
                new string(' ', 8 * 1024 * 1024 + 1))
        };

        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(scriptPath)}}' -LibraryOnly
            $valid = @(Read-WgstManagedRouteSnapshot `
                -Path '{{Escape(valid)}}')
            $rejected = 0
            foreach ($path in @(
                {{string.Join(",\n", invalidPaths.Select(path => $"'{Escape(path)}'"))}}
            )) {
                try {
                    Read-WgstManagedRouteSnapshot -Path $path | Out-Null
                }
                catch {
                    $rejected++
                }
            }
            [pscustomobject]@{
                Valid = @($valid)
                Rejected = $rejected
            } | ConvertTo-Json -Compress
            """);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        var observed = JsonSerializer.Deserialize<StateReaderResult>(
            result.StandardOutput.Trim(),
            JsonOptions)!;
        observed.Valid.Should().Equal(
            "198.51.100.7",
            "203.0.113.8");
        observed.Rejected.Should().Be(invalidPaths.Length);

        var source = File.ReadAllText(scriptPath);
        source.Should().NotContain(
            "Join-Path `\r\n    $repositoryRoot `\r\n    'WireguardSplitTunnel\\state.json'");
    }

    [Fact]
    public void AppBootstrapLogging_NeverWritesElevatedOrToCurrentDirectory()
    {
        var source = ReadRepositoryFile(
            "src/WireguardSplitTunnel.App/App.xaml.cs");

        source.Should().Contain(
            "AppBootstrapLoggingPolicy.ShouldWrite(IsRunningAsAdministrator())");
        source.Should().Contain("if (!AppBootstrapLoggingPolicy.ShouldWrite");
        source.Should().NotContain("Environment.CurrentDirectory");
    }

    [Fact]
    public void ResetNetwork_UsesKnownFolderLocalAppData()
    {
        var source = ReadRepositoryFile(
            "scripts/reset-network.ps1");

        source.Should().Contain(
            "[Environment+SpecialFolder]::LocalApplicationData");
        source.Should().NotContain("$env:LOCALAPPDATA");
    }

    [Fact]
    public void StartAdmin_EntersTheGuardedNonElevatedLauncher()
    {
        var source = ReadRepositoryFile("start-admin.cmd");

        source.Should().Contain(
            @"-File ""%SCRIPT_DIR%scripts\start.ps1""");
        var normalized = source.ToLowerInvariant();
        normalized.Should().NotContain("start-process");
        normalized.Should().NotContain("runas");
        normalized.Should().NotContain("launcherlogpath");
        normalized.Should().NotContain("-elevated");
    }

    [Theory]
    [InlineData("start.cmd")]
    [InlineData("start-safe.cmd")]
    [InlineData("fix-dns.cmd")]
    [InlineData("reset-network.cmd")]
    public void PackagedLaunchWrappers_UseOnlyFixedWindowsPowerShell(
        string relativePath)
    {
        var source = ReadRepositoryFile(relativePath);
        var normalized = source.ToLowerInvariant();
        var protectedHost = normalized.IndexOf(
            @"%systemroot%\system32\windowspowershell\v1.0\powershell.exe",
            StringComparison.Ordinal);
        var missingGuard = normalized.IndexOf(
            "if not exist",
            protectedHost < 0 ? 0 : protectedHost,
            StringComparison.Ordinal);
        var failClosed = normalized.IndexOf(
            "exit /b 1",
            missingGuard < 0 ? 0 : missingGuard,
            StringComparison.Ordinal);
        var invocation = normalized.LastIndexOf(
            "-noprofile",
            StringComparison.Ordinal);

        protectedHost.Should().BeGreaterThanOrEqualTo(0);
        missingGuard.Should().BeGreaterThan(protectedHost);
        failClosed.Should().BeGreaterThan(missingGuard);
        invocation.Should().BeGreaterThan(failClosed);
        normalized.Should().NotMatchRegex(
            "(?im)set\\s+\"[^\"]*=powershell(?:\\.exe)?\"");
        normalized.Should().NotMatchRegex(
            "(?im)^\\s*powershell(?:\\.exe)?(?:\\s|$)");
    }

    [Fact]
    public void AppAutoElevation_RequiresValidatedProtectedInstallOnly()
    {
        var source = ReadRepositoryFile(
            "src/WireguardSplitTunnel.App/App.xaml.cs");
        source.Should().Contain("location.InstallationRoot");
        source.Should().Contain(
            "Environment.SpecialFolder.ProgramFiles");
        source.Should().Contain(
            "AppAutoElevationPolicy");
        source.Should().Contain(
            "IsExecutableEligibleForAutoElevation(");
        source.Should().NotContain(
            "IsDeveloperBuildExecutable");
        source.Should().NotContain(
            "Directory.Build.props");
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void AppAutoElevation_InjectedRunAsStarterUsesPinnedPathAndLeaseUntilCompletion(
        bool throwFromStarter,
        bool expectedResult)
    {
        var applicationPath =
            @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel\WireguardSplitTunnel.App.exe";
        var resource = new RecordingDisposable();
        using var lease = new InstalledReleaseLaunchLease(
            applicationPath,
            resource,
            () => !resource.Disposed);
        ProcessStartInfo? observedStartInfo = null;
        var leaseWasLiveInsideStarter = false;

        Process? Starter(ProcessStartInfo startInfo)
        {
            observedStartInfo = startInfo;
            leaseWasLiveInsideStarter =
                lease.Revalidate()
                && !resource.Disposed;
            if (throwFromStarter)
            {
                throw new InvalidOperationException(
                    "Injected starter failure.");
            }

            return null;
        }

        var result = InvokeAppAutoElevationRelaunch(
            ["--example"],
            lease,
            Starter);

        result.Should().Be(expectedResult);
        leaseWasLiveInsideStarter.Should().BeTrue();
        observedStartInfo.Should().NotBeNull();
        observedStartInfo!.FileName.Should().Be(applicationPath);
        observedStartInfo.WorkingDirectory.Should().Be(
            Path.GetDirectoryName(applicationPath));
        observedStartInfo.UseShellExecute.Should().BeTrue();
        observedStartInfo.Verb.Should().Be("runas");
        resource.Disposed.Should().BeTrue();
    }

    [Fact]
    public void AppAutoElevation_PlantedDeveloperLayoutIsRejectedByHelper()
    {
        var plantedRoot = Path.Combine(
            root,
            "Downloads",
            "planted-developer");
        var plantedOutput = Path.Combine(
            plantedRoot,
            "src",
            "WireguardSplitTunnel.App",
            "bin",
            "Release",
            "net8.0-windows");
        Directory.CreateDirectory(plantedOutput);
        File.WriteAllText(
            Path.Combine(plantedRoot, "Directory.Build.props"),
            "<Project />");
        File.WriteAllText(
            Path.Combine(
                plantedRoot,
                "src",
                "WireguardSplitTunnel.App",
                "WireguardSplitTunnel.App.csproj"),
            "<Project />");
        var plantedExecutable = Path.Combine(
            plantedOutput,
            "WireguardSplitTunnel.App.exe");
        File.WriteAllBytes(plantedExecutable, [0x4d, 0x5a]);

        var appAssemblyPath = BuildAppForReflection();
        var outputDirectory = Path.GetDirectoryName(appAssemblyPath)!;
        var context = System.Runtime.Loader.AssemblyLoadContext.Default;
        System.Reflection.Assembly? Resolver(
            System.Runtime.Loader.AssemblyLoadContext loadContext,
            System.Reflection.AssemblyName name)
        {
            var candidate = Path.Combine(
                outputDirectory,
                $"{name.Name}.dll");
            if (!File.Exists(candidate))
            {
                return null;
            }

            using var dependency = new MemoryStream(
                File.ReadAllBytes(candidate));
            return loadContext.LoadFromStream(dependency);
        }

        context.Resolving += Resolver;
        try
        {
            using var appBytes = new MemoryStream(
                File.ReadAllBytes(appAssemblyPath));
            var appAssembly = context.LoadFromStream(appBytes);
            var policyType = appAssembly.GetType(
                "WireguardSplitTunnel.App.AppAutoElevationPolicy",
                throwOnError: true)!;
            var helper = policyType.GetMethod(
                "IsExecutableEligibleForAutoElevation",
                System.Reflection.BindingFlags.Static
                    | System.Reflection.BindingFlags.NonPublic);

            helper.Should().NotBeNull();
            var eligible = (bool)helper!.Invoke(
                null,
                [plantedExecutable])!;
            eligible.Should().BeFalse();

            var loggingPolicyType = appAssembly.GetType(
                "WireguardSplitTunnel.App.AppBootstrapLoggingPolicy",
                throwOnError: true)!;
            var shouldWrite = loggingPolicyType.GetMethod(
                "ShouldWrite",
                System.Reflection.BindingFlags.Static
                    | System.Reflection.BindingFlags.NonPublic);
            shouldWrite.Should().NotBeNull();
            ((bool)shouldWrite!.Invoke(null, [true])!).Should().BeFalse();
            ((bool)shouldWrite.Invoke(null, [false])!).Should().BeTrue();
        }
        finally
        {
            context.Resolving -= Resolver;
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private string StartScript =>
        ReadRepositoryPath("scripts/start.ps1");

    private ScriptProcessResult RunInlinePowerShell(
        string source,
        params string[] arguments)
    {
        Directory.CreateDirectory(root);
        var path = Path.Combine(
            root,
            $"inline-{Guid.NewGuid():N}.ps1");
        File.WriteAllText(
            path,
            source,
            new UTF8Encoding(false));
        return ReleaseScriptFixture.RunPowerShell(path, arguments);
    }

    private bool ProbeInstalledGuard(
        string relativePath,
        string programFiles,
        string installedRoot)
    {
        var scriptPath = ReadRepositoryPath(relativePath);
        var installedScript = Path.Combine(
            installedRoot,
            relativePath.Replace('/', Path.DirectorySeparatorChar));
        var probe = relativePath switch
        {
            "scripts/start.ps1" => $$"""
                $policy = Get-WgstLauncherTrust `
                    -RepositoryRoot '{{Escape(installedRoot)}}' `
                    -ProgramFilesPath '{{Escape(programFiles)}}'
                [bool]$policy.ElevationAllowed
                """,
            "scripts/update-launcher.ps1" => $$"""
                Assert-WgstUpdateLauncherRoot `
                    -RepositoryRoot '{{Escape(installedRoot)}}' `
                    -ProgramFilesPath '{{Escape(programFiles)}}'
                $true
                """,
            _ => $$"""
                Assert-WgstProtectedElevationRoot `
                    -RepositoryRoot '{{Escape(installedRoot)}}' `
                    -ProgramFilesPath '{{Escape(programFiles)}}' `
                    -ScriptPath '{{Escape(installedScript)}}'
                $true
                """
        };
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(scriptPath)}}' -LibraryOnly
            try {
                $accepted = & {
                    {{probe}}
                }
                if ([bool]$accepted) { 'accepted' } else { 'rejected' }
            }
            catch {
                'rejected'
            }
            """);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        return result.StandardOutput.Trim() == "accepted";
    }

    private void CreateWeakInstalledLayout(
        string installedRoot,
        string relativePath)
    {
        var paths = new[]
        {
            relativePath,
            "release-manifest.json",
            "start.cmd",
            "scripts/start.ps1",
            "scripts/update-launcher.ps1",
            "scripts/fix-dns.ps1",
            "scripts/reset-network.ps1",
            "WireguardSplitTunnel/WireguardSplitTunnel.App.exe",
            "WireguardSplitTunnel/WireguardSplitTunnel.Updater.exe"
        };
        foreach (var path in paths.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var fullPath = Path.Combine(
                installedRoot,
                path.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
            File.WriteAllText(fullPath, "weak test file");
        }
    }

    private static void CreateJunction(
        string junctionPath,
        string targetPath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(junctionPath)!);
        var start = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "cmd.exe",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        start.ArgumentList.Add("/d");
        start.ArgumentList.Add("/c");
        start.ArgumentList.Add("mklink");
        start.ArgumentList.Add("/J");
        start.ArgumentList.Add(junctionPath);
        start.ArgumentList.Add(targetPath);
        using var process = System.Diagnostics.Process.Start(start);
        process.Should().NotBeNull();
        var output = process!.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit(10_000).Should().BeTrue();
        process.ExitCode.Should().Be(0, output + Environment.NewLine + error);
    }

    private string WriteState(string fileName, string content)
    {
        var path = Path.Combine(root, fileName);
        Directory.CreateDirectory(root);
        File.WriteAllText(path, content, new UTF8Encoding(false));
        return path;
    }

    private string ReadRepositoryPath(string relativePath) =>
        Path.Combine(
            repositoryRoot,
            relativePath.Replace(
                '/',
                Path.DirectorySeparatorChar));

    private string ReadRepositoryFile(string relativePath) =>
        File.ReadAllText(ReadRepositoryPath(relativePath));

    private bool InvokeAppAutoElevationRelaunch(
        string[] arguments,
        InstalledReleaseLaunchLease lease,
        Func<ProcessStartInfo, Process?> starter)
    {
        var appAssemblyPath = BuildAppForReflection();
        var outputDirectory = Path.GetDirectoryName(appAssemblyPath)!;
        var context = System.Runtime.Loader.AssemblyLoadContext.Default;
        System.Reflection.Assembly? Resolver(
            System.Runtime.Loader.AssemblyLoadContext loadContext,
            System.Reflection.AssemblyName name)
        {
            var candidate = Path.Combine(
                outputDirectory,
                $"{name.Name}.dll");
            if (!File.Exists(candidate))
            {
                return null;
            }

            using var dependency = new MemoryStream(
                File.ReadAllBytes(candidate));
            return loadContext.LoadFromStream(dependency);
        }

        context.Resolving += Resolver;
        try
        {
            using var appBytes = new MemoryStream(
                File.ReadAllBytes(appAssemblyPath));
            var appAssembly = context.LoadFromStream(appBytes);
            var appType = appAssembly.GetType(
                "WireguardSplitTunnel.App.AppAutoElevationRelaunch",
                throwOnError: true)!;
            var helper = appType
                .GetMethods(
                    System.Reflection.BindingFlags.Static
                        | System.Reflection.BindingFlags.NonPublic)
                .Single(method =>
                    method.Name == "TryRelaunchAsAdministrator"
                    && method.GetParameters().Length == 3);

            return (bool)helper.Invoke(
                null,
                [arguments, lease, starter])!;
        }
        finally
        {
            context.Resolving -= Resolver;
        }
    }

    private string BuildAppForReflection()
    {
        var outputDirectory = Path.Combine(
            root,
            "app-reflection-output");
        Directory.CreateDirectory(outputDirectory);
        var start = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "dotnet",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var argument in new[]
                 {
                     "build",
                     ReadRepositoryPath(
                         "src/WireguardSplitTunnel.App/"
                             + "WireguardSplitTunnel.App.csproj"),
                     "-c",
                     "Release",
                     "--no-restore",
                     "-m:1",
                     $"-p:OutDir={outputDirectory}"
                         + Path.DirectorySeparatorChar,
                     "-v:minimal"
                 })
        {
            start.ArgumentList.Add(argument);
        }

        using var process = System.Diagnostics.Process.Start(start);
        process.Should().NotBeNull();
        var standardOutput = process!.StandardOutput.ReadToEnd();
        var standardError = process.StandardError.ReadToEnd();
        if (!process.WaitForExit(120_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException(
                "Timed out building the App reflection fixture.");
        }

        process.ExitCode.Should().Be(
            0,
            standardOutput + Environment.NewLine + standardError);
        var assemblyPath = Path.Combine(
            outputDirectory,
            "WireguardSplitTunnel.App.dll");
        File.Exists(assemblyPath).Should().BeTrue();
        return assemblyPath;
    }

    private static string ExtractBetween(
        string source,
        string startMarker,
        string endMarker)
    {
        var start = source.IndexOf(
            startMarker,
            StringComparison.Ordinal);
        var end = source.IndexOf(
            endMarker,
            start < 0 ? 0 : start,
            StringComparison.Ordinal);
        start.Should().BeGreaterThanOrEqualTo(0);
        end.Should().BeGreaterThan(start);
        return source[start..end];
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(
            AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(
                    current.FullName,
                    "WireguardSplitTunnel.sln")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException(
            "Could not locate repository root.");
    }

    private static string Escape(string value) =>
        value.Replace("'", "''", StringComparison.Ordinal);

    private static string Ps(bool value) =>
        value ? "$true" : "$false";

    private static readonly JsonSerializerOptions JsonOptions =
        new()
        {
            PropertyNameCaseInsensitive = true
        };

    private sealed record LauncherTrust(
        bool Supported,
        bool ElevationAllowed,
        bool RecoveryAllowed,
        string Kind);

    private sealed record PowerShellEnvironment(
        string ModulePath,
        string AutoLoading,
        bool MarkerExists);

    private sealed record StateReaderResult(
        string[] Valid,
        int Rejected);

    private sealed record InstalledReleasePolicy(
        bool Valid,
        bool WeakScript,
        bool WeakParent);

    private sealed record ResolverPolicy(
        string? Protected,
        string Developer);

    private sealed class RecordingDisposable : IDisposable
    {
        public bool Disposed { get; private set; }

        public void Dispose() => Disposed = true;
    }
}
