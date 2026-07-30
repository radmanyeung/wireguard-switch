using System.Security.AccessControl;
using System.Text.Json;
using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Transactions;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class InstallerBootstrapTests : IDisposable
{
    private readonly ReleaseScriptFixture _fixture = new();

    [Theory]
    [InlineData(true, true, false, false, true, false, false, "BundledRelease")]
    [InlineData(false, false, true, true, true, false, false, "PublishSource")]
    [InlineData(false, true, false, false, false, true, false, "BundledRelease")]
    public void InstallMode_UsesValidatedBundledReleaseBeforeSdkPublishing(
        bool hasManifest,
        bool hasBundledExecutable,
        bool hasSourceProject,
        bool hasProps,
        bool hasSdk,
        bool skipPublish,
        bool forcePublish,
        string expected)
    {
        var result = InvokeInstallMode(
            hasManifest,
            hasBundledExecutable,
            hasSourceProject,
            hasProps,
            hasSdk,
            skipPublish,
            forcePublish);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        result.StandardOutput.Trim().Should().Be(expected);
    }

    [Fact]
    public void InstallMode_RejectsForcePublishWithoutSourceAndProps()
    {
        var result = InvokeInstallMode(
            hasManifest: true,
            hasBundledExecutable: true,
            hasSourceProject: false,
            hasProps: false,
            hasSdk: true,
            skipPublish: false,
            forcePublish: true);

        result.ExitCode.Should().NotBe(0);
    }

    [Fact]
    public void BootstrapContract_IsFixedAndIgnoresRepositoryUrlEnvironment()
    {
        var script = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "ensure-prebuilt.ps1");
        var result = ReleaseScriptFixture.RunPowerShell(
            script,
            ["-RepoRoot", _fixture.RepositoryRoot, "-DescribeContract"],
            new Dictionary<string, string>
            {
                ["WGST_RELEASE_REPO"] = "attacker/repository",
                ["WGST_RELEASE_ASSET_URL"] =
                    "http://attacker.invalid/payload.zip"
            });

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        using var document = JsonDocument.Parse(
            result.StandardOutput.Trim());
        var contract = document.RootElement;
        contract.GetProperty("repository").GetString()
            .Should().Be(UpdateReleaseContract.Repository);
        contract.GetProperty("archiveAsset").GetString()
            .Should().Be(UpdateReleaseContract.WindowsAssetName);
        contract.GetProperty("checksumAsset").GetString()
            .Should().Be(
                UpdateReleaseContract.WindowsChecksumAssetName);
        contract.GetProperty("maximumRedirects").GetInt32()
            .Should().Be(UpdateNetworkLimits.MaximumRedirects);
        contract.GetProperty("redirectHosts")
            .EnumerateArray()
            .Select(value => value.GetString())
            .Should().Equal(UpdateReleaseContract.RedirectHosts);
        result.CombinedOutput.ToLowerInvariant()
            .Should().NotContain("attacker");
    }

    [Fact]
    public void SourceBootstrapCopy_CopiesOnlyValidatedApplicationSubtree()
    {
        _fixture.Package().ExitCode.Should().Be(0);
        var destination = Path.Combine(
            _fixture.Root,
            "source-checkout-copy");
        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $module = Import-Module '{{Escape(modulePath)}}' -Force -PassThru
            & $module {
                param($PackageRoot, $Destination)
                Copy-WgstValidatedApplicationSubtree `
                    -PackageRoot $PackageRoot `
                    -DestinationRoot $Destination
            } '{{Escape(_fixture.PackageRoot)}}' '{{Escape(destination)}}'
            """;

        var result = _fixture.RunInlinePowerShell(script);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        File.Exists(
                Path.Combine(
                    destination,
                    "WireguardSplitTunnel.App.exe"))
            .Should().BeTrue();
        File.Exists(
                Path.Combine(
                    destination,
                    "WireguardSplitTunnel.Updater.exe"))
            .Should().BeTrue();
        File.Exists(
                Path.Combine(
                    destination,
                    UpdateReleaseContract.ReleaseManifestPath))
            .Should().BeFalse();
        Directory.EnumerateFiles(
                destination,
                "*",
                SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(destination, path))
            .Should().OnlyContain(path =>
                !path.StartsWith("scripts", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void SourceBootstrapCopy_RefusesAnExistingDestinationPayload()
    {
        _fixture.Package().ExitCode.Should().Be(0);
        var destination = Path.Combine(
            _fixture.Root,
            "existing-destination");
        Directory.CreateDirectory(destination);
        var existing = Path.Combine(
            destination,
            "WireguardSplitTunnel.App.exe");
        File.WriteAllText(existing, "do not replace");
        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $module = Import-Module '{{Escape(modulePath)}}' -Force -PassThru
            & $module {
                param($PackageRoot, $Destination)
                Copy-WgstValidatedApplicationSubtree `
                    -PackageRoot $PackageRoot `
                    -DestinationRoot $Destination
            } '{{Escape(_fixture.PackageRoot)}}' '{{Escape(destination)}}'
            """;

        var result = _fixture.RunInlinePowerShell(script);

        result.ExitCode.Should().NotBe(0);
        File.ReadAllText(existing).Should().Be("do not replace");
    }

    [Fact]
    public void SourceBootstrapCopy_RejectsPayloadChangedAfterValidation()
    {
        _fixture.Package().ExitCode.Should().Be(0);
        File.AppendAllText(
            Path.Combine(
                _fixture.PackageRoot,
                UpdateReleaseContract.WindowsApplicationPath
                    .Replace('/', Path.DirectorySeparatorChar)),
            "tampered after validation");
        var destination = Path.Combine(
            _fixture.Root,
            "tampered-source-copy");
        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $module = Import-Module '{{Escape(modulePath)}}' -Force -PassThru
            & $module {
                param($PackageRoot, $Destination)
                Copy-WgstValidatedApplicationSubtree `
                    -PackageRoot $PackageRoot `
                    -DestinationRoot $Destination
            } '{{Escape(_fixture.PackageRoot)}}' '{{Escape(destination)}}'
            """;

        var result = _fixture.RunInlinePowerShell(script);

        result.ExitCode.Should().NotBe(0);
    }

    [Fact]
    public void NativeDestinationIdentity_RejectsHardLinkedPayload()
    {
        var original = Path.Combine(
            _fixture.Root,
            "hardlink-original.bin");
        var linked = Path.Combine(
            _fixture.Root,
            "hardlink-destination.bin");
        File.WriteAllText(original, "linked payload");
        var createLink = _fixture.RunInlinePowerShell(
            $$"""
              $ErrorActionPreference = 'Stop'
              New-Item `
                  -ItemType HardLink `
                  -Path '{{Escape(linked)}}' `
                  -Target '{{Escape(original)}}' | Out-Null
              """);
        createLink.ExitCode.Should().Be(0, createLink.CombinedOutput);

        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var validate = _fixture.RunInlinePowerShell(
            $$"""
              $ErrorActionPreference = 'Stop'
              $module = Import-Module `
                  '{{Escape(modulePath)}}' `
                  -Force `
                  -PassThru
              & $module {
                  param($Path)
                  Get-WgstNativeFileSnapshot `
                      -Path $Path `
                      -RequireSingleLink
              } '{{Escape(linked)}}'
              """);

        validate.ExitCode.Should().NotBe(0);
        File.ReadAllText(original).Should().Be("linked payload");
    }

    [Fact]
    public void InstalledReleaseDescriptorBuilder_MatchesRuntimeAclPolicy()
    {
        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $module = Import-Module '{{Escape(modulePath)}}' -Force -PassThru
            & $module {
                $descriptors = [ordered]@{}
                foreach ($scope in @(
                        'RootDirectory',
                        'DescendantDirectory',
                        'ManagedFile')) {
                    $security =
                        New-WgstExactInstalledReleaseSecurity -Scope $scope
                    if (-not (Test-WgstExactInstalledReleaseSecurity `
                            -Security $security `
                            -Scope $scope)) {
                        throw "Installed Release descriptor failed: $scope"
                    }
                    $raw =
                        [Security.AccessControl.RawSecurityDescriptor]::new(
                            $security.GetSecurityDescriptorBinaryForm(),
                            0)
                    $isRoot = $scope -ceq 'RootDirectory'
                    $protected =
                        [Security.AccessControl.ControlFlags]::
                            DiscretionaryAclProtected
                    if ($raw.Owner.Value -cne 'S-1-5-18' -or
                        $raw.DiscretionaryAcl.Count -ne 3 -or
                        ((($raw.ControlFlags -band $protected) -ne 0) `
                            -ne $isRoot)) {
                        throw "Installed Release header failed: $scope"
                    }
                    $expectedFlags = if ($isRoot) {
                        [Security.AccessControl.AceFlags](
                            [int][Security.AccessControl.AceFlags]::
                                ContainerInherit -bor
                            [int][Security.AccessControl.AceFlags]::
                                ObjectInherit)
                    }
                    elseif ($scope -ceq 'DescendantDirectory') {
                        [Security.AccessControl.AceFlags](
                            [int][Security.AccessControl.AceFlags]::
                                ContainerInherit -bor
                            [int][Security.AccessControl.AceFlags]::
                                ObjectInherit -bor
                            [int][Security.AccessControl.AceFlags]::Inherited)
                    }
                    else {
                        [Security.AccessControl.AceFlags]::Inherited
                    }
                    $expected = @{
                        'S-1-5-18' = 0x1f01ff
                        'S-1-5-32-544' = 0x1f01ff
                        'S-1-5-32-545' = 0x1200a9
                    }
                    foreach ($genericAce in $raw.DiscretionaryAcl) {
                        if (-not ($genericAce -is
                                [Security.AccessControl.CommonAce])) {
                            throw "Installed Release ACE type failed: $scope"
                        }
                        $ace = [Security.AccessControl.CommonAce]$genericAce
                        $sid = $ace.SecurityIdentifier.Value
                        if ($ace.IsCallback -or
                            $ace.AceQualifier -ne
                                [Security.AccessControl.AceQualifier]::
                                    AccessAllowed -or
                            $ace.AceFlags -ne $expectedFlags -or
                            $ace.OpaqueLength -ne 0 -or
                            -not $expected.ContainsKey($sid) -or
                            $ace.AccessMask -ne $expected[$sid]) {
                            throw "Installed Release ACE failed: $scope"
                        }
                        [void]$expected.Remove($sid)
                    }
                    if ($expected.Count -ne 0) {
                        throw "Installed Release SID set failed: $scope"
                    }
                    $descriptors[$scope] = [Convert]::ToBase64String(
                        $security.GetSecurityDescriptorBinaryForm())
                }
                $descriptors | ConvertTo-Json -Compress
            }
            """;

        var result = _fixture.RunInlinePowerShell(script);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        using var descriptors = JsonDocument.Parse(
            result.StandardOutput.Trim());
        ProtectedDirectoryAcl.HasExactInstalledRootDescriptor(
                Convert.FromBase64String(
                    descriptors.RootElement
                        .GetProperty("RootDirectory")
                        .GetString()!))
            .Should().BeTrue();
        ProtectedDirectoryAcl.HasExactInstalledDescendantDescriptor(
                Convert.FromBase64String(
                    descriptors.RootElement
                        .GetProperty("DescendantDirectory")
                        .GetString()!),
                directory: true)
            .Should().BeTrue();
        ProtectedDirectoryAcl.HasExactInstalledDescendantDescriptor(
                Convert.FromBase64String(
                    descriptors.RootElement
                        .GetProperty("ManagedFile")
                        .GetString()!),
                directory: false)
            .Should().BeTrue();
    }

    [Fact]
    public void AuthenticatedBundleAclPlan_CoversManagedFilesAndParentsOnly()
    {
        _fixture.Package().ExitCode.Should().Be(0);
        var runtimeLog = Path.Combine(_fixture.PackageRoot, "runtime.log");
        var legacyLog = Path.Combine(
            _fixture.PackageRoot,
            "logs",
            "legacy.log");
        Directory.CreateDirectory(Path.GetDirectoryName(legacyLog)!);
        File.WriteAllText(runtimeLog, "preserve runtime log");
        File.WriteAllText(legacyLog, "preserve legacy log");
        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $module = Import-Module '{{Escape(modulePath)}}' -Force -PassThru
            & $module {
                param($PackageRoot)
                $plan = Get-WgstAuthenticatedBundledReleaseAclPlan `
                    -PackageRoot $PackageRoot
                [ordered]@{
                    directories = @($plan.Directories |
                        ForEach-Object {
                            $_.RelativePath.Replace('\', '/')
                        })
                    files = @($plan.Files |
                        ForEach-Object { $_.RelativePath })
                } | ConvertTo-Json -Depth 4 -Compress
            } '{{Escape(_fixture.PackageRoot)}}'
            """;

        var result = _fixture.RunInlinePowerShell(script);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        using var plan = JsonDocument.Parse(result.StandardOutput.Trim());
        var plannedFiles = plan.RootElement.GetProperty("files")
            .EnumerateArray()
            .Select(element => element.GetString()!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        using var manifest = JsonDocument.Parse(
            File.ReadAllBytes(
                Path.Combine(
                    _fixture.PackageRoot,
                    UpdateReleaseContract.ReleaseManifestPath)));
        var expectedFiles = manifest.RootElement.GetProperty("files")
            .EnumerateArray()
            .Select(element => element.GetProperty("path").GetString()!)
            .Append(UpdateReleaseContract.ReleaseManifestPath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        plannedFiles.Should().BeEquivalentTo(expectedFiles);

        var expectedDirectories = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase) { string.Empty };
        foreach (var file in expectedFiles)
        {
            var parent = file;
            while ((parent = Path.GetDirectoryName(parent)
                       ?.Replace(
                           Path.DirectorySeparatorChar,
                           '/')) is { Length: > 0 })
            {
                expectedDirectories.Add(parent);
            }
        }
        var plannedDirectories = plan.RootElement
            .GetProperty("directories")
            .EnumerateArray()
            .Select(element => element.GetString()!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        plannedDirectories.Should().BeEquivalentTo(expectedDirectories);
        plannedFiles.Should().NotContain("runtime.log");
        plannedFiles.Should().NotContain("logs/legacy.log");
        plannedDirectories.Should().NotContain("logs");
        File.ReadAllText(runtimeLog).Should().Be("preserve runtime log");
        File.ReadAllText(legacyLog).Should().Be("preserve legacy log");
    }

    [Fact]
    public void ProtectedInstallRoot_UsesProgramFilesAndRejectsMutationForANonAdminToken()
    {
        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $module = Import-Module '{{Escape(modulePath)}}' -Force -PassThru
            & $module {
                $root = Get-WgstProtectedInstallRoot
                $parent = Split-Path -Parent $root
                $parentSecurity = Get-WgstFileSystemSecurity `
                    -Path $parent `
                    -Directory $true
                [ordered]@{
                    root = $root
                    parentOwner = $parentSecurity.Owner
                    parentSddl = $parentSecurity.Sddl
                    descriptorAuthority =
                        Test-WgstProtectedInstallParentDescriptorAuthority `
                            -Security $parentSecurity
                    parentAuthority =
                        Test-WgstProtectedInstallParentAuthority `
                            -InstallRoot $root
                    isAdministrator =
                        ([Security.Principal.WindowsPrincipal]::new(
                            [Security.Principal.WindowsIdentity]::GetCurrent())).
                            IsInRole(
                                [Security.Principal.WindowsBuiltInRole]::Administrator)
                    currentTokenCanMutateParent =
                        [WireguardSplitTunnel.ReleaseScripts.NativeFileIdentity]::CanOpenDirectoryForMutation($parent)
                } | ConvertTo-Json -Compress
            }
            """;

        var result = _fixture.RunInlinePowerShell(script);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        using var contract = JsonDocument.Parse(
            result.StandardOutput.Trim());
        contract.RootElement.GetProperty("root").GetString()
            .Should().Be(
                Path.Combine(
                    Environment.GetFolderPath(
                        Environment.SpecialFolder.ProgramFiles),
                    "WireguardSplitTunnel"));
        contract.RootElement.GetProperty("parentAuthority")
            .GetBoolean().Should().BeTrue(contract.RootElement.ToString());
        if (!contract.RootElement.GetProperty("isAdministrator").GetBoolean())
        {
            contract.RootElement.GetProperty("currentTokenCanMutateParent")
                .GetBoolean().Should().BeFalse();
        }
    }

    [Fact]
    public void ProtectedInstallParentAuthority_RejectsUntrustedOwnerAndArbitraryWriter()
    {
        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $module = Import-Module '{{Escape(modulePath)}}' -Force -PassThru
            & $module {
                function New-TestParentSecurity {
                    param($Owner, [switch]$ArbitraryWriter)
                    $security = [Security.AccessControl.DirectorySecurity]::new()
                    $security.SetAccessRuleProtection($true, $false)
                    $security.SetOwner(
                        [Security.Principal.SecurityIdentifier]::new($Owner))
                    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
                        $security.AddAccessRule(
                            [Security.AccessControl.FileSystemAccessRule]::new(
                                [Security.Principal.SecurityIdentifier]::new($sid),
                                [Security.AccessControl.FileSystemRights]::FullControl,
                                [Security.AccessControl.InheritanceFlags]::None,
                                [Security.AccessControl.PropagationFlags]::None,
                                [Security.AccessControl.AccessControlType]::Allow))
                    }
                    if ($ArbitraryWriter) {
                        $security.AddAccessRule(
                            [Security.AccessControl.FileSystemAccessRule]::new(
                                [Security.Principal.SecurityIdentifier]::new(
                                    'S-1-5-21-111-222-333-444'),
                                [Security.AccessControl.FileSystemRights]::CreateDirectories,
                                [Security.AccessControl.InheritanceFlags]::None,
                                [Security.AccessControl.PropagationFlags]::None,
                                [Security.AccessControl.AccessControlType]::Allow))
                    }
                    return $security
                }
                [ordered]@{
                    untrustedOwner =
                        Test-WgstProtectedInstallParentDescriptorAuthority `
                            -Security (New-TestParentSecurity `
                                -Owner 'S-1-5-21-111-222-333-555')
                    arbitraryWriter =
                        Test-WgstProtectedInstallParentDescriptorAuthority `
                            -Security (New-TestParentSecurity `
                                -Owner 'S-1-5-18' `
                                -ArbitraryWriter)
                } | ConvertTo-Json -Compress
            }
            """;

        var result = _fixture.RunInlinePowerShell(script);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        using var contract = JsonDocument.Parse(result.StandardOutput.Trim());
        contract.RootElement.GetProperty("untrustedOwner")
            .GetBoolean().Should().BeFalse();
        contract.RootElement.GetProperty("arbitraryWriter")
            .GetBoolean().Should().BeFalse();
    }

    [Fact]
    public void BoundReleaseIdentity_RejectsParentNamespaceSwapWithSameBytes()
    {
        _fixture.Package().ExitCode.Should().Be(0);
        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var bindScript = $$"""
            $ErrorActionPreference = 'Stop'
            $module = Import-Module '{{Escape(modulePath)}}' -Force -PassThru
            & $module {
                param($PackageRoot)
                Get-WgstAuthenticatedBundledReleaseBinding `
                    -PackageRoot $PackageRoot |
                    ConvertTo-Json -Depth 4 -Compress
            } '{{Escape(_fixture.PackageRoot)}}'
            """;
        var bound = _fixture.RunInlinePowerShell(bindScript);
        bound.ExitCode.Should().Be(0, bound.CombinedOutput);
        using var binding = JsonDocument.Parse(bound.StandardOutput.Trim());

        var displaced = _fixture.PackageRoot + "-displaced";
        Directory.Move(_fixture.PackageRoot, displaced);
        CopyDirectory(displaced, _fixture.PackageRoot);
        var assertScript = $$"""
            $ErrorActionPreference = 'Stop'
            $module = Import-Module '{{Escape(modulePath)}}' -Force -PassThru
            & $module {
                param(
                    $PackageRoot,
                    [uint32]$Volume,
                    [uint64]$Index,
                    [long]$ManifestLength,
                    $ManifestSha256)
                Assert-WgstAuthenticatedBundledReleaseBinding `
                    -PackageRoot $PackageRoot `
                    -ExpectedVolumeSerialNumber $Volume `
                    -ExpectedFileIndex $Index `
                    -ExpectedManifestLength $ManifestLength `
                    -ExpectedManifestSha256 $ManifestSha256
            } `
                '{{Escape(_fixture.PackageRoot)}}' `
                {{binding.RootElement.GetProperty("volumeSerialNumber").GetUInt32()}} `
                {{binding.RootElement.GetProperty("fileIndex").GetUInt64()}} `
                {{binding.RootElement.GetProperty("manifestLength").GetInt64()}} `
                '{{binding.RootElement.GetProperty("manifestSha256").GetString()}}'
            """;

        var rejected = _fixture.RunInlinePowerShell(assertScript);

        rejected.ExitCode.Should().NotBe(0);
        File.Exists(
                Path.Combine(
                    displaced,
                    UpdateReleaseContract.ReleaseManifestPath))
            .Should().BeTrue();
    }

    [Fact]
    public void InstallerElevationBootstrap_ExecutesOnlyBoundBytesThenProtectedCopy()
    {
        var script = File.ReadAllText(
            Path.Combine(
                _fixture.ActualRepositoryRoot,
                "scripts",
                "install.ps1"));
        var bundleGate = script.IndexOf(
            "Invoke-WgstBoundBundledReleaseBootstrap",
            StringComparison.Ordinal);
        var memoryModule = script.IndexOf(
            "New-Module -ScriptBlock",
            bundleGate,
            StringComparison.Ordinal);
        var protectedCopy = script.IndexOf(
            "Install-WgstAuthenticatedBundledReleaseToProtectedAnchor",
            StringComparison.Ordinal);
        var installedScript = script.IndexOf(
            "& $installedScript",
            StringComparison.Ordinal);
        var encoded = script.IndexOf(
            "-EncodedCommand",
            installedScript,
            StringComparison.Ordinal);
        var ordinaryElevation = script.IndexOf(
            "Ensure-Administrator",
            bundleGate,
            StringComparison.Ordinal);

        bundleGate.Should().BeGreaterThanOrEqualTo(0);
        memoryModule.Should().BeGreaterThan(bundleGate);
        protectedCopy.Should().BeGreaterThan(memoryModule);
        installedScript.Should().BeGreaterThan(protectedCopy);
        encoded.Should().BeGreaterThan(installedScript);
        ordinaryElevation.Should().BeGreaterThan(installedScript);
        script[bundleGate..ordinaryElevation]
            .Should().NotContain("-File', \"`\"$self`\"\"");
    }

    [Fact]
    public void PackagedReleaseMarkers_TakePrecedenceOverPlantedDeveloperFiles()
    {
        _fixture.Package().ExitCode.Should().Be(0);
        var plantedProject = Path.Combine(
            _fixture.PackageRoot,
            "src",
            "WireguardSplitTunnel.App",
            "WireguardSplitTunnel.App.csproj");
        Directory.CreateDirectory(Path.GetDirectoryName(plantedProject)!);
        File.WriteAllText(plantedProject, "<Project />");
        File.WriteAllText(
            Path.Combine(_fixture.PackageRoot, "Directory.Build.props"),
            "<Project />");
        File.Copy(
            Path.Combine(
                _fixture.ActualRepositoryRoot,
                "scripts",
                "install.ps1"),
            Path.Combine(
                _fixture.PackageRoot,
                "scripts",
                "install.ps1"),
            overwrite: true);
        File.Delete(
            Path.Combine(
                _fixture.PackageRoot,
                UpdateReleaseContract.WindowsUpdaterPath.Replace(
                    '/',
                    Path.DirectorySeparatorChar)));

        var result = ReleaseScriptFixture.RunPowerShell(
            Path.Combine(
                _fixture.PackageRoot,
                "scripts",
                "install.ps1"),
            ["-RepairBlockedUpdate"]);

        result.ExitCode.Should().NotBe(0);
        result.CombinedOutput.Should().Contain(
            "packaged Release is incomplete");
        result.CombinedOutput.Should().NotContain(
            "RepairBlockedUpdate must enter");
    }

    [Fact]
    public void DeveloperSource_NeverReopensMutableInstallerWithRunAs()
    {
        var script = File.ReadAllText(
            Path.Combine(
                _fixture.ActualRepositoryRoot,
                "scripts",
                "install.ps1"));
        var start = script.IndexOf(
            "function Ensure-Administrator",
            StringComparison.Ordinal);
        var end = script.IndexOf(
            "function New-DesktopShortcut",
            start,
            StringComparison.Ordinal);

        start.Should().BeGreaterThanOrEqualTo(0);
        end.Should().BeGreaterThan(start);
        var administratorGate = script[start..end];
        administratorGate.Should().NotContain("Start-Process");
        administratorGate.Should().NotContain("-Verb RunAs");
        administratorGate.Should().Contain(
            "Administrator terminal");
    }

    [Fact]
    public void ElevatedInstallerAndLauncher_DoNotForwardCallerLogPaths()
    {
        var install = File.ReadAllText(
            Path.Combine(
                _fixture.ActualRepositoryRoot,
                "scripts",
                "install.ps1"));
        var start = File.ReadAllText(
            Path.Combine(
                _fixture.ActualRepositoryRoot,
                "scripts",
                "start.ps1"));
        var startAdmin = File.ReadAllText(
            Path.Combine(_fixture.ActualRepositoryRoot, "start-admin.cmd"));

        install.Should().Contain("$LauncherLogPath = $null");
        install.Should().NotContain("$argList += '-LauncherLogPath'");
        start.Should().Contain("$LauncherLogPath = $null");
        start.Should().NotContain("$argList += '-LauncherLogPath'");
        startAdmin.Should().NotContain("-LauncherLogPath");
    }

    [Fact]
    public void ElevatedInstaller_NeverExecutesPrerequisitesFromUserPathOrTemp()
    {
        var install = File.ReadAllText(
            Path.Combine(
                _fixture.ActualRepositoryRoot,
                "scripts",
                "install.ps1"));

        install.Should().NotContain("Get-Command dotnet");
        install.Should().NotContain("Get-Command winget");
        install.Should().NotContain("Get-Command wireguard");
        install.Should().NotContain("Invoke-DownloadAndRun");
        install.Should().NotContain("Install-WithWinget");
        install.Should().NotContain("$env:TEMP");
        install.Should().NotContain("dotnet-sdk-win-x64.exe");
        install.Should().NotContain("wireguard-installer.exe");
    }

    [Fact]
    public void PostInstallSelfTest_DisablesPowerShellProfiles()
    {
        var install = File.ReadAllText(
            Path.Combine(
                _fixture.ActualRepositoryRoot,
                "scripts",
                "install.ps1"));
        var start = install.IndexOf(
            "Launching app for post-install self test",
            StringComparison.Ordinal);
        var child = install[start..].ReplaceLineEndings("\n");

        start.Should().BeGreaterThanOrEqualTo(0);
        child.Should().Contain("Get-WgstSystemPowerShellPath");
        child.Should().Contain(
            "'-NoProfile',\n        '-ExecutionPolicy', 'Bypass'");
    }

    [Fact]
    public void InstallCmd_UsesOnlyTheFixedSystemPowerShellHost()
    {
        var launcher = File.ReadAllText(
            Path.Combine(_fixture.ActualRepositoryRoot, "install.cmd"));

        launcher.Should().Contain(
            "set \"PS_EXE=%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"");
        launcher.Should().Contain("if not exist \"%PS_EXE%\" (");
        launcher.Should().Contain("exit /b 9009");
        launcher.Should().Contain("\"%PS_EXE%\" -NoProfile");
        launcher.Should().NotContain("set \"PS_EXE=powershell\"");
    }

    [Fact]
    public void Installer_IgnoresAttackerControlledPowerShellModulePath()
    {
        _fixture.Package().ExitCode.Should().Be(0);
        File.Copy(
            Path.Combine(
                _fixture.ActualRepositoryRoot,
                "scripts",
                "install.ps1"),
            Path.Combine(
                _fixture.PackageRoot,
                "scripts",
                "install.ps1"),
            overwrite: true);
        var maliciousRoot = Path.Combine(
            _fixture.Root,
            "attacker-modules");
        var maliciousModule = Path.Combine(
            maliciousRoot,
            "Attacker.Utility");
        Directory.CreateDirectory(maliciousModule);
        var marker = Path.Combine(_fixture.Root, "module-loaded.txt");
        File.WriteAllText(
            Path.Combine(
                maliciousModule,
                "Attacker.Utility.psd1"),
            "@{ RootModule = 'Attacker.Utility.psm1'; " +
            "ModuleVersion = '99.0.0'; " +
            "FunctionsToExport = @('ConvertFrom-Json') }");
        File.WriteAllText(
            Path.Combine(
                maliciousModule,
                "Attacker.Utility.psm1"),
            $"[IO.File]::WriteAllText('{Escape(marker)}', 'loaded')\r\n" +
            "function ConvertFrom-Json { return $null }\r\n" +
            "Export-ModuleMember -Function '*'\r\n");

        var result = ReleaseScriptFixture.RunPowerShell(
            Path.Combine(
                _fixture.PackageRoot,
                "scripts",
                "install.ps1"),
            ["-RepairBlockedUpdate"],
            new Dictionary<string, string>
            {
                ["PSModulePath"] = maliciousRoot
            });

        result.ExitCode.Should().NotBe(0);
        File.Exists(marker).Should().BeFalse(result.CombinedOutput);
    }

    [Fact]
    public void ElevatedEncodedBootstrap_SanitizesModulesBeforeJsonCommands()
    {
        var install = File.ReadAllText(
            Path.Combine(
                _fixture.ActualRepositoryRoot,
                "scripts",
                "install.ps1"));
        var template = install.IndexOf(
            "$bootstrapTemplate = @'",
            StringComparison.Ordinal);
        var sanitizer = install.IndexOf(
            "$PSModuleAutoLoadingPreference = 'None'",
            template,
            StringComparison.Ordinal);
        var payload = install.IndexOf(
            "$payloadText =",
            template,
            StringComparison.Ordinal);

        template.Should().BeGreaterThanOrEqualTo(0);
        sanitizer.Should().BeGreaterThan(template);
        sanitizer.Should().BeLessThan(payload);
    }

    [Fact]
    public void BlockedRepair_ReinstallsAndRevalidatesTheRecordedProtectedRootBeforeDeactivation()
    {
        var module = File.ReadAllText(
            Path.Combine(
                _fixture.ActualRepositoryRoot,
                "scripts",
                "WindowsRelease.psm1"));
        var repair = module.IndexOf(
            "function Invoke-WgstRepairBlockedState",
            StringComparison.Ordinal);
        var installRoot = module.IndexOf(
            "$record.installedRelease.installRoot",
            repair,
            StringComparison.Ordinal);
        var archive = module.IndexOf(
            "$record.candidate.archiveSha256",
            repair,
            StringComparison.Ordinal);
        var manifest = module.IndexOf(
            "$record.candidate.newManifestSha256",
            repair,
            StringComparison.Ordinal);
        var reinstall = module.IndexOf(
            "Repair-WgstProtectedInstalledRelease",
            archive,
            StringComparison.Ordinal);
        var resolution = module.IndexOf(
            "$resolutionPath",
            repair,
            StringComparison.Ordinal);
        var deactivate = module.IndexOf(
            "[IO.File]::Replace(",
            resolution,
            StringComparison.Ordinal);

        installRoot.Should().BeGreaterThan(repair);
        archive.Should().BeGreaterThan(installRoot);
        manifest.Should().BeGreaterThan(installRoot);
        reinstall.Should().BeGreaterThan(archive);
        reinstall.Should().BeLessThan(resolution);
        deactivate.Should().BeGreaterThan(resolution);
    }

    [Fact]
    public void RepairMutexDescriptor_MatchesTheRuntimeUpdaterAuthority()
    {
        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            Import-Module '{{Escape(modulePath)}}' -Force
            [ordered]@{
                name =
                    [WireguardSplitTunnel.ReleaseScripts.NativeUpdateMutex]::Name
                descriptor = [Convert]::ToBase64String(
                    [WireguardSplitTunnel.ReleaseScripts.NativeUpdateMutex]::
                        ExpectedSecurityDescriptor())
            } | ConvertTo-Json -Compress
            """;

        var result = _fixture.RunInlinePowerShell(script);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        using var contract = JsonDocument.Parse(result.StandardOutput.Trim());
        contract.RootElement.GetProperty("name").GetString()
            .Should().Be(ProtectedUpdateMutex.Name);
        var security = new MutexSecurity();
        security.SetSecurityDescriptorBinaryForm(
            Convert.FromBase64String(
                contract.RootElement.GetProperty("descriptor").GetString()!));
        ProtectedUpdateMutex.HasExactSecurity(security).Should().BeTrue();
    }

    [Fact]
    public void AuthenticatedBlockedRepair_HoldsTheExactGlobalMutexForAllWork()
    {
        var module = File.ReadAllText(
            Path.Combine(
                _fixture.ActualRepositoryRoot,
                "scripts",
                "WindowsRelease.psm1"));
        var mutex = module.IndexOf(
            "function Invoke-WgstWithProtectedUpdateMutex",
            StringComparison.Ordinal);
        var repair = module.IndexOf(
            "function Invoke-WgstAuthenticatedBlockedRepair",
            StringComparison.Ordinal);
        var export = module.IndexOf(
            "Export-ModuleMember",
            repair,
            StringComparison.Ordinal);

        mutex.Should().BeGreaterThanOrEqualTo(0);
        repair.Should().BeGreaterThan(mutex);
        var mutexBody = module[mutex..repair];
        mutexBody.Should().Contain("NativeUpdateMutex");
        mutexBody.Should().Contain("OpenExact()");
        mutexBody.Should().Contain("$mutex.Wait(0)");
        mutexBody.Should().Contain("$mutex.ValidateSecurity()");
        mutexBody.Should().Contain("$mutex.Release()");
        var repairBody = module[repair..export];
        repairBody.Should().Contain("Invoke-WgstWithProtectedUpdateMutex");
        repairBody.IndexOf("Invoke-WgstWithProtectedUpdateMutex", StringComparison.Ordinal)
            .Should().BeLessThan(
                repairBody.IndexOf("New-WgstProtectedWorkspace", StringComparison.Ordinal));
    }

    [Fact]
    public void AuthenticatedBundleProvisioning_InvalidPayloadFailsBeforeAclMutation()
    {
        _fixture.Package().ExitCode.Should().Be(0);
        File.AppendAllText(
            Path.Combine(
                _fixture.PackageRoot,
                UpdateReleaseContract.WindowsApplicationPath
                    .Replace('/', Path.DirectorySeparatorChar)),
            "tampered before ACL provisioning");
        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $module = Import-Module '{{Escape(modulePath)}}' -Force -PassThru
            & $module {
                param($PackageRoot)
                if ($null -eq (Get-Command `
                        Set-WgstAuthenticatedBundledReleaseAcl `
                        -ErrorAction SilentlyContinue)) {
                    throw 'ACL provisioner is missing.'
                }
                $before = [Convert]::ToBase64String(
                    (Get-WgstFileSystemSecurity `
                        -Path $PackageRoot `
                        -Directory $true).
                            GetSecurityDescriptorBinaryForm())
                $rejected = $false
                try {
                    Set-WgstAuthenticatedBundledReleaseAcl `
                        -PackageRoot $PackageRoot
                }
                catch {
                    $rejected = $true
                }
                $after = [Convert]::ToBase64String(
                    (Get-WgstFileSystemSecurity `
                        -Path $PackageRoot `
                        -Directory $true).
                            GetSecurityDescriptorBinaryForm())
                if (-not $rejected -or $before -cne $after) {
                    throw 'Invalid package changed the installed root ACL.'
                }
                'fail-closed-before-mutation'
            } '{{Escape(_fixture.PackageRoot)}}'
            """;

        var result = _fixture.RunInlinePowerShell(script);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        result.StandardOutput.Trim().Should().Be(
            "fail-closed-before-mutation");
    }

    [Fact]
    public void AuthenticatedBundleProvisioning_ReparsePointFailsBeforeAclMutation()
    {
        _fixture.Package().ExitCode.Should().Be(0);
        var target = Path.Combine(_fixture.Root, "junction-target");
        var junction = Path.Combine(_fixture.PackageRoot, "unsafe-junction");
        Directory.CreateDirectory(target);
        var createJunction = _fixture.RunInlinePowerShell(
            $$"""
              $ErrorActionPreference = 'Stop'
              New-Item `
                  -ItemType Junction `
                  -Path '{{Escape(junction)}}' `
                  -Target '{{Escape(target)}}' | Out-Null
              """);
        createJunction.ExitCode.Should().Be(
            0,
            createJunction.CombinedOutput);
        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $module = Import-Module '{{Escape(modulePath)}}' -Force -PassThru
            & $module {
                param($PackageRoot)
                if ($null -eq (Get-Command `
                        Set-WgstAuthenticatedBundledReleaseAcl `
                        -ErrorAction SilentlyContinue)) {
                    throw 'ACL provisioner is missing.'
                }
                $before = [Convert]::ToBase64String(
                    (Get-WgstFileSystemSecurity `
                        -Path $PackageRoot `
                        -Directory $true).
                            GetSecurityDescriptorBinaryForm())
                $rejected = $false
                try {
                    Set-WgstAuthenticatedBundledReleaseAcl `
                        -PackageRoot $PackageRoot
                }
                catch {
                    $rejected = $true
                }
                $after = [Convert]::ToBase64String(
                    (Get-WgstFileSystemSecurity `
                        -Path $PackageRoot `
                        -Directory $true).
                            GetSecurityDescriptorBinaryForm())
                if (-not $rejected -or $before -cne $after) {
                    throw 'Unsafe package changed the installed root ACL.'
                }
                'reparse-fail-closed'
            } '{{Escape(_fixture.PackageRoot)}}'
            """;

        var result = _fixture.RunInlinePowerShell(script);

        if (Directory.Exists(junction))
        {
            Directory.Delete(junction);
        }
        result.ExitCode.Should().Be(0, result.CombinedOutput);
        result.StandardOutput.Trim().Should().Be("reparse-fail-closed");
    }

    [Fact]
    public void InstallerContract_HardensOnlyBundledReleaseBeforeSelfTest()
    {
        var path = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "install.ps1");
        var script = File.ReadAllText(path);
        var guard = script.IndexOf(
            "if ($installMode -eq 'BundledRelease')",
            StringComparison.Ordinal);
        var harden = script.IndexOf(
            "Set-WgstAuthenticatedBundledReleaseAcl",
            guard,
            StringComparison.Ordinal);
        var selfTest = script.IndexOf(
            "Launching app for post-install self test",
            StringComparison.Ordinal);

        guard.Should().BeGreaterThanOrEqualTo(0);
        harden.Should().BeGreaterThan(guard);
        selfTest.Should().BeGreaterThan(harden);
    }

    [Theory]
    [InlineData("start.cmd")]
    [InlineData("start-admin.cmd")]
    [InlineData("start-safe.cmd")]
    [InlineData("install.cmd")]
    [InlineData("test.cmd")]
    [InlineData("diagnose.cmd")]
    public void LauncherLogs_AreWrittenUnderPerUserLocalAppData(
        string fileName)
    {
        var script = File.ReadAllText(
            Path.Combine(_fixture.ActualRepositoryRoot, fileName));

        script.Should().Contain(
            "set \"LOG_DIR=%LOCALAPPDATA%\\WireguardSplitTunnel\\logs\"");
        script.Should().NotContain("set \"LOG_DIR=%SCRIPT_DIR%logs\"");
    }

    [Fact]
    public void RuntimePackageValidation_DoesNotRequireDotnetOrToolSources()
    {
        _fixture.Package().ExitCode.Should().Be(0);
        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $module = Import-Module '{{Escape(modulePath)}}' -Force -PassThru
            & $module {
                param($PackageRoot, $Props, $Tag)
                Test-WgstReleasePackageNoSdk `
                    -PackageRoot $PackageRoot `
                    -Props $Props `
                    -ExpectedTag $Tag
            } `
                '{{Escape(_fixture.PackageRoot)}}' `
                '{{Escape(_fixture.PropsPath)}}' `
                'v{{_fixture.Version}}'
            """;

        var result = _fixture.RunInlinePowerShell(
            script,
            new Dictionary<string, string>
            {
                ["PATH"] = string.Empty
            });

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        result.StandardOutput.Should().Contain("True");
    }

    [Fact]
    public void Packaging_DoesNotTouchRepresentativeLegacyLocalAppData()
    {
        var localAppData = Path.Combine(
            _fixture.Root,
            "legacy-local-app-data");
        Directory.CreateDirectory(localAppData);
        var state = Path.Combine(localAppData, "state.json");
        var applied = Path.Combine(
            localAppData,
            "applied-domains.json");
        File.WriteAllBytes(state, [1, 2, 3, 4]);
        File.WriteAllBytes(applied, [5, 6, 7, 8]);
        var before = Directory.EnumerateFiles(localAppData)
            .ToDictionary(
                path => Path.GetFileName(path)!,
                File.ReadAllBytes,
                StringComparer.Ordinal);

        var result = ReleaseScriptFixture.RunPowerShell(
            Path.Combine(
                _fixture.ActualRepositoryRoot,
                "scripts",
                "package-windows.ps1"),
            [
                "-Tag", $"v{_fixture.Version}",
                "-OutputRoot", _fixture.OutputRoot,
                "-RepositoryRoot", _fixture.RepositoryRoot,
                "-AppPublishRoot", _fixture.AppPublishRoot,
                "-UpdaterPublishRoot", _fixture.UpdaterPublishRoot,
                "-Props", _fixture.PropsPath
            ],
            new Dictionary<string, string>
            {
                ["LOCALAPPDATA"] = localAppData
            });

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        foreach (var pair in before)
        {
            File.ReadAllBytes(
                    Path.Combine(localAppData, pair.Key))
                .Should().Equal(pair.Value);
        }
    }

    [Fact]
    public void RepairBlockedUpdate_RequiresExplicitSwitchAndPreservesEvidence()
    {
        _fixture.Package().ExitCode.Should().Be(0);
        var repair = CreateBlockedRepairFixture();

        var withoutExplicit = InvokeRepair(
            repair,
            explicitRepair: false);
        withoutExplicit.ExitCode.Should().NotBe(0);
        ReadActiveTransactionId(repair.ActivePointerPath)
            .Should().Be(repair.TransactionId);

        var recordBefore = File.ReadAllBytes(repair.RecordPath);
        var journalBefore = File.ReadAllBytes(repair.JournalPath);
        var backupBefore = File.ReadAllBytes(repair.BackupPath);
        var completed = InvokeRepair(
            repair,
            explicitRepair: true);

        completed.ExitCode.Should().Be(0, completed.CombinedOutput);
        ReadActiveTransactionId(repair.ActivePointerPath)
            .Should().BeNull();
        File.ReadAllBytes(repair.RecordPath)
            .Should().Equal(recordBefore);
        File.ReadAllBytes(repair.JournalPath)
            .Should().Equal(journalBefore);
        File.ReadAllBytes(repair.BackupPath)
            .Should().Equal(backupBefore);
        File.Exists(repair.ResolutionPath).Should().BeTrue();
        File.ReadAllText(repair.PointerBackupPath)
            .Should().Contain(repair.TransactionId);
    }

    [Fact]
    public void RepairBlockedUpdate_IgnoresPermittedRuntimeExtrasButComparesManagedPayloads()
    {
        _fixture.Package().ExitCode.Should().Be(0);
        var repair = CreateBlockedRepairFixture();
        Directory.CreateDirectory(
            Path.Combine(_fixture.PackageRoot, "logs"));
        File.WriteAllText(
            Path.Combine(_fixture.PackageRoot, "logs", "install.log"),
            "runtime log");
        File.WriteAllText(
            Path.Combine(_fixture.PackageRoot, "runtime.log"),
            "runtime marker");

        var result = InvokeRepair(repair, explicitRepair: true);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        ReadActiveTransactionId(repair.ActivePointerPath)
            .Should().BeNull();
    }

    [Fact]
    public void ProtectedRepairValidation_PreservesUnknownRegularFilesByteForByte()
    {
        _fixture.Package().ExitCode.Should().Be(0);
        var custom = Path.Combine(
            _fixture.PackageRoot,
            "custom",
            "operator-policy.bin");
        Directory.CreateDirectory(Path.GetDirectoryName(custom)!);
        var expected = new byte[] { 0, 255, 19, 37, 0, 128, 64 };
        File.WriteAllBytes(custom, expected);
        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $module = Import-Module '{{Escape(modulePath)}}' -Force -PassThru
            & $module {
                param($InstalledRoot, $ExpectedTag, $CustomPath)
                $before = [Convert]::ToBase64String(
                    [IO.File]::ReadAllBytes($CustomPath))
                $plan = Get-WgstAuthenticatedBundledReleaseAclPlan `
                    -PackageRoot $InstalledRoot `
                    -AllowInstalledExtras
                [void](Test-WgstReleasePackageNoSdk `
                    -PackageRoot $InstalledRoot `
                    -ExpectedTag $ExpectedTag `
                    -AllowInstalledExtras)
                $after = [Convert]::ToBase64String(
                    [IO.File]::ReadAllBytes($CustomPath))
                [ordered]@{
                    before = $before
                    after = $after
                    planned = @($plan.Files | ForEach-Object {
                        $_.RelativePath
                    })
                } | ConvertTo-Json -Depth 4 -Compress
            } `
                '{{Escape(_fixture.PackageRoot)}}' `
                'v{{_fixture.Version}}' `
                '{{Escape(custom)}}'
            """;

        var result = _fixture.RunInlinePowerShell(script);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        using var outcome = JsonDocument.Parse(result.StandardOutput.Trim());
        outcome.RootElement.GetProperty("before").GetString()
            .Should().Be(Convert.ToBase64String(expected));
        outcome.RootElement.GetProperty("after").GetString()
            .Should().Be(Convert.ToBase64String(expected));
        outcome.RootElement.GetProperty("planned")
            .EnumerateArray()
            .Select(element => element.GetString())
            .Should().NotContain("custom/operator-policy.bin");
    }

    [Fact]
    public void RepairBlockedUpdate_ResumesAfterResolutionBeforePointerFailure()
    {
        _fixture.Package().ExitCode.Should().Be(0);
        var repair = CreateBlockedRepairFixture();

        var interrupted = InvokeRepair(
            repair,
            explicitRepair: true,
            failBeforePointerReplace: true);

        interrupted.ExitCode.Should().NotBe(0);
        ReadActiveTransactionId(repair.ActivePointerPath)
            .Should().Be(repair.TransactionId);
        File.Exists(repair.ResolutionPath).Should().BeTrue();
        var resolutionBefore = File.ReadAllBytes(repair.ResolutionPath);

        var resumed = InvokeRepair(
            repair,
            explicitRepair: true);

        resumed.ExitCode.Should().Be(0, resumed.CombinedOutput);
        ReadActiveTransactionId(repair.ActivePointerPath)
            .Should().BeNull();
        File.ReadAllBytes(repair.ResolutionPath)
            .Should().Equal(resolutionBefore);
        File.ReadAllText(repair.PointerBackupPath)
            .Should().Contain(repair.TransactionId);
    }

    [Fact]
    public void ProductionRepairAcl_RejectsOrdinaryUserOwnedFixture()
    {
        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var ordinary = Path.Combine(_fixture.Root, "ordinary-acl");
        Directory.CreateDirectory(ordinary);
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $module = Import-Module '{{Escape(modulePath)}}' -Force -PassThru
            & $module {
                param($Path)
                Test-WgstProtectedRepairAcl -Path $Path
            } '{{Escape(ordinary)}}'
            """;

        var result = _fixture.RunInlinePowerShell(script);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        result.StandardOutput.Trim().Should().Be("False");
    }

    [Fact]
    public void ProtectedDescriptorBuilder_UsesExactSystemAndAdministratorsAcl()
    {
        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $module = Import-Module '{{Escape(modulePath)}}' -Force -PassThru
            & $module {
                foreach ($directory in @($true, $false)) {
                    $security =
                        New-WgstExactProtectedSecurity -Directory $directory
                    $raw =
                        [Security.AccessControl.RawSecurityDescriptor]::new(
                            $security.GetSecurityDescriptorBinaryForm(),
                            0)
                    $protected =
                        [Security.AccessControl.ControlFlags]::
                            DiscretionaryAclProtected
                    if ($raw.Owner.Value -cne 'S-1-5-18' -or
                        $raw.DiscretionaryAcl.Count -ne 2 -or
                        ($raw.ControlFlags -band $protected) -eq 0) {
                        throw 'Exact protected descriptor header is invalid.'
                    }
                    $expectedFlags = if ($directory) {
                        [Security.AccessControl.AceFlags](
                            [int][Security.AccessControl.AceFlags]::
                                ContainerInherit -bor
                            [int][Security.AccessControl.AceFlags]::
                                ObjectInherit)
                    }
                    else {
                        [Security.AccessControl.AceFlags]::None
                    }
                    $identities = @()
                    foreach ($ace in $raw.DiscretionaryAcl) {
                        if (-not ($ace -is
                                [Security.AccessControl.CommonAce]) -or
                            $ace.AceQualifier -ne
                                [Security.AccessControl.AceQualifier]::
                                    AccessAllowed -or
                            $ace.AccessMask -ne
                                [int][Security.AccessControl.FileSystemRights]::
                                    FullControl -or
                            $ace.AceFlags -ne $expectedFlags) {
                            throw 'Exact protected ACE is invalid.'
                        }
                        $identities += $ace.SecurityIdentifier.Value
                    }
                    if (($identities | Sort-Object) -join ',' -cne
                        'S-1-5-18,S-1-5-32-544') {
                        throw 'Exact protected SID set is invalid.'
                    }
                }
                'exact'
            }
            """;

        var result = _fixture.RunInlinePowerShell(script);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        result.StandardOutput.Trim().Should().Be("exact");
    }

    [Fact]
    public void RestorePrivilegeScope_RestoreFailureIsFailClosed()
    {
        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            Import-Module '{{Escape(modulePath)}}' -Force
            if (-not [WireguardSplitTunnel.ReleaseScripts.NativeFileIdentity]::
                    RestoreFailureIsFailClosedForTests()) {
                throw 'Restore privilege failure was ignored.'
            }
            'fail-closed'
            """;

        var result = _fixture.RunInlinePowerShell(script);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        result.StandardOutput.Trim().Should().Be("fail-closed");
    }

    [Fact]
    public void ProtectedWorkspace_RejectsPrecreatedOrdinaryUserRoot()
    {
        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var ordinary = Path.Combine(
            _fixture.Root,
            "ordinary-precreated-protected-root");
        Directory.CreateDirectory(ordinary);
        var sentinel = Path.Combine(ordinary, "user-controlled.txt");
        File.WriteAllText(sentinel, "do not trust");
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $module = Import-Module '{{Escape(modulePath)}}' -Force -PassThru
            & $module {
                param($Path)
                New-WgstProtectedWorkspace `
                    -ProtectedRoot $Path `
                    -Purpose bootstrap `
                    -CreateProtectedRoot
            } '{{Escape(ordinary)}}'
            """;

        var result = _fixture.RunInlinePowerShell(script);

        result.ExitCode.Should().NotBe(0);
        File.ReadAllText(sentinel).Should().Be("do not trust");
        Directory.EnumerateDirectories(ordinary).Should().BeEmpty();
    }

    [Fact]
    public void BootstrapAndRepair_NeverUseAnOrdinaryTempWorkspace()
    {
        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $module = Import-Module '{{Escape(modulePath)}}' -Force -PassThru
            & $module {
                $bootstrap = ${function:Invoke-WgstBootstrapRelease}.ToString()
                $repair =
                    ${function:Invoke-WgstAuthenticatedBlockedRepair}.ToString()
                if ($bootstrap -notmatch 'New-WgstProtectedWorkspace' -or
                    $repair -notmatch 'New-WgstProtectedWorkspace' -or
                    $bootstrap -match 'GetTempPath' -or
                    $repair -match 'GetTempPath') {
                    throw 'Bootstrap or repair uses an ordinary temp workspace.'
                }
                'protected'
            }
            """;

        var result = _fixture.RunInlinePowerShell(script);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        result.StandardOutput.Trim().Should().Be("protected");
    }

    [Fact]
    public void RepairBlockedUpdate_InvalidBundledPackageLeavesPointerActive()
    {
        _fixture.Package().ExitCode.Should().Be(0);
        var repair = CreateBlockedRepairFixture();
        File.AppendAllText(
            Path.Combine(
                _fixture.PackageRoot,
                "scripts",
                "start.ps1"),
            "tamper");

        var result = InvokeRepair(repair, explicitRepair: true);

        result.ExitCode.Should().NotBe(0);
        ReadActiveTransactionId(repair.ActivePointerPath)
            .Should().Be(repair.TransactionId);
        File.Exists(repair.ResolutionPath).Should().BeFalse();
    }

    public void Dispose() => _fixture.Dispose();

    private ScriptProcessResult InvokeInstallMode(
        bool hasManifest,
        bool hasBundledExecutable,
        bool hasSourceProject,
        bool hasProps,
        bool hasSdk,
        bool skipPublish,
        bool forcePublish)
    {
        var library = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "lib",
            "release-package.ps1");
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(library)}}'
            Get-WgstInstallMode `
                -HasManifest {{Ps(hasManifest)}} `
                -HasBundledExecutable {{Ps(hasBundledExecutable)}} `
                -HasSourceProject {{Ps(hasSourceProject)}} `
                -HasProps {{Ps(hasProps)}} `
                -HasSdk {{Ps(hasSdk)}} `
                -SkipPublish {{Ps(skipPublish)}} `
                -ForcePublish {{Ps(forcePublish)}}
            """;
        return _fixture.RunInlinePowerShell(script);
    }

    private ScriptProcessResult InvokeRepair(
        BlockedRepairFixture repair,
        bool explicitRepair,
        bool failBeforePointerReplace = false)
    {
        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $module = Import-Module '{{Escape(modulePath)}}' -Force -PassThru
            & $module {
                param(
                    $ProtectedRoot,
                    $BundledRoot,
                    $AuthenticatedRoot,
                    $AuthenticatedArchive,
                    $Props,
                    $Tag,
                    $InstalledRoot,
                    [bool]$ExplicitRepair,
                    [bool]$FailBeforePointerReplace)
                $aclValidator = { param($Path) return $true }
                $protectedFileWriter = {
                    param($Path, $Text)
                    [IO.File]::WriteAllText(
                        $Path,
                        $Text,
                        [Text.UTF8Encoding]::new($false))
                    return $Path
                }
                $beforePointerReplace = {}
                if ($FailBeforePointerReplace) {
                    $beforePointerReplace = {
                        throw 'Injected failure before pointer replacement.'
                    }
                }
                Invoke-WgstRepairBlockedState `
                    -ProtectedRoot $ProtectedRoot `
                    -BundledPackageRoot $BundledRoot `
                    -AuthenticatedPackageRoot $AuthenticatedRoot `
                    -AuthenticatedArchivePath $AuthenticatedArchive `
                    -Props $Props `
                    -ExpectedTag $Tag `
                    -ExplicitRepair:$ExplicitRepair `
                    -ExpectedInstallRoot $InstalledRoot `
                    -AclValidator $aclValidator `
                    -ProtectedFileWriter $protectedFileWriter `
                    -InstallRootValidator { param($Path) $true } `
                    -InstalledReleaseRepairAction {
                        param($InstallRoot, $AuthenticatedRoot)
                        return $InstallRoot
                    } `
                    -InstalledReleaseValidator {
                        param($InstallRoot, $AuthenticatedRoot)
                        return $true
                    } `
                    -BeforePointerReplace $beforePointerReplace
            } `
                '{{Escape(repair.ProtectedRoot)}}' `
                '{{Escape(_fixture.PackageRoot)}}' `
                '{{Escape(repair.AuthenticatedPackageRoot)}}' `
                '{{Escape(repair.AuthenticatedArchivePath)}}' `
                '{{Escape(_fixture.PropsPath)}}' `
                'v{{_fixture.Version}}' `
                '{{Escape(repair.InstalledRoot)}}' `
                {{Ps(explicitRepair)}} `
                {{Ps(failBeforePointerReplace)}}
            """;
        return _fixture.RunInlinePowerShell(script);
    }

    private BlockedRepairFixture CreateBlockedRepairFixture()
    {
        var transactionId =
            "00112233445566778899aabbccddeeff";
        var protectedRoot = Path.Combine(
            _fixture.Root,
            $"protected-{Guid.NewGuid():N}");
        var transactionsRoot = Path.Combine(
            protectedRoot,
            "UpdateTransactions");
        var transactionRoot = Path.Combine(
            transactionsRoot,
            transactionId);
        var backupsRoot = Path.Combine(
            transactionRoot,
            "backups");
        Directory.CreateDirectory(backupsRoot);
        var active = Path.Combine(
            transactionsRoot,
            "active-transaction.json");
        var record = Path.Combine(
            transactionRoot,
            "transaction.json");
        var journal = Path.Combine(
            transactionRoot,
            "journal.json");
        var backup = Path.Combine(
            backupsRoot,
            "app.exe.bak");
        var installedRoot = Path.Combine(
            _fixture.Root,
            $"installed-{Guid.NewGuid():N}");
        CopyDirectory(_fixture.PackageRoot, installedRoot);
        var authenticatedArchive = Path.Combine(
            _fixture.Root,
            $"authenticated-{Guid.NewGuid():N}.zip");
        File.WriteAllBytes(authenticatedArchive, [1, 3, 3, 7]);
        var archiveSha256 = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                File.ReadAllBytes(authenticatedArchive)))
            .ToLowerInvariant();
        var manifestSha256 = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                File.ReadAllBytes(Path.Combine(
                    _fixture.PackageRoot,
                    UpdateReleaseContract.ReleaseManifestPath))))
            .ToLowerInvariant();
        File.WriteAllText(
            active,
            $$"""{"schemaVersion":1,"transactionId":"{{transactionId}}"}""");
        File.WriteAllText(
            record,
            JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                transactionId,
                phase = "RecoveryBlocked",
                version = _fixture.Version,
                installedRelease = new
                {
                    installRoot = installedRoot
                },
                candidate = new
                {
                    archiveSha256,
                    newManifestSha256 = manifestSha256
                }
            }));
        File.WriteAllText(journal, """{"generation":9}""");
        File.WriteAllBytes(backup, [9, 8, 7, 6]);

        var authenticated = Path.Combine(
            _fixture.Root,
            $"authenticated-{Guid.NewGuid():N}");
        CopyDirectory(_fixture.PackageRoot, authenticated);
        return new BlockedRepairFixture(
            protectedRoot,
            transactionId,
            active,
            record,
            journal,
            backup,
            Path.Combine(
                transactionRoot,
                "repair-resolution.json"),
            Path.Combine(
                transactionRoot,
                "active-pointer-before-repair.json"),
            authenticated,
            authenticatedArchive,
            installedRoot);
    }

    private static string? ReadActiveTransactionId(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(path));
        var property = document.RootElement
            .GetProperty("transactionId");
        return property.ValueKind == JsonValueKind.Null
            ? null
            : property.GetString();
    }

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var directory in Directory.EnumerateDirectories(
                     source,
                     "*",
                     SearchOption.AllDirectories))
        {
            Directory.CreateDirectory(
                Path.Combine(
                    destination,
                    Path.GetRelativePath(source, directory)));
        }

        foreach (var file in Directory.EnumerateFiles(
                     source,
                     "*",
                     SearchOption.AllDirectories))
        {
            var target = Path.Combine(
                destination,
                Path.GetRelativePath(source, file));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target);
        }
    }

    private static string Escape(string value) =>
        value.Replace("'", "''", StringComparison.Ordinal);

    private static string Ps(bool value) =>
        value ? "$true" : "$false";

    private sealed record BlockedRepairFixture(
        string ProtectedRoot,
        string TransactionId,
        string ActivePointerPath,
        string RecordPath,
        string JournalPath,
        string BackupPath,
        string ResolutionPath,
        string PointerBackupPath,
        string AuthenticatedPackageRoot,
        string AuthenticatedArchivePath,
        string InstalledRoot);
}
