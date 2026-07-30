using System.Text.Json;
using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class InstalledReleaseLocatorTests
{
    [Fact]
    public void Locate_RecognizesOnlyTheExactInstalledReleaseLayout()
    {
        using var layout = new ReleaseLayout();
        var locator = layout.CreateLocator();

        var result = locator.Locate(layout.ApplicationPath);

        result.Status.Should().Be(InstalledReleaseLocatorStatus.Available);
        result.InstallationRoot.Should().Be(layout.Root);
        result.ApplicationPath.Should().Be(layout.ApplicationPath);
        result.UpdaterPath.Should().Be(layout.UpdaterPath);
        result.Version.Should().Be(new SemanticVersion(1, 2, 3));
    }

    [Fact]
    public void Locate_RejectsAValidPortableReleaseOutsideTheProtectedAnchor()
    {
        using var layout = new ReleaseLayout();
        var otherRoot = Path.Combine(
            Path.GetTempPath(),
            "WireguardSplitTunnel.WindowsUpdate.Tests",
            Guid.NewGuid().ToString("N"));
        var locator = layout.CreateLocator(
            security: new FakeInstalledReleaseSecurity(otherRoot));

        var result = locator.Locate(layout.ApplicationPath);

        AssertUnavailable(result);
        result.DetailCode.Should().Be("unprotected_installation_root");
    }

    [Fact]
    public void Locate_RejectsAProtectedAnchorWithNonExactManagedAcls()
    {
        using var layout = new ReleaseLayout();
        var locator = layout.CreateLocator(
            security: new FakeInstalledReleaseSecurity(
                layout.Root,
                exactManagedSecurity: false));

        var result = locator.Locate(layout.ApplicationPath);

        AssertUnavailable(result);
        result.DetailCode.Should().Be("installed_release_acl");
    }

    [Fact]
    public void Locate_ValidatesTheManifestAndEveryManagedPathAgainstTheInstalledAcl()
    {
        using var layout = new ReleaseLayout();
        var security = new FakeInstalledReleaseSecurity(layout.Root);

        layout.CreateLocator(security: security)
            .Locate(layout.ApplicationPath)
            .Status.Should().Be(InstalledReleaseLocatorStatus.Available);

        security.ValidatedPaths.Should().BeEquivalentTo(
            new[] { UpdateReleaseContract.ReleaseManifestPath }
                .Concat(layout.ManifestManagedPaths),
            options => options.WithStrictOrdering());
    }

    [Fact]
    public void AcquireLaunchLease_FailsClosedWhenTheProtectedNamespaceCannotBePinned()
    {
        using var layout = new ReleaseLayout();
        var security = new FakeInstalledReleaseSecurity(
            layout.Root,
            acquireLaunchLease: _ => null);

        using var lease = layout.CreateLocator(security: security)
            .AcquireLaunchLease(layout.ApplicationPath);

        lease.Should().BeNull();
        security.ExactSecurityValidationCount.Should().Be(0);
    }

    [Fact]
    public void AcquireLaunchLease_RunsFullLocatorValidationWhileThePinsAreHeld()
    {
        using var layout = new ReleaseLayout();
        var events = new List<string>();
        var resource = new RecordingDisposable(
            () => events.Add("lease-disposed"));
        var security = new FakeInstalledReleaseSecurity(
            layout.Root,
            events: events,
            acquireLaunchLease: applicationPath =>
            {
                events.Add("lease-acquired");
                return new InstalledReleaseLaunchLease(
                    applicationPath,
                    resource,
                    () =>
                    {
                        events.Add("lease-revalidated");
                        return true;
                    });
            });

        using var lease = layout.CreateLocator(security: security)
            .AcquireLaunchLease(layout.ApplicationPath);

        lease.Should().NotBeNull();
        security.ExactSecurityValidationCount.Should().Be(1);
        events.Should().StartWith(
            "lease-acquired",
            "full-validation",
            "lease-revalidated");
    }

    [Fact]
    public void LaunchLease_RevalidationFailureBlocksTheLaunchHook()
    {
        var disposed = false;
        var invoked = false;
        var lease = new InstalledReleaseLaunchLease(
            @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel\WireguardSplitTunnel.App.exe",
            new RecordingDisposable(() => disposed = true),
            () => false);

        var launched = lease.TryLaunch(_ =>
        {
            invoked = true;
            return true;
        });

        launched.Should().BeFalse();
        invoked.Should().BeFalse();
        disposed.Should().BeTrue();
    }

    [Fact]
    public void LaunchLease_DisposesOnlyAfterTheLaunchHookReturns()
    {
        var disposed = false;
        var lease = new InstalledReleaseLaunchLease(
            @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel\WireguardSplitTunnel.App.exe",
            new RecordingDisposable(() => disposed = true),
            () => true);

        var launched = lease.TryLaunch(applicationPath =>
        {
            applicationPath.Should().EndWith(
                "WireguardSplitTunnel.App.exe");
            disposed.Should().BeFalse();
            return true;
        });

        launched.Should().BeTrue();
        disposed.Should().BeTrue();
    }

    [Fact]
    public void LaunchLease_DisposesOnlyAfterTheLaunchHookThrows()
    {
        var disposed = false;
        var lease = new InstalledReleaseLaunchLease(
            @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel\WireguardSplitTunnel.App.exe",
            new RecordingDisposable(() => disposed = true),
            () => true);

        var act = () => lease.TryLaunch(_ =>
        {
            disposed.Should().BeFalse();
            throw new InvalidOperationException("launch failed");
        });

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("launch failed");
        disposed.Should().BeTrue();
    }

    [Theory]
    [InlineData("bin")]
    [InlineData("TestResults")]
    [InlineData(".vs")]
    public void Locate_RejectsDeveloperAndTestOutputLayouts(string directory)
    {
        using var layout = new ReleaseLayout(directory);

        AssertUnavailable(layout.CreateLocator().Locate(layout.ApplicationPath));
    }

    [Fact]
    public void Locate_RejectsMissingReleaseMarkerWithoutExposingTheInstallRoot()
    {
        using var layout = new ReleaseLayout();
        File.Delete(Path.Combine(layout.Root, UpdateReleaseContract.ReleaseManifestPath));

        AssertUnavailable(layout.CreateLocator().Locate(layout.ApplicationPath));
    }

    [Fact]
    public void Locate_RejectsWrongManifestVersionOrExecutableProductVersion()
    {
        using var layout = new ReleaseLayout();
        layout.WriteManifest("1.2.4");

        AssertUnavailable(layout.CreateLocator().Locate(layout.ApplicationPath));
    }

    [Fact]
    public void Locate_RejectsMissingUpdaterOrRequiredRootLauncher()
    {
        using var layout = new ReleaseLayout();
        File.Delete(layout.UpdaterPath);

        AssertUnavailable(layout.CreateLocator().Locate(layout.ApplicationPath));
    }

    [Fact]
    public void Locate_RejectsAReparseInstallationRootWithoutExposingTheInstallRoot()
    {
        using var layout = new ReleaseLayout();
        var locator = layout.CreateLocator(path => path.Equals(layout.Root, StringComparison.OrdinalIgnoreCase));

        AssertUnavailable(locator.Locate(layout.ApplicationPath));
    }

    [Fact]
    public void Locate_RejectsUncPathsWithoutExposingTheInstallRoot()
    {
        var locator = new InstalledReleaseLocator(new FakeVersionReader(), new WindowsPathSafetyInspector());

        AssertUnavailable(locator.Locate("\\\\server\\share\\WireguardSplitTunnel\\WireguardSplitTunnel.App.exe"));
    }

    [Theory]
    [InlineData("relative\\WireguardSplitTunnel.App.exe")]
    [InlineData("C:WireguardSplitTunnel.App.exe")]
    [InlineData("\\WireguardSplitTunnel.App.exe")]
    [InlineData("//server/share/WireguardSplitTunnel.App.exe")]
    [InlineData("\\\\?\\C:\\app.exe")]
    [InlineData("\\\\.\\C:\\app.exe")]
    [InlineData("\\\\??\\C:\\app.exe")]
    public void Locate_RejectsNonCanonicalOrNamespaceExecutablePaths(string path)
    {
        AssertUnavailable(new InstalledReleaseLocator(new FakeVersionReader(), new WindowsPathSafetyInspector()).Locate(path));
    }

    [Theory]
    [InlineData(UpdateReleaseContract.WindowsApplicationPath)]
    [InlineData(UpdateReleaseContract.WindowsUpdaterPath)]
    [InlineData("start.cmd")]
    public void Locate_RejectsSameLengthPayloadTampering(string releasePath)
    {
        using var layout = new ReleaseLayout();
        layout.ReplaceWithSameLength(releasePath);

        AssertUnavailable(layout.CreateLocator().Locate(layout.ApplicationPath));
    }

    [Theory]
    [InlineData("logs/runtime.log")]
    [InlineData("backup/file.txt")]
    [InlineData("data/state.json")]
    [InlineData("data/file.conf")]
    [InlineData("data/file.dpapi")]
    [InlineData("data/file.bak")]
    [InlineData("data/file.tmp")]
    [InlineData("data/candidate-metadata.json")]
    [InlineData("data/transaction-metadata.json")]
    public void Locate_RejectsProtectedManifestPayloadPath(string protectedPath)
    {
        using var layout = new ReleaseLayout();
        layout.AddPayload(protectedPath, "x");

        AssertUnavailable(layout.CreateLocator().Locate(layout.ApplicationPath));
    }

    [Fact]
    public void Locate_RejectsUnsupportedInstalledStateSchema()
    {
        using var layout = new ReleaseLayout();
        layout.SetStateSchemaVersion(2);

        AssertUnavailable(layout.CreateLocator().Locate(layout.ApplicationPath));
    }

    [Fact]
    public void Locate_RejectsOversizedOrReparseManifest()
    {
        using var oversized = new ReleaseLayout();
        oversized.MakeManifestOversized();
        AssertUnavailable(oversized.CreateLocator().Locate(oversized.ApplicationPath));

        using var reparse = new ReleaseLayout();
        AssertUnavailable(reparse.CreateLocator(path => path.Equals(reparse.ManifestPath, StringComparison.OrdinalIgnoreCase)).Locate(reparse.ApplicationPath));
    }

    [Fact]
    public void Locate_AcceptsPackageBelowAnUnrelatedDistantBinAncestor()
    {
        using var layout = new ReleaseLayout(rootChild: "bin", nestedRoot: true);

        layout.CreateLocator().Locate(layout.ApplicationPath).Status.Should().Be(InstalledReleaseLocatorStatus.Available);
    }

    [Fact]
    public void ReleaseLayout_DisposeDeletesItsExactTestOwnedRoot()
    {
        var layout = new ReleaseLayout(rootChild: "bin", nestedRoot: true);
        var testOwnedRoot = layout.TestOwnedRoot;

        layout.Dispose();

        Directory.Exists(testOwnedRoot).Should().BeFalse();
    }

    private static void AssertUnavailable(InstalledReleaseLocation result)
    {
        result.Status.Should().Be(InstalledReleaseLocatorStatus.AutomaticInstallationUnavailable);
        result.InstallationRoot.Should().BeNull();
        result.ApplicationPath.Should().BeNull();
        result.UpdaterPath.Should().BeNull();
        result.Version.Should().BeNull();
    }

    private sealed class ReleaseLayout : IDisposable
    {
        private readonly Dictionary<string, string> _versions = new(StringComparer.OrdinalIgnoreCase);
        private readonly string _testOwnedRoot;

        public ReleaseLayout(string? rootChild = null, bool nestedRoot = false)
        {
            var basePath = Path.Combine(Path.GetTempPath(), "WireguardSplitTunnel.WindowsUpdate.Tests", Guid.NewGuid().ToString("N"));
            _testOwnedRoot = basePath;
            Root = rootChild is null ? basePath : nestedRoot ? Path.Combine(basePath, rootChild, "unrelated", "release") : Path.Combine(basePath, rootChild);
            ApplicationPath = Path.Combine(Root, "WireguardSplitTunnel", "WireguardSplitTunnel.App.exe");
            UpdaterPath = Path.Combine(Root, "WireguardSplitTunnel", "WireguardSplitTunnel.Updater.exe");
            Directory.CreateDirectory(Path.GetDirectoryName(ApplicationPath)!);
            File.WriteAllText(ApplicationPath, "application");
            File.WriteAllText(UpdaterPath, "updater");
            _versions[ApplicationPath] = "1.2.3";
            _versions[UpdaterPath] = "1.2.3";

            foreach (var launcher in UpdateReleaseContract.RequiredLauncherPaths)
            {
                var path = ToPath(launcher);
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.WriteAllText(path, launcher);
            }

            WriteManifest("1.2.3");
        }

        public string Root { get; }
        public string ApplicationPath { get; }
        public string UpdaterPath { get; }
        public string ManifestPath => Path.Combine(Root, UpdateReleaseContract.ReleaseManifestPath);
        public string TestOwnedRoot => _testOwnedRoot;

        public IReadOnlyList<string> ManifestManagedPaths =>
            JsonSerializer.Deserialize<ReleaseManifest>(
                File.ReadAllText(ManifestPath),
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                })!.Files!.Select(file => file.Path).ToArray();

        public InstalledReleaseLocator CreateLocator(
            Func<string, bool>? reparse = null,
            IInstalledReleaseSecurityValidator? security = null) =>
            new(
                new FakeVersionReader(_versions),
                new FakePathSafetyInspector(reparse),
                security ?? new FakeInstalledReleaseSecurity(Root));

        public void WriteManifest(string version)
        {
            var files = new[]
            {
                UpdateReleaseContract.WindowsApplicationPath,
                UpdateReleaseContract.WindowsUpdaterPath
            }.Concat(UpdateReleaseContract.RequiredLauncherPaths)
                .Select(path => new ReleasePayloadFile(path, new FileInfo(ToPath(path)).Length, Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(ToPath(path)))).ToLowerInvariant()))
                .ToArray();
            var manifest = new ReleaseManifest(1, version, UpdateReleaseContract.WindowsRuntimeIdentifier, "1.0.0", "1.0.0", 1,
                UpdateReleaseContract.WindowsApplicationPath, UpdateReleaseContract.WindowsUpdaterPath,
                UpdateReleaseContract.RequiredLauncherPaths, files);
            File.WriteAllText(
                ManifestPath,
                JsonSerializer.Serialize(manifest, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));
        }

        public void ReplaceWithSameLength(string releasePath)
        {
            var path = ToPath(releasePath);
            File.WriteAllText(path, new string('z', checked((int)new FileInfo(path).Length)));
        }

        public void AddPayload(string releasePath, string content)
        {
            var path = ToPath(releasePath);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, content);
            var manifest = JsonSerializer.Deserialize<ReleaseManifest>(File.ReadAllText(ManifestPath), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
            File.WriteAllText(ManifestPath, JsonSerializer.Serialize(manifest with { Files = manifest.Files!.Append(new ReleasePayloadFile(releasePath, content.Length, Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(content))).ToLowerInvariant())).ToArray() }, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));
        }

        public void MakeManifestOversized() => File.WriteAllBytes(ManifestPath, new byte[UpdateNetworkLimits.MetadataBytes + 1]);

        public void SetStateSchemaVersion(int schemaVersion)
        {
            var manifest = JsonSerializer.Deserialize<ReleaseManifest>(File.ReadAllText(ManifestPath), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
            File.WriteAllText(ManifestPath, JsonSerializer.Serialize(manifest with { StateSchemaVersion = schemaVersion }, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(_testOwnedRoot, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        private string ToPath(string releasePath) =>
            Path.Combine(Root, releasePath.Replace('/', Path.DirectorySeparatorChar));

    }

    private sealed class FakeVersionReader(IReadOnlyDictionary<string, string>? versions = null) : IExecutableProductVersionReader
    {
        public string? ReadProductVersion(string executablePath) =>
            versions is not null && versions.TryGetValue(executablePath, out var version) ? version : null;
    }

    private sealed class FakePathSafetyInspector(Func<string, bool>? isReparsePoint) : IPathSafetyInspector
    {
        public bool IsReparsePoint(string path) => isReparsePoint?.Invoke(path) ?? false;
    }

    private sealed class FakeInstalledReleaseSecurity(
        string expectedRoot,
        bool exactManagedSecurity = true,
        List<string>? events = null,
        Func<string, InstalledReleaseLaunchLease?>?
            acquireLaunchLease = null)
        : IInstalledReleaseSecurityValidator
    {
        private readonly List<string> _validatedPaths = [];

        public IReadOnlyList<string> ValidatedPaths => _validatedPaths;
        public int ExactSecurityValidationCount { get; private set; }

        public bool IsExpectedProtectedRoot(string installationRoot) =>
            string.Equals(
                installationRoot,
                expectedRoot,
                StringComparison.OrdinalIgnoreCase);

        public bool HasExactInstalledSecurity(
            string installationRoot,
            IReadOnlyList<string> managedRelativePaths)
        {
            ExactSecurityValidationCount++;
            events?.Add("full-validation");
            _validatedPaths.AddRange(managedRelativePaths);
            return exactManagedSecurity;
        }

        public InstalledReleaseLaunchLease? TryAcquireLaunchLease(
            string applicationPath) =>
            acquireLaunchLease?.Invoke(applicationPath);
    }

    private sealed class RecordingDisposable(Action onDispose)
        : IDisposable
    {
        private bool _disposed;

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            onDispose();
        }
    }
}
