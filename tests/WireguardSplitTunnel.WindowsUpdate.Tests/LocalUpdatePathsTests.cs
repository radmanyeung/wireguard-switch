using System.Diagnostics;
using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Staging;
using WireguardSplitTunnel.WindowsUpdate.Validation;
using Xunit.Sdk;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class LocalUpdatePathsTests
{
    [Fact]
    public void GetLayout_DerivesEveryPathFromTheFixedLocalAppDataRoot()
    {
        using var root = new TemporaryDirectory();
        var paths = new LocalUpdatePaths(root.Path, new WindowsPathSafetyInspector(), _ => DriveType.Fixed);

        var result = paths.GetLayout(new SemanticVersion(1, 2, 3));

        result.Success.Should().BeTrue();
        result.Layout.Should().BeEquivalentTo(new LocalUpdateLayout(
            new SemanticVersion(1, 2, 3),
            root.ProductRoot,
            Path.Combine(root.ProductRoot, "update-metadata.json"),
            Path.Combine(root.ProductRoot, "updates"),
            Path.Combine(root.ProductRoot, "updates", "1.2.3"),
            Path.Combine(root.ProductRoot, "updates", "1.2.3", "staging"),
            Path.Combine(root.ProductRoot, "updates", "1.2.3", "staging", "wireguard-split-tunnel-win-x64.zip"),
            Path.Combine(root.ProductRoot, "updates", "1.2.3", "staging", "wireguard-split-tunnel-win-x64.zip.sha256"),
            Path.Combine(root.ProductRoot, "updates", "1.2.3", "candidate"),
            Path.Combine(root.ProductRoot, "updates", "1.2.3", "candidate", "release-manifest.json")));
        Directory.Exists(result.Layout!.CandidateRoot).Should().BeFalse();
    }

    [Theory]
    [InlineData("version")]
    [InlineData("productRoot")]
    [InlineData("metadataPath")]
    [InlineData("updatesRoot")]
    [InlineData("versionRoot")]
    [InlineData("stagingRoot")]
    [InlineData("archivePath")]
    [InlineData("checksumPath")]
    [InlineData("candidateRoot")]
    [InlineData("manifestPath")]
    public void TryValidateLayout_RecomputesEveryPathAndVersion(string mutation)
    {
        using var root = new TemporaryDirectory();
        var paths = root.CreatePaths();
        var layout = paths.GetLayout(new SemanticVersion(1, 2, 3)).Layout!;

        paths.TryValidateLayout(layout).Success.Should().BeTrue();

        var forged = new LocalUpdateLayout(
            mutation == "version" ? new SemanticVersion(9, 9, 9) : layout.Version,
            Mutate(layout.ProductRoot, mutation == "productRoot"),
            Mutate(layout.MetadataPath, mutation == "metadataPath"),
            Mutate(layout.UpdatesRoot, mutation == "updatesRoot"),
            Mutate(layout.VersionRoot, mutation == "versionRoot"),
            Mutate(layout.StagingRoot, mutation == "stagingRoot"),
            Mutate(layout.ArchivePath, mutation == "archivePath"),
            Mutate(layout.ChecksumPath, mutation == "checksumPath"),
            Mutate(layout.CandidateRoot, mutation == "candidateRoot"),
            Mutate(layout.ManifestPath, mutation == "manifestPath"));

        paths.TryValidateLayout(forged).Error.Should().Be(LocalUpdatePathError.MetadataMismatch);
    }

    [Fact]
    public void TryValidateLayout_RejectsNull()
    {
        using var root = new TemporaryDirectory();

        root.CreatePaths().TryValidateLayout(null).Error.Should().Be(LocalUpdatePathError.MetadataMismatch);
    }

    [Fact]
    public void EnsureStaging_CreatesOnlySafeParentsAndRevalidatesThem()
    {
        using var root = new TemporaryDirectory();
        var paths = root.CreatePaths();

        var result = paths.EnsureStaging(new SemanticVersion(1, 2, 3));

        result.Success.Should().BeTrue();
        Directory.Exists(result.Layout!.ProductRoot).Should().BeTrue();
        Directory.Exists(result.Layout.UpdatesRoot).Should().BeTrue();
        Directory.Exists(result.Layout.VersionRoot).Should().BeTrue();
        Directory.Exists(result.Layout.StagingRoot).Should().BeTrue();
        Directory.Exists(result.Layout.CandidateRoot).Should().BeFalse();
    }

    [Fact]
    public void EnsureStaging_CreatesOnlyFixedSegmentsThroughThePinnedDirectoryBoundary()
    {
        using var root = new TemporaryDirectory();
        var directories = new RecordingPinnedDirectoryService(PinnedDirectoryStatus.Unsafe);
        var paths = new LocalUpdatePaths(
            root.Path,
            new NeverReparse(),
            _ => DriveType.Fixed,
            new SwapAfterCheckFileSystem(),
            directories);

        var result = paths.EnsureStaging(new SemanticVersion(1, 2, 3));

        result.Error.Should().Be(LocalUpdatePathError.UnsafePath);
        directories.EnsureCalls.Should().ContainSingle();
        directories.EnsureCalls.Single().AnchorPath.Should().Be(root.Path);
        directories.EnsureCalls.Single().Segments.Should().Equal(
            "WireguardSplitTunnel",
            "updates",
            "1.2.3",
            "staging");
        Directory.Exists(root.ProductRoot).Should().BeFalse(
            "a create-time identity swap must fail before any unpinned fallback creation");
    }

    [Fact]
    public void EnsureRoot_CreatesOnlyTheFixedProductSegmentThroughThePinnedDirectoryBoundary()
    {
        using var root = new TemporaryDirectory();
        var directories = new RecordingPinnedDirectoryService(PinnedDirectoryStatus.Opened);
        var paths = new LocalUpdatePaths(
            root.Path,
            new NeverReparse(),
            _ => DriveType.Fixed,
            new SwapAfterCheckFileSystem(),
            directories);

        var result = paths.EnsureRoot();

        result.Success.Should().BeTrue();
        directories.EnsureCalls.Should().ContainSingle();
        directories.EnsureCalls.Single().AnchorPath.Should().Be(root.Path);
        directories.EnsureCalls.Single().Segments.Should().Equal("WireguardSplitTunnel");
    }

    [Theory]
    [InlineData(-1, 2, 3)]
    [InlineData(1, -2, 3)]
    [InlineData(1, 2, -3)]
    public void GetLayout_RejectsNegativeVersions(int major, int minor, int patch)
    {
        using var root = new TemporaryDirectory();

        root.CreatePaths().GetLayout(new SemanticVersion(major, minor, patch)).Success.Should().BeFalse();
    }

    [Fact]
    public void GetLayout_RejectsNetworkAndNonCanonicalRoots()
    {
        new LocalUpdatePaths("\\\\server\\share", new NeverReparse(), _ => DriveType.Fixed)
            .GetLayout(new SemanticVersion(1, 2, 3)).Success.Should().BeFalse();
        new LocalUpdatePaths("C:relative", new NeverReparse(), _ => DriveType.Fixed)
            .GetLayout(new SemanticVersion(1, 2, 3)).Success.Should().BeFalse();
        new LocalUpdatePaths("Z:\\local", new NeverReparse(), _ => DriveType.Network)
            .GetLayout(new SemanticVersion(1, 2, 3)).Success.Should().BeFalse();
    }

    [Theory]
    [InlineData("install-root")]
    [InlineData("C:\\Windows")]
    [InlineData("another-version")]
    [InlineData("\\\\server\\share")]
    [InlineData("..\\escape")]
    public void TryResolve_RejectsEveryForgedMetadataPath(string forgedPath)
    {
        using var root = new TemporaryDirectory();
        var paths = root.CreatePaths();
        var layout = paths.GetLayout(new SemanticVersion(1, 2, 3)).Layout!;
        var staged = new LocalStagedUpdate(
            new SemanticVersion(1, 2, 3),
            forgedPath, layout.ChecksumPath, layout.ManifestPath, layout.CandidateRoot,
            Hash('a'), Hash('b'), PendingUpdateSource.Automatic);

        paths.TryResolve(staged).Success.Should().BeFalse();
    }

    [Fact]
    public void CleanupVersion_DeletesOnlyTheComputedVersionRoot()
    {
        using var root = new TemporaryDirectory();
        var paths = root.CreatePaths();
        var first = paths.EnsureStaging(new SemanticVersion(1, 2, 3)).Layout!;
        var second = paths.EnsureStaging(new SemanticVersion(1, 2, 4)).Layout!;
        File.WriteAllText(Path.Combine(first.StagingRoot, "owned.txt"), "owned");
        File.WriteAllText(Path.Combine(second.StagingRoot, "sibling.txt"), "sibling");
        var unrelated = Path.Combine(root.Path, "unrelated.txt");
        File.WriteAllText(unrelated, "unrelated");

        paths.CleanupVersion(new SemanticVersion(1, 2, 3)).Success.Should().BeTrue();

        Directory.Exists(first.VersionRoot).Should().BeFalse();
        Directory.Exists(second.VersionRoot).Should().BeTrue();
        File.Exists(unrelated).Should().BeTrue();
    }

    [Fact]
    public void CleanupCandidate_DeletesOnlyTheDerivedCandidateTree()
    {
        using var root = new TemporaryDirectory();
        var paths = root.CreatePaths();
        var layout = paths.EnsureStaging(
            new SemanticVersion(1, 2, 3)).Layout!;
        File.WriteAllText(layout.ArchivePath, "archive");
        Directory.CreateDirectory(
            Path.Combine(layout.CandidateRoot, "payload"));
        File.WriteAllText(
            Path.Combine(layout.CandidateRoot, "payload", "app.exe"),
            "candidate");

        var result = paths.CleanupCandidate(layout.Version);

        result.Success.Should().BeTrue();
        Directory.Exists(layout.CandidateRoot).Should().BeFalse();
        File.Exists(layout.ArchivePath).Should().BeTrue();
        Directory.Exists(layout.StagingRoot).Should().BeTrue();
    }

    [Fact]
    public void CleanupVersion_RefusesAFileAtTheComputedVersionRoot()
    {
        using var root = new TemporaryDirectory();
        var paths = root.CreatePaths();
        var layout = paths.EnsureStaging(new SemanticVersion(1, 2, 3)).Layout!;
        Directory.Delete(layout.VersionRoot, recursive: true);
        File.WriteAllText(layout.VersionRoot, "not-a-directory");

        var result = paths.CleanupVersion(layout.Version);

        result.Error.Should().Be(LocalUpdatePathError.UnsafePath);
        File.ReadAllText(layout.VersionRoot).Should().Be("not-a-directory");
    }

    [Fact]
    public void CleanupVersion_FailsClosedWhenAnEntrySwapsAfterRevalidation()
    {
        using var root = new TemporaryDirectory();
        var fileSystem = new SwapAfterCheckFileSystem();
        var paths = new LocalUpdatePaths(root.Path, new NeverReparse(), _ => DriveType.Fixed, fileSystem);
        var layout = paths.GetLayout(new SemanticVersion(1, 2, 3)).Layout!;
        var child = Path.Combine(layout.VersionRoot, "owned.txt");
        fileSystem.AddDirectory(layout.VersionRoot, child);

        var result = paths.CleanupVersion(layout.Version);

        result.Error.Should().Be(LocalUpdatePathError.UnsafePath);
        fileSystem.SwapOccurred.Should().BeTrue();
        fileSystem.DeletedPaths.Should().BeEmpty();
    }

    [Fact]
    public void CleanupVersion_RefusesANestedJunctionWithoutTouchingItsTarget()
    {
        using var root = new TemporaryDirectory();
        var paths = new LocalUpdatePaths(root.Path, new WindowsPathSafetyInspector(), _ => DriveType.Fixed);
        var layout = paths.EnsureStaging(new SemanticVersion(1, 2, 3)).Layout!;
        var nested = Path.Combine(layout.StagingRoot, "nested");
        var target = Path.Combine(root.Path, "junction-target");
        var marker = Path.Combine(target, "outside.txt");
        var junction = Path.Combine(nested, "escape");
        Directory.CreateDirectory(nested);
        Directory.CreateDirectory(target);
        File.WriteAllText(marker, "outside");
        CreateJunctionOrSkip(junction, target);

        try
        {
            var result = paths.CleanupVersion(layout.Version);

            result.Error.Should().Be(LocalUpdatePathError.UnsafePath);
            File.ReadAllText(marker).Should().Be("outside");
            Directory.Exists(layout.VersionRoot).Should().BeTrue();
        }
        finally
        {
            DeleteJunctionOnly(junction);
        }
    }

    [Fact]
    public void CleanupVersion_RefusesADanglingJunctionAtTheComputedVersionRoot()
    {
        using var root = new TemporaryDirectory();
        var paths = new LocalUpdatePaths(root.Path, new WindowsPathSafetyInspector(), _ => DriveType.Fixed);
        var layout = paths.EnsureStaging(new SemanticVersion(1, 2, 3)).Layout!;
        var target = Path.Combine(root.Path, "temporary-target");
        Directory.Delete(layout.VersionRoot, recursive: true);
        Directory.CreateDirectory(target);
        CreateJunctionOrSkip(layout.VersionRoot, target);
        Directory.Delete(target);

        try
        {
            paths.CleanupVersion(layout.Version).Error.Should().Be(LocalUpdatePathError.UnsafePath);
        }
        finally
        {
            DeleteJunctionOnly(layout.VersionRoot);
        }
    }

    [Fact(Skip = "Requires Windows CreateSymbolicLink privilege; nested junction coverage runs separately.")]
    public void CleanupVersion_RefusesAReparseVersionRoot_WhenTheTokenPermitsIt()
    {
        using var root = new TemporaryDirectory();
        var paths = new LocalUpdatePaths(root.Path, new WindowsPathSafetyInspector(), _ => DriveType.Fixed);
        var layout = paths.EnsureStaging(new SemanticVersion(1, 2, 3)).Layout!;
        var target = Path.Combine(root.Path, "target");
        Directory.CreateDirectory(target);
        Directory.Delete(layout.VersionRoot, recursive: true);

        Directory.CreateSymbolicLink(layout.VersionRoot, target);

        paths.CleanupVersion(new SemanticVersion(1, 2, 3)).Success.Should().BeFalse();
        Directory.Exists(target).Should().BeTrue();
    }

    private static string Hash(char value) => new(value, 64);

    private static string Mutate(string value, bool mutate) => mutate ? value + ".forged" : value;

    private static void CreateJunctionOrSkip(string junction, string target)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                ArgumentList = { "/d", "/c", "mklink", "/J", junction, target }
            });
            if (process is null)
            {
                throw SkipException.ForSkip("Could not start mklink to create a real junction.");
            }

            process.WaitForExit();
            if (process.ExitCode != 0)
            {
                throw SkipException.ForSkip($"Junction creation is unavailable: {process.StandardError.ReadToEnd()}");
            }
        }
        catch (SkipException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            throw SkipException.ForSkip($"Junction creation is unavailable: {exception.Message}");
        }
    }

    private static void DeleteJunctionOnly(string junction)
    {
        try { Directory.Delete(junction, recursive: false); }
        catch (DirectoryNotFoundException) { }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private sealed class NeverReparse : IPathSafetyInspector
    {
        public bool IsReparsePoint(string path) => false;
    }

    private sealed class SwapAfterCheckFileSystem : ILocalUpdateCleanupFileSystem
    {
        private readonly Dictionary<string, LocalUpdateCleanupEntry> _entries = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, IReadOnlyList<string>> _children = new(StringComparer.OrdinalIgnoreCase);
        private string? _swappedPath;

        public bool SwapOccurred { get; private set; }
        public List<string> DeletedPaths { get; } = [];

        public void AddDirectory(string path, string child)
        {
            _entries[path] = Entry(path, LocalUpdateCleanupEntryKind.Directory, 1);
            _entries[child] = Entry(child, LocalUpdateCleanupEntryKind.File, 2);
            _children[path] = [child];
            _swappedPath = child;
        }

        public LocalUpdateCleanupEntry Inspect(string path) => _entries.TryGetValue(path, out var entry)
            ? entry
            : Entry(path, LocalUpdateCleanupEntryKind.Missing, 0);

        public bool IsSameEntry(LocalUpdateCleanupEntry entry) => _entries.TryGetValue(entry.Path, out var current)
            && current == entry;

        public bool TryEnumerate(
            LocalUpdateCleanupEntry directory,
            out IReadOnlyList<LocalUpdateCleanupEntry> entries)
        {
            entries = _children[directory.Path].Select(path => _entries[path]).ToArray();
            return IsSameEntry(directory);
        }

        public bool DeleteFile(LocalUpdateCleanupEntry file)
        {
            if (string.Equals(file.Path, _swappedPath, StringComparison.OrdinalIgnoreCase))
            {
                _entries[file.Path] = file with
                {
                    Identity = new LocalUpdateCleanupIdentity(
                        file.Identity.VolumeSerialNumber,
                        file.Identity.FileIdLow,
                        file.Identity.FileIdHigh + 1)
                };
                SwapOccurred = true;
            }

            if (!IsSameEntry(file)) return false;
            DeletedPaths.Add(file.Path);
            _entries.Remove(file.Path);
            return true;
        }

        public bool DeleteDirectory(LocalUpdateCleanupEntry directory)
        {
            if (!IsSameEntry(directory)) return false;
            DeletedPaths.Add(directory.Path);
            _entries.Remove(directory.Path);
            return true;
        }

        private static LocalUpdateCleanupEntry Entry(string path, LocalUpdateCleanupEntryKind kind, ulong id) =>
            new(path, path, kind, new LocalUpdateCleanupIdentity(1, id, 0));
    }

    private sealed class RecordingPinnedDirectoryService(PinnedDirectoryStatus ensureStatus)
        : IPinnedLocalDirectoryService
    {
        public List<(string AnchorPath, IReadOnlyList<string> Segments)> EnsureCalls { get; } = [];

        public PinnedDirectoryStatus EnsureDirectory(
            string anchorPath,
            IReadOnlyList<string> relativeSegments)
        {
            EnsureCalls.Add((anchorPath, relativeSegments.ToArray()));
            return ensureStatus;
        }

        public PinnedDirectoryOpenResult OpenExisting(string path) =>
            throw new NotSupportedException();

        public bool IsSafe(PinnedLocalDirectoryLease lease, string expectedPath) =>
            throw new NotSupportedException();

        public PinnedFileOpenResult CreateNewFile(
            PinnedLocalDirectoryLease parent,
            string childName,
            string expectedPath) =>
            throw new NotSupportedException();
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "WireguardSplitTunnel.WindowsUpdate.Tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
            ProductRoot = System.IO.Path.Combine(Path, "WireguardSplitTunnel");
        }

        public string Path { get; }
        public string ProductRoot { get; }

        public LocalUpdatePaths CreatePaths() => new(Path, new NeverReparse(), _ => DriveType.Fixed);

        public void Dispose()
        {
            try { Directory.Delete(Path, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}
