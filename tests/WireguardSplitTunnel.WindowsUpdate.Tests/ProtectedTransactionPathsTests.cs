using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Transactions;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class ProtectedTransactionPathsTests
{
    [Fact]
    public void DefaultConstructor_UsesTheFixedProgramDataAuthority()
    {
        var result = new ProtectedTransactionPaths().GetRoot();

        result.Success.Should().BeTrue();
        result.Layout!.ProductRoot.Should().Be(Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData),
            "WireguardSplitTunnel"));
    }

    [Fact]
    public void GetLayout_DerivesEveryChildFromTheFixedProgramDataRootAndLowercaseGuid()
    {
        using var fixture = new PathFixture();
        var id = new ProtectedTransactionId(Guid.Parse("AABBCCDD-1122-3344-5566-778899AABBCC"));

        var result = fixture.Paths.GetLayout(id);

        result.Success.Should().BeTrue();
        result.Layout.Should().BeEquivalentTo(new ProtectedTransactionLayout(
            fixture.ProductRoot,
            Path.Combine(fixture.ProductRoot, "UpdateTransactions"),
            Path.Combine(fixture.ProductRoot, "UpdateTransactions", "active-transaction.json"),
            Path.Combine(fixture.ProductRoot, "UpdateTransactions", "aabbccdd112233445566778899aabbcc"),
            Path.Combine(fixture.ProductRoot, "UpdateTransactions", "aabbccdd112233445566778899aabbcc", "transaction.json"),
            Path.Combine(fixture.ProductRoot, "UpdateTransactions", "aabbccdd112233445566778899aabbcc", "journal.json"),
            Path.Combine(fixture.ProductRoot, "UpdateTransactions", "aabbccdd112233445566778899aabbcc", "health.json"),
            Path.Combine(fixture.ProductRoot, "UpdateTransactions", "aabbccdd112233445566778899aabbcc", "helper"),
            Path.Combine(fixture.ProductRoot, "UpdateTransactions", "aabbccdd112233445566778899aabbcc", "helper", "WireguardSplitTunnel.Updater.exe"),
            Path.Combine(fixture.ProductRoot, "UpdateTransactions", "aabbccdd112233445566778899aabbcc", "candidate"),
            Path.Combine(fixture.ProductRoot, "UpdateTransactions", "aabbccdd112233445566778899aabbcc", "backups")));
    }

    [Fact]
    public void GetLayout_RejectsAnEmptyTransactionId()
    {
        using var fixture = new PathFixture();

        fixture.Paths.GetLayout(new ProtectedTransactionId(Guid.Empty)).Success.Should().BeFalse();
    }

    [Theory]
    [InlineData("relative")]
    [InlineData("C:relative")]
    [InlineData("\\rooted")]
    [InlineData("\\\\server\\share")]
    [InlineData("\\\\?\\C:\\ProgramData\\WireguardSplitTunnel")]
    [InlineData("\\\\.\\C:\\ProgramData\\WireguardSplitTunnel")]
    public void GetRoot_RejectsNonCanonicalOrNonLocalRoots(string root)
    {
        var paths = new ProtectedTransactionPaths(root, new NeverReparse(), _ => DriveType.Fixed);

        paths.GetRoot().Success.Should().BeFalse();
    }

    [Fact]
    public void GetRoot_RejectsMappedDrives()
    {
        var paths = new ProtectedTransactionPaths(
            "Z:\\ProgramData\\WireguardSplitTunnel",
            new NeverReparse(),
            _ => DriveType.Network);

        paths.GetRoot().Success.Should().BeFalse();
    }

    [Fact]
    public void GetLayout_RejectsAReparseAncestor()
    {
        using var fixture = new PathFixture();
        var transactionsRoot = Path.Combine(fixture.ProductRoot, "UpdateTransactions");
        var paths = new ProtectedTransactionPaths(
            fixture.ProductRoot,
            new SelectedReparse(transactionsRoot),
            _ => DriveType.Fixed);

        paths.GetLayout(ProtectedTransactionId.New()).Success.Should().BeFalse();
    }

    [Fact]
    public void GetRoot_RejectsAnExistingFileWhereTheProductDirectoryMustBe()
    {
        using var fixture = new PathFixture(createProductRoot: false);
        File.WriteAllText(fixture.ProductRoot, "not a directory");

        var paths = new ProtectedTransactionPaths(
            fixture.ProductRoot,
            new WindowsPathSafetyInspector(),
            _ => DriveType.Fixed);

        paths.GetRoot().Success.Should().BeFalse();
    }

    [Fact]
    public void GetRoot_RejectsADanglingDirectoryReparsePoint_WhenTheTokenPermitsIt()
    {
        using var fixture = new PathFixture(createProductRoot: false);
        var missingTarget = Path.Combine(fixture.BaseRoot, "missing-target");

        try
        {
            Directory.CreateSymbolicLink(fixture.ProductRoot, missingTarget);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
            return;
        }

        var paths = new ProtectedTransactionPaths(
            fixture.ProductRoot,
            new WindowsPathSafetyInspector(),
            _ => DriveType.Fixed);

        paths.GetRoot().Success.Should().BeFalse();
    }

    [Fact]
    public void ResolveCandidateAndBackupPayload_DeriveCanonicalContainedPaths()
    {
        using var fixture = new PathFixture();
        var id = ProtectedTransactionId.New();

        var candidate = fixture.Paths.ResolveCandidatePayload(id, "WireguardSplitTunnel/WireguardSplitTunnel.App.exe");
        var backup = fixture.Paths.ResolveBackupPayload(id, "scripts/start.ps1");
        var layout = fixture.Paths.GetLayout(id).Layout!;

        candidate.Success.Should().BeTrue();
        candidate.Path.Should().Be(Path.Combine(layout.CandidateRoot, "WireguardSplitTunnel", "WireguardSplitTunnel.App.exe"));
        backup.Success.Should().BeTrue();
        backup.Path.Should().Be(Path.Combine(layout.BackupsRoot, "scripts", "start.ps1"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("../escape")]
    [InlineData("folder\\file")]
    [InlineData("/rooted")]
    [InlineData("C:/absolute")]
    [InlineData("folder/CON.txt")]
    [InlineData("folder/file.txt:stream")]
    public void ResolvePayload_RejectsNonCanonicalRelativePaths(string? relativePath)
    {
        using var fixture = new PathFixture();
        var id = ProtectedTransactionId.New();

        fixture.Paths.ResolveCandidatePayload(id, relativePath).Success.Should().BeFalse();
        fixture.Paths.ResolveBackupPayload(id, relativePath).Success.Should().BeFalse();
    }

    [Theory]
    [InlineData("state.json")]
    [InlineData("nested/applied-state.json")]
    [InlineData("logs/runtime.log")]
    [InlineData("profiles/home.conf")]
    [InlineData("cache/file.tmp")]
    public void ResolvePayload_RejectsProtectedUserAndRuntimePaths(
        string relativePath)
    {
        using var fixture = new PathFixture();
        var id = ProtectedTransactionId.New();

        fixture.Paths.ResolveCandidatePayload(id, relativePath)
            .Error.Should().Be(
                ProtectedTransactionPathError.InvalidRelativePath);
        fixture.Paths.ResolveBackupPayload(id, relativePath)
            .Error.Should().Be(
                ProtectedTransactionPathError.InvalidRelativePath);
    }

    private sealed class PathFixture : IDisposable
    {
        public PathFixture(bool createProductRoot = true)
        {
            BaseRoot = Path.Combine(
                Path.GetTempPath(),
                "WireguardSplitTunnel.WindowsUpdate.Tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(BaseRoot);
            ProductRoot = Path.Combine(BaseRoot, "WireguardSplitTunnel");
            if (createProductRoot)
            {
                Directory.CreateDirectory(ProductRoot);
            }

            Paths = new ProtectedTransactionPaths(ProductRoot, new NeverReparse(), _ => DriveType.Fixed);
        }

        public string BaseRoot { get; }
        public string ProductRoot { get; }
        public ProtectedTransactionPaths Paths { get; }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(ProductRoot)
                    && (File.GetAttributes(ProductRoot) & FileAttributes.ReparsePoint) != 0)
                {
                    Directory.Delete(ProductRoot);
                }

                if (Directory.Exists(BaseRoot))
                {
                    Directory.Delete(BaseRoot, recursive: true);
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private sealed class NeverReparse : IPathSafetyInspector
    {
        public bool IsReparsePoint(string path) => false;
    }

    private sealed class SelectedReparse(string reparsePath) : IPathSafetyInspector
    {
        public bool IsReparsePoint(string path) =>
            string.Equals(path, reparsePath, StringComparison.OrdinalIgnoreCase);
    }
}
