using System.Security.Principal;
using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Transactions;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed partial class ProtectedTransactionStoreTests
{
    [Fact]
    public void DeactivateProtectedStaged_ReleasesSnapshotBeforePointerCompareExchange()
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(fixture.Authority, fixture.Material);
        fixture.Store.Activate(fixture.Authority, created.Record!).Success.Should().BeTrue();
        var expected = fixture.Store.ReadJournalForRecovery(fixture.Authority, fixture.Material.TransactionId);

        fixture.Store.DeactivateProtectedStaged(fixture.Authority, expected).Success.Should().BeTrue();
        fixture.Store.ReadActive(fixture.Authority).TransactionId.Should().BeNull();
    }

    // This opt-in integration uses real Windows protected-file operations only
    // for active.json. Package artifacts and installed-release identity stay in
    // the existing in-memory fixture; no installed app or ProgramData is touched.
    public sealed class NativeActivePointerTests
    {
        [PrivilegedNativeFact]
        public void Store_CreatesReplacesDeactivatesAndReactivatesRealProtectedPointer()
        {
            using var identity = WindowsIdentity.GetCurrent();
            new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)
                .Should().BeTrue("this opt-in test requires a real elevated token");
            var parent = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "WGST-native-active-pointer"));
            var root = Path.GetFullPath(Path.Combine(parent, Guid.NewGuid().ToString("N")));
            root.Should().StartWith(parent + Path.DirectorySeparatorChar);
            Directory.CreateDirectory(root);
            var protectedDirectory = Path.Combine(root, "protected");
            var nativePointer = Path.Combine(protectedDirectory, "active.json");
            try
            {
                var acl = new ProtectedDirectoryAcl();
                var createdDirectory = acl.EnsureProtectedDirectory(protectedDirectory);
                createdDirectory.Success.Should().BeTrue("native ACL creation returned {0}", createdDirectory.Error);
                using var fixture = new StoreFixture();
                var fileSystem = new ActivePointerNativeFileSystem(
                    fixture.FileSystem, fixture.Layout.ActivePointerPath, nativePointer);
                var store = new ProtectedTransactionStore(fixture.Paths, fileSystem,
                    _ => DriveType.Fixed, fixture.VersionReader, fixture.InstalledReleaseVerifier);
                var first = store.CreateProtectedStaged(fixture.Authority, fixture.Material);
                first.Success.Should().BeTrue();
                store.Activate(fixture.Authority, first.Record!).Success.Should().BeTrue("initial active pointer creation");
                acl.ValidateProtectedFile(nativePointer).Success.Should().BeTrue();

                var secondMaterial = fixture.AddTransaction(Guid.NewGuid(), patch: 5);
                var second = store.CreateProtectedStaged(fixture.Authority, secondMaterial);
                second.Success.Should().BeTrue();
                store.ActivateReplacingProtectedStaged(fixture.Authority, second.Record!,
                    new ProtectedActiveTransactionExpectation(fixture.Material.TransactionId,
                        fixture.Material.Version, fixture.Material.Source))
                    .Success.Should().BeTrue("the old read snapshot must be released before native pointer replacement");
                store.ReadActive(fixture.Authority).TransactionId.Should().Be(secondMaterial.TransactionId);

                var staged = store.ReadJournalForRecovery(fixture.Authority, secondMaterial.TransactionId);
                store.DeactivateProtectedStaged(fixture.Authority, staged).Success.Should().BeTrue("native pointer deactivation");
                store.ReadActive(fixture.Authority).TransactionId.Should().BeNull();
                store.Activate(fixture.Authority, second.Record!).Success.Should().BeTrue("reactivation replaces the inactive tombstone");
                store.ReadActive(fixture.Authority).TransactionId.Should().Be(secondMaterial.TransactionId);
                acl.ValidateProtectedFile(nativePointer).Success.Should().BeTrue();
            }
            finally
            {
                DeleteNativePointerTree(root, parent + Path.DirectorySeparatorChar);
            }
        }

        private static void DeleteNativePointerTree(string path, string allowedPrefix)
        {
            var full = Path.GetFullPath(path);
            if (!full.StartsWith(allowedPrefix, StringComparison.OrdinalIgnoreCase)
                || (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Unsafe native pointer test cleanup path.");
            foreach (var entry in Directory.EnumerateFileSystemEntries(full))
            {
                var attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Native pointer test cleanup encountered a reparse point.");
                if ((attributes & FileAttributes.Directory) != 0)
                    DeleteNativePointerTree(entry, allowedPrefix);
                else File.Delete(entry);
            }
            Directory.Delete(full);
        }

        private sealed class ActivePointerNativeFileSystem(
            IProtectedTransactionFileSystem fixture, string logicalPointer, string nativePointer)
            : IProtectedTransactionFileSystem
        {
            private readonly IProtectedTransactionFileSystem _native = new WindowsProtectedTransactionFileSystem();
            private bool IsPointer(string path) => string.Equals(path, logicalPointer, StringComparison.OrdinalIgnoreCase);
            private IProtectedTransactionFileSystem Select(string path) => IsPointer(path) ? _native : fixture;
            private string Map(string path) => IsPointer(path) ? nativePointer : path;
            public bool ValidateProtectedDirectory(string path) => fixture.ValidateProtectedDirectory(path);
            public ProtectedTransactionDirectoryState InspectProtectedDirectory(string path) => fixture.InspectProtectedDirectory(path);
            public ProtectedTransactionFileState InspectProtectedFile(string path) => Select(path).InspectProtectedFile(Map(path));
            public byte[]? ReadProtectedFile(string path, long maximumBytes) => Select(path).ReadProtectedFile(Map(path), maximumBytes);
            public IProtectedFileSnapshotLease? OpenProtectedFileSnapshot(string path, long maximumBytes) => Select(path).OpenProtectedFileSnapshot(Map(path), maximumBytes);
            public ProtectedAtomicCommitResult AtomicCreate(string path, byte[] bytes) => Select(path).AtomicCreate(Map(path), bytes);
            public ProtectedAtomicCommitResult AtomicCompareExchange(string path, byte[] expected, byte[] replacement) => Select(path).AtomicCompareExchange(Map(path), expected, replacement);
            public ProtectedAtomicCommitResult AtomicCompareExchange(string path, ProtectedFileIdentity128 identity, byte[] expected, byte[] replacement) => Select(path).AtomicCompareExchange(Map(path), identity, expected, replacement);
            public bool HasProtectedProductVersion(string path, string expected, IExecutableProductVersionReader reader) => fixture.HasProtectedProductVersion(path, expected, reader);
            public string? ComputeProtectedSha256(string path, long maximumBytes) => fixture.ComputeProtectedSha256(path, maximumBytes);
            public IReadOnlyList<ProtectedCandidateFileSnapshot>? SnapshotProtectedFiles(string path, int maximumEntries, long maximumBytes) => fixture.SnapshotProtectedFiles(path, maximumEntries, maximumBytes);
            public long? MeasureProtectedDirectory(string path, long maximumBytes) => fixture.MeasureProtectedDirectory(path, maximumBytes);
        }
    }
}
