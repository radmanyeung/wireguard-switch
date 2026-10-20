using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Transactions;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class ProtectedFirstUpdateTests
{
    private const string ProductRoot = @"C:\safe\product";

    [Theory]
    [InlineData(@"C:\safe")]
    [InlineData(ProductRoot)]
    [InlineData(ProductRoot + @"\UpdateTransactions")]
    public void ReadActive_WhenRootOrAncestorIsMissing_ReturnsNoTransactionWithoutCreatingDirectories(
        string missingPath)
    {
        var native = new DirectoryNative();
        native.AddDirectory(@"C:\safe");
        native.AddDirectory(ProductRoot);
        native.RemoveDirectory(missingPath);
        var paths = CreatePaths();
        var store = new ProtectedTransactionStore(
            paths,
            new WindowsProtectedTransactionFileSystem(CreateAcl(native)),
            _ => DriveType.Fixed);
        var authority = new ProtectedUpdateMutexContext(false);

        var result = store.ReadActive(authority);

        result.Success.Should().BeTrue();
        result.TransactionId.Should().BeNull();
        native.CreatedPaths.Should().BeEmpty();
    }

    [Theory]
    [InlineData(@"C:\safe", ProtectedAclError.AccessDenied)]
    [InlineData(ProductRoot, ProtectedAclError.AccessDenied)]
    [InlineData(ProductRoot + @"\UpdateTransactions", ProtectedAclError.AccessDenied)]
    [InlineData(ProductRoot, ProtectedAclError.IoFailure)]
    public void ReadActive_WhenNativeOpenFails_DoesNotTreatFailureAsAbsence(
        string failedPath,
        ProtectedAclError error)
    {
        var native = new DirectoryNative();
        native.AddDirectory(@"C:\safe");
        native.AddDirectory(ProductRoot);
        native.OpenFailures[failedPath] = error;
        var store = new ProtectedTransactionStore(
            CreatePaths(),
            new WindowsProtectedTransactionFileSystem(CreateAcl(native)),
            _ => DriveType.Fixed);
        var authority = new ProtectedUpdateMutexContext(false);

        store.ReadActive(authority).Error.Should().Be(
            ProtectedTransactionStoreError.AclMismatch);
        native.CreatedPaths.Should().BeEmpty();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReadActive_WhenExistingProductIsUnsafeAndTransactionsAreMissing_FailsClosed(
        bool reparsePoint)
    {
        var native = new DirectoryNative();
        native.AddDirectory(@"C:\safe");
        native.AddDirectory(ProductRoot, reparsePoint, invalidSecurity: !reparsePoint);
        var store = new ProtectedTransactionStore(
            CreatePaths(),
            new WindowsProtectedTransactionFileSystem(CreateAcl(native)),
            _ => DriveType.Fixed);
        var authority = new ProtectedUpdateMutexContext(false);

        store.ReadActive(authority).Error.Should().Be(
            ProtectedTransactionStoreError.AclMismatch);
        native.CreatedPaths.Should().BeEmpty();
    }

    [Fact]
    public void CleanupInactiveTransaction_WhenRootIsMissing_RejectsMutationWithoutInvokingCleanup()
    {
        var native = new DirectoryNative();
        native.AddDirectory(@"C:\safe");
        var store = new ProtectedTransactionStore(
            CreatePaths(),
            new WindowsProtectedTransactionFileSystem(CreateAcl(native)),
            _ => DriveType.Fixed);
        var authority = new ProtectedUpdateMutexContext(false);
        var cleanupCalled = false;
        var material = new ProtectedStagedTransactionMaterial(
            ProtectedTransactionId.New(),
            new SemanticVersion(0, 2, 11),
            PendingUpdateSource.Manual,
            null!,
            null!,
            string.Empty,
            new ProtectedJournalMetadata(1, 0));

        var result = store.CleanupInactiveTransaction(authority, material, () =>
        {
            cleanupCalled = true;
            return true;
        });

        result.Error.Should().Be(ProtectedTransactionStoreError.AclMismatch);
        cleanupCalled.Should().BeFalse();
        native.CreatedPaths.Should().BeEmpty();
    }

    [Fact]
    public void NativePreparation_WhenProductDoesNotExist_CreatesCanonicalWorkspace()
    {
        var native = new DirectoryNative();
        native.AddDirectory(@"C:\safe");
        var paths = CreatePaths();
        var transactionId = ProtectedTransactionId.New();
        var layout = paths.GetLayout(transactionId).Layout!;

        var result = WindowsProtectedTransactionPreparationWorkspace.TryCreate(
            layout,
            paths,
            CreateAcl(native),
            new WindowsExecutableProductVersionReader(),
            new NeverReparse(),
            new SemanticVersion(0, 2, 11));
        using var workspace = result.Workspace;

        result.Success.Should().BeTrue("native preparation should use the canonical transaction root; {0}", result.DetailCode);
        native.CreatedPaths.Should().ContainInOrder(
            layout.ProductRoot,
            layout.TransactionsRoot,
            layout.TransactionRoot,
            layout.HelperRoot,
            layout.CandidateRoot,
            layout.BackupsRoot);
        native.CreatedPaths.Should().NotContain(ProductRoot + @"\transactions");
        workspace!.TransactionId.Should().Be(transactionId);
    }

    private static ProtectedTransactionPaths CreatePaths() =>
        new(ProductRoot, new NeverReparse(), _ => DriveType.Fixed);

    private static ProtectedDirectoryAcl CreateAcl(DirectoryNative native) =>
        new(native, _ => DriveType.Fixed);

    private sealed class NeverReparse : IPathSafetyInspector
    {
        public bool IsReparsePoint(string path) => false;
    }

    // Models native handle-relative directory operations; no real filesystem is mutated.
    private sealed class DirectoryNative : IProtectedAclNativeFileSystem
    {
        private readonly Dictionary<string, ProtectedAclNativeSnapshot> _directories =
            new(StringComparer.OrdinalIgnoreCase);
        private ulong _nextIdentity;

        public DirectoryNative() => AddDirectory(@"C:\");

        public List<string> CreatedPaths { get; } = [];
        public Dictionary<string, ProtectedAclError> OpenFailures { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        public void AddDirectory(string path, bool reparsePoint = false, bool invalidSecurity = false) =>
            _directories[path] = new ProtectedAclNativeSnapshot(
                true,
                reparsePoint,
                path,
                new ProtectedFileIdentity128(1, ++_nextIdentity, 0),
                invalidSecurity
                    ? ProtectedDirectoryAcl.BuildInstalledRootSecurity().GetSecurityDescriptorBinaryForm()
                    : ProtectedDirectoryAcl.BuildDirectorySecurity().GetSecurityDescriptorBinaryForm());

        public void RemoveDirectory(string path) => _directories.Remove(path);

        public ProtectedAclNativeOpenResult OpenRoot(
            string rootPath,
            bool openReparsePoint,
            bool shareDelete,
            bool requireWriteAccess = false) => Open(rootPath);

        public ProtectedAclNativeOpenResult OpenRelative(
            IProtectedAclNativeHandle parent,
            string name,
            ProtectedAclNativeOpenRequest request)
        {
            var path = Path.Combine(parent.ReadSnapshot().FinalPath, name);
            if (request.Disposition == ProtectedAclNativeDisposition.CreateNew)
            {
                if (_directories.ContainsKey(path))
                {
                    return ProtectedAclNativeOpenResult.Failed(ProtectedAclError.AlreadyExists);
                }

                AddDirectory(path);
                _directories[path] = _directories[path] with
                {
                    SecurityDescriptor = request.SecurityDescriptor!.ToArray()
                };
                CreatedPaths.Add(path);
            }

            return Open(path);
        }

        public ProtectedAclNativeOperationResult FlushDirectory(IProtectedAclNativeHandle directory) =>
            ProtectedAclNativeOperationResult.Committed();

        private ProtectedAclNativeOpenResult Open(string path) =>
            OpenFailures.TryGetValue(path, out var error)
                ? ProtectedAclNativeOpenResult.Failed(error)
                : _directories.TryGetValue(path, out var snapshot)
                    ? ProtectedAclNativeOpenResult.Opened(new DirectoryHandle(snapshot))
                    : ProtectedAclNativeOpenResult.Failed(ProtectedAclError.Missing);

        private sealed class DirectoryHandle(ProtectedAclNativeSnapshot snapshot)
            : IProtectedAclNativeHandle
        {
            public ProtectedAclNativeSnapshot ReadSnapshot() => snapshot;
            public FileStream TakeFileStream() => throw new InvalidOperationException();
            public void Dispose() { }
        }
    }
}
