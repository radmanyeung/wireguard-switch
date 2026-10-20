using System.Security.Principal;
using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Transactions;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class ProtectedFirstUpdateNativeTests
{
    [PrivilegedNativeFact]
    public void FirstUpdate_CreatesRealProtectedWorkspace_AndKeepsDirectoryPinned()
    {
        using var identity = WindowsIdentity.GetCurrent();
        new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)
            .Should().BeTrue("this opt-in test requires a real elevated token");
        var parent = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "WGST-native-first-update"));
        var root = Path.GetFullPath(Path.Combine(parent, Guid.NewGuid().ToString("N")));
        root.Should().StartWith(parent + Path.DirectorySeparatorChar);
        Directory.CreateDirectory(root);
        try
        {
            var product = Path.Combine(root, "product");
            var inspector = new WindowsPathSafetyInspector();
            var paths = new ProtectedTransactionPaths(product, inspector, p => new DriveInfo(p).DriveType);
            var acl = new ProtectedDirectoryAcl();
            var store = new ProtectedTransactionStore(paths);
            var absent = store.ReadActive(new ProtectedUpdateMutexContext(false));
            absent.Success.Should().BeTrue();
            absent.TransactionId.Should().BeNull();
            Directory.Exists(product).Should().BeFalse();

            var layout = paths.GetLayout(ProtectedTransactionId.New()).Layout!;
            var result = WindowsProtectedTransactionPreparationWorkspace.TryCreate(
                layout, paths, acl, new WindowsExecutableProductVersionReader(), inspector,
                new SemanticVersion(0, 2, 12));
            using var workspace = result.Workspace;
            result.Success.Should().BeTrue("real native preparation returned {0}: {1}", result.Error, result.DetailCode);
            foreach (var directory in new[] { product, layout.TransactionsRoot, layout.TransactionRoot,
                         layout.HelperRoot, layout.CandidateRoot, layout.BackupsRoot })
            {
                acl.ValidateProtectedDirectory(directory).Success.Should().BeTrue(directory);
            }

            var probePath = Path.Combine(layout.CandidateRoot, "probe.bin");
            using (var file = acl.OpenNewProtectedFile(probePath))
            {
                file.Success.Should().BeTrue("native file creation returned {0}", file.Error);
                file.Stream!.WriteByte(42);
                file.Stream.Flush(true);
            }
            acl.ValidateProtectedFile(probePath).Success.Should().BeTrue();
            File.ReadAllBytes(probePath).Should().Equal((byte)42);
            var journalPath = Path.Combine(layout.CandidateRoot, "journal-probe.bin");
            var created = acl.CreateProtectedFileIfAbsent(journalPath, new byte[] { 1 });
            created.Outcome.Should().Be(ProtectedFileMutationOutcome.Committed,
                "native atomic creation returned {0}", created.Error);
            var changed = acl.CompareExchangeProtectedFile(journalPath, created.Identity!.Value,
                new byte[] { 1 }, new byte[] { 2 });
            changed.Outcome.Should().Be(ProtectedFileCompareExchangeOutcome.Committed,
                "native journal replacement returned {0}", changed.Error);
            File.ReadAllBytes(journalPath).Should().Equal((byte)2);
            Action rename = () => Directory.Move(layout.TransactionRoot, layout.TransactionRoot + "-moved");
            rename.Should().Throw<IOException>("the active workspace must keep its directory identity pinned");
            File.Delete(probePath);
            File.Delete(journalPath);
            workspace!.TryCleanup().Should().BeTrue("an unused native workspace must be recoverable");
            Directory.Exists(layout.TransactionRoot).Should().BeFalse();
        }
        finally
        {
            // Delete only this unique test directory and never traverse a reparse point.
            DeletePlainTree(root, parent + Path.DirectorySeparatorChar);
        }
    }

    private static void DeletePlainTree(string path, string allowedPrefix)
    {
        var full = Path.GetFullPath(path);
        if (!full.StartsWith(allowedPrefix, StringComparison.OrdinalIgnoreCase)
            || (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Unsafe native-test cleanup path.");
        foreach (var entry in Directory.EnumerateFileSystemEntries(full))
        {
            var attributes = File.GetAttributes(entry);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Native-test cleanup encountered a reparse point.");
            if ((attributes & FileAttributes.Directory) != 0)
                DeletePlainTree(entry, allowedPrefix);
            else
                File.Delete(entry);
        }
        Directory.Delete(full);
    }
}

public sealed class PrivilegedNativeFactAttribute : FactAttribute
{
    public PrivilegedNativeFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("WGST_RUN_PRIVILEGED_NATIVE_TESTS") != "1")
            Skip = "Opt in with WGST_RUN_PRIVILEGED_NATIVE_TESTS=1 and an elevated Windows token.";
    }
}
