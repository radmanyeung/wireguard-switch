using FluentAssertions;
using WireguardSplitTunnel.WindowsUpdate.Transactions;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class UpdateFileSystemTests : IDisposable
{
    private static readonly byte[] InstalledRootDescriptor = [1];
    private static readonly byte[] InstalledDirectoryDescriptor = [2];
    private static readonly byte[] InstalledFileDescriptor = [3];
    private static readonly byte[] BackupRootDescriptor = [4];
    private static readonly byte[] BackupDirectoryDescriptor = [5];
    private static readonly byte[] BackupFileDescriptor = [6];

    private readonly FakeNativeFileSystem _native = new();

    [Fact]
    public void WindowsSecurityPolicy_UsesExactInstalledAndProtectedFileDescriptors()
    {
        var policy = UpdateFileSystemSecurityPolicy.Windows;

        ProtectedDirectoryAcl
            .HasExactInstalledDescendantDescriptor(
                policy.InstalledFileDescriptor,
                directory: false)
            .Should().BeTrue();
        ProtectedDirectoryAcl.HasExactProtectedDescriptor(
                policy.BackupFileDescriptor,
                directory: false)
            .Should().BeTrue();
        policy.InstalledFileDescriptor[0] ^= 0xff;
        ProtectedDirectoryAcl
            .HasExactInstalledDescendantDescriptor(
                policy.InstalledFileDescriptor,
                directory: false)
            .Should().BeTrue();
        new UpdateFileSystem().Should().NotBeNull();
    }

    [Fact]
    public void OpenSession_PinsBothExactRootsForTheWholeSession()
    {
        var installed = _native.AddRoot(
            @"C:\Program Files\WireguardSplitTunnel",
            Identity(1, 10),
            InstalledRootDescriptor);
        var backup = _native.AddRoot(
            @"C:\ProgramData\WireguardSplitTunnel\transactions\tx\backup",
            Identity(2, 20),
            BackupRootDescriptor);
        var sut = CreateFileSystem();

        using var opened = sut.OpenSession(
            new UpdateFileSystemSessionRequest(
                installed.FinalPath,
                FileIdentity(installed.Identity),
                backup.FinalPath,
                FileIdentity(backup.Identity)));

        opened.Success.Should().BeTrue();
        opened.Session.Should().NotBeNull();
        installed.OpenHandles.Should().Be(1);
        backup.OpenHandles.Should().Be(1);
        _native.RootRequests.Should().OnlyContain(
            request => request.RequireWriteAccess);

        installed.Identity = Identity(1, 11);
        var observation = opened.Session!.Observe(
            ValidOperation(),
            UpdateFileLocation.Target);

        observation.Observation.Should().Be(
            UpdateFileObservation.Unknown);
        observation.Error.Should().Be(
            UpdateFileSystemError.UnsafeRoot);
    }

    [Fact]
    public void Observe_ClassifiesOnlyMissingExactOldExactNewOrUnknown()
    {
        var installed = _native.AddRoot(
            @"C:\Program Files\WireguardSplitTunnel",
            Identity(1, 10),
            InstalledRootDescriptor);
        var bin = installed.AddDirectory(
            "bin",
            InstalledDirectoryDescriptor);
        bin.AddFile(
            "old.exe",
            InstalledFileDescriptor,
            Bytes("old"));
        bin.AddFile(
            "new.exe",
            InstalledFileDescriptor,
            Bytes("new"));
        bin.AddFile(
            "unknown.exe",
            InstalledFileDescriptor,
            Bytes("attacker"));
        var backup = _native.AddRoot(
            @"C:\ProgramData\WireguardSplitTunnel\transactions\tx\backup",
            Identity(2, 20),
            BackupRootDescriptor);
        using var opened = CreateFileSystem().OpenSession(
            SessionRequest(installed, backup));

        Observe("bin/missing.exe")
            .Should().Be(UpdateFileObservation.Missing);
        Observe("bin/old.exe")
            .Should().Be(UpdateFileObservation.ExactOld);
        Observe("bin/new.exe")
            .Should().Be(UpdateFileObservation.ExactNew);
        Observe("bin/unknown.exe")
            .Should().Be(UpdateFileObservation.Unknown);

        _native.RelativeRequests.Should().OnlyContain(
            request => request.Request.OpenReparsePoint
                && !request.Request.ShareDelete);

        UpdateFileObservation Observe(string target)
        {
            var operation = ValidOperation() with
            {
                TargetRelativePath = target,
                BackupRelativePath = target + ".bak",
                TemporaryRelativePath =
                    target + ".update-tmp"
            };
            var result = opened.Session!.Observe(
                operation,
                UpdateFileLocation.Target);
            result.Error.Should().Be(
                UpdateFileSystemError.None);
            return result.Observation;
        }
    }

    [Theory]
    [InlineData(@"\\server\share\app.exe")]
    [InlineData("bin/app.exe:stream")]
    [InlineData("../app.exe")]
    [InlineData("bin\\app.exe")]
    [InlineData("/bin/app.exe")]
    [InlineData("bin/app.exe.")]
    [InlineData("bin/../app.exe")]
    public void Observe_RejectsNonCanonicalManagedTargets(
        string target)
    {
        var installed = _native.AddRoot(
            @"C:\Program Files\WireguardSplitTunnel",
            Identity(1, 10),
            InstalledRootDescriptor);
        var backup = _native.AddRoot(
            @"C:\ProgramData\WireguardSplitTunnel\transactions\tx\backup",
            Identity(2, 20),
            BackupRootDescriptor);
        using var opened = CreateFileSystem().OpenSession(
            SessionRequest(installed, backup));
        var operation = ValidOperation() with
        {
            TargetRelativePath = target,
            BackupRelativePath = target + ".bak",
            TemporaryRelativePath =
                target + ".update-tmp"
        };

        var result = opened.Session!.Observe(
            operation,
            UpdateFileLocation.Target);

        result.Observation.Should().Be(
            UpdateFileObservation.Unknown);
        result.Error.Should().Be(
            UpdateFileSystemError.InvalidInput);
        _native.RelativeRequests.Should().BeEmpty();
    }

    [Fact]
    public void Observe_RejectsMissingOrReparseParentsWithoutFollowingThem()
    {
        var installed = _native.AddRoot(
            @"C:\Program Files\WireguardSplitTunnel",
            Identity(1, 10),
            InstalledRootDescriptor);
        installed.AddDirectory(
                "junction",
                InstalledDirectoryDescriptor)
            .ReparsePoint = true;
        var backup = _native.AddRoot(
            @"C:\ProgramData\WireguardSplitTunnel\transactions\tx\backup",
            Identity(2, 20),
            BackupRootDescriptor);
        using var opened = CreateFileSystem().OpenSession(
            SessionRequest(installed, backup));

        var missing = opened.Session!.Observe(
            ValidOperation() with
            {
                TargetRelativePath = "missing/app.exe",
                BackupRelativePath =
                    "missing/app.exe.bak",
                TemporaryRelativePath =
                    "missing/app.exe.update-tmp"
            },
            UpdateFileLocation.Target);
        var junction = opened.Session.Observe(
            ValidOperation() with
            {
                TargetRelativePath = "junction/app.exe",
                BackupRelativePath =
                    "junction/app.exe.bak",
                TemporaryRelativePath =
                    "junction/app.exe.update-tmp"
            },
            UpdateFileLocation.Target);

        missing.Error.Should().Be(
            UpdateFileSystemError.MissingParent);
        junction.Error.Should().Be(
            UpdateFileSystemError.UnsafePath);
    }

    [Fact]
    public void Observe_RejectsAmbiguousContentAndNonDeterministicArtifactPaths()
    {
        var installed = _native.AddRoot(
            @"C:\Program Files\WireguardSplitTunnel",
            Identity(1, 10),
            InstalledRootDescriptor);
        var backup = _native.AddRoot(
            @"C:\ProgramData\WireguardSplitTunnel\transactions\tx\backup",
            Identity(2, 20),
            BackupRootDescriptor);
        using var opened = CreateFileSystem().OpenSession(
            SessionRequest(installed, backup));
        var ambiguous = ValidOperation() with
        {
            NewContent = Content("old")
        };
        var arbitraryBackup = ValidOperation() with
        {
            BackupRelativePath = "other/sentinel.bak"
        };
        var arbitraryTemp = ValidOperation() with
        {
            TemporaryRelativePath = "bin/other.tmp"
        };

        foreach (var operation in new[]
                 {
                     ambiguous,
                     arbitraryBackup,
                     arbitraryTemp
                 })
        {
            opened.Session!.Observe(
                    operation,
                    UpdateFileLocation.Target)
                .Error.Should().Be(
                    UpdateFileSystemError.InvalidInput);
        }

        _native.RelativeRequests.Should().BeEmpty();
    }

    [Fact]
    public void Observe_WhenTargetPathIsPosixReplacedDuringRead_FailsClosed()
    {
        var installed = _native.AddRoot(
            @"C:\Program Files\WireguardSplitTunnel",
            Identity(1, 10),
            InstalledRootDescriptor);
        var bin = installed.AddDirectory(
            "bin",
            InstalledDirectoryDescriptor);
        var old = bin.AddFile(
            "app.exe",
            InstalledFileDescriptor,
            Bytes("old"));
        var replacement = bin.CreateDetachedFile(
            "app.exe",
            InstalledFileDescriptor,
            Bytes("attacker"));
        var backup = _native.AddRoot(
            @"C:\ProgramData\WireguardSplitTunnel\transactions\tx\backup",
            Identity(2, 20),
            BackupRootDescriptor);
        using var opened = CreateFileSystem().OpenSession(
            SessionRequest(installed, backup));
        _native.AfterReadStreamOpened = node =>
        {
            if (ReferenceEquals(node, old))
            {
                bin.ReplaceChild(
                    "app.exe",
                    replacement);
                _native.AfterReadStreamOpened = null;
            }
        };

        var result = opened.Session!.Observe(
            ValidOperation(),
            UpdateFileLocation.Target);

        result.Observation.Should().Be(
            UpdateFileObservation.Unknown);
        result.Error.Should().Be(
            UpdateFileSystemError.UnsafePath);
        bin.Children["app.exe"].Should().BeSameAs(
            replacement);
    }

    [Fact]
    public void Observe_WhenTargetContentChangesAfterInitialHash_FailsClosed()
    {
        var installed = _native.AddRoot(
            @"C:\Program Files\WireguardSplitTunnel",
            Identity(1, 10),
            InstalledRootDescriptor);
        var bin = installed.AddDirectory(
            "bin",
            InstalledDirectoryDescriptor);
        var target = bin.AddFile(
            "app.exe",
            InstalledFileDescriptor,
            Bytes("old"));
        var backup = _native.AddRoot(
            @"C:\ProgramData\WireguardSplitTunnel\transactions\tx\backup",
            Identity(2, 20),
            BackupRootDescriptor);
        using var opened = CreateFileSystem().OpenSession(
            SessionRequest(installed, backup));
        var targetOpens = 0;
        _native.BeforeOpenRelative = (_, name, request) =>
        {
            if (name == "app.exe"
                && request.Disposition
                    == ProtectedAclNativeDisposition.OpenExisting
                && ++targetOpens == 2)
            {
                target.WriteBytes(Bytes("bad"));
            }
        };

        var result = opened.Session!.Observe(
            ValidOperation(),
            UpdateFileLocation.Target);

        result.Observation.Should().Be(
            UpdateFileObservation.Unknown);
        result.Error.Should().Be(
            UpdateFileSystemError.UnsafePath);
    }

    [Fact]
    public void CreateBackup_CreateNewFlushesAndVerifiesWithoutChangingTarget()
    {
        var layout = CreateLayout();
        using var opened = CreateFileSystem().OpenSession(
            SessionRequest(
                layout.Installed,
                layout.Backup));

        var result = opened.Session!.CreateBackup(
            layout.Operation);

        result.Success.Should().BeTrue();
        result.NamespaceChanged.Should().BeTrue();
        layout.BackupBin.ReadFile("app.exe.bak")
            .Should().Equal(Bytes("old"));
        layout.Target!.ReadBytes()
            .Should().Equal(Bytes("old"));
        layout.BackupBin.FlushCount.Should().Be(1);
        var created = _native.CreatedRequests.Should()
            .ContainSingle(
            request => request.Name == "app.exe.bak"
                && request.Request.Disposition
                    == ProtectedAclNativeDisposition.CreateNew)
            .Subject;
        created.Request.SecurityDescriptor.Should().Equal(
            BackupFileDescriptor);
    }

    [Fact]
    public void CreateBackup_WhenBackupExists_FailsWithoutOverwritingSentinel()
    {
        var layout = CreateLayout();
        layout.BackupBin.AddFile(
            "app.exe.bak",
            BackupFileDescriptor,
            Bytes("sentinel"));
        using var opened = CreateFileSystem().OpenSession(
            SessionRequest(
                layout.Installed,
                layout.Backup));

        var result = opened.Session!.CreateBackup(
            layout.Operation);

        result.Success.Should().BeFalse();
        result.Error.Should().Be(
            UpdateFileSystemError.BackupCollision);
        result.NamespaceChanged.Should().BeFalse();
        layout.BackupBin.ReadFile("app.exe.bak")
            .Should().Equal(Bytes("sentinel"));
        layout.Target!.ReadBytes()
            .Should().Equal(Bytes("old"));
    }

    [Fact]
    public void CreateBackup_WhenFileFlushFails_PreservesEvidenceAndFailsClosed()
    {
        var layout = CreateLayout();
        _native.FailNextCreatedFileFlush = true;
        using var opened = CreateFileSystem().OpenSession(
            SessionRequest(
                layout.Installed,
                layout.Backup));

        var result = opened.Session!.CreateBackup(
            layout.Operation);

        result.Success.Should().BeFalse();
        result.Error.Should().Be(
            UpdateFileSystemError.FileFlushFailed);
        result.NamespaceChanged.Should().BeTrue();
        layout.BackupBin.Children.Should().ContainKey(
            "app.exe.bak");
        layout.Target!.ReadBytes()
            .Should().Equal(Bytes("old"));
    }

    [Fact]
    public void StageReplacement_CreateNewFlushesVerifiesAndPreservesSourcePosition()
    {
        var layout = CreateLayout();
        using var opened = CreateFileSystem().OpenSession(
            SessionRequest(
                layout.Installed,
                layout.Backup));
        using var source = new MemoryStream(
            Bytes("new"));
        source.Position = 1;

        var result = opened.Session!.StageReplacement(
            layout.Operation,
            source);

        result.Success.Should().BeTrue();
        result.NamespaceChanged.Should().BeTrue();
        layout.Bin.ReadFile("app.exe.update-tmp")
            .Should().Equal(Bytes("new"));
        layout.Target!.ReadBytes()
            .Should().Equal(Bytes("old"));
        source.CanRead.Should().BeTrue();
        source.Position.Should().Be(1);
        layout.Bin.FlushCount.Should().Be(1);
    }

    [Fact]
    public void StageReplacement_RejectsMissingReplaceUnknownTargetAndCrossVolumeTemp()
    {
        var missing = CreateLayout(
            targetBytes: null,
            useDefaultTarget: false);
        using var missingSession =
            CreateFileSystem().OpenSession(
                SessionRequest(
                    missing.Installed,
                    missing.Backup));
        using var source = new MemoryStream(
            Bytes("new"));

        var missingResult =
            missingSession.Session!.StageReplacement(
                missing.Operation,
                source);

        missingResult.Error.Should().Be(
            UpdateFileSystemError.UnexpectedTarget);
        missing.Bin.Children.Should().NotContainKey(
            "app.exe.update-tmp");

        _native.Reset();
        var crossVolume = CreateLayout();
        _native.NextCreatedFileVolume = 99;
        using var crossVolumeSession =
            CreateFileSystem().OpenSession(
                SessionRequest(
                    crossVolume.Installed,
                    crossVolume.Backup));

        var crossVolumeResult =
            crossVolumeSession.Session!.StageReplacement(
                crossVolume.Operation,
                source);

        crossVolumeResult.Error.Should().Be(
            UpdateFileSystemError.CrossVolume);
        crossVolumeResult.NamespaceChanged.Should().BeTrue();
        crossVolume.Bin.Children.Should().ContainKey(
            "app.exe.update-tmp");
        crossVolume.Target!.ReadBytes()
            .Should().Equal(Bytes("old"));
    }

    [Fact]
    public void StageReplacement_TempCollisionAndParentFlushFailurePreserveEvidence()
    {
        var collision = CreateLayout();
        collision.Bin.AddFile(
            "app.exe.update-tmp",
            InstalledFileDescriptor,
            Bytes("sentinel"));
        using var collisionSession =
            CreateFileSystem().OpenSession(
                SessionRequest(
                    collision.Installed,
                    collision.Backup));
        using var source = new MemoryStream(
            Bytes("new"));

        var collisionResult =
            collisionSession.Session!.StageReplacement(
                collision.Operation,
                source);

        collisionResult.Error.Should().Be(
            UpdateFileSystemError.TemporaryCollision);
        collisionResult.NamespaceChanged.Should().BeFalse();
        collision.Bin.ReadFile(
                "app.exe.update-tmp")
            .Should().Equal(Bytes("sentinel"));
        collision.Target!.ReadBytes()
            .Should().Equal(Bytes("old"));

        _native.Reset();
        var flush = CreateLayout();
        using var flushSession =
            CreateFileSystem().OpenSession(
                SessionRequest(
                    flush.Installed,
                    flush.Backup));
        _native.FailNextDirectoryFlush = true;

        var flushResult =
            flushSession.Session!.StageReplacement(
                flush.Operation,
                source);

        flushResult.Error.Should().Be(
            UpdateFileSystemError.DirectoryFlushFailed);
        flushResult.NamespaceChanged.Should().BeTrue();
        flush.Bin.ReadFile("app.exe.update-tmp")
            .Should().Equal(Bytes("new"));
        flush.Target!.ReadBytes()
            .Should().Equal(Bytes("old"));
    }

    [Fact]
    public void ApplyReplace_AtomicallyInstallsExactTempAndLeavesBackupAndSentinelsUntouched()
    {
        var layout = CreateLayout();
        layout.Bin.AddFile(
            "sentinel.txt",
            InstalledFileDescriptor,
            Bytes("sentinel"));
        layout.BackupBin.AddFile(
            "sentinel.bak",
            BackupFileDescriptor,
            Bytes("backup-sentinel"));
        using var opened = CreateFileSystem().OpenSession(
            SessionRequest(
                layout.Installed,
                layout.Backup));
        using var source = new MemoryStream(
            Bytes("new"));
        opened.Session!.CreateBackup(
                layout.Operation)
            .Success.Should().BeTrue();
        opened.Session.StageReplacement(
                layout.Operation,
                source)
            .Success.Should().BeTrue();

        var result = opened.Session.Apply(
            layout.Operation);

        result.Success.Should().BeTrue();
        result.NamespaceChanged.Should().BeTrue();
        layout.Bin.ReadFile("app.exe")
            .Should().Equal(Bytes("new"));
        layout.Bin.Children.Should().NotContainKey(
            "app.exe.update-tmp");
        layout.BackupBin.ReadFile("app.exe.bak")
            .Should().Equal(Bytes("old"));
        layout.Bin.ReadFile("sentinel.txt")
            .Should().Equal(Bytes("sentinel"));
        layout.BackupBin.ReadFile("sentinel.bak")
            .Should().Equal(Bytes("backup-sentinel"));
        _native.RenameCount.Should().Be(1);
        _native.DestinationOpenHandlesAtRename
            .Should().Be(0);
        _native.EnumerationCount.Should().Be(0);

        var repeated = opened.Session.Apply(
            layout.Operation);
        repeated.Success.Should().BeTrue();
        repeated.NamespaceChanged.Should().BeFalse();
        _native.RenameCount.Should().Be(1);
    }

    [Fact]
    public void ApplyReplace_MissingBackupUnknownTempOrMissingTargetFailsWithoutRename()
    {
        var noBackup = CreateLayout();
        using var noBackupSession =
            CreateFileSystem().OpenSession(
                SessionRequest(
                    noBackup.Installed,
                    noBackup.Backup));
        using var source = new MemoryStream(
            Bytes("new"));
        noBackupSession.Session!.StageReplacement(
                noBackup.Operation,
                source)
            .Success.Should().BeTrue();

        var missingBackup = noBackupSession.Session.Apply(
            noBackup.Operation);

        missingBackup.Error.Should().Be(
            UpdateFileSystemError.UnexpectedBackup);
        _native.RenameCount.Should().Be(0);
        noBackup.Target!.ReadBytes()
            .Should().Equal(Bytes("old"));

        _native.Reset();
        var unknownTemp = CreateLayout();
        using var unknownTempSession =
            CreateFileSystem().OpenSession(
                SessionRequest(
                    unknownTemp.Installed,
                    unknownTemp.Backup));
        unknownTempSession.Session!.CreateBackup(
                unknownTemp.Operation)
            .Success.Should().BeTrue();
        unknownTempSession.Session.StageReplacement(
                unknownTemp.Operation,
                source)
            .Success.Should().BeTrue();
        unknownTemp.Bin.Children[
                "app.exe.update-tmp"]
            .WriteBytes(Bytes("attacker"));

        var badTemp = unknownTempSession.Session.Apply(
            unknownTemp.Operation);

        badTemp.Error.Should().Be(
            UpdateFileSystemError.UnexpectedTemporary);
        _native.RenameCount.Should().Be(0);
        unknownTemp.Target!.ReadBytes()
            .Should().Equal(Bytes("old"));

        unknownTemp.Bin.RemoveChild("app.exe");
        var missingTarget =
            unknownTempSession.Session.Apply(
                unknownTemp.Operation);
        missingTarget.Error.Should().Be(
            UpdateFileSystemError.UnexpectedTarget);
        _native.RenameCount.Should().Be(0);
    }

    [Fact]
    public void ApplyReplace_UnknownBackupFailsWithoutChangingAnyInstallFile()
    {
        var layout = CreateLayout();
        layout.BackupBin.AddFile(
            "app.exe.bak",
            BackupFileDescriptor,
            Bytes("attacker"));
        using var opened = CreateFileSystem().OpenSession(
            SessionRequest(
                layout.Installed,
                layout.Backup));
        using var source = new MemoryStream(
            Bytes("new"));
        opened.Session!.StageReplacement(
                layout.Operation,
                source)
            .Success.Should().BeTrue();

        var result = opened.Session.Apply(
            layout.Operation);

        result.Error.Should().Be(
            UpdateFileSystemError.UnexpectedBackup);
        _native.RenameCount.Should().Be(0);
        layout.Target!.ReadBytes()
            .Should().Equal(Bytes("old"));
        layout.Bin.ReadFile("app.exe.update-tmp")
            .Should().Equal(Bytes("new"));
        layout.BackupBin.ReadFile("app.exe.bak")
            .Should().Equal(Bytes("attacker"));
    }

    [Fact]
    public void Apply_WhenParentFlushFailsAfterRename_ReportsTheCommittedNamespace()
    {
        var layout = CreateLayout();
        using var opened = CreateFileSystem().OpenSession(
            SessionRequest(
                layout.Installed,
                layout.Backup));
        using var source = new MemoryStream(
            Bytes("new"));
        opened.Session!.CreateBackup(
                layout.Operation)
            .Success.Should().BeTrue();
        opened.Session.StageReplacement(
                layout.Operation,
                source)
            .Success.Should().BeTrue();
        _native.FailNextRenameFlush = true;

        var result = opened.Session.Apply(
            layout.Operation);

        result.Success.Should().BeFalse();
        result.Error.Should().Be(
            UpdateFileSystemError.DirectoryFlushFailed);
        result.NamespaceChanged.Should().BeTrue();
        layout.Bin.ReadFile("app.exe")
            .Should().Equal(Bytes("new"));
        layout.BackupBin.ReadFile("app.exe.bak")
            .Should().Equal(Bytes("old"));
    }

    [Fact]
    public void Apply_WhenTargetIsSwappedAfterReleaseBeforeRename_ReturnsRecoveryBlocked()
    {
        var layout = CreateLayout();
        var attacker = layout.Bin.CreateDetachedFile(
            "app.exe",
            InstalledFileDescriptor,
            Bytes("bad"));
        var fileSystem = CreateFileSystem(
            point =>
            {
                if (point
                    == UpdateFileSystemFaultPoint
                        .TargetReleasedBeforeRename)
                {
                    layout.Bin.ReplaceChild(
                        "app.exe",
                        attacker);
                }
            });
        using var opened = fileSystem.OpenSession(
            SessionRequest(
                layout.Installed,
                layout.Backup));
        using var source = new MemoryStream(
            Bytes("new"));
        opened.Session!.CreateBackup(
                layout.Operation)
            .Success.Should().BeTrue();
        opened.Session.StageReplacement(
                layout.Operation,
                source)
            .Success.Should().BeTrue();

        var result = opened.Session.Apply(
            layout.Operation);

        result.Success.Should().BeFalse();
        result.Error.Should().Be(
            UpdateFileSystemError.RecoveryBlocked);
        result.NamespaceChanged.Should().BeFalse();
        _native.RenameCount.Should().Be(0);
        layout.Bin.ReadFile("app.exe")
            .Should().Equal(Bytes("bad"));
        layout.Bin.ReadFile("app.exe.update-tmp")
            .Should().Equal(Bytes("new"));
        layout.BackupBin.ReadFile("app.exe.bak")
            .Should().Equal(Bytes("old"));
    }

    [Fact]
    public void RollbackReplace_CopiesVerifiedBackupToSameVolumeAndRestoresAtomically()
    {
        var layout = CreateLayout();
        using var opened = CreateFileSystem().OpenSession(
            SessionRequest(
                layout.Installed,
                layout.Backup));
        using var source = new MemoryStream(
            Bytes("new"));
        opened.Session!.CreateBackup(
                layout.Operation)
            .Success.Should().BeTrue();
        opened.Session.StageReplacement(
                layout.Operation,
                source)
            .Success.Should().BeTrue();
        opened.Session.Apply(layout.Operation)
            .Success.Should().BeTrue();

        var result = opened.Session.Rollback(
            layout.Operation);

        result.Success.Should().BeTrue();
        result.NamespaceChanged.Should().BeTrue();
        layout.Bin.ReadFile("app.exe")
            .Should().Equal(Bytes("old"));
        layout.BackupBin.ReadFile("app.exe.bak")
            .Should().Equal(Bytes("old"));
        layout.Bin.Children.Should().NotContainKey(
            "app.exe.update-tmp");
        _native.RenameCount.Should().Be(2);
        _native.EnumerationCount.Should().Be(0);

        var repeated = opened.Session.Rollback(
            layout.Operation);
        repeated.Success.Should().BeTrue();
        repeated.NamespaceChanged.Should().BeFalse();
    }

    [Fact]
    public void RollbackReplace_WhenAppliedTargetIsMissing_FailsClosedAndKeepsBackup()
    {
        var layout = CreateLayout();
        using var opened = CreateFileSystem().OpenSession(
            SessionRequest(
                layout.Installed,
                layout.Backup));
        using var source = new MemoryStream(
            Bytes("new"));
        opened.Session!.CreateBackup(
                layout.Operation)
            .Success.Should().BeTrue();
        opened.Session.StageReplacement(
                layout.Operation,
                source)
            .Success.Should().BeTrue();
        opened.Session.Apply(layout.Operation)
            .Success.Should().BeTrue();
        layout.Bin.RemoveChild("app.exe");

        var result = opened.Session.Rollback(
            layout.Operation);

        result.Error.Should().Be(
            UpdateFileSystemError.UnexpectedTarget);
        _native.RenameCount.Should().Be(1);
        _native.DeleteCount.Should().Be(0);
        layout.BackupBin.ReadFile("app.exe.bak")
            .Should().Equal(Bytes("old"));
    }

    [Fact]
    public void RollbackBeforeApply_RemovesOnlyExactDeterministicTemp()
    {
        var replace = CreateLayout();
        using var replaceSession =
            CreateFileSystem().OpenSession(
                SessionRequest(
                    replace.Installed,
                    replace.Backup));
        using var source = new MemoryStream(
            Bytes("new"));
        replaceSession.Session!.CreateBackup(
                replace.Operation)
            .Success.Should().BeTrue();
        replaceSession.Session.StageReplacement(
                replace.Operation,
                source)
            .Success.Should().BeTrue();

        var replaceRollback =
            replaceSession.Session.Rollback(
                replace.Operation);

        replaceRollback.Success.Should().BeTrue();
        replaceRollback.NamespaceChanged.Should().BeTrue();
        replace.Bin.Children.Should().NotContainKey(
            "app.exe.update-tmp");
        replace.Target!.ReadBytes()
            .Should().Equal(Bytes("old"));

        _native.Reset();
        var create = CreateLayout(
            targetBytes: null,
            useDefaultTarget: false);
        var createOperation = create.Operation with
        {
            TargetExisted = false,
            OldContent = null
        };
        using var createSession =
            CreateFileSystem().OpenSession(
                SessionRequest(
                    create.Installed,
                    create.Backup));
        createSession.Session!.StageReplacement(
                createOperation,
                source)
            .Success.Should().BeTrue();

        var createRollback =
            createSession.Session.Rollback(
                createOperation);

        createRollback.Success.Should().BeTrue();
        createRollback.NamespaceChanged.Should().BeTrue();
        create.Bin.Children.Should().NotContainKey(
            "app.exe.update-tmp");
        create.Bin.Children.Should().NotContainKey(
            "app.exe");
    }

    [Fact]
    public void RollbackBeforeApply_UnknownTempIsPreservedAndBlocksRecovery()
    {
        var layout = CreateLayout();
        using var opened = CreateFileSystem().OpenSession(
            SessionRequest(
                layout.Installed,
                layout.Backup));
        using var source = new MemoryStream(
            Bytes("new"));
        opened.Session!.CreateBackup(
                layout.Operation)
            .Success.Should().BeTrue();
        opened.Session.StageReplacement(
                layout.Operation,
                source)
            .Success.Should().BeTrue();
        layout.Bin.Children["app.exe.update-tmp"]
            .WriteBytes(Bytes("bad"));

        var result = opened.Session.Rollback(
            layout.Operation);

        result.Success.Should().BeFalse();
        result.Error.Should().Be(
            UpdateFileSystemError.UnexpectedTemporary);
        layout.Bin.ReadFile("app.exe.update-tmp")
            .Should().Equal(Bytes("bad"));
        layout.Target!.ReadBytes()
            .Should().Equal(Bytes("old"));
    }

    [Fact]
    public void RollbackCreate_DeletesOnlyExactNewAndPreservesUnknownContent()
    {
        var layout = CreateLayout(
            targetBytes: null,
            useDefaultTarget: false);
        var operation = layout.Operation with
        {
            TargetExisted = false,
            OldContent = null
        };
        using var opened = CreateFileSystem().OpenSession(
            SessionRequest(
                layout.Installed,
                layout.Backup));
        using var source = new MemoryStream(
            Bytes("new"));
        opened.Session!.StageReplacement(
                operation,
                source)
            .Success.Should().BeTrue();
        opened.Session.Apply(operation)
            .Success.Should().BeTrue();

        var result = opened.Session.Rollback(operation);

        result.Success.Should().BeTrue();
        result.NamespaceChanged.Should().BeTrue();
        layout.Bin.Children.Should().NotContainKey(
            "app.exe");
        _native.DeleteCount.Should().Be(1);

        layout.Bin.AddFile(
            "app.exe",
            InstalledFileDescriptor,
            Bytes("sentinel"));
        var unknown = opened.Session.Rollback(operation);
        unknown.Success.Should().BeFalse();
        unknown.Error.Should().Be(
            UpdateFileSystemError.UnexpectedTarget);
        layout.Bin.ReadFile("app.exe")
            .Should().Equal(Bytes("sentinel"));
        _native.DeleteCount.Should().Be(1);
        _native.EnumerationCount.Should().Be(0);
    }

    public void Dispose() => _native.Dispose();

    private UpdateFileSystem CreateFileSystem(
        Action<UpdateFileSystemFaultPoint>? fault = null) =>
        new(
            _native,
            new UpdateFileSystemSecurityPolicy(
                descriptor => Matches(
                    descriptor,
                    InstalledRootDescriptor),
                (descriptor, directory) => Matches(
                    descriptor,
                    directory
                        ? InstalledDirectoryDescriptor
                        : InstalledFileDescriptor),
                descriptor => Matches(
                    descriptor,
                    BackupRootDescriptor),
                (descriptor, directory) => Matches(
                    descriptor,
                    directory
                        ? BackupDirectoryDescriptor
                        : BackupFileDescriptor),
                InstalledFileDescriptor,
                BackupFileDescriptor),
            _ => DriveType.Fixed,
            fault);

    private static UpdateFileOperationInput ValidOperation() =>
        new(
            "bin/app.exe",
            TargetExisted: true,
            OldContent: Content("old"),
            NewContent: Content("new"),
            BackupRelativePath: "bin/app.exe.bak",
            TemporaryRelativePath: "bin/app.exe.update-tmp");

    private static UpdateFileSystemSessionRequest SessionRequest(
        FakeNativeFileSystem.FakeNode installed,
        FakeNativeFileSystem.FakeNode backup) =>
        new(
            installed.FinalPath,
            FileIdentity(installed.Identity),
            backup.FinalPath,
            FileIdentity(backup.Identity));

    private static byte[] Bytes(string value) =>
        System.Text.Encoding.UTF8.GetBytes(value);

    private TestLayout CreateLayout(
        byte[]? targetBytes = null,
        bool useDefaultTarget = true)
    {
        var installed = _native.AddRoot(
            @"C:\Program Files\WireguardSplitTunnel",
            Identity(1, 10),
            InstalledRootDescriptor);
        var bin = installed.AddDirectory(
            "bin",
            InstalledDirectoryDescriptor);
        FakeNativeFileSystem.FakeNode? target = null;
        if (useDefaultTarget || targetBytes is not null)
        {
            target = bin.AddFile(
                "app.exe",
                InstalledFileDescriptor,
                targetBytes ?? Bytes("old"));
        }

        var backup = _native.AddRoot(
            @"C:\ProgramData\WireguardSplitTunnel\transactions\tx\backup",
            Identity(2, 20),
            BackupRootDescriptor);
        var backupBin = backup.AddDirectory(
            "bin",
            BackupDirectoryDescriptor);
        return new TestLayout(
            installed,
            bin,
            target,
            backup,
            backupBin,
            ValidOperation());
    }

    private sealed record TestLayout(
        FakeNativeFileSystem.FakeNode Installed,
        FakeNativeFileSystem.FakeNode Bin,
        FakeNativeFileSystem.FakeNode? Target,
        FakeNativeFileSystem.FakeNode Backup,
        FakeNativeFileSystem.FakeNode BackupBin,
        UpdateFileOperationInput Operation);

    private static UpdateFileContentIdentity Content(
        string value)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(value);
        return new UpdateFileContentIdentity(
            bytes.Length,
            Convert.ToHexString(
                    System.Security.Cryptography.SHA256.HashData(bytes))
                .ToLowerInvariant());
    }

    private static UpdateFileIdentity128 FileIdentity(
        ProtectedFileIdentity128 identity) =>
        new(
            identity.VolumeSerialNumber,
            identity.FileIdLow,
            identity.FileIdHigh);

    private static ProtectedFileIdentity128 Identity(
        ulong volume,
        ulong low,
        ulong high = 0) =>
        new(volume, low, high);

    private static bool Matches(
        byte[] actual,
        byte[] expected) =>
        actual.AsSpan().SequenceEqual(expected);

    private sealed class FakeNativeFileSystem
        : IProtectedAclNativeFileSystem,
          IDisposable
    {
        private readonly Dictionary<string, FakeNode> _roots =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly string _storageRoot = Path.Combine(
            Path.GetTempPath(),
            "update-filesystem-tests",
            Guid.NewGuid().ToString("N"));
        private ulong _nextIdentity = 100;

        public List<RootOpenRequest> RootRequests { get; } = [];
        public List<RelativeOpenRequest> RelativeRequests { get; } =
            [];
        public List<RelativeOpenRequest> CreatedRequests { get; } =
            [];
        public Action<FakeNode>? AfterReadStreamOpened { get; set; }
        public Action<
            FakeNode,
            string,
            ProtectedAclNativeOpenRequest>?
            BeforeOpenRelative { get; set; }
        public bool FailNextCreatedFileFlush { get; set; }
        public ulong? NextCreatedFileVolume { get; set; }
        public bool FailNextRenameFlush { get; set; }
        public bool FailNextDirectoryFlush { get; set; }
        public int RenameCount { get; private set; }
        public int DeleteCount { get; private set; }
        public int EnumerationCount { get; private set; }
        public int DestinationOpenHandlesAtRename { get; private set; }

        public void Reset()
        {
            foreach (var root in _roots.Values.ToArray())
            {
                root.MarkDeletedRecursively();
            }

            _roots.Clear();
            RootRequests.Clear();
            RelativeRequests.Clear();
            CreatedRequests.Clear();
            AfterReadStreamOpened = null;
            FailNextCreatedFileFlush = false;
            NextCreatedFileVolume = null;
            FailNextRenameFlush = false;
            FailNextDirectoryFlush = false;
            RenameCount = 0;
            DeleteCount = 0;
            EnumerationCount = 0;
            DestinationOpenHandlesAtRename = 0;
        }

        public FakeNode AddRoot(
            string path,
            ProtectedFileIdentity128 identity,
            byte[] descriptor)
        {
            Directory.CreateDirectory(_storageRoot);
            var node = new FakeNode(
                this,
                parent: null,
                name: path,
                directory: true,
                identity,
                descriptor,
                storagePath: null);
            _roots.Add(path, node);
            return node;
        }

        public ProtectedAclNativeOpenResult OpenRoot(
            string rootPath,
            bool openReparsePoint,
            bool shareDelete,
            bool requireWriteAccess = false)
        {
            RootRequests.Add(
                new RootOpenRequest(
                    rootPath,
                    openReparsePoint,
                    shareDelete,
                    requireWriteAccess));
            return _roots.TryGetValue(
                    rootPath,
                    out var root)
                ? ProtectedAclNativeOpenResult.Opened(
                    new FakeHandle(root))
                : ProtectedAclNativeOpenResult.Failed(
                    ProtectedAclError.Missing);
        }

        public ProtectedAclNativeOpenResult OpenRelative(
            IProtectedAclNativeHandle parent,
            string name,
            ProtectedAclNativeOpenRequest request)
        {
            if (parent is not FakeHandle handle
                || handle.Node.Deleted
                || !handle.Node.Directory)
            {
                return ProtectedAclNativeOpenResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            BeforeOpenRelative?.Invoke(
                handle.Node,
                name,
                request);

            RelativeRequests.Add(
                new RelativeOpenRequest(
                    handle.Node.Identity,
                    name,
                    request));

            if (handle.Node.Children.TryGetValue(
                    name,
                    out var existing))
            {
                return request.Disposition
                        == ProtectedAclNativeDisposition.CreateNew
                    ? ProtectedAclNativeOpenResult.Failed(
                        ProtectedAclError.AlreadyExists)
                    : ProtectedAclNativeOpenResult.Opened(
                        new FakeHandle(existing));
            }

            if (request.Disposition
                == ProtectedAclNativeDisposition.OpenExisting)
            {
                return ProtectedAclNativeOpenResult.Failed(
                    ProtectedAclError.Missing);
            }

            var directory = request.Kind
                == ProtectedAclNativeObjectKind.Directory;
            var storage = directory
                ? null
                : Path.Combine(
                    _storageRoot,
                    Guid.NewGuid().ToString("N"));
            if (storage is not null)
            {
                using var created = new FileStream(
                    storage,
                    FileMode.CreateNew,
                    FileAccess.ReadWrite,
                    FileShare.Read);
            }

            var node = new FakeNode(
                this,
                handle.Node,
                name,
                directory,
                Identity(
                    NextCreatedFileVolume
                        ?? handle.Node.Identity.VolumeSerialNumber,
                    _nextIdentity++),
                request.SecurityDescriptor ?? [],
                storage)
            {
                FailFlush = FailNextCreatedFileFlush
            };
            FailNextCreatedFileFlush = false;
            NextCreatedFileVolume = null;
            handle.Node.Children.Add(name, node);
            CreatedRequests.Add(
                new RelativeOpenRequest(
                    handle.Node.Identity,
                    name,
                    request));
            return ProtectedAclNativeOpenResult.Opened(
                new FakeHandle(node));
        }

        public ProtectedAclNativeOperationResult FlushDirectory(
            IProtectedAclNativeHandle directory)
        {
            if (directory is not FakeHandle handle
                || !handle.Node.Directory
                || handle.Node.Deleted)
            {
                return ProtectedAclNativeOperationResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            handle.Node.FlushCount++;
            if (FailNextDirectoryFlush)
            {
                FailNextDirectoryFlush = false;
                return ProtectedAclNativeOperationResult.Failed(
                    ProtectedAclError.IoFailure);
            }

            return ProtectedAclNativeOperationResult.Committed(
                namespaceChanged: false);
        }

        public ProtectedAclNativeOperationResult RenameRelative(
            IProtectedAclNativeHandle source,
            IProtectedAclNativeHandle destinationDirectory,
            string destinationName,
            bool replaceIfExists)
        {
            if (source is not FakeHandle sourceHandle
                || destinationDirectory
                    is not FakeHandle destination
                || sourceHandle.Node.Deleted
                || destination.Node.Deleted
                || !destination.Node.Directory)
            {
                return ProtectedAclNativeOperationResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            var sourceNode = sourceHandle.Node;
            if (sourceNode.Parent is null
                || sourceNode.Identity.VolumeSerialNumber
                    != destination.Node.Identity
                        .VolumeSerialNumber)
            {
                return ProtectedAclNativeOperationResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            DestinationOpenHandlesAtRename =
                destination.Node.Children.TryGetValue(
                    destinationName,
                    out var existing)
                    ? existing.OpenHandles
                    : 0;
            if (existing is not null)
            {
                if (!replaceIfExists)
                {
                    return ProtectedAclNativeOperationResult.Failed(
                        ProtectedAclError.AlreadyExists);
                }

                existing.Deleted = true;
                destination.Node.Children.Remove(
                    destinationName);
            }

            sourceNode.Parent.Children.Remove(
                sourceNode.Name);
            sourceNode.Parent = destination.Node;
            sourceNode.Name = destinationName;
            destination.Node.Children[destinationName] =
                sourceNode;
            RenameCount++;
            destination.Node.FlushCount++;
            if (FailNextRenameFlush)
            {
                FailNextRenameFlush = false;
                return ProtectedAclNativeOperationResult.Failed(
                    ProtectedAclError.IoFailure,
                    namespaceChanged: true);
            }

            return ProtectedAclNativeOperationResult.Committed();
        }

        public ProtectedAclNativeOperationResult Delete(
            IProtectedAclNativeHandle target,
            bool directory)
        {
            if (target is not FakeHandle handle
                || handle.Node.Deleted
                || handle.Node.Directory != directory
                || handle.Node.ReparsePoint
                || handle.Node.Parent is null)
            {
                return ProtectedAclNativeOperationResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            handle.Node.Parent.Children.Remove(
                handle.Node.Name);
            handle.Node.Deleted = true;
            DeleteCount++;
            return ProtectedAclNativeOperationResult.Committed();
        }

        public ProtectedAclNativeEnumerationResult
            EnumerateRelative(
                IProtectedAclNativeHandle directory)
        {
            EnumerationCount++;
            return ProtectedAclNativeEnumerationResult.Failed(
                ProtectedAclError.IoFailure);
        }

        public void Dispose()
        {
            if (Directory.Exists(_storageRoot))
            {
                Directory.Delete(
                    _storageRoot,
                    recursive: true);
            }
        }

        public sealed class FakeNode
        {
            private readonly FakeNativeFileSystem _owner;

            public FakeNode(
                FakeNativeFileSystem owner,
                FakeNode? parent,
                string name,
                bool directory,
                ProtectedFileIdentity128 identity,
                byte[] descriptor,
                string? storagePath)
            {
                _owner = owner;
                Parent = parent;
                Name = name;
                Directory = directory;
                Identity = identity;
                Descriptor = descriptor.ToArray();
                StoragePath = storagePath;
            }

            public FakeNode? Parent { get; set; }
            public FakeNativeFileSystem Owner => _owner;
            public string Name { get; set; }
            public bool Directory { get; }
            public bool ReparsePoint { get; set; }
            public bool Deleted { get; set; }
            public bool FailFlush { get; set; }
            public int FlushCount { get; set; }
            public ProtectedFileIdentity128 Identity { get; set; }
            public byte[] Descriptor { get; set; }
            public string? StoragePath { get; }
            public int OpenHandles { get; set; }
            public Dictionary<string, FakeNode> Children { get; } =
                new(StringComparer.OrdinalIgnoreCase);

            public string FinalPath =>
                Parent is null
                    ? Name
                    : Path.Combine(
                        Parent.FinalPath,
                        Name);

            public FakeNode AddDirectory(
                string name,
                byte[] descriptor) =>
                AddNode(
                    name,
                    directory: true,
                    descriptor,
                    []);

            public FakeNode AddFile(
                string name,
                byte[] descriptor,
                byte[] bytes) =>
                AddNode(
                    name,
                    directory: false,
                    descriptor,
                    bytes);

            public FakeNode CreateDetachedFile(
                string name,
                byte[] descriptor,
                byte[] bytes)
            {
                var child = AddNode(
                    name + ".detached",
                    directory: false,
                    descriptor,
                    bytes);
                Children.Remove(child.Name);
                child.Name = name;
                return child;
            }

            public void ReplaceChild(
                string name,
                FakeNode replacement)
            {
                replacement.Parent = this;
                replacement.Name = name;
                Children[name] = replacement;
            }

            public byte[] ReadBytes()
            {
                if (StoragePath is null)
                {
                    throw new InvalidOperationException();
                }

                return File.ReadAllBytes(StoragePath);
            }

            public byte[] ReadFile(string name) =>
                Children[name].ReadBytes();

            public void WriteBytes(byte[] bytes)
            {
                if (StoragePath is null)
                {
                    throw new InvalidOperationException();
                }

                File.WriteAllBytes(StoragePath, bytes);
            }

            public void RemoveChild(string name)
            {
                var child = Children[name];
                Children.Remove(name);
                child.Deleted = true;
            }

            public void MarkDeletedRecursively()
            {
                Deleted = true;
                foreach (var child in Children.Values)
                {
                    child.MarkDeletedRecursively();
                }
            }

            private FakeNode AddNode(
                string name,
                bool directory,
                byte[] descriptor,
                byte[] bytes)
            {
                var storage = directory
                    ? null
                    : Path.Combine(
                        _owner._storageRoot,
                        Guid.NewGuid().ToString("N"));
                if (storage is not null)
                {
                    System.IO.Directory.CreateDirectory(
                        _owner._storageRoot);
                    File.WriteAllBytes(storage, bytes);
                }

                var child = new FakeNode(
                    _owner,
                    this,
                    name,
                    directory,
                    Identity(
                        Identity.VolumeSerialNumber,
                        _owner._nextIdentity++),
                    descriptor,
                    storage);
                Children.Add(name, child);
                return child;
            }
        }

        private sealed class FakeHandle
            : IProtectedAclNativeHandle
        {
            private bool _disposed;

            public FakeHandle(FakeNode node)
            {
                Node = node;
                Node.OpenHandles++;
            }

            public FakeNode Node { get; }

            public ProtectedAclNativeSnapshot ReadSnapshot()
            {
                ObjectDisposedException.ThrowIf(
                    _disposed,
                    this);
                return new ProtectedAclNativeSnapshot(
                    Node.Directory,
                    Node.ReparsePoint,
                    Node.FinalPath,
                    Node.Identity,
                    Node.Descriptor.ToArray());
            }

            public FileStream TakeFileStream() =>
                OpenFileStream(FileAccess.ReadWrite);

            public FileStream OpenFileStream(
                FileAccess access)
            {
                ObjectDisposedException.ThrowIf(
                    _disposed,
                    this);
                if (Node.StoragePath is null)
                {
                    throw new InvalidOperationException();
                }

                if (access == FileAccess.Read)
                {
                    Node.Owner.AfterReadStreamOpened?.Invoke(
                        Node);
                }

                return Node.FailFlush
                    ? new FlushFailingFileStream(
                        Node.StoragePath,
                        access)
                    : new FileStream(
                    Node.StoragePath,
                    FileMode.Open,
                    access,
                    FileShare.Read);
            }

            public void Dispose()
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
                Node.OpenHandles--;
            }
        }

        public sealed record RootOpenRequest(
            string Path,
            bool OpenReparsePoint,
            bool ShareDelete,
            bool RequireWriteAccess);

        public sealed record RelativeOpenRequest(
            ProtectedFileIdentity128 ParentIdentity,
            string Name,
            ProtectedAclNativeOpenRequest Request);

        private sealed class FlushFailingFileStream
            : FileStream
        {
            public FlushFailingFileStream(
                string path,
                FileAccess access)
                : base(
                    path,
                    FileMode.Open,
                    access,
                    FileShare.Read)
            {
            }

            public override void Flush(bool flushToDisk) =>
                throw new IOException(
                    "Injected file flush failure.");
        }
    }
}
