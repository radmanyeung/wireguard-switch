using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Transactions;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed partial class ProtectedTransactionStoreTests
{
    [Fact]
    public void InstalledReleaseSecurityPolicy_SeparatesTheExactRootAndInheritedDescendantDescriptors()
    {
        var root = InstalledDescriptor(
            InstalledReleaseSecurityScope.RootDirectory);
        var directory = InstalledDescriptor(
            InstalledReleaseSecurityScope
                .DescendantDirectory);
        var file = InstalledDescriptor(
            InstalledReleaseSecurityScope.ManagedFile);

        InstalledReleaseSecurityPolicy.HasExactDescriptor(
                root,
                InstalledReleaseSecurityScope.RootDirectory)
            .Should().BeTrue();
        InstalledReleaseSecurityPolicy.HasExactDescriptor(
                directory,
                InstalledReleaseSecurityScope
                    .DescendantDirectory)
            .Should().BeTrue();
        InstalledReleaseSecurityPolicy.HasExactDescriptor(
                file,
                InstalledReleaseSecurityScope.ManagedFile)
            .Should().BeTrue();
        InstalledReleaseSecurityPolicy.HasExactDescriptor(
                root,
                InstalledReleaseSecurityScope
                    .DescendantDirectory)
            .Should().BeFalse();
        InstalledReleaseSecurityPolicy.HasExactDescriptor(
                directory,
                InstalledReleaseSecurityScope.RootDirectory)
            .Should().BeFalse();
    }

    [Fact]
    public void InstalledReleaseSecurityPolicy_RejectsExtraDenyOrUserWriteAces()
    {
        InstalledReleaseSecurityPolicy.HasExactDescriptor(
                InstalledDescriptor(
                    InstalledReleaseSecurityScope.RootDirectory,
                    usersMask:
                        (int)FileSystemRights.Modify),
                InstalledReleaseSecurityScope.RootDirectory)
            .Should().BeFalse();
        InstalledReleaseSecurityPolicy.HasExactDescriptor(
                InstalledDescriptor(
                    InstalledReleaseSecurityScope.RootDirectory,
                    addWorldAce: true),
                InstalledReleaseSecurityScope.RootDirectory)
            .Should().BeFalse();
        InstalledReleaseSecurityPolicy.HasExactDescriptor(
                InstalledDescriptor(
                    InstalledReleaseSecurityScope.RootDirectory,
                    denyUsers: true),
                InstalledReleaseSecurityScope.RootDirectory)
            .Should().BeFalse();
        InstalledReleaseSecurityPolicy.HasExactDescriptor(
                ReplaceDescriptorOwner(
                    InstalledDescriptor(
                        InstalledReleaseSecurityScope
                            .ManagedFile),
                    new SecurityIdentifier(
                        WellKnownSidType.BuiltinUsersSid,
                        domainSid: null)),
                InstalledReleaseSecurityScope.ManagedFile)
            .Should().BeFalse();
    }

    [Fact]
    public void InstalledReleaseSecurityPolicy_UsesRealWindowsInheritedDirectoryAndLeafAceFlags()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var currentUser =
            WindowsIdentity.GetCurrent().User!;
        var root = Path.Combine(
            Path.GetTempPath(),
            $"WireguardSplitTunnel.StoreAcl.{Guid.NewGuid():N}");
        var child = Path.Combine(root, "nested");
        var file = Path.Combine(child, "payload.bin");
        Directory.CreateDirectory(child);
        File.WriteAllBytes(file, "payload"u8.ToArray());
        try
        {
            new DirectoryInfo(root).SetAccessControl(
                InstalledRootSecurityForInheritanceTest(
                    currentUser));

            var actualRoot =
                new DirectorySecurity(
                    root,
                    AccessControlSections.Owner
                        | AccessControlSections.Access)
                    .GetSecurityDescriptorBinaryForm();
            var actualChild =
                new DirectorySecurity(
                    child,
                    AccessControlSections.Owner
                        | AccessControlSections.Access)
                    .GetSecurityDescriptorBinaryForm();
            var actualFile =
                new FileSecurity(
                    file,
                    AccessControlSections.Owner
                        | AccessControlSections.Access)
                    .GetSecurityDescriptorBinaryForm();

            InstalledReleaseSecurityPolicy.HasExactDescriptor(
                    actualRoot,
                    InstalledReleaseSecurityScope.RootDirectory)
                .Should().BeFalse(
                    "the non-elevated test root is not SYSTEM-owned");
            InstalledReleaseSecurityPolicy.HasExactDescriptor(
                    NormalizeOwnerToSystemForDaclInheritanceAssertionOnly(
                        actualRoot),
                    InstalledReleaseSecurityScope.RootDirectory)
                .Should().BeTrue();
            InstalledReleaseSecurityPolicy.HasExactDescriptor(
                    NormalizeOwnerToSystemForDaclInheritanceAssertionOnly(
                        actualChild),
                    InstalledReleaseSecurityScope
                        .DescendantDirectory)
                .Should().BeTrue();
            InstalledReleaseSecurityPolicy.HasExactDescriptor(
                    NormalizeOwnerToSystemForDaclInheritanceAssertionOnly(
                        actualFile),
                    InstalledReleaseSecurityScope.ManagedFile)
                .Should().BeTrue();
        }
        finally
        {
            GrantCleanupAndDelete(root, currentUser);
        }
    }

    [Fact]
    public void InstalledReleaseSecurityPolicy_AcceptsRealSystemOwnedInheritanceWhenRestorePrivilegeIsAvailable()
    {
        if (!OperatingSystem.IsWindows()
            || !WindowsRestorePrivilegeScope.TryEnable(
                out var privilege)
            || privilege is null)
        {
            return;
        }

        using (privilege)
        {
            var system = new SecurityIdentifier(
                WellKnownSidType.LocalSystemSid,
                domainSid: null);
            var root = Path.Combine(
                Path.GetTempPath(),
                $"WireguardSplitTunnel.StoreAcl.System.{Guid.NewGuid():N}");
            var child = Path.Combine(root, "nested");
            var file = Path.Combine(child, "payload.bin");
            try
            {
                new DirectoryInfo(root).Create(
                    InstalledRootSecurityForInheritanceTest(
                        system));
                Directory.CreateDirectory(child);
                File.WriteAllBytes(
                    file,
                    "payload"u8.ToArray());
                SetDirectoryOwner(child, system);
                SetFileOwner(file, system);

                InstalledReleaseSecurityPolicy
                    .HasExactDescriptor(
                        new DirectorySecurity(
                            root,
                            AccessControlSections.Owner
                                | AccessControlSections.Access)
                            .GetSecurityDescriptorBinaryForm(),
                        InstalledReleaseSecurityScope
                            .RootDirectory)
                    .Should().BeTrue();
                InstalledReleaseSecurityPolicy
                    .HasExactDescriptor(
                        new DirectorySecurity(
                            child,
                            AccessControlSections.Owner
                                | AccessControlSections.Access)
                            .GetSecurityDescriptorBinaryForm(),
                        InstalledReleaseSecurityScope
                            .DescendantDirectory)
                    .Should().BeTrue();
                InstalledReleaseSecurityPolicy
                    .HasExactDescriptor(
                        new FileSecurity(
                            file,
                            AccessControlSections.Owner
                                | AccessControlSections.Access)
                            .GetSecurityDescriptorBinaryForm(),
                        InstalledReleaseSecurityScope
                            .ManagedFile)
                    .Should().BeTrue();
            }
            finally
            {
                if (Directory.Exists(root))
                {
                    Directory.Delete(root, recursive: true);
                }
            }
        }
    }

    [Fact]
    public void PhaseGraph_AllowsOnlyForwardApplyRollbackAndBlockingEdges()
    {
        var phases =
            Enum.GetValues<ProtectedTransactionPhase>();
        var allowed = new HashSet<(
            ProtectedTransactionPhase Current,
            ProtectedTransactionPhase Next)>(
            phases.Select(phase => (phase, phase)))
        {
            (
                ProtectedTransactionPhase.ProtectedStaged,
                ProtectedTransactionPhase.CloseAuthorized),
            (
                ProtectedTransactionPhase.CloseAuthorized,
                ProtectedTransactionPhase.Prepared),
            (
                ProtectedTransactionPhase.Prepared,
                ProtectedTransactionPhase.BackingUp),
            (
                ProtectedTransactionPhase.BackingUp,
                ProtectedTransactionPhase.Applying),
            (
                ProtectedTransactionPhase.Applying,
                ProtectedTransactionPhase
                    .AppliedAwaitingHealth),
            (
                ProtectedTransactionPhase
                    .AppliedAwaitingHealth,
                ProtectedTransactionPhase.Committed),
            (
                ProtectedTransactionPhase.CloseAuthorized,
                ProtectedTransactionPhase.RollingBack),
            (
                ProtectedTransactionPhase.Prepared,
                ProtectedTransactionPhase.RollingBack),
            (
                ProtectedTransactionPhase.BackingUp,
                ProtectedTransactionPhase.RollingBack),
            (
                ProtectedTransactionPhase.Applying,
                ProtectedTransactionPhase.RollingBack),
            (
                ProtectedTransactionPhase
                    .AppliedAwaitingHealth,
                ProtectedTransactionPhase.RollingBack),
            (
                ProtectedTransactionPhase.RollingBack,
                ProtectedTransactionPhase.RolledBack),
            (
                ProtectedTransactionPhase.CloseAuthorized,
                ProtectedTransactionPhase.RecoveryBlocked),
            (
                ProtectedTransactionPhase.Prepared,
                ProtectedTransactionPhase.RecoveryBlocked),
            (
                ProtectedTransactionPhase.BackingUp,
                ProtectedTransactionPhase.RecoveryBlocked),
            (
                ProtectedTransactionPhase.Applying,
                ProtectedTransactionPhase.RecoveryBlocked),
            (
                ProtectedTransactionPhase
                    .AppliedAwaitingHealth,
                ProtectedTransactionPhase.RecoveryBlocked),
            (
                ProtectedTransactionPhase.RollingBack,
                ProtectedTransactionPhase.RecoveryBlocked)
        };

        foreach (var current in phases)
        {
            foreach (var next in phases)
            {
                ProtectedTransactionStore
                    .IsLegalPhaseTransition(current, next)
                    .Should().Be(
                        allowed.Contains((current, next)),
                        $"{current} -> {next} must be explicit");
            }
        }

        ProtectedTransactionStore.IsLegalPhaseTransition(
                (ProtectedTransactionPhase)int.MaxValue,
                (ProtectedTransactionPhase)int.MaxValue)
            .Should().BeFalse();
    }

    [Fact]
    public void PublicConstructor_WiresTheWindowsProtectedFileSystem()
    {
        var store = new ProtectedTransactionStore(
            new ProtectedTransactionPaths());

        store.Should().NotBeNull();
    }

    [Fact]
    public async Task StoreOperations_RejectACapturedMutexContextAfterTheExclusiveActionReturns()
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        created.Success.Should().BeTrue();
        ProtectedUpdateMutexContext? captured = null;
        var mutex = new ProtectedUpdateMutex(
            new ImmediateMutexFactory());

        var run = await mutex.RunExclusiveAsync(
            (context, _) =>
            {
                captured = context;
                return 1;
            },
            TimeSpan.Zero,
            CancellationToken.None);

        run.Status.Should().Be(
            ProtectedUpdateMutexStatus.Acquired);
        captured.Should().NotBeNull();
        fixture.Store.CreateProtectedStaged(
                captured,
                fixture.Material)
            .Error.Should().Be(
                ProtectedTransactionStoreError.InvalidAuthority);
        fixture.Store.ReadTransaction(
                captured,
                fixture.Material.TransactionId)
            .Error.Should().Be(
                ProtectedTransactionStoreError.InvalidAuthority);
        fixture.Store.ReadActive(captured)
            .Error.Should().Be(
                ProtectedTransactionStoreError.InvalidAuthority);
        fixture.Store.Activate(captured, created.Record!)
            .Error.Should().Be(
                ProtectedTransactionStoreError.InvalidAuthority);
        var expected = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        fixture.Store.PublishJournalCheckpoint(
                captured,
                expected,
                """{"schemaVersion":1,"generation":1}"""u8
                    .ToArray())
            .Error.Should().Be(
                ProtectedTransactionStoreError.InvalidAuthority);
        fixture.Store.EnterRecoveryBlocked(
                captured,
                created.Record!)
            .Error.Should().Be(
                ProtectedTransactionStoreError.InvalidAuthority);
        fixture.Store.VerifyHelper(
                captured,
                fixture.Material.TransactionId,
                fixture.Material.HelperSha256)
            .Error.Should().Be(
                ProtectedTransactionStoreError.InvalidAuthority);
    }

    [Fact]
    public void CreateProtectedStaged_HardCodesTheUnconsentedPhaseAndNullProcessIdentity()
    {
        using var fixture = new StoreFixture();

        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        var read = fixture.Store.ReadTransaction(
            fixture.Authority,
            fixture.Material.TransactionId);

        created.Success.Should().BeTrue();
        read.Success.Should().BeTrue();
        read.Record!.Phase.Should().Be(
            ProtectedTransactionPhase.ProtectedStaged);
        read.Record.AuthorizedProcess.Should().BeNull();
        typeof(ProtectedStagedTransactionMaterial)
            .GetProperties()
            .Select(property => property.Name)
            .Should()
            .NotContain(["Phase", "AuthorizedProcess"]);
    }

    [Fact]
    public void InstalledReleaseIdentity_RoundTripsCurrentCompatibilityAndFixedExecutableIdentities()
    {
        using var fixture = new StoreFixture();
        fixture.Store.CreateProtectedStaged(
                fixture.Authority,
                fixture.Material)
            .Success.Should().BeTrue();

        var read = fixture.Store.ReadTransaction(
            fixture.Authority,
            fixture.Material.TransactionId);

        read.Success.Should().BeTrue();
        read.Record!.InstalledRelease.CurrentVersion
            .Should().Be(new SemanticVersion(1, 2, 3));
        read.Record.InstalledRelease.MinimumAutoUpdateVersion
            .Should().Be(new SemanticVersion(1, 0, 0));
        read.Record.InstalledRelease.RollbackCompatibleFromVersion
            .Should().Be(new SemanticVersion(1, 0, 0));
        read.Record.InstalledRelease.StateSchemaVersion
            .Should().Be(1);
        read.Record.InstalledRelease.ApplicationRelativePath
            .Should().Be(
                UpdateReleaseContract.WindowsApplicationPath);
        read.Record.InstalledRelease.UpdaterRelativePath
            .Should().Be(
                UpdateReleaseContract.WindowsUpdaterPath);
        read.Record.InstalledRelease.ManagedFiles
            .Select(file => file.RelativePath)
            .Should().Contain(
                UpdateReleaseContract.RequiredLauncherPaths
                    .Append(
                        UpdateReleaseContract.WindowsApplicationPath)
                    .Append(
                        UpdateReleaseContract.WindowsUpdaterPath));
    }

    [Fact]
    public void CreateProtectedStaged_RejectsInvalidInstalledCompatibilityOrMissingRequiredManagedIdentity()
    {
        using var fixture = new StoreFixture();
        var installed = fixture.Material.InstalledRelease;
        var invalid = new[]
        {
            installed with
            {
                CurrentVersion = default
            },
            installed with
            {
                MinimumAutoUpdateVersion =
                    new SemanticVersion(1, 2, 4)
            },
            installed with
            {
                RollbackCompatibleFromVersion =
                    new SemanticVersion(1, 2, 4)
            },
            installed with
            {
                StateSchemaVersion = 0
            },
            installed with
            {
                ApplicationRelativePath =
                    "WireguardSplitTunnel/forged.exe"
            },
            installed with
            {
                UpdaterRelativePath =
                    "WireguardSplitTunnel/forged-updater.exe"
            },
            installed with
            {
                ManagedFiles = installed.ManagedFiles
                    .Where(file => file.RelativePath
                        != UpdateReleaseContract.WindowsApplicationPath)
                    .ToArray()
            },
            installed with
            {
                ManagedFiles = installed.ManagedFiles
                    .Where(file => file.RelativePath
                        != UpdateReleaseContract.RequiredLauncherPaths[0])
                    .ToArray()
            }
        };

        foreach (var identity in invalid)
        {
            fixture.Store.CreateProtectedStaged(
                    fixture.Authority,
                    fixture.Material with
                    {
                        InstalledRelease = identity
                    })
                .Error.Should().Be(
                    ProtectedTransactionStoreError.InvalidData);
        }
    }

    [Fact]
    public void CreateAndActivate_IndependentlyReverifyTheExactInstalledIdentity()
    {
        using var fixture = new StoreFixture();
        fixture.InstalledReleaseVerifier.Result = false;
        fixture.Store.CreateProtectedStaged(
                fixture.Authority,
                fixture.Material)
            .Error.Should().Be(
                ProtectedTransactionStoreError.VerificationFailed);
        fixture.InstalledReleaseVerifier.LastExpected
            .Should().BeEquivalentTo(
                fixture.Material.InstalledRelease);

        fixture.InstalledReleaseVerifier.Result = true;
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        created.Success.Should().BeTrue();
        fixture.InstalledReleaseVerifier.Result = false;

        fixture.Store.Activate(
                fixture.Authority,
                created.Record!)
            .Error.Should().Be(
                ProtectedTransactionStoreError.VerificationFailed);
        fixture.Store.ReadActive(fixture.Authority)
            .TransactionId.Should().BeNull();
        fixture.InstalledReleaseVerifier.CallCount
            .Should().Be(3);
    }

    [Fact]
    public void CreateProtectedStaged_RequiresTheInitialNullHashJournalGeneration()
    {
        using var fixture = new StoreFixture();
        var nonInitial = fixture.Material with
        {
            Journal = new ProtectedJournalMetadata(
                SchemaVersion: 1,
                Generation: 1,
                Sha256: Hash('a'))
        };

        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            nonInitial);

        created.Success.Should().BeFalse();
        created.Error.Should().Be(
            ProtectedTransactionStoreError.InvalidData);
    }

    [Fact]
    public void CreateProtectedStaged_RejectsASameLengthCandidatePayloadSubstitution()
    {
        using var fixture = new StoreFixture();
        var applicationPath = fixture.Paths
            .ResolveCandidatePayload(
                fixture.Material.TransactionId,
                UpdateReleaseContract.WindowsApplicationPath)
            .Path!;
        var original = fixture.FileSystem.GetProtectedFile(
            applicationPath);
        var substituted = original.ToArray();
        substituted[0] ^= 0x01;
        fixture.FileSystem.ProtectFile(
            applicationPath,
            substituted);

        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);

        created.Error.Should().Be(
            ProtectedTransactionStoreError.VerificationFailed);
    }

    [Fact]
    public void CreateProtectedStaged_RejectsMalformedManifestEvenWhenItsOuterHashAndAggregateAreUpdated()
    {
        using var fixture = new StoreFixture();
        var manifestPath = fixture.Paths
            .ResolveCandidatePayload(
                fixture.Material.TransactionId,
                UpdateReleaseContract.ReleaseManifestPath)
            .Path!;
        var oldManifest = fixture.FileSystem.GetProtectedFile(
            manifestPath);
        var malformed = """{"schemaVersion":1}"""u8.ToArray();
        fixture.FileSystem.ProtectFile(
            manifestPath,
            malformed);
        var material = fixture.Material with
        {
            Candidate = fixture.Material.Candidate with
            {
                NewManifestSha256 = Hash(malformed),
                ExpandedBytes =
                    fixture.Material.Candidate.ExpandedBytes
                    - oldManifest.LongLength
                    + malformed.LongLength
            }
        };

        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            material);

        created.Error.Should().Be(
            ProtectedTransactionStoreError.VerificationFailed);
    }

    [Fact]
    public void CreateProtectedStaged_RejectsExtraAndMissingCandidateFilesEvenWhenAggregateMatches()
    {
        using var extraFixture = new StoreFixture();
        var extraBytes = "extra"u8.ToArray();
        var extraPath = extraFixture.Paths
            .ResolveCandidatePayload(
                extraFixture.Material.TransactionId,
                "extra.txt")
            .Path!;
        extraFixture.FileSystem.ProtectFile(
            extraPath,
            extraBytes);
        var withExtra = extraFixture.Material with
        {
            Candidate = extraFixture.Material.Candidate with
            {
                ExpandedBytes =
                    extraFixture.Material.Candidate.ExpandedBytes
                    + extraBytes.LongLength
            }
        };

        extraFixture.Store.CreateProtectedStaged(
                extraFixture.Authority,
                withExtra)
            .Error.Should().Be(
                ProtectedTransactionStoreError.VerificationFailed);

        using var missingFixture = new StoreFixture();
        var missingRelative =
            UpdateReleaseContract.RequiredLauncherPaths[0];
        var missingPath = missingFixture.Paths
            .ResolveCandidatePayload(
                missingFixture.Material.TransactionId,
                missingRelative)
            .Path!;
        var missingBytes = missingFixture.FileSystem
            .GetProtectedFile(missingPath);
        missingFixture.FileSystem.RemoveFile(missingPath);
        var withMissing = missingFixture.Material with
        {
            Candidate = missingFixture.Material.Candidate with
            {
                ExpandedBytes =
                    missingFixture.Material.Candidate.ExpandedBytes
                    - missingBytes.LongLength
            }
        };

        missingFixture.Store.CreateProtectedStaged(
                missingFixture.Authority,
                withMissing)
            .Error.Should().Be(
                ProtectedTransactionStoreError.VerificationFailed);
    }

    [Fact]
    public void CreateProtectedStaged_RejectsAnyCandidateOrHelperProductVersionMismatch()
    {
        using (var applicationFixture = new StoreFixture())
        {
            var application = applicationFixture.Paths
                .ResolveCandidatePayload(
                    applicationFixture.Material.TransactionId,
                    UpdateReleaseContract.WindowsApplicationPath)
                .Path!;
            applicationFixture.VersionReader.SetVersion(
                application,
                "1.2.3");

            applicationFixture.Store.CreateProtectedStaged(
                    applicationFixture.Authority,
                    applicationFixture.Material)
                .Error.Should().Be(
                    ProtectedTransactionStoreError
                        .VerificationFailed);
        }

        using (var updaterFixture = new StoreFixture())
        {
            var updater = updaterFixture.Paths
                .ResolveCandidatePayload(
                    updaterFixture.Material.TransactionId,
                    UpdateReleaseContract.WindowsUpdaterPath)
                .Path!;
            updaterFixture.VersionReader.SetVersion(
                updater,
                "1.2.3");

            updaterFixture.Store.CreateProtectedStaged(
                    updaterFixture.Authority,
                    updaterFixture.Material)
                .Error.Should().Be(
                    ProtectedTransactionStoreError
                        .VerificationFailed);
        }

        using (var helperFixture = new StoreFixture())
        {
            helperFixture.VersionReader.SetVersion(
                helperFixture.Layout.HelperPath,
                "1.2.3");

            helperFixture.Store.CreateProtectedStaged(
                    helperFixture.Authority,
                    helperFixture.Material)
                .Error.Should().Be(
                    ProtectedTransactionStoreError
                        .VerificationFailed);
        }
    }

    [Fact]
    public void CreateProtectedStaged_UsesOnlyRetainedStreamsForCandidateAndHelperProductVersions()
    {
        using var fixture = new StoreFixture();

        fixture.Store.CreateProtectedStaged(
                fixture.Authority,
                fixture.Material)
            .Success.Should().BeTrue();

        fixture.VersionReader.PathCalls.Should().Be(0);
        fixture.VersionReader.StreamCalls.Should().Be(3);
    }

    [Fact]
    public void ProtectedProductVersionCheck_UsesRetainedStreamAndRestoresItsPosition()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(path, [1, 2, 3, 4]);
        try
        {
            var revalidations = 0;
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read | FileShare.Delete);
            var owner = new ProtectedLeaseOwner(
                new CancellationTokenSource(),
                () =>
                {
                    revalidations++;
                    return true;
                });
            using var file = new ProtectedFileReadLease(
                owner,
                stream,
                new ProtectedAclNativeSnapshot(
                    IsDirectory: false,
                    IsReparsePoint: false,
                    FinalPath: @"C:\decoy\replaced.exe",
                    new ProtectedFileIdentity128(
                        VolumeSerialNumber: 1,
                        FileIdLow: 2,
                        FileIdHigh: 3),
                    SecurityDescriptor: []));
            file.Stream.Position = 2;
            var reader =
                new PositionChangingStreamOnlyProductVersionReader(
                    "1.2.4");

            WindowsProtectedTransactionFileSystem
                .HasExpectedProductVersion(
                    file,
                    "1.2.4",
                    reader)
                .Should().BeTrue();

            reader.PathCalls.Should().Be(0);
            reader.StreamCalls.Should().Be(1);
            reader.ObservedPosition.Should().Be(2);
            file.Stream.Position.Should().Be(2);
            revalidations.Should().Be(1);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void StoreOperations_MapThrowingFilesystemAndVersionSeamsToTypedIoFailure()
    {
        using (var snapshotFixture = new StoreFixture())
        {
            snapshotFixture.FileSystem.SnapshotException =
                new IOException("snapshot failed");

            snapshotFixture.Store.CreateProtectedStaged(
                    snapshotFixture.Authority,
                    snapshotFixture.Material)
                .Error.Should().Be(
                    ProtectedTransactionStoreError.IoFailure);
        }

        using (var versionFixture = new StoreFixture())
        {
            versionFixture.VersionReader.ReadException =
                new IOException("version failed");

            versionFixture.Store.CreateProtectedStaged(
                    versionFixture.Authority,
                    versionFixture.Material)
                .Error.Should().Be(
                    ProtectedTransactionStoreError.IoFailure);
        }

        using (var readFixture = new StoreFixture())
        {
            readFixture.FileSystem.DirectoryException =
                new IOException("directory failed");

            readFixture.Store.ReadActive(
                    readFixture.Authority)
                .Error.Should().Be(
                    ProtectedTransactionStoreError.IoFailure);
        }

        using (var installedFixture = new StoreFixture())
        {
            installedFixture.InstalledReleaseVerifier
                .VerificationException =
                    new IOException(
                        "installed verification failed");

            installedFixture.Store.CreateProtectedStaged(
                    installedFixture.Authority,
                    installedFixture.Material)
                .Error.Should().Be(
                    ProtectedTransactionStoreError.IoFailure);
        }
    }

    [Fact]
    public void CreateProtectedStaged_RejectsACommitPrimitiveThatDoesNotPublishTheDerivedDestination()
    {
        using var fixture = new StoreFixture();
        fixture.FileSystem.SuppressAtomicCreatePublish = true;

        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);

        created.Success.Should().BeFalse();
        created.Error.Should().Be(
            ProtectedTransactionStoreError.AtomicWriteFailed);
        fixture.FileSystem.InspectProtectedFile(
                fixture.Layout.TransactionRecordPath)
            .Should().Be(
                ProtectedTransactionFileState.Missing);
    }

    [Fact]
    public void Activate_PublishesThePointerOnlyAfterRevalidatingTheDurableRecordCandidateAndHelper()
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        created.Success.Should().BeTrue();
        fixture.FileSystem.Operations.Clear();

        var activated = fixture.Store.Activate(
            fixture.Authority,
            created.Record!);
        var active = fixture.Store.ReadActive(
            fixture.Authority);

        activated.Success.Should().BeTrue();
        active.Success.Should().BeTrue();
        active.TransactionId.Should().Be(
            fixture.Material.TransactionId);

        var pointerCommit = fixture.FileSystem.Operations
            .FindIndex(operation =>
                operation == $"move:{fixture.Layout.ActivePointerPath}");
        pointerCommit.Should().BeGreaterThan(
            fixture.FileSystem.Operations.FindLastIndex(
                operation =>
                    operation == $"read:{fixture.Layout.TransactionRecordPath}"));
        pointerCommit.Should().BeGreaterThan(
            fixture.FileSystem.Operations.FindLastIndex(
                operation =>
                    operation == $"hash:{fixture.Layout.HelperPath}"));
        pointerCommit.Should().BeGreaterThan(
            fixture.FileSystem.Operations.FindLastIndex(
                operation =>
                    operation == $"snapshot:{fixture.Layout.CandidateRoot}"));
        pointerCommit.Should().BeGreaterThan(
            fixture.FileSystem.Operations.FindLastIndex(
                operation => operation.StartsWith(
                    "flush:",
                    StringComparison.Ordinal)));
    }

    [Fact]
    public void Activate_UsesInitialMoveThenReplaceAndIsIdempotentOnlyForTheExactSameRecord()
    {
        using var fixture = new StoreFixture();
        var first = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.Store.Activate(
                fixture.Authority,
                first.Record!)
            .Success.Should().BeTrue();
        fixture.FileSystem.Operations.Should().Contain(
            $"move:{fixture.Layout.ActivePointerPath}");

        fixture.FileSystem.Operations.Clear();
        fixture.Store.Activate(
                fixture.Authority,
                first.Record!)
            .Success.Should().BeTrue();
        fixture.FileSystem.Operations.Should().NotContain(
            operation => operation.StartsWith(
                "move:",
                StringComparison.Ordinal)
                || operation.StartsWith(
                    "replace:",
                    StringComparison.Ordinal));

        var mismatchingExpected = first.Record! with
        {
            HelperSha256 = Hash('e')
        };
        fixture.Store.Activate(
                fixture.Authority,
                mismatchingExpected)
            .Error.Should().Be(
                ProtectedTransactionStoreError.Conflict);

        var secondMaterial = fixture.AddTransaction(
            Guid.Parse("bbbbbbbb-1122-3344-5566-778899aabbcc"),
            patch: 5);
        var second = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            secondMaterial);
        fixture.FileSystem.Operations.Clear();

        fixture.Store.Activate(
                fixture.Authority,
                second.Record!)
            .Success.Should().BeTrue();

        fixture.FileSystem.Operations.Should().Contain(
            $"replace:{fixture.Layout.ActivePointerPath}");
        fixture.Store.ReadActive(fixture.Authority)
            .TransactionId.Should().Be(
                secondMaterial.TransactionId);
    }

    [Fact]
    public void ActivateReplacingProtectedStaged_AtomicallySwapsOnlyTheExpectedOldPointer()
    {
        using var fixture = new StoreFixture();
        var first = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.Store.Activate(
                fixture.Authority,
                first.Record!)
            .Success.Should().BeTrue();
        var secondMaterial = fixture.AddTransaction(
            Guid.Parse(
                "bbbbbbbb-1122-3344-5566-778899aabbcc"),
            patch: 5);
        var second = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            secondMaterial);
        var expectation =
            new ProtectedActiveTransactionExpectation(
                fixture.Material.TransactionId,
                fixture.Material.Version,
                fixture.Material.Source);
        fixture.FileSystem.Operations.Clear();

        var activated = fixture.Store
            .ActivateReplacingProtectedStaged(
                fixture.Authority,
                second.Record!,
                expectation);

        activated.Success.Should().BeTrue();
        fixture.Store.ReadActive(fixture.Authority)
            .TransactionId.Should().Be(
                secondMaterial.TransactionId);
        fixture.FileSystem.Operations.Should().Contain(
            $"replace:{fixture.Layout.ActivePointerPath}");
        fixture.FileSystem.Operations.Should().NotContain(
            operation => operation.Contains(
                "inactive",
                StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ActivateReplacingProtectedStaged_AllowsSameVersionAutomaticToManualPromotion()
    {
        using var fixture = new StoreFixture();
        var first = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.Store.Activate(
                fixture.Authority,
                first.Record!)
            .Success.Should().BeTrue();
        var secondMaterial = fixture.AddTransaction(
                Guid.Parse(
                    "bbbbbbbb-1122-3344-5566-778899aabbcc"),
                patch: 4)
            with
            {
                Source = PendingUpdateSource.Manual
            };
        var second = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            secondMaterial);
        var expectation =
            new ProtectedActiveTransactionExpectation(
                fixture.Material.TransactionId,
                fixture.Material.Version,
                PendingUpdateSource.Automatic);

        var activated = fixture.Store
            .ActivateReplacingProtectedStaged(
                fixture.Authority,
                second.Record!,
                expectation);

        activated.Success.Should().BeTrue();
        fixture.Store.ReadActive(fixture.Authority)
            .TransactionId.Should().Be(
                secondMaterial.TransactionId);
    }

    [Fact]
    public void ActivateReplacingProtectedStaged_ExpectedPointerMismatchPreservesOldPointer()
    {
        using var fixture = new StoreFixture();
        var first = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.Store.Activate(
                fixture.Authority,
                first.Record!)
            .Success.Should().BeTrue();
        var secondMaterial = fixture.AddTransaction(
            Guid.Parse(
                "bbbbbbbb-1122-3344-5566-778899aabbcc"),
            patch: 5);
        var second = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            secondMaterial);
        var wrongExpectation =
            new ProtectedActiveTransactionExpectation(
                new ProtectedTransactionId(
                    Guid.Parse(
                        "cccccccc-1122-3344-5566-778899aabbcc")),
                fixture.Material.Version,
                fixture.Material.Source);
        var oldPointer = fixture.FileSystem.GetProtectedFile(
            fixture.Layout.ActivePointerPath);

        var activated = fixture.Store
            .ActivateReplacingProtectedStaged(
                fixture.Authority,
                second.Record!,
                wrongExpectation);

        activated.Error.Should().Be(
            ProtectedTransactionStoreError.Conflict);
        fixture.FileSystem.GetProtectedFile(
                fixture.Layout.ActivePointerPath)
            .Should().Equal(oldPointer);
        fixture.Store.ReadActive(fixture.Authority)
            .TransactionId.Should().Be(
                fixture.Material.TransactionId);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ActivateReplacingProtectedStaged_ExpectedEvidenceMismatchPreservesOldPointer(
        bool mismatchSource)
    {
        using var fixture = new StoreFixture();
        var first = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.Store.Activate(
                fixture.Authority,
                first.Record!)
            .Success.Should().BeTrue();
        var secondMaterial = fixture.AddTransaction(
            Guid.Parse(
                "bbbbbbbb-1122-3344-5566-778899aabbcc"),
            patch: 5);
        var second = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            secondMaterial);
        var wrongExpectation =
            new ProtectedActiveTransactionExpectation(
                fixture.Material.TransactionId,
                mismatchSource
                    ? fixture.Material.Version
                    : new SemanticVersion(1, 2, 3),
                mismatchSource
                    ? PendingUpdateSource.Manual
                    : fixture.Material.Source);
        var oldPointer = fixture.FileSystem.GetProtectedFile(
            fixture.Layout.ActivePointerPath);

        var activated = fixture.Store
            .ActivateReplacingProtectedStaged(
                fixture.Authority,
                second.Record!,
                wrongExpectation);

        activated.Error.Should().Be(
            ProtectedTransactionStoreError.Conflict);
        fixture.FileSystem.GetProtectedFile(
                fixture.Layout.ActivePointerPath)
            .Should().Equal(oldPointer);
        fixture.Store.ReadActive(fixture.Authority)
            .TransactionId.Should().Be(
                fixture.Material.TransactionId);
    }

    [Fact]
    public void Activate_PointerCompareExchangeRejectsAnInterleavingPointerChangeWithoutOverwritingIt()
    {
        using var fixture = new StoreFixture();
        var first = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.Store.Activate(
                fixture.Authority,
                first.Record!)
            .Success.Should().BeTrue();
        var secondMaterial = fixture.AddTransaction(
            Guid.Parse(
                "bbbbbbbb-1122-3344-5566-778899aabbcc"),
            patch: 5);
        var second = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            secondMaterial);
        var racedId = new ProtectedTransactionId(
            Guid.Parse(
                "cccccccc-1122-3344-5566-778899aabbcc"));
        byte[]? racedPointer = null;
        fixture.FileSystem.BeforeAtomicReplace =
            destinationPath =>
            {
                var oldPointer = fixture.FileSystem
                    .GetProtectedFile(destinationPath);
                racedPointer = MutateRecord(
                    oldPointer,
                    root =>
                        root["transactionId"] =
                            racedId.DirectoryName);
                fixture.FileSystem.ProtectFile(
                    destinationPath,
                    racedPointer);
            };

        var activated = fixture.Store.Activate(
            fixture.Authority,
            second.Record!);

        activated.Error.Should().Be(
            ProtectedTransactionStoreError.Conflict);
        fixture.FileSystem.GetProtectedFile(
                fixture.Layout.ActivePointerPath)
            .Should().Equal(racedPointer!);
        fixture.Store.ReadActive(fixture.Authority)
            .TransactionId.Should().Be(racedId);
    }

    [Fact]
    public void Activate_PointerCompareExchangeRejectsAbaPointerIdentityChange()
    {
        using var fixture = new StoreFixture();
        var first = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.Store.Activate(
                fixture.Authority,
                first.Record!)
            .Success.Should().BeTrue();
        var oldPointer = fixture.FileSystem.GetProtectedFile(
            fixture.Layout.ActivePointerPath);
        var secondMaterial = fixture.AddTransaction(
            Guid.Parse(
                "bbbbbbbb-1122-3344-5566-778899aabbcc"),
            patch: 5);
        var second = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            secondMaterial);
        var racedId = new ProtectedTransactionId(
            Guid.Parse(
                "cccccccc-1122-3344-5566-778899aabbcc"));
        var racedPointer = MutateRecord(
            oldPointer,
            root =>
                root["transactionId"] = racedId.DirectoryName);
        fixture.FileSystem.BeforeAtomicReplace = path =>
        {
            fixture.FileSystem.ProtectFile(path, racedPointer);
            fixture.FileSystem.ProtectFile(path, oldPointer);
        };

        var activated = fixture.Store.Activate(
            fixture.Authority,
            second.Record!);

        activated.Error.Should().Be(
            ProtectedTransactionStoreError.Conflict);
        fixture.FileSystem.GetProtectedFile(
                fixture.Layout.ActivePointerPath)
            .Should().Equal(oldPointer);
        fixture.Store.ReadActive(fixture.Authority)
            .TransactionId.Should().Be(
                fixture.Material.TransactionId);
    }

    [Fact]
    public void Activate_DoesNotReportIdempotentWhenActivePointerChangesAfterSnapshotRead()
    {
        using var fixture = new StoreFixture();
        var first = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.Store.Activate(
                fixture.Authority,
                first.Record!)
            .Success.Should().BeTrue();
        var oldPointer = fixture.FileSystem.GetProtectedFile(
            fixture.Layout.ActivePointerPath);
        var racedId = new ProtectedTransactionId(
            Guid.Parse(
                "cccccccc-1122-3344-5566-778899aabbcc"));
        var racedPointer = MutateRecord(
            oldPointer,
            root =>
                root["transactionId"] = racedId.DirectoryName);
        fixture.FileSystem.AfterProtectedRead = path =>
        {
            if (!string.Equals(
                    path,
                    fixture.Layout.ActivePointerPath,
                    StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            fixture.FileSystem.AfterProtectedRead = null;
            fixture.FileSystem.ProtectFile(path, racedPointer);
        };

        var activated = fixture.Store.Activate(
            fixture.Authority,
            first.Record!);

        activated.Error.Should().Be(
            ProtectedTransactionStoreError.Conflict);
        fixture.FileSystem.GetProtectedFile(
                fixture.Layout.ActivePointerPath)
            .Should().Equal(racedPointer);
    }

    [Fact]
    public async Task Activate_HoldsTheAuthorityLeaseThroughThePointerCompareExchange()
    {
        using var fixture = new StoreFixture();
        var first = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.Store.Activate(
                fixture.Authority,
                first.Record!)
            .Success.Should().BeTrue();
        var secondMaterial = fixture.AddTransaction(
            Guid.Parse(
                "bbbbbbbb-1122-3344-5566-778899aabbcc"),
            patch: 5);
        var second = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            secondMaterial);
        using var enteredCommit = new ManualResetEventSlim();
        using var releaseCommit = new ManualResetEventSlim();
        fixture.FileSystem.BeforeAtomicReplace =
            _ =>
            {
                enteredCommit.Set();
                releaseCommit.Wait(
                        TimeSpan.FromSeconds(5))
                    .Should().BeTrue();
            };

        var activation = Task.Run(() =>
            fixture.Store.Activate(
                fixture.Authority,
                second.Record!));
        enteredCommit.Wait(TimeSpan.FromSeconds(5))
            .Should().BeTrue();
        var invalidation = Task.Run(
            fixture.Authority.InvalidateAndWaitForLeases);
        await Task.Delay(50);
        invalidation.IsCompleted.Should().BeFalse();

        releaseCommit.Set();
        (await activation.WaitAsync(
            TimeSpan.FromSeconds(5))).Success.Should().BeTrue();
        await invalidation.WaitAsync(
            TimeSpan.FromSeconds(5));
        fixture.Authority.IsActive.Should().BeFalse();
    }

    [Fact]
    public async Task CleanupInactiveTransaction_SerializesTheActivePointerCheckAndCleanupAgainstActivate()
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        using var cleanupEntered = new ManualResetEventSlim();
        using var releaseCleanup = new ManualResetEventSlim();
        using var activationStarted = new ManualResetEventSlim();

        var cleanup = Task.Run(() =>
            fixture.Store.CleanupInactiveTransaction(
                fixture.Authority,
                fixture.Material,
                () =>
                {
                    cleanupEntered.Set();
                    releaseCleanup.Wait(
                            TimeSpan.FromSeconds(5))
                        .Should().BeTrue();
                    fixture.FileSystem.RemoveFile(
                        fixture.Layout.TransactionRecordPath);
                    return true;
                }));
        cleanupEntered.Wait(TimeSpan.FromSeconds(5))
            .Should().BeTrue();

        var activation = Task.Run(() =>
        {
            activationStarted.Set();
            return fixture.Store.Activate(
                fixture.Authority,
                created.Record!);
        });
        activationStarted.Wait(TimeSpan.FromSeconds(5))
            .Should().BeTrue();
        await Task.Delay(50);

        activation.IsCompleted.Should().BeFalse(
            "activation must wait for the cleanup callback holding the mutation gate");
        releaseCleanup.Set();
        (await cleanup.WaitAsync(TimeSpan.FromSeconds(5)))
            .Success.Should().BeTrue();
        (await activation.WaitAsync(TimeSpan.FromSeconds(5)))
            .Error.Should().Be(
                ProtectedTransactionStoreError.Missing);
        fixture.Store.ReadActive(fixture.Authority)
            .TransactionId.Should().BeNull();
    }

    [Fact]
    public void CleanupInactiveTransaction_DoesNotInvokeCleanupForTheActiveTransaction()
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.Store.Activate(
                fixture.Authority,
                created.Record!)
            .Success.Should().BeTrue();
        var cleanupCalls = 0;

        var cleaned = fixture.Store.CleanupInactiveTransaction(
            fixture.Authority,
            fixture.Material,
            () =>
            {
                cleanupCalls++;
                return true;
            });

        cleaned.Error.Should().Be(
            ProtectedTransactionStoreError.Conflict);
        cleanupCalls.Should().Be(0);
    }

    [Theory]
    [InlineData("advanced", ProtectedTransactionStoreError.Conflict)]
    [InlineData("corrupt", ProtectedTransactionStoreError.CorruptData)]
    [InlineData("unsafe", ProtectedTransactionStoreError.AclMismatch)]
    [InlineData("different", ProtectedTransactionStoreError.Conflict)]
    public void CleanupInactiveTransaction_FailsClosedForAnUnownedOrUnreadableRecord(
        string recordState,
        ProtectedTransactionStoreError expectedError)
    {
        using var fixture = new StoreFixture();
        fixture.Store.CreateProtectedStaged(
                fixture.Authority,
                fixture.Material)
            .Success.Should().BeTrue();
        var recordPath = fixture.Layout.TransactionRecordPath;
        if (recordState == "advanced")
        {
            fixture.FileSystem.ProtectFile(
                recordPath,
                MutateRecord(
                    fixture.FileSystem.GetProtectedFile(recordPath),
                    root =>
                    {
                        root["phase"] = "CloseAuthorized";
                        root["authorizedProcess"] =
                            new JsonObject
                            {
                                ["processId"] = 1234,
                                ["creationTimeFileTimeUtc"] =
                                    133000000000000000L,
                                ["imagePath"] =
                                    @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel.App.exe"
                            };
                    }));
        }
        else if (recordState == "corrupt")
        {
            fixture.FileSystem.ProtectFile(
                recordPath,
                "{"u8.ToArray());
        }
        else if (recordState == "unsafe")
        {
            fixture.FileSystem.MarkUnsafe(recordPath);
        }

        var expectedMaterial = recordState == "different"
            ? fixture.Material with
            {
                Source = PendingUpdateSource.Manual
            }
            : fixture.Material;
        var cleanupCalls = 0;
        var cleaned = fixture.Store.CleanupInactiveTransaction(
            fixture.Authority,
            expectedMaterial,
            () =>
            {
                cleanupCalls++;
                return true;
            });

        cleaned.Error.Should().Be(expectedError);
        cleanupCalls.Should().Be(0);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CleanupInactiveTransaction_AllowsAnInactiveExactOrMissingRecord(
        bool removeRecord)
    {
        using var fixture = new StoreFixture();
        fixture.Store.CreateProtectedStaged(
                fixture.Authority,
                fixture.Material)
            .Success.Should().BeTrue();
        if (removeRecord)
        {
            fixture.FileSystem.RemoveFile(
                fixture.Layout.TransactionRecordPath);
        }

        var cleanupCalls = 0;
        var cleaned = fixture.Store.CleanupInactiveTransaction(
            fixture.Authority,
            fixture.Material,
            () =>
            {
                cleanupCalls++;
                return true;
            });

        cleaned.Success.Should().BeTrue();
        cleanupCalls.Should().Be(1);
    }

    [Fact]
    public void CleanupInactiveTransaction_AllowsTheExactStagedRecordWhenAnotherTransactionIsActive()
    {
        using var fixture = new StoreFixture();
        var first = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.Store.Activate(
                fixture.Authority,
                first.Record!)
            .Success.Should().BeTrue();
        var secondMaterial = fixture.AddTransaction(
            Guid.Parse(
                "bbbbbbbb-1122-3344-5566-778899aabbcc"),
            patch: 5);
        fixture.Store.CreateProtectedStaged(
                fixture.Authority,
                secondMaterial)
            .Success.Should().BeTrue();
        var cleanupCalls = 0;

        var cleaned = fixture.Store.CleanupInactiveTransaction(
            fixture.Authority,
            secondMaterial,
            () =>
            {
                cleanupCalls++;
                return true;
            });

        cleaned.Success.Should().BeTrue();
        cleanupCalls.Should().Be(1);
        fixture.Store.ReadActive(fixture.Authority)
            .TransactionId.Should().Be(
                fixture.Material.TransactionId);
    }

    [Fact]
    public void CleanupInactiveTransaction_ReportsCallbackFailureWithoutThrowing()
    {
        using var fixture = new StoreFixture();
        fixture.Store.CreateProtectedStaged(
                fixture.Authority,
                fixture.Material)
            .Success.Should().BeTrue();

        fixture.Store.CleanupInactiveTransaction(
                fixture.Authority,
                fixture.Material,
                () => false)
            .Error.Should().Be(
                ProtectedTransactionStoreError.IoFailure);
        fixture.Store.CleanupInactiveTransaction(
                fixture.Authority,
                fixture.Material,
                () => throw new IOException("cleanup"))
            .Error.Should().Be(
                ProtectedTransactionStoreError.IoFailure);
    }
    [Theory]
    [InlineData("close-authorized")]
    [InlineData("missing")]
    [InlineData("corrupt")]
    public void Activate_FailsClosedWhenTheCurrentRecordIsNotReadableProtectedStaged(
        string currentState)
    {
        using var fixture = new StoreFixture();
        var first = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.Store.Activate(
                fixture.Authority,
                first.Record!)
            .Success.Should().BeTrue();

        if (currentState == "close-authorized")
        {
            var bytes = fixture.FileSystem.GetProtectedFile(
                fixture.Layout.TransactionRecordPath);
            fixture.FileSystem.ProtectFile(
                fixture.Layout.TransactionRecordPath,
                MutateRecord(
                    bytes,
                    root =>
                    {
                        root["phase"] = "CloseAuthorized";
                        root["authorizedProcess"] =
                            new JsonObject
                            {
                                ["processId"] = 1234,
                                ["creationTimeFileTimeUtc"] =
                                    133000000000000000L,
                                ["imagePath"] =
                                    @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel.App.exe"
                            };
                    }));
        }
        else if (currentState == "missing")
        {
            fixture.FileSystem.RemoveFile(
                fixture.Layout.TransactionRecordPath);
        }
        else
        {
            fixture.FileSystem.ProtectFile(
                fixture.Layout.TransactionRecordPath,
                "{"u8.ToArray());
        }

        var secondMaterial = fixture.AddTransaction(
            Guid.Parse("bbbbbbbb-1122-3344-5566-778899aabbcc"),
            patch: 5);
        var second = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            secondMaterial);
        var oldPointer = fixture.FileSystem.GetProtectedFile(
            fixture.Layout.ActivePointerPath);

        var activated = fixture.Store.Activate(
            fixture.Authority,
            second.Record!);

        activated.Success.Should().BeFalse();
        activated.Error.Should().Be(
            ProtectedTransactionStoreError.Conflict);
        fixture.FileSystem.GetProtectedFile(
                fixture.Layout.ActivePointerPath)
            .Should().Equal(oldPointer);
    }

    [Fact]
    public void Activate_AtomicMoveFailureLeavesNoPointerAndCleansTheOwnedTemp()
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.FileSystem.FailAtomicMove = true;

        var activated = fixture.Store.Activate(
            fixture.Authority,
            created.Record!);

        activated.Error.Should().Be(
            ProtectedTransactionStoreError.AtomicWriteFailed);
        fixture.Store.ReadActive(fixture.Authority)
            .TransactionId.Should().BeNull();
        fixture.FileSystem.HasTemporaryFiles.Should().BeFalse();
        fixture.FileSystem.Operations.Should().Contain(
            operation => operation.StartsWith(
                "delete:",
                StringComparison.Ordinal));
    }

    [Fact]
    public void Activate_AtomicReplaceFailurePreservesOldPointerAndCleansTheOwnedTemp()
    {
        using var fixture = new StoreFixture();
        var first = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.Store.Activate(
                fixture.Authority,
                first.Record!)
            .Success.Should().BeTrue();
        var oldPointer = fixture.FileSystem.GetProtectedFile(
            fixture.Layout.ActivePointerPath);
        var secondMaterial = fixture.AddTransaction(
            Guid.Parse("bbbbbbbb-1122-3344-5566-778899aabbcc"),
            patch: 5);
        var second = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            secondMaterial);
        fixture.FileSystem.FailAtomicReplace = true;

        var activated = fixture.Store.Activate(
            fixture.Authority,
            second.Record!);

        activated.Error.Should().Be(
            ProtectedTransactionStoreError.AtomicWriteFailed);
        fixture.FileSystem.GetProtectedFile(
                fixture.Layout.ActivePointerPath)
            .Should().Equal(oldPointer);
        fixture.FileSystem.HasTemporaryFiles.Should().BeFalse();
        fixture.FileSystem.Operations.Should().Contain(
            operation => operation.StartsWith(
                "delete:",
                StringComparison.Ordinal));
    }

    [Fact]
    public void VerifyHelper_RehashesOnlyTheDerivedProtectedHelper()
    {
        using var fixture = new StoreFixture();

        var verified = fixture.Store.VerifyHelper(
            fixture.Authority,
            fixture.Material.TransactionId,
            fixture.Material.HelperSha256);
        var mismatch = fixture.Store.VerifyHelper(
            fixture.Authority,
            fixture.Material.TransactionId,
            Hash('f'));

        verified.Success.Should().BeTrue();
        mismatch.Success.Should().BeFalse();
        mismatch.Error.Should().Be(
            ProtectedTransactionStoreError.VerificationFailed);
        fixture.FileSystem.Operations
            .Where(operation => operation.StartsWith(
                "hash:",
                StringComparison.Ordinal))
            .Should()
            .OnlyContain(operation =>
                operation == $"hash:{fixture.Layout.HelperPath}");
    }

    [Fact]
    public void ReadActive_RequiresTheExactBoundedPointerSchemaAndCanonicalLowercaseGuid()
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.Store.Activate(
                fixture.Authority,
                created.Record!)
            .Success.Should().BeTrue();

        var validBytes = fixture.FileSystem.GetProtectedFile(
            fixture.Layout.ActivePointerPath);
        using (var document = JsonDocument.Parse(validBytes))
        {
            document.RootElement.EnumerateObject()
                .Select(property => property.Name)
                .Should()
                .Equal("schemaVersion", "transactionId");
            document.RootElement.GetProperty("transactionId")
                .GetString()
                .Should()
                .Be(fixture.Material.TransactionId.DirectoryName);
        }

        var id = fixture.Material.TransactionId.DirectoryName;
        var invalidPointers = new[]
        {
            $"{{\"schemaVersion\":\"1\",\"transactionId\":\"{id}\"}}",
            $"{{\"schemaVersion\":1,\"transactionId\":\"{id.ToUpperInvariant()}\"}}",
            $"{{\"schemaVersion\":1,\"transactionId\":\"{fixture.Material.TransactionId.Value}\"}}",
            $"{{\"schemaVersion\":1,\"transactionId\":\"{Guid.Empty:N}\"}}",
            $"{{\"SchemaVersion\":1,\"transactionId\":\"{id}\"}}",
            $"{{\"schemaVersion\":1,\"transactionId\":\"{id}\",\"helperPath\":\"C:\\\\forged.exe\"}}",
            $"{{\"schemaVersion\":1,\"schemaVersion\":1,\"transactionId\":\"{id}\"}}",
            "{\"schemaVersion\":1,\"transactionId\":null }",
            " {\"schemaVersion\":1,\"transactionId\":null}",
            "{\"transactionId\":null,\"schemaVersion\":1}",
            "{\"schemaVersion\":1,\"transactionId\":false}",
            "{\"schemaVersion\":1,\"transactionId\":\"\"}",
            "{\"schemaVersion\":1,\"transactionId\":null,\"transactionId\":null}",
            "{",
            new string(' ', 257)
        };

        foreach (var invalid in invalidPointers)
        {
            fixture.FileSystem.ProtectFile(
                fixture.Layout.ActivePointerPath,
                Encoding.UTF8.GetBytes(invalid));

            var read = fixture.Store.ReadActive(
                fixture.Authority);

            read.Success.Should().BeFalse(invalid);
            read.Error.Should().Be(
                ProtectedTransactionStoreError.CorruptData,
                invalid);
        }
    }

    [Fact]
    public void DeactivateTerminal_AtomicallyClearsTheExactActivePointer()
    {
        using var fixture = new StoreFixture();
        var terminal = AdvanceToCommittedAndActivate(fixture);
        var pointerBefore = fixture.FileSystem.GetProtectedFile(
            fixture.Layout.ActivePointerPath);
        fixture.FileSystem.Operations.Clear();

        var result = fixture.Store.DeactivateTerminal(
            fixture.Authority,
            terminal);

        result.Success.Should().BeTrue();
        fixture.Store.ReadActive(fixture.Authority)
            .TransactionId.Should().BeNull();
        fixture.FileSystem.GetProtectedFile(
                fixture.Layout.ActivePointerPath)
            .Should()
            .NotEqual(pointerBefore);
        fixture.FileSystem.Operations.Should().Contain(
            $"replace:{fixture.Layout.ActivePointerPath}");
    }

    [Fact]
    public void DeactivateTerminal_RejectsNonterminalOrConflictingEvidence()
    {
        using var fixture = new StoreFixture();
        var closeAuthorized =
            AdvanceToCloseAuthorizedAndActivate(fixture);
        var pointerBefore = fixture.FileSystem.GetProtectedFile(
            fixture.Layout.ActivePointerPath);

        fixture.Store.DeactivateTerminal(
                fixture.Authority,
                closeAuthorized)
            .Error.Should().Be(
                ProtectedTransactionStoreError.InvalidData);
        fixture.Store.DeactivateTerminal(
                fixture.Authority,
                closeAuthorized with
                {
                    Phase = ProtectedTransactionPhase.Committed
                })
            .Error.Should().Be(
                ProtectedTransactionStoreError.Conflict);
        fixture.FileSystem.GetProtectedFile(
                fixture.Layout.ActivePointerPath)
            .Should()
            .Equal(pointerBefore);
    }

    [Fact]
    public void DeactivateTerminal_CasFailureNeverReportsInactive()
    {
        using var fixture = new StoreFixture();
        var terminal = AdvanceToCommittedAndActivate(fixture);
        fixture.FileSystem.FailAtomicReplace = true;

        var result = fixture.Store.DeactivateTerminal(
            fixture.Authority,
            terminal);

        result.Success.Should().BeFalse();
        result.Error.Should().Be(
            ProtectedTransactionStoreError.AtomicWriteFailed);
        fixture.Store.ReadActive(fixture.Authority)
            .TransactionId.Should().Be(
                fixture.Material.TransactionId);
    }

    [Fact]
    public void Activate_ReplacesCanonicalInactivePointerWithNewActiveId()
    {
        using var fixture = new StoreFixture();
        var terminal = AdvanceToCommittedAndActivate(fixture);
        fixture.Store.DeactivateTerminal(
                fixture.Authority,
                terminal)
            .Success.Should().BeTrue();
        var installedAfterCommit =
            fixture.InstalledReleaseVerifier.LastExpected!;
        var next = fixture.AddTransaction(
            Guid.Parse(
                "11223344-5566-7788-99aa-bbccddeeff00"),
            patch: 5) with
        {
            InstalledRelease = installedAfterCommit
        };
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            next);

        var activated = fixture.Store.Activate(
            fixture.Authority,
            created.Record!);

        activated.Success.Should().BeTrue();
        fixture.Store.ReadActive(fixture.Authority)
            .TransactionId.Should().Be(next.TransactionId);
    }

    [Fact]
    public void CleanupInactiveTerminal_RequiresExactInactiveTerminalEvidence()
    {
        using var fixture = new StoreFixture();
        var terminal = AdvanceToCommittedAndActivate(fixture);
        var cleanupCalls = 0;

        fixture.Store.CleanupInactiveTerminalTransaction(
                fixture.Authority,
                terminal,
                () =>
                {
                    cleanupCalls++;
                    return true;
                })
            .Error.Should().Be(
                ProtectedTransactionStoreError.Conflict);
        cleanupCalls.Should().Be(0);

        fixture.Store.DeactivateTerminal(
                fixture.Authority,
                terminal)
            .Success.Should().BeTrue();
        fixture.Store.CleanupInactiveTerminalTransaction(
                fixture.Authority,
                terminal with
                {
                    Version = new SemanticVersion(9, 9, 9)
                },
                () =>
                {
                    cleanupCalls++;
                    return true;
                })
            .Error.Should().Be(
                ProtectedTransactionStoreError.Conflict);
        cleanupCalls.Should().Be(0);

        fixture.Store.CleanupInactiveTerminalTransaction(
                fixture.Authority,
                terminal,
                () =>
                {
                    cleanupCalls++;
                    return true;
                })
            .Success.Should().BeTrue();
        cleanupCalls.Should().Be(1);
    }

    [Fact]
    public void CleanupInactiveTerminal_NeverRunsForRecoveryBlockedEvidence()
    {
        using var fixture = new StoreFixture();
        var closeAuthorized =
            AdvanceToCloseAuthorizedAndActivate(fixture);
        var blocked = fixture.Store.EnterRecoveryBlocked(
            fixture.Authority,
            closeAuthorized);
        var cleanupCalls = 0;

        var result =
            fixture.Store.CleanupInactiveTerminalTransaction(
                fixture.Authority,
                blocked.Record!,
                () =>
                {
                    cleanupCalls++;
                    return true;
                });

        result.Error.Should().Be(
            ProtectedTransactionStoreError.InvalidData);
        cleanupCalls.Should().Be(0);
    }

    [Fact]
    public void CleanupInactiveTerminal_RevalidatesInstalledArtifactsBeforeCallback()
    {
        using var fixture = new StoreFixture();
        var terminal = AdvanceToCommittedAndActivate(fixture);
        fixture.Store.DeactivateTerminal(
                fixture.Authority,
                terminal)
            .Success.Should().BeTrue();
        fixture.InstalledReleaseVerifier.MutateManagedFileToOld(
            UpdateReleaseContract.WindowsApplicationPath);
        var cleanupCalls = 0;

        var result =
            fixture.Store.CleanupInactiveTerminalTransaction(
                fixture.Authority,
                terminal,
                () =>
                {
                    cleanupCalls++;
                    return true;
                });

        result.Error.Should().Be(
            ProtectedTransactionStoreError.VerificationFailed);
        cleanupCalls.Should().Be(0);
        fixture.Store.ReadTransaction(
                fixture.Authority,
                fixture.Material.TransactionId)
            .Success.Should().BeTrue();
    }

    [Fact]
    public void CleanupInactiveTerminal_CallbackFailurePreservesTerminalEvidence()
    {
        using var fixture = new StoreFixture();
        var terminal = AdvanceToCommittedAndActivate(fixture);
        fixture.Store.DeactivateTerminal(
                fixture.Authority,
                terminal)
            .Success.Should().BeTrue();

        var result =
            fixture.Store.CleanupInactiveTerminalTransaction(
                fixture.Authority,
                terminal,
                () => false);

        result.Error.Should().Be(
            ProtectedTransactionStoreError.IoFailure);
        fixture.Store.ReadActive(fixture.Authority)
            .TransactionId.Should().BeNull();
        fixture.Store.ReadTransaction(
                fixture.Authority,
                fixture.Material.TransactionId)
            .Record.Should().BeEquivalentTo(terminal);
    }

    [Fact]
    public void CleanupInactiveTerminal_MissingPointerNeverAuthorizesDeletion()
    {
        using var fixture = new StoreFixture();
        var terminal = AdvanceToCommittedAndActivate(fixture);
        fixture.Store.DeactivateTerminal(
                fixture.Authority,
                terminal)
            .Success.Should().BeTrue();
        fixture.FileSystem.RemoveFile(
            fixture.Layout.ActivePointerPath);
        var cleanupCalls = 0;

        var result =
            fixture.Store.CleanupInactiveTerminalTransaction(
                fixture.Authority,
                terminal,
                () =>
                {
                    cleanupCalls++;
                    return true;
                });

        result.Error.Should().Be(
            ProtectedTransactionStoreError.Conflict);
        cleanupCalls.Should().Be(0);
        fixture.Store.ReadTransaction(
                fixture.Authority,
                fixture.Material.TransactionId)
            .Success.Should().BeTrue();
    }

    [Fact]
    public void ReadTransaction_RejectsUnknownDuplicateWrongTypeNonCanonicalAndInvalidIdentityFields()
    {
        using var fixture = new StoreFixture();
        fixture.Store.CreateProtectedStaged(
                fixture.Authority,
                fixture.Material)
            .Success.Should().BeTrue();
        var validBytes = fixture.FileSystem.GetProtectedFile(
            fixture.Layout.TransactionRecordPath);

        var invalidRecords = new List<byte[]>
        {
            MutateRecord(validBytes, root =>
                root["browserState"] = "forged"),
            Encoding.UTF8.GetBytes(
                """{"schemaVersion":1,"""
                + Encoding.UTF8.GetString(validBytes)[1..]),
            MutateRecord(validBytes, root =>
            {
                root["SchemaVersion"] = root["schemaVersion"]!.DeepClone();
                root.Remove("schemaVersion");
            }),
            MutateRecord(validBytes, root =>
                root["schemaVersion"] = "1"),
            MutateRecord(validBytes, root =>
                root["transactionId"] =
                    fixture.Material.TransactionId.DirectoryName
                        .ToUpperInvariant()),
            MutateRecord(validBytes, root =>
                root["version"] = "01.2.4"),
            MutateRecord(validBytes, root =>
                root["source"] = "automatic"),
            MutateRecord(validBytes, root =>
                root["helperSha256"] =
                    fixture.Material.HelperSha256.ToUpperInvariant()),
            MutateRecord(validBytes, root =>
                root["installedRelease"]!["volumeSerialNumber"] = 0),
            MutateRecord(validBytes, root =>
                root["installedRelease"]!["managedFiles"]![0]!["relativePath"] =
                    @"C:\forged.exe"),
            MutateRecord(validBytes, root =>
                root["installedRelease"]!["managedFiles"]![0]!["length"] =
                    "10"),
            MutateRecord(validBytes, root =>
                root["candidate"]!["expandedBytes"] = "20"),
            MutateRecord(validBytes, root =>
                root["journal"]!["generation"] = "0"),
            MutateRecord(validBytes, root =>
                root["journal"]!["generation"] = -1),
            MutateRecord(validBytes, root =>
                root["helperPath"] = @"C:\attacker\helper.exe"),
            MutateRecord(validBytes, root =>
                root["candidateRoot"] = @"C:\attacker\candidate"),
            MutateRecord(validBytes, root =>
                root["journalPath"] = @"C:\attacker\journal.json"),
            MutateRecord(validBytes, root =>
                root["backupRoot"] = @"C:\attacker\backups"),
            MutateRecord(validBytes, root =>
                root["targetRoot"] = @"C:\attacker\target")
        };

        foreach (var invalid in invalidRecords)
        {
            fixture.FileSystem.ProtectFile(
                fixture.Layout.TransactionRecordPath,
                invalid);

            var read = fixture.Store.ReadTransaction(
                fixture.Authority,
                fixture.Material.TransactionId);

            read.Success.Should().BeFalse(
                Encoding.UTF8.GetString(invalid));
            read.Error.Should().Be(
                ProtectedTransactionStoreError.CorruptData);
        }

        fixture.FileSystem.Operations.Should().NotContain(
            operation => operation.Contains(
                @"C:\attacker",
                StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ReadTransaction_EnforcesThePhaseAndProcessIdentityInvariant()
    {
        using var fixture = new StoreFixture();
        fixture.Store.CreateProtectedStaged(
                fixture.Authority,
                fixture.Material)
            .Success.Should().BeTrue();
        var validBytes = fixture.FileSystem.GetProtectedFile(
            fixture.Layout.TransactionRecordPath);
        var process = new JsonObject
        {
            ["processId"] = 1234,
            ["creationTimeFileTimeUtc"] = 133000000000000000L,
            ["imagePath"] =
                @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel.App.exe"
        };

        var stagedWithProcess = MutateRecord(
            validBytes,
            root => root["authorizedProcess"] = process.DeepClone());
        fixture.FileSystem.ProtectFile(
            fixture.Layout.TransactionRecordPath,
            stagedWithProcess);
        fixture.Store.ReadTransaction(
                fixture.Authority,
                fixture.Material.TransactionId)
            .Success.Should().BeFalse();

        var authorizedWithoutProcess = MutateRecord(
            validBytes,
            root => root["phase"] = "CloseAuthorized");
        fixture.FileSystem.ProtectFile(
            fixture.Layout.TransactionRecordPath,
            authorizedWithoutProcess);
        fixture.Store.ReadTransaction(
                fixture.Authority,
                fixture.Material.TransactionId)
            .Success.Should().BeFalse();

        var validAuthorized = MutateRecord(
            validBytes,
            root =>
            {
                root["phase"] = "CloseAuthorized";
                root["authorizedProcess"] = process.DeepClone();
            });
        fixture.FileSystem.ProtectFile(
            fixture.Layout.TransactionRecordPath,
            validAuthorized);

        var read = fixture.Store.ReadTransaction(
            fixture.Authority,
            fixture.Material.TransactionId);

        read.Success.Should().BeTrue();
        read.Record!.AuthorizedProcess.Should().Be(
            new ProcessIdentity(
                1234,
                133000000000000000L,
                @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel.App.exe"));
    }

    [Theory]
    [InlineData("AppliedAwaitingHealth")]
    [InlineData("Committed")]
    [InlineData("RollingBack")]
    [InlineData("RolledBack")]
    [InlineData("RecoveryBlocked")]
    public void ReadTransaction_AllowsNoProcessWhenTheOldProcessIsNoLongerRequired(
        string phase)
    {
        using var fixture = new StoreFixture();
        fixture.Store.CreateProtectedStaged(
                fixture.Authority,
                fixture.Material)
            .Success.Should().BeTrue();
        var bytes = fixture.FileSystem.GetProtectedFile(
            fixture.Layout.TransactionRecordPath);
        fixture.FileSystem.ProtectFile(
            fixture.Layout.TransactionRecordPath,
            MutateRecord(
                bytes,
                root => root["phase"] = phase));

        var read = fixture.Store.ReadTransaction(
            fixture.Authority,
            fixture.Material.TransactionId);

        read.Success.Should().BeTrue();
        read.Record!.AuthorizedProcess.Should().BeNull();
    }

    [Fact]
    public void ReadsAndHelperVerification_FailClosedOnAnyExactAclMismatch()
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.Store.Activate(
                fixture.Authority,
                created.Record!)
            .Success.Should().BeTrue();

        fixture.FileSystem.MarkUnsafe(
            fixture.Layout.ActivePointerPath);
        fixture.Store.ReadActive(fixture.Authority)
            .Error.Should().Be(
                ProtectedTransactionStoreError.AclMismatch);
        fixture.FileSystem.ClearUnsafe(
            fixture.Layout.ActivePointerPath);

        fixture.FileSystem.MarkUnsafe(
            fixture.Layout.HelperPath);
        fixture.Store.VerifyHelper(
                fixture.Authority,
                fixture.Material.TransactionId,
                fixture.Material.HelperSha256)
            .Error.Should().Be(
                ProtectedTransactionStoreError.AclMismatch);
        fixture.FileSystem.ClearUnsafe(
            fixture.Layout.HelperPath);

        fixture.FileSystem.UnprotectDirectory(
            fixture.Layout.TransactionRoot);
        fixture.Store.ReadTransaction(
                fixture.Authority,
                fixture.Material.TransactionId)
            .Error.Should().Be(
                ProtectedTransactionStoreError.AclMismatch);
    }

    [Fact]
    public void ReadTransaction_BindsJournalGenerationZeroToNullHashAndLaterGenerationsToLowercaseHash()
    {
        using var fixture = new StoreFixture();
        fixture.Store.CreateProtectedStaged(
                fixture.Authority,
                fixture.Material)
            .Success.Should().BeTrue();
        var validBytes = fixture.FileSystem.GetProtectedFile(
            fixture.Layout.TransactionRecordPath);
        var validJson = JsonNode.Parse(validBytes)!.AsObject();
        validJson["journal"]!["sha256"]
            .Should().BeNull();

        var invalidRecords = new[]
        {
            MutateRecord(validBytes, root =>
                root["journal"]!["sha256"] = Hash('a')),
            MutateRecord(validBytes, root =>
            {
                root["journal"]!["generation"] = 1;
                root["journal"]!["sha256"] = null;
            }),
            MutateRecord(validBytes, root =>
            {
                root["journal"]!["generation"] = 1;
                root["journal"]!["sha256"] =
                    Hash('a').ToUpperInvariant();
            })
        };
        foreach (var invalid in invalidRecords)
        {
            fixture.FileSystem.ProtectFile(
                fixture.Layout.TransactionRecordPath,
                invalid);
            fixture.Store.ReadTransaction(
                    fixture.Authority,
                    fixture.Material.TransactionId)
                .Success.Should().BeFalse();
        }

        var laterGeneration = MutateRecord(
            validBytes,
            root =>
            {
                root["journal"]!["generation"] = 1;
                root["journal"]!["sha256"] = Hash('a');
            });
        fixture.FileSystem.ProtectFile(
            fixture.Layout.TransactionRecordPath,
            laterGeneration);

        var read = fixture.Store.ReadTransaction(
            fixture.Authority,
            fixture.Material.TransactionId);

        read.Success.Should().BeTrue();
        read.Record!.Journal.Should().Be(
            new ProtectedJournalMetadata(
                SchemaVersion: 1,
                Generation: 1,
                Sha256: Hash('a')));
    }

    [Fact]
    public void CreateAndActivate_RequirePhysicalJournalAbsenceForGenerationZero()
    {
        using (var createFixture = new StoreFixture())
        {
            createFixture.FileSystem.ProtectFile(
                createFixture.Layout.JournalPath,
                """{"generation":1}"""u8.ToArray());

            createFixture.Store.CreateProtectedStaged(
                    createFixture.Authority,
                    createFixture.Material)
                .Error.Should().Be(
                    ProtectedTransactionStoreError
                        .VerificationFailed);
        }

        using (var activateFixture = new StoreFixture())
        {
            var created =
                activateFixture.Store.CreateProtectedStaged(
                    activateFixture.Authority,
                    activateFixture.Material);
            activateFixture.FileSystem.ProtectFile(
                activateFixture.Layout.JournalPath,
                """{"generation":1}"""u8.ToArray());

            activateFixture.Store.Activate(
                    activateFixture.Authority,
                    created.Record!)
                .Error.Should().Be(
                    ProtectedTransactionStoreError
                        .VerificationFailed);
            activateFixture.Store.ReadActive(
                    activateFixture.Authority)
                .TransactionId.Should().BeNull();
        }
    }

    [Fact]
    public void ReadJournalForRecovery_DistinguishesAbsentBoundMissingStaleAndOneAheadBytes()
    {
        using var fixture = new StoreFixture();
        fixture.Store.CreateProtectedStaged(
                fixture.Authority,
                fixture.Material)
            .Success.Should().BeTrue();

        var absent = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        absent.Success.Should().BeTrue();
        absent.Observation.Should().Be(
            ProtectedJournalObservation.AbsentInitial);
        absent.JournalBytes.Should().BeNull();

        var journalBytes = InitialJournalBytes(
            fixture.Material.TransactionId);
        fixture.FileSystem.ProtectFile(
            fixture.Layout.JournalPath,
            journalBytes);
        var ahead = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        ahead.Success.Should().BeTrue();
        ahead.Observation.Should().Be(
            ProtectedJournalObservation.PresentButUnbound);
        ahead.JournalBytes.Should().Equal(journalBytes);
        ahead.JournalSha256.Should().Be(Hash(journalBytes));

        var recordBytes = fixture.FileSystem.GetProtectedFile(
            fixture.Layout.TransactionRecordPath);
        fixture.FileSystem.ProtectFile(
            fixture.Layout.TransactionRecordPath,
            MutateRecord(
                recordBytes,
                root =>
                {
                    root["journal"]!["generation"] = 1;
                    root["journal"]!["sha256"] =
                        Hash(journalBytes);
                }));
        var bound = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        bound.Success.Should().BeTrue();
        bound.Observation.Should().Be(
            ProtectedJournalObservation.MatchesBoundHash);

        fixture.FileSystem.RemoveFile(
            fixture.Layout.JournalPath);
        var missing = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        missing.Success.Should().BeTrue();
        missing.Observation.Should().Be(
            ProtectedJournalObservation.MissingButBound);

        fixture.FileSystem.ProtectFile(
            fixture.Layout.JournalPath,
            """{"torn":true}"""u8.ToArray());
        var stale = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        stale.Success.Should().BeTrue();
        stale.Observation.Should().Be(
            ProtectedJournalObservation.HashMismatch);
    }

    [Fact]
    public void PublishJournalCheckpoint_AtomicallyPublishesExactlyOneAheadWithoutBindingTheRecord()
    {
        using var fixture = new StoreFixture();
        AdvanceToCloseAuthorizedAndActivate(fixture);
        var expected = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        var bytes = InitialJournalBytes(
            fixture.Material.TransactionId);
        fixture.FileSystem.Operations.Clear();

        var published =
            fixture.Store.PublishJournalCheckpoint(
                fixture.Authority,
                expected,
                bytes);

        published.Success.Should().BeTrue();
        published.Observation.Should().Be(
            ProtectedJournalObservation.PresentButUnbound);
        published.JournalBytes.Should().Equal(bytes);
        published.JournalSha256.Should().Be(Hash(bytes));
        published.Record!.Journal.Should().Be(
            new ProtectedJournalMetadata(
                SchemaVersion: 1,
                Generation: 0));
        fixture.FileSystem.GetProtectedFile(
                fixture.Layout.JournalPath)
            .Should().Equal(bytes);
        fixture.FileSystem.Operations.Should().Contain(
            $"move:{fixture.Layout.JournalPath}");
        fixture.FileSystem.Operations.Should().NotContain(
            $"replace:{fixture.Layout.TransactionRecordPath}");
    }

    [Theory]
    [InlineData("""{"schemaVersion":1,"generation":2}""")]
    [InlineData("""{"schemaVersion":1,"generation":1}{}""")]
    [InlineData("""{"SchemaVersion":1,"generation":1}""")]
    [InlineData("""{"schemaVersion":1,"generation":1,"generation":1}""")]
    public void PublishJournalCheckpoint_RejectsAnythingExceptAValidExactNextEnvelope(
        string untrusted)
    {
        using var fixture = new StoreFixture();
        AdvanceToCloseAuthorizedAndActivate(fixture);
        var expected = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        fixture.FileSystem.Operations.Clear();

        var published =
            fixture.Store.PublishJournalCheckpoint(
                fixture.Authority,
                expected,
                Encoding.UTF8.GetBytes(untrusted));

        published.Error.Should().Be(
            ProtectedTransactionStoreError.InvalidData);
        fixture.FileSystem.InspectProtectedFile(
                fixture.Layout.JournalPath)
            .Should().Be(
                ProtectedTransactionFileState.Missing);
        fixture.FileSystem.Operations.Should().NotContain(
            operation => operation.StartsWith(
                "create:",
                StringComparison.Ordinal));
    }

    [Fact]
    public void ReadJournalForRecovery_RejectsCanonicalInitialPlanForAnotherTransaction()
    {
        using var fixture = new StoreFixture();
        fixture.Store.CreateProtectedStaged(
                fixture.Authority,
                fixture.Material)
            .Success.Should().BeTrue();
        var wrongTransactionBytes = InitialJournalBytes(
            ProtectedTransactionId.New());
        fixture.FileSystem.ProtectFile(
            fixture.Layout.JournalPath,
            wrongTransactionBytes);

        var observed = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);

        observed.Success.Should().BeTrue();
        observed.Observation.Should().Be(
            ProtectedJournalObservation.HashMismatch);
    }

    [Fact]
    public void BoundGenerationOne_MustRemainTheCanonicalInitialPlan()
    {
        using var fixture = new StoreFixture();
        fixture.Store.CreateProtectedStaged(
                fixture.Authority,
                fixture.Material)
            .Success.Should().BeTrue();
        var initial = InitialJournal(
            fixture.Material.TransactionId);
        var operations = initial.Operations.ToArray();
        operations[0] = operations[0] with
        {
            State = UpdateOperationState.BackupStarted
        };
        var nonInitialBytes = JournalBytes(initial with
        {
            Operations = operations
        });
        var recordBytes = fixture.FileSystem.GetProtectedFile(
            fixture.Layout.TransactionRecordPath);
        fixture.FileSystem.ProtectFile(
            fixture.Layout.TransactionRecordPath,
            MutateRecord(
                recordBytes,
                root =>
                {
                    root["journal"]!["generation"] = 1;
                    root["journal"]!["sha256"] =
                        Hash(nonInitialBytes);
                }));
        fixture.FileSystem.ProtectFile(
            fixture.Layout.JournalPath,
            nonInitialBytes);

        var observed = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        var record = fixture.Store.ReadTransaction(
            fixture.Authority,
            fixture.Material.TransactionId);

        observed.Success.Should().BeTrue();
        observed.Observation.Should().Be(
            ProtectedJournalObservation.HashMismatch);
        record.Success.Should().BeTrue();
        fixture.Store.Activate(
                fixture.Authority,
                record.Record)
            .Error.Should().Be(
                ProtectedTransactionStoreError.VerificationFailed);
        fixture.Store.ReadActive(fixture.Authority)
            .TransactionId.Should().BeNull();
    }

    [Fact]
    public void ReadJournalForRecovery_RejectsCanonicalSkippedCheckpointAsOneAhead()
    {
        using var fixture = new StoreFixture();
        var closeAuthorized =
            AdvanceToCloseAuthorizedAndActivate(fixture);
        var initial = InitialJournal(
            fixture.Material.TransactionId);
        var initialBytes = JournalBytes(initial);
        var absent = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        var published = fixture.Store.PublishJournalCheckpoint(
            fixture.Authority,
            absent,
            initialBytes);
        fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                published,
                closeAuthorized with
                {
                    Phase = ProtectedTransactionPhase.Prepared,
                    Journal = new ProtectedJournalMetadata(
                        SchemaVersion: 1,
                        Generation: 1,
                        Sha256: Hash(initialBytes))
                })
            .Success.Should().BeTrue();
        var operations = initial.Operations.ToArray();
        operations[0] = operations[0] with
        {
            State = UpdateOperationState.BackupComplete
        };
        var skippedBytes = JournalBytes(initial with
        {
            Generation = 2,
            Operations = operations
        });
        fixture.FileSystem.ProtectFile(
            fixture.Layout.JournalPath,
            skippedBytes);

        var observed = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);

        observed.Success.Should().BeTrue();
        observed.Observation.Should().Be(
            ProtectedJournalObservation.HashMismatch);
    }

    [Fact]
    public void PublishJournalCheckpoint_RejectsCanonicalImmutablePlanRewrite()
    {
        using var fixture = new StoreFixture();
        var closeAuthorized =
            AdvanceToCloseAuthorizedAndActivate(fixture);
        var initial = InitialJournal(
            fixture.Material.TransactionId);
        var initialBytes = JournalBytes(initial);
        var absent = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        var published = fixture.Store.PublishJournalCheckpoint(
            fixture.Authority,
            absent,
            initialBytes);
        fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                published,
                closeAuthorized with
                {
                    Phase = ProtectedTransactionPhase.Prepared,
                    Journal = new ProtectedJournalMetadata(
                        SchemaVersion: 1,
                        Generation: 1,
                        Sha256: Hash(initialBytes))
                })
            .Success.Should().BeTrue();
        var bound = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        var rewrittenOperations = initial.Operations.ToArray();
        rewrittenOperations[0] = rewrittenOperations[0] with
        {
            NewLength = rewrittenOperations[0].NewLength + 1
        };
        var rewrittenPredecessor = initial with
        {
            Operations = rewrittenOperations
        };
        var rewrittenNextBytes = JournalBytes(
            AdvanceFirstOperation(rewrittenPredecessor));
        fixture.FileSystem.Operations.Clear();

        var rejected = fixture.Store.PublishJournalCheckpoint(
            fixture.Authority,
            bound,
            rewrittenNextBytes);

        rejected.Error.Should().Be(
            ProtectedTransactionStoreError.InvalidData);
        fixture.FileSystem.GetProtectedFile(
                fixture.Layout.JournalPath)
            .Should().Equal(initialBytes);
        fixture.FileSystem.Operations.Should().NotContain(
            $"replace:{fixture.Layout.JournalPath}");
    }

    [Fact]
    public void PublishJournalCheckpoint_RequiresTheExactActiveTransactionAndBoundObservation()
    {
        using var fixture = new StoreFixture();
        AdvanceToCloseAuthorizedAndActivate(
            fixture,
            activate: false);
        var expected = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        var initialJournal = InitialJournal(
            fixture.Material.TransactionId);
        var bytes = JournalBytes(initialJournal);

        var inactive =
            fixture.Store.PublishJournalCheckpoint(
                fixture.Authority,
                expected,
                bytes);
        fixture.FileSystem.ProtectFile(
            fixture.Layout.JournalPath,
            bytes);
        var oneAhead =
            fixture.Store.ReadJournalForRecovery(
                fixture.Authority,
                fixture.Material.TransactionId);
        var unbound =
            fixture.Store.PublishJournalCheckpoint(
                fixture.Authority,
                oneAhead,
                JournalBytes(
                    AdvanceFirstOperation(initialJournal)));

        inactive.Error.Should().Be(
            ProtectedTransactionStoreError.Conflict);
        oneAhead.Observation.Should().Be(
            ProtectedJournalObservation.PresentButUnbound);
        unbound.Error.Should().Be(
            ProtectedTransactionStoreError.InvalidData);
    }

    [Fact]
    public void EnterRecoveryBlocked_BypassesCorruptArtifactsButPreservesAllEvidence()
    {
        using var fixture = new StoreFixture();
        AdvanceToCloseAuthorizedAndActivate(fixture);
        var corruptJournal = """{"torn":true}"""u8.ToArray();
        var corruptHelper = "tampered-helper"u8.ToArray();
        fixture.FileSystem.ProtectFile(
            fixture.Layout.JournalPath,
            corruptJournal);
        fixture.FileSystem.ProtectFile(
            fixture.Layout.HelperPath,
            corruptHelper);
        fixture.FileSystem.MarkUnsafe(
            fixture.Layout.JournalPath);
        fixture.FileSystem.MarkUnsafe(
            fixture.Layout.HelperPath);
        fixture.InstalledReleaseVerifier.Result = false;
        var expected = fixture.Store.ReadTransaction(
            fixture.Authority,
            fixture.Material.TransactionId).Record!;
        fixture.FileSystem.Operations.Clear();

        var blocked = fixture.Store.EnterRecoveryBlocked(
            fixture.Authority,
            expected);

        blocked.Success.Should().BeTrue();
        blocked.Record!.Phase.Should().Be(
            ProtectedTransactionPhase.RecoveryBlocked);
        fixture.Store.ReadTransaction(
                fixture.Authority,
                fixture.Material.TransactionId)
            .Record!.Phase.Should().Be(
                ProtectedTransactionPhase.RecoveryBlocked);
        fixture.FileSystem.GetProtectedFile(
                fixture.Layout.JournalPath)
            .Should().Equal(corruptJournal);
        fixture.FileSystem.GetProtectedFile(
                fixture.Layout.HelperPath)
            .Should().Equal(corruptHelper);
        fixture.Store.ReadActive(fixture.Authority)
            .TransactionId.Should().Be(
                fixture.Material.TransactionId);
        fixture.FileSystem.Operations.Should().NotContain(
            operation =>
                operation.StartsWith(
                    "snapshot:",
                    StringComparison.Ordinal)
                || operation.StartsWith(
                    "hash:",
                    StringComparison.Ordinal)
                || operation.StartsWith(
                    "version:",
                    StringComparison.Ordinal));
    }

    [Fact]
    public async Task PublishJournalCheckpoint_SerializesTwoStoresSharingOneAuthority()
    {
        using var fixture = new StoreFixture();
        AdvanceToCloseAuthorizedAndActivate(fixture);
        var expected = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        var secondStore = new ProtectedTransactionStore(
            fixture.Paths,
            fixture.FileSystem,
            _ => DriveType.Fixed,
            fixture.VersionReader,
            fixture.InstalledReleaseVerifier);
        var bytes = InitialJournalBytes(
            fixture.Material.TransactionId);
        using var start = new ManualResetEventSlim();

        var first = Task.Run(
            () =>
            {
                start.Wait();
                return fixture.Store.PublishJournalCheckpoint(
                    fixture.Authority,
                    expected,
                    bytes);
            });
        var second = Task.Run(
            () =>
            {
                start.Wait();
                return secondStore.PublishJournalCheckpoint(
                    fixture.Authority,
                    expected,
                    bytes);
            });
        start.Set();
        var results = await Task.WhenAll(first, second)
            .WaitAsync(TimeSpan.FromSeconds(10));

        results.Count(result => result.Success)
            .Should().Be(1);
        results.Count(
                result => result.Error
                    == ProtectedTransactionStoreError.Conflict)
            .Should().Be(1);
    }

    [Fact]
    public void PublishJournalCheckpoint_ReplacesOnlyAnExactlyBoundPriorGeneration()
    {
        using var fixture = new StoreFixture();
        var closeAuthorized =
            AdvanceToCloseAuthorizedAndActivate(fixture);
        var initial = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        var initialJournal = InitialJournal(
            fixture.Material.TransactionId);
        var firstBytes = JournalBytes(initialJournal);
        var first = fixture.Store.PublishJournalCheckpoint(
            fixture.Authority,
            initial,
            firstBytes);
        var prepared = closeAuthorized with
        {
            Phase = ProtectedTransactionPhase.Prepared,
            Journal = new ProtectedJournalMetadata(
                SchemaVersion: 1,
                Generation: 1,
                Sha256: Hash(firstBytes))
        };
        fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                first,
                prepared)
            .Success.Should().BeTrue();
        var bound = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        var secondBytes = JournalBytes(
            AdvanceFirstOperation(initialJournal));
        fixture.FileSystem.Operations.Clear();

        var second = fixture.Store.PublishJournalCheckpoint(
            fixture.Authority,
            bound,
            secondBytes);

        second.Success.Should().BeTrue();
        second.Observation.Should().Be(
            ProtectedJournalObservation.PresentButUnbound);
        fixture.FileSystem.Operations.Should().Contain(
            $"replace:{fixture.Layout.JournalPath}");
        fixture.FileSystem.GetProtectedFile(
                fixture.Layout.JournalPath)
            .Should().Equal(secondBytes);
    }

    [Fact]
    public void EnterRecoveryBlocked_RejectsInactiveOrStaleStateWithoutMutation()
    {
        using var inactiveFixture = new StoreFixture();
        AdvanceToCloseAuthorizedAndActivate(
            inactiveFixture,
            activate: false);
        var inactiveExpected =
            inactiveFixture.Store.ReadJournalForRecovery(
                inactiveFixture.Authority,
                inactiveFixture.Material.TransactionId);
        inactiveFixture.FileSystem.Operations.Clear();

        inactiveFixture.Store.EnterRecoveryBlocked(
                inactiveFixture.Authority,
                inactiveExpected.Record!)
            .Error.Should().Be(
                ProtectedTransactionStoreError.Conflict);
        inactiveFixture.FileSystem.Operations.Should().NotContain(
            $"replace:{inactiveFixture.Layout.TransactionRecordPath}");

        using var staleFixture = new StoreFixture();
        var closeAuthorized =
            AdvanceToCloseAuthorizedAndActivate(staleFixture);
        var stale = staleFixture.Store.ReadJournalForRecovery(
            staleFixture.Authority,
            staleFixture.Material.TransactionId);
        staleFixture.Store.CompareExchangeTransaction(
                staleFixture.Authority,
                stale,
                closeAuthorized with
                {
                    Phase = ProtectedTransactionPhase.Prepared
                })
            .Success.Should().BeTrue();
        staleFixture.FileSystem.Operations.Clear();

        var staleResult =
            staleFixture.Store.EnterRecoveryBlocked(
                staleFixture.Authority,
                stale.Record!);

        staleResult.Error.Should().Be(
            ProtectedTransactionStoreError.Conflict);
        staleFixture.Store.ReadTransaction(
                staleFixture.Authority,
                staleFixture.Material.TransactionId)
            .Record!.Phase.Should().Be(
                ProtectedTransactionPhase.Prepared);
        staleFixture.FileSystem.Operations.Should().NotContain(
            $"replace:{staleFixture.Layout.TransactionRecordPath}");
    }

    [Fact]
    public void EnterRecoveryBlocked_IsIdempotentWithoutRewritingTheTerminalRecord()
    {
        using var fixture = new StoreFixture();
        AdvanceToCloseAuthorizedAndActivate(fixture);
        var expected = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        fixture.Store.EnterRecoveryBlocked(
                fixture.Authority,
                expected.Record!)
            .Success.Should().BeTrue();
        var alreadyBlocked =
            fixture.Store.ReadJournalForRecovery(
                fixture.Authority,
                fixture.Material.TransactionId);
        fixture.FileSystem.Operations.Clear();

        var repeated = fixture.Store.EnterRecoveryBlocked(
            fixture.Authority,
            alreadyBlocked.Record!);

        repeated.Success.Should().BeTrue();
        repeated.Record!.Phase.Should().Be(
            ProtectedTransactionPhase.RecoveryBlocked);
        fixture.FileSystem.Operations.Should().NotContain(
            $"replace:{fixture.Layout.TransactionRecordPath}");
    }

    [Fact]
    public void CompareExchangeTransaction_AdoptsOnlyTheObservedExactlyOneAheadJournalAcrossGenerations()
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        var staged = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        var closeAuthorized = created.Record! with
        {
            Phase = ProtectedTransactionPhase.CloseAuthorized,
            AuthorizedProcess = new ProcessIdentity(
                ProcessId: 1234,
                CreationTimeFileTimeUtc:
                    133000000000000000L,
                ImagePath:
                    @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel.App.exe")
        };
        fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                staged,
                closeAuthorized)
            .Success.Should().BeTrue();
        var initialJournal = InitialJournal(
            fixture.Material.TransactionId);
        var journalBytes = JournalBytes(initialJournal);
        fixture.FileSystem.ProtectFile(
            fixture.Layout.JournalPath,
            journalBytes);
        var observed = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        observed.Observation.Should().Be(
            ProtectedJournalObservation.PresentButUnbound);
        var replacement = closeAuthorized with
        {
            Phase = ProtectedTransactionPhase.Prepared,
            Journal = new ProtectedJournalMetadata(
                SchemaVersion: 1,
                Generation: 1,
                Sha256: Hash(journalBytes))
        };

        var exchanged =
            fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                observed,
                replacement);

        exchanged.Success.Should().BeTrue();
        fixture.Store.ReadTransaction(
                fixture.Authority,
                fixture.Material.TransactionId)
            .Record!.Journal.Should().Be(
                replacement.Journal);
        fixture.Store.ReadJournalForRecovery(
                fixture.Authority,
                fixture.Material.TransactionId)
            .Observation.Should().Be(
                ProtectedJournalObservation.MatchesBoundHash);

        var secondJournalBytes = JournalBytes(
            AdvanceFirstOperation(initialJournal));
        fixture.FileSystem.ProtectFile(
            fixture.Layout.JournalPath,
            secondJournalBytes);
        var secondObserved = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        secondObserved.Observation.Should().Be(
            ProtectedJournalObservation.PresentButUnbound);
        var backingUp = replacement with
        {
            Phase = ProtectedTransactionPhase.BackingUp,
            Journal = new ProtectedJournalMetadata(
                SchemaVersion: 1,
                Generation: 2,
                Sha256: Hash(secondJournalBytes))
        };

        var secondExchange =
            fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                secondObserved,
                backingUp);

        secondExchange.Success.Should().BeTrue();
        fixture.Store.ReadJournalForRecovery(
                fixture.Authority,
                fixture.Material.TransactionId)
            .Observation.Should().Be(
                ProtectedJournalObservation.MatchesBoundHash);
    }

    [Theory]
    [InlineData("{")]
    [InlineData(
        """{"schemaVersion":1,"schemaVersion":1,"generation":2}""")]
    [InlineData(
        """{"schemaVersion":1,"generation":2,"generation":2}""")]
    [InlineData(
        """{"schemaVersion":1,"generation":2,"operation":{"state":1,"state":2}}""")]
    [InlineData(
        """{"schemaVersion":1,"generation":2}{}""")]
    [InlineData(
        """{"schemaVersion":2,"generation":2}""")]
    [InlineData(
        """{"schemaVersion":1,"generation":3}""")]
    [InlineData(
        """{"schemaVersion":1,"generation":"2"}""")]
    [InlineData(
        """{"SchemaVersion":1,"generation":2}""")]
    public void ReadJournalForRecovery_RejectsMalformedDuplicateOrWrongOneAheadEnvelope(
        string untrustedJournal)
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        var staged = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        var closeAuthorized = created.Record! with
        {
            Phase = ProtectedTransactionPhase.CloseAuthorized,
            AuthorizedProcess = new ProcessIdentity(
                ProcessId: 1234,
                CreationTimeFileTimeUtc:
                    133000000000000000L,
                ImagePath:
                    @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel.App.exe")
        };
        fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                staged,
                closeAuthorized)
            .Success.Should().BeTrue();
        var firstJournalBytes = InitialJournalBytes(
            fixture.Material.TransactionId);
        fixture.FileSystem.ProtectFile(
            fixture.Layout.JournalPath,
            firstJournalBytes);
        var firstObserved = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        var prepared = closeAuthorized with
        {
            Phase = ProtectedTransactionPhase.Prepared,
            Journal = new ProtectedJournalMetadata(
                SchemaVersion: 1,
                Generation: 1,
                Sha256: Hash(firstJournalBytes))
        };
        fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                firstObserved,
                prepared)
            .Success.Should().BeTrue();
        var untrustedBytes = Encoding.UTF8.GetBytes(
            untrustedJournal);
        fixture.FileSystem.ProtectFile(
            fixture.Layout.JournalPath,
            untrustedBytes);

        var observed = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        var proposed = prepared with
        {
            Phase = ProtectedTransactionPhase.BackingUp,
            Journal = new ProtectedJournalMetadata(
                SchemaVersion: 1,
                Generation: 2,
                Sha256: Hash(untrustedBytes))
        };

        observed.Success.Should().BeTrue();
        observed.Observation.Should().Be(
            ProtectedJournalObservation.HashMismatch);
        fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                observed,
                proposed)
            .Error.Should().Be(
                ProtectedTransactionStoreError.InvalidData);
    }

    [Fact]
    public void ReadJournalForRecovery_RequiresTheBoundHashAndEmbeddedGenerationToAgree()
    {
        using var fixture = new StoreFixture();
        fixture.Store.CreateProtectedStaged(
                fixture.Authority,
                fixture.Material)
            .Success.Should().BeTrue();
        var wrongGenerationBytes = JournalBytes(
            AdvanceFirstOperation(
                InitialJournal(
                    fixture.Material.TransactionId)));
        var recordBytes = fixture.FileSystem.GetProtectedFile(
            fixture.Layout.TransactionRecordPath);
        fixture.FileSystem.ProtectFile(
            fixture.Layout.TransactionRecordPath,
            MutateRecord(
                recordBytes,
                root =>
                {
                    root["journal"]!["generation"] = 1;
                    root["journal"]!["sha256"] =
                        Hash(wrongGenerationBytes);
                }));
        fixture.FileSystem.ProtectFile(
            fixture.Layout.JournalPath,
            wrongGenerationBytes);

        var observed = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);

        observed.Success.Should().BeTrue();
        observed.Observation.Should().Be(
            ProtectedJournalObservation.HashMismatch);
        fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                observed,
                observed.Record)
            .Error.Should().Be(
                ProtectedTransactionStoreError.InvalidData);
    }

    [Fact]
    public void CompareExchangeTransaction_RejectsAnIllegalPhaseJump()
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        var observed = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        var illegal = created.Record! with
        {
            Phase = ProtectedTransactionPhase.Committed
        };

        var exchanged =
            fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                observed,
                illegal);

        exchanged.Error.Should().Be(
            ProtectedTransactionStoreError.InvalidData);
        fixture.Store.ReadTransaction(
                fixture.Authority,
                fixture.Material.TransactionId)
            .Record!.Phase.Should().Be(
                ProtectedTransactionPhase.ProtectedStaged);
    }

    [Fact]
    public void CompareExchangeTransaction_AfterFirstTargetMutationUsesNamespaceVerification()
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        var closeAuthorized = created.Record! with
        {
            Phase = ProtectedTransactionPhase.CloseAuthorized,
            AuthorizedProcess = new ProcessIdentity(
                ProcessId: 1234,
                CreationTimeFileTimeUtc:
                    133000000000000000L,
                ImagePath:
                    @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel.App.exe")
        };
        var staged = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                staged,
                closeAuthorized)
            .Success.Should().BeTrue();
        var closeObserved =
            fixture.Store.ReadJournalForRecovery(
                fixture.Authority,
                fixture.Material.TransactionId);
        var prepared = closeAuthorized with
        {
            Phase = ProtectedTransactionPhase.Prepared
        };
        fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                closeObserved,
                prepared)
            .Success.Should().BeTrue();
        var preparedObserved =
            fixture.Store.ReadJournalForRecovery(
                fixture.Authority,
                fixture.Material.TransactionId);
        var backingUp = prepared with
        {
            Phase = ProtectedTransactionPhase.BackingUp
        };
        fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                preparedObserved,
                backingUp)
            .Success.Should().BeTrue();

        // Task9 may now have atomically replaced one installed target,
        // so a full-old content check would be invalid. The retained root
        // identity, ACL and managed namespace must still be intact.
        fixture.InstalledReleaseVerifier.MutateManagedFileToNew(
            UpdateReleaseContract.RequiredLauncherPaths[0]);
        fixture.InstalledReleaseVerifier.MatchesOldSnapshot
            .Should().BeFalse();
        var journalBytes = InitialJournalBytes(
            fixture.Material.TransactionId);
        fixture.FileSystem.ProtectFile(
            fixture.Layout.JournalPath,
            journalBytes);
        var afterFirstMutation =
            fixture.Store.ReadJournalForRecovery(
                fixture.Authority,
                fixture.Material.TransactionId);
        var applying = backingUp with
        {
            Phase = ProtectedTransactionPhase.Applying,
            Journal = new ProtectedJournalMetadata(
                SchemaVersion: 1,
                Generation: 1,
                Sha256: Hash(journalBytes))
        };

        var exchanged =
            fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                afterFirstMutation,
                applying);

        exchanged.Success.Should().BeTrue();
        fixture.InstalledReleaseVerifier.LastVerification
            .Should().Be(
                ProtectedInstalledReleaseVerification.NamespaceOnly);
    }

    [Theory]
    [InlineData("exact", true)]
    [InlineData("partial", false)]
    [InlineData("managed-extra", false)]
    [InlineData("missing", false)]
    [InlineData("product-version", false)]
    public void CompareExchangeTransaction_AppliedAwaitingHealthRequiresExactNewInstalledSnapshot(
        string installedState,
        bool expectedSuccess)
    {
        using var fixture = new StoreFixture();
        var applying = AdvanceToApplying(fixture);
        fixture.InstalledReleaseVerifier.SetFullyNew();
        switch (installedState)
        {
            case "exact":
                break;
            case "partial":
                fixture.InstalledReleaseVerifier
                    .MutateManagedFileToOld(
                        UpdateReleaseContract
                            .RequiredLauncherPaths[0]);
                break;
            case "managed-extra":
                fixture.InstalledReleaseVerifier
                    .AddManifestDeclaredManagedExtra();
                break;
            case "missing":
                fixture.InstalledReleaseVerifier
                    .RemoveManagedFile(
                        UpdateReleaseContract
                            .RequiredLauncherPaths[0]);
                break;
            case "product-version":
                fixture.InstalledReleaseVerifier
                    .SetApplicationProductVersion("0.0.0");
                break;
            default:
                throw new ArgumentOutOfRangeException(
                    nameof(installedState));
        }

        var observed = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        var result = fixture.Store.CompareExchangeTransaction(
            fixture.Authority,
            observed,
            applying with
            {
                Phase = ProtectedTransactionPhase
                    .AppliedAwaitingHealth
            });

        result.Success.Should().Be(expectedSuccess);
        fixture.InstalledReleaseVerifier.LastVerification
            .Should().Be(
                ProtectedInstalledReleaseVerification.FullNew);
        if (!expectedSuccess)
        {
            result.Error.Should().Be(
                ProtectedTransactionStoreError
                    .VerificationFailed);
            fixture.Store.ReadTransaction(
                    fixture.Authority,
                    fixture.Material.TransactionId)
                .Record!.Phase.Should().Be(
                    ProtectedTransactionPhase.Applying);
        }
    }

    [Fact]
    public void InstalledVerification_DoesNotTraverseOrRejectSafeUnmanagedRuntimeAndCustomFiles()
    {
        using var fixture = new StoreFixture();
        fixture.InstalledReleaseVerifier.AddSafeUnmanagedFile(
            "state.json",
            """{"schemaVersion":1}"""u8.ToArray());
        fixture.InstalledReleaseVerifier.AddSafeUnmanagedFile(
            "logs/runtime.log",
            "do not inspect"u8.ToArray());
        fixture.InstalledReleaseVerifier.AddSafeUnmanagedFile(
            "profiles/custom/profile.json",
            """{"custom":true}"""u8.ToArray());

        var applying = AdvanceToApplying(fixture);
        fixture.InstalledReleaseVerifier.SetFullyNew();
        var observed = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        var completed =
            fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                observed,
                applying with
                {
                    Phase = ProtectedTransactionPhase
                        .AppliedAwaitingHealth
                });

        completed.Success.Should().BeTrue();
        fixture.InstalledReleaseVerifier
            .UnmanagedContentReadCount.Should().Be(0);
    }

    [Theory]
    [InlineData("changed")]
    [InlineData("missing")]
    public void CreateProtectedStaged_FullOldRejectsChangedOrMissingManagedFiles(
        string installedState)
    {
        using var fixture = new StoreFixture();
        var path =
            UpdateReleaseContract.RequiredLauncherPaths[0];
        if (installedState == "changed")
        {
            fixture.InstalledReleaseVerifier
                .MutateManagedFileToNew(path);
        }
        else
        {
            fixture.InstalledReleaseVerifier
                .RemoveManagedFile(path);
        }

        fixture.Store.CreateProtectedStaged(
                fixture.Authority,
                fixture.Material)
            .Error.Should().Be(
                ProtectedTransactionStoreError
                    .VerificationFailed);
        fixture.InstalledReleaseVerifier.LastVerification
            .Should().Be(
                ProtectedInstalledReleaseVerification.FullOld);
    }

    [Fact]
    public void CompareExchangeTransaction_IsIdempotentWithoutRewritingAnExactRecord()
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        var observed = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        fixture.FileSystem.Operations.Clear();

        var exchanged =
            fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                observed,
                created.Record!);

        exchanged.Success.Should().BeTrue();
        fixture.FileSystem.Operations.Should().NotContain(
            $"replace:{fixture.Layout.TransactionRecordPath}");
    }

    [Theory]
    [InlineData("helper")]
    [InlineData("journal")]
    public void CompareExchangeTransaction_IdempotentRecordStillRevalidatesDurableArtifacts(
        string changedArtifact)
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        var observed = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        if (changedArtifact == "helper")
        {
            fixture.FileSystem.ProtectFile(
                fixture.Layout.HelperPath,
                "tampered"u8.ToArray());
        }
        else
        {
            fixture.FileSystem.ProtectFile(
                fixture.Layout.JournalPath,
                """{"schemaVersion":1,"generation":1}"""u8
                    .ToArray());
        }

        fixture.FileSystem.Operations.Clear();
        var exchanged = fixture.Store.CompareExchangeTransaction(
            fixture.Authority,
            observed,
            created.Record!);

        exchanged.Error.Should().Be(
            ProtectedTransactionStoreError.VerificationFailed);
        fixture.FileSystem.Operations.Should().NotContain(
            $"replace:{fixture.Layout.TransactionRecordPath}");
    }
    [Fact]
    public void CompareExchangeTransaction_RejectsAnExactRecordByteInterleavingWithoutOverwritingIt()
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        var staged = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        var closeAuthorized = created.Record! with
        {
            Phase = ProtectedTransactionPhase.CloseAuthorized,
            AuthorizedProcess = new ProcessIdentity(
                ProcessId: 1234,
                CreationTimeFileTimeUtc:
                    133000000000000000L,
                ImagePath:
                    @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel.App.exe")
        };
        fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                staged,
                closeAuthorized)
            .Success.Should().BeTrue();
        var journalBytes = InitialJournalBytes(
            fixture.Material.TransactionId);
        fixture.FileSystem.ProtectFile(
            fixture.Layout.JournalPath,
            journalBytes);
        var observed = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        var replacement = closeAuthorized with
        {
            Phase = ProtectedTransactionPhase.Prepared,
            Journal = new ProtectedJournalMetadata(
                SchemaVersion: 1,
                Generation: 1,
                Sha256: Hash(journalBytes))
        };
        var racedRecord = MutateRecord(
            observed.RecordBytes!,
            root =>
            {
                root["authorizedProcess"]!["processId"] =
                    5678;
            });
        fixture.FileSystem.ProtectFile(
            fixture.Layout.TransactionRecordPath,
            racedRecord);

        var exchanged =
            fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                observed,
                replacement);

        exchanged.Error.Should().Be(
            ProtectedTransactionStoreError.Conflict);
        fixture.FileSystem.GetProtectedFile(
                fixture.Layout.TransactionRecordPath)
            .Should().Equal(racedRecord);
    }

    [Fact]
    public async Task CompareExchangeTransaction_SerializesTwoStoreInstancesSharingOneAuthority()
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        var observed = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        var firstReplacement = created.Record! with
        {
            Phase = ProtectedTransactionPhase.CloseAuthorized,
            AuthorizedProcess = new ProcessIdentity(
                ProcessId: 1234,
                CreationTimeFileTimeUtc:
                    133000000000000000L,
                ImagePath:
                    @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel.App.exe")
        };
        var secondReplacement = firstReplacement with
        {
            AuthorizedProcess = firstReplacement.AuthorizedProcess! with
            {
                ProcessId = 5678
            }
        };
        var secondStore = new ProtectedTransactionStore(
            fixture.Paths,
            fixture.FileSystem,
            _ => DriveType.Fixed,
            fixture.VersionReader,
            fixture.InstalledReleaseVerifier);
        fixture.FileSystem.EnableRacyCompareExchange(
            fixture.Layout.TransactionRecordPath);
        using var start = new ManualResetEventSlim();

        var first = Task.Run(
            () =>
            {
                start.Wait();
                return fixture.Store.CompareExchangeTransaction(
                    fixture.Authority,
                    observed,
                    firstReplacement);
            });
        var second = Task.Run(
            () =>
            {
                start.Wait();
                return secondStore.CompareExchangeTransaction(
                    fixture.Authority,
                    observed,
                    secondReplacement);
            });
        start.Set();
        var results = await Task.WhenAll(first, second)
            .WaitAsync(TimeSpan.FromSeconds(10));

        results.Count(result => result.Success)
            .Should().Be(1);
        results.Count(
                result => result.Error
                    == ProtectedTransactionStoreError.Conflict)
            .Should().Be(1);
    }

    [Fact]
    public void PersistedRecord_ContainsNoAbsoluteChildOrUserBrowserVpnLogStateAuthority()
    {
        using var fixture = new StoreFixture();
        fixture.Store.CreateProtectedStaged(
                fixture.Authority,
                fixture.Material)
            .Success.Should().BeTrue();

        var json = Encoding.UTF8.GetString(
            fixture.FileSystem.GetProtectedFile(
                fixture.Layout.TransactionRecordPath));

        json.Should().NotContainAny(
            "helperPath",
            "candidateRoot",
            "journalPath",
            "backupRoot",
            "targetRoot",
            "browser",
            "account",
            "vpn",
            "logPath",
            "statePath");
    }

    private static string Hash(char character) =>
        new(character, 64);

    private static string Hash(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes))
            .ToLowerInvariant();

    private static UpdateOperationJournal InitialJournal(
        ProtectedTransactionId transactionId) =>
        new(
            UpdateOperationJournalCodec.SchemaVersion,
            Generation: 1,
            transactionId,
            UpdateJournalMode.Applying,
            RollbackCursor: -1,
            RollbackMutationStarted: false,
            Operations:
            [
                new UpdateOperation(
                    Ordinal: 0,
                    UpdateOperationKind.Replace,
                    UpdateReleaseContract.WindowsApplicationPath,
                    Existed: true,
                    OldLength: 10,
                    OldSha256: Hash('a'),
                    BackupRelativePath:
                        UpdateReleaseContract.WindowsApplicationPath,
                    BackupSha256: Hash('a'),
                    NewLength: 11,
                    NewSha256: Hash('b'),
                    UpdateOperationState.Planned),
                new UpdateOperation(
                    Ordinal: 1,
                    UpdateOperationKind.ReplaceManifest,
                    UpdateReleaseContract.ReleaseManifestPath,
                    Existed: true,
                    OldLength: 20,
                    OldSha256: Hash('c'),
                    BackupRelativePath:
                        UpdateReleaseContract.ReleaseManifestPath,
                    BackupSha256: Hash('c'),
                    NewLength: 21,
                    NewSha256: Hash('d'),
                    UpdateOperationState.Planned)
            ]);

    private static UpdateOperationJournal AdvanceFirstOperation(
        UpdateOperationJournal current)
    {
        var operations = current.Operations.ToArray();
        operations[0] = operations[0] with
        {
            State = UpdateOperationState.BackupStarted
        };
        return current with
        {
            Generation = current.Generation + 1,
            Operations = operations
        };
    }

    private static byte[] JournalBytes(
        UpdateOperationJournal journal)
    {
        UpdateOperationJournalCodec.TrySerialize(
                journal,
                out var bytes)
            .Should().BeTrue();
        return bytes;
    }

    private static byte[] InitialJournalBytes(
        ProtectedTransactionId transactionId) =>
        JournalBytes(InitialJournal(transactionId));

    private static ProtectedTransactionRecord
        AdvanceToCloseAuthorizedAndActivate(
            StoreFixture fixture,
            bool activate = true)
    {
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        created.Success.Should().BeTrue();
        if (activate)
        {
            fixture.Store.Activate(
                    fixture.Authority,
                    created.Record!)
                .Success.Should().BeTrue();
        }

        var observed = fixture.Store.ReadJournalForRecovery(
            fixture.Authority,
            fixture.Material.TransactionId);
        var closeAuthorized = created.Record! with
        {
            Phase = ProtectedTransactionPhase.CloseAuthorized,
            AuthorizedProcess = new ProcessIdentity(
                ProcessId: 1234,
                CreationTimeFileTimeUtc:
                    133000000000000000L,
                ImagePath:
                    @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel.App.exe")
        };
        fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                observed,
                closeAuthorized)
            .Success.Should().BeTrue();
        return closeAuthorized;
    }

    private static ProtectedTransactionRecord
        AdvanceToCommittedAndActivate(
            StoreFixture fixture)
    {
        var record =
            AdvanceToCloseAuthorizedAndActivate(fixture);
        var initialBytes = InitialJournalBytes(
            fixture.Material.TransactionId);
        var closeObserved =
            fixture.Store.ReadJournalForRecovery(
                fixture.Authority,
                fixture.Material.TransactionId);
        var published = fixture.Store.PublishJournalCheckpoint(
            fixture.Authority,
            closeObserved,
            initialBytes);
        published.Success.Should().BeTrue();
        record = record with
        {
            Phase = ProtectedTransactionPhase.Prepared,
            Journal = new ProtectedJournalMetadata(
                ProtectedTransactionStore.JournalSchemaVersion,
                Generation: 1,
                Sha256: Hash(initialBytes))
        };
        fixture.Store.CompareExchangeTransaction(
                fixture.Authority,
                published,
                record)
            .Success.Should().BeTrue();
        foreach (var phase in new[]
        {
            ProtectedTransactionPhase.BackingUp,
            ProtectedTransactionPhase.Applying
        })
        {
            var observed =
                fixture.Store.ReadJournalForRecovery(
                    fixture.Authority,
                    fixture.Material.TransactionId);
            record = record with
            {
                Phase = phase
            };
            fixture.Store.CompareExchangeTransaction(
                    fixture.Authority,
                    observed,
                    record)
                .Success.Should().BeTrue();
        }

        fixture.InstalledReleaseVerifier.SetFullyNew();
        foreach (var phase in new[]
        {
            ProtectedTransactionPhase.AppliedAwaitingHealth,
            ProtectedTransactionPhase.Committed
        })
        {
            var observed =
                fixture.Store.ReadJournalForRecovery(
                    fixture.Authority,
                    fixture.Material.TransactionId);
            record = record with
            {
                Phase = phase
            };
            fixture.Store.CompareExchangeTransaction(
                    fixture.Authority,
                    observed,
                    record)
                .Success.Should().BeTrue();
        }

        return record;
    }

    private static ProtectedTransactionRecord AdvanceToApplying(
        StoreFixture fixture)
    {
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        created.Success.Should().BeTrue();
        var record = created.Record! with
        {
            Phase = ProtectedTransactionPhase.CloseAuthorized,
            AuthorizedProcess = new ProcessIdentity(
                ProcessId: 1234,
                CreationTimeFileTimeUtc:
                    133000000000000000L,
                ImagePath:
                    @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel.App.exe")
        };
        foreach (var phase in new[]
        {
            ProtectedTransactionPhase.CloseAuthorized,
            ProtectedTransactionPhase.Prepared,
            ProtectedTransactionPhase.BackingUp,
            ProtectedTransactionPhase.Applying
        })
        {
            record = record with
            {
                Phase = phase
            };
            var observed =
                fixture.Store.ReadJournalForRecovery(
                    fixture.Authority,
                    fixture.Material.TransactionId);
            fixture.Store.CompareExchangeTransaction(
                    fixture.Authority,
                    observed,
                    record)
                .Success.Should().BeTrue();
        }

        return record;
    }

    private static byte[] InstalledDescriptor(
        InstalledReleaseSecurityScope scope,
        int? usersMask = null,
        bool addWorldAce = false,
        bool denyUsers = false)
    {
        var administrators = new SecurityIdentifier(
            WellKnownSidType.BuiltinAdministratorsSid,
            domainSid: null);
        var system = new SecurityIdentifier(
            WellKnownSidType.LocalSystemSid,
            domainSid: null);
        var users = new SecurityIdentifier(
            WellKnownSidType.BuiltinUsersSid,
            domainSid: null);
        var flags = scope switch
        {
            InstalledReleaseSecurityScope.RootDirectory =>
                AceFlags.ContainerInherit
                | AceFlags.ObjectInherit,
            InstalledReleaseSecurityScope
                .DescendantDirectory =>
                AceFlags.ContainerInherit
                | AceFlags.ObjectInherit
                | AceFlags.Inherited,
            _ => AceFlags.Inherited
        };
        var dacl = new RawAcl(
            GenericAcl.AclRevision,
            addWorldAce ? 4 : 3);
        dacl.InsertAce(
            0,
            new CommonAce(
                flags,
                AceQualifier.AccessAllowed,
                (int)FileSystemRights.FullControl,
                administrators,
                isCallback: false,
                opaque: null));
        dacl.InsertAce(
            1,
            new CommonAce(
                flags,
                AceQualifier.AccessAllowed,
                (int)FileSystemRights.FullControl,
                system,
                isCallback: false,
                opaque: null));
        dacl.InsertAce(
            2,
            new CommonAce(
                flags,
                denyUsers
                    ? AceQualifier.AccessDenied
                    : AceQualifier.AccessAllowed,
                usersMask
                    ?? (int)(
                        FileSystemRights.ReadAndExecute
                        | FileSystemRights.Synchronize),
                users,
                isCallback: false,
                opaque: null));
        if (addWorldAce)
        {
            dacl.InsertAce(
                3,
                new CommonAce(
                    flags,
                    AceQualifier.AccessAllowed,
                    (int)FileSystemRights.Read,
                    new SecurityIdentifier(
                        WellKnownSidType.WorldSid,
                        domainSid: null),
                    isCallback: false,
                    opaque: null));
        }

        var control =
            ControlFlags.DiscretionaryAclPresent;
        if (scope
            == InstalledReleaseSecurityScope.RootDirectory)
        {
            control |=
                ControlFlags.DiscretionaryAclProtected;
        }

        var descriptor = new RawSecurityDescriptor(
            control,
            system,
            system,
            systemAcl: null,
            dacl);
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        return bytes;
    }

    private static DirectorySecurity
        InstalledRootSecurityForInheritanceTest(
            SecurityIdentifier owner)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.SetOwner(owner);
        security.AddAccessRule(
            InstalledRootRule(
                WellKnownSidType.BuiltinAdministratorsSid,
                FileSystemRights.FullControl));
        security.AddAccessRule(
            InstalledRootRule(
                WellKnownSidType.LocalSystemSid,
                FileSystemRights.FullControl));
        security.AddAccessRule(
            InstalledRootRule(
                WellKnownSidType.BuiltinUsersSid,
                FileSystemRights.ReadAndExecute
                    | FileSystemRights.Synchronize));
        return security;
    }

    private static FileSystemAccessRule InstalledRootRule(
        WellKnownSidType sidType,
        FileSystemRights rights) =>
        new(
            new SecurityIdentifier(
                sidType,
                domainSid: null),
            rights,
            InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow);

    private static byte[]
        NormalizeOwnerToSystemForDaclInheritanceAssertionOnly(
            byte[] descriptor) =>
        ReplaceDescriptorOwner(
            descriptor,
            new SecurityIdentifier(
                WellKnownSidType.LocalSystemSid,
                domainSid: null));

    private static byte[] ReplaceDescriptorOwner(
        byte[] descriptor,
        SecurityIdentifier owner)
    {
        var raw = new RawSecurityDescriptor(
            descriptor,
            offset: 0)
        {
            Owner = owner
        };
        var result = new byte[raw.BinaryLength];
        raw.GetBinaryForm(result, 0);
        return result;
    }

    private static void SetDirectoryOwner(
        string path,
        SecurityIdentifier owner)
    {
        var security = new DirectorySecurity(
            path,
            AccessControlSections.Owner
                | AccessControlSections.Access);
        security.SetOwner(owner);
        new DirectoryInfo(path).SetAccessControl(security);
    }

    private static void SetFileOwner(
        string path,
        SecurityIdentifier owner)
    {
        var security = new FileSecurity(
            path,
            AccessControlSections.Owner
                | AccessControlSections.Access);
        security.SetOwner(owner);
        new FileInfo(path).SetAccessControl(security);
    }

    private static void GrantCleanupAndDelete(
        string root,
        SecurityIdentifier currentUser)
    {
        if (!Directory.Exists(root))
        {
            return;
        }

        var security = new DirectorySecurity(
            root,
            AccessControlSections.Access);
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.AddAccessRule(
            new FileSystemAccessRule(
                currentUser,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                    | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        new DirectoryInfo(root).SetAccessControl(security);
        Directory.Delete(root, recursive: true);
    }

    private static byte[] MutateRecord(
        byte[] bytes,
        Action<JsonObject> mutation)
    {
        var root = JsonNode.Parse(bytes)!.AsObject();
        mutation(root);
        return Encoding.UTF8.GetBytes(root.ToJsonString());
    }

    private static IReadOnlyList<ProtectedManagedFileIdentity>
        InstalledManagedFiles() =>
        UpdateReleaseContract.RequiredLauncherPaths
            .Append(UpdateReleaseContract.WindowsApplicationPath)
            .Append(UpdateReleaseContract.WindowsUpdaterPath)
            .OrderBy(path => path, StringComparer.Ordinal)
            .Select(path =>
                new ProtectedManagedFileIdentity(
                    path,
                    Length: 10,
                    Hash('d')))
            .ToArray();

    private static IReadOnlyDictionary<string, byte[]>
        CandidatePayloadFiles(int patch) =>
        UpdateReleaseContract.RequiredLauncherPaths
            .Append(UpdateReleaseContract.WindowsApplicationPath)
            .Append(UpdateReleaseContract.WindowsUpdaterPath)
            .Distinct(StringComparer.Ordinal)
            .ToDictionary(
                path => path,
                path => Encoding.UTF8.GetBytes(
                    $"{path}-v1.2.{patch}"),
                StringComparer.Ordinal);

    private static byte[] CandidateManifestBytes(
        int patch,
        IReadOnlyDictionary<string, byte[]> payloads)
    {
        var files = payloads
            .OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .Select(pair => new
            {
                path = pair.Key,
                length = pair.Value.LongLength,
                sha256 = Hash(pair.Value)
            })
            .ToArray();
        return JsonSerializer.SerializeToUtf8Bytes(
            new
            {
                schemaVersion = 1,
                version = $"1.2.{patch}",
                runtimeIdentifier =
                    UpdateReleaseContract.WindowsRuntimeIdentifier,
                minimumAutoUpdateVersion = "1.0.0",
                rollbackCompatibleFromVersion = "1.0.0",
                stateSchemaVersion = 1,
                entryPoint =
                    UpdateReleaseContract.WindowsApplicationPath,
                updaterEntryPoint =
                    UpdateReleaseContract.WindowsUpdaterPath,
                requiredLaunchers =
                    UpdateReleaseContract.RequiredLauncherPaths,
                files
            });
    }

    private sealed class StoreFixture : IDisposable
    {
        private readonly string _productRoot =
            $@"C:\ProgramData\WireguardSplitTunnel.Tests\{Guid.NewGuid():N}";

        public StoreFixture()
        {
            Paths = new ProtectedTransactionPaths(
                _productRoot,
                new NeverReparse(),
                _ => DriveType.Fixed);
            FileSystem = new FakeProtectedTransactionFileSystem();
            VersionReader =
                new FakeExecutableProductVersionReader();
            InstalledReleaseVerifier =
                new FakeInstalledReleaseVerifier();
            Store = new ProtectedTransactionStore(
                Paths,
                FileSystem,
                _ => DriveType.Fixed,
                VersionReader,
                InstalledReleaseVerifier);
            Authority = new ProtectedUpdateMutexContext(
                wasAbandoned: false);

            var transactionId = new ProtectedTransactionId(
                Guid.Parse("aabbccdd-1122-3344-5566-778899aabbcc"));
            Layout = Paths.GetLayout(transactionId).Layout!;
            FileSystem.ProtectDirectory(Layout.ProductRoot);
            FileSystem.ProtectDirectory(Layout.TransactionsRoot);
            FileSystem.ProtectDirectory(Layout.TransactionRoot);
            FileSystem.ProtectDirectory(Layout.CandidateRoot);
            FileSystem.ProtectDirectory(Layout.HelperRoot);

            var payloads = CandidatePayloadFiles(patch: 4);
            var manifestBytes = CandidateManifestBytes(
                patch: 4,
                payloads);
            FileSystem.ProtectFile(
                Path.Combine(
                    Layout.CandidateRoot,
                    UpdateReleaseContract.ReleaseManifestPath),
                manifestBytes);
            foreach (var (relativePath, bytes) in payloads)
            {
                FileSystem.ProtectFile(
                    Path.Combine(
                        Layout.CandidateRoot,
                        relativePath.Replace(
                            '/',
                            Path.DirectorySeparatorChar)),
                    bytes);
            }

            var helperBytes =
                payloads[UpdateReleaseContract.WindowsUpdaterPath];
            FileSystem.ProtectFile(
                Layout.HelperPath,
                helperBytes);
            VersionReader.SetVersion(
                Paths.ResolveCandidatePayload(
                        transactionId,
                        UpdateReleaseContract
                            .WindowsApplicationPath)
                    .Path!,
                "1.2.4");
            VersionReader.SetVersion(
                Paths.ResolveCandidatePayload(
                        transactionId,
                        UpdateReleaseContract
                            .WindowsUpdaterPath)
                    .Path!,
                "1.2.4");
            VersionReader.SetVersion(
                Layout.HelperPath,
                "1.2.4");

            Material = new ProtectedStagedTransactionMaterial(
                transactionId,
                new SemanticVersion(1, 2, 4),
                PendingUpdateSource.Automatic,
                new ProtectedInstalledReleaseIdentity(
                    @"C:\Program Files\WireguardSplitTunnel",
                    VolumeSerialNumber: 123,
                    RootFileIdLow: 456,
                    RootFileIdHigh: 789,
                    CurrentVersion:
                        new SemanticVersion(1, 2, 3),
                    MinimumAutoUpdateVersion:
                        new SemanticVersion(1, 0, 0),
                    RollbackCompatibleFromVersion:
                        new SemanticVersion(1, 0, 0),
                    StateSchemaVersion: 1,
                    ApplicationRelativePath:
                        UpdateReleaseContract.WindowsApplicationPath,
                    UpdaterRelativePath:
                        UpdateReleaseContract.WindowsUpdaterPath,
                    CurrentManifestSha256: Hash('c'),
                    ManagedFiles: InstalledManagedFiles()),
                new ProtectedCandidateIdentity(
                    Hash('a'),
                    Hash(manifestBytes),
                    manifestBytes.LongLength
                        + payloads.Values.Sum(
                            bytes => bytes.LongLength)),
                Hash(helperBytes),
                new ProtectedJournalMetadata(
                    SchemaVersion: 1,
                    Generation: 0));
            InstalledReleaseVerifier.Configure(
                Material.InstalledRelease,
                Material.InstalledRelease with
                {
                    CurrentVersion = Material.Version,
                    CurrentManifestSha256 =
                        Material.Candidate.NewManifestSha256,
                    ManagedFiles = payloads
                        .OrderBy(
                            pair => pair.Key,
                            StringComparer.Ordinal)
                        .Select(pair =>
                            new ProtectedManagedFileIdentity(
                                pair.Key,
                                pair.Value.LongLength,
                                Hash(pair.Value)))
                        .ToArray()
                });
        }

        public ProtectedTransactionPaths Paths { get; }
        public FakeProtectedTransactionFileSystem FileSystem { get; }
        public FakeExecutableProductVersionReader VersionReader { get; }
        public FakeInstalledReleaseVerifier
            InstalledReleaseVerifier
        { get; }
        public ProtectedTransactionStore Store { get; }
        public ProtectedUpdateMutexContext Authority { get; }
        public ProtectedTransactionLayout Layout { get; }
        public ProtectedStagedTransactionMaterial Material { get; }

        public ProtectedStagedTransactionMaterial AddTransaction(
            Guid guid,
            int patch)
        {
            var transactionId =
                new ProtectedTransactionId(guid);
            var layout = Paths.GetLayout(
                transactionId).Layout!;
            FileSystem.ProtectDirectory(layout.ProductRoot);
            FileSystem.ProtectDirectory(layout.TransactionsRoot);
            FileSystem.ProtectDirectory(layout.TransactionRoot);
            FileSystem.ProtectDirectory(layout.CandidateRoot);
            FileSystem.ProtectDirectory(layout.HelperRoot);

            var payloads = CandidatePayloadFiles(patch);
            var manifestBytes = CandidateManifestBytes(
                patch,
                payloads);
            FileSystem.ProtectFile(
                Path.Combine(
                    layout.CandidateRoot,
                    UpdateReleaseContract.ReleaseManifestPath),
                manifestBytes);
            foreach (var (relativePath, bytes) in payloads)
            {
                FileSystem.ProtectFile(
                    Path.Combine(
                        layout.CandidateRoot,
                        relativePath.Replace(
                            '/',
                            Path.DirectorySeparatorChar)),
                    bytes);
            }

            var helperBytes =
                payloads[UpdateReleaseContract.WindowsUpdaterPath];
            FileSystem.ProtectFile(
                layout.HelperPath,
                helperBytes);
            VersionReader.SetVersion(
                Paths.ResolveCandidatePayload(
                        transactionId,
                        UpdateReleaseContract
                            .WindowsApplicationPath)
                    .Path!,
                $"1.2.{patch}");
            VersionReader.SetVersion(
                Paths.ResolveCandidatePayload(
                        transactionId,
                        UpdateReleaseContract
                            .WindowsUpdaterPath)
                    .Path!,
                $"1.2.{patch}");
            VersionReader.SetVersion(
                layout.HelperPath,
                $"1.2.{patch}");

            return new ProtectedStagedTransactionMaterial(
                transactionId,
                new SemanticVersion(1, 2, patch),
                PendingUpdateSource.Automatic,
                new ProtectedInstalledReleaseIdentity(
                    @"C:\Program Files\WireguardSplitTunnel",
                    VolumeSerialNumber: 123,
                    RootFileIdLow: 456,
                    RootFileIdHigh: 789,
                    CurrentVersion:
                        new SemanticVersion(1, 2, 3),
                    MinimumAutoUpdateVersion:
                        new SemanticVersion(1, 0, 0),
                    RollbackCompatibleFromVersion:
                        new SemanticVersion(1, 0, 0),
                    StateSchemaVersion: 1,
                    ApplicationRelativePath:
                        UpdateReleaseContract.WindowsApplicationPath,
                    UpdaterRelativePath:
                        UpdateReleaseContract.WindowsUpdaterPath,
                    CurrentManifestSha256: Hash('c'),
                    ManagedFiles: InstalledManagedFiles()),
                new ProtectedCandidateIdentity(
                    Hash('a'),
                    Hash(manifestBytes),
                    manifestBytes.LongLength
                        + payloads.Values.Sum(
                            bytes => bytes.LongLength)),
                Hash(helperBytes),
                new ProtectedJournalMetadata(
                    SchemaVersion: 1,
                    Generation: 0));
        }

        public void Dispose()
        {
        }
    }

    private sealed class NeverReparse : IPathSafetyInspector
    {
        public bool IsReparsePoint(string path) => false;
    }

    private sealed class FakeProtectedTransactionFileSystem
        : IProtectedTransactionFileSystem
    {
        private readonly object _stateGate = new();
        private readonly HashSet<string> _directories =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, byte[]> _files =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<
            string,
            ProtectedFileIdentity128> _identities =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _unsafeFiles =
            new(StringComparer.OrdinalIgnoreCase);
        private long _nextIdentity;

        public List<string> Operations { get; } = [];
        public bool FailAtomicMove { get; set; }
        public bool FailAtomicReplace { get; set; }
        public Action<string>? BeforeAtomicReplace { get; set; }
        public Action<string>? AfterProtectedRead { get; set; }
        public Exception? SnapshotException { get; set; }
        public Exception? DirectoryException { get; set; }
        public bool SuppressAtomicCreatePublish { get; set; }
        private RacyCompareExchangeCoordinator?
            _racyCompareExchange;
        public bool HasTemporaryFiles =>
            _files.Keys.Any(path => path.EndsWith(
                ".tmp",
                StringComparison.OrdinalIgnoreCase));

        public void ProtectDirectory(string path) =>
            _directories.Add(path);

        public void UnprotectDirectory(string path) =>
            _directories.Remove(path);

        public void ProtectFile(string path, byte[] bytes)
        {
            lock (_stateGate)
            {
                _files[path] = bytes.ToArray();
                _identities[path] = NewIdentity();
            }
        }

        public byte[] GetProtectedFile(string path)
        {
            lock (_stateGate)
            {
                return _files[path].ToArray();
            }
        }

        public void RemoveFile(string path)
        {
            lock (_stateGate)
            {
                _files.Remove(path);
                _identities.Remove(path);
            }
        }

        public void MarkUnsafe(string path) =>
            _unsafeFiles.Add(path);

        public void ClearUnsafe(string path) =>
            _unsafeFiles.Remove(path);

        public void EnableRacyCompareExchange(string path) =>
            _racyCompareExchange =
                new RacyCompareExchangeCoordinator(path);

        public bool ValidateProtectedDirectory(string path)
        {
            RecordOperation($"directory:{path}");
            if (DirectoryException is not null)
            {
                throw DirectoryException;
            }

            return _directories.Contains(path);
        }

        public ProtectedTransactionFileState InspectProtectedFile(
            string path)
        {
            RecordOperation($"inspect:{path}");
            lock (_stateGate)
            {
                if (_unsafeFiles.Contains(path))
                {
                    return ProtectedTransactionFileState.Unsafe;
                }

                return _files.ContainsKey(path)
                    ? ProtectedTransactionFileState.Protected
                    : ProtectedTransactionFileState.Missing;
            }
        }

        public byte[]? ReadProtectedFile(
            string path,
            long maximumBytes)
        {
            RecordOperation($"read:{path}");
            byte[]? result;
            lock (_stateGate)
            {
                result = _files.TryGetValue(path, out var bytes)
                    && bytes.LongLength <= maximumBytes
                    ? bytes.ToArray()
                    : null;
            }

            _racyCompareExchange?.ObserveRead(path, result);
            AfterProtectedRead?.Invoke(path);
            return result;
        }

        public IProtectedFileSnapshotLease?
            OpenProtectedFileSnapshot(
                string path,
                long maximumBytes)
        {
            RecordOperation($"open-snapshot:{path}");
            byte[] bytes;
            ProtectedFileIdentity128 identity;
            lock (_stateGate)
            {
                if (_unsafeFiles.Contains(path)
                    || !_files.TryGetValue(
                        path,
                        out var currentBytes)
                    || currentBytes.LongLength > maximumBytes
                    || !_identities.TryGetValue(
                        path,
                        out identity))
                {
                    return null;
                }

                bytes = currentBytes.ToArray();
            }

            AfterProtectedRead?.Invoke(path);
            return new FakeProtectedFileSnapshotLease(
                this,
                path,
                identity,
                bytes);
        }

        public ProtectedAtomicCommitResult AtomicCreate(
            string destinationPath,
            byte[] replacementBytes)
        {
            var temporaryPath =
                $"{destinationPath}.{Guid.NewGuid():N}.tmp";
            RecordOperation($"create:{temporaryPath}");
            RecordOperation($"write:{temporaryPath}");
            _files[temporaryPath] =
                replacementBytes.ToArray();
            RecordOperation($"flush:{temporaryPath}");
            RecordOperation($"move:{destinationPath}");
            if (FailAtomicMove
                || _files.ContainsKey(destinationPath))
            {
                _files.Remove(temporaryPath);
                RecordOperation($"delete:{temporaryPath}");
                return FailAtomicMove
                    ? ProtectedAtomicCommitResult.Failed
                    : ProtectedAtomicCommitResult.Conflict;
            }

            _files.Remove(temporaryPath);
            if (!SuppressAtomicCreatePublish)
            {
                _files[destinationPath] =
                    replacementBytes.ToArray();
                _identities[destinationPath] = NewIdentity();
            }

            return ProtectedAtomicCommitResult.Committed;
        }

        public ProtectedAtomicCommitResult AtomicCompareExchange(
            string destinationPath,
            byte[] expectedDestinationBytes,
            byte[] replacementBytes) =>
            AtomicCompareExchangeCore(
                destinationPath,
                expectedIdentity: null,
                expectedDestinationBytes,
                replacementBytes);

        public ProtectedAtomicCommitResult AtomicCompareExchange(
            string destinationPath,
            ProtectedFileIdentity128 expectedIdentity,
            byte[] expectedDestinationBytes,
            byte[] replacementBytes) =>
            expectedIdentity.IsValid
                ? AtomicCompareExchangeCore(
                    destinationPath,
                    expectedIdentity,
                    expectedDestinationBytes,
                    replacementBytes)
                : ProtectedAtomicCommitResult.Conflict;

        private ProtectedAtomicCommitResult
            AtomicCompareExchangeCore(
                string destinationPath,
                ProtectedFileIdentity128? expectedIdentity,
                byte[] expectedDestinationBytes,
                byte[] replacementBytes)
        {
            var temporaryPath =
                $"{destinationPath}.{Guid.NewGuid():N}.tmp";
            RecordOperation($"create:{temporaryPath}");
            RecordOperation($"write:{temporaryPath}");
            RecordOperation($"flush:{temporaryPath}");
            RecordOperation($"replace:{destinationPath}");
            if (_racyCompareExchange is { } race
                && race.IsFor(destinationPath))
            {
                return RunRacyCompareExchange(
                    race,
                    destinationPath,
                    temporaryPath,
                    expectedIdentity,
                    expectedDestinationBytes,
                    replacementBytes);
            }

            lock (_stateGate)
            {
                _files[temporaryPath] =
                    replacementBytes.ToArray();
            }
            if (FailAtomicReplace)
            {
                lock (_stateGate)
                {
                    _files.Remove(temporaryPath);
                }
                RecordOperation($"delete:{temporaryPath}");
                return ProtectedAtomicCommitResult.Failed;
            }

            var callback = BeforeAtomicReplace;
            BeforeAtomicReplace = null;
            callback?.Invoke(destinationPath);
            lock (_stateGate)
            {
                if (!_files.TryGetValue(
                        destinationPath,
                        out var destinationBytes)
                    || !destinationBytes.AsSpan().SequenceEqual(
                        expectedDestinationBytes)
                    || expectedIdentity is { } exactIdentity
                        && (!_identities.TryGetValue(
                                destinationPath,
                                out var currentIdentity)
                            || currentIdentity != exactIdentity))
                {
                    _files.Remove(temporaryPath);
                    RecordOperation($"delete:{temporaryPath}");
                    return ProtectedAtomicCommitResult.Conflict;
                }

                _files.Remove(temporaryPath);
                _files[destinationPath] =
                    replacementBytes.ToArray();
                _identities[destinationPath] = NewIdentity();
            }
            return ProtectedAtomicCommitResult.Committed;
        }

        public bool HasProtectedProductVersion(
            string path,
            string expectedVersion,
            IExecutableProductVersionReader versionReader)
        {
            RecordOperation($"version:{path}");
            if (!_files.TryGetValue(path, out var bytes))
            {
                return false;
            }

            using var stream =
                new NamedProductVersionStream(path, bytes);
            stream.Position = Math.Min(1, stream.Length);
            var position = stream.Position;
            var actualVersion =
                versionReader.ReadProductVersion(stream);
            return stream.Position == position
                && string.Equals(
                    actualVersion,
                    expectedVersion,
                    StringComparison.Ordinal);
        }

        public string? ComputeProtectedSha256(
            string path,
            long maximumBytes)
        {
            RecordOperation($"hash:{path}");
            return _files.TryGetValue(path, out var bytes)
                && bytes.LongLength <= maximumBytes
                ? Hash(bytes)
                : null;
        }

        public IReadOnlyList<ProtectedCandidateFileSnapshot>?
            SnapshotProtectedFiles(
                string path,
                int maximumEntries,
                long maximumBytes)
        {
            RecordOperation($"snapshot:{path}");
            if (SnapshotException is not null)
            {
                throw SnapshotException;
            }

            if (!_directories.Contains(path)
                || maximumEntries < 0
                || maximumBytes < 0)
            {
                return null;
            }

            var prefix = path + Path.DirectorySeparatorChar;
            var files =
                new List<ProtectedCandidateFileSnapshot>();
            long total = 0;
            foreach (var (filePath, bytes) in _files)
            {
                if (!filePath.StartsWith(
                        prefix,
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (_unsafeFiles.Contains(filePath)
                    || files.Count >= maximumEntries)
                {
                    return null;
                }

                total = checked(total + bytes.LongLength);
                if (total > maximumBytes)
                {
                    return null;
                }

                files.Add(
                    new ProtectedCandidateFileSnapshot(
                        Path.GetRelativePath(path, filePath)
                            .Replace(
                                Path.DirectorySeparatorChar,
                                '/'),
                        bytes.LongLength,
                        Hash(bytes)));
            }

            return files
                .OrderBy(
                    file => file.RelativePath,
                    StringComparer.Ordinal)
                .ToArray();
        }

        public long? MeasureProtectedDirectory(
            string path,
            long maximumBytes)
        {
            RecordOperation($"measure:{path}");
            if (!_directories.Contains(path))
            {
                return null;
            }

            var prefix = path + Path.DirectorySeparatorChar;
            long total = 0;
            foreach (var (filePath, bytes) in _files)
            {
                if (!filePath.StartsWith(
                        prefix,
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                total = checked(total + bytes.LongLength);
                if (total > maximumBytes)
                {
                    return null;
                }
            }

            return total;
        }

        private ProtectedAtomicCommitResult
            RunRacyCompareExchange(
                RacyCompareExchangeCoordinator race,
                string destinationPath,
                string temporaryPath,
                ProtectedFileIdentity128? expectedIdentity,
                byte[] expectedDestinationBytes,
                byte[] replacementBytes)
        {
            int ordinal;
            lock (_stateGate)
            {
                if (!_files.TryGetValue(
                        destinationPath,
                        out var destinationBytes)
                    || !destinationBytes.AsSpan().SequenceEqual(
                        expectedDestinationBytes)
                    || expectedIdentity is { } exactIdentity
                        && (!_identities.TryGetValue(
                                destinationPath,
                                out var currentIdentity)
                            || currentIdentity != exactIdentity))
                {
                    _files.Remove(temporaryPath);
                    RecordOperation($"delete:{temporaryPath}");
                    return ProtectedAtomicCommitResult.Conflict;
                }

                ordinal = race.ObserveMatchingCompareExchange(
                    replacementBytes);
            }

            if (ordinal == 1)
            {
                race.WaitForSecondMatchingCompareExchange();
            }
            else
            {
                race.WaitForFirstPostVerification();
            }

            lock (_stateGate)
            {
                if (!_files.TryGetValue(
                        destinationPath,
                        out var destinationBytes)
                    || !destinationBytes.AsSpan().SequenceEqual(
                        expectedDestinationBytes)
                    || expectedIdentity is { } exactIdentity
                        && (!_identities.TryGetValue(
                                destinationPath,
                                out var currentIdentity)
                            || currentIdentity != exactIdentity))
                {
                    _files.Remove(temporaryPath);
                    RecordOperation($"delete:{temporaryPath}");
                    return ProtectedAtomicCommitResult.Conflict;
                }

                _files.Remove(temporaryPath);
                _files[destinationPath] =
                    replacementBytes.ToArray();
                _identities[destinationPath] = NewIdentity();
            }

            return ProtectedAtomicCommitResult.Committed;
        }

        private void RecordOperation(string operation)
        {
            lock (_stateGate)
            {
                Operations.Add(operation);
            }
        }

        private ProtectedFileIdentity128 NewIdentity() =>
            new(
                1,
                unchecked((ulong)Interlocked.Increment(
                    ref _nextIdentity)),
                0);

        private bool RevalidateSnapshot(
            string path,
            ProtectedFileIdentity128 identity,
            byte[] bytes)
        {
            lock (_stateGate)
            {
                return _identities.TryGetValue(
                        path,
                        out var currentIdentity)
                    && currentIdentity == identity
                    && _files.TryGetValue(
                        path,
                        out var currentBytes)
                    && currentBytes.AsSpan().SequenceEqual(bytes);
            }
        }

        private sealed class FakeProtectedFileSnapshotLease(
            FakeProtectedTransactionFileSystem owner,
            string path,
            ProtectedFileIdentity128 identity,
            byte[] bytes)
            : IProtectedFileSnapshotLease
        {
            private readonly byte[] _bytes = bytes.ToArray();

            public ProtectedFileIdentity128 Identity { get; } =
                identity;

            public byte[] Bytes => _bytes.ToArray();

            public bool Revalidate() =>
                owner.RevalidateSnapshot(
                    path,
                    Identity,
                    _bytes);

            public void Dispose()
            {
            }
        }

        private sealed class RacyCompareExchangeCoordinator(
            string path)
        {
            private readonly ManualResetEventSlim
                _secondMatchingCompareExchange = new();
            private readonly ManualResetEventSlim
                _firstPostVerification = new();
            private int _matchingCompareExchangeCount;
            private byte[]? _firstReplacement;

            public bool IsFor(string candidatePath) =>
                string.Equals(
                    path,
                    candidatePath,
                    StringComparison.OrdinalIgnoreCase);

            public int ObserveMatchingCompareExchange(
                byte[] replacementBytes)
            {
                var ordinal = checked(
                    ++_matchingCompareExchangeCount);
                if (ordinal == 1)
                {
                    _firstReplacement =
                        replacementBytes.ToArray();
                }
                else
                {
                    _secondMatchingCompareExchange.Set();
                }

                return ordinal;
            }

            public void WaitForSecondMatchingCompareExchange() =>
                _secondMatchingCompareExchange.Wait(
                    TimeSpan.FromSeconds(1));

            public void WaitForFirstPostVerification() =>
                _firstPostVerification.Wait(
                    TimeSpan.FromSeconds(2));

            public void ObserveRead(
                string candidatePath,
                byte[]? bytes)
            {
                if (IsFor(candidatePath)
                    && bytes is not null
                    && _firstReplacement is not null
                    && bytes.AsSpan().SequenceEqual(
                        _firstReplacement))
                {
                    _firstPostVerification.Set();
                }
            }
        }
    }

    private sealed class FakeExecutableProductVersionReader
        : IExecutableProductVersionReader
    {
        private readonly Dictionary<string, string?> _versions =
            new(StringComparer.OrdinalIgnoreCase);

        public Exception? ReadException { get; set; }
        public int PathCalls { get; private set; }
        public int StreamCalls { get; private set; }

        public void SetVersion(
            string path,
            string? version) =>
            _versions[path] = version;

        public string? ReadProductVersion(
            string executablePath)
        {
            PathCalls++;
            if (ReadException is not null)
            {
                throw ReadException;
            }

            return _versions.TryGetValue(
                executablePath,
                out var version)
                ? version
                : null;
        }

        public string? ReadProductVersion(
            Stream executableStream)
        {
            StreamCalls++;
            if (ReadException is not null)
            {
                throw ReadException;
            }

            return executableStream
                    is NamedProductVersionStream named
                && _versions.TryGetValue(
                    named.Path,
                    out var version)
                    ? version
                    : null;
        }
    }

    private sealed class NamedProductVersionStream(
        string path,
        byte[] bytes)
        : MemoryStream(bytes, writable: false)
    {
        public string Path { get; } = path;
    }

    private sealed class
        PositionChangingStreamOnlyProductVersionReader(
            string version)
        : IExecutableProductVersionReader
    {
        public int PathCalls { get; private set; }
        public int StreamCalls { get; private set; }
        public long? ObservedPosition { get; private set; }

        public string? ReadProductVersion(
            string executablePath)
        {
            PathCalls++;
            throw new InvalidOperationException(
                "The path overload must not be used.");
        }

        public string? ReadProductVersion(
            Stream executableStream)
        {
            StreamCalls++;
            ObservedPosition = executableStream.Position;
            executableStream.Position =
                executableStream.Length;
            return version;
        }
    }

    private sealed class FakeInstalledReleaseVerifier
        : IProtectedInstalledReleaseVerifier
    {
        private readonly Dictionary<
            string,
            ProtectedManagedFileIdentity> _installedFiles =
            new(StringComparer.Ordinal);
        private readonly Dictionary<string, byte[]>
            _unmanagedFiles =
                new(StringComparer.Ordinal);
        private ProtectedInstalledReleaseIdentity? _oldRelease;
        private ProtectedInstalledReleaseIdentity? _newRelease;
        private SemanticVersion _currentVersion;
        private string? _currentManifestSha256;
        private string? _applicationProductVersion;
        private string? _updaterProductVersion;

        public bool FullOldResult { get; set; } = true;
        public bool NamespaceResult { get; set; } = true;
        public bool FullNewResult { get; set; } = true;
        public bool RootPolicyValid { get; set; } = true;
        public bool Result
        {
            get => FullOldResult
                && NamespaceResult
                && FullNewResult;
            set
            {
                FullOldResult = value;
                NamespaceResult = value;
                FullNewResult = value;
            }
        }
        public Exception? VerificationException { get; set; }
        public int CallCount { get; private set; }
        public ProtectedInstalledReleaseIdentity? LastExpected
        {
            get;
            private set;
        }
        public ProtectedInstalledReleaseVerification LastVerification
        {
            get;
            private set;
        }
        public bool MatchesOldSnapshot =>
            _oldRelease is not null
            && MatchesRelease(_oldRelease);
        public int UnmanagedContentReadCount { get; private set; }

        public void Configure(
            ProtectedInstalledReleaseIdentity oldRelease,
            ProtectedInstalledReleaseIdentity newRelease)
        {
            _oldRelease = oldRelease;
            _newRelease = newRelease;
            _installedFiles.Clear();
            foreach (var file in oldRelease.ManagedFiles)
            {
                _installedFiles.Add(file.RelativePath, file);
            }

            _currentVersion = oldRelease.CurrentVersion;
            _currentManifestSha256 =
                oldRelease.CurrentManifestSha256;
            _applicationProductVersion =
                oldRelease.CurrentVersion.ToString();
            _updaterProductVersion =
                oldRelease.CurrentVersion.ToString();
        }

        public void MutateManagedFileToNew(string relativePath)
        {
            if (_newRelease is null)
            {
                throw new InvalidOperationException();
            }

            var replacement = _newRelease.ManagedFiles
                .Single(file => string.Equals(
                    file.RelativePath,
                    relativePath,
                    StringComparison.Ordinal));
            _installedFiles[relativePath] = replacement;
        }

        public void MutateManagedFileToOld(string relativePath)
        {
            if (_oldRelease is null)
            {
                throw new InvalidOperationException();
            }

            var replacement = _oldRelease.ManagedFiles
                .Single(file => string.Equals(
                    file.RelativePath,
                    relativePath,
                    StringComparison.Ordinal));
            _installedFiles[relativePath] = replacement;
        }

        public void SetFullyNew()
        {
            if (_newRelease is null)
            {
                throw new InvalidOperationException();
            }

            _installedFiles.Clear();
            foreach (var file in _newRelease.ManagedFiles)
            {
                _installedFiles.Add(file.RelativePath, file);
            }

            _currentVersion = _newRelease.CurrentVersion;
            _currentManifestSha256 =
                _newRelease.CurrentManifestSha256;
            _applicationProductVersion =
                _newRelease.CurrentVersion.ToString();
            _updaterProductVersion =
                _newRelease.CurrentVersion.ToString();
        }

        public void AddManifestDeclaredManagedExtra()
        {
            _installedFiles["unexpected.dll"] =
                new ProtectedManagedFileIdentity(
                    "unexpected.dll",
                    Length: 1,
                    Hash('e'));
            _currentManifestSha256 = Hash('e');
        }

        public void AddSafeUnmanagedFile(
            string relativePath,
            byte[] bytes) =>
            _unmanagedFiles.Add(
                relativePath,
                bytes.ToArray());

        public void RemoveManagedFile(string relativePath) =>
            _installedFiles.Remove(relativePath);

        public void SetApplicationProductVersion(
            string version) =>
            _applicationProductVersion = version;

        public bool Verify(
            ProtectedInstalledReleaseIdentity oldRelease,
            ProtectedInstalledReleaseIdentity newRelease,
            ProtectedInstalledReleaseVerification verification)
        {
            CallCount++;
            LastExpected = verification
                == ProtectedInstalledReleaseVerification.FullNew
                    ? newRelease
                    : oldRelease;
            LastVerification = verification;
            if (VerificationException is not null)
            {
                throw VerificationException;
            }

            return verification switch
            {
                ProtectedInstalledReleaseVerification.FullOld =>
                    FullOldResult
                    && MatchesRelease(oldRelease),
                ProtectedInstalledReleaseVerification.NamespaceOnly =>
                    NamespaceResult
                    && MatchesNamespace(oldRelease, newRelease),
                ProtectedInstalledReleaseVerification.FullNew =>
                    FullNewResult
                    && MatchesRelease(newRelease),
                _ => false
            };
        }

        private bool MatchesNamespace(
            ProtectedInstalledReleaseIdentity oldRelease,
            ProtectedInstalledReleaseIdentity newRelease)
            => RootPolicyValid;

        private bool MatchesRelease(
            ProtectedInstalledReleaseIdentity expected)
        {
            if (!RootPolicyValid
                || _currentVersion != expected.CurrentVersion
                || !string.Equals(
                    _currentManifestSha256,
                    expected.CurrentManifestSha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    _applicationProductVersion,
                    expected.CurrentVersion.ToString(),
                    StringComparison.Ordinal)
                || !string.Equals(
                    _updaterProductVersion,
                    expected.CurrentVersion.ToString(),
                    StringComparison.Ordinal)
                )
            {
                return false;
            }

            foreach (var expectedFile in expected.ManagedFiles)
            {
                if (!_installedFiles.TryGetValue(
                        expectedFile.RelativePath,
                        out var actual)
                    || actual.Length != expectedFile.Length
                    || !string.Equals(
                        actual.Sha256,
                        expectedFile.Sha256,
                        StringComparison.Ordinal))
                {
                    return false;
                }
            }

            return true;
        }
    }

    private sealed class ImmediateMutexFactory
        : IProtectedUpdateMutexFactory
    {
        public ProtectedMutexOpenResult Open(
            string name,
            MutexSecurity security) =>
            ProtectedMutexOpenResult.Opened(
                new ImmediateMutexHandle(security));
    }

    private sealed class ImmediateMutexHandle(
        MutexSecurity security)
        : IProtectedUpdateMutexHandle
    {
        public MutexSecurity ReadSecurity() => security;

        public ProtectedMutexWaitOutcome Wait(
            TimeSpan timeout,
            CancellationToken cancellationToken) =>
            ProtectedMutexWaitOutcome.Acquired;

        public void Release()
        {
        }

        public void Dispose()
        {
        }
    }
}
