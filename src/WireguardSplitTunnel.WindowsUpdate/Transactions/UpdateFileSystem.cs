using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate.Transactions;

internal enum UpdateFileLocation
{
    Target,
    Backup,
    Temporary
}

internal enum UpdateFileObservation
{
    Missing,
    ExactOld,
    ExactNew,
    Unknown
}

internal enum UpdateFileSystemError
{
    None,
    InvalidInput,
    UnsafeRoot,
    UnsafePath,
    MissingParent,
    UnexpectedTarget,
    UnexpectedBackup,
    UnexpectedTemporary,
    BackupCollision,
    TemporaryCollision,
    CrossVolume,
    FileFlushFailed,
    DirectoryFlushFailed,
    RecoveryBlocked,
    IoFailure
}

internal enum UpdateFileSystemFaultPoint
{
    TargetReleasedBeforeRename
}

internal readonly record struct UpdateFileIdentity128(
    ulong VolumeSerialNumber,
    ulong FileIdLow,
    ulong FileIdHigh)
{
    public bool IsValid =>
        VolumeSerialNumber != 0
        && (FileIdLow != 0 || FileIdHigh != 0);

    internal ProtectedFileIdentity128 ToProtected() =>
        new(
            VolumeSerialNumber,
            FileIdLow,
            FileIdHigh);
}

internal readonly record struct UpdateFileContentIdentity(
    long Length,
    string Sha256);

internal sealed record UpdateFileOperationInput(
    string TargetRelativePath,
    bool TargetExisted,
    UpdateFileContentIdentity? OldContent,
    UpdateFileContentIdentity NewContent,
    string BackupRelativePath,
    string TemporaryRelativePath);

internal sealed record UpdateFileSystemSessionRequest(
    string InstalledRoot,
    UpdateFileIdentity128 InstalledRootIdentity,
    string BackupRoot,
    UpdateFileIdentity128 BackupRootIdentity);

internal readonly record struct UpdateFileObservationResult(
    UpdateFileObservation Observation,
    UpdateFileSystemError Error)
{
    public static UpdateFileObservationResult Observed(
        UpdateFileObservation observation) =>
        new(observation, UpdateFileSystemError.None);

    public static UpdateFileObservationResult Failed(
        UpdateFileSystemError error) =>
        new(UpdateFileObservation.Unknown, error);
}

internal readonly record struct UpdateFileSystemResult(
    bool Success,
    UpdateFileSystemError Error,
    bool NamespaceChanged)
{
    public static UpdateFileSystemResult Committed(
        bool namespaceChanged = true) =>
        new(
            true,
            UpdateFileSystemError.None,
            namespaceChanged);

    public static UpdateFileSystemResult Failed(
        UpdateFileSystemError error,
        bool namespaceChanged = false) =>
        new(false, error, namespaceChanged);
}

internal readonly record struct UpdateFileSystemSessionOpenResult(
    UpdateFileSystemSession? Session,
    UpdateFileSystemError Error) : IDisposable
{
    public bool Success => Session is not null;

    public static UpdateFileSystemSessionOpenResult Opened(
        UpdateFileSystemSession session) =>
        new(session, UpdateFileSystemError.None);

    public static UpdateFileSystemSessionOpenResult Failed(
        UpdateFileSystemError error) =>
        new(null, error);

    public void Dispose() => Session?.Dispose();
}

internal sealed class UpdateFileSystemSecurityPolicy
{
    private static readonly SecurityIdentifier Administrators =
        new(
            WellKnownSidType.BuiltinAdministratorsSid,
            null);
    private static readonly SecurityIdentifier LocalSystem =
        new(
            WellKnownSidType.LocalSystemSid,
            null);
    private static readonly SecurityIdentifier BuiltinUsers =
        new(
            WellKnownSidType.BuiltinUsersSid,
            null);
    private readonly Func<byte[], bool> _installedRoot;
    private readonly Func<byte[], bool, bool> _installedDescendant;
    private readonly Func<byte[], bool> _backupRoot;
    private readonly Func<byte[], bool, bool> _backupDescendant;
    private readonly byte[] _installedFileDescriptor;
    private readonly byte[] _backupFileDescriptor;

    public static UpdateFileSystemSecurityPolicy Windows
        { get; } =
        new(
            ProtectedDirectoryAcl
                .HasExactInstalledRootDescriptor,
            ProtectedDirectoryAcl
                .HasExactInstalledDescendantDescriptor,
            descriptor =>
                ProtectedDirectoryAcl
                    .HasExactProtectedDescriptor(
                        descriptor,
                        directory: true),
            ProtectedDirectoryAcl
                .HasExactProtectedDescriptor,
            BuildInstalledFileDescriptor(),
            ProtectedDirectoryAcl.BuildFileSecurity()
                .GetSecurityDescriptorBinaryForm());

    public UpdateFileSystemSecurityPolicy(
        Func<byte[], bool> installedRoot,
        Func<byte[], bool, bool> installedDescendant,
        Func<byte[], bool> backupRoot,
        Func<byte[], bool, bool> backupDescendant,
        byte[] installedFileDescriptor,
        byte[] backupFileDescriptor)
    {
        _installedRoot = installedRoot
            ?? throw new ArgumentNullException(
                nameof(installedRoot));
        _installedDescendant = installedDescendant
            ?? throw new ArgumentNullException(
                nameof(installedDescendant));
        _backupRoot = backupRoot
            ?? throw new ArgumentNullException(
                nameof(backupRoot));
        _backupDescendant = backupDescendant
            ?? throw new ArgumentNullException(
                nameof(backupDescendant));
        _installedFileDescriptor =
            (installedFileDescriptor
                ?? throw new ArgumentNullException(
                    nameof(installedFileDescriptor)))
            .ToArray();
        _backupFileDescriptor =
            (backupFileDescriptor
                ?? throw new ArgumentNullException(
                    nameof(backupFileDescriptor)))
            .ToArray();
    }

    public byte[] InstalledFileDescriptor =>
        _installedFileDescriptor.ToArray();

    public byte[] BackupFileDescriptor =>
        _backupFileDescriptor.ToArray();

    public bool IsInstalledRoot(byte[] descriptor) =>
        descriptor is { Length: > 0 }
        && _installedRoot(descriptor);

    public bool IsInstalledDescendant(
        byte[] descriptor,
        bool directory) =>
        descriptor is { Length: > 0 }
        && _installedDescendant(
            descriptor,
            directory);

    public bool IsBackupRoot(byte[] descriptor) =>
        descriptor is { Length: > 0 }
        && _backupRoot(descriptor);

    public bool IsBackupDescendant(
        byte[] descriptor,
        bool directory) =>
        descriptor is { Length: > 0 }
        && _backupDescendant(
            descriptor,
            directory);

    private static byte[] BuildInstalledFileDescriptor()
    {
        var acl = new RawAcl(
            GenericAcl.AclRevision,
            capacity: 3);
        acl.InsertAce(
            0,
            AllowInherited(
                Administrators,
                FileSystemRights.FullControl));
        acl.InsertAce(
            1,
            AllowInherited(
                LocalSystem,
                FileSystemRights.FullControl));
        acl.InsertAce(
            2,
            AllowInherited(
                BuiltinUsers,
                FileSystemRights.ReadAndExecute
                    | FileSystemRights.Synchronize));
        var descriptor = new RawSecurityDescriptor(
            ControlFlags.DiscretionaryAclPresent
                | ControlFlags.DiscretionaryAclAutoInherited
                | ControlFlags.SelfRelative,
            LocalSystem,
            group: null,
            systemAcl: null,
            discretionaryAcl: acl);
        var bytes = new byte[
            descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, offset: 0);
        return bytes;
    }

    private static CommonAce AllowInherited(
        SecurityIdentifier identity,
        FileSystemRights rights) =>
        new(
            AceFlags.Inherited,
            AceQualifier.AccessAllowed,
            (int)rights,
            identity,
            isCallback: false,
            opaque: null);
}

internal sealed class UpdateFileSystem
{
    private readonly IProtectedAclNativeFileSystem _native;
    private readonly UpdateFileSystemSecurityPolicy _security;
    private readonly Func<string, DriveType> _getDriveType;
    private readonly Action<UpdateFileSystemFaultPoint>? _fault;

    internal UpdateFileSystem()
        : this(
            new WindowsProtectedAclNativeFileSystem(),
            UpdateFileSystemSecurityPolicy.Windows,
            root => new DriveInfo(root).DriveType,
            fault: null)
    {
    }

    internal UpdateFileSystem(
        IProtectedAclNativeFileSystem native,
        UpdateFileSystemSecurityPolicy security,
        Func<string, DriveType> getDriveType,
        Action<UpdateFileSystemFaultPoint>? fault = null)
    {
        _native = native
            ?? throw new ArgumentNullException(nameof(native));
        _security = security
            ?? throw new ArgumentNullException(nameof(security));
        _getDriveType = getDriveType
            ?? throw new ArgumentNullException(
                nameof(getDriveType));
        _fault = fault;
    }

    public UpdateFileSystemSessionOpenResult OpenSession(
        UpdateFileSystemSessionRequest? request)
    {
        if (request is null
            || !request.InstalledRootIdentity.IsValid
            || !request.BackupRootIdentity.IsValid
            || !TryCanonicalRoot(
                request.InstalledRoot,
                out var installedPath)
            || !TryCanonicalRoot(
                request.BackupRoot,
                out var backupPath)
            || string.Equals(
                installedPath,
                backupPath,
                StringComparison.OrdinalIgnoreCase))
        {
            return UpdateFileSystemSessionOpenResult.Failed(
                UpdateFileSystemError.InvalidInput);
        }

        var installed = TryOpenRoot(
            installedPath,
            request.InstalledRootIdentity.ToProtected(),
            _security.IsInstalledRoot,
            _security.IsInstalledDescendant);
        if (installed is null)
        {
            return UpdateFileSystemSessionOpenResult.Failed(
                UpdateFileSystemError.UnsafeRoot);
        }

        var backup = TryOpenRoot(
            backupPath,
            request.BackupRootIdentity.ToProtected(),
            _security.IsBackupRoot,
            _security.IsBackupDescendant);
        if (backup is null)
        {
            installed.Dispose();
            return UpdateFileSystemSessionOpenResult.Failed(
                UpdateFileSystemError.UnsafeRoot);
        }

        return UpdateFileSystemSessionOpenResult.Opened(
            new UpdateFileSystemSession(
                _native,
                _security,
                installed,
                backup,
                _fault));
    }

    private PinnedUpdateRoot? TryOpenRoot(
        string canonicalPath,
        ProtectedFileIdentity128 expectedIdentity,
        Func<byte[], bool> descriptorValidator,
        Func<byte[], bool, bool>
            descendantDescriptorValidator)
    {
        var opened = _native.OpenRoot(
            canonicalPath,
            openReparsePoint: true,
            shareDelete: false,
            requireWriteAccess: true);
        if (!opened.Success || opened.Handle is null)
        {
            return null;
        }

        var root = new PinnedUpdateRoot(
            opened.Handle,
            canonicalPath,
            expectedIdentity,
            descriptorValidator,
            descendantDescriptorValidator);
        if (root.Revalidate())
        {
            return root;
        }

        root.Dispose();
        return null;
    }

    private bool TryCanonicalRoot(
        string? path,
        out string canonical)
    {
        canonical = string.Empty;
        if (!WindowsLocalPath.TryGetCanonicalLocalDosPath(
                path,
                _getDriveType,
                out var result)
            || result is null)
        {
            return false;
        }

        canonical = result;
        return true;
    }
}

internal sealed class UpdateFileSystemSession : IDisposable
{
    private readonly object _gate = new();
    private readonly IProtectedAclNativeFileSystem _native;
    private readonly UpdateFileSystemSecurityPolicy _security;
    private readonly Action<UpdateFileSystemFaultPoint>? _fault;
    private PinnedUpdateRoot? _installed;
    private PinnedUpdateRoot? _backup;

    internal UpdateFileSystemSession(
        IProtectedAclNativeFileSystem native,
        UpdateFileSystemSecurityPolicy security,
        PinnedUpdateRoot installed,
        PinnedUpdateRoot backup,
        Action<UpdateFileSystemFaultPoint>? fault)
    {
        _native = native;
        _security = security;
        _installed = installed;
        _backup = backup;
        _fault = fault;
    }

    public UpdateFileObservationResult Observe(
        UpdateFileOperationInput? operation,
        UpdateFileLocation location)
    {
        lock (_gate)
        {
            if (_installed is null
                || _backup is null
                || !_installed.Revalidate()
                || !_backup.Revalidate())
            {
                return UpdateFileObservationResult.Failed(
                    UpdateFileSystemError.UnsafeRoot);
            }

            if (!UpdateFileOperationValidation.IsValid(
                    operation))
            {
                return UpdateFileObservationResult.Failed(
                    UpdateFileSystemError.InvalidInput);
            }

            return location switch
            {
                UpdateFileLocation.Target =>
                    ObserveRelative(
                        _installed,
                        operation!.TargetRelativePath,
                        _security.IsInstalledDescendant,
                        operation),
                UpdateFileLocation.Backup =>
                    ObserveRelative(
                        _backup,
                        operation!.BackupRelativePath,
                        _security.IsBackupDescendant,
                        operation),
                UpdateFileLocation.Temporary =>
                    ObserveRelative(
                        _installed,
                        operation!.TemporaryRelativePath,
                        _security.IsInstalledDescendant,
                        operation),
                _ => UpdateFileObservationResult.Failed(
                    UpdateFileSystemError.InvalidInput)
            };
        }
    }

    public UpdateFileSystemResult CreateBackup(
        UpdateFileOperationInput? operation)
    {
        lock (_gate)
        {
            if (!TryGetLiveRoots(
                    out var installed,
                    out var backup))
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.UnsafeRoot);
            }

            if (!UpdateFileOperationValidation.IsValid(
                    operation)
                || !operation!.TargetExisted
                || operation.OldContent is null)
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.InvalidInput);
            }

            var observation = Observe(
                operation,
                UpdateFileLocation.Target);
            if (observation.Error
                    != UpdateFileSystemError.None
                || observation.Observation
                    != UpdateFileObservation.ExactOld)
            {
                return UpdateFileSystemResult.Failed(
                    observation.Error
                        == UpdateFileSystemError.None
                            ? UpdateFileSystemError
                                .UnexpectedTarget
                            : observation.Error);
            }

            using var sourceParent =
                PinnedUpdateParent.TryOpen(
                    _native,
                    installed,
                    operation.TargetRelativePath,
                    _security.IsInstalledDescendant,
                    requireWriteAccess: false,
                    out var sourceLeaf,
                    out var sourceParentError);
            if (sourceParent is null)
            {
                return UpdateFileSystemResult.Failed(
                    sourceParentError);
            }

            var sourceOpen = _native.OpenRelative(
                sourceParent.Handle,
                sourceLeaf,
                ExistingFileRequest(
                    requireDeleteAccess: false));
            if (!sourceOpen.Success
                || sourceOpen.Handle is null)
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.UnexpectedTarget);
            }

            using var source = sourceOpen.Handle;
            if (!TryReadFileSnapshot(
                    source,
                    sourceParent.LeafPath(sourceLeaf),
                    installed.Identity.VolumeSerialNumber,
                    _security.IsInstalledDescendant,
                    expectedIdentity: null,
                    out var sourceSnapshot)
                || !MatchesContent(
                    source,
                    operation.OldContent.Value)
                || !sourceParent.Revalidate())
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.UnexpectedTarget);
            }

            var result = CreateVerifiedRelativeFile(
                backup,
                operation.BackupRelativePath,
                _security.IsBackupDescendant,
                _security.BackupFileDescriptor,
                operation.OldContent.Value,
                UpdateFileSystemError.BackupCollision,
                destination =>
                    CopyRetainedFile(
                        source,
                        destination));
            if (!VerifyRetainedFileAndNamespace(
                    sourceParent,
                    sourceLeaf,
                    source,
                    sourceSnapshot.Identity,
                    _security.IsInstalledDescendant,
                    operation.OldContent.Value))
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.UnsafePath,
                    result.NamespaceChanged);
            }

            return result;
        }
    }

    public UpdateFileSystemResult StageReplacement(
        UpdateFileOperationInput? operation,
        Stream? source)
    {
        lock (_gate)
        {
            if (!TryGetLiveRoots(
                    out var installed,
                    out _))
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.UnsafeRoot);
            }

            if (!UpdateFileOperationValidation.IsValid(
                    operation)
                || source is null
                || !TryCaptureSource(
                    source,
                    operation!.NewContent,
                    out var originalPosition))
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.InvalidInput);
            }

            var before = Observe(
                operation,
                UpdateFileLocation.Target);
            var expectedBefore = operation.TargetExisted
                ? UpdateFileObservation.ExactOld
                : UpdateFileObservation.Missing;
            if (before.Error != UpdateFileSystemError.None
                || before.Observation != expectedBefore)
            {
                return UpdateFileSystemResult.Failed(
                    before.Error == UpdateFileSystemError.None
                        ? UpdateFileSystemError.UnexpectedTarget
                        : before.Error);
            }

            var sourcePositionRestored = true;
            var result = CreateVerifiedRelativeFile(
                installed,
                operation.TemporaryRelativePath,
                _security.IsInstalledDescendant,
                _security.InstalledFileDescriptor,
                operation.NewContent,
                UpdateFileSystemError.TemporaryCollision,
                destination =>
                {
                    try
                    {
                        source.Position = 0;
                        destination.SetLength(0);
                        source.CopyTo(destination);
                        return source.Position
                                == operation.NewContent.Length
                            && source.Length
                                == operation.NewContent.Length
                                ? UpdateFileSystemError.None
                                : UpdateFileSystemError.IoFailure;
                    }
                    catch (Exception exception) when (
                        IsOrdinaryFileFailure(exception))
                    {
                        return UpdateFileSystemError.IoFailure;
                    }
                    finally
                    {
                        sourcePositionRestored =
                            TryRestorePosition(
                                source,
                                originalPosition);
                    }
                });
            if (!sourcePositionRestored)
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.IoFailure,
                    result.NamespaceChanged);
            }

            var after = Observe(
                operation,
                UpdateFileLocation.Target);
            if (after.Error != UpdateFileSystemError.None
                || after.Observation != expectedBefore)
            {
                return UpdateFileSystemResult.Failed(
                    after.Error == UpdateFileSystemError.None
                        ? UpdateFileSystemError.UnexpectedTarget
                        : after.Error,
                    result.NamespaceChanged);
            }

            return result;
        }
    }

    public UpdateFileSystemResult Apply(
        UpdateFileOperationInput? operation)
    {
        lock (_gate)
        {
            if (!TryGetLiveRoots(out _, out _))
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.UnsafeRoot);
            }

            if (!UpdateFileOperationValidation.IsValid(
                    operation))
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.InvalidInput);
            }

            var target = Observe(
                operation,
                UpdateFileLocation.Target);
            if (target.Error != UpdateFileSystemError.None)
            {
                return UpdateFileSystemResult.Failed(
                    target.Error);
            }

            if (target.Observation
                == UpdateFileObservation.ExactNew)
            {
                var completedTemp = Observe(
                    operation,
                    UpdateFileLocation.Temporary);
                if (completedTemp.Error
                        != UpdateFileSystemError.None
                    || completedTemp.Observation
                        != UpdateFileObservation.Missing)
                {
                    return UpdateFileSystemResult.Failed(
                        UpdateFileSystemError
                            .UnexpectedTemporary);
                }

                if (operation!.TargetExisted)
                {
                    var completedBackup = Observe(
                        operation,
                        UpdateFileLocation.Backup);
                    if (completedBackup.Error
                            != UpdateFileSystemError.None
                        || completedBackup.Observation
                            != UpdateFileObservation.ExactOld)
                    {
                        return UpdateFileSystemResult.Failed(
                            UpdateFileSystemError
                                .UnexpectedBackup);
                    }
                }

                return FlushInstalledParent(
                    operation.TargetRelativePath);
            }

            var expectedTarget = operation!.TargetExisted
                ? UpdateFileObservation.ExactOld
                : UpdateFileObservation.Missing;
            if (target.Observation != expectedTarget)
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.UnexpectedTarget);
            }

            if (operation.TargetExisted)
            {
                var backup = Observe(
                    operation,
                    UpdateFileLocation.Backup);
                if (backup.Error
                        != UpdateFileSystemError.None
                    || backup.Observation
                        != UpdateFileObservation.ExactOld)
                {
                    return UpdateFileSystemResult.Failed(
                        UpdateFileSystemError
                            .UnexpectedBackup);
                }
            }

            var temporary = Observe(
                operation,
                UpdateFileLocation.Temporary);
            if (temporary.Error
                    != UpdateFileSystemError.None
                || temporary.Observation
                    != UpdateFileObservation.ExactNew)
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError
                        .UnexpectedTemporary);
            }

            return CommitTemporary(
                operation,
                expectedTarget,
                operation.NewContent);
        }
    }

    public UpdateFileSystemResult Rollback(
        UpdateFileOperationInput? operation)
    {
        lock (_gate)
        {
            if (!TryGetLiveRoots(out _, out _))
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.UnsafeRoot);
            }

            if (!UpdateFileOperationValidation.IsValid(
                    operation))
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.InvalidInput);
            }

            var target = Observe(
                operation,
                UpdateFileLocation.Target);
            if (target.Error != UpdateFileSystemError.None)
            {
                return UpdateFileSystemResult.Failed(
                    target.Error);
            }

            if (!operation!.TargetExisted)
            {
                return target.Observation switch
                {
                    UpdateFileObservation.Missing =>
                        CompleteRollbackWithoutTargetMutation(
                            operation),
                    UpdateFileObservation.ExactNew =>
                        DeleteExactCreatedTarget(operation),
                    _ => UpdateFileSystemResult.Failed(
                        UpdateFileSystemError.UnexpectedTarget)
                };
            }

            if (target.Observation
                == UpdateFileObservation.ExactOld)
            {
                return CompleteRollbackWithoutTargetMutation(
                    operation);
            }

            if (target.Observation
                != UpdateFileObservation.ExactNew)
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.UnexpectedTarget);
            }

            var backup = Observe(
                operation,
                UpdateFileLocation.Backup);
            if (backup.Error != UpdateFileSystemError.None
                || backup.Observation
                    != UpdateFileObservation.ExactOld)
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.UnexpectedBackup);
            }

            var temporary = Observe(
                operation,
                UpdateFileLocation.Temporary);
            var stagedDuringRollback = false;
            if (temporary.Error != UpdateFileSystemError.None)
            {
                return UpdateFileSystemResult.Failed(
                    temporary.Error);
            }

            if (temporary.Observation
                == UpdateFileObservation.Missing)
            {
                var staged = StageBackupForRollback(
                    operation);
                if (!staged.Success)
                {
                    return staged;
                }

                stagedDuringRollback =
                    staged.NamespaceChanged;
            }
            else if (temporary.Observation
                != UpdateFileObservation.ExactOld)
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError
                        .UnexpectedTemporary);
            }

            var committed = CommitTemporary(
                operation,
                UpdateFileObservation.ExactNew,
                operation.OldContent!.Value);
            return committed with
            {
                NamespaceChanged =
                    committed.NamespaceChanged
                    || stagedDuringRollback
            };
        }
    }

    private UpdateFileSystemResult
        CompleteRollbackWithoutTargetMutation(
            UpdateFileOperationInput operation)
    {
        var temporary = Observe(
            operation,
            UpdateFileLocation.Temporary);
        if (temporary.Error != UpdateFileSystemError.None)
        {
            return UpdateFileSystemResult.Failed(
                temporary.Error);
        }

        return temporary.Observation switch
        {
            UpdateFileObservation.Missing =>
                FlushInstalledParent(
                    operation.TargetRelativePath),
            UpdateFileObservation.ExactNew =>
                DeleteExactInstalledFile(
                    operation,
                    UpdateFileLocation.Temporary,
                    operation.TemporaryRelativePath,
                    operation.NewContent,
                    UpdateFileSystemError
                        .UnexpectedTemporary),
            _ => UpdateFileSystemResult.Failed(
                UpdateFileSystemError
                    .UnexpectedTemporary)
        };
    }

    private UpdateFileSystemResult CommitTemporary(
        UpdateFileOperationInput operation,
        UpdateFileObservation expectedTarget,
        UpdateFileContentIdentity temporaryContent)
    {
        if (!TryGetLiveRoots(
                out var installed,
                out _))
        {
            return UpdateFileSystemResult.Failed(
                UpdateFileSystemError.UnsafeRoot);
        }

        using var parent = PinnedUpdateParent.TryOpen(
            _native,
            installed,
            operation.TargetRelativePath,
            _security.IsInstalledDescendant,
            requireWriteAccess: true,
            out var targetLeaf,
            out var parentError);
        if (parent is null)
        {
            return UpdateFileSystemResult.Failed(parentError);
        }

        var temporaryLeaf =
            operation.TemporaryRelativePath.Split('/')[^1];
        IProtectedAclNativeHandle? target = null;
        ProtectedFileIdentity128? targetIdentity = null;
        try
        {
            if (expectedTarget
                == UpdateFileObservation.Missing)
            {
                var missing = _native.OpenRelative(
                    parent.Handle,
                    targetLeaf,
                    ExistingFileRequest(
                        requireDeleteAccess: false));
                if (missing.Success
                    && missing.Handle is not null)
                {
                    missing.Handle.Dispose();
                    return UpdateFileSystemResult.Failed(
                        UpdateFileSystemError.UnexpectedTarget);
                }

                if (missing.Error != ProtectedAclError.Missing
                    || !parent.Revalidate())
                {
                    return UpdateFileSystemResult.Failed(
                        UpdateFileSystemError.UnsafePath);
                }
            }
            else
            {
                var targetOpen = _native.OpenRelative(
                    parent.Handle,
                    targetLeaf,
                    ExistingFileRequest(
                        requireDeleteAccess: true));
                if (!targetOpen.Success
                    || targetOpen.Handle is null)
                {
                    return UpdateFileSystemResult.Failed(
                        UpdateFileSystemError.UnexpectedTarget);
                }

                target = targetOpen.Handle;
                var expectedContent =
                    expectedTarget
                        == UpdateFileObservation.ExactOld
                        ? operation.OldContent!.Value
                        : operation.NewContent;
                if (!TryReadFileSnapshot(
                        target,
                        parent.LeafPath(targetLeaf),
                        installed.Identity.VolumeSerialNumber,
                        _security.IsInstalledDescendant,
                        expectedIdentity: null,
                        out var snapshot)
                    || !MatchesContent(
                        target,
                        expectedContent)
                    || !VerifyRetainedFileAndNamespace(
                        parent,
                        targetLeaf,
                        target,
                        snapshot.Identity,
                        _security.IsInstalledDescendant,
                        expectedContent))
                {
                    return UpdateFileSystemResult.Failed(
                        UpdateFileSystemError.UnexpectedTarget);
                }

                targetIdentity = snapshot.Identity;
            }

            var tempOpen = _native.OpenRelative(
                parent.Handle,
                temporaryLeaf,
                ExistingFileRequest(
                    requireDeleteAccess: true));
            if (!tempOpen.Success
                || tempOpen.Handle is null)
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError
                        .UnexpectedTemporary);
            }

            using var temporary = tempOpen.Handle;
            if (!TryReadFileSnapshot(
                    temporary,
                    parent.LeafPath(temporaryLeaf),
                    installed.Identity.VolumeSerialNumber,
                    _security.IsInstalledDescendant,
                    expectedIdentity: null,
                    out var temporarySnapshot)
                || !MatchesContent(
                    temporary,
                    temporaryContent)
                || !VerifyRetainedFileAndNamespace(
                    parent,
                    temporaryLeaf,
                    temporary,
                    temporarySnapshot.Identity,
                    _security.IsInstalledDescendant,
                    temporaryContent)
                || !parent.Revalidate())
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError
                        .UnexpectedTemporary);
            }

            if (target is not null)
            {
                var expectedContent =
                    expectedTarget
                        == UpdateFileObservation.ExactOld
                        ? operation.OldContent!.Value
                        : operation.NewContent;
                if (!VerifyRetainedFileAndNamespace(
                        parent,
                        targetLeaf,
                        target,
                        targetIdentity!.Value,
                        _security.IsInstalledDescendant,
                        expectedContent))
                {
                    return UpdateFileSystemResult.Failed(
                        UpdateFileSystemError.UnexpectedTarget);
                }

                target.Dispose();
                target = null;
            }

            _fault?.Invoke(
                UpdateFileSystemFaultPoint
                    .TargetReleasedBeforeRename);
            if (!RevalidateReleasedTarget(
                    parent,
                    installed,
                    targetLeaf,
                    expectedTarget,
                    targetIdentity,
                    operation))
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.RecoveryBlocked);
            }

            if (!parent.Revalidate())
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.UnsafePath);
            }

            var renamed = _native.RenameRelative(
                temporary,
                parent.Handle,
                targetLeaf,
                replaceIfExists:
                    expectedTarget
                        != UpdateFileObservation.Missing);
            if (renamed.NamespaceChanged
                && !VerifyRetainedFileAndNamespace(
                    parent,
                    targetLeaf,
                    temporary,
                    temporarySnapshot.Identity,
                    _security.IsInstalledDescendant,
                    temporaryContent))
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.RecoveryBlocked,
                    namespaceChanged: true);
            }

            if (!renamed.Success)
            {
                return UpdateFileSystemResult.Failed(
                    renamed.NamespaceChanged
                        ? UpdateFileSystemError
                            .DirectoryFlushFailed
                        : UpdateFileSystemError
                            .UnexpectedTarget,
                    renamed.NamespaceChanged);
            }

            return VerifyRetainedFileAndNamespace(
                    parent,
                    targetLeaf,
                    temporary,
                    temporarySnapshot.Identity,
                    _security.IsInstalledDescendant,
                    temporaryContent)
                && TryGetLiveRoots(out _, out _)
                    ? UpdateFileSystemResult.Committed()
                    : UpdateFileSystemResult.Failed(
                        UpdateFileSystemError.RecoveryBlocked,
                        namespaceChanged: true);
        }
        finally
        {
            target?.Dispose();
        }
    }

    private bool RevalidateReleasedTarget(
        PinnedUpdateParent parent,
        PinnedUpdateRoot installed,
        string targetLeaf,
        UpdateFileObservation expectedTarget,
        ProtectedFileIdentity128? targetIdentity,
        UpdateFileOperationInput operation)
    {
        var reopened = _native.OpenRelative(
            parent.Handle,
            targetLeaf,
            ExistingFileRequest(
                requireDeleteAccess: false));
        if (expectedTarget
            == UpdateFileObservation.Missing)
        {
            if (reopened.Success
                && reopened.Handle is not null)
            {
                reopened.Handle.Dispose();
                return false;
            }

            return reopened.Error == ProtectedAclError.Missing
                && parent.Revalidate()
                && TryGetLiveRoots(out _, out _);
        }

        if (!reopened.Success
            || reopened.Handle is null
            || targetIdentity is null)
        {
            reopened.Handle?.Dispose();
            return false;
        }

        using (reopened.Handle)
        {
            var expectedContent =
                expectedTarget
                    == UpdateFileObservation.ExactOld
                    ? operation.OldContent!.Value
                    : operation.NewContent;
            return TryReadFileSnapshot(
                    reopened.Handle,
                    parent.LeafPath(targetLeaf),
                    installed.Identity.VolumeSerialNumber,
                    _security.IsInstalledDescendant,
                    targetIdentity,
                    out _)
                && MatchesContent(
                    reopened.Handle,
                    expectedContent)
                && VerifyRetainedFileAndNamespace(
                    parent,
                    targetLeaf,
                    reopened.Handle,
                    targetIdentity.Value,
                    _security.IsInstalledDescendant,
                    expectedContent)
                && TryGetLiveRoots(out _, out _);
        }
    }

    private UpdateFileSystemResult StageBackupForRollback(
        UpdateFileOperationInput operation)
    {
        if (!TryGetLiveRoots(
                out var installed,
                out var backup)
            || operation.OldContent is null)
        {
            return UpdateFileSystemResult.Failed(
                UpdateFileSystemError.UnsafeRoot);
        }

        using var backupParent =
            PinnedUpdateParent.TryOpen(
                _native,
                backup,
                operation.BackupRelativePath,
                _security.IsBackupDescendant,
                requireWriteAccess: false,
                out var backupLeaf,
                out var parentError);
        if (backupParent is null)
        {
            return UpdateFileSystemResult.Failed(parentError);
        }

        var backupOpen = _native.OpenRelative(
            backupParent.Handle,
            backupLeaf,
            ExistingFileRequest(
                requireDeleteAccess: false));
        if (!backupOpen.Success
            || backupOpen.Handle is null)
        {
            return UpdateFileSystemResult.Failed(
                UpdateFileSystemError.UnexpectedBackup);
        }

        using var retainedBackup = backupOpen.Handle;
        if (!TryReadFileSnapshot(
                retainedBackup,
                backupParent.LeafPath(backupLeaf),
                backup.Identity.VolumeSerialNumber,
                _security.IsBackupDescendant,
                expectedIdentity: null,
                out var backupSnapshot)
            || !MatchesContent(
                retainedBackup,
                operation.OldContent.Value))
        {
            return UpdateFileSystemResult.Failed(
                UpdateFileSystemError.UnexpectedBackup);
        }

        var staged = CreateVerifiedRelativeFile(
            installed,
            operation.TemporaryRelativePath,
            _security.IsInstalledDescendant,
            _security.InstalledFileDescriptor,
            operation.OldContent.Value,
            UpdateFileSystemError.UnexpectedTemporary,
            destination =>
                CopyRetainedFile(
                    retainedBackup,
                    destination));
        if (!VerifyRetainedFileAndNamespace(
                backupParent,
                backupLeaf,
                retainedBackup,
                backupSnapshot.Identity,
                _security.IsBackupDescendant,
                operation.OldContent.Value))
        {
            return UpdateFileSystemResult.Failed(
                UpdateFileSystemError.UnexpectedBackup,
                staged.NamespaceChanged);
        }

        return staged;
    }

    private UpdateFileSystemResult DeleteExactCreatedTarget(
        UpdateFileOperationInput operation) =>
        DeleteExactInstalledFile(
            operation,
            UpdateFileLocation.Target,
            operation.TargetRelativePath,
            operation.NewContent,
            UpdateFileSystemError.UnexpectedTarget);

    private UpdateFileSystemResult DeleteExactInstalledFile(
        UpdateFileOperationInput operation,
        UpdateFileLocation location,
        string relativePath,
        UpdateFileContentIdentity expectedContent,
        UpdateFileSystemError unexpectedError)
    {
        if (!TryGetLiveRoots(
                out var installed,
                out _))
        {
            return UpdateFileSystemResult.Failed(
                UpdateFileSystemError.UnsafeRoot);
        }

        using var parent = PinnedUpdateParent.TryOpen(
            _native,
            installed,
            relativePath,
            _security.IsInstalledDescendant,
            requireWriteAccess: true,
            out var leafName,
            out var parentError);
        if (parent is null)
        {
            return UpdateFileSystemResult.Failed(parentError);
        }

        var opened = _native.OpenRelative(
            parent.Handle,
            leafName,
            ExistingFileRequest(
                requireDeleteAccess: true));
        if (!opened.Success || opened.Handle is null)
        {
            return UpdateFileSystemResult.Failed(
                unexpectedError);
        }

        var target = opened.Handle;
        try
        {
            if (!TryReadFileSnapshot(
                    target,
                    parent.LeafPath(leafName),
                    installed.Identity.VolumeSerialNumber,
                    _security.IsInstalledDescendant,
                    expectedIdentity: null,
                    out var snapshot)
                || !MatchesContent(
                    target,
                    expectedContent)
                || !VerifyRetainedFileAndNamespace(
                    parent,
                    leafName,
                    target,
                    snapshot.Identity,
                    _security.IsInstalledDescendant,
                    expectedContent))
            {
                return UpdateFileSystemResult.Failed(
                    unexpectedError);
            }

            var deleted = _native.Delete(
                target,
                directory: false);
            if (!deleted.Success)
            {
                return UpdateFileSystemResult.Failed(
                    deleted.NamespaceChanged
                        ? UpdateFileSystemError
                            .RecoveryBlocked
                        : UpdateFileSystemError.IoFailure,
                    deleted.NamespaceChanged);
            }
        }
        finally
        {
            target.Dispose();
        }

        if (!parent.Revalidate())
        {
            return UpdateFileSystemResult.Failed(
                UpdateFileSystemError.RecoveryBlocked,
                namespaceChanged: true);
        }

        var flushed = _native.FlushDirectory(
            parent.Handle);
        if (!flushed.Success)
        {
            return UpdateFileSystemResult.Failed(
                UpdateFileSystemError.DirectoryFlushFailed,
                namespaceChanged: true);
        }

        var post = Observe(
            operation,
            location);
        return post.Error == UpdateFileSystemError.None
                && post.Observation
                    == UpdateFileObservation.Missing
            ? UpdateFileSystemResult.Committed()
            : UpdateFileSystemResult.Failed(
                UpdateFileSystemError.RecoveryBlocked,
                namespaceChanged: true);
    }

    private UpdateFileSystemResult FlushInstalledParent(
        string relativePath)
    {
        if (!TryGetLiveRoots(
                out var installed,
                out _))
        {
            return UpdateFileSystemResult.Failed(
                UpdateFileSystemError.UnsafeRoot);
        }

        using var parent = PinnedUpdateParent.TryOpen(
            _native,
            installed,
            relativePath,
            _security.IsInstalledDescendant,
            requireWriteAccess: true,
            out _,
            out var error);
        if (parent is null)
        {
            return UpdateFileSystemResult.Failed(error);
        }

        var flushed = _native.FlushDirectory(
            parent.Handle);
        return flushed.Success
            && parent.Revalidate()
            && TryGetLiveRoots(out _, out _)
                ? UpdateFileSystemResult.Committed(
                    namespaceChanged: false)
                : UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.DirectoryFlushFailed);
    }

    private UpdateFileSystemResult CreateVerifiedRelativeFile(
        PinnedUpdateRoot root,
        string relativePath,
        Func<byte[], bool, bool> descriptorValidator,
        byte[] securityDescriptor,
        UpdateFileContentIdentity expectedContent,
        UpdateFileSystemError collisionError,
        Func<FileStream, UpdateFileSystemError> write)
    {
        using var parent = PinnedUpdateParent.TryOpen(
            _native,
            root,
            relativePath,
            descriptorValidator,
            requireWriteAccess: true,
            out var leafName,
            out var parentError);
        if (parent is null)
        {
            return UpdateFileSystemResult.Failed(parentError);
        }

        var existing = _native.OpenRelative(
            parent.Handle,
            leafName,
            ExistingFileRequest(
                requireDeleteAccess: false));
        if (existing.Success && existing.Handle is not null)
        {
            existing.Handle.Dispose();
            return UpdateFileSystemResult.Failed(
                collisionError);
        }

        if (existing.Error != ProtectedAclError.Missing
            || !parent.Revalidate())
        {
            return UpdateFileSystemResult.Failed(
                existing.Error
                    == ProtectedAclError.Missing
                        ? UpdateFileSystemError.UnsafePath
                        : MapOpenError(existing.Error));
        }

        var created = _native.OpenRelative(
            parent.Handle,
            leafName,
            new ProtectedAclNativeOpenRequest(
                ProtectedAclNativeObjectKind.File,
                ProtectedAclNativeDisposition.CreateNew,
                OpenReparsePoint: true,
                ShareDelete: false,
                SecurityDescriptor:
                    securityDescriptor.ToArray())
            {
                RequireWriteAccess = true
            });
        if (!created.Success || created.Handle is null)
        {
            return UpdateFileSystemResult.Failed(
                created.Error
                    is ProtectedAclError.AlreadyExists
                        or ProtectedAclError.AccessDenied
                    ? collisionError
                    : MapOpenError(created.Error));
        }

        using var file = created.Handle;
        const bool namespaceChanged = true;
        if (!TryReadFileSnapshot(
                file,
                parent.LeafPath(leafName),
                root.Identity.VolumeSerialNumber,
                descriptorValidator,
                expectedIdentity: null,
                out var snapshot))
        {
            ProtectedAclNativeSnapshot raw;
            try
            {
                raw = file.ReadSnapshot();
            }
            catch (Exception exception) when (
                IsOrdinaryFileFailure(exception))
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.UnsafePath,
                    namespaceChanged);
            }

            return UpdateFileSystemResult.Failed(
                raw.Identity.VolumeSerialNumber
                    != root.Identity.VolumeSerialNumber
                        ? UpdateFileSystemError.CrossVolume
                        : UpdateFileSystemError.UnsafePath,
                namespaceChanged);
        }

        UpdateFileSystemError writeError;
        try
        {
            using var destination = file.OpenFileStream(
                FileAccess.Write);
            writeError = write(destination);
            if (writeError != UpdateFileSystemError.None)
            {
                return UpdateFileSystemResult.Failed(
                    writeError,
                    namespaceChanged);
            }

            try
            {
                destination.Flush(flushToDisk: true);
            }
            catch (Exception exception) when (
                IsOrdinaryFileFailure(exception))
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.FileFlushFailed,
                    namespaceChanged);
            }
        }
        catch (Exception exception) when (
            IsOrdinaryFileFailure(exception))
        {
            return UpdateFileSystemResult.Failed(
                UpdateFileSystemError.IoFailure,
                namespaceChanged);
        }

        if (!MatchesContent(file, expectedContent)
            || !TryReadFileSnapshot(
                file,
                parent.LeafPath(leafName),
                root.Identity.VolumeSerialNumber,
                descriptorValidator,
                snapshot.Identity,
                out _)
            || !parent.Revalidate())
        {
            return UpdateFileSystemResult.Failed(
                UpdateFileSystemError.UnsafePath,
                namespaceChanged);
        }

        var flushed = _native.FlushDirectory(
            parent.Handle);
        if (!flushed.Success)
        {
            return UpdateFileSystemResult.Failed(
                UpdateFileSystemError.DirectoryFlushFailed,
                namespaceChanged);
        }

        if (!VerifyRetainedFileAndNamespace(
                parent,
                leafName,
                file,
                snapshot.Identity,
                descriptorValidator,
                expectedContent))
        {
            return UpdateFileSystemResult.Failed(
                UpdateFileSystemError.UnsafePath,
                namespaceChanged);
        }

        return UpdateFileSystemResult.Committed();
    }

    private bool VerifyRetainedFileAndNamespace(
        PinnedUpdateParent parent,
        string leafName,
        IProtectedAclNativeHandle retained,
        ProtectedFileIdentity128 identity,
        Func<byte[], bool, bool> descriptorValidator,
        UpdateFileContentIdentity expectedContent)
    {
        if (!parent.Revalidate()
            || !TryReadFileSnapshot(
                retained,
                parent.LeafPath(leafName),
                parent.RootIdentity.VolumeSerialNumber,
                descriptorValidator,
                identity,
                out _)
            || !MatchesContent(
                retained,
                expectedContent))
        {
            return false;
        }

        var reopened = _native.OpenRelative(
            parent.Handle,
            leafName,
            ExistingFileRequest(
                requireDeleteAccess: false));
        if (!reopened.Success || reopened.Handle is null)
        {
            return false;
        }

        using (reopened.Handle)
        {
            return TryReadFileSnapshot(
                    reopened.Handle,
                    parent.LeafPath(leafName),
                    parent.RootIdentity.VolumeSerialNumber,
                    descriptorValidator,
                    identity,
                    out _)
                && MatchesContent(
                    reopened.Handle,
                    expectedContent)
                && parent.Revalidate();
        }
    }

    private static UpdateFileSystemError CopyRetainedFile(
        IProtectedAclNativeHandle source,
        FileStream destination)
    {
        try
        {
            using var sourceStream = source.OpenFileStream(
                FileAccess.Read);
            var length = sourceStream.Length;
            sourceStream.Position = 0;
            destination.SetLength(0);
            sourceStream.CopyTo(destination);
            return sourceStream.Position == length
                && sourceStream.Length == length
                    ? UpdateFileSystemError.None
                    : UpdateFileSystemError.IoFailure;
        }
        catch (Exception exception) when (
            IsOrdinaryFileFailure(exception))
        {
            return UpdateFileSystemError.IoFailure;
        }
    }

    private static bool MatchesContent(
        IProtectedAclNativeHandle file,
        UpdateFileContentIdentity expected)
    {
        try
        {
            using var stream = file.OpenFileStream(
                FileAccess.Read);
            if (stream.Length != expected.Length)
            {
                return false;
            }

            stream.Position = 0;
            var digest = Convert.ToHexString(
                    SHA256.HashData(stream))
                .ToLowerInvariant();
            return stream.Position == expected.Length
                && stream.Length == expected.Length
                && FixedHashEquals(
                    digest,
                    expected.Sha256);
        }
        catch (Exception exception) when (
            IsOrdinaryFileFailure(exception)
            || exception is CryptographicException)
        {
            return false;
        }
    }

    private bool TryGetLiveRoots(
        out PinnedUpdateRoot installed,
        out PinnedUpdateRoot backup)
    {
        installed = _installed!;
        backup = _backup!;
        return installed is not null
            && backup is not null
            && installed.Revalidate()
            && backup.Revalidate();
    }

    private static bool TryCaptureSource(
        Stream source,
        UpdateFileContentIdentity expected,
        out long originalPosition)
    {
        originalPosition = 0;
        try
        {
            if (!source.CanRead
                || !source.CanSeek
                || source.Length != expected.Length)
            {
                return false;
            }

            originalPosition = source.Position;
            return originalPosition >= 0
                && originalPosition <= source.Length;
        }
        catch (Exception exception) when (
            IsOrdinaryFileFailure(exception))
        {
            return false;
        }
    }

    private static bool TryRestorePosition(
        Stream source,
        long originalPosition)
    {
        try
        {
            source.Position = originalPosition;
            return source.Position == originalPosition;
        }
        catch (Exception exception) when (
            IsOrdinaryFileFailure(exception))
        {
            return false;
        }
    }

    private UpdateFileObservationResult ObserveRelative(
        PinnedUpdateRoot root,
        string relativePath,
        Func<byte[], bool, bool> descriptorValidator,
        UpdateFileOperationInput operation)
    {
        using var parent = PinnedUpdateParent.TryOpen(
            _native,
            root,
            relativePath,
            descriptorValidator,
            requireWriteAccess: false,
            out var leafName,
            out var error);
        if (parent is null)
        {
            return UpdateFileObservationResult.Failed(error);
        }

        return ObserveLeaf(
            parent,
            leafName,
            descriptorValidator,
            operation);
    }

    private UpdateFileObservationResult ObserveLeaf(
        PinnedUpdateParent parent,
        string leafName,
        Func<byte[], bool, bool> descriptorValidator,
        UpdateFileOperationInput operation)
    {
        var request = ExistingFileRequest(
            requireDeleteAccess: false);
        var opened = _native.OpenRelative(
            parent.Handle,
            leafName,
            request);
        if (!opened.Success || opened.Handle is null)
        {
            if (opened.Error != ProtectedAclError.Missing
                || !parent.Revalidate())
            {
                return UpdateFileObservationResult.Failed(
                    opened.Error == ProtectedAclError.Missing
                        ? UpdateFileSystemError.UnsafePath
                        : MapOpenError(opened.Error));
            }

            var repeated = _native.OpenRelative(
                parent.Handle,
                leafName,
                request);
            if (repeated.Success
                && repeated.Handle is not null)
            {
                repeated.Handle.Dispose();
                return UpdateFileObservationResult.Failed(
                    UpdateFileSystemError.UnsafePath);
            }

            return repeated.Error == ProtectedAclError.Missing
                && parent.Revalidate()
                ? UpdateFileObservationResult.Observed(
                    UpdateFileObservation.Missing)
                : UpdateFileObservationResult.Failed(
                    UpdateFileSystemError.UnsafePath);
        }

        using var retained = opened.Handle;
        if (!TryReadFileSnapshot(
                retained,
                parent.LeafPath(leafName),
                parent.RootIdentity.VolumeSerialNumber,
                descriptorValidator,
                expectedIdentity: null,
                out var initial))
        {
            return UpdateFileObservationResult.Failed(
                UpdateFileSystemError.UnsafePath);
        }

        var content = TryReadContent(
            retained,
            operation);
        if (content.Error != UpdateFileSystemError.None)
        {
            return UpdateFileObservationResult.Failed(
                content.Error);
        }

        if (!parent.Revalidate()
            || !TryReadFileSnapshot(
                retained,
                parent.LeafPath(leafName),
                parent.RootIdentity.VolumeSerialNumber,
                descriptorValidator,
                initial.Identity,
                out _))
        {
            return UpdateFileObservationResult.Failed(
                UpdateFileSystemError.UnsafePath);
        }

        var namespaceCheck = _native.OpenRelative(
            parent.Handle,
            leafName,
            request);
        if (!namespaceCheck.Success
            || namespaceCheck.Handle is null)
        {
            return UpdateFileObservationResult.Failed(
                UpdateFileSystemError.UnsafePath);
        }

        using (namespaceCheck.Handle)
        {
            if (!TryReadFileSnapshot(
                    namespaceCheck.Handle,
                    parent.LeafPath(leafName),
                    parent.RootIdentity.VolumeSerialNumber,
                    descriptorValidator,
                    initial.Identity,
                    out _)
                || !parent.Revalidate())
            {
                return UpdateFileObservationResult.Failed(
                    UpdateFileSystemError.UnsafePath);
            }
        }

        var repeatedContent = TryReadContent(
            retained,
            operation);
        if (repeatedContent.Error
                != UpdateFileSystemError.None
            || repeatedContent.Observation
                != content.Observation
            || !TryReadFileSnapshot(
                retained,
                parent.LeafPath(leafName),
                parent.RootIdentity.VolumeSerialNumber,
                descriptorValidator,
                initial.Identity,
                out _)
            || !parent.Revalidate())
        {
            return UpdateFileObservationResult.Failed(
                UpdateFileSystemError.UnsafePath);
        }

        return UpdateFileObservationResult.Observed(
            content.Observation);
    }

    private static ContentObservation TryReadContent(
        IProtectedAclNativeHandle retained,
        UpdateFileOperationInput operation)
    {
        try
        {
            using var stream = retained.OpenFileStream(
                FileAccess.Read);
            var length = stream.Length;
            if (length != operation.NewContent.Length
                && (operation.OldContent is null
                    || length
                        != operation.OldContent.Value.Length))
            {
                return ContentObservation.Valid(
                    UpdateFileObservation.Unknown);
            }

            stream.Position = 0;
            var digest = Convert.ToHexString(
                    SHA256.HashData(stream))
                .ToLowerInvariant();
            if (stream.Position != length
                || stream.Length != length)
            {
                return ContentObservation.Failed(
                    UpdateFileSystemError.IoFailure);
            }

            if (operation.OldContent is { } old
                && length == old.Length
                && FixedHashEquals(
                    digest,
                    old.Sha256))
            {
                return ContentObservation.Valid(
                    UpdateFileObservation.ExactOld);
            }

            return length == operation.NewContent.Length
                && FixedHashEquals(
                    digest,
                    operation.NewContent.Sha256)
                ? ContentObservation.Valid(
                    UpdateFileObservation.ExactNew)
                : ContentObservation.Valid(
                    UpdateFileObservation.Unknown);
        }
        catch (Exception exception) when (
            IsOrdinaryFileFailure(exception)
            || exception is CryptographicException)
        {
            return ContentObservation.Failed(
                UpdateFileSystemError.IoFailure);
        }
    }

    private static bool TryReadFileSnapshot(
        IProtectedAclNativeHandle handle,
        string expectedPath,
        ulong expectedVolume,
        Func<byte[], bool, bool> descriptorValidator,
        ProtectedFileIdentity128? expectedIdentity,
        out ProtectedAclNativeSnapshot snapshot)
    {
        snapshot = null!;
        try
        {
            snapshot = handle.ReadSnapshot();
            return !snapshot.IsDirectory
                && !snapshot.IsReparsePoint
                && snapshot.Identity.IsValid
                && snapshot.Identity.VolumeSerialNumber
                    == expectedVolume
                && (expectedIdentity is null
                    || snapshot.Identity
                        == expectedIdentity.Value)
                && string.Equals(
                    Path.GetFullPath(snapshot.FinalPath),
                    expectedPath,
                    StringComparison.OrdinalIgnoreCase)
                && descriptorValidator(
                    snapshot.SecurityDescriptor,
                    false);
        }
        catch (Exception exception) when (
            IsOrdinaryFileFailure(exception))
        {
            snapshot = null!;
            return false;
        }
    }

    private static ProtectedAclNativeOpenRequest
        ExistingFileRequest(bool requireDeleteAccess) =>
        new(
            ProtectedAclNativeObjectKind.File,
            ProtectedAclNativeDisposition.OpenExisting,
            OpenReparsePoint: true,
            ShareDelete: false,
            SecurityDescriptor: null)
        {
            RequireDeleteAccess = requireDeleteAccess
        };

    internal static UpdateFileSystemError MapOpenError(
        ProtectedAclError error) =>
        error switch
        {
            ProtectedAclError.Missing =>
                UpdateFileSystemError.MissingParent,
            ProtectedAclError.InvalidPath =>
                UpdateFileSystemError.InvalidInput,
            ProtectedAclError.UnsafePath
                or ProtectedAclError.SecurityMismatch =>
                UpdateFileSystemError.UnsafePath,
            _ => UpdateFileSystemError.IoFailure
        };

    private static bool FixedHashEquals(
        string first,
        string second)
    {
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(first),
                Convert.FromHexString(second));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool IsOrdinaryFileFailure(
        Exception exception) =>
        exception is IOException
            or UnauthorizedAccessException
            or ArgumentException
            or InvalidOperationException
            or NotSupportedException
            or ObjectDisposedException;

    private readonly record struct ContentObservation(
        UpdateFileObservation Observation,
        UpdateFileSystemError Error)
    {
        public static ContentObservation Valid(
            UpdateFileObservation observation) =>
            new(observation, UpdateFileSystemError.None);

        public static ContentObservation Failed(
            UpdateFileSystemError error) =>
            new(UpdateFileObservation.Unknown, error);
    }

    public void Dispose()
    {
        PinnedUpdateRoot? installed;
        PinnedUpdateRoot? backup;
        lock (_gate)
        {
            installed = _installed;
            backup = _backup;
            _installed = null;
            _backup = null;
        }

        backup?.Dispose();
        installed?.Dispose();
    }
}

internal static class UpdateFileOperationValidation
{
    public static bool IsValid(
        UpdateFileOperationInput? operation)
    {
        if (operation is null
            || !WindowsReleasePathPolicy.Validate(
                operation.TargetRelativePath).Success
            || !WindowsReleasePathPolicy.Validate(
                operation.BackupRelativePath).Success
            || !WindowsReleasePathPolicy.Validate(
                operation.TemporaryRelativePath).Success
            || !string.Equals(
                operation.BackupRelativePath,
                operation.TargetRelativePath + ".bak",
                StringComparison.Ordinal)
            || !string.Equals(
                operation.TemporaryRelativePath,
                operation.TargetRelativePath
                    + ".update-tmp",
                StringComparison.Ordinal)
            || string.Equals(
                operation.TargetRelativePath,
                operation.TemporaryRelativePath,
                StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                Parent(operation.TargetRelativePath),
                Parent(operation.TemporaryRelativePath),
                StringComparison.OrdinalIgnoreCase)
            || !IsValidContent(operation.NewContent)
            || operation.TargetExisted
                != operation.OldContent.HasValue
            || operation.OldContent is { } old
                && (!IsValidContent(old)
                    || SameContent(
                        old,
                        operation.NewContent)))
        {
            return false;
        }

        return true;
    }

    private static bool SameContent(
        UpdateFileContentIdentity left,
        UpdateFileContentIdentity right) =>
        left.Length == right.Length
        && string.Equals(
            left.Sha256,
            right.Sha256,
            StringComparison.Ordinal);

    private static string Parent(string relativePath)
    {
        var separator = relativePath.LastIndexOf('/');
        return separator < 0
            ? string.Empty
            : relativePath[..separator];
    }

    private static bool IsValidContent(
        UpdateFileContentIdentity content) =>
        content.Length >= 0
        && content.Length
            <= UpdatePackageLimits.Default.MaximumFileBytes
        && content.Sha256 is { Length: 64 }
        && content.Sha256.All(character =>
            character is >= '0' and <= '9'
                or >= 'a' and <= 'f');
}

internal sealed class PinnedUpdateParent : IDisposable
{
    private readonly PinnedUpdateRoot _root;
    private readonly IReadOnlyList<PinnedUpdateDirectory> _directories;

    private PinnedUpdateParent(
        PinnedUpdateRoot root,
        IReadOnlyList<PinnedUpdateDirectory> directories,
        string finalPath)
    {
        _root = root;
        _directories = directories;
        FinalPath = finalPath;
    }

    public IProtectedAclNativeHandle Handle =>
        _directories.Count == 0
            ? _root.Handle
            : _directories[^1].Handle;

    public ProtectedFileIdentity128 RootIdentity =>
        _root.Identity;

    public string FinalPath { get; }

    public string LeafPath(string leafName) =>
        Path.GetFullPath(
            Path.Combine(FinalPath, leafName));

    public static PinnedUpdateParent? TryOpen(
        IProtectedAclNativeFileSystem native,
        PinnedUpdateRoot root,
        string relativePath,
        Func<byte[], bool, bool> descriptorValidator,
        bool requireWriteAccess,
        out string leafName,
        out UpdateFileSystemError error)
    {
        leafName = string.Empty;
        error = UpdateFileSystemError.UnsafePath;
        var segments = relativePath.Split('/');
        if (segments.Length == 0)
        {
            error = UpdateFileSystemError.InvalidInput;
            return null;
        }

        leafName = segments[^1];
        var directories = new List<PinnedUpdateDirectory>();
        var current = root.Handle;
        var currentPath = root.Path;
        try
        {
            for (var index = 0;
                 index < segments.Length - 1;
                 index++)
            {
                if (!root.Revalidate()
                    || !RevalidateDirectories(
                        directories,
                        root,
                        descriptorValidator))
                {
                    error = UpdateFileSystemError.UnsafePath;
                    DisposeDirectories(directories);
                    return null;
                }

                var request =
                    new ProtectedAclNativeOpenRequest(
                        ProtectedAclNativeObjectKind.Directory,
                        ProtectedAclNativeDisposition.OpenExisting,
                        OpenReparsePoint: true,
                        ShareDelete: false,
                        SecurityDescriptor: null)
                    {
                        RequireWriteAccess =
                            requireWriteAccess
                            && index == segments.Length - 2
                    };
                var opened = native.OpenRelative(
                    current,
                    segments[index],
                    request);
                if (!opened.Success
                    || opened.Handle is null)
                {
                    error = opened.Error
                        == ProtectedAclError.Missing
                            ? UpdateFileSystemError.MissingParent
                            : UpdateFileSystemSession
                                .MapOpenError(opened.Error);
                    DisposeDirectories(directories);
                    return null;
                }

                currentPath = Path.GetFullPath(
                    Path.Combine(
                        currentPath,
                        segments[index]));
                if (!TryReadDirectorySnapshot(
                        opened.Handle,
                        currentPath,
                        root.Identity.VolumeSerialNumber,
                        descriptorValidator,
                        expectedIdentity: null,
                        out var snapshot))
                {
                    opened.Handle.Dispose();
                    DisposeDirectories(directories);
                    error = UpdateFileSystemError.UnsafePath;
                    return null;
                }

                directories.Add(
                    new PinnedUpdateDirectory(
                        opened.Handle,
                        currentPath,
                        snapshot.Identity));
                current = opened.Handle;
            }

            var parent = new PinnedUpdateParent(
                root,
                directories.AsReadOnly(),
                currentPath);
            if (parent.Revalidate())
            {
                return parent;
            }

            parent.Dispose();
            error = UpdateFileSystemError.UnsafePath;
            return null;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or InvalidOperationException
                or NotSupportedException
                or ObjectDisposedException)
        {
            DisposeDirectories(directories);
            error = UpdateFileSystemError.IoFailure;
            return null;
        }
    }

    public bool Revalidate() =>
        _root.Revalidate()
        && RevalidateDirectories(
            _directories,
            _root,
            _root.DescendantDescriptorValidator);

    public void Dispose() =>
        DisposeDirectories(_directories);

    private static bool RevalidateDirectories(
        IEnumerable<PinnedUpdateDirectory> directories,
        PinnedUpdateRoot root,
        Func<byte[], bool, bool> descriptorValidator) =>
        directories.All(directory =>
            TryReadDirectorySnapshot(
                directory.Handle,
                directory.ExpectedPath,
                root.Identity.VolumeSerialNumber,
                descriptorValidator,
                directory.Identity,
                out _));

    private static bool TryReadDirectorySnapshot(
        IProtectedAclNativeHandle handle,
        string expectedPath,
        ulong expectedVolume,
        Func<byte[], bool, bool> descriptorValidator,
        ProtectedFileIdentity128? expectedIdentity,
        out ProtectedAclNativeSnapshot snapshot)
    {
        snapshot = null!;
        try
        {
            snapshot = handle.ReadSnapshot();
            return snapshot.IsDirectory
                && !snapshot.IsReparsePoint
                && snapshot.Identity.IsValid
                && snapshot.Identity.VolumeSerialNumber
                    == expectedVolume
                && (expectedIdentity is null
                    || snapshot.Identity
                        == expectedIdentity.Value)
                && string.Equals(
                    Path.GetFullPath(snapshot.FinalPath),
                    expectedPath,
                    StringComparison.OrdinalIgnoreCase)
                && descriptorValidator(
                    snapshot.SecurityDescriptor,
                    true);
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or InvalidOperationException
                or NotSupportedException
                or ObjectDisposedException)
        {
            snapshot = null!;
            return false;
        }
    }

    private static void DisposeDirectories(
        IEnumerable<PinnedUpdateDirectory> directories)
    {
        foreach (var directory in directories.Reverse())
        {
            directory.Handle.Dispose();
        }
    }

    private sealed record PinnedUpdateDirectory(
        IProtectedAclNativeHandle Handle,
        string ExpectedPath,
        ProtectedFileIdentity128 Identity);
}

internal sealed class PinnedUpdateRoot : IDisposable
{
    private readonly IProtectedAclNativeHandle _handle;
    private readonly string _expectedPath;
    private readonly ProtectedFileIdentity128 _expectedIdentity;
    private readonly Func<byte[], bool> _descriptorValidator;
    private readonly Func<byte[], bool, bool>
        _descendantDescriptorValidator;
    private bool _disposed;

    public PinnedUpdateRoot(
        IProtectedAclNativeHandle handle,
        string expectedPath,
        ProtectedFileIdentity128 expectedIdentity,
        Func<byte[], bool> descriptorValidator,
        Func<byte[], bool, bool>
            descendantDescriptorValidator)
    {
        _handle = handle;
        _expectedPath = expectedPath;
        _expectedIdentity = expectedIdentity;
        _descriptorValidator = descriptorValidator;
        _descendantDescriptorValidator =
            descendantDescriptorValidator;
    }

    public bool Revalidate()
    {
        if (_disposed)
        {
            return false;
        }

        try
        {
            var snapshot = _handle.ReadSnapshot();
            return snapshot.IsDirectory
                && !snapshot.IsReparsePoint
                && snapshot.Identity == _expectedIdentity
                && string.Equals(
                    System.IO.Path.GetFullPath(
                        snapshot.FinalPath),
                    _expectedPath,
                    StringComparison.OrdinalIgnoreCase)
                && _descriptorValidator(
                    snapshot.SecurityDescriptor);
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or InvalidOperationException
                or NotSupportedException
                or ObjectDisposedException)
        {
            return false;
        }
    }

    internal IProtectedAclNativeHandle Handle => _handle;
    internal string Path => _expectedPath;
    internal ProtectedFileIdentity128 Identity =>
        _expectedIdentity;
    internal Func<byte[], bool, bool>
        DescendantDescriptorValidator =>
            _descendantDescriptorValidator;

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _handle.Dispose();
    }
}
