using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate.Transactions;

public enum ProtectedAclError
{
    None,
    InvalidPath,
    UnsafePath,
    Missing,
    AlreadyExists,
    SecurityMismatch,
    PrivilegeUnavailable,
    AccessDenied,
    IoFailure
}

public readonly record struct ProtectedAclResult(
    bool Success,
    bool Created,
    ProtectedAclError Error)
{
    internal static ProtectedAclResult Valid(bool created = false) =>
        new(true, created, ProtectedAclError.None);

    internal static ProtectedAclResult Failed(ProtectedAclError error) =>
        new(false, false, error);
}

public sealed class ProtectedFileOpenResult : IDisposable
{
    private ProtectedFileOpenResult(
        bool success,
        FileStream? stream,
        ProtectedAclError error)
    {
        Success = success;
        Stream = stream;
        Error = error;
    }

    public bool Success { get; }
    public FileStream? Stream { get; }
    public ProtectedAclError Error { get; }

    internal static ProtectedFileOpenResult Opened(FileStream stream) =>
        new(true, stream, ProtectedAclError.None);

    internal static ProtectedFileOpenResult Failed(ProtectedAclError error) =>
        new(false, null, error);

    public void Dispose() => Stream?.Dispose();
}

internal enum ProtectedAclNativeObjectKind
{
    Directory,
    File
}

internal enum ProtectedAclNativeDisposition
{
    OpenExisting,
    CreateNew
}

internal readonly record struct ProtectedFileIdentity128(
    ulong VolumeSerialNumber,
    ulong FileIdLow,
    ulong FileIdHigh)
{
    public bool IsValid =>
        VolumeSerialNumber != 0
        && (FileIdLow != 0 || FileIdHigh != 0);
}

internal readonly record struct ProtectedAclNativeOpenRequest(
    ProtectedAclNativeObjectKind Kind,
    ProtectedAclNativeDisposition Disposition,
    bool OpenReparsePoint,
    bool ShareDelete,
    byte[]? SecurityDescriptor)
{
    public bool RequireDeleteAccess { get; init; }
    public bool RequireWriteAccess { get; init; }
}

internal sealed record ProtectedAclNativeSnapshot(
    bool IsDirectory,
    bool IsReparsePoint,
    string FinalPath,
    ProtectedFileIdentity128 Identity,
    byte[] SecurityDescriptor);

internal interface IProtectedAclNativeHandle : IDisposable
{
    ProtectedAclNativeSnapshot ReadSnapshot();

    FileStream TakeFileStream();

    FileStream OpenFileStream(FileAccess access) =>
        TakeFileStream();
}

internal interface IProtectedAclNativeFileSystem
{
    ProtectedAclNativeOpenResult OpenRoot(
        string rootPath,
        bool openReparsePoint,
        bool shareDelete,
        bool requireWriteAccess = false);

    ProtectedAclNativeOpenResult OpenRelative(
        IProtectedAclNativeHandle parent,
        string name,
        ProtectedAclNativeOpenRequest request);

    ProtectedAclNativeEnumerationResult EnumerateRelative(
        IProtectedAclNativeHandle directory) =>
        ProtectedAclNativeEnumerationResult.Failed(
            ProtectedAclError.IoFailure);

    ProtectedAclNativeOperationResult RenameRelative(
        IProtectedAclNativeHandle source,
        IProtectedAclNativeHandle destinationDirectory,
        string destinationName,
        bool replaceIfExists) =>
        ProtectedAclNativeOperationResult.Failed(
            ProtectedAclError.IoFailure);

    ProtectedAclNativeOperationResult Delete(
        IProtectedAclNativeHandle target,
        bool directory) =>
        ProtectedAclNativeOperationResult.Failed(
            ProtectedAclError.IoFailure);

    ProtectedAclNativeOperationResult FlushDirectory(
        IProtectedAclNativeHandle directory) =>
        ProtectedAclNativeOperationResult.Failed(
            ProtectedAclError.IoFailure);
}

internal readonly record struct ProtectedAclNativeOpenResult(
    IProtectedAclNativeHandle? Handle,
    ProtectedAclError Error)
{
    public bool Success => Handle is not null;

    public static ProtectedAclNativeOpenResult Opened(
        IProtectedAclNativeHandle handle) =>
        new(handle, ProtectedAclError.None);

    public static ProtectedAclNativeOpenResult Failed(
        ProtectedAclError error) =>
        new(null, error);
}

internal sealed record ProtectedAclNativeDirectoryEntry(
    string Name,
    ProtectedAclNativeObjectKind Kind,
    bool IsReparsePoint);

internal readonly record struct ProtectedAclNativeEnumerationResult(
    IReadOnlyList<ProtectedAclNativeDirectoryEntry>? Entries,
    ProtectedAclError Error)
{
    public bool Success => Entries is not null;

    public static ProtectedAclNativeEnumerationResult Enumerated(
        IReadOnlyList<ProtectedAclNativeDirectoryEntry> entries) =>
        new(entries, ProtectedAclError.None);

    public static ProtectedAclNativeEnumerationResult Failed(
        ProtectedAclError error) =>
        new(null, error);
}

internal readonly record struct ProtectedAclNativeOperationResult(
    bool Success,
    ProtectedAclError Error,
    bool NamespaceChanged)
{
    public static ProtectedAclNativeOperationResult Committed(
        bool namespaceChanged = true) =>
        new(true, ProtectedAclError.None, namespaceChanged);

    public static ProtectedAclNativeOperationResult Failed(
        ProtectedAclError error,
        bool namespaceChanged = false) =>
        new(false, error, namespaceChanged);
}

internal sealed class ProtectedDirectoryInspectionPolicy
{
    private readonly Func<byte[], bool> _rootValidator;
    private readonly Func<byte[], bool, bool> _descendantValidator;

    internal ProtectedDirectoryInspectionPolicy(
        Func<byte[], bool> rootValidator,
        Func<byte[], bool, bool> descendantValidator)
    {
        _rootValidator = rootValidator
            ?? throw new ArgumentNullException(nameof(rootValidator));
        _descendantValidator = descendantValidator
            ?? throw new ArgumentNullException(nameof(descendantValidator));
    }

    public static ProtectedDirectoryInspectionPolicy Transaction { get; } =
        new(
            descriptor =>
                ProtectedDirectoryAcl.HasExactProtectedDescriptor(
                    descriptor,
                    directory: true),
            (descriptor, directory) =>
                ProtectedDirectoryAcl.HasExactProtectedDescriptor(
                    descriptor,
                    directory));

    public static ProtectedDirectoryInspectionPolicy InstalledRelease { get; } =
        new(
            ProtectedDirectoryAcl.HasExactInstalledRootDescriptor,
            ProtectedDirectoryAcl.HasExactInstalledDescendantDescriptor);

    public static ProtectedDirectoryInspectionPolicy InstalledReleaseParent
        { get; } =
        new(
            ProtectedDirectoryAcl.HasTrustedInstallParentDescriptor,
            (_, _) => false);

    internal bool IsValidRoot(byte[] descriptor) =>
        descriptor is { Length: > 0 }
        && _rootValidator(descriptor);

    internal bool IsValidDescendant(
        byte[] descriptor,
        bool directory) =>
        descriptor is { Length: > 0 }
        && _descendantValidator(descriptor, directory);
}

internal readonly record struct ProtectedDirectoryLeaseOpenResult(
    ProtectedDirectoryInspectionLease? Lease,
    bool Created,
    ProtectedAclError Error) : IDisposable
{
    public bool Success => Lease is not null;

    public static ProtectedDirectoryLeaseOpenResult Opened(
        ProtectedDirectoryInspectionLease lease,
        bool created = false) =>
        new(lease, created, ProtectedAclError.None);

    public static ProtectedDirectoryLeaseOpenResult Failed(
        ProtectedAclError error) =>
        new(null, false, error);

    public void Dispose() => Lease?.Dispose();
}

internal readonly record struct ProtectedFileReadOpenResult(
    ProtectedFileReadLease? Lease,
    ProtectedAclError Error) : IDisposable
{
    public bool Success => Lease is not null;

    public static ProtectedFileReadOpenResult Opened(
        ProtectedFileReadLease lease) =>
        new(lease, ProtectedAclError.None);

    public static ProtectedFileReadOpenResult Failed(
        ProtectedAclError error) =>
        new(null, error);

    public void Dispose() => Lease?.Dispose();
}

internal readonly record struct
    ProtectedInstalledApplicationLeaseOpenResult(
        ProtectedInstalledApplicationLaunchLease? Lease,
        ProtectedAclError Error) : IDisposable
{
    public bool Success => Lease is not null;

    public static ProtectedInstalledApplicationLeaseOpenResult Opened(
        ProtectedInstalledApplicationLaunchLease lease) =>
        new(lease, ProtectedAclError.None);

    public static ProtectedInstalledApplicationLeaseOpenResult Failed(
        ProtectedAclError error) =>
        new(null, error);

    public void Dispose() => Lease?.Dispose();
}

internal readonly record struct ProtectedDirectoryEnumerationOpenResult(
    ProtectedDirectoryEnumerationLease? Lease,
    ProtectedAclError Error) : IDisposable
{
    public bool Success => Lease is not null;

    public static ProtectedDirectoryEnumerationOpenResult Opened(
        ProtectedDirectoryEnumerationLease lease) =>
        new(lease, ProtectedAclError.None);

    public static ProtectedDirectoryEnumerationOpenResult Failed(
        ProtectedAclError error) =>
        new(null, error);

    public void Dispose() => Lease?.Dispose();
}


internal enum ProtectedFileMutationOutcome
{
    Committed,
    Conflict,
    Failed
}

internal readonly record struct ProtectedFileMutationResult(
    ProtectedFileMutationOutcome Outcome,
    ProtectedAclError Error,
    ProtectedFileIdentity128? Identity)
{
    public static ProtectedFileMutationResult Committed(
        ProtectedFileIdentity128? identity = null) =>
        new(
            ProtectedFileMutationOutcome.Committed,
            ProtectedAclError.None,
            identity);

    public static ProtectedFileMutationResult Conflict(
        ProtectedAclError error = ProtectedAclError.None) =>
        new(
            ProtectedFileMutationOutcome.Conflict,
            error,
            null);

    public static ProtectedFileMutationResult Failed(
        ProtectedAclError error) =>
        new(
            ProtectedFileMutationOutcome.Failed,
            error,
            null);
}

internal enum ProtectedFileCompareExchangeOutcome
{
    Committed,
    Conflict,
    Failed
}

internal readonly record struct ProtectedFileCompareExchangeResult(
    ProtectedFileCompareExchangeOutcome Outcome,
    ProtectedAclError Error,
    ProtectedFileIdentity128? Identity)
{
    public static ProtectedFileCompareExchangeResult Committed(
        ProtectedFileIdentity128 identity) =>
        new(
            ProtectedFileCompareExchangeOutcome.Committed,
            ProtectedAclError.None,
            identity);

    public static ProtectedFileCompareExchangeResult Conflict() =>
        new(
            ProtectedFileCompareExchangeOutcome.Conflict,
            ProtectedAclError.None,
            null);

    public static ProtectedFileCompareExchangeResult Failed(
        ProtectedAclError error) =>
        new(
            ProtectedFileCompareExchangeOutcome.Failed,
            error,
            null);
}
/// <summary>
/// Creates and verifies filesystem objects whose only access is explicit
/// Administrators/SYSTEM FullControl and whose owner is SYSTEM.
/// Existing weaker objects are rejected and never repaired.
/// </summary>
public sealed class ProtectedDirectoryAcl
{
    private static readonly SecurityIdentifier Administrators =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    private static readonly SecurityIdentifier LocalSystem =
        new(WellKnownSidType.LocalSystemSid, null);

    private static readonly SecurityIdentifier BuiltinUsers =
        new(WellKnownSidType.BuiltinUsersSid, null);

    private static readonly SecurityIdentifier TrustedInstaller =
        new(
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    private readonly IProtectedAclNativeFileSystem _native;
    private readonly Func<string, DriveType> _getDriveType;
    private readonly Func<IDisposable?> _acquireRestorePrivilege;

    public ProtectedDirectoryAcl()
        : this(
            new WindowsProtectedAclNativeFileSystem(),
            root => new DriveInfo(root).DriveType,
            TryAcquireRestorePrivilege)
    {
    }

    internal ProtectedDirectoryAcl(
        IProtectedAclNativeFileSystem native,
        Func<string, DriveType> getDriveType,
        Func<IDisposable?>? acquireRestorePrivilege = null)
    {
        _native = native
            ?? throw new ArgumentNullException(nameof(native));
        _getDriveType = getDriveType
            ?? throw new ArgumentNullException(nameof(getDriveType));
        _acquireRestorePrivilege = acquireRestorePrivilege
            ?? (() => NoopDisposable.Instance);
    }

    public static DirectorySecurity BuildDirectorySecurity()
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.SetOwner(LocalSystem);
        security.AddAccessRule(
            new FileSystemAccessRule(
                Administrators,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                    | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        security.AddAccessRule(
            new FileSystemAccessRule(
                LocalSystem,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                    | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        return security;
    }

    public static FileSecurity BuildFileSecurity()
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.SetOwner(LocalSystem);
        security.AddAccessRule(
            new FileSystemAccessRule(
                Administrators,
                FileSystemRights.FullControl,
                InheritanceFlags.None,
                PropagationFlags.None,
                AccessControlType.Allow));
        security.AddAccessRule(
            new FileSystemAccessRule(
                LocalSystem,
                FileSystemRights.FullControl,
                InheritanceFlags.None,
                PropagationFlags.None,
                AccessControlType.Allow));
        return security;
    }


    public static DirectorySecurity BuildInstalledRootSecurity()
    {
        var security = BuildDirectorySecurity();
        security.AddAccessRule(
            new FileSystemAccessRule(
                BuiltinUsers,
                FileSystemRights.ReadAndExecute
                    | FileSystemRights.Synchronize,
                InheritanceFlags.ContainerInherit
                    | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        return security;
    }
    internal static bool HasExactDirectoryDescriptor(
        FileSystemSecurity? security) =>
        HasExactDescriptor(
            security,
            InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit);

    internal static bool HasExactFileDescriptor(
        FileSystemSecurity? security) =>
        HasExactDescriptor(security, InheritanceFlags.None);

    public ProtectedAclResult ValidateProtectedDirectory(string? path)
    {
        if (!TryCanonicalLocalPath(path, out var canonicalPath))
        {
            return ProtectedAclResult.Failed(
                ProtectedAclError.InvalidPath);
        }

        var opened = OpenPinnedChain(
            canonicalPath,
            ProtectedAclNativeObjectKind.Directory);
        if (!opened.Success || opened.Chain is null)
        {
            return ProtectedAclResult.Failed(opened.Error);
        }

        using var chain = opened.Chain;
        if (!chain.TryReadLeaf(out var snapshot))
        {
            return ProtectedAclResult.Failed(
                ProtectedAclError.UnsafePath);
        }

        return HasExactNativeDescriptor(
                snapshot.SecurityDescriptor,
                directory: true)
            ? ProtectedAclResult.Valid()
            : ProtectedAclResult.Failed(
                ProtectedAclError.SecurityMismatch);
    }

    public ProtectedAclResult ValidateProtectedFile(string? path)
    {
        if (!TryCanonicalLocalPath(path, out var canonicalPath))
        {
            return ProtectedAclResult.Failed(
                ProtectedAclError.InvalidPath);
        }

        var opened = OpenPinnedChain(
            canonicalPath,
            ProtectedAclNativeObjectKind.File);
        if (!opened.Success || opened.Chain is null)
        {
            return ProtectedAclResult.Failed(opened.Error);
        }

        using var chain = opened.Chain;
        if (!chain.TryReadLeaf(out var snapshot))
        {
            return ProtectedAclResult.Failed(
                ProtectedAclError.UnsafePath);
        }

        return HasExactNativeDescriptor(
                snapshot.SecurityDescriptor,
                directory: false)
            ? ProtectedAclResult.Valid()
            : ProtectedAclResult.Failed(
                ProtectedAclError.SecurityMismatch);
    }

    public ProtectedAclResult EnsureProtectedDirectory(string? path)
    {
        if (!TryCanonicalLocalPath(path, out var canonicalPath)
            || !TryGetParentAndLeaf(
                canonicalPath,
                out var parentPath,
                out var leafName))
        {
            return ProtectedAclResult.Failed(
                ProtectedAclError.InvalidPath);
        }

        var parentOpened = OpenPinnedChain(
            parentPath,
            ProtectedAclNativeObjectKind.Directory);
        if (!parentOpened.Success || parentOpened.Chain is null)
        {
            return ProtectedAclResult.Failed(parentOpened.Error);
        }

        using var parent = parentOpened.Chain;
        if (!parent.Revalidate())
        {
            return ProtectedAclResult.Failed(
                ProtectedAclError.UnsafePath);
        }

        var existing = _native.OpenRelative(
            parent.LeafHandle,
            leafName,
            ExistingRequest(
                ProtectedAclNativeObjectKind.Directory));
        if (existing.Success && existing.Handle is not null)
        {
            using var existingHandle = existing.Handle;
            if (!TryReadValidSnapshot(
                    existingHandle,
                    canonicalPath,
                    ProtectedAclNativeObjectKind.Directory,
                    expectedIdentity: null,
                    out var existingSnapshot)
                || !parent.Revalidate())
            {
                return ProtectedAclResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            return HasExactNativeDescriptor(
                    existingSnapshot.SecurityDescriptor,
                    directory: true)
                ? ProtectedAclResult.Valid()
                : ProtectedAclResult.Failed(
                    ProtectedAclError.SecurityMismatch);
        }

        if (existing.Error != ProtectedAclError.Missing)
        {
            return ProtectedAclResult.Failed(existing.Error);
        }

        using var privilege = _acquireRestorePrivilege();
        if (privilege is null)
        {
            return ProtectedAclResult.Failed(
                ProtectedAclError.PrivilegeUnavailable);
        }

        if (!parent.Revalidate())
        {
            return ProtectedAclResult.Failed(
                ProtectedAclError.UnsafePath);
        }

        var descriptor = BuildDirectorySecurity()
            .GetSecurityDescriptorBinaryForm();
        var created = _native.OpenRelative(
            parent.LeafHandle,
            leafName,
            CreateRequest(
                ProtectedAclNativeObjectKind.Directory,
                descriptor));
        if (!created.Success || created.Handle is null)
        {
            return ProtectedAclResult.Failed(created.Error);
        }

        using var createdHandle = created.Handle;
        if (!TryReadValidSnapshot(
                createdHandle,
                canonicalPath,
                ProtectedAclNativeObjectKind.Directory,
                expectedIdentity: null,
                out var createdSnapshot)
            || !parent.Revalidate())
        {
            return ProtectedAclResult.Failed(
                ProtectedAclError.UnsafePath);
        }

        return HasExactNativeDescriptor(
                createdSnapshot.SecurityDescriptor,
                directory: true)
            ? ProtectedAclResult.Valid(created: true)
            : ProtectedAclResult.Failed(
                ProtectedAclError.SecurityMismatch);
    }

    public ProtectedFileOpenResult OpenNewProtectedFile(string? path)
    {
        if (!TryCanonicalLocalPath(path, out var canonicalPath)
            || !TryGetParentAndLeaf(
                canonicalPath,
                out var parentPath,
                out var leafName))
        {
            return ProtectedFileOpenResult.Failed(
                ProtectedAclError.InvalidPath);
        }

        var parentOpened = OpenPinnedChain(
            parentPath,
            ProtectedAclNativeObjectKind.Directory);
        if (!parentOpened.Success || parentOpened.Chain is null)
        {
            return ProtectedFileOpenResult.Failed(parentOpened.Error);
        }

        using var parent = parentOpened.Chain;
        if (!parent.TryReadLeaf(out var parentSnapshot)
            || !HasExactNativeDescriptor(
                parentSnapshot.SecurityDescriptor,
                directory: true)
            || !parent.Revalidate())
        {
            return ProtectedFileOpenResult.Failed(
                ProtectedAclError.SecurityMismatch);
        }

        using var privilege = _acquireRestorePrivilege();
        if (privilege is null)
        {
            return ProtectedFileOpenResult.Failed(
                ProtectedAclError.PrivilegeUnavailable);
        }

        var descriptor = BuildFileSecurity()
            .GetSecurityDescriptorBinaryForm();
        var created = _native.OpenRelative(
            parent.LeafHandle,
            leafName,
            CreateRequest(
                ProtectedAclNativeObjectKind.File,
                descriptor));
        if (!created.Success || created.Handle is null)
        {
            return ProtectedFileOpenResult.Failed(created.Error);
        }

        using var createdHandle = created.Handle;
        if (!TryReadValidSnapshot(
                createdHandle,
                canonicalPath,
                ProtectedAclNativeObjectKind.File,
                expectedIdentity: null,
                out var createdSnapshot)
            || !HasExactNativeDescriptor(
                createdSnapshot.SecurityDescriptor,
                directory: false)
            || !parent.Revalidate())
        {
            return ProtectedFileOpenResult.Failed(
                ProtectedAclError.UnsafePath);
        }

        try
        {
            return ProtectedFileOpenResult.Opened(
                createdHandle.TakeFileStream());
        }
        catch (Exception exception) when (
            IsAccessFailure(exception)
            || IsIoFailure(exception))
        {
            return ProtectedFileOpenResult.Failed(
                IsAccessFailure(exception)
                    ? ProtectedAclError.AccessDenied
                    : ProtectedAclError.IoFailure);
        }
    }


    internal ProtectedDirectoryLeaseOpenResult InspectProtectedDirectory(
        string? path,
        ProtectedDirectoryInspectionPolicy policy)
    {
        if (policy is null
            || !TryCanonicalLocalPath(path, out var canonicalPath))
        {
            return ProtectedDirectoryLeaseOpenResult.Failed(
                ProtectedAclError.InvalidPath);
        }

        var opened = OpenPinnedChain(
            canonicalPath,
            ProtectedAclNativeObjectKind.Directory);
        if (!opened.Success || opened.Chain is null)
        {
            return ProtectedDirectoryLeaseOpenResult.Failed(
                opened.Error);
        }

        var chain = opened.Chain;
        if (!chain.TryReadLeaf(out var snapshot)
            || !policy.IsValidRoot(
                snapshot.SecurityDescriptor))
        {
            chain.Dispose();
            return ProtectedDirectoryLeaseOpenResult.Failed(
                ProtectedAclError.SecurityMismatch);
        }

        var owner = new ProtectedLeaseOwner(
            chain,
            () => chain.Revalidate()
                && chain.TryReadLeaf(out var current)
                && policy.IsValidRoot(
                    current.SecurityDescriptor));
        return ProtectedDirectoryLeaseOpenResult.Opened(
            new ProtectedDirectoryInspectionLease(
                owner,
                chain.LeafHandle,
                snapshot));
    }


    private ProtectedDirectoryLeaseOpenResult
        InspectProtectedDirectoryForMutation(string parentPath)
    {
        if (!TryCanonicalLocalPath(parentPath, out var canonicalPath))
        {
            return ProtectedDirectoryLeaseOpenResult.Failed(
                ProtectedAclError.InvalidPath);
        }

        var policy =
            ProtectedDirectoryInspectionPolicy.Transaction;
        var opened = OpenPinnedChain(
            canonicalPath,
            ProtectedAclNativeObjectKind.Directory,
            leafWriteAccess: true);
        if (!opened.Success || opened.Chain is null)
        {
            return ProtectedDirectoryLeaseOpenResult.Failed(
                opened.Error);
        }

        var chain = opened.Chain;
        if (!chain.TryReadLeaf(out var snapshot)
            || !policy.IsValidRoot(
                snapshot.SecurityDescriptor))
        {
            chain.Dispose();
            return ProtectedDirectoryLeaseOpenResult.Failed(
                ProtectedAclError.SecurityMismatch);
        }

        var owner = new ProtectedLeaseOwner(
            chain,
            () => chain.Revalidate()
                && chain.TryReadLeaf(out var current)
                && policy.IsValidRoot(
                    current.SecurityDescriptor));
        return ProtectedDirectoryLeaseOpenResult.Opened(
            new ProtectedDirectoryInspectionLease(
                owner,
                chain.LeafHandle,
                snapshot));
    }
    internal ProtectedDirectoryLeaseOpenResult EnsureProtectedDirectoryTree(
        string? anchorPath,
        IReadOnlyList<string> relativeSegments)
    {
        if (relativeSegments is null
            || relativeSegments.Any(segment =>
                !IsSimpleRelativeName(segment)))
        {
            return ProtectedDirectoryLeaseOpenResult.Failed(
                ProtectedAclError.InvalidPath);
        }

        var anchor = InspectProtectedDirectoryForMutation(
            anchorPath!);
        if (!anchor.Success || anchor.Lease is null)
        {
            return anchor;
        }

        if (relativeSegments.Count == 0)
        {
            return anchor;
        }

        var root = anchor.Lease;
        RelativePinnedHandleSet? set = null;
        IDisposable? privilege = null;
        try
        {
            if (!root.TryRetain(out var retention)
                || retention is null)
            {
                return ProtectedDirectoryLeaseOpenResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            set = new RelativePinnedHandleSet(
                retention,
                root.Handle,
                root.Snapshot);
            var currentHandle = root.Handle;
            var currentPath = root.FinalPath;
            var createdAny = false;
            foreach (var segment in relativeSegments)
            {
                if (!set.Revalidate())
                {
                    set.CleanupCreatedDirectories(_native);
                    return ProtectedDirectoryLeaseOpenResult.Failed(
                        ProtectedAclError.UnsafePath);
                }

                var created = false;
                var existingRequest = ExistingRequest(
                    ProtectedAclNativeObjectKind.Directory) with
                {
                    RequireWriteAccess = true
                };
                var child = _native.OpenRelative(
                    currentHandle,
                    segment,
                    existingRequest);
                if (!child.Success
                    && child.Error == ProtectedAclError.Missing)
                {
                    privilege ??= _acquireRestorePrivilege();
                    if (privilege is null)
                    {
                        set.CleanupCreatedDirectories(_native);
                        return ProtectedDirectoryLeaseOpenResult.Failed(
                            ProtectedAclError.PrivilegeUnavailable);
                    }

                    child = _native.OpenRelative(
                        currentHandle,
                        segment,
                        CreateRequest(
                            ProtectedAclNativeObjectKind.Directory,
                            BuildDirectorySecurity()
                                .GetSecurityDescriptorBinaryForm()));
                    created = child.Success;
                }

                if (!child.Success || child.Handle is null)
                {
                    set.CleanupCreatedDirectories(_native);
                    return ProtectedDirectoryLeaseOpenResult.Failed(
                        child.Error);
                }

                if (created)
                {
                    var flushed = _native.FlushDirectory(
                        currentHandle);
                    if (!flushed.Success)
                    {
                        _native.Delete(
                            child.Handle,
                            directory: true);
                        child.Handle.Dispose();
                        set.CleanupCreatedDirectories(_native);
                        return ProtectedDirectoryLeaseOpenResult.Failed(
                            flushed.Error);
                    }
                }

                currentPath = Path.GetFullPath(
                    Path.Combine(currentPath, segment));
                if (!set.TryAdd(
                        child.Handle,
                        currentPath,
                        ProtectedAclNativeObjectKind.Directory,
                        created,
                        out var snapshot))
                {
                    child.Handle.Dispose();
                    set.CleanupCreatedDirectories(_native);
                    return ProtectedDirectoryLeaseOpenResult.Failed(
                        ProtectedAclError.UnsafePath);
                }

                if (!ProtectedDirectoryInspectionPolicy.Transaction
                        .IsValidDescendant(
                            snapshot.SecurityDescriptor,
                            directory: true))
                {
                    set.CleanupCreatedDirectories(_native);
                    return ProtectedDirectoryLeaseOpenResult.Failed(
                        ProtectedAclError.SecurityMismatch);
                }

                currentHandle = child.Handle;
                createdAny |= created;
            }

            if (!RevalidateRelativeSet(
                    set,
                    ProtectedDirectoryInspectionPolicy.Transaction))
            {
                set.CleanupCreatedDirectories(_native);
                return ProtectedDirectoryLeaseOpenResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            var completed = set;
            set = null;
            var owner = new ProtectedLeaseOwner(
                completed,
                () => RevalidateRelativeSet(
                    completed,
                    ProtectedDirectoryInspectionPolicy.Transaction));
            return ProtectedDirectoryLeaseOpenResult.Opened(
                new ProtectedDirectoryInspectionLease(
                    owner,
                    completed.LeafHandle,
                    completed.LeafSnapshot),
                createdAny);
        }
        catch (Exception exception) when (
            IsAccessFailure(exception)
            || IsIoFailure(exception))
        {
            set?.CleanupCreatedDirectories(_native);
            return ProtectedDirectoryLeaseOpenResult.Failed(
                IsAccessFailure(exception)
                    ? ProtectedAclError.AccessDenied
                    : ProtectedAclError.IoFailure);
        }
        finally
        {
            set?.Dispose();
            privilege?.Dispose();
            root.Dispose();
        }
    }

    internal ProtectedFileReadOpenResult OpenProtectedFileForRead(
        string? path)
    {
        if (!TryCanonicalLocalPath(path, out var canonicalPath)
            || !TryGetParentAndLeaf(
                canonicalPath,
                out var parentPath,
                out var leafName))
        {
            return ProtectedFileReadOpenResult.Failed(
                ProtectedAclError.InvalidPath);
        }

        var parent = InspectProtectedDirectory(
            parentPath,
            ProtectedDirectoryInspectionPolicy.Transaction);
        if (!parent.Success || parent.Lease is null)
        {
            return ProtectedFileReadOpenResult.Failed(
                parent.Error);
        }

        try
        {
            return OpenProtectedFileForRead(
                parent.Lease,
                leafName,
                ProtectedDirectoryInspectionPolicy.Transaction);
        }
        finally
        {
            parent.Dispose();
        }
    }

    internal ProtectedFileReadOpenResult OpenProtectedFileForRead(
        ProtectedDirectoryInspectionLease directory,
        string relativePath,
        ProtectedDirectoryInspectionPolicy policy)
    {
        if (directory is null
            || policy is null
            || !policy.IsValidRoot(
                directory.SecurityDescriptor)
            || !TrySplitRelativePath(
                relativePath,
                out var segments))
        {
            return ProtectedFileReadOpenResult.Failed(
                ProtectedAclError.InvalidPath);
        }

        RelativePinnedHandleSet? set = null;
        try
        {
            if (!directory.TryRetain(out var retention)
                || retention is null)
            {
                return ProtectedFileReadOpenResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            set = new RelativePinnedHandleSet(
                retention,
                directory.Handle,
                directory.Snapshot);
            var currentHandle = directory.Handle;
            var currentPath = directory.FinalPath;
            for (var index = 0;
                 index < segments.Length;
                 index++)
            {
                var kind = index == segments.Length - 1
                    ? ProtectedAclNativeObjectKind.File
                    : ProtectedAclNativeObjectKind.Directory;
                var opened = _native.OpenRelative(
                    currentHandle,
                    segments[index],
                    ExistingRequest(kind));
                if (!opened.Success || opened.Handle is null)
                {
                    return ProtectedFileReadOpenResult.Failed(
                        opened.Error);
                }

                currentPath = Path.GetFullPath(
                    Path.Combine(
                        currentPath,
                        segments[index]));
                if (!set.TryAdd(
                        opened.Handle,
                        currentPath,
                        kind,
                        created: false,
                        out var snapshot))
                {
                    opened.Handle.Dispose();
                    return ProtectedFileReadOpenResult.Failed(
                        ProtectedAclError.UnsafePath);
                }

                if (!policy.IsValidDescendant(
                        snapshot.SecurityDescriptor,
                        directory: kind
                            == ProtectedAclNativeObjectKind.Directory))
                {
                    return ProtectedFileReadOpenResult.Failed(
                        ProtectedAclError.SecurityMismatch);
                }

                currentHandle = opened.Handle;
            }

            if (!RevalidateRelativeSet(set, policy))
            {
                return ProtectedFileReadOpenResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            var stream = set.LeafHandle.OpenFileStream(
                FileAccess.Read);
            var completed = set;
            set = null;
            var owner = new ProtectedLeaseOwner(
                completed,
                () => RevalidateRelativeSet(
                    completed,
                    policy));
            return ProtectedFileReadOpenResult.Opened(
                new ProtectedFileReadLease(
                    owner,
                    stream,
                    completed.LeafSnapshot));
        }
        catch (Exception exception) when (
            IsAccessFailure(exception)
            || IsIoFailure(exception))
        {
            return ProtectedFileReadOpenResult.Failed(
                IsAccessFailure(exception)
                    ? ProtectedAclError.AccessDenied
                    : ProtectedAclError.IoFailure);
        }
        finally
        {
            set?.Dispose();
        }
    }

    internal ProtectedInstalledApplicationLeaseOpenResult
        OpenInstalledApplicationForLaunch(
            string? programFilesPath,
            string? installationRoot,
            string? applicationPath)
    {
        var applicationRelativePath =
            UpdateReleaseContract.WindowsApplicationPath.Replace(
                '/',
                Path.DirectorySeparatorChar);
        if (!TryCanonicalLocalPath(
                programFilesPath,
                out var canonicalProgramFiles)
            || !TryCanonicalLocalPath(
                installationRoot,
                out var canonicalInstallationRoot)
            || !TryCanonicalLocalPath(
                applicationPath,
                out var canonicalApplicationPath)
            || !string.Equals(
                Path.GetDirectoryName(canonicalInstallationRoot),
                canonicalProgramFiles,
                StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                Path.GetFullPath(
                    Path.Combine(
                        canonicalInstallationRoot,
                        applicationRelativePath)),
                canonicalApplicationPath,
                StringComparison.OrdinalIgnoreCase))
        {
            return ProtectedInstalledApplicationLeaseOpenResult.Failed(
                ProtectedAclError.InvalidPath);
        }

        var parent = InspectProtectedDirectory(
            canonicalProgramFiles,
            ProtectedDirectoryInspectionPolicy.InstalledReleaseParent);
        var root = default(ProtectedDirectoryLeaseOpenResult);
        var application = default(ProtectedFileReadOpenResult);
        try
        {
            if (!parent.Success || parent.Lease is null)
            {
                return ProtectedInstalledApplicationLeaseOpenResult.Failed(
                    parent.Error);
            }

            root = InspectProtectedDirectory(
                canonicalInstallationRoot,
                ProtectedDirectoryInspectionPolicy.InstalledRelease);
            if (!root.Success || root.Lease is null)
            {
                return ProtectedInstalledApplicationLeaseOpenResult.Failed(
                    root.Error);
            }

            application = OpenProtectedFileForRead(
                root.Lease,
                applicationRelativePath,
                ProtectedDirectoryInspectionPolicy.InstalledRelease);
            if (!application.Success || application.Lease is null)
            {
                return ProtectedInstalledApplicationLeaseOpenResult.Failed(
                    application.Error);
            }

            var lease = new ProtectedInstalledApplicationLaunchLease(
                parent.Lease,
                root.Lease,
                application.Lease);
            parent = default;
            root = default;
            application = default;
            if (!lease.Revalidate())
            {
                lease.Dispose();
                return ProtectedInstalledApplicationLeaseOpenResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            return ProtectedInstalledApplicationLeaseOpenResult.Opened(
                lease);
        }
        finally
        {
            application.Dispose();
            root.Dispose();
            parent.Dispose();
        }
    }

    internal ProtectedDirectoryEnumerationOpenResult
        EnumerateProtectedDirectory(
            ProtectedDirectoryInspectionLease directory,
            ProtectedDirectoryInspectionPolicy policy,
            int maximumEntries)
    {
        if (directory is null
            || policy is null
            || maximumEntries < 0
            || !policy.IsValidRoot(
                directory.SecurityDescriptor))
        {
            return ProtectedDirectoryEnumerationOpenResult.Failed(
                ProtectedAclError.InvalidPath);
        }

        RelativePinnedHandleSet? set = null;
        ProtectedLeaseOwner? owner = null;
        var fileLeases =
            new List<ProtectedEnumeratedFileLease>();
        try
        {
            if (!directory.TryRetain(out var retention)
                || retention is null)
            {
                return ProtectedDirectoryEnumerationOpenResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            set = new RelativePinnedHandleSet(
                retention,
                directory.Handle,
                directory.Snapshot);
            var pending = new Stack<EnumerationDirectory>();
            pending.Push(new EnumerationDirectory(
                directory.Handle,
                directory.FinalPath,
                string.Empty));
            var files = new List<EnumerationFile>();
            var directories =
                new List<ProtectedEnumeratedDirectorySnapshot>();
            var count = 0;
            while (pending.Count > 0)
            {
                var current = pending.Pop();
                var enumerated = _native.EnumerateRelative(
                    current.Handle);
                if (!enumerated.Success
                    || enumerated.Entries is null)
                {
                    return ProtectedDirectoryEnumerationOpenResult.Failed(
                        enumerated.Error);
                }

                var names = new HashSet<string>(
                    StringComparer.OrdinalIgnoreCase);
                foreach (var entry in enumerated.Entries
                    .OrderBy(item => item.Name,
                        StringComparer.Ordinal))
                {
                    if (!IsSimpleRelativeName(entry.Name)
                        || !names.Add(entry.Name)
                        || entry.IsReparsePoint
                        || ++count > maximumEntries)
                    {
                        return ProtectedDirectoryEnumerationOpenResult.Failed(
                            ProtectedAclError.UnsafePath);
                    }

                    var relativePath = current.RelativePath.Length == 0
                        ? entry.Name
                        : $"{current.RelativePath}/{entry.Name}";
                    var expectedPath = Path.GetFullPath(
                        Path.Combine(
                            current.FinalPath,
                            entry.Name));
                    var opened = _native.OpenRelative(
                        current.Handle,
                        entry.Name,
                        ExistingRequest(entry.Kind));
                    if (!opened.Success || opened.Handle is null)
                    {
                        return ProtectedDirectoryEnumerationOpenResult.Failed(
                            opened.Error);
                    }

                    if (!set.TryAdd(
                            opened.Handle,
                            expectedPath,
                            entry.Kind,
                            created: false,
                            out var snapshot))
                    {
                        opened.Handle.Dispose();
                        return ProtectedDirectoryEnumerationOpenResult.Failed(
                            ProtectedAclError.UnsafePath);
                    }

                    var isDirectory = entry.Kind
                        == ProtectedAclNativeObjectKind.Directory;
                    if (!policy.IsValidDescendant(
                            snapshot.SecurityDescriptor,
                            isDirectory))
                    {
                        return ProtectedDirectoryEnumerationOpenResult.Failed(
                            ProtectedAclError.SecurityMismatch);
                    }

                    if (isDirectory)
                    {
                        directories.Add(
                            new ProtectedEnumeratedDirectorySnapshot(
                                relativePath,
                                snapshot.FinalPath,
                                snapshot.Identity,
                                snapshot.SecurityDescriptor.ToArray()));
                        pending.Push(new EnumerationDirectory(
                            opened.Handle,
                            snapshot.FinalPath,
                            relativePath));
                    }
                    else
                    {
                        files.Add(new EnumerationFile(
                            relativePath,
                            opened.Handle,
                            snapshot));
                    }
                }
            }

            if (!RevalidateRelativeSet(set, policy))
            {
                return ProtectedDirectoryEnumerationOpenResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            var completed = set;
            set = null;
            owner = new ProtectedLeaseOwner(
                completed,
                () => RevalidateRelativeSet(
                    completed,
                    policy));
            foreach (var file in files
                .OrderBy(item => item.RelativePath,
                    StringComparer.Ordinal))
            {
                if (!owner.TryRetain(out var fileRetention)
                    || fileRetention is null)
                {
                    return ProtectedDirectoryEnumerationOpenResult.Failed(
                        ProtectedAclError.UnsafePath);
                }

                var fileOwner = new ProtectedLeaseOwner(
                    fileRetention,
                    fileRetention.Revalidate);
                FileStream stream;
                try
                {
                    stream = file.Handle.OpenFileStream(
                        FileAccess.Read);
                }
                catch
                {
                    fileOwner.Release();
                    throw;
                }

                fileLeases.Add(
                    new ProtectedEnumeratedFileLease(
                        file.RelativePath,
                        new ProtectedFileReadLease(
                            fileOwner,
                            stream,
                            file.Snapshot)));
            }

            var orderedDirectories = directories
                .OrderByDescending(item =>
                    item.RelativePath.Count(character =>
                        character == '/'))
                .ThenBy(item => item.RelativePath,
                    StringComparer.Ordinal)
                .ToArray();
            var enumerationOwner = owner;
            owner = null;
            return ProtectedDirectoryEnumerationOpenResult.Opened(
                new ProtectedDirectoryEnumerationLease(
                    enumerationOwner,
                    fileLeases.ToArray(),
                    orderedDirectories));
        }
        catch (Exception exception) when (
            IsAccessFailure(exception)
            || IsIoFailure(exception))
        {
            return ProtectedDirectoryEnumerationOpenResult.Failed(
                IsAccessFailure(exception)
                    ? ProtectedAclError.AccessDenied
                    : ProtectedAclError.IoFailure);
        }
        finally
        {
            if (owner is not null)
            {
                foreach (var file in fileLeases)
                {
                    file.Dispose();
                }

                owner.Release();
            }

            set?.Dispose();
        }
    }

    private static bool RevalidateRelativeSet(
        RelativePinnedHandleSet set,
        ProtectedDirectoryInspectionPolicy policy)
    {
        if (!set.Revalidate())
        {
            return false;
        }

        foreach (var entry in set.Entries)
        {
            if (!TryReadValidSnapshot(
                    entry.Handle,
                    entry.ExpectedPath,
                    entry.Kind,
                    entry.Snapshot.Identity,
                    out var snapshot)
                || !policy.IsValidDescendant(
                    snapshot.SecurityDescriptor,
                    directory: entry.Kind
                        == ProtectedAclNativeObjectKind.Directory))
            {
                return false;
            }
        }

        return true;
    }

    private static bool TrySplitRelativePath(
        string relativePath,
        out string[] segments)
    {
        segments = [];
        if (string.IsNullOrWhiteSpace(relativePath)
            || Path.IsPathRooted(relativePath)
            || relativePath.IndexOf(':') >= 0)
        {
            return false;
        }

        segments = relativePath.Split(
            [Path.DirectorySeparatorChar,
             Path.AltDirectorySeparatorChar],
            StringSplitOptions.None);
        return segments.Length > 0
            && segments.All(IsSimpleRelativeName);
    }

    private static bool IsSimpleRelativeName(string name) =>
        name.Length > 0
        && name is not ("." or "..")
        && name.IndexOfAny(
            ['\\', '/', ':', '\0']) < 0;

    private sealed record EnumerationDirectory(
        IProtectedAclNativeHandle Handle,
        string FinalPath,
        string RelativePath);

    private sealed record EnumerationFile(
        string RelativePath,
        IProtectedAclNativeHandle Handle,
        ProtectedAclNativeSnapshot Snapshot);

    internal ProtectedFileMutationResult CreateProtectedFileIfAbsent(
        string? path,
        ReadOnlyMemory<byte> replacementBytes)
    {
        if (!TryCanonicalLocalPath(path, out var canonicalPath)
            || !TryGetParentAndLeaf(
                canonicalPath,
                out var parentPath,
                out var leafName))
        {
            return ProtectedFileMutationResult.Failed(
                ProtectedAclError.InvalidPath);
        }

        using var parent = InspectProtectedDirectoryForMutation(
            parentPath);
        if (!parent.Success || parent.Lease is null)
        {
            return ProtectedFileMutationResult.Failed(
                parent.Error);
        }

        var existing = _native.OpenRelative(
            parent.Lease.Handle,
            leafName,
            ExistingRequest(
                ProtectedAclNativeObjectKind.File));
        if (existing.Success && existing.Handle is not null)
        {
            existing.Handle.Dispose();
            return ProtectedFileMutationResult.Conflict(
                ProtectedAclError.AlreadyExists);
        }

        if (existing.Error != ProtectedAclError.Missing)
        {
            return ProtectedFileMutationResult.Conflict(
                existing.Error);
        }

        ProtectedWrittenTemp? temporary = null;
        var renamed = false;
        try
        {
            if (!TryCreateWrittenTemp(
                    parent.Lease,
                    replacementBytes,
                    out temporary,
                    out var error)
                || temporary is null)
            {
                return ProtectedFileMutationResult.Failed(error);
            }

            if (!parent.Lease.Revalidate())
            {
                return ProtectedFileMutationResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            var committed = _native.RenameRelative(
                temporary.Handle,
                parent.Lease.Handle,
                leafName,
                replaceIfExists: false);
            renamed = committed.NamespaceChanged;
            if (!committed.Success)
            {
                return committed.Error
                        is ProtectedAclError.AlreadyExists
                            or ProtectedAclError.AccessDenied
                    ? ProtectedFileMutationResult.Conflict(
                        committed.Error)
                    : ProtectedFileMutationResult.Failed(
                        committed.Error);
            }

            renamed = true;
            using var verification = OpenProtectedFileForRead(
                parent.Lease,
                leafName,
                ProtectedDirectoryInspectionPolicy.Transaction);
            if (!verification.Success
                || verification.Lease is null
                || verification.Lease.Identity
                    != temporary.Snapshot.Identity
                || !verification.Lease.TryReadAllBytes(
                    replacementBytes.Length,
                    out var actual)
                || !actual.AsSpan().SequenceEqual(
                    replacementBytes.Span))
            {
                return ProtectedFileMutationResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            return ProtectedFileMutationResult.Committed(
                temporary.Snapshot.Identity);
        }
        finally
        {
            if (temporary is not null)
            {
                if (!renamed)
                {
                    _native.Delete(
                        temporary.Handle,
                        directory: false);
                }

                temporary.Handle.Dispose();
            }
        }
    }

    internal ProtectedFileCompareExchangeResult
        CompareExchangeProtectedFile(
            string? path,
            ProtectedFileIdentity128 expectedIdentity,
            ReadOnlyMemory<byte> expectedBytes,
            ReadOnlyMemory<byte> replacementBytes)
    {
        if (!expectedIdentity.IsValid
            || !TryCanonicalLocalPath(path, out var canonicalPath)
            || !TryGetParentAndLeaf(
                canonicalPath,
                out var parentPath,
                out var leafName))
        {
            return ProtectedFileCompareExchangeResult.Failed(
                ProtectedAclError.InvalidPath);
        }

        using var parent = InspectProtectedDirectoryForMutation(
            parentPath);
        if (!parent.Success || parent.Lease is null)
        {
            return ProtectedFileCompareExchangeResult.Failed(
                parent.Error);
        }

        IProtectedAclNativeHandle? destination = null;
        FileStream? destinationStream = null;
        ProtectedWrittenTemp? temporary = null;
        var renamed = false;
        try
        {
            var opened = _native.OpenRelative(
                parent.Lease.Handle,
                leafName,
                ExistingRequest(
                    ProtectedAclNativeObjectKind.File));
            if (!opened.Success || opened.Handle is null)
            {
                return opened.Error == ProtectedAclError.Missing
                    ? ProtectedFileCompareExchangeResult.Conflict()
                    : ProtectedFileCompareExchangeResult.Failed(
                        opened.Error);
            }

            destination = opened.Handle;
            if (!TryReadValidSnapshot(
                    destination,
                    canonicalPath,
                    ProtectedAclNativeObjectKind.File,
                    expectedIdentity,
                    out var destinationSnapshot)
                || !ProtectedDirectoryInspectionPolicy.Transaction
                    .IsValidDescendant(
                        destinationSnapshot.SecurityDescriptor,
                        directory: false))
            {
                return ProtectedFileCompareExchangeResult.Conflict();
            }

            destinationStream = destination.OpenFileStream(
                FileAccess.Read);
            if (!TryReadExactBytes(
                    destinationStream,
                    expectedBytes.Span))
            {
                return ProtectedFileCompareExchangeResult.Conflict();
            }

            if (!TryCreateWrittenTemp(
                    parent.Lease,
                    replacementBytes,
                    out temporary,
                    out var temporaryError)
                || temporary is null)
            {
                return ProtectedFileCompareExchangeResult.Failed(
                    temporaryError);
            }

            if (!TryReadValidSnapshot(
                    destination,
                    canonicalPath,
                    ProtectedAclNativeObjectKind.File,
                    expectedIdentity,
                    out destinationSnapshot)
                || !ProtectedDirectoryInspectionPolicy.Transaction
                    .IsValidDescendant(
                        destinationSnapshot.SecurityDescriptor,
                        directory: false)
                || !TryReadExactBytes(
                    destinationStream,
                    expectedBytes.Span)
                || !parent.Lease.Revalidate())
            {
                return ProtectedFileCompareExchangeResult.Conflict();
            }

            if (!parent.Lease.Revalidate())
            {
                return ProtectedFileCompareExchangeResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            var committed = _native.RenameRelative(
                temporary.Handle,
                parent.Lease.Handle,
                leafName,
                replaceIfExists: true);
            renamed = committed.NamespaceChanged;
            if (!committed.Success)
            {
                return committed.Error
                        is ProtectedAclError.Missing
                            or ProtectedAclError.AlreadyExists
                    ? ProtectedFileCompareExchangeResult.Conflict()
                    : ProtectedFileCompareExchangeResult.Failed(
                        committed.Error);
            }

            renamed = true;
            using var verification = OpenProtectedFileForRead(
                parent.Lease,
                leafName,
                ProtectedDirectoryInspectionPolicy.Transaction);
            if (!verification.Success
                || verification.Lease is null
                || verification.Lease.Identity
                    != temporary.Snapshot.Identity
                || !verification.Lease.TryReadAllBytes(
                    replacementBytes.Length,
                    out var actual)
                || !actual.AsSpan().SequenceEqual(
                    replacementBytes.Span))
            {
                return ProtectedFileCompareExchangeResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            return ProtectedFileCompareExchangeResult.Committed(
                temporary.Snapshot.Identity);
        }
        catch (Exception exception) when (
            IsAccessFailure(exception)
            || IsIoFailure(exception))
        {
            return ProtectedFileCompareExchangeResult.Failed(
                IsAccessFailure(exception)
                    ? ProtectedAclError.AccessDenied
                    : ProtectedAclError.IoFailure);
        }
        finally
        {
            destinationStream?.Dispose();
            destination?.Dispose();
            if (temporary is not null)
            {
                if (!renamed)
                {
                    _native.Delete(
                        temporary.Handle,
                        directory: false);
                }

                temporary.Handle.Dispose();
            }
        }
    }

    internal ProtectedFileMutationResult DeleteProtectedFile(
        string? path,
        ProtectedFileIdentity128 expectedIdentity) =>
        DeleteProtectedObject(
            path,
            expectedIdentity,
            ProtectedAclNativeObjectKind.File);

    internal ProtectedFileMutationResult DeleteProtectedDirectory(
        string? path,
        ProtectedFileIdentity128 expectedIdentity) =>
        DeleteProtectedObject(
            path,
            expectedIdentity,
            ProtectedAclNativeObjectKind.Directory);

    private ProtectedFileMutationResult DeleteProtectedObject(
        string? path,
        ProtectedFileIdentity128 expectedIdentity,
        ProtectedAclNativeObjectKind kind)
    {
        if (!expectedIdentity.IsValid
            || !TryCanonicalLocalPath(path, out var canonicalPath)
            || !TryGetParentAndLeaf(
                canonicalPath,
                out var parentPath,
                out var leafName))
        {
            return ProtectedFileMutationResult.Failed(
                ProtectedAclError.InvalidPath);
        }

        using var parent = InspectProtectedDirectoryForMutation(
            parentPath);
        if (!parent.Success || parent.Lease is null)
        {
            return ProtectedFileMutationResult.Failed(
                parent.Error);
        }

        var request = ExistingRequest(kind) with
        {
            RequireDeleteAccess = true
        };
        var opened = _native.OpenRelative(
            parent.Lease.Handle,
            leafName,
            request);
        if (!opened.Success || opened.Handle is null)
        {
            return opened.Error == ProtectedAclError.Missing
                ? ProtectedFileMutationResult.Conflict(
                    ProtectedAclError.Missing)
                : ProtectedFileMutationResult.Failed(
                    opened.Error);
        }

        var target = opened.Handle;
        try
        {
            if (!TryReadValidSnapshot(
                    target,
                    canonicalPath,
                    kind,
                    expectedIdentity,
                    out var snapshot))
            {
                return ProtectedFileMutationResult.Conflict();
            }

            if (!ProtectedDirectoryInspectionPolicy.Transaction
                    .IsValidDescendant(
                        snapshot.SecurityDescriptor,
                        directory: kind
                            == ProtectedAclNativeObjectKind.Directory))
            {
                return ProtectedFileMutationResult.Failed(
                    ProtectedAclError.SecurityMismatch);
            }

            if (kind == ProtectedAclNativeObjectKind.Directory)
            {
                var children = _native.EnumerateRelative(target);
                if (!children.Success
                    || children.Entries is null)
                {
                    return ProtectedFileMutationResult.Failed(
                        children.Error);
                }

                if (children.Entries.Count != 0)
                {
                    return ProtectedFileMutationResult.Conflict();
                }
            }

            if (!parent.Lease.Revalidate()
                || !TryReadValidSnapshot(
                    target,
                    canonicalPath,
                    kind,
                    expectedIdentity,
                    out _))
            {
                return ProtectedFileMutationResult.Conflict();
            }

            var deleted = _native.Delete(
                target,
                directory: kind
                    == ProtectedAclNativeObjectKind.Directory);
            if (!deleted.Success)
            {
                return ProtectedFileMutationResult.Failed(
                    deleted.Error);
            }
        }
        finally
        {
            target.Dispose();
        }

        if (!parent.Lease.Revalidate())
        {
            return ProtectedFileMutationResult.Failed(
                ProtectedAclError.UnsafePath);
        }

        var flushed = _native.FlushDirectory(
            parent.Lease.Handle);
        if (!flushed.Success)
        {
            return ProtectedFileMutationResult.Failed(
                flushed.Error);
        }

        var post = _native.OpenRelative(
            parent.Lease.Handle,
            leafName,
            ExistingRequest(kind));
        if (post.Success && post.Handle is not null)
        {
            post.Handle.Dispose();
            return ProtectedFileMutationResult.Failed(
                ProtectedAclError.UnsafePath);
        }

        return post.Error == ProtectedAclError.Missing
            ? ProtectedFileMutationResult.Committed()
            : ProtectedFileMutationResult.Failed(post.Error);
    }

    private bool TryCreateWrittenTemp(
        ProtectedDirectoryInspectionLease parent,
        ReadOnlyMemory<byte> bytes,
        out ProtectedWrittenTemp? temporary,
        out ProtectedAclError error)
    {
        temporary = null;
        error = ProtectedAclError.IoFailure;
        using var privilege = _acquireRestorePrivilege();
        if (privilege is null)
        {
            error = ProtectedAclError.PrivilegeUnavailable;
            return false;
        }

        for (var attempt = 0; attempt < 8; attempt++)
        {
            if (!parent.Revalidate())
            {
                error = ProtectedAclError.UnsafePath;
                return false;
            }

            var name = $".wgst-{Guid.NewGuid():N}.tmp";
            var expectedPath = Path.GetFullPath(
                Path.Combine(parent.FinalPath, name));
            var created = _native.OpenRelative(
                parent.Handle,
                name,
                CreateRequest(
                    ProtectedAclNativeObjectKind.File,
                    BuildFileSecurity()
                        .GetSecurityDescriptorBinaryForm()));
            if (!created.Success || created.Handle is null)
            {
                if (created.Error == ProtectedAclError.AlreadyExists)
                {
                    continue;
                }

                error = created.Error;
                return false;
            }

            var handle = created.Handle;
            var owned = true;
            try
            {
                if (!TryReadValidSnapshot(
                        handle,
                        expectedPath,
                        ProtectedAclNativeObjectKind.File,
                        expectedIdentity: null,
                        out var snapshot)
                    || snapshot.Identity.VolumeSerialNumber
                        != parent.Identity.VolumeSerialNumber
                    || !ProtectedDirectoryInspectionPolicy.Transaction
                        .IsValidDescendant(
                            snapshot.SecurityDescriptor,
                            directory: false)
                    || !parent.Revalidate())
                {
                    error = ProtectedAclError.UnsafePath;
                    return false;
                }

                using (var stream = handle.OpenFileStream(
                    FileAccess.ReadWrite))
                {
                    stream.SetLength(0);
                    stream.Write(bytes.Span);
                    stream.Flush(flushToDisk: true);
                    if (!TryReadExactBytes(stream, bytes.Span))
                    {
                        error = ProtectedAclError.IoFailure;
                        return false;
                    }
                }

                if (!TryReadValidSnapshot(
                        handle,
                        expectedPath,
                        ProtectedAclNativeObjectKind.File,
                        snapshot.Identity,
                        out var flushedSnapshot)
                    || !ProtectedDirectoryInspectionPolicy.Transaction
                        .IsValidDescendant(
                            flushedSnapshot.SecurityDescriptor,
                            directory: false)
                    || !parent.Revalidate())
                {
                    error = ProtectedAclError.UnsafePath;
                    return false;
                }

                temporary = new ProtectedWrittenTemp(
                    handle,
                    name,
                    flushedSnapshot);
                owned = false;
                error = ProtectedAclError.None;
                return true;
            }
            catch (Exception exception) when (
                IsAccessFailure(exception)
                || IsIoFailure(exception))
            {
                error = IsAccessFailure(exception)
                    ? ProtectedAclError.AccessDenied
                    : ProtectedAclError.IoFailure;
                return false;
            }
            finally
            {
                if (owned)
                {
                    _native.Delete(handle, directory: false);
                    handle.Dispose();
                }
            }
        }

        error = ProtectedAclError.AlreadyExists;
        return false;
    }

    private static bool TryReadExactBytes(
        FileStream stream,
        ReadOnlySpan<byte> expected)
    {
        try
        {
            if (stream.Length != expected.Length)
            {
                return false;
            }

            stream.Position = 0;
            var buffer = new byte[expected.Length];
            stream.ReadExactly(buffer);
            return stream.ReadByte() == -1
                && stream.Length == expected.Length
                && buffer.AsSpan().SequenceEqual(expected);
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or NotSupportedException
                or ObjectDisposedException)
        {
            return false;
        }
    }

    private sealed record ProtectedWrittenTemp(
        IProtectedAclNativeHandle Handle,
        string Name,
        ProtectedAclNativeSnapshot Snapshot);
    private PinnedChainOpenResult OpenPinnedChain(
        string canonicalPath,
        ProtectedAclNativeObjectKind leafKind,
        bool leafWriteAccess = false)
    {
        if (!TrySplitCanonicalPath(
                canonicalPath,
                out var rootPath,
                out var components))
        {
            return PinnedChainOpenResult.Failed(
                ProtectedAclError.InvalidPath);
        }

        try
        {
            var rootOpened = _native.OpenRoot(
                rootPath,
                openReparsePoint: true,
                shareDelete: false);
            if (!rootOpened.Success || rootOpened.Handle is null)
            {
                return PinnedChainOpenResult.Failed(
                    rootOpened.Error);
            }

            var chain = new PinnedHandleChain();
            if (!chain.TryAdd(
                    rootOpened.Handle,
                    rootPath,
                    ProtectedAclNativeObjectKind.Directory))
            {
                rootOpened.Handle.Dispose();
                chain.Dispose();
                return PinnedChainOpenResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            var currentPath = rootPath;
            for (var index = 0; index < components.Length; index++)
            {
                var kind = index == components.Length - 1
                    ? leafKind
                    : ProtectedAclNativeObjectKind.Directory;
                var request = ExistingRequest(kind);
                if (leafWriteAccess
                    && index == components.Length - 1)
                {
                    request = request with
                    {
                        RequireWriteAccess = true
                    };
                }

                var opened = _native.OpenRelative(
                    chain.LeafHandle,
                    components[index],
                    request);

                if (!opened.Success || opened.Handle is null)
                {
                    chain.Dispose();
                    return PinnedChainOpenResult.Failed(
                        opened.Error);
                }

                currentPath = Path.GetFullPath(
                    Path.Combine(
                        currentPath,
                        components[index]));
                if (!chain.TryAdd(
                        opened.Handle,
                        currentPath,
                        kind))
                {
                    opened.Handle.Dispose();
                    chain.Dispose();
                    return PinnedChainOpenResult.Failed(
                        ProtectedAclError.UnsafePath);
                }
            }

            return PinnedChainOpenResult.Opened(chain);
        }
        catch (Exception exception) when (
            IsAccessFailure(exception)
            || IsIoFailure(exception))
        {
            return PinnedChainOpenResult.Failed(
                IsAccessFailure(exception)
                    ? ProtectedAclError.AccessDenied
                    : ProtectedAclError.IoFailure);
        }
    }

    private static ProtectedAclNativeOpenRequest ExistingRequest(
        ProtectedAclNativeObjectKind kind) =>
        new(
            kind,
            ProtectedAclNativeDisposition.OpenExisting,
            OpenReparsePoint: true,
            ShareDelete: false,
            SecurityDescriptor: null);

    private static ProtectedAclNativeOpenRequest CreateRequest(
        ProtectedAclNativeObjectKind kind,
        byte[] securityDescriptor) =>
        new(
            kind,
            ProtectedAclNativeDisposition.CreateNew,
            OpenReparsePoint: true,
            ShareDelete: false,
            securityDescriptor);

    private static bool TrySplitCanonicalPath(
        string path,
        out string root,
        out string[] components)
    {
        root = Path.GetPathRoot(path) ?? string.Empty;
        components = [];
        if (root.Length == 0
            || !Path.IsPathFullyQualified(path))
        {
            return false;
        }

        components = path[root.Length..]
            .Split(
                [Path.DirectorySeparatorChar,
                 Path.AltDirectorySeparatorChar],
                StringSplitOptions.RemoveEmptyEntries);
        return components.All(component =>
            component is not ("." or "..")
            && component.IndexOfAny(
                [Path.DirectorySeparatorChar,
                 Path.AltDirectorySeparatorChar]) < 0);
    }

    private static bool TryGetParentAndLeaf(
        string path,
        out string parent,
        out string leaf)
    {
        parent = Path.GetDirectoryName(path) ?? string.Empty;
        leaf = Path.GetFileName(path);
        return parent.Length != 0
            && leaf.Length != 0
            && leaf is not ("." or "..");
    }

    private static bool TryReadValidSnapshot(
        IProtectedAclNativeHandle handle,
        string expectedPath,
        ProtectedAclNativeObjectKind expectedKind,
        ProtectedFileIdentity128? expectedIdentity,
        out ProtectedAclNativeSnapshot snapshot)
    {
        snapshot = null!;
        try
        {
            snapshot = handle.ReadSnapshot();
            return snapshot.SecurityDescriptor is { Length: > 0 }
                && snapshot.Identity.IsValid
                && !snapshot.IsReparsePoint
                && snapshot.IsDirectory
                    == (expectedKind
                        == ProtectedAclNativeObjectKind.Directory)
                && string.Equals(
                    Path.GetFullPath(snapshot.FinalPath),
                    Path.GetFullPath(expectedPath),
                    StringComparison.OrdinalIgnoreCase)
                && (expectedIdentity is null
                    || snapshot.Identity == expectedIdentity.Value);
        }
        catch (Exception exception) when (
            IsAccessFailure(exception)
            || IsIoFailure(exception))
        {
            snapshot = null!;
            return false;
        }
    }

    private static bool HasExactNativeDescriptor(
        byte[] descriptor,
        bool directory)
    {
        try
        {
            FileSystemSecurity security = directory
                ? new DirectorySecurity()
                : new FileSecurity();
            security.SetSecurityDescriptorBinaryForm(descriptor);
            return directory
                ? HasExactDirectoryDescriptor(security)
                : HasExactFileDescriptor(security);
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or InvalidOperationException
                or SecurityException)
        {
            return false;
        }
    }


    internal static bool HasExactProtectedDescriptor(
        byte[] descriptor,
        bool directory) =>
        HasExactNativeDescriptor(descriptor, directory);

    internal static bool HasTrustedInstallParentDescriptor(
        byte[] descriptorBytes)
    {
        const int dangerousMask =
            0x00000002
            | 0x00000004
            | 0x00000040
            | 0x00010000
            | 0x00040000
            | 0x00080000
            | 0x10000000
            | 0x40000000;
        try
        {
            var security = new DirectorySecurity();
            security.SetSecurityDescriptorBinaryForm(
                descriptorBytes);
            if (!security.AreAccessRulesProtected
                || !security.AreAccessRulesCanonical)
            {
                return false;
            }

            var descriptor = new RawSecurityDescriptor(
                descriptorBytes,
                offset: 0);
            if ((descriptor.ControlFlags
                    & ControlFlags.DiscretionaryAclProtected) == 0
                || (descriptor.ControlFlags
                    & ControlFlags.DiscretionaryAclPresent) == 0
                || descriptor.Owner
                    is not SecurityIdentifier owner
                || !IsTrustedInstallAuthority(owner)
                || descriptor.DiscretionaryAcl is null)
            {
                return false;
            }

            foreach (GenericAce genericAce
                in descriptor.DiscretionaryAcl)
            {
                if (genericAce is not CommonAce ace
                    || ace.IsCallback
                    || ace.OpaqueLength != 0
                    || ace.AceQualifier is not (
                        AceQualifier.AccessAllowed
                            or AceQualifier.AccessDenied)
                    || ace.SecurityIdentifier
                        is not SecurityIdentifier identity)
                {
                    return false;
                }

                if ((ace.AceFlags & AceFlags.InheritOnly) != 0)
                {
                    continue;
                }

                if (ace.AceQualifier
                        == AceQualifier.AccessAllowed
                    && !IsTrustedInstallAuthority(identity)
                    && (ace.AccessMask & dangerousMask) != 0)
                {
                    return false;
                }
            }

            return true;
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or IdentityNotMappedException
                or InvalidOperationException
                or SecurityException)
        {
            return false;
        }
    }

    private static bool IsTrustedInstallAuthority(
        SecurityIdentifier identity) =>
        LocalSystem.Equals(identity)
        || Administrators.Equals(identity)
        || TrustedInstaller.Equals(identity);

    internal static bool HasExactInstalledRootDescriptor(
        byte[] descriptor) =>
        HasExactInstalledDescriptor(
            descriptor,
            directory: true,
            root: true);

    internal static bool HasExactInstalledDescendantDescriptor(
        byte[] descriptor,
        bool directory) =>
        HasExactInstalledDescriptor(
            descriptor,
            directory,
            root: false);

    private static bool HasExactInstalledDescriptor(
        byte[] descriptorBytes,
        bool directory,
        bool root)
    {
        try
        {
            FileSystemSecurity security = directory
                ? new DirectorySecurity()
                : new FileSecurity();
            security.SetSecurityDescriptorBinaryForm(
                descriptorBytes);
            if (!LocalSystem.Equals(
                    security.GetOwner(
                        typeof(SecurityIdentifier)))
                || security.AreAccessRulesProtected != root
                || !security.AreAccessRulesCanonical)
            {
                return false;
            }

            var descriptor = new RawSecurityDescriptor(
                descriptorBytes,
                offset: 0);
            if (descriptor.Owner
                    is not SecurityIdentifier owner
                || !LocalSystem.Equals(owner)
                || descriptor.DiscretionaryAcl is null
                || descriptor.DiscretionaryAcl.Count != 3
                || (descriptor.ControlFlags
                    & ControlFlags.DiscretionaryAclPresent) == 0
                || ((descriptor.ControlFlags
                        & ControlFlags.DiscretionaryAclProtected) != 0)
                    != root)
            {
                return false;
            }

            var expectedFlags = root
                ? AceFlags.ContainerInherit
                    | AceFlags.ObjectInherit
                : directory
                    ? AceFlags.ContainerInherit
                        | AceFlags.ObjectInherit
                        | AceFlags.Inherited
                    : AceFlags.Inherited;
            var expectedRights = new Dictionary<string, int>(
                StringComparer.Ordinal)
            {
                [Administrators.Value] =
                    (int)FileSystemRights.FullControl,
                [LocalSystem.Value] =
                    (int)FileSystemRights.FullControl,
                [BuiltinUsers.Value] =
                    (int)(FileSystemRights.ReadAndExecute
                        | FileSystemRights.Synchronize)
            };
            foreach (GenericAce genericAce
                in descriptor.DiscretionaryAcl)
            {
                if (genericAce is not CommonAce ace
                    || ace.IsCallback
                    || ace.AceQualifier
                        != AceQualifier.AccessAllowed
                    || ace.SecurityIdentifier
                        is not SecurityIdentifier identity
                    || ace.AceFlags != expectedFlags
                    || ace.OpaqueLength != 0
                    || !expectedRights.Remove(
                        identity.Value,
                        out var expectedMask)
                    || ace.AccessMask != expectedMask)
                {
                    return false;
                }
            }

            return expectedRights.Count == 0;
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or IdentityNotMappedException
                or InvalidOperationException
                or SecurityException)
        {
            return false;
        }
    }
    private static IDisposable? TryAcquireRestorePrivilege() =>
        WindowsRestorePrivilegeScope.TryEnable(out var scope)
            ? scope
            : null;

    private readonly record struct PinnedChainOpenResult(
        PinnedHandleChain? Chain,
        ProtectedAclError Error)
    {
        public bool Success => Chain is not null;

        public static PinnedChainOpenResult Opened(
            PinnedHandleChain chain) =>
            new(chain, ProtectedAclError.None);

        public static PinnedChainOpenResult Failed(
            ProtectedAclError error) =>
            new(null, error);
    }

    private sealed class PinnedHandleChain : IDisposable
    {
        private readonly List<PinnedHandleEntry> _entries = [];

        public IProtectedAclNativeHandle LeafHandle =>
            _entries[^1].Handle;

        public bool TryAdd(
            IProtectedAclNativeHandle handle,
            string expectedPath,
            ProtectedAclNativeObjectKind kind)
        {
            if (!TryReadValidSnapshot(
                    handle,
                    expectedPath,
                    kind,
                    expectedIdentity: null,
                    out var snapshot))
            {
                return false;
            }

            _entries.Add(new PinnedHandleEntry(
                handle,
                expectedPath,
                kind,
                snapshot.Identity));
            return true;
        }

        public bool Revalidate() =>
            _entries.All(entry =>
                TryReadValidSnapshot(
                    entry.Handle,
                    entry.ExpectedPath,
                    entry.Kind,
                    entry.Identity,
                    out _));

        public bool TryReadLeaf(
            out ProtectedAclNativeSnapshot snapshot)
        {
            var leaf = _entries[^1];
            return TryReadValidSnapshot(
                leaf.Handle,
                leaf.ExpectedPath,
                leaf.Kind,
                leaf.Identity,
                out snapshot);
        }

        public void Dispose()
        {
            for (var index = _entries.Count - 1;
                 index >= 0;
                 index--)
            {
                _entries[index].Handle.Dispose();
            }

            _entries.Clear();
        }
    }

    private sealed record PinnedHandleEntry(
        IProtectedAclNativeHandle Handle,
        string ExpectedPath,
        ProtectedAclNativeObjectKind Kind,
        ProtectedFileIdentity128 Identity);


    private sealed class RelativePinnedHandleSet : IDisposable
    {
        private readonly ProtectedLeaseRetention _rootRetention;
        private readonly List<RelativePinnedHandleEntry> _entries = [];

        public RelativePinnedHandleSet(
            ProtectedLeaseRetention rootRetention,
            IProtectedAclNativeHandle rootHandle,
            ProtectedAclNativeSnapshot rootSnapshot)
        {
            _rootRetention = rootRetention;
            RootHandle = rootHandle;
            RootSnapshot = rootSnapshot;
        }

        public IProtectedAclNativeHandle RootHandle { get; }
        public ProtectedAclNativeSnapshot RootSnapshot { get; }
        public IReadOnlyList<RelativePinnedHandleEntry> Entries =>
            _entries;
        public IProtectedAclNativeHandle LeafHandle =>
            _entries.Count == 0
                ? RootHandle
                : _entries[^1].Handle;
        public ProtectedAclNativeSnapshot LeafSnapshot =>
            _entries.Count == 0
                ? RootSnapshot
                : _entries[^1].Snapshot;

        public bool TryAdd(
            IProtectedAclNativeHandle handle,
            string expectedPath,
            ProtectedAclNativeObjectKind kind,
            bool created,
            out ProtectedAclNativeSnapshot snapshot)
        {
            if (!TryReadValidSnapshot(
                    handle,
                    expectedPath,
                    kind,
                    expectedIdentity: null,
                    out snapshot)
                || snapshot.Identity.VolumeSerialNumber
                    != RootSnapshot.Identity.VolumeSerialNumber)
            {
                return false;
            }

            _entries.Add(new RelativePinnedHandleEntry(
                handle,
                expectedPath,
                kind,
                snapshot,
                created));
            return true;
        }

        public bool Revalidate() =>
            _rootRetention.Revalidate()
            && _entries.All(entry =>
                TryReadValidSnapshot(
                    entry.Handle,
                    entry.ExpectedPath,
                    entry.Kind,
                    entry.Snapshot.Identity,
                    out _));

        public void CleanupCreatedDirectories(
            IProtectedAclNativeFileSystem native)
        {
            for (var index = _entries.Count - 1;
                 index >= 0;
                 index--)
            {
                var entry = _entries[index];
                if (!entry.Created
                    || entry.Kind
                        != ProtectedAclNativeObjectKind.Directory)
                {
                    continue;
                }

                native.Delete(entry.Handle, directory: true);
                entry.Handle.Dispose();
            }
        }

        public void Dispose()
        {
            for (var index = _entries.Count - 1;
                 index >= 0;
                 index--)
            {
                _entries[index].Handle.Dispose();
            }

            _entries.Clear();
            _rootRetention.Dispose();
        }
    }

    private sealed record RelativePinnedHandleEntry(
        IProtectedAclNativeHandle Handle,
        string ExpectedPath,
        ProtectedAclNativeObjectKind Kind,
        ProtectedAclNativeSnapshot Snapshot,
        bool Created);
    private sealed class NoopDisposable : IDisposable
    {
        public static NoopDisposable Instance { get; } = new();

        public void Dispose()
        {
        }
    }

    private bool TryCanonicalLocalPath(
        string? path,
        out string canonicalPath)
    {
        canonicalPath = string.Empty;
        if (!WindowsLocalPath.TryGetCanonicalLocalDosPath(
                path,
                _getDriveType,
                out var result)
            || result is null)
        {
            return false;
        }

        canonicalPath = result;
        return true;
    }

    private static bool HasExactDescriptor(
        FileSystemSecurity? security,
        InheritanceFlags expectedInheritance)
    {
        if (security is null
            || !security.AreAccessRulesProtected
            || !security.AreAccessRulesCanonical)
        {
            return false;
        }

        try
        {
            if (!LocalSystem.Equals(
                    security.GetOwner(
                        typeof(SecurityIdentifier))))
            {
                return false;
            }

            var descriptorBytes =
                security.GetSecurityDescriptorBinaryForm();
            var descriptor = new RawSecurityDescriptor(
                descriptorBytes,
                offset: 0);
            if ((descriptor.ControlFlags
                    & ControlFlags.DiscretionaryAclProtected) == 0
                || (descriptor.ControlFlags
                    & ControlFlags.DiscretionaryAclPresent) == 0
                || descriptor.DiscretionaryAcl is null
                || descriptor.DiscretionaryAcl.Count != 2
                || descriptor.Owner is not SecurityIdentifier owner
                || !LocalSystem.Equals(owner))
            {
                return false;
            }

            if (expectedInheritance
                    is not InheritanceFlags.None
                && expectedInheritance
                    != (InheritanceFlags.ContainerInherit
                        | InheritanceFlags.ObjectInherit))
            {
                return false;
            }

            var expectedFlags = expectedInheritance switch
            {
                InheritanceFlags.None => AceFlags.None,
                _ => AceFlags.ContainerInherit
                    | AceFlags.ObjectInherit
            };
            var identities = new HashSet<string>(
                StringComparer.Ordinal);
            foreach (GenericAce genericAce
                in descriptor.DiscretionaryAcl)
            {
                if (genericAce is not CommonAce ace
                    || ace.IsCallback
                    || ace.AceQualifier
                        != AceQualifier.AccessAllowed
                    || ace.AccessMask
                        != (int)FileSystemRights.FullControl
                    || ace.AceFlags != expectedFlags
                    || ace.OpaqueLength != 0
                    || ace.SecurityIdentifier
                        is not SecurityIdentifier identity)
                {
                    return false;
                }

                identities.Add(identity.Value);
            }

            return identities.Count == 2
                && identities.Contains(Administrators.Value)
                && identities.Contains(LocalSystem.Value);
        }
        catch (Exception exception) when (
            exception is IdentityNotMappedException
                or InvalidOperationException
                or ArgumentException
                or SecurityException)
        {
            return false;
        }
    }

    private static bool HasExpectedFinalPath(
        FileStream stream,
        string expectedPath)
    {
        const int maximumPathLength = 32768;
        var capacity = 512;
        while (capacity <= maximumPathLength)
        {
            var buffer = new StringBuilder(capacity);
            var length = GetFinalPathNameByHandle(
                stream.SafeFileHandle,
                buffer,
                (uint)buffer.Capacity,
                flags: 0);
            if (length == 0)
            {
                return false;
            }

            if (length < buffer.Capacity)
            {
                var finalPath = buffer.ToString();
                if (finalPath.StartsWith(
                        @"\\?\",
                        StringComparison.Ordinal))
                {
                    finalPath = finalPath[4..];
                }

                return string.Equals(
                    Path.GetFullPath(finalPath),
                    expectedPath,
                    StringComparison.OrdinalIgnoreCase);
            }

            capacity = checked((int)length + 1);
        }

        return false;
    }

    private static bool IsAccessFailure(Exception exception) =>
        exception is UnauthorizedAccessException
            or PrivilegeNotHeldException
            or SecurityException
            or Win32Exception;

    private static bool IsIoFailure(Exception exception) =>
        exception is IOException
            or ArgumentException
            or NotSupportedException
            or ObjectDisposedException;

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        StringBuilder filePath,
        uint filePathLength,
        uint flags);
}
internal sealed class ProtectedDirectoryInspectionLease : IDisposable
{
    private ProtectedLeaseOwner? _owner;
    private readonly IProtectedAclNativeHandle _handle;
    private readonly ProtectedAclNativeSnapshot _snapshot;

    internal ProtectedDirectoryInspectionLease(
        ProtectedLeaseOwner owner,
        IProtectedAclNativeHandle handle,
        ProtectedAclNativeSnapshot snapshot)
    {
        _owner = owner;
        _handle = handle;
        _snapshot = Clone(snapshot);
    }

    public string FinalPath => _snapshot.FinalPath;
    public ProtectedFileIdentity128 Identity => _snapshot.Identity;
    public byte[] SecurityDescriptor =>
        _snapshot.SecurityDescriptor.ToArray();

    internal IProtectedAclNativeHandle Handle => _handle;
    internal ProtectedAclNativeSnapshot Snapshot => Clone(_snapshot);

    internal bool TryRetain(
        out ProtectedLeaseRetention? retention)
    {
        var owner = Volatile.Read(ref _owner);
        retention = null;
        return owner is not null
            && owner.TryRetain(out retention);
    }

    public bool Revalidate()
    {
        var owner = Volatile.Read(ref _owner);
        return owner is not null && owner.Revalidate();
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _owner, null)?.Release();
    }

    private static ProtectedAclNativeSnapshot Clone(
        ProtectedAclNativeSnapshot snapshot) =>
        snapshot with
        {
            SecurityDescriptor =
                snapshot.SecurityDescriptor.ToArray()
        };
}

internal sealed class ProtectedFileReadLease : IDisposable
{
    private readonly object _gate = new();
    private ProtectedLeaseOwner? _owner;
    private FileStream? _stream;
    private readonly ProtectedAclNativeSnapshot _snapshot;

    internal ProtectedFileReadLease(
        ProtectedLeaseOwner owner,
        FileStream stream,
        ProtectedAclNativeSnapshot snapshot)
    {
        _owner = owner;
        _stream = stream;
        _snapshot = snapshot with
        {
            SecurityDescriptor =
                snapshot.SecurityDescriptor.ToArray()
        };
    }

    public string FinalPath => _snapshot.FinalPath;
    public ProtectedFileIdentity128 Identity => _snapshot.Identity;
    public byte[] SecurityDescriptor =>
        _snapshot.SecurityDescriptor.ToArray();

    public FileStream Stream
    {
        get
        {
            lock (_gate)
            {
                return _stream
                    ?? throw new ObjectDisposedException(
                        nameof(ProtectedFileReadLease));
            }
        }
    }

    public bool TryReadAllBytes(
        long maximumBytes,
        out byte[] bytes)
    {
        bytes = [];
        lock (_gate)
        {
            if (_owner is null
                || _stream is null
                || maximumBytes < 0
                || maximumBytes > int.MaxValue
                || !_owner.Revalidate())
            {
                return false;
            }

            try
            {
                var length = _stream.Length;
                if (length < 0
                    || length > maximumBytes
                    || length > int.MaxValue)
                {
                    return false;
                }

                _stream.Position = 0;
                bytes = new byte[(int)length];
                _stream.ReadExactly(bytes);
                if (_stream.ReadByte() != -1
                    || _stream.Length != length
                    || !_owner.Revalidate())
                {
                    bytes = [];
                    return false;
                }

                return true;
            }
            catch (Exception exception) when (
                exception is IOException
                    or UnauthorizedAccessException
                    or ObjectDisposedException
                    or NotSupportedException)
            {
                bytes = [];
                return false;
            }
        }
    }

    public bool Revalidate()
    {
        lock (_gate)
        {
            return _owner is not null
                && _stream is not null
                && _owner.Revalidate();
        }
    }

    public void Dispose()
    {
        ProtectedLeaseOwner? owner;
        FileStream? stream;
        lock (_gate)
        {
            owner = _owner;
            _owner = null;
            stream = _stream;
            _stream = null;
        }

        stream?.Dispose();
        owner?.Release();
    }
}

internal sealed class ProtectedInstalledApplicationLaunchLease
    : IDisposable
{
    private readonly object _gate = new();
    private ProtectedDirectoryInspectionLease? _parent;
    private ProtectedDirectoryInspectionLease? _root;
    private ProtectedFileReadLease? _application;

    internal ProtectedInstalledApplicationLaunchLease(
        ProtectedDirectoryInspectionLease parent,
        ProtectedDirectoryInspectionLease root,
        ProtectedFileReadLease application)
    {
        _parent = parent
            ?? throw new ArgumentNullException(nameof(parent));
        _root = root
            ?? throw new ArgumentNullException(nameof(root));
        _application = application
            ?? throw new ArgumentNullException(nameof(application));
        ApplicationPath = application.FinalPath;
    }

    public string ApplicationPath { get; }

    public bool Revalidate()
    {
        lock (_gate)
        {
            return _parent is not null
                && _root is not null
                && _application is not null
                && _parent.Revalidate()
                && _root.Revalidate()
                && _application.Revalidate();
        }
    }

    public void Dispose()
    {
        ProtectedDirectoryInspectionLease? parent;
        ProtectedDirectoryInspectionLease? root;
        ProtectedFileReadLease? application;
        lock (_gate)
        {
            parent = _parent;
            _parent = null;
            root = _root;
            _root = null;
            application = _application;
            _application = null;
        }

        application?.Dispose();
        root?.Dispose();
        parent?.Dispose();
    }
}

internal sealed class ProtectedEnumeratedFileLease : IDisposable
{
    private readonly ProtectedFileReadLease _file;

    internal ProtectedEnumeratedFileLease(
        string relativePath,
        ProtectedFileReadLease file)
    {
        RelativePath = relativePath;
        _file = file;
    }

    public string RelativePath { get; }
    public string FinalPath => _file.FinalPath;
    public ProtectedFileIdentity128 Identity => _file.Identity;
    public byte[] SecurityDescriptor => _file.SecurityDescriptor;
    public FileStream Stream => _file.Stream;

    public bool TryReadAllBytes(
        long maximumBytes,
        out byte[] bytes) =>
        _file.TryReadAllBytes(maximumBytes, out bytes);

    public bool Revalidate() => _file.Revalidate();

    public void Dispose() => _file.Dispose();
}

internal sealed record ProtectedEnumeratedDirectorySnapshot(
    string RelativePath,
    string FinalPath,
    ProtectedFileIdentity128 Identity,
    byte[] SecurityDescriptor);

internal sealed class ProtectedDirectoryEnumerationLease : IDisposable
{
    private ProtectedLeaseOwner? _owner;
    private IReadOnlyList<ProtectedEnumeratedFileLease> _files;

    internal ProtectedDirectoryEnumerationLease(
        ProtectedLeaseOwner owner,
        IReadOnlyList<ProtectedEnumeratedFileLease> files,
        IReadOnlyList<ProtectedEnumeratedDirectorySnapshot> directories)
    {
        _owner = owner;
        _files = files;
        Files = files;
        Directories = directories;
    }

    public IReadOnlyList<ProtectedEnumeratedFileLease> Files { get; }

    // Descendants only, ordered deepest-first for identity-bound cleanup.
    public IReadOnlyList<ProtectedEnumeratedDirectorySnapshot> Directories
    {
        get;
    }

    public bool Revalidate()
    {
        var owner = Volatile.Read(ref _owner);
        return owner is not null
            && owner.Revalidate()
            && Files.All(file => file.Revalidate());
    }

    public void Dispose()
    {
        var owner = Interlocked.Exchange(ref _owner, null);
        var files = Interlocked.Exchange(
            ref _files,
            Array.Empty<ProtectedEnumeratedFileLease>());
        foreach (var file in files)
        {
            file.Dispose();
        }

        owner?.Release();
    }
}

internal sealed class ProtectedLeaseOwner
{
    private readonly object _gate = new();
    private IDisposable? _resource;
    private Func<bool>? _revalidate;
    private int _referenceCount = 1;

    internal ProtectedLeaseOwner(
        IDisposable resource,
        Func<bool> revalidate)
    {
        _resource = resource;
        _revalidate = revalidate;
    }

    internal bool TryRetain(
        out ProtectedLeaseRetention? retention)
    {
        lock (_gate)
        {
            if (_referenceCount == 0)
            {
                retention = null;
                return false;
            }

            checked
            {
                _referenceCount++;
            }

            retention = new ProtectedLeaseRetention(this);
            return true;
        }
    }

    internal bool Revalidate()
    {
        Func<bool>? revalidate;
        lock (_gate)
        {
            if (_referenceCount == 0)
            {
                return false;
            }

            revalidate = _revalidate;
        }

        try
        {
            return revalidate?.Invoke() == true;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or InvalidOperationException
                or ObjectDisposedException
                or SecurityException)
        {
            return false;
        }
    }

    internal void Release()
    {
        IDisposable? resource = null;
        lock (_gate)
        {
            if (_referenceCount == 0)
            {
                return;
            }

            _referenceCount--;
            if (_referenceCount == 0)
            {
                resource = _resource;
                _resource = null;
                _revalidate = null;
            }
        }

        resource?.Dispose();
    }
}

internal sealed class ProtectedLeaseRetention : IDisposable
{
    private ProtectedLeaseOwner? _owner;

    internal ProtectedLeaseRetention(
        ProtectedLeaseOwner owner)
    {
        _owner = owner;
    }

    internal bool Revalidate() =>
        Volatile.Read(ref _owner)?.Revalidate()
            == true;

    public void Dispose() =>
        Interlocked.Exchange(ref _owner, null)?.Release();
}

internal sealed class WindowsProtectedAclNativeFileSystem
    : IProtectedAclNativeFileSystem
{
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint Win32FileFlagOpenReparsePoint = 0x00200000;
    private const uint ReadControl = 0x00020000;
    private const uint Synchronize = 0x00100000;
    private const uint GenericRead = 0x80000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint FileWriteData = 0x00000002;
    private const uint FileAddSubdirectory = 0x00000004;
    private const uint FileDeleteChild = 0x00000040;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileListDirectory = 0x00000001;
    private const uint FileTraverse = 0x00000020;
    private const uint FileDirectoryFile = 0x00000001;
    private const uint FileWriteThrough = 0x00000002;
    private const uint FileSynchronousIoNonAlert = 0x00000020;
    private const uint FileNonDirectoryFile = 0x00000040;
    private const uint NativeFileOpenReparsePoint = 0x00200000;
    private const uint FileOpen = 0x00000001;
    private const uint FileCreate = 0x00000002;
    private const uint ObjCaseInsensitive = 0x00000040;
    private const uint ObjDontReparse = 0x00001000;
    private const uint FileRenameReplaceIfExists = 0x00000001;
    private const uint FileRenamePosixSemantics = 0x00000002;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const int DirectoryBufferBytes = 64 * 1024;
    private const int DirectoryNextEntryOffset = 0;
    private const int DirectoryAttributesOffset = 56;
    private const int DirectoryNameLengthOffset = 60;
    private const int DirectoryNameOffset = 104;
    private const int FileDispositionInfo = 4;
    private const int FileRenameInfoEx = 22;
    private const int FileIdBothDirectoryInformation = 37;
    private const int StatusBufferOverflow =
        unchecked((int)0x80000005);
    private const int StatusNoMoreFiles =
        unchecked((int)0x80000006);
    private const int StatusObjectNameNotFound =
        unchecked((int)0xC0000034);
    private const int StatusObjectPathNotFound =
        unchecked((int)0xC000003A);
    private const int StatusObjectNameCollision =
        unchecked((int)0xC0000035);
    private const int StatusAccessDenied =
        unchecked((int)0xC0000022);
    private const int StatusPrivilegeNotHeld =
        unchecked((int)0xC0000061);
    private const int StatusReparsePointEncountered =
        unchecked((int)0xC000050B);
    private const int StatusFileIsADirectory =
        unchecked((int)0xC00000BA);
    private const int StatusNotADirectory =
        unchecked((int)0xC0000103);

    public ProtectedAclNativeOpenResult OpenRoot(
        string rootPath,
        bool openReparsePoint,
        bool shareDelete,
        bool requireWriteAccess = false)
    {
        if (!openReparsePoint || shareDelete)
        {
            return ProtectedAclNativeOpenResult.Failed(
                ProtectedAclError.UnsafePath);
        }

        var desiredAccess = GetRootDesiredAccess(
            requireWriteAccess);
        var handle = CreateFileW(
            rootPath,
            desiredAccess,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics
                | Win32FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            return ProtectedAclNativeOpenResult.Failed(
                MapWin32Error(error));
        }

        return ProtectedAclNativeOpenResult.Opened(
            new WindowsProtectedAclNativeHandle(handle));
    }

    internal static uint GetRootDesiredAccess(
        bool requireWriteAccess)
    {
        var desiredAccess = ReadControl
            | Synchronize
            | FileReadAttributes
            | FileListDirectory
            | FileTraverse;
        if (requireWriteAccess)
        {
            desiredAccess |= FileWriteData
                | FileAddSubdirectory
                | FileDeleteChild;
        }

        return desiredAccess;
    }

    public ProtectedAclNativeOpenResult OpenRelative(
        IProtectedAclNativeHandle parent,
        string name,
        ProtectedAclNativeOpenRequest request)
    {
        if (parent is not WindowsProtectedAclNativeHandle windowsParent
            || !IsSimpleLeafName(name)
            || !request.OpenReparsePoint
            || request.ShareDelete
            || request.Disposition
                == ProtectedAclNativeDisposition.CreateNew
                && request.SecurityDescriptor is not { Length: > 0 })
        {
            return ProtectedAclNativeOpenResult.Failed(
                ProtectedAclError.UnsafePath);
        }

        using var nativeName = new NativeUnicodeString(name);
        GCHandle descriptorPin = default;
        var parentAddRef = false;
        SafeFileHandle? parentHandle = null;
        try
        {
            var descriptorPointer = IntPtr.Zero;
            if (request.SecurityDescriptor is { Length: > 0 } descriptor)
            {
                descriptorPin = GCHandle.Alloc(
                    descriptor,
                    GCHandleType.Pinned);
                descriptorPointer = descriptorPin.AddrOfPinnedObject();
            }

            parentHandle = windowsParent.SafeHandle;
            parentHandle.DangerousAddRef(ref parentAddRef);
            var attributes = new ObjectAttributes
            {
                Length = Marshal.SizeOf<ObjectAttributes>(),
                RootDirectory = parentHandle.DangerousGetHandle(),
                ObjectName = nativeName.StructurePointer,
                Attributes = ObjCaseInsensitive | ObjDontReparse,
                SecurityDescriptor = descriptorPointer,
                SecurityQualityOfService = IntPtr.Zero
            };
            var desiredAccess = request.Disposition
                    == ProtectedAclNativeDisposition.CreateNew
                ? (uint)FileSystemRights.FullControl
                    | Synchronize
                : ReadControl
                    | Synchronize
                    | FileReadAttributes
                    | (request.Kind
                        == ProtectedAclNativeObjectKind.Directory
                        ? FileListDirectory | FileTraverse
                        : GenericRead);
            if (request.RequireDeleteAccess)
            {
                desiredAccess |= DeleteAccess;
            }

            if (request.RequireWriteAccess)
            {
                desiredAccess |= FileWriteData
                    | FileAddSubdirectory
                    | FileDeleteChild;
            }

            var createOptions = FileSynchronousIoNonAlert
                | NativeFileOpenReparsePoint
                | (request.Kind
                    == ProtectedAclNativeObjectKind.Directory
                    ? FileDirectoryFile
                    : FileNonDirectoryFile)
                | (request.Disposition
                    == ProtectedAclNativeDisposition.CreateNew
                    && request.Kind
                        == ProtectedAclNativeObjectKind.File
                    ? FileWriteThrough
                    : 0);
            var status = NtCreateFile(
                out var handle,
                desiredAccess,
                ref attributes,
                out _,
                IntPtr.Zero,
                fileAttributes: 0,
                FileShareRead,
                request.Disposition
                    == ProtectedAclNativeDisposition.CreateNew
                    ? FileCreate
                    : FileOpen,
                createOptions,
                IntPtr.Zero,
                eaLength: 0);
            if (status < 0 || handle.IsInvalid)
            {
                handle?.Dispose();
                return ProtectedAclNativeOpenResult.Failed(
                    MapNtStatus(status));
            }

            return ProtectedAclNativeOpenResult.Opened(
                new WindowsProtectedAclNativeHandle(handle));
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or InvalidOperationException
                or ObjectDisposedException
                or Win32Exception
                or SecurityException)
        {
            return ProtectedAclNativeOpenResult.Failed(
                exception is UnauthorizedAccessException
                    or SecurityException
                    ? ProtectedAclError.AccessDenied
                    : ProtectedAclError.IoFailure);
        }
        finally
        {
            if (parentAddRef)
            {
                parentHandle!.DangerousRelease();
            }

            if (descriptorPin.IsAllocated)
            {
                descriptorPin.Free();
            }
        }
    }


    public ProtectedAclNativeEnumerationResult EnumerateRelative(
        IProtectedAclNativeHandle directory)
    {
        if (directory is not WindowsProtectedAclNativeHandle native)
        {
            return ProtectedAclNativeEnumerationResult.Failed(
                ProtectedAclError.UnsafePath);
        }

        var addRef = false;
        SafeFileHandle? safeHandle = null;
        var buffer = IntPtr.Zero;
        try
        {
            safeHandle = native.SafeHandle;
            safeHandle.DangerousAddRef(ref addRef);
            var rawHandle = safeHandle.DangerousGetHandle();
            buffer = Marshal.AllocHGlobal(DirectoryBufferBytes);
            var entries =
                new List<ProtectedAclNativeDirectoryEntry>();
            var restartScan = true;
            while (true)
            {
                var status = NtQueryDirectoryFile(
                    rawHandle,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    out var ioStatus,
                    buffer,
                    DirectoryBufferBytes,
                    FileIdBothDirectoryInformation,
                    returnSingleEntry: false,
                    IntPtr.Zero,
                    restartScan);
                restartScan = false;
                if (status == StatusNoMoreFiles)
                {
                    break;
                }

                if (status < 0 && status != StatusBufferOverflow)
                {
                    return ProtectedAclNativeEnumerationResult.Failed(
                        MapNtStatus(status));
                }

                var bytes = checked((int)ioStatus.Information.ToUInt64());
                if (bytes <= 0 || bytes > DirectoryBufferBytes)
                {
                    return ProtectedAclNativeEnumerationResult.Failed(
                        ProtectedAclError.IoFailure);
                }

                var offset = 0;
                while (true)
                {
                    if (offset < 0
                        || offset > bytes - DirectoryNameOffset)
                    {
                        return ProtectedAclNativeEnumerationResult.Failed(
                            ProtectedAclError.IoFailure);
                    }

                    var entryPointer = IntPtr.Add(buffer, offset);
                    var nextOffset = Marshal.ReadInt32(
                        entryPointer,
                        DirectoryNextEntryOffset);
                    var attributes = unchecked((uint)Marshal.ReadInt32(
                        entryPointer,
                        DirectoryAttributesOffset));
                    var nameBytes = Marshal.ReadInt32(
                        entryPointer,
                        DirectoryNameLengthOffset);
                    if (nameBytes < 0
                        || (nameBytes & 1) != 0
                        || nameBytes > bytes - offset - DirectoryNameOffset)
                    {
                        return ProtectedAclNativeEnumerationResult.Failed(
                            ProtectedAclError.IoFailure);
                    }

                    var name = Marshal.PtrToStringUni(
                        IntPtr.Add(
                            entryPointer,
                            DirectoryNameOffset),
                        nameBytes / sizeof(char));
                    if (name is null)
                    {
                        return ProtectedAclNativeEnumerationResult.Failed(
                            ProtectedAclError.IoFailure);
                    }

                    if (name is not ("." or ".."))
                    {
                        entries.Add(
                            new ProtectedAclNativeDirectoryEntry(
                                name,
                                (attributes & FileAttributeDirectory) != 0
                                    ? ProtectedAclNativeObjectKind.Directory
                                    : ProtectedAclNativeObjectKind.File,
                                (attributes & FileAttributeReparsePoint) != 0));
                    }

                    if (nextOffset == 0)
                    {
                        break;
                    }

                    if (nextOffset < DirectoryNameOffset
                        || (nextOffset & 3) != 0
                        || nextOffset > bytes - offset)
                    {
                        return ProtectedAclNativeEnumerationResult.Failed(
                            ProtectedAclError.IoFailure);
                    }

                    offset = checked(offset + nextOffset);
                }
            }

            return ProtectedAclNativeEnumerationResult.Enumerated(
                entries.AsReadOnly());
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or InvalidOperationException
                or ObjectDisposedException
                or OverflowException
                or Win32Exception)
        {
            return ProtectedAclNativeEnumerationResult.Failed(
                ProtectedAclError.IoFailure);
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
            }

            if (addRef)
            {
                safeHandle!.DangerousRelease();
            }
        }
    }

    public ProtectedAclNativeOperationResult RenameRelative(
        IProtectedAclNativeHandle source,
        IProtectedAclNativeHandle destinationDirectory,
        string destinationName,
        bool replaceIfExists)
    {
        if (source is not WindowsProtectedAclNativeHandle nativeSource
            || destinationDirectory
                is not WindowsProtectedAclNativeHandle nativeDirectory
            || !IsSimpleLeafName(destinationName))
        {
            return ProtectedAclNativeOperationResult.Failed(
                ProtectedAclError.UnsafePath);
        }

        var sourceAddRef = false;
        var directoryAddRef = false;
        SafeFileHandle? sourceHandle = null;
        SafeFileHandle? directoryHandle = null;
        var buffer = IntPtr.Zero;
        try
        {
            sourceHandle = nativeSource.SafeHandle;
            directoryHandle = nativeDirectory.SafeHandle;
            sourceHandle.DangerousAddRef(ref sourceAddRef);
            directoryHandle.DangerousAddRef(ref directoryAddRef);
            var nameBytes = Encoding.Unicode.GetBytes(
                destinationName);
            var rootOffset = IntPtr.Size;
            var lengthOffset = rootOffset + IntPtr.Size;
            var nameOffset = lengthOffset + sizeof(uint);
            var bufferSize = checked(
                nameOffset + nameBytes.Length + sizeof(char));
            buffer = Marshal.AllocHGlobal(bufferSize);
            for (var index = 0; index < bufferSize; index++)
            {
                Marshal.WriteByte(buffer, index, 0);
            }

            Marshal.WriteInt32(
                buffer,
                replaceIfExists
                    ? unchecked((int)(
                        FileRenameReplaceIfExists
                        | FileRenamePosixSemantics))
                    : 0);
            Marshal.WriteIntPtr(
                buffer,
                rootOffset,
                directoryHandle.DangerousGetHandle());
            Marshal.WriteInt32(
                buffer,
                lengthOffset,
                nameBytes.Length);
            Marshal.Copy(
                nameBytes,
                startIndex: 0,
                IntPtr.Add(buffer, nameOffset),
                nameBytes.Length);
            if (!SetFileInformationByHandle(
                    sourceHandle.DangerousGetHandle(),
                    FileRenameInfoEx,
                    buffer,
                    unchecked((uint)bufferSize)))
            {
                return ProtectedAclNativeOperationResult.Failed(
                    MapWin32Error(Marshal.GetLastWin32Error()));
            }

            var flushStatus = NtFlushBuffersFile(
                directoryHandle.DangerousGetHandle(),
                out _);
            if (flushStatus < 0)
            {
                return ProtectedAclNativeOperationResult.Failed(
                    MapNtStatus(flushStatus),
                    namespaceChanged: true);
            }

            return ProtectedAclNativeOperationResult.Committed();
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or InvalidOperationException
                or ObjectDisposedException
                or OverflowException
                or Win32Exception)
        {
            return ProtectedAclNativeOperationResult.Failed(
                ProtectedAclError.IoFailure);
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
            }

            if (directoryAddRef)
            {
                directoryHandle!.DangerousRelease();
            }

            if (sourceAddRef)
            {
                sourceHandle!.DangerousRelease();
            }
        }
    }

    public ProtectedAclNativeOperationResult Delete(
        IProtectedAclNativeHandle target,
        bool directory)
    {
        if (target is not WindowsProtectedAclNativeHandle native)
        {
            return ProtectedAclNativeOperationResult.Failed(
                ProtectedAclError.UnsafePath);
        }

        try
        {
            var snapshot = native.ReadSnapshot();
            if (snapshot.IsDirectory != directory
                || snapshot.IsReparsePoint)
            {
                return ProtectedAclNativeOperationResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            var disposition = new FileDispositionInformation
            {
                DeleteFile = true
            };
            if (!SetFileInformationByHandleDisposition(
                    native.SafeHandle,
                    FileDispositionInfo,
                    ref disposition,
                    (uint)Marshal.SizeOf<FileDispositionInformation>()))
            {
                return ProtectedAclNativeOperationResult.Failed(
                    MapWin32Error(Marshal.GetLastWin32Error()));
            }

            return ProtectedAclNativeOperationResult.Committed();
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or InvalidOperationException
                or ObjectDisposedException
                or Win32Exception)
        {
            return ProtectedAclNativeOperationResult.Failed(
                ProtectedAclError.IoFailure);
        }
    }

    public ProtectedAclNativeOperationResult FlushDirectory(
        IProtectedAclNativeHandle directory)
    {
        if (directory is not WindowsProtectedAclNativeHandle native)
        {
            return ProtectedAclNativeOperationResult.Failed(
                ProtectedAclError.UnsafePath);
        }

        var addRef = false;
        SafeFileHandle? safeHandle = null;
        try
        {
            safeHandle = native.SafeHandle;
            safeHandle.DangerousAddRef(ref addRef);
            var status = NtFlushBuffersFile(
                safeHandle.DangerousGetHandle(),
                out _);
            return status < 0
                ? ProtectedAclNativeOperationResult.Failed(
                    MapNtStatus(status))
                : ProtectedAclNativeOperationResult.Committed(
                    namespaceChanged: false);
        }
        catch (Exception exception) when (
            exception is InvalidOperationException
                or ObjectDisposedException
                or Win32Exception)
        {
            return ProtectedAclNativeOperationResult.Failed(
                ProtectedAclError.IoFailure);
        }
        finally
        {
            if (addRef)
            {
                safeHandle!.DangerousRelease();
            }
        }
    }
    private static bool IsSimpleLeafName(string name) =>
        name.Length > 0
        && name is not ("." or "..")
        && name.IndexOfAny(
            ['\\', '/', ':', '\0']) < 0;

    private static ProtectedAclError MapNtStatus(int status)
    {
        if (status == StatusObjectNameNotFound
            || status == StatusObjectPathNotFound)
        {
            return ProtectedAclError.Missing;
        }

        if (status == StatusObjectNameCollision)
        {
            return ProtectedAclError.AlreadyExists;
        }

        if (status == StatusReparsePointEncountered
            || status == StatusFileIsADirectory
            || status == StatusNotADirectory)
        {
            return ProtectedAclError.UnsafePath;
        }

        if (status == StatusPrivilegeNotHeld)
        {
            return ProtectedAclError.PrivilegeUnavailable;
        }

        if (status == StatusAccessDenied)
        {
            return ProtectedAclError.AccessDenied;
        }

        return MapWin32Error(
            unchecked((int)RtlNtStatusToDosError(status)));
    }

    private static ProtectedAclError MapWin32Error(int error) =>
        error switch
        {
            2 or 3 => ProtectedAclError.Missing,
            5 => ProtectedAclError.AccessDenied,
            80 or 183 => ProtectedAclError.AlreadyExists,
            1314 => ProtectedAclError.PrivilegeUnavailable,
            1920 or 4390 => ProtectedAclError.UnsafePath,
            _ => ProtectedAclError.IoFailure
        };

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        public IntPtr Status;
        public UIntPtr Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInformation
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool DeleteFile;
    }

    private sealed class NativeUnicodeString : IDisposable
    {
        private IntPtr _buffer;
        private IntPtr _structure;

        public NativeUnicodeString(string value)
        {
            var byteLength = checked(value.Length * sizeof(char));
            if (byteLength > ushort.MaxValue - sizeof(char))
            {
                throw new ArgumentException(
                    "The relative name is too long.",
                    nameof(value));
            }

            _buffer = Marshal.StringToHGlobalUni(value);
            var native = new UnicodeString
            {
                Length = (ushort)byteLength,
                MaximumLength = (ushort)(byteLength + sizeof(char)),
                Buffer = _buffer
            };
            _structure = Marshal.AllocHGlobal(
                Marshal.SizeOf<UnicodeString>());
            Marshal.StructureToPtr(
                native,
                _structure,
                fDeleteOld: false);
        }

        public IntPtr StructurePointer => _structure;

        public void Dispose()
        {
            if (_structure != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_structure);
                _structure = IntPtr.Zero;
            }

            if (_buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_buffer);
                _buffer = IntPtr.Zero;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("ntdll.dll")]
    private static extern int NtCreateFile(
        out SafeFileHandle fileHandle,
        uint desiredAccess,
        ref ObjectAttributes objectAttributes,
        out IoStatusBlock ioStatusBlock,
        IntPtr allocationSize,
        uint fileAttributes,
        uint shareAccess,
        uint createDisposition,
        uint createOptions,
        IntPtr eaBuffer,
        uint eaLength);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryDirectoryFile(
        IntPtr fileHandle,
        IntPtr eventHandle,
        IntPtr apcRoutine,
        IntPtr apcContext,
        out IoStatusBlock ioStatusBlock,
        IntPtr fileInformation,
        uint length,
        int fileInformationClass,
        [MarshalAs(UnmanagedType.U1)] bool returnSingleEntry,
        IntPtr fileName,
        [MarshalAs(UnmanagedType.U1)] bool restartScan);

    [DllImport("ntdll.dll")]
    private static extern int NtFlushBuffersFile(
        IntPtr fileHandle,
        out IoStatusBlock ioStatusBlock);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        IntPtr fileHandle,
        int fileInformationClass,
        IntPtr fileInformation,
        uint bufferSize);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "SetFileInformationByHandle",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandleDisposition(
        SafeFileHandle fileHandle,
        int fileInformationClass,
        ref FileDispositionInformation fileInformation,
        uint bufferSize);

    [DllImport("ntdll.dll")]
    private static extern uint RtlNtStatusToDosError(
        int status);
}

internal sealed class WindowsProtectedAclNativeHandle
    : IProtectedAclNativeHandle
{
    private const int FileAttributeTagInfoClass = 9;
    private const int FileIdInfoClass = 18;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const uint SeFileObject = 1;
    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint DaclSecurityInformation = 0x00000004;
    private const uint DuplicateSameAccess = 0x00000002;
    private readonly object _gate = new();
    private SafeFileHandle? _handle;

    internal WindowsProtectedAclNativeHandle(
        SafeFileHandle handle)
    {
        _handle = handle
            ?? throw new ArgumentNullException(nameof(handle));
    }

    internal SafeFileHandle SafeHandle
    {
        get
        {
            lock (_gate)
            {
                return _handle
                    ?? throw new ObjectDisposedException(
                        nameof(WindowsProtectedAclNativeHandle));
            }
        }
    }

    public ProtectedAclNativeSnapshot ReadSnapshot()
    {
        lock (_gate)
        {
            var handle = _handle
                ?? throw new ObjectDisposedException(
                    nameof(WindowsProtectedAclNativeHandle));
            if (!GetFileInformationByHandleExAttributes(
                    handle,
                    FileAttributeTagInfoClass,
                    out var attributes,
                    (uint)Marshal.SizeOf<FileAttributeTagInfo>())
                || !GetFileInformationByHandleExIdentity(
                    handle,
                    FileIdInfoClass,
                    out var identity,
                    (uint)Marshal.SizeOf<FileIdInfo>()))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error());
            }

            return new ProtectedAclNativeSnapshot(
                IsDirectory:
                    (attributes.FileAttributes
                        & FileAttributeDirectory) != 0,
                IsReparsePoint:
                    (attributes.FileAttributes
                        & FileAttributeReparsePoint) != 0,
                ReadFinalPath(handle),
                new ProtectedFileIdentity128(
                    identity.VolumeSerialNumber,
                    identity.FileId.Low,
                    identity.FileId.High),
                ReadSecurityDescriptor(handle));
        }
    }

    public FileStream TakeFileStream() =>
        OpenFileStream(FileAccess.ReadWrite);

    public FileStream OpenFileStream(FileAccess access)
    {
        lock (_gate)
        {
            var handle = _handle
                ?? throw new ObjectDisposedException(
                    nameof(WindowsProtectedAclNativeHandle));
            var addRef = false;
            try
            {
                handle.DangerousAddRef(ref addRef);
                if (!DuplicateHandle(
                        GetCurrentProcess(),
                        handle.DangerousGetHandle(),
                        GetCurrentProcess(),
                        out var duplicate,
                        desiredAccess: 0,
                        inheritHandle: false,
                        DuplicateSameAccess))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error());
                }

                try
                {
                    return new FileStream(
                        duplicate,
                        access,
                        bufferSize: 81920,
                        isAsync: false);
                }
                catch
                {
                    duplicate.Dispose();
                    throw;
                }
            }
            finally
            {
                if (addRef)
                {
                    handle.DangerousRelease();
                }
            }
        }
    }

    public void Dispose()
    {
        SafeFileHandle? handle;
        lock (_gate)
        {
            handle = _handle;
            _handle = null;
        }

        handle?.Dispose();
    }

    private static string ReadFinalPath(SafeFileHandle handle)
    {
        const int maximumPathLength = 32768;
        var capacity = 512;
        while (capacity <= maximumPathLength)
        {
            var buffer = new StringBuilder(capacity);
            var length = GetFinalPathNameByHandle(
                handle,
                buffer,
                (uint)buffer.Capacity,
                flags: 0);
            if (length == 0)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error());
            }

            if (length < buffer.Capacity)
            {
                var finalPath = buffer.ToString();
                if (finalPath.StartsWith(
                        @"\\?\UNC\",
                        StringComparison.OrdinalIgnoreCase))
                {
                    finalPath = @"\\" + finalPath[8..];
                }
                else if (finalPath.StartsWith(
                             @"\\?\",
                             StringComparison.Ordinal))
                {
                    finalPath = finalPath[4..];
                }

                return Path.GetFullPath(finalPath);
            }

            capacity = checked((int)length + 1);
        }

        throw new IOException("The final path exceeded the supported bound.");
    }

    private static byte[] ReadSecurityDescriptor(
        SafeFileHandle handle)
    {
        var error = GetSecurityInfo(
            handle,
            SeFileObject,
            OwnerSecurityInformation | DaclSecurityInformation,
            out _,
            out _,
            out _,
            out _,
            out var descriptor);
        if (error != 0 || descriptor == IntPtr.Zero)
        {
            throw new Win32Exception(unchecked((int)error));
        }

        try
        {
            var length = GetSecurityDescriptorLength(descriptor);
            if (length == 0 || length > 1024 * 1024)
            {
                throw new SecurityException(
                    "The security descriptor length is invalid.");
            }

            var bytes = new byte[length];
            Marshal.Copy(
                descriptor,
                bytes,
                startIndex: 0,
                checked((int)length));
            return bytes;
        }
        finally
        {
            LocalFree(descriptor);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileId128
    {
        public ulong Low;
        public ulong High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInfo
    {
        public ulong VolumeSerialNumber;
        public FileId128 FileId;
    }

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetFileInformationByHandleEx",
        SetLastError = true)]
    private static extern bool GetFileInformationByHandleExAttributes(
        SafeFileHandle file,
        int fileInformationClass,
        out FileAttributeTagInfo fileInformation,
        uint bufferSize);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetFileInformationByHandleEx",
        SetLastError = true)]
    private static extern bool GetFileInformationByHandleExIdentity(
        SafeFileHandle file,
        int fileInformationClass,
        out FileIdInfo fileInformation,
        uint bufferSize);

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        StringBuilder filePath,
        uint filePathLength,
        uint flags);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityInfo(
        SafeFileHandle handle,
        uint objectType,
        uint securityInformation,
        out IntPtr owner,
        out IntPtr group,
        out IntPtr dacl,
        out IntPtr sacl,
        out IntPtr securityDescriptor);

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(
        IntPtr securityDescriptor);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(
        IntPtr sourceProcessHandle,
        IntPtr sourceHandle,
        IntPtr targetProcessHandle,
        out SafeFileHandle targetHandle,
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint options);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}

internal sealed class WindowsRestorePrivilegeScope : IDisposable
{
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint TokenQuery = 0x0008;
    private const uint SePrivilegeEnabled = 0x00000002;
    private const int ErrorNotAllAssigned = 1300;
    private const string RestorePrivilegeName = "SeRestorePrivilege";
    private static readonly object PrivilegeAdjustmentGate = new();

    private readonly SafeAccessTokenHandle _token;
    private TokenPrivileges _previousState;
    private readonly bool _gateHeld;
    private bool _disposed;

    private WindowsRestorePrivilegeScope(
        SafeAccessTokenHandle token,
        TokenPrivileges previousState)
    {
        _token = token;
        _previousState = previousState;
        _gateHeld = true;
    }

    public static bool TryEnable(
        out WindowsRestorePrivilegeScope? scope)
    {
        scope = null;
        SafeAccessTokenHandle? token = null;
        var gateHeld = false;
        try
        {
            Monitor.Enter(
                PrivilegeAdjustmentGate,
                ref gateHeld);
            if (!OpenProcessToken(
                    Process.GetCurrentProcess().Handle,
                    TokenAdjustPrivileges | TokenQuery,
                    out token)
                || token.IsInvalid
                || !LookupPrivilegeValue(
                    null,
                    RestorePrivilegeName,
                    out var luid))
            {
                token?.Dispose();
                return false;
            }

            var requested = new TokenPrivileges
            {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = SePrivilegeEnabled
            };
            if (!AdjustTokenPrivileges(
                    token,
                    disableAllPrivileges: false,
                    ref requested,
                    (uint)Marshal.SizeOf<TokenPrivileges>(),
                    out var previous,
                    out _)
                || Marshal.GetLastWin32Error()
                    == ErrorNotAllAssigned)
            {
                token.Dispose();
                token = null;
                Monitor.Exit(PrivilegeAdjustmentGate);
                gateHeld = false;
                return false;
            }

            scope = new WindowsRestorePrivilegeScope(
                token,
                previous);
            token = null;
            gateHeld = false;
            return true;
        }
        catch (Exception exception) when (
            exception is DllNotFoundException
                or EntryPointNotFoundException
                or PlatformNotSupportedException
                or InvalidOperationException)
        {
            token?.Dispose();
            return false;
        }
        finally
        {
            if (gateHeld)
            {
                token?.Dispose();
                Monitor.Exit(PrivilegeAdjustmentGate);
            }
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        Exception? restoreFailure = null;
        try
        {
            Marshal.SetLastPInvokeError(0);
            var restored = AdjustTokenPrivileges(
                _token,
                disableAllPrivileges: false,
                ref _previousState,
                (uint)Marshal.SizeOf<TokenPrivileges>(),
                out _,
                out _);
            var error = Marshal.GetLastWin32Error();
            if (!restored || error == ErrorNotAllAssigned)
            {
                restoreFailure = new Win32Exception(
                    error == 0 ? Marshal.GetLastWin32Error() : error,
                    "Failed to restore SeRestorePrivilege.");
            }
        }
        finally
        {
            _token.Dispose();
            if (_gateHeld)
            {
                Monitor.Exit(PrivilegeAdjustmentGate);
            }
        }

        if (restoreFailure is not null)
        {
            throw restoreFailure;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public uint PrivilegeCount;
        public Luid Luid;
        public uint Attributes;
    }

    [DllImport(
        "advapi32.dll",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out SafeAccessTokenHandle tokenHandle);

    [DllImport(
        "advapi32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(
        string? systemName,
        string name,
        out Luid luid);

    [DllImport(
        "advapi32.dll",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(
        SafeAccessTokenHandle tokenHandle,
        [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
        ref TokenPrivileges newState,
        uint bufferLength,
        out TokenPrivileges previousState,
        out uint returnLength);
}
