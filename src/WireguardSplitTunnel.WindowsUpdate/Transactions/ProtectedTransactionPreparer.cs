using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Launcher;
using WireguardSplitTunnel.WindowsUpdate.Staging;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate.Transactions;

public sealed record TrustedReleaseBinding
{
    internal TrustedReleaseBinding(
        SemanticVersion version,
        string archiveSha256,
        string newManifestSha256,
        PendingUpdateSource source)
    {
        Version = version;
        ArchiveSha256 = archiveSha256;
        NewManifestSha256 = newManifestSha256;
        Source = source;
    }

    public SemanticVersion Version { get; init; }
    public string ArchiveSha256 { get; init; }
    public string NewManifestSha256 { get; init; }
    public PendingUpdateSource Source { get; init; }

    internal static TrustedReleaseBinding? TryCreate(
        SelectedWindowsRelease? release,
        ValidatedUpdatePackage? package,
        PendingUpdateSource source)
    {
        if (release is null
            || package is null
            || release.Version != package.Version
            || !Enum.IsDefined(source)
            || !IsCanonicalSha256(release.ArchiveSha256)
            || !IsCanonicalSha256(package.ArchiveSha256)
            || !IsCanonicalSha256(package.NewManifestSha256)
            || !HashesEqual(
                release.ArchiveSha256,
                package.ArchiveSha256))
        {
            return null;
        }

        return new TrustedReleaseBinding(
            release.Version,
            release.ArchiveSha256,
            package.NewManifestSha256,
            source);
    }

    private static bool IsCanonicalSha256(string? value) =>
        value is { Length: 64 }
        && value.All(character =>
            character is >= '0' and <= '9'
                or >= 'a' and <= 'f');

    private static bool HashesEqual(
        string left,
        string right) =>
        CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(left),
            Convert.FromHexString(right));
}

public sealed record ProtectedTransactionPreparationRequest(
    LocalStagedUpdate StagedUpdate,
    TrustedReleaseBinding TrustedRelease,
    int SupportedStateSchemaVersion,
    UpdatePackageLimits Limits)
{
    public ProtectedActiveTransactionExpectation? ExpectedActive
    {
        get;
        init;
    }
}

public enum ProtectedTransactionPreparationError
{
    None,
    InvalidAuthority,
    InvalidRequest,
    NotElevated,
    UnsafeLocalStaging,
    InstalledReleaseUnavailable,
    VerificationFailed,
    InsufficientDiskSpace,
    ProtectedStorageFailed,
    StoreCreateFailed,
    HelperVerificationFailed,
    ActivationFailed,
    Cancelled,
    CleanupFailed
}

public sealed record ProtectedTransactionPreparationResult(
    bool Success,
    ProtectedTransactionId? TransactionId,
    ProtectedTransactionPreparationError Error,
    string? DetailCode)
{
    internal static ProtectedTransactionPreparationResult Completed(
        ProtectedTransactionId transactionId,
        string? detailCode = null) =>
        new(
            true,
            transactionId,
            ProtectedTransactionPreparationError.None,
            detailCode);

    internal static ProtectedTransactionPreparationResult Failed(
        ProtectedTransactionPreparationError error,
        string? detailCode = null) =>
        new(false, null, error, detailCode);
}

internal interface IProtectedTransactionPreparationWorkspace : IDisposable
{
    ProtectedStagedTransactionMaterial Material { get; }

    bool VerifyHelperIdentity();

    bool TryCleanup();

    void Commit();
}

internal sealed record ProtectedTransactionWorkspaceResult(
    bool Success,
    IProtectedTransactionPreparationWorkspace? Workspace,
    ProtectedTransactionPreparationError Error,
    string? DetailCode)
{
    public static ProtectedTransactionWorkspaceResult Completed(
        IProtectedTransactionPreparationWorkspace workspace) =>
        new(true, workspace, ProtectedTransactionPreparationError.None, null);

    public static ProtectedTransactionWorkspaceResult Failed(
        ProtectedTransactionPreparationError error,
        string? detailCode = null) =>
        new(false, null, error, detailCode);
}

internal interface IProtectedTransactionPreparationBoundary
{
    Task<ProtectedTransactionWorkspaceResult> PrepareAsync(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionPreparationRequest request,
        ProtectedTransactionId transactionId,
        CancellationToken cancellationToken);
}

internal interface IProtectedPreparationEnvironment
{
    bool IsElevated();

    string? GetCurrentExecutablePath();
}

internal interface IInstalledReleaseLocationProvider
{
    InstalledReleaseLocation Locate(
        string? runningExecutablePath);
}

internal interface IProtectedPreparationArtifactBuilder
{
    Task<ProtectedTransactionWorkspaceResult> BuildAsync(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionPreparationRequest request,
        LocalUpdateLayout localLayout,
        ProtectedTransactionLayout protectedLayout,
        InstalledReleaseLocation installedRelease,
        CancellationToken cancellationToken);
}

internal interface IProtectedTransactionStoreGateway
{
    ProtectedTransactionWriteResult CreateProtectedStaged(
        ProtectedUpdateMutexContext authority,
        ProtectedStagedTransactionMaterial material);

    ProtectedTransactionStoreResult VerifyHelper(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionId transactionId,
        string expectedSha256);

    ProtectedTransactionStoreResult Activate(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionRecord expectedRecord,
        ProtectedActiveTransactionExpectation? expectedActive);

    ProtectedTransactionStoreResult CleanupInactiveTransaction(
        ProtectedUpdateMutexContext authority,
        ProtectedStagedTransactionMaterial expectedMaterial,
        Func<bool> cleanup);

    ProtectedTransactionStoreResult CleanupSupersededTransaction(
        ProtectedUpdateMutexContext authority,
        ProtectedActiveTransactionExpectation expectedActive,
        Func<bool> cleanup);
}

public sealed class ProtectedTransactionPreparer
{
    private const int SupersededCleanupAttemptLimit = 2;
    private readonly IProtectedTransactionPreparationBoundary _boundary;
    private readonly IProtectedTransactionStoreGateway _store;
    private readonly Func<ProtectedTransactionId> _createTransactionId;
    private readonly Func<ProtectedTransactionId, bool>
        _cleanupSuperseded;

    public ProtectedTransactionPreparer()
    {
        var protectedPaths = new ProtectedTransactionPaths();
        _boundary =
            new WindowsProtectedTransactionPreparationBoundary(
                new LocalUpdatePaths(),
                protectedPaths,
                new WindowsProtectedPreparationEnvironment(),
                new InstalledReleaseLocationProvider(
                    new InstalledReleaseLocator()),
                new WindowsProtectedPreparationArtifactBuilder(
                    protectedPaths,
                    new ProtectedDirectoryAcl(),
                    new WindowsExecutableProductVersionReader(),
                    new WindowsDiskSpaceProvider(),
                    new WindowsPathSafetyInspector()));
        _store = new ProtectedTransactionStoreGateway(
            new ProtectedTransactionStore(protectedPaths));
        _createTransactionId = ProtectedTransactionId.New;
        var cleaner = new ProtectedTerminalTransactionCleaner(
            protectedPaths,
            new ProtectedDirectoryAcl());
        _cleanupSuperseded = cleaner.Cleanup;
    }

    internal ProtectedTransactionPreparer(
        IProtectedTransactionPreparationBoundary boundary,
        IProtectedTransactionStoreGateway store,
        Func<ProtectedTransactionId> createTransactionId,
        Func<ProtectedTransactionId, bool>? cleanupSuperseded = null)
    {
        _boundary = boundary
            ?? throw new ArgumentNullException(nameof(boundary));
        _store = store
            ?? throw new ArgumentNullException(nameof(store));
        _createTransactionId = createTransactionId
            ?? throw new ArgumentNullException(nameof(createTransactionId));
        _cleanupSuperseded = cleanupSuperseded ?? (_ => true);
    }

    public async Task<ProtectedTransactionPreparationResult> PrepareAsync(
        ProtectedUpdateMutexContext? authority,
        ProtectedTransactionPreparationRequest? request,
        CancellationToken cancellationToken = default)
    {
        if (authority is null
            || !authority.TryAcquireLease(out var authorityLease)
            || authorityLease is null)
        {
            return ProtectedTransactionPreparationResult.Failed(
                ProtectedTransactionPreparationError.InvalidAuthority);
        }

        using (authorityLease)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return ProtectedTransactionPreparationResult.Failed(
                    ProtectedTransactionPreparationError.Cancelled);
            }

            if (!IsValidRequest(request))
            {
                return ProtectedTransactionPreparationResult.Failed(
                    ProtectedTransactionPreparationError.InvalidRequest);
            }

            ProtectedTransactionId transactionId;
            try
            {
                transactionId = _createTransactionId();
            }
            catch (Exception exception) when (
                exception is InvalidOperationException
                    or ArgumentException)
            {
                return ProtectedTransactionPreparationResult.Failed(
                    ProtectedTransactionPreparationError.InvalidRequest,
                    "transaction_id");
            }

            if (!transactionId.IsValid)
            {
                return ProtectedTransactionPreparationResult.Failed(
                    ProtectedTransactionPreparationError.InvalidRequest,
                    "transaction_id");
            }

            ProtectedTransactionWorkspaceResult prepared;
            try
            {
                prepared = await _boundary.PrepareAsync(
                        authority,
                        request!,
                        transactionId,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                return ProtectedTransactionPreparationResult.Failed(
                    ProtectedTransactionPreparationError.Cancelled);
            }
            catch (Exception exception) when (
                IsBoundaryFailure(exception))
            {
                return ProtectedTransactionPreparationResult.Failed(
                    ProtectedTransactionPreparationError.VerificationFailed,
                    "boundary_exception");
            }

            if (cancellationToken.IsCancellationRequested)
            {
                CleanupCancelledWorkspace(
                    prepared.Workspace);
                return ProtectedTransactionPreparationResult.Failed(
                    ProtectedTransactionPreparationError.Cancelled);
            }

            if (!prepared.Success
                || prepared.Workspace is null)
            {
                return ProtectedTransactionPreparationResult.Failed(
                    prepared.Error
                        == ProtectedTransactionPreparationError.None
                        ? ProtectedTransactionPreparationError.VerificationFailed
                        : prepared.Error,
                    prepared.DetailCode);
            }

            var workspace = prepared.Workspace;
            var shouldCleanup = true;
            ProtectedStagedTransactionMaterial? cleanupMaterial =
                null;
            var result = ProtectedTransactionPreparationResult.Failed(
                ProtectedTransactionPreparationError.VerificationFailed);
            try
            {
                var material = workspace.Material;
                cleanupMaterial = material;
                if (!MatchesRequest(
                        material,
                        request!,
                        transactionId))
                {
                    result =
                        ProtectedTransactionPreparationResult.Failed(
                            ProtectedTransactionPreparationError.VerificationFailed,
                            "material_binding");
                }
                else if (cancellationToken.IsCancellationRequested)
                {
                    result =
                        ProtectedTransactionPreparationResult.Failed(
                            ProtectedTransactionPreparationError.Cancelled);
                }
                else if (!workspace.VerifyHelperIdentity())
                {
                    result =
                        ProtectedTransactionPreparationResult.Failed(
                            ProtectedTransactionPreparationError.HelperVerificationFailed,
                            "before_create");
                }
                else
                {
                    var created = _store.CreateProtectedStaged(
                        authority,
                        material);
                    if (!created.Success
                        || created.Record is null)
                    {
                        result =
                            ProtectedTransactionPreparationResult.Failed(
                                ProtectedTransactionPreparationError.StoreCreateFailed,
                                created.Error.ToString());
                    }
                    else if (!IsExpectedProtectedStagedRecord(
                            created.Record,
                            material))
                    {
                        result =
                            ProtectedTransactionPreparationResult.Failed(
                                ProtectedTransactionPreparationError.StoreCreateFailed,
                                "unexpected_record");
                    }
                    else if (cancellationToken.IsCancellationRequested)
                    {
                        result =
                            ProtectedTransactionPreparationResult.Failed(
                                ProtectedTransactionPreparationError.Cancelled);
                    }
                    else if (!workspace.VerifyHelperIdentity())
                    {
                        result =
                            ProtectedTransactionPreparationResult.Failed(
                                ProtectedTransactionPreparationError.HelperVerificationFailed,
                                "before_activation");
                    }
                    else
                    {
                        var helper = _store.VerifyHelper(
                            authority,
                            transactionId,
                            material.HelperSha256);
                        if (!helper.Success)
                        {
                            result =
                                ProtectedTransactionPreparationResult.Failed(
                                    ProtectedTransactionPreparationError.HelperVerificationFailed,
                                    helper.Error.ToString());
                        }
                        else if (cancellationToken.IsCancellationRequested)
                        {
                            result =
                                ProtectedTransactionPreparationResult.Failed(
                                    ProtectedTransactionPreparationError.Cancelled);
                        }
                        else
                        {
                            var activation = _store.Activate(
                                authority,
                                created.Record,
                                request!.ExpectedActive);
                            if (!activation.Success)
                            {
                                result =
                                    ProtectedTransactionPreparationResult.Failed(
                                        ProtectedTransactionPreparationError.ActivationFailed,
                                        activation.Error.ToString());
                            }
                            else
                            {
                                shouldCleanup = false;
                                workspace.Commit();
                                var supersededCleanupPending =
                                    request!.ExpectedActive is { } superseded
                                    && !TryCleanupSuperseded(
                                        authority,
                                        superseded);
                                result =
                                    ProtectedTransactionPreparationResult.Completed(
                                        transactionId,
                                        supersededCleanupPending
                                            ? "superseded_cleanup_pending"
                                            : null);
                            }
                        }
                    }
                }
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                result = ProtectedTransactionPreparationResult.Failed(
                    ProtectedTransactionPreparationError.Cancelled);
            }
            catch (Exception exception) when (
                IsBoundaryFailure(exception))
            {
                result = ProtectedTransactionPreparationResult.Failed(
                    ProtectedTransactionPreparationError.VerificationFailed,
                    "preparation_exception");
            }
            finally
            {
                if (shouldCleanup)
                {
                    try
                    {
                        var cleanup = cleanupMaterial is not null
                                && cleanupMaterial.TransactionId.IsValid
                            ? _store.CleanupInactiveTransaction(
                                authority,
                                cleanupMaterial,
                                workspace.TryCleanup)
                            : workspace.TryCleanup()
                                ? ProtectedTransactionStoreResult
                                    .Completed()
                                : ProtectedTransactionStoreResult
                                    .Failed(
                                        ProtectedTransactionStoreError
                                            .IoFailure);
                        if (!cleanup.Success
                            && cleanup.Error
                                != ProtectedTransactionStoreError
                                    .Conflict)
                        {
                            result =
                                ProtectedTransactionPreparationResult.Failed(
                                    ProtectedTransactionPreparationError.CleanupFailed);
                        }
                    }
                    catch (Exception exception) when (
                        IsBoundaryFailure(exception))
                    {
                        result =
                            ProtectedTransactionPreparationResult.Failed(
                                ProtectedTransactionPreparationError.CleanupFailed);
                    }
                }

                workspace.Dispose();
            }

            return result;
        }
    }

    private static bool IsValidRequest(
        ProtectedTransactionPreparationRequest? request)
    {
        if (request is null
            || request.StagedUpdate is null
            || request.TrustedRelease is null
            || request.SupportedStateSchemaVersion <= 0
            || !request.Limits.Validate().Success
            || !IsStrictVersion(request.StagedUpdate.Version)
            || request.StagedUpdate.Version
                != request.TrustedRelease.Version
            || request.StagedUpdate.Source
                != request.TrustedRelease.Source
            || !Enum.IsDefined(request.StagedUpdate.Source)
            || !IsCanonicalSha256(
                request.StagedUpdate.ArchiveSha256)
            || !IsCanonicalSha256(
                request.StagedUpdate.NewManifestSha256)
            || !IsCanonicalSha256(
                request.TrustedRelease.ArchiveSha256)
            || !IsCanonicalSha256(
                request.TrustedRelease.NewManifestSha256))
        {
            return false;
        }

        if (request.ExpectedActive is { } expectedActive
            && (!expectedActive.TransactionId.IsValid
                || !IsStrictVersion(expectedActive.Version)
                || !Enum.IsDefined(expectedActive.Source)
                || request.TrustedRelease.Version.CompareTo(
                        expectedActive.Version) < 0
                || request.TrustedRelease.Version
                        == expectedActive.Version
                    && !(expectedActive.Source
                            == PendingUpdateSource.Automatic
                        && request.TrustedRelease.Source
                            == PendingUpdateSource.Manual)))
        {
            return false;
        }

        return HashesEqual(
                request.StagedUpdate.ArchiveSha256,
                request.TrustedRelease.ArchiveSha256)
            && HashesEqual(
                request.StagedUpdate.NewManifestSha256,
                request.TrustedRelease.NewManifestSha256);
    }

    private bool TryCleanupSuperseded(
        ProtectedUpdateMutexContext authority,
        ProtectedActiveTransactionExpectation superseded)
    {
        for (var attempt = 0;
             attempt < SupersededCleanupAttemptLimit;
             attempt++)
        {
            try
            {
                var cleanup = _store.CleanupSupersededTransaction(
                    authority,
                    superseded,
                    () => _cleanupSuperseded(
                        superseded.TransactionId));
                if (cleanup.Success)
                {
                    return true;
                }
            }
            catch (Exception exception) when (
                IsBoundaryFailure(exception))
            {
            }
        }

        return false;
    }

    private static void CleanupCancelledWorkspace(
        IProtectedTransactionPreparationWorkspace? workspace)
    {
        if (workspace is null)
        {
            return;
        }

        try
        {
            _ = workspace.TryCleanup();
        }
        catch (Exception exception) when (
            IsBoundaryFailure(exception))
        {
        }
        finally
        {
            workspace.Dispose();
        }
    }

    private static bool MatchesRequest(
        ProtectedStagedTransactionMaterial? material,
        ProtectedTransactionPreparationRequest request,
        ProtectedTransactionId transactionId) =>
        material is not null
        && material.TransactionId == transactionId
        && material.Version == request.TrustedRelease.Version
        && material.Source == request.TrustedRelease.Source
        && material.Candidate is not null
        && HashesEqual(
            material.Candidate.ArchiveSha256,
            request.TrustedRelease.ArchiveSha256)
        && HashesEqual(
            material.Candidate.NewManifestSha256,
            request.TrustedRelease.NewManifestSha256)
        && material.Journal is
        {
            SchemaVersion:
                ProtectedTransactionStore.JournalSchemaVersion,
            Generation: 0,
            Sha256: null
        };

    private static bool IsExpectedProtectedStagedRecord(
        ProtectedTransactionRecord record,
        ProtectedStagedTransactionMaterial material) =>
        record.TransactionId == material.TransactionId
        && record.Version == material.Version
        && record.Source == material.Source
        && record.Phase
            == ProtectedTransactionPhase.ProtectedStaged
        && record.AuthorizedProcess is null
        && record.InstalledRelease == material.InstalledRelease
        && record.Candidate == material.Candidate
        && record.HelperSha256 == material.HelperSha256
        && record.Journal == material.Journal;

    private static bool IsStrictVersion(
        SemanticVersion version) =>
        version.Major >= 0
        && version.Minor >= 0
        && version.Patch >= 0
        && SemanticVersion.TryParseNormalized(
            version.ToString(),
            out var roundTripped)
        && roundTripped == version;

    private static bool IsCanonicalSha256(
        string? value) =>
        value is { Length: 64 }
        && value.All(character =>
            character is >= '0' and <= '9'
                or >= 'a' and <= 'f');

    private static bool HashesEqual(
        string first,
        string second)
    {
        try
        {
            return System.Security.Cryptography.CryptographicOperations
                .FixedTimeEquals(
                    Convert.FromHexString(first),
                    Convert.FromHexString(second));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool IsBoundaryFailure(
        Exception exception) =>
        exception is IOException
            or UnauthorizedAccessException
            or InvalidDataException
            or ArgumentException
            or InvalidOperationException
            or NotSupportedException
            or System.Security.SecurityException
            or System.ComponentModel.Win32Exception
            or ObjectDisposedException;
}

internal static class ProtectedPreparationDiskPolicy
{
    public static UpdateDiskSpaceResult Evaluate(
        long programDataAvailableBytes,
        long installAvailableBytes,
        long archiveBytes,
        long expandedCandidateBytes,
        long currentManagedBytes,
        UpdatePackageLimits limits)
    {
        var programData = UpdateDiskSpacePolicy.Evaluate(
            programDataAvailableBytes,
            archiveBytes,
            expandedCandidateBytes,
            currentManagedBytes,
            limits);
        if (!programData.Success)
        {
            return programData;
        }

        var install = UpdateDiskSpacePolicy.Evaluate(
            installAvailableBytes,
            archiveBytes,
            expandedCandidateBytes,
            currentManagedBytes,
            limits);
        return install.Success
            ? programData
            : install;
    }
}

internal static class RetainedProductVersionVerifier
{
    public static bool Matches(
        IExecutableProductVersionReader reader,
        Stream stream,
        SemanticVersion expected,
        Func<bool> revalidate)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(revalidate);
        if (!stream.CanRead
            || !stream.CanSeek
            || !revalidate())
        {
            return false;
        }

        try
        {
            var position = stream.Position;
            var raw = reader.ReadProductVersion(stream);
            return stream.Position == position
                && SemanticVersion.TryParseNormalized(
                    raw,
                    out var actual)
                && actual == expected
                && revalidate()
                && stream.Position == position;
        }
        catch (Exception exception) when (
            WindowsPreparationPathSafety
                .IsOrdinaryFileFailure(exception)
            || exception is Win32Exception
            || exception is CryptographicException)
        {
            return false;
        }
    }
}

internal sealed class WindowsProtectedPreparationEnvironment
    : IProtectedPreparationEnvironment
{
    public bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(
                WindowsBuiltInRole.Administrator);
        }
        catch (Exception exception) when (
            exception is UnauthorizedAccessException
                or System.Security.SecurityException
                or PlatformNotSupportedException
                or InvalidOperationException)
        {
            return false;
        }
    }

    public string? GetCurrentExecutablePath() =>
        Environment.ProcessPath;
}

internal sealed class InstalledReleaseLocationProvider
    : IInstalledReleaseLocationProvider
{
    private readonly InstalledReleaseLocator _locator;

    public InstalledReleaseLocationProvider(
        InstalledReleaseLocator locator)
    {
        _locator = locator
            ?? throw new ArgumentNullException(nameof(locator));
    }

    public InstalledReleaseLocation Locate(
        string? runningExecutablePath) =>
        _locator.Locate(runningExecutablePath);
}

internal sealed class WindowsProtectedTransactionPreparationBoundary
    : IProtectedTransactionPreparationBoundary
{
    private readonly LocalUpdatePaths _localPaths;
    private readonly ProtectedTransactionPaths _protectedPaths;
    private readonly IProtectedPreparationEnvironment _environment;
    private readonly IInstalledReleaseLocationProvider _installedLocator;
    private readonly IProtectedPreparationArtifactBuilder _artifactBuilder;

    public WindowsProtectedTransactionPreparationBoundary(
        LocalUpdatePaths localPaths,
        ProtectedTransactionPaths protectedPaths,
        IProtectedPreparationEnvironment environment,
        IInstalledReleaseLocationProvider installedLocator,
        IProtectedPreparationArtifactBuilder artifactBuilder)
    {
        _localPaths = localPaths
            ?? throw new ArgumentNullException(nameof(localPaths));
        _protectedPaths = protectedPaths
            ?? throw new ArgumentNullException(nameof(protectedPaths));
        _environment = environment
            ?? throw new ArgumentNullException(nameof(environment));
        _installedLocator = installedLocator
            ?? throw new ArgumentNullException(nameof(installedLocator));
        _artifactBuilder = artifactBuilder
            ?? throw new ArgumentNullException(nameof(artifactBuilder));
    }

    public async Task<ProtectedTransactionWorkspaceResult> PrepareAsync(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionPreparationRequest request,
        ProtectedTransactionId transactionId,
        CancellationToken cancellationToken)
    {
        if (!authority.IsActive)
        {
            return Failed(
                ProtectedTransactionPreparationError.InvalidAuthority);
        }

        if (!_environment.IsElevated())
        {
            return Failed(
                ProtectedTransactionPreparationError.NotElevated);
        }

        var local = _localPaths.TryResolve(
            request.StagedUpdate);
        if (!local.Success || local.Layout is null)
        {
            return Failed(
                ProtectedTransactionPreparationError.UnsafeLocalStaging,
                local.Error.ToString());
        }

        var protectedResult = _protectedPaths.GetLayout(
            transactionId);
        if (!protectedResult.Success
            || protectedResult.Layout is null)
        {
            return Failed(
                ProtectedTransactionPreparationError.ProtectedStorageFailed,
                protectedResult.Error.ToString());
        }

        var installed = _installedLocator.Locate(
            _environment.GetCurrentExecutablePath());
        if (installed.Status
                != InstalledReleaseLocatorStatus.Available
            || installed.InstallationRoot is null
            || installed.ApplicationPath is null
            || installed.UpdaterPath is null
            || installed.Version is null)
        {
            return Failed(
                ProtectedTransactionPreparationError.InstalledReleaseUnavailable,
                installed.DetailCode);
        }

        var prepared = await _artifactBuilder.BuildAsync(
                authority,
                request,
                local.Layout,
                protectedResult.Layout,
                installed,
                cancellationToken)
            .ConfigureAwait(false);
        if (cancellationToken.IsCancellationRequested)
        {
            CleanupCancelledBoundaryWorkspace(
                prepared.Workspace);
            cancellationToken.ThrowIfCancellationRequested();
        }

        return prepared;
    }

    private static void CleanupCancelledBoundaryWorkspace(
        IProtectedTransactionPreparationWorkspace? workspace)
    {
        if (workspace is null)
        {
            return;
        }

        try
        {
            _ = workspace.TryCleanup();
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or InvalidOperationException
                or ArgumentException
                or NotSupportedException)
        {
        }
        finally
        {
            workspace.Dispose();
        }
    }

    private static ProtectedTransactionWorkspaceResult Failed(
        ProtectedTransactionPreparationError error,
        string? detailCode = null) =>
        ProtectedTransactionWorkspaceResult.Failed(
            error,
            detailCode);
}

internal sealed class ProtectedTransactionStoreGateway
    : IProtectedTransactionStoreGateway
{
    private readonly ProtectedTransactionStore _store;

    public ProtectedTransactionStoreGateway(
        ProtectedTransactionStore store)
    {
        _store = store
            ?? throw new ArgumentNullException(nameof(store));
    }

    public ProtectedTransactionWriteResult CreateProtectedStaged(
        ProtectedUpdateMutexContext authority,
        ProtectedStagedTransactionMaterial material) =>
        _store.CreateProtectedStaged(authority, material);

    public ProtectedTransactionStoreResult VerifyHelper(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionId transactionId,
        string expectedSha256) =>
        _store.VerifyHelper(
            authority,
            transactionId,
            expectedSha256);

    public ProtectedTransactionStoreResult Activate(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionRecord expectedRecord,
        ProtectedActiveTransactionExpectation? expectedActive) =>
        _store.ActivateReplacingProtectedStaged(
            authority,
            expectedRecord,
            expectedActive);

    public ProtectedTransactionStoreResult
        CleanupInactiveTransaction(
            ProtectedUpdateMutexContext authority,
            ProtectedStagedTransactionMaterial expectedMaterial,
            Func<bool> cleanup) =>
        _store.CleanupInactiveTransaction(
            authority,
            expectedMaterial,
            cleanup);

    public ProtectedTransactionStoreResult
        CleanupSupersededTransaction(
            ProtectedUpdateMutexContext authority,
            ProtectedActiveTransactionExpectation expectedActive,
            Func<bool> cleanup)
    {
        var read = _store.ReadTransaction(
            authority,
            expectedActive.TransactionId);
        if (!read.Success
            || read.Record is not { } record)
        {
            return ProtectedTransactionStoreResult.Failed(
                read.Error);
        }

        if (record.TransactionId != expectedActive.TransactionId
            || record.Version != expectedActive.Version
            || record.Source != expectedActive.Source
            || record.Phase
                != ProtectedTransactionPhase.ProtectedStaged
            || record.AuthorizedProcess is not null)
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.Conflict);
        }

        return _store.CleanupInactiveTransaction(
            authority,
            new ProtectedStagedTransactionMaterial(
                record.TransactionId,
                record.Version,
                record.Source,
                record.InstalledRelease,
                record.Candidate,
                record.HelperSha256,
                record.Journal),
            cleanup);
    }
}

internal sealed partial class WindowsProtectedPreparationArtifactBuilder
    : IProtectedPreparationArtifactBuilder
{
    private readonly ProtectedTransactionPaths _protectedPaths;
    private readonly ProtectedDirectoryAcl _acl;
    private readonly IExecutableProductVersionReader _versionReader;
    private readonly IDiskSpaceProvider _diskSpace;
    private readonly IPathSafetyInspector _pathSafetyInspector;

    public WindowsProtectedPreparationArtifactBuilder(
        ProtectedTransactionPaths protectedPaths,
        ProtectedDirectoryAcl acl,
        IExecutableProductVersionReader versionReader,
        IDiskSpaceProvider diskSpace,
        IPathSafetyInspector pathSafetyInspector)
    {
        _protectedPaths = protectedPaths
            ?? throw new ArgumentNullException(nameof(protectedPaths));
        _acl = acl
            ?? throw new ArgumentNullException(nameof(acl));
        _versionReader = versionReader
            ?? throw new ArgumentNullException(nameof(versionReader));
        _diskSpace = diskSpace
            ?? throw new ArgumentNullException(nameof(diskSpace));
        _pathSafetyInspector = pathSafetyInspector
            ?? throw new ArgumentNullException(nameof(pathSafetyInspector));
    }

    public async Task<ProtectedTransactionWorkspaceResult> BuildAsync(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionPreparationRequest request,
        LocalUpdateLayout localLayout,
        ProtectedTransactionLayout protectedLayout,
        InstalledReleaseLocation installedRelease,
        CancellationToken cancellationToken)
    {
        if (!authority.IsActive)
        {
            return ProtectedTransactionWorkspaceResult.Failed(
                ProtectedTransactionPreparationError.InvalidAuthority);
        }

        WindowsProtectedTransactionPreparationWorkspace?
            workspace = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var installed = await SnapshotInstalledAsync(
                    installedRelease,
                    request.SupportedStateSchemaVersion,
                    request.Limits,
                    cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (!installed.Success
                || installed.Identity is null)
            {
                return ProtectedTransactionWorkspaceResult.Failed(
                    ProtectedTransactionPreparationError.VerificationFailed,
                    installed.DetailCode);
            }

            var candidate = await VerifyCandidateAsync(
                    request,
                    localLayout,
                    installed.Identity.CurrentVersion,
                    cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (!candidate.Success
                || candidate.Manifest is null
                || candidate.ManifestBytes is null)
            {
                return ProtectedTransactionWorkspaceResult.Failed(
                    candidate.Error,
                    candidate.DetailCode);
            }

            long programDataAvailable;
            long installAvailable;
            try
            {
                programDataAvailable =
                    _diskSpace.GetAvailableBytes(
                        protectedLayout.ProductRoot);
                installAvailable =
                    _diskSpace.GetAvailableBytes(
                        installed.Identity.InstallRoot);
            }
            catch (Exception exception) when (
                WindowsPreparationPathSafety
                    .IsOrdinaryFileFailure(exception))
            {
                return ProtectedTransactionWorkspaceResult.Failed(
                    ProtectedTransactionPreparationError.VerificationFailed,
                    "disk_query");
            }

            var disk = ProtectedPreparationDiskPolicy.Evaluate(
                programDataAvailable,
                installAvailable,
                candidate.ArchiveBytes,
                candidate.ExpandedBytes,
                installed.CurrentManagedBytes,
                request.Limits);
            if (!disk.Success)
            {
                return ProtectedTransactionWorkspaceResult.Failed(
                    disk.ErrorCode
                        == UpdateDiskSpaceError.InsufficientSpace
                        ? ProtectedTransactionPreparationError
                            .InsufficientDiskSpace
                        : ProtectedTransactionPreparationError
                            .VerificationFailed,
                    disk.ErrorCode.ToString());
            }

            var workspaceResult =
                WindowsProtectedTransactionPreparationWorkspace
                    .TryCreate(
                        protectedLayout,
                        _protectedPaths,
                        _acl,
                        _versionReader,
                        _pathSafetyInspector,
                        request.TrustedRelease.Version);
            if (!workspaceResult.Success
                || workspaceResult.Workspace is null)
            {
                return ProtectedTransactionWorkspaceResult.Failed(
                    workspaceResult.Error,
                    workspaceResult.DetailCode);
            }

            workspace = workspaceResult.Workspace;
            var candidateCopied = await CopyCandidateAsync(
                    workspace,
                    localLayout,
                    candidate,
                    cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (!candidateCopied)
            {
                return FailAndCleanup(
                    workspace,
                    ProtectedTransactionPreparationError
                        .VerificationFailed,
                    "candidate_copy");
            }

            var helperPayload = candidate.Manifest.Files!
                .SingleOrDefault(file =>
                    file.Path.Equals(
                        UpdateReleaseContract.WindowsUpdaterPath,
                        StringComparison.Ordinal));
            if (helperPayload is null)
            {
                return FailAndCleanup(
                    workspace,
                    ProtectedTransactionPreparationError
                        .VerificationFailed,
                    "helper_copy");
            }

            var helperCopied = await workspace.CopyHelperAsync(
                        WindowsPreparationPathSafety
                            .ResolveReleasePath(
                                localLayout.CandidateRoot,
                                helperPayload.Path),
                        helperPayload,
                        cancellationToken)
                    .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (!helperCopied
                || !workspace.VerifyCandidateIdentity(
                    candidate.Manifest,
                    candidate.ManifestBytes,
                    candidate.ExpandedBytes))
            {
                return FailAndCleanup(
                    workspace,
                    ProtectedTransactionPreparationError
                        .VerificationFailed,
                    "helper_copy");
            }

            var material =
                new ProtectedStagedTransactionMaterial(
                    protectedLayout.TransactionRoot is not null
                        ? ParseTransactionId(
                            protectedLayout.TransactionRoot)
                        : default,
                    request.TrustedRelease.Version,
                    request.TrustedRelease.Source,
                    installed.Identity,
                    new ProtectedCandidateIdentity(
                        request.TrustedRelease.ArchiveSha256,
                        request.TrustedRelease.NewManifestSha256,
                        candidate.ExpandedBytes),
                    helperPayload.Sha256,
                    new ProtectedJournalMetadata(
                        ProtectedTransactionStore
                            .JournalSchemaVersion,
                        Generation: 0,
                        Sha256: null));
            if (!material.TransactionId.IsValid
                || material.TransactionId
                    != workspace.TransactionId)
            {
                return FailAndCleanup(
                    workspace,
                    ProtectedTransactionPreparationError
                        .ProtectedStorageFailed,
                    "transaction_id");
            }

            workspace.SetMaterial(material);
            var completed =
                ProtectedTransactionWorkspaceResult.Completed(
                    workspace);
            workspace = null;
            return completed;
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            return workspace is null
                ? ProtectedTransactionWorkspaceResult.Failed(
                    ProtectedTransactionPreparationError.Cancelled)
                : FailAndCleanup(
                    workspace,
                    ProtectedTransactionPreparationError.Cancelled);
        }
        catch (Exception exception) when (
            WindowsPreparationPathSafety
                .IsOrdinaryFileFailure(exception)
            || exception is CryptographicException
            || exception is JsonException
            || exception is OverflowException
            || exception is Win32Exception)
        {
            return workspace is null
                ? ProtectedTransactionWorkspaceResult.Failed(
                    ProtectedTransactionPreparationError
                        .VerificationFailed,
                    "filesystem")
                : FailAndCleanup(
                    workspace,
                    ProtectedTransactionPreparationError
                        .VerificationFailed,
                    "filesystem");
        }
        finally
        {
            workspace?.Dispose();
        }
    }

    private static ProtectedTransactionId ParseTransactionId(
        string transactionRoot)
    {
        var name = Path.GetFileName(transactionRoot);
        return name is { Length: 32 }
            && Guid.TryParseExact(name, "N", out var value)
            && value != Guid.Empty
            ? new ProtectedTransactionId(value)
            : default;
    }

    private static ProtectedTransactionWorkspaceResult
        FailAndCleanup(
            WindowsProtectedTransactionPreparationWorkspace workspace,
            ProtectedTransactionPreparationError error,
            string? detailCode = null)
    {
        var cleanup = workspace.TryCleanup();
        workspace.Dispose();
        return ProtectedTransactionWorkspaceResult.Failed(
            cleanup
                ? error
                : ProtectedTransactionPreparationError
                    .CleanupFailed,
            cleanup ? detailCode : "cleanup");
    }
}

internal sealed record ProtectedPreparationWorkspaceCreateResult(
    bool Success,
    WindowsProtectedTransactionPreparationWorkspace? Workspace,
    ProtectedTransactionPreparationError Error,
    string? DetailCode)
{
    public static ProtectedPreparationWorkspaceCreateResult
        Completed(
            WindowsProtectedTransactionPreparationWorkspace
                workspace) =>
        new(
            true,
            workspace,
            ProtectedTransactionPreparationError.None,
            null);

    public static ProtectedPreparationWorkspaceCreateResult Failed(
        ProtectedTransactionPreparationError error,
        string? detailCode = null) =>
        new(false, null, error, detailCode);
}

internal sealed class WindowsProtectedTransactionPreparationWorkspace
    : IProtectedTransactionPreparationWorkspace
{
    private readonly ProtectedTransactionLayout _layout;
    private readonly ProtectedTransactionPaths _paths;
    private readonly ProtectedDirectoryAcl _acl;
    private readonly IExecutableProductVersionReader _versionReader;
    private readonly IPathSafetyInspector _pathSafetyInspector;
    private readonly SemanticVersion _candidateVersion;
    private readonly Dictionary<
        string,
        ProtectedFileIdentity128> _createdFiles =
            new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _createdDirectories =
        new(StringComparer.OrdinalIgnoreCase);
    private ProtectedDirectoryInspectionLease?
        _transactionRootLease;
    private ProtectedStagedTransactionMaterial? _material;
    private bool _committed;
    private bool _disposed;

    private WindowsProtectedTransactionPreparationWorkspace(
        ProtectedTransactionLayout layout,
        ProtectedTransactionPaths paths,
        ProtectedDirectoryAcl acl,
        IExecutableProductVersionReader versionReader,
        IPathSafetyInspector pathSafetyInspector,
        SemanticVersion candidateVersion,
        ProtectedTransactionId transactionId,
        ProtectedDirectoryInspectionLease
            transactionRootLease)
    {
        _layout = layout;
        _paths = paths;
        _acl = acl;
        _versionReader = versionReader;
        _pathSafetyInspector = pathSafetyInspector;
        _candidateVersion = candidateVersion;
        TransactionId = transactionId;
        _transactionRootLease = transactionRootLease;
    }

    public ProtectedTransactionId TransactionId { get; }

    public ProtectedStagedTransactionMaterial Material =>
        _material
        ?? throw new InvalidOperationException(
            "Protected transaction material has not been finalized.");

    public static ProtectedPreparationWorkspaceCreateResult
        TryCreate(
            ProtectedTransactionLayout layout,
            ProtectedTransactionPaths paths,
            ProtectedDirectoryAcl acl,
            IExecutableProductVersionReader versionReader,
            IPathSafetyInspector pathSafetyInspector,
            SemanticVersion candidateVersion)
    {
        var transactionId = ParseTransactionId(
            layout.TransactionRoot);
        if (!transactionId.IsValid)
        {
            return ProtectedPreparationWorkspaceCreateResult
                .Failed(
                    ProtectedTransactionPreparationError
                        .ProtectedStorageFailed,
                    "transaction_exists");
        }

        var product = acl.EnsureProtectedDirectory(
            layout.ProductRoot);
        using var productInspection =
            acl.InspectProtectedDirectory(
                layout.ProductRoot,
                ProtectedDirectoryInspectionPolicy
                    .Transaction);
        if (!product.Success
            || !productInspection.Success
            || productInspection.Lease is not { } productRoot
            || !string.Equals(
                productRoot.FinalPath,
                layout.ProductRoot,
                StringComparison.OrdinalIgnoreCase))
        {
            return ProtectedPreparationWorkspaceCreateResult
                .Failed(
                    ProtectedTransactionPreparationError
                        .ProtectedStorageFailed,
                    product.Success
                        ? productInspection.Error.ToString()
                        : product.Error.ToString());
        }

        using var transactionsResult =
            acl.EnsureProtectedDirectoryTree(
                layout.ProductRoot,
                ["transactions"]);
        if (!transactionsResult.Success
            || transactionsResult.Lease
                is not { } transactionsRoot
            || !string.Equals(
                transactionsRoot.FinalPath,
                layout.TransactionsRoot,
                StringComparison.OrdinalIgnoreCase)
            || !productRoot.Revalidate())
        {
            return ProtectedPreparationWorkspaceCreateResult
                .Failed(
                    ProtectedTransactionPreparationError
                        .ProtectedStorageFailed,
                    transactionsResult.Error.ToString());
        }

        var transactionResult =
            acl.EnsureProtectedDirectoryTree(
                layout.TransactionsRoot,
                [transactionId.Value.ToString("N")]);
        if (!transactionResult.Success
            || transactionResult.Lease
                is not { } transactionRoot
            || !transactionResult.Created
            || !string.Equals(
                transactionRoot.FinalPath,
                layout.TransactionRoot,
                StringComparison.OrdinalIgnoreCase)
            || !transactionsRoot.Revalidate())
        {
            transactionResult.Dispose();
            return ProtectedPreparationWorkspaceCreateResult
                .Failed(
                    ProtectedTransactionPreparationError
                        .ProtectedStorageFailed,
                    transactionResult.Success
                        ? "transaction_exists"
                        : transactionResult.Error.ToString());
        }

        var workspace =
            new WindowsProtectedTransactionPreparationWorkspace(
                layout,
                paths,
                acl,
                versionReader,
                pathSafetyInspector,
                candidateVersion,
                transactionId,
                transactionRoot);
        workspace._createdDirectories.Add(
            layout.TransactionRoot);
        foreach (var directory in new[]
        {
            layout.TransactionRoot,
            layout.HelperRoot,
            layout.CandidateRoot,
            layout.BackupsRoot
        })
        {
            if (!workspace.EnsureOwnedDirectory(directory))
            {
                var cleaned = workspace.TryCleanup();
                workspace.Dispose();
                return ProtectedPreparationWorkspaceCreateResult
                    .Failed(
                        cleaned
                            ? ProtectedTransactionPreparationError
                                .ProtectedStorageFailed
                            : ProtectedTransactionPreparationError
                                .CleanupFailed,
                        "protected_directory");
            }
        }

        return ProtectedPreparationWorkspaceCreateResult
            .Completed(workspace);
    }

    public void SetMaterial(
        ProtectedStagedTransactionMaterial material)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_material is not null
            || material.TransactionId != TransactionId
            || material.Version != _candidateVersion
            || material.Journal is not
            {
                SchemaVersion:
                    ProtectedTransactionStore.JournalSchemaVersion,
                Generation: 0,
                Sha256: null
            })
        {
            throw new InvalidOperationException(
                "Protected transaction material is inconsistent.");
        }

        _material = material;
    }

    public async Task<bool> CopyCandidateFileAsync(
        string sourcePath,
        ReleasePayloadFile expected,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var target = _paths.ResolveCandidatePayload(
            TransactionId,
            expected.Path);
        if (!target.Success
            || target.Path is null
            || !EnsureOwnedAncestors(
                Path.GetDirectoryName(target.Path),
                _layout.CandidateRoot))
        {
            return false;
        }

        var copied = await CopyProtectedFileAsync(
                sourcePath,
                target.Path,
                expected,
                cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return copied;
    }

    public async Task<bool> CopyHelperAsync(
        string? sourcePath,
        ReleasePayloadFile expected,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (sourcePath is null
            || expected.Path
                != UpdateReleaseContract.WindowsUpdaterPath)
        {
            return false;
        }

        var copied = await CopyProtectedFileAsync(
                sourcePath,
                _layout.HelperPath,
                expected,
                cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return copied;
    }

    public bool VerifyCandidateIdentity(
        ReleaseManifest manifest,
        byte[] manifestBytes,
        long expandedBytes)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var transactionRoot = _transactionRootLease;
        if (transactionRoot is null
            || manifest.Files is null
            || !transactionRoot.Revalidate())
        {
            return false;
        }

        using var candidateResult =
            _acl.InspectProtectedDirectory(
                _layout.CandidateRoot,
                ProtectedDirectoryInspectionPolicy.Transaction);
        using var helperResult =
            _acl.InspectProtectedDirectory(
                _layout.HelperRoot,
                ProtectedDirectoryInspectionPolicy.Transaction);
        using var backupsResult =
            _acl.InspectProtectedDirectory(
                _layout.BackupsRoot,
                ProtectedDirectoryInspectionPolicy.Transaction);
        if (!candidateResult.Success
            || candidateResult.Lease
                is not { } candidateRoot
            || !helperResult.Success
            || helperResult.Lease is not { } helperRoot
            || !backupsResult.Success
            || backupsResult.Lease is not { } backupsRoot)
        {
            return false;
        }

        using var candidateEnumerationResult =
            _acl.EnumerateProtectedDirectory(
                candidateRoot,
                ProtectedDirectoryInspectionPolicy.Transaction,
                WindowsReleasePathPolicy.MaximumArchiveEntries);
        using var helperEnumerationResult =
            _acl.EnumerateProtectedDirectory(
                helperRoot,
                ProtectedDirectoryInspectionPolicy.Transaction,
                maximumEntries: 2);
        using var backupsEnumerationResult =
            _acl.EnumerateProtectedDirectory(
                backupsRoot,
                ProtectedDirectoryInspectionPolicy.Transaction,
                maximumEntries: 0);
        if (!candidateEnumerationResult.Success
            || candidateEnumerationResult.Lease
                is not { } candidateEnumeration
            || !helperEnumerationResult.Success
            || helperEnumerationResult.Lease
                is not { } helperEnumeration
            || !backupsEnumerationResult.Success
            || backupsEnumerationResult.Lease
                is not { } backupsEnumeration
            || backupsEnumeration.Files.Count != 0
            || backupsEnumeration.Directories.Count != 0)
        {
            return false;
        }

        var expected = manifest.Files
            .Prepend(
                new ReleasePayloadFile(
                    UpdateReleaseContract.ReleaseManifestPath,
                    manifestBytes.LongLength,
                    Convert.ToHexString(
                            SHA256.HashData(manifestBytes))
                        .ToLowerInvariant()))
            .ToArray();
        var actualPaths = candidateEnumeration.Files
            .Select(file => file.RelativePath)
            .ToArray();
        if (!HasExactCandidateFiles(
                actualPaths,
                manifest.Files)
            || !HasExactCandidateDirectories(
                candidateEnumeration.Directories,
                expected))
        {
            return false;
        }

        var byPath = new Dictionary<
            string,
            ProtectedEnumeratedFileLease>(
                StringComparer.Ordinal);
        var insensitive = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase);
        foreach (var actual in candidateEnumeration.Files)
        {
            if (!byPath.TryAdd(
                    actual.RelativePath,
                    actual)
                || !insensitive.Add(
                    actual.RelativePath))
            {
                return false;
            }
        }

        long measured = 0;
        foreach (var file in expected)
        {
            if (!byPath.TryGetValue(
                    file.Path,
                    out var retained)
                || !MatchesProtectedFile(
                    retained,
                    file))
            {
                return false;
            }

            measured = checked(measured + file.Length);
        }

        if (!byPath.TryGetValue(
                UpdateReleaseContract.WindowsApplicationPath,
                out var application)
            || !byPath.TryGetValue(
                UpdateReleaseContract.WindowsUpdaterPath,
                out var updater)
            || !HasProductVersion(
                application,
                _candidateVersion)
            || !HasProductVersion(
                updater,
                _candidateVersion))
        {
            return false;
        }

        var helperPayload = manifest.Files.SingleOrDefault(
            file => string.Equals(
                file.Path,
                UpdateReleaseContract.WindowsUpdaterPath,
                StringComparison.Ordinal));
        var helperName = Path.GetFileName(
            _layout.HelperPath);
        return helperPayload is not null
            && helperEnumeration.Files.Count == 1
            && helperEnumeration.Directories.Count == 0
            && string.Equals(
                helperEnumeration.Files[0].RelativePath,
                helperName,
                StringComparison.Ordinal)
            && MatchesProtectedFile(
                helperEnumeration.Files[0],
                helperPayload)
            && HasProductVersion(
                helperEnumeration.Files[0],
                _candidateVersion)
            && measured == expandedBytes
            && candidateEnumeration.Revalidate()
            && helperEnumeration.Revalidate()
            && backupsEnumeration.Revalidate()
            && transactionRoot.Revalidate();
    }

    public bool VerifyHelperIdentity()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var transactionRoot = _transactionRootLease;
        if (_material is null
            || transactionRoot is null
            || !transactionRoot.Revalidate()
            || !TryGetTransactionRelativePath(
                _layout.HelperPath,
                out var relativePath))
        {
            return false;
        }

        using var helperRootResult =
            _acl.InspectProtectedDirectory(
                _layout.HelperRoot,
                ProtectedDirectoryInspectionPolicy.Transaction);
        using var helperResult =
            _acl.OpenProtectedFileForRead(
                transactionRoot,
                relativePath,
                ProtectedDirectoryInspectionPolicy.Transaction);
        return helperRootResult.Success
            && helperRootResult.Lease?.Revalidate() == true
            && helperResult.Success
            && helperResult.Lease is { } helper
            && MatchesProtectedFile(
                helper,
                _material.HelperSha256,
                UpdatePackageLimits.Default.MaximumFileBytes)
            && HasProductVersion(
                helper,
                _candidateVersion)
            && transactionRoot.Revalidate();
    }

    public bool TryCleanup()
    {
        if (_disposed || _committed)
        {
            return false;
        }

        try
        {
            var transactionRoot = _transactionRootLease;
            if (transactionRoot is null
                || !transactionRoot.Revalidate())
            {
                return false;
            }

            var expectedFiles = new Dictionary<
                string,
                ProtectedFileIdentity128>(
                    StringComparer.OrdinalIgnoreCase);
            foreach (var created in _createdFiles)
            {
                if (!created.Value.IsValid
                    || !TryGetTransactionRelativePath(
                        created.Key,
                        out var relative)
                    || !expectedFiles.TryAdd(
                        relative,
                        created.Value))
                {
                    return false;
                }
            }

            if (!TryGetTransactionRelativePath(
                    _layout.TransactionRecordPath,
                    out var transactionRecordRelative))
            {
                return false;
            }

            var expectedDirectories = new HashSet<string>(
                StringComparer.OrdinalIgnoreCase)
            ;
            foreach (var directory in _createdDirectories)
            {
                if (string.Equals(
                        directory,
                        _layout.TransactionRoot,
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!TryGetTransactionRelativePath(
                        directory,
                        out var relative)
                    || !expectedDirectories.Add(relative))
                {
                    return false;
                }
            }

            var filesToDelete =
                new List<(
                    string Path,
                    ProtectedFileIdentity128 Identity)>();
            var directoriesToDelete =
                new List<(
                    string Path,
                    ProtectedFileIdentity128 Identity)>();
            using (var enumerationResult =
                _acl.EnumerateProtectedDirectory(
                    transactionRoot,
                    ProtectedDirectoryInspectionPolicy
                        .Transaction,
                    checked(
                        WindowsReleasePathPolicy
                            .MaximumArchiveEntries * 2
                        + 16)))
            {
                if (!enumerationResult.Success
                    || enumerationResult.Lease
                        is not { } enumeration)
                {
                    return false;
                }

                var observedCreatedFiles =
                    new HashSet<string>(
                        StringComparer.OrdinalIgnoreCase);
                var observedFiles =
                    new HashSet<string>(
                        StringComparer.OrdinalIgnoreCase);
                foreach (var file in enumeration.Files)
                {
                    if (!observedFiles.Add(
                            file.RelativePath)
                        || !TryResolveTransactionRelativePath(
                            file.RelativePath,
                            out var expectedPath)
                        || !string.Equals(
                            file.FinalPath,
                            expectedPath,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    if (expectedFiles.TryGetValue(
                            file.RelativePath,
                            out var expectedIdentity))
                    {
                        if (file.Identity
                                != expectedIdentity
                            || !observedCreatedFiles.Add(
                                file.RelativePath))
                        {
                            return false;
                        }
                    }
                    else if (!string.Equals(
                        file.RelativePath,
                        transactionRecordRelative,
                        StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    filesToDelete.Add(
                        (file.FinalPath, file.Identity));
                }

                if (observedCreatedFiles.Count
                    != expectedFiles.Count)
                {
                    return false;
                }

                var observedDirectories =
                    new HashSet<string>(
                        StringComparer.OrdinalIgnoreCase);
                foreach (var directory
                    in enumeration.Directories)
                {
                    if (!expectedDirectories.Contains(
                            directory.RelativePath)
                        || !observedDirectories.Add(
                            directory.RelativePath)
                        || !TryResolveTransactionRelativePath(
                            directory.RelativePath,
                            out var expectedPath)
                        || !string.Equals(
                            directory.FinalPath,
                            expectedPath,
                            StringComparison.OrdinalIgnoreCase)
                        || !directory.Identity.IsValid)
                    {
                        return false;
                    }

                    directoriesToDelete.Add(
                        (directory.FinalPath,
                         directory.Identity));
                }

                if (observedDirectories.Count
                        != expectedDirectories.Count
                    || !enumeration.Revalidate()
                    || !transactionRoot.Revalidate())
                {
                    return false;
                }
            }

            foreach (var file in filesToDelete
                .OrderByDescending(item =>
                    item.Path.Length))
            {
                var deleted = _acl.DeleteProtectedFile(
                    file.Path,
                    file.Identity);
                if (deleted.Outcome
                    != ProtectedFileMutationOutcome.Committed)
                {
                    return false;
                }
            }

            foreach (var directory in directoriesToDelete)
            {
                var deleted =
                    _acl.DeleteProtectedDirectory(
                        directory.Path,
                        directory.Identity);
                if (deleted.Outcome
                    != ProtectedFileMutationOutcome.Committed)
                {
                    return false;
                }
            }

            var rootIdentity = transactionRoot.Identity;
            transactionRoot.Dispose();
            _transactionRootLease = null;
            var rootDeleted =
                _acl.DeleteProtectedDirectory(
                    _layout.TransactionRoot,
                    rootIdentity);
            return rootDeleted.Outcome
                == ProtectedFileMutationOutcome.Committed;
        }
        catch (Exception exception) when (
            WindowsPreparationPathSafety
                .IsOrdinaryFileFailure(exception))
        {
            return false;
        }
    }

    public void Commit()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_material is null)
        {
            throw new InvalidOperationException(
                "Cannot commit an incomplete protected workspace.");
        }

        _committed = true;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _transactionRootLease?.Dispose();
        _transactionRootLease = null;
    }

    private async Task<bool> CopyProtectedFileAsync(
        string sourcePath,
        string targetPath,
        ReleasePayloadFile expected,
        CancellationToken cancellationToken)
    {
        if (!PreparationPinnedFile.TryOpen(
                sourcePath,
                UpdatePackageLimits.Default.MaximumFileBytes,
                _pathSafetyInspector,
                out var source)
            || source is null)
        {
            return false;
        }

        var transactionRoot = _transactionRootLease;
        if (transactionRoot is null
            || !TryGetTransactionRelativePath(
                targetPath,
                out var relativePath)
            || !transactionRoot.Revalidate())
        {
            source.Dispose();
            return false;
        }

        using (source)
        {
            var sourceHash = await source
                .ComputeSha256Async(cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (source.Length != expected.Length
                || !HashesEqual(
                    sourceHash,
                    expected.Sha256))
            {
                return false;
            }

            var bytes = source.ReadAllBytes();
            if (bytes is null
                || bytes.LongLength != expected.Length
                || !HashesEqual(
                    Convert.ToHexString(
                            SHA256.HashData(bytes))
                        .ToLowerInvariant(),
                    expected.Sha256)
                || !source.Revalidate())
            {
                return false;
            }

            var created =
                _acl.CreateProtectedFileIfAbsent(
                    targetPath,
                    bytes);
            if (created.Outcome
                    != ProtectedFileMutationOutcome.Committed
                || created.Identity is not { } identity
                || !identity.IsValid)
            {
                return false;
            }

            _createdFiles[targetPath] = identity;
        }

        using var opened =
            _acl.OpenProtectedFileForRead(
                transactionRoot,
                relativePath,
                ProtectedDirectoryInspectionPolicy.Transaction);
        if (!opened.Success
            || opened.Lease is not { } retained)
        {
            return false;
        }

        return retained.Identity
                == _createdFiles[targetPath]
            && MatchesProtectedFile(
                retained,
                expected)
            && transactionRoot.Revalidate();
    }

    private static bool MatchesProtectedFile(
        ProtectedFileReadLease opened,
        string expectedSha256,
        long maximumBytes)
    {
        try
        {
            var stream = opened.Stream;
            var length = stream.Length;
            if (length < 0
                || length > maximumBytes
                || !opened.Revalidate())
            {
                return false;
            }

            stream.Position = 0;
            var hash = Convert.ToHexString(
                    SHA256.HashData(stream))
                .ToLowerInvariant();
            return stream.Length == length
                && opened.Revalidate()
                && HashesEqual(
                    hash,
                    expectedSha256);
        }
        catch (Exception exception) when (
            WindowsPreparationPathSafety
                .IsOrdinaryFileFailure(exception)
            || exception is CryptographicException)
        {
            return false;
        }
    }

    private static bool MatchesProtectedFile(
        ProtectedFileReadLease opened,
        ReleasePayloadFile expected)
    {
        try
        {
            var stream = opened.Stream;
            if (stream.Length != expected.Length
                || !opened.Revalidate())
            {
                return false;
            }

            stream.Position = 0;
            var hash = Convert.ToHexString(
                    SHA256.HashData(stream))
                .ToLowerInvariant();
            return stream.Length == expected.Length
                && opened.Revalidate()
                && HashesEqual(hash, expected.Sha256);
        }
        catch (Exception exception) when (
            WindowsPreparationPathSafety
                .IsOrdinaryFileFailure(exception)
            || exception is CryptographicException)
        {
            return false;
        }
    }

    private bool HasProductVersion(
        ProtectedFileReadLease pinned,
        SemanticVersion expected) =>
        RetainedProductVersionVerifier.Matches(
            _versionReader,
            pinned.Stream,
            expected,
            pinned.Revalidate);

    private bool TryGetTransactionRelativePath(
        string path,
        out string relativePath)
    {
        relativePath = string.Empty;
        try
        {
            var canonical = Path.GetFullPath(path);
            if (!WindowsPreparationPathSafety.IsContainedBy(
                    canonical,
                    _layout.TransactionRoot))
            {
                return false;
            }

            var relative = Path.GetRelativePath(
                    _layout.TransactionRoot,
                    canonical)
                .Replace(
                    Path.DirectorySeparatorChar,
                    '/');
            var validation =
                WindowsReleasePathPolicy.Validate(relative);
            if (!validation.Success
                || validation.CanonicalKey is null)
            {
                return false;
            }

            relativePath = validation.CanonicalKey;
            return true;
        }
        catch (Exception exception) when (
            WindowsPreparationPathSafety
                .IsOrdinaryFileFailure(exception))
        {
            return false;
        }
    }

    private bool TryResolveTransactionRelativePath(
        string relativePath,
        out string path)
    {
        path = string.Empty;
        var validation =
            WindowsReleasePathPolicy.Validate(
                relativePath);
        if (!validation.Success
            || validation.CanonicalKey is null
            || !string.Equals(
                validation.CanonicalKey,
                relativePath,
                StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            var resolved = Path.GetFullPath(
                Path.Combine(
                    _layout.TransactionRoot,
                    relativePath.Replace(
                        '/',
                        Path.DirectorySeparatorChar)));
            if (!WindowsPreparationPathSafety.IsContainedBy(
                    resolved,
                    _layout.TransactionRoot))
            {
                return false;
            }

            path = resolved;
            return true;
        }
        catch (Exception exception) when (
            WindowsPreparationPathSafety
                .IsOrdinaryFileFailure(exception))
        {
            return false;
        }
    }

    private bool EnsureOwnedAncestors(
        string? directory,
        string root)
    {
        var transactionRoot = _transactionRootLease;
        if (directory is null
            || transactionRoot is null
            || !_createdDirectories.Contains(root)
            || !transactionRoot.Revalidate())
        {
            return false;
        }

        var pending = new Stack<string>();
        for (var current = directory;
             !string.Equals(
                 current,
                 root,
                 StringComparison.OrdinalIgnoreCase);)
        {
            if (!WindowsPreparationPathSafety
                .IsContainedBy(current, root))
            {
                return false;
            }

            pending.Push(current);
            var parent = Path.GetDirectoryName(current);
            if (string.IsNullOrEmpty(parent))
            {
                return false;
            }

            current = parent;
        }

        while (pending.Count > 0)
        {
            if (!EnsureOwnedDirectory(pending.Pop()))
            {
                return false;
            }
        }

        using var rootResult =
            _acl.InspectProtectedDirectory(
                root,
                ProtectedDirectoryInspectionPolicy.Transaction);
        return rootResult.Success
            && rootResult.Lease?.Revalidate() == true
            && transactionRoot.Revalidate();
    }

    private bool EnsureOwnedDirectory(string path)
    {
        var transactionRoot = _transactionRootLease;
        if (transactionRoot is null
            || !transactionRoot.Revalidate())
        {
            return false;
        }

        var canonical = Path.GetFullPath(path);
        if (string.Equals(
                canonical,
                _layout.TransactionRoot,
                StringComparison.OrdinalIgnoreCase))
        {
            return _createdDirectories.Contains(canonical);
        }

        if (!WindowsPreparationPathSafety.IsContainedBy(
                canonical,
                _layout.TransactionRoot))
        {
            return false;
        }

        var relative = Path.GetRelativePath(
            _layout.TransactionRoot,
            canonical);
        var segments = relative.Split(
            [
                Path.DirectorySeparatorChar,
                Path.AltDirectorySeparatorChar
            ],
            StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0
            || segments.Any(segment =>
                segment.Length == 0
                || segment is "." or ".."
                || segment.IndexOfAny(
                    ['\\', '/', ':', '\0']) >= 0))
        {
            return false;
        }

        var parent = _layout.TransactionRoot;
        foreach (var segment in segments)
        {
            var current = Path.GetFullPath(
                Path.Combine(parent, segment));
            if (_createdDirectories.Contains(current))
            {
                using var existing =
                    _acl.InspectProtectedDirectory(
                        current,
                        ProtectedDirectoryInspectionPolicy
                            .Transaction);
                if (!existing.Success
                    || existing.Lease?.Revalidate()
                        != true)
                {
                    return false;
                }

                parent = current;
                continue;
            }

            using var created =
                _acl.EnsureProtectedDirectoryTree(
                    parent,
                    [segment]);
            if (!created.Success
                || !created.Created
                || created.Lease is not { } lease
                || !string.Equals(
                    lease.FinalPath,
                    current,
                    StringComparison.OrdinalIgnoreCase)
                || !lease.Revalidate()
                || !transactionRoot.Revalidate())
            {
                return false;
            }

            _createdDirectories.Add(current);
            parent = current;
        }

        return true;
    }

    private bool HasProductVersion(
        ProtectedEnumeratedFileLease pinned,
        SemanticVersion expected) =>
        RetainedProductVersionVerifier.Matches(
            _versionReader,
            pinned.Stream,
            expected,
            pinned.Revalidate);

    private static bool HasExactCandidateFiles(
        IReadOnlyList<string> actual,
        IReadOnlyList<ReleasePayloadFile> payloads)
    {
        var expected = payloads
            .Select(file => file.Path)
            .Append(
                UpdateReleaseContract.ReleaseManifestPath)
            .ToArray();
        return actual.Count == expected.Length
            && new HashSet<string>(
                    actual,
                    StringComparer.Ordinal)
                .SetEquals(expected)
            && new HashSet<string>(
                    actual,
                    StringComparer.OrdinalIgnoreCase)
                .Count == actual.Count;
    }

    private static bool HasExactCandidateDirectories(
        IReadOnlyList<
            ProtectedEnumeratedDirectorySnapshot> actual,
        IReadOnlyList<ReleasePayloadFile> payloads)
    {
        var expected = new HashSet<string>(
            StringComparer.Ordinal);
        foreach (var payload in payloads)
        {
            var separator = payload.Path.LastIndexOf('/');
            while (separator > 0)
            {
                expected.Add(
                    payload.Path[..separator]);
                separator = payload.Path.LastIndexOf(
                    '/',
                    separator - 1);
            }
        }

        var actualPaths = actual
            .Select(directory => directory.RelativePath)
            .ToArray();
        return actualPaths.Length == expected.Count
            && new HashSet<string>(
                    actualPaths,
                    StringComparer.Ordinal)
                .SetEquals(expected)
            && new HashSet<string>(
                    actualPaths,
                    StringComparer.OrdinalIgnoreCase)
                .Count == actualPaths.Length;
    }

    private static bool MatchesProtectedFile(
        ProtectedEnumeratedFileLease opened,
        ReleasePayloadFile expected)
    {
        try
        {
            var stream = opened.Stream;
            if (stream.Length != expected.Length
                || !opened.Revalidate())
            {
                return false;
            }

            stream.Position = 0;
            var hash = Convert.ToHexString(
                    SHA256.HashData(stream))
                .ToLowerInvariant();
            return stream.Length == expected.Length
                && opened.Revalidate()
                && HashesEqual(hash, expected.Sha256);
        }
        catch (Exception exception) when (
            WindowsPreparationPathSafety
                .IsOrdinaryFileFailure(exception)
            || exception is CryptographicException)
        {
            return false;
        }
    }

    private static ProtectedTransactionId ParseTransactionId(
        string transactionRoot)
    {
        var name = Path.GetFileName(transactionRoot);
        return name is { Length: 32 }
            && Guid.TryParseExact(name, "N", out var value)
            && value != Guid.Empty
            ? new ProtectedTransactionId(value)
            : default;
    }

    private static bool HashesEqual(
        string? first,
        string? second)
    {
        if (first is not { Length: 64 }
            || second is not { Length: 64 })
        {
            return false;
        }

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
}

internal readonly record struct PreparationFileIdentity(
    ulong VolumeSerialNumber,
    ulong FileIdLow,
    ulong FileIdHigh);

internal sealed class PreparationPinnedDirectory : IDisposable
{
    private readonly IReadOnlyList<PinnedDirectoryEntry> _entries;
    private readonly IPathSafetyInspector _pathSafetyInspector;
    private bool _disposed;

    private PreparationPinnedDirectory(
        string path,
        IReadOnlyList<PinnedDirectoryEntry> entries,
        IPathSafetyInspector pathSafetyInspector)
    {
        Path = path;
        _entries = entries;
        _pathSafetyInspector = pathSafetyInspector;
        Identity = entries[^1].Identity;
    }

    public string Path { get; }
    public PreparationFileIdentity Identity { get; }

    public static bool TryOpen(
        string path,
        IPathSafetyInspector pathSafetyInspector,
        out PreparationPinnedDirectory? pinned)
    {
        pinned = null;
        ArgumentNullException.ThrowIfNull(pathSafetyInspector);
        if (!WindowsLocalPath.TryGetCanonicalLocalDosPath(
                path,
                out var canonical)
            || canonical is null
            || !string.Equals(
                canonical,
                path,
                StringComparison.OrdinalIgnoreCase)
            || !WindowsPreparationPathSafety
                .IsSafeExistingDirectory(
                    canonical,
                    pathSafetyInspector)
            || !TryBuildDirectoryChain(
                canonical,
                out var directories))
        {
            return false;
        }

        var entries = new List<PinnedDirectoryEntry>(
            directories.Count);
        try
        {
            foreach (var directory in directories)
            {
                if (!WindowsPreparationPathSafety
                    .TryOpenPinnedDirectoryHandle(
                        directory,
                        pathSafetyInspector,
                        out var handle,
                        out var identity)
                    || handle is null)
                {
                    DisposeEntries(entries);
                    return false;
                }

                entries.Add(
                    new PinnedDirectoryEntry(
                        directory,
                        handle,
                        identity));
            }

            var result = new PreparationPinnedDirectory(
                canonical,
                entries,
                pathSafetyInspector);
            if (!result.Revalidate())
            {
                result.Dispose();
                return false;
            }

            pinned = result;
            return true;
        }
        catch (Exception exception) when (
            WindowsPreparationPathSafety
                .IsOrdinaryFileFailure(exception)
            || exception is Win32Exception)
        {
            DisposeEntries(entries);
            return false;
        }
    }

    public bool Revalidate()
    {
        if (_disposed
            || !WindowsPreparationPathSafety
                .IsSafeExistingDirectory(
                    Path,
                    _pathSafetyInspector))
        {
            return false;
        }

        foreach (var entry in _entries)
        {
            if (entry.Handle.IsInvalid
                || entry.Handle.IsClosed
                || !WindowsPreparationPathSafety
                    .HasExpectedFinalPath(
                        entry.Handle,
                        entry.Path)
                || !WindowsPreparationPathSafety
                    .TryGetHandleIdentity(
                        entry.Handle,
                        out var current)
                || current != entry.Identity
                || !WindowsPreparationPathSafety
                    .HasExpectedHandleKind(
                        entry.Handle,
                        directory: true))
            {
                return false;
            }
        }

        return true;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        DisposeEntries(_entries);
    }

    private static bool TryBuildDirectoryChain(
        string canonical,
        out IReadOnlyList<string> directories)
    {
        directories = [];
        var root = System.IO.Path.GetPathRoot(canonical);
        if (string.IsNullOrEmpty(root)
            || root.StartsWith(
                @"\\",
                StringComparison.Ordinal))
        {
            return false;
        }

        var result = new List<string>
        {
            root
        };
        var relative = canonical[root.Length..];
        var current = root;
        foreach (var component in relative.Split(
            [
                System.IO.Path.DirectorySeparatorChar,
                System.IO.Path.AltDirectorySeparatorChar
            ],
            StringSplitOptions.RemoveEmptyEntries))
        {
            current = System.IO.Path.Combine(
                current,
                component);
            result.Add(current);
        }

        directories = result;
        return result.Count > 0
            && string.Equals(
                result[^1],
                canonical,
                StringComparison.OrdinalIgnoreCase);
    }

    private static void DisposeEntries(
        IEnumerable<PinnedDirectoryEntry> entries)
    {
        foreach (var entry in entries.Reverse())
        {
            entry.Handle.Dispose();
        }
    }

    private sealed record PinnedDirectoryEntry(
        string Path,
        SafeFileHandle Handle,
        PreparationFileIdentity Identity);
}

internal sealed class PreparationPinnedFile : IDisposable
{
    private readonly FileStream _stream;
    private readonly PreparationPinnedDirectory _parentLease;
    private readonly PreparationPinnedDirectory? _retainedRoot;
    private readonly IPathSafetyInspector _pathSafetyInspector;
    private readonly long _length;
    private bool _disposed;

    private PreparationPinnedFile(
        string path,
        FileStream stream,
        PreparationPinnedDirectory parentLease,
        PreparationPinnedDirectory? retainedRoot,
        IPathSafetyInspector pathSafetyInspector,
        PreparationFileIdentity identity)
    {
        Path = path;
        _stream = stream;
        _parentLease = parentLease;
        _retainedRoot = retainedRoot;
        _pathSafetyInspector = pathSafetyInspector;
        _length = stream.Length;
        Identity = identity;
    }

    public string Path { get; }
    public long Length => _length;
    public PreparationFileIdentity Identity { get; }
    public FileStream Stream => _stream;

    public static bool TryOpen(
        string path,
        long maximumBytes,
        IPathSafetyInspector pathSafetyInspector,
        out PreparationPinnedFile? pinned) =>
        TryOpenCore(
            retainedRoot: null,
            path,
            maximumBytes,
            pathSafetyInspector,
            out pinned);

    public static bool TryOpen(
        PreparationPinnedDirectory retainedRoot,
        string path,
        long maximumBytes,
        IPathSafetyInspector pathSafetyInspector,
        out PreparationPinnedFile? pinned)
    {
        ArgumentNullException.ThrowIfNull(retainedRoot);
        return TryOpenCore(
            retainedRoot,
            path,
            maximumBytes,
            pathSafetyInspector,
            out pinned);
    }

    private static bool TryOpenCore(
        PreparationPinnedDirectory? retainedRoot,
        string path,
        long maximumBytes,
        IPathSafetyInspector pathSafetyInspector,
        out PreparationPinnedFile? pinned)
    {
        pinned = null;
        ArgumentNullException.ThrowIfNull(pathSafetyInspector);
        if (maximumBytes < 0
            || !WindowsLocalPath.TryGetCanonicalLocalDosPath(
                path,
                out var canonical)
            || canonical is null
            || !string.Equals(
                canonical,
                path,
                StringComparison.OrdinalIgnoreCase)
            || retainedRoot is not null
                && (!retainedRoot.Revalidate()
                    || !WindowsPreparationPathSafety
                        .IsContainedBy(
                            canonical,
                            retainedRoot.Path))
            || !WindowsPreparationPathSafety
                .IsSafeExistingFile(
                    canonical,
                    pathSafetyInspector))
        {
            return false;
        }

        var parentPath = System.IO.Path
            .GetDirectoryName(canonical);
        if (string.IsNullOrEmpty(parentPath)
            || !PreparationPinnedDirectory.TryOpen(
                parentPath,
                pathSafetyInspector,
                out var parentLease)
            || parentLease is null)
        {
            return false;
        }

        FileStream? stream = null;
        try
        {
            if (retainedRoot is not null
                && (!retainedRoot.Revalidate()
                    || !WindowsPreparationPathSafety
                        .IsContainedByOrEqual(
                            parentLease.Path,
                            retainedRoot.Path)))
            {
                return false;
            }

            stream = new FileStream(
                canonical,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 81920,
                options: FileOptions.Asynchronous
                    | FileOptions.SequentialScan);
            if (stream.Length > maximumBytes
                || !WindowsPreparationPathSafety
                    .HasExpectedFinalPath(
                        stream.SafeFileHandle,
                        canonical)
                || !WindowsPreparationPathSafety
                    .TryGetHandleIdentity(
                        stream.SafeFileHandle,
                        out var identity)
                || !WindowsPreparationPathSafety
                    .HasExpectedHandleKind(
                        stream.SafeFileHandle,
                        directory: false)
                || !parentLease.Revalidate()
                || retainedRoot is not null
                    && !retainedRoot.Revalidate()
                || !WindowsPreparationPathSafety
                    .IsSafeExistingFile(
                        canonical,
                        pathSafetyInspector))
            {
                return false;
            }

            pinned = new PreparationPinnedFile(
                canonical,
                stream,
                parentLease,
                retainedRoot,
                pathSafetyInspector,
                identity);
            stream = null;
            parentLease = null;
            return pinned.Revalidate();
        }
        catch (Exception exception) when (
            WindowsPreparationPathSafety
                .IsOrdinaryFileFailure(exception)
            || exception is Win32Exception)
        {
            return false;
        }
        finally
        {
            stream?.Dispose();
            parentLease?.Dispose();
            if (pinned is not null
                && !pinned.Revalidate())
            {
                pinned.Dispose();
                pinned = null;
            }
        }
    }

    public bool Revalidate()
    {
        if (_disposed
            || _stream.SafeFileHandle.IsInvalid
            || _stream.SafeFileHandle.IsClosed
            || _stream.Length != _length
            || !_parentLease.Revalidate()
            || _retainedRoot is not null
                && !_retainedRoot.Revalidate()
            || !WindowsPreparationPathSafety
                .HasExpectedFinalPath(
                    _stream.SafeFileHandle,
                    Path)
            || !WindowsPreparationPathSafety
                .TryGetHandleIdentity(
                    _stream.SafeFileHandle,
                    out var current)
            || current != Identity
            || !WindowsPreparationPathSafety
                .HasExpectedHandleKind(
                    _stream.SafeFileHandle,
                    directory: false))
        {
            return false;
        }

        return WindowsPreparationPathSafety
            .IsSafeExistingFile(
                Path,
                _pathSafetyInspector);
    }

    public byte[]? ReadAllBytes()
    {
        if (Length > int.MaxValue
            || !Revalidate())
        {
            return null;
        }

        try
        {
            _stream.Position = 0;
            var bytes = new byte[(int)Length];
            _stream.ReadExactly(bytes);
            _stream.Position = 0;
            return Revalidate()
                ? bytes
                : null;
        }
        catch (Exception exception) when (
            WindowsPreparationPathSafety
                .IsOrdinaryFileFailure(exception))
        {
            return null;
        }
    }

    public async Task<string?> ComputeSha256Async(
        CancellationToken cancellationToken)
    {
        try
        {
            if (!Revalidate())
            {
                return null;
            }

            _stream.Position = 0;
            using var sha256 = SHA256.Create();
            var digest = await sha256.ComputeHashAsync(
                    _stream,
                    cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            _stream.Position = 0;
            return Revalidate()
                ? Convert.ToHexString(digest)
                    .ToLowerInvariant()
                : null;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (
            WindowsPreparationPathSafety
                .IsOrdinaryFileFailure(exception)
            || exception is CryptographicException)
        {
            return null;
        }
    }

    public async Task<bool> CopyToAsync(
        Stream destination,
        CancellationToken cancellationToken)
    {
        try
        {
            if (!Revalidate())
            {
                return false;
            }

            _stream.Position = 0;
            await _stream.CopyToAsync(
                    destination,
                    81920,
                    cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            _stream.Position = 0;
            return Revalidate();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (
            WindowsPreparationPathSafety
                .IsOrdinaryFileFailure(exception))
        {
            return false;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _stream.Dispose();
        _parentLease.Dispose();
    }
}

internal readonly record struct PreparationDirectoryIdentity(
    ulong VolumeSerialNumber,
    ulong FileIdLow,
    ulong FileIdHigh);

internal static class WindowsPreparationPathSafety
{
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const int FileIdInfo = 18;
    private const int FileAttributeTagInfo = 9;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeReparsePoint = 0x00000400;

    internal static bool TryOpenPinnedDirectoryHandle(
        string path,
        IPathSafetyInspector inspector,
        out SafeFileHandle? handle,
        out PreparationFileIdentity identity)
    {
        handle = null;
        identity = default;
        if (!WindowsLocalPath.TryGetCanonicalLocalDosPath(
                path,
                out var canonical)
            || canonical is null
            || !string.Equals(
                canonical,
                path,
                StringComparison.OrdinalIgnoreCase)
            || !IsSafeExistingDirectory(
                canonical,
                inspector))
        {
            return false;
        }

        SafeFileHandle? opened = null;
        try
        {
            opened = CreateFileW(
                canonical,
                FileReadAttributes,
                FileShareRead | FileShareWrite,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics
                    | FileFlagOpenReparsePoint,
                IntPtr.Zero);
            if (opened.IsInvalid
                || !HasExpectedFinalPath(opened, canonical)
                || !TryGetHandleIdentity(
                    opened,
                    out identity)
                || !HasExpectedHandleKind(
                    opened,
                    directory: true)
                || !IsSafeExistingDirectory(
                    canonical,
                    inspector))
            {
                identity = default;
                return false;
            }

            handle = opened;
            opened = null;
            return true;
        }
        catch (Exception exception) when (
            IsOrdinaryFileFailure(exception)
            || exception is Win32Exception)
        {
            identity = default;
            return false;
        }
        finally
        {
            opened?.Dispose();
        }
    }

    internal static bool TryGetHandleIdentity(
        SafeFileHandle handle,
        out PreparationFileIdentity identity)
    {
        identity = default;
        if (handle.IsInvalid
            || handle.IsClosed
            || !GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                out var information,
                (uint)Marshal.SizeOf<FileIdInformation>())
            || information.VolumeSerialNumber == 0
            || information.FileId.LowPart == 0
                && information.FileId.HighPart == 0)
        {
            return false;
        }

        identity = new PreparationFileIdentity(
            information.VolumeSerialNumber,
            information.FileId.LowPart,
            information.FileId.HighPart);
        return true;
    }

    internal static bool HasExpectedHandleKind(
        SafeFileHandle handle,
        bool directory)
    {
        if (handle.IsInvalid
            || handle.IsClosed
            || !GetFileAttributeInformationByHandleEx(
                handle,
                FileAttributeTagInfo,
                out var information,
                (uint)Marshal.SizeOf<
                    FileAttributeTagInformation>()))
        {
            return false;
        }

        var isDirectory =
            (information.FileAttributes
                & FileAttributeDirectory) != 0;
        var isReparsePoint =
            (information.FileAttributes
                & FileAttributeReparsePoint) != 0;
        return !isReparsePoint
            && isDirectory == directory;
    }

    public static bool IsSafeExistingFile(
        string? path,
        IPathSafetyInspector inspector)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path)
                || !WindowsLocalPath.TryGetCanonicalLocalDosPath(
                    path,
                    out var canonical)
                || canonical is null
                || !string.Equals(
                    canonical,
                    path,
                    StringComparison.OrdinalIgnoreCase)
                || !File.Exists(canonical)
                || Directory.Exists(canonical)
                || inspector.IsReparsePoint(canonical))
            {
                return false;
            }

            return IsSafeExistingDirectory(
                Path.GetDirectoryName(canonical),
                inspector);
        }
        catch (Exception exception) when (
            IsOrdinaryFileFailure(exception))
        {
            return false;
        }
    }

    public static bool IsSafeExistingDirectory(
        string? path,
        IPathSafetyInspector inspector)
    {
        try
        {
            for (var current = path;
                 !string.IsNullOrEmpty(current);)
            {
                if (!Directory.Exists(current)
                    || File.Exists(current)
                    || inspector.IsReparsePoint(current))
                {
                    return false;
                }

                var parent = Path.GetDirectoryName(current);
                if (string.IsNullOrEmpty(parent)
                    || string.Equals(
                        current,
                        parent,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                current = parent;
            }
        }
        catch (Exception exception) when (
            IsOrdinaryFileFailure(exception))
        {
            return false;
        }

        return false;
    }

    public static bool TryEnumerateRegularFiles(
        string root,
        IPathSafetyInspector inspector,
        out IReadOnlyList<string> relativeFiles)
    {
        relativeFiles = [];
        if (!IsSafeExistingDirectory(root, inspector))
        {
            return false;
        }

        try
        {
            var canonicalRoot = Path.GetFullPath(root);
            var pending = new Stack<string>();
            var files = new List<string>();
            pending.Push(canonicalRoot);
            while (pending.Count > 0)
            {
                var directory = pending.Pop();
                if (!IsContainedByOrEqual(
                        directory,
                        canonicalRoot)
                    || !IsSafeExistingDirectory(
                        directory,
                        inspector))
                {
                    return false;
                }

                foreach (var entry in Directory
                    .EnumerateFileSystemEntries(directory))
                {
                    var canonical = Path.GetFullPath(entry);
                    if (!IsContainedBy(
                            canonical,
                            canonicalRoot))
                    {
                        return false;
                    }

                    if (Directory.Exists(canonical))
                    {
                        if (!IsSafeExistingDirectory(
                                canonical,
                                inspector))
                        {
                            return false;
                        }

                        pending.Push(canonical);
                        continue;
                    }

                    if (!IsSafeExistingFile(
                            canonical,
                            inspector))
                    {
                        return false;
                    }

                    var relative = Path.GetRelativePath(
                            canonicalRoot,
                            canonical)
                        .Replace(
                            Path.DirectorySeparatorChar,
                            '/');
                    var validation =
                        WindowsReleasePathPolicy.Validate(
                            relative);
                    if (!validation.Success
                        || validation.CanonicalKey is null)
                    {
                        return false;
                    }

                    files.Add(validation.CanonicalKey);
                    if (files.Count
                        > WindowsReleasePathPolicy
                            .MaximumArchiveEntries)
                    {
                        return false;
                    }
                }
            }

            relativeFiles = files;
            return IsSafeExistingDirectory(
                canonicalRoot,
                inspector);
        }
        catch (Exception exception) when (
            IsOrdinaryFileFailure(exception))
        {
            return false;
        }
    }

    public static bool TryGetDirectoryIdentity(
        string path,
        IPathSafetyInspector inspector,
        out PreparationDirectoryIdentity identity)
    {
        identity = default;
        if (!IsSafeExistingDirectory(path, inspector))
        {
            return false;
        }

        SafeFileHandle? handle = null;
        try
        {
            var canonical = Path.GetFullPath(path);
            handle = CreateFileW(
                canonical,
                FileReadAttributes,
                FileShareRead,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics
                    | FileFlagOpenReparsePoint,
                IntPtr.Zero);
            if (handle.IsInvalid
                || !HasExpectedFinalPath(handle, canonical)
                || !GetFileInformationByHandleEx(
                    handle,
                    FileIdInfo,
                    out var information,
                    (uint)Marshal.SizeOf<FileIdInformation>())
                || information.VolumeSerialNumber == 0
                || information.FileId.LowPart == 0
                    && information.FileId.HighPart == 0
                || !IsSafeExistingDirectory(
                    canonical,
                    inspector))
            {
                return false;
            }

            identity = new PreparationDirectoryIdentity(
                information.VolumeSerialNumber,
                information.FileId.LowPart,
                information.FileId.HighPart);
            return true;
        }
        catch (Exception exception) when (
            IsOrdinaryFileFailure(exception)
            || exception is Win32Exception)
        {
            return false;
        }
        finally
        {
            handle?.Dispose();
        }
    }

    public static string? ResolveReleasePath(
        string root,
        string? relativePath)
    {
        var validation =
            WindowsReleasePathPolicy.Validate(relativePath);
        if (!validation.Success
            || validation.CanonicalKey is null)
        {
            return null;
        }

        try
        {
            var canonicalRoot = Path.GetFullPath(root);
            var path = Path.GetFullPath(
                Path.Combine(
                    canonicalRoot,
                    validation.CanonicalKey.Replace(
                        '/',
                        Path.DirectorySeparatorChar)));
            return IsContainedBy(path, canonicalRoot)
                ? path
                : null;
        }
        catch (Exception exception) when (
            IsOrdinaryFileFailure(exception))
        {
            return null;
        }
    }

    public static bool HasExpectedFinalPath(
        SafeFileHandle handle,
        string expectedPath)
    {
        var capacity = 512;
        while (capacity <= 32768)
        {
            var buffer = new StringBuilder(capacity);
            var length = GetFinalPathNameByHandleW(
                handle,
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
                        @"\\?\UNC\",
                        StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                if (finalPath.StartsWith(
                        @"\\?\",
                        StringComparison.OrdinalIgnoreCase))
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

    public static bool IsContainedBy(
        string path,
        string root) =>
        path.StartsWith(
            root + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase);

    public static bool IsContainedByOrEqual(
        string path,
        string root) =>
        string.Equals(
            path,
            root,
            StringComparison.OrdinalIgnoreCase)
        || IsContainedBy(path, root);

    public static bool IsOrdinaryFileFailure(
        Exception exception) =>
        exception is IOException
            or UnauthorizedAccessException
            or ArgumentException
            or InvalidOperationException
            or NotSupportedException
            or ObjectDisposedException
            or System.Security.SecurityException;

    [StructLayout(LayoutKind.Sequential)]
    private struct FileId128
    {
        public ulong LowPart;
        public ulong HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInformation
    {
        public ulong VolumeSerialNumber;
        public FileId128 FileId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInformation
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle file,
        StringBuilder filePath,
        uint filePathLength,
        uint flags);

    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        int fileInformationClass,
        out FileIdInformation fileInformation,
        uint bufferSize);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetFileInformationByHandleEx",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool
        GetFileAttributeInformationByHandleEx(
            SafeFileHandle file,
            int fileInformationClass,
            out FileAttributeTagInformation fileInformation,
            uint bufferSize);
}

internal static class ProtectedPreparationManifestCodec
{
    private static readonly string[] ManifestProperties =
    [
        "schemaVersion",
        "version",
        "runtimeIdentifier",
        "minimumAutoUpdateVersion",
        "rollbackCompatibleFromVersion",
        "stateSchemaVersion",
        "entryPoint",
        "updaterEntryPoint",
        "requiredLaunchers",
        "files"
    ];

    private static readonly string[] FileProperties =
        ["path", "length", "sha256"];

    public static bool TryParse(
        byte[]? bytes,
        out ReleaseManifest? manifest)
    {
        manifest = null;
        if (bytes is null
            || bytes.LongLength
                > UpdateNetworkLimits.MetadataBytes)
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(
                bytes,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling =
                        JsonCommentHandling.Disallow,
                    MaxDepth = 32
                });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !HasExactProperties(
                    root,
                    ManifestProperties)
                || root.GetProperty("schemaVersion").ValueKind
                    != JsonValueKind.Number
                || root.GetProperty("version").ValueKind
                    != JsonValueKind.String
                || root.GetProperty("runtimeIdentifier").ValueKind
                    != JsonValueKind.String
                || root.GetProperty(
                        "minimumAutoUpdateVersion").ValueKind
                    != JsonValueKind.String
                || root.GetProperty(
                        "rollbackCompatibleFromVersion").ValueKind
                    != JsonValueKind.String
                || root.GetProperty("stateSchemaVersion").ValueKind
                    != JsonValueKind.Number
                || root.GetProperty("entryPoint").ValueKind
                    != JsonValueKind.String
                || root.GetProperty("updaterEntryPoint").ValueKind
                    != JsonValueKind.String
                || root.GetProperty("requiredLaunchers").ValueKind
                    != JsonValueKind.Array
                || root.GetProperty("files").ValueKind
                    != JsonValueKind.Array)
            {
                return false;
            }

            var launchers =
                root.GetProperty("requiredLaunchers");
            var files = root.GetProperty("files");
            if (launchers.GetArrayLength()
                    != UpdateReleaseContract
                        .RequiredLauncherPaths.Count
                || files.GetArrayLength() is < 1
                    or > WindowsReleasePathPolicy
                        .MaximumArchiveEntries - 1)
            {
                return false;
            }

            foreach (var launcher in launchers.EnumerateArray())
            {
                if (launcher.ValueKind
                    != JsonValueKind.String)
                {
                    return false;
                }
            }

            foreach (var file in files.EnumerateArray())
            {
                if (file.ValueKind != JsonValueKind.Object
                    || !HasExactProperties(
                        file,
                        FileProperties)
                    || file.GetProperty("path").ValueKind
                        != JsonValueKind.String
                    || file.GetProperty("length").ValueKind
                        != JsonValueKind.Number
                    || file.GetProperty("sha256").ValueKind
                        != JsonValueKind.String)
                {
                    return false;
                }
            }

            manifest = JsonSerializer.Deserialize<ReleaseManifest>(
                bytes,
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = false,
                    PropertyNamingPolicy =
                        JsonNamingPolicy.CamelCase,
                    AllowTrailingCommas = false,
                    ReadCommentHandling =
                        JsonCommentHandling.Disallow,
                    MaxDepth = 32
                });
            return manifest is not null;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool HasExactProperties(
        JsonElement element,
        IReadOnlyCollection<string> expected)
    {
        var names = new HashSet<string>(
            StringComparer.Ordinal);
        var count = 0;
        foreach (var property in element.EnumerateObject())
        {
            count++;
            if (!expected.Contains(
                    property.Name,
                    StringComparer.Ordinal)
                || !names.Add(property.Name))
            {
                return false;
            }
        }

        return count == expected.Count;
    }
}

internal sealed partial class WindowsProtectedPreparationArtifactBuilder
{
    private sealed record InstalledSnapshotResult(
        bool Success,
        ProtectedInstalledReleaseIdentity? Identity,
        long CurrentManagedBytes,
        string? DetailCode);

    private sealed record CandidateSnapshotResult(
        bool Success,
        ReleaseManifest? Manifest,
        byte[]? ManifestBytes,
        long ArchiveBytes,
        long ExpandedBytes,
        ProtectedTransactionPreparationError Error,
        string? DetailCode);

    private async Task<InstalledSnapshotResult>
        SnapshotInstalledAsync(
            InstalledReleaseLocation installed,
            int supportedStateSchemaVersion,
            UpdatePackageLimits limits,
            CancellationToken cancellationToken)
    {
        if (installed.Status
                != InstalledReleaseLocatorStatus.Available
            || installed.InstallationRoot is null
            || installed.ApplicationPath is null
            || installed.UpdaterPath is null
            || installed.Version is null)
        {
            return new InstalledSnapshotResult(
                false,
                null,
                0,
                "installed_root");
        }

        using var rootResult =
            _acl.InspectProtectedDirectory(
                installed.InstallationRoot,
                ProtectedDirectoryInspectionPolicy
                    .InstalledRelease);
        if (!rootResult.Success
            || rootResult.Lease is not { } root
            || !string.Equals(
                root.FinalPath,
                installed.InstallationRoot,
                StringComparison.OrdinalIgnoreCase)
            || !root.Identity.IsValid)
        {
            return new InstalledSnapshotResult(
                false,
                null,
                0,
                "installed_root_policy");
        }

        using var manifestResult =
            _acl.OpenProtectedFileForRead(
                root,
                UpdateReleaseContract.ReleaseManifestPath,
                ProtectedDirectoryInspectionPolicy
                    .InstalledRelease);
        if (!manifestResult.Success
            || manifestResult.Lease is not { } manifestFile
            || !manifestFile.TryReadAllBytes(
                UpdateNetworkLimits.MetadataBytes,
                out var manifestBytes))
        {
            return new InstalledSnapshotResult(
                false,
                null,
                0,
                "installed_manifest");
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (!ProtectedPreparationManifestCodec.TryParse(
                manifestBytes,
                out var manifest)
            || manifest is null
            || !TryValidateInstalledManifest(
                manifest,
                installed,
                supportedStateSchemaVersion,
                out var currentVersion,
                out var minimumVersion,
                out var rollbackVersion,
                out var managedManifestFiles))
        {
            return new InstalledSnapshotResult(
                false,
                null,
                0,
                "installed_manifest_contract");
        }

        var manifestHash = CanonicalHash(
            Convert.ToHexString(
                SHA256.HashData(manifestBytes)));
        if (!IsCanonicalSha256(manifestHash)
            || !manifestFile.Revalidate())
        {
            return new InstalledSnapshotResult(
                false,
                null,
                0,
                "installed_manifest_hash");
        }

        var managed =
            new List<ProtectedManagedFileIdentity>(
                managedManifestFiles.Count);
        long managedBytes = manifestBytes.LongLength;
        foreach (var file in managedManifestFiles
            .OrderBy(
                file => file.Path,
                StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var openedResult =
                _acl.OpenProtectedFileForRead(
                    root,
                    file.Path,
                    ProtectedDirectoryInspectionPolicy
                        .InstalledRelease);
            if (!openedResult.Success
                || openedResult.Lease is not { } opened)
            {
                return new InstalledSnapshotResult(
                    false,
                    null,
                    0,
                    "installed_payload_open");
            }

            var stream = opened.Stream;
            var length = stream.Length;
            if (length < 0
                || length > limits.MaximumFileBytes)
            {
                return new InstalledSnapshotResult(
                    false,
                    null,
                    0,
                    "installed_payload_length");
            }

            stream.Position = 0;
            using var sha256 = SHA256.Create();
            var digest = await sha256.ComputeHashAsync(
                    stream,
                    cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            var hash = CanonicalHash(
                Convert.ToHexString(digest));
            if (stream.Length != length
                || length != file.Length
                || !HashesEqual(hash, file.Sha256)
                || !opened.Revalidate())
            {
                return new InstalledSnapshotResult(
                    false,
                    null,
                    0,
                    "installed_payload_hash");
            }

            managedBytes = checked(
                managedBytes + length);
            managed.Add(
                new ProtectedManagedFileIdentity(
                    file.Path,
                    length,
                    hash));
        }

        var expectedApplication =
            WindowsPreparationPathSafety.ResolveReleasePath(
                installed.InstallationRoot,
                UpdateReleaseContract.WindowsApplicationPath);
        var expectedUpdater =
            WindowsPreparationPathSafety.ResolveReleasePath(
                installed.InstallationRoot,
                UpdateReleaseContract.WindowsUpdaterPath);
        using var applicationResult =
            _acl.OpenProtectedFileForRead(
                root,
                UpdateReleaseContract.WindowsApplicationPath,
                ProtectedDirectoryInspectionPolicy
                    .InstalledRelease);
        using var updaterResult =
            _acl.OpenProtectedFileForRead(
                root,
                UpdateReleaseContract.WindowsUpdaterPath,
                ProtectedDirectoryInspectionPolicy
                    .InstalledRelease);
        if (expectedApplication is null
            || expectedUpdater is null
            || !string.Equals(
                expectedApplication,
                installed.ApplicationPath,
                StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                expectedUpdater,
                installed.UpdaterPath,
                StringComparison.OrdinalIgnoreCase)
            || !applicationResult.Success
            || applicationResult.Lease
                is not { } applicationFile
            || !updaterResult.Success
            || updaterResult.Lease is not { } updaterFile
            || !HasProductVersion(
                applicationFile,
                currentVersion)
            || !HasProductVersion(
                updaterFile,
                currentVersion)
            || !manifestFile.Revalidate()
            || !root.Revalidate())
        {
            return new InstalledSnapshotResult(
                false,
                null,
                0,
                "installed_identity_changed");
        }

        return new InstalledSnapshotResult(
            true,
            new ProtectedInstalledReleaseIdentity(
                installed.InstallationRoot,
                root.Identity.VolumeSerialNumber,
                root.Identity.FileIdLow,
                root.Identity.FileIdHigh,
                currentVersion,
                minimumVersion,
                rollbackVersion,
                manifest.StateSchemaVersion,
                UpdateReleaseContract
                    .WindowsApplicationPath,
                UpdateReleaseContract
                    .WindowsUpdaterPath,
                manifestHash,
                managed),
            managedBytes,
            null);
    }

    private async Task<CandidateSnapshotResult>
        VerifyCandidateAsync(
            ProtectedTransactionPreparationRequest request,
            LocalUpdateLayout local,
            SemanticVersion currentVersion,
            CancellationToken cancellationToken)
    {
        PreparationPinnedDirectory? versionRoot = null;
        PreparationPinnedDirectory? candidateRoot = null;
        PreparationPinnedFile? archive = null;
        PreparationPinnedFile? checksum = null;
        if (local.Version != request.TrustedRelease.Version
            || !PreparationPinnedDirectory.TryOpen(
                local.VersionRoot,
                _pathSafetyInspector,
                out versionRoot)
            || versionRoot is null
            || !PreparationPinnedDirectory.TryOpen(
                local.CandidateRoot,
                _pathSafetyInspector,
                out candidateRoot)
            || candidateRoot is null
            || !WindowsPreparationPathSafety.IsContainedBy(
                candidateRoot.Path,
                versionRoot.Path)
            || !PreparationPinnedFile.TryOpen(
                versionRoot,
                local.ArchivePath,
                UpdateNetworkLimits.ArchiveBytes,
                _pathSafetyInspector,
                out archive)
            || archive is null
            || !PreparationPinnedFile.TryOpen(
                versionRoot,
                local.ChecksumPath,
                UpdateNetworkLimits.MetadataBytes,
                _pathSafetyInspector,
                out checksum)
            || checksum is null)
        {
            checksum?.Dispose();
            archive?.Dispose();
            candidateRoot?.Dispose();
            versionRoot?.Dispose();
            return CandidateFailure("source_open");
        }

        using (versionRoot)
        using (candidateRoot)
        using (archive)
        using (checksum)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var sidecar = Sha256SidecarParser.Parse(
                checksum.ReadAllBytes());
            if (!sidecar.Success
                || !HashesEqual(
                    sidecar.Digest,
                    request.TrustedRelease.ArchiveSha256)
                || !checksum.Revalidate())
            {
                return CandidateFailure("checksum");
            }

            if (!archive.Revalidate())
            {
                return CandidateFailure("archive_identity");
            }

            using var opened = SafeZipExtractor.Open(
                archive.Stream,
                request.Limits,
                _pathSafetyInspector);
            if (!opened.Success
                || opened.Session is null
                || !archive.Revalidate())
            {
                return CandidateFailure("archive_open");
            }

            var archiveHash = await opened.Session
                .ComputeSha256Async(cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (!archiveHash.Success
                || !HashesEqual(
                    archiveHash.Digest,
                    request.TrustedRelease.ArchiveSha256)
                || archive.Length
                    > UpdateNetworkLimits.ArchiveBytes
                || !archive.Revalidate())
            {
                return CandidateFailure("archive_hash");
            }

            var preflight = opened.Session.Preflight();
            if (!preflight.Success
                || !archive.Revalidate())
            {
                return CandidateFailure("archive_preflight");
            }

            var manifestRead =
                opened.Session.ReadManifest();
            if (!manifestRead.Success
                || manifestRead.Bytes is null
                || !ProtectedPreparationManifestCodec.TryParse(
                    manifestRead.Bytes,
                    out var untrustedManifest)
                || !archive.Revalidate())
            {
                return CandidateFailure("manifest_parse");
            }

            var regularFiles = opened.Session.Entries
                .Where(entry => !entry.IsDirectory)
                .Select(entry => (string?)entry.Path)
                .ToArray();
            var validated =
                ReleaseManifestValidator.Validate(
                    untrustedManifest,
                    request.TrustedRelease.Version,
                    currentVersion,
                    request.SupportedStateSchemaVersion,
                    regularFiles);
            if (!validated.IsValid
                || validated.Manifest is null)
            {
                return CandidateFailure(
                    "manifest_contract");
            }

            var manifestHash = CanonicalHash(
                Convert.ToHexString(
                    SHA256.HashData(
                        manifestRead.Bytes)));
            if (!HashesEqual(
                    manifestHash,
                    request.TrustedRelease
                        .NewManifestSha256)
                || !TryExpandedBytes(
                    opened.Session.Entries,
                    out var expandedBytes))
            {
                return CandidateFailure(
                    "manifest_binding");
            }

            if (!PreparationPinnedFile.TryOpen(
                    candidateRoot,
                    local.ManifestPath,
                    UpdateNetworkLimits.MetadataBytes,
                    _pathSafetyInspector,
                    out var localManifest)
                || localManifest is null)
            {
                return CandidateFailure(
                    "candidate_manifest_open");
            }

            using (localManifest)
            {
                var localManifestBytes =
                    localManifest.ReadAllBytes();
                var localManifestHash =
                    await localManifest.ComputeSha256Async(
                            cancellationToken)
                        .ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                if (localManifestBytes is null
                    || !localManifestBytes.AsSpan()
                        .SequenceEqual(manifestRead.Bytes)
                    || !HashesEqual(
                        localManifestHash,
                        manifestHash)
                    || !localManifest.Revalidate())
                {
                    return CandidateFailure(
                        "candidate_manifest_hash");
                }
            }

            if (!WindowsPreparationPathSafety
                .TryEnumerateRegularFiles(
                    local.CandidateRoot,
                    _pathSafetyInspector,
                    out var candidateFiles)
                || !HasExactCandidateFiles(
                    candidateFiles,
                    validated.Manifest.Files!))
            {
                return CandidateFailure(
                    "candidate_file_set");
            }

            foreach (var file in validated.Manifest.Files!)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var path =
                    WindowsPreparationPathSafety
                        .ResolveReleasePath(
                            local.CandidateRoot,
                            file.Path);
                if (path is null
                    || !PreparationPinnedFile.TryOpen(
                        candidateRoot,
                        path,
                        request.Limits.MaximumFileBytes,
                        _pathSafetyInspector,
                        out var payload)
                    || payload is null)
                {
                    return CandidateFailure(
                        "candidate_payload_open");
                }

                using (payload)
                {
                    var hash = await payload
                        .ComputeSha256Async(
                            cancellationToken)
                        .ConfigureAwait(false);
                    cancellationToken.ThrowIfCancellationRequested();
                    if (payload.Length != file.Length
                        || !HashesEqual(
                            hash,
                            file.Sha256)
                        || !payload.Revalidate())
                    {
                        return CandidateFailure(
                            "candidate_payload_hash");
                    }
                }
            }

            var application =
                WindowsPreparationPathSafety.ResolveReleasePath(
                    local.CandidateRoot,
                    UpdateReleaseContract.WindowsApplicationPath);
            var updater =
                WindowsPreparationPathSafety.ResolveReleasePath(
                    local.CandidateRoot,
                    UpdateReleaseContract.WindowsUpdaterPath);
            if (application is null
                || updater is null
                || !PreparationPinnedFile.TryOpen(
                    candidateRoot,
                    application,
                    request.Limits.MaximumFileBytes,
                    _pathSafetyInspector,
                    out var applicationLease)
                || applicationLease is null
                || !PreparationPinnedFile.TryOpen(
                    candidateRoot,
                    updater,
                    request.Limits.MaximumFileBytes,
                    _pathSafetyInspector,
                    out var updaterLease)
                || updaterLease is null)
            {
                return CandidateFailure(
                    "candidate_product_version");
            }

            using (applicationLease)
            using (updaterLease)
            {
                if (!HasProductVersion(
                        applicationLease,
                        request.TrustedRelease.Version)
                    || !HasProductVersion(
                        updaterLease,
                        request.TrustedRelease.Version)
                    || !archive.Revalidate()
                    || !versionRoot.Revalidate()
                    || !candidateRoot.Revalidate())
                {
                    return CandidateFailure(
                        "candidate_product_version");
                }
            }

            return new CandidateSnapshotResult(
                true,
                validated.Manifest,
                manifestRead.Bytes,
                archive.Length,
                expandedBytes,
                ProtectedTransactionPreparationError.None,
                null);
        }
    }

    private async Task<bool> CopyCandidateAsync(
        WindowsProtectedTransactionPreparationWorkspace workspace,
        LocalUpdateLayout local,
        CandidateSnapshotResult candidate,
        CancellationToken cancellationToken)
    {
        var manifest = new ReleasePayloadFile(
            UpdateReleaseContract.ReleaseManifestPath,
            candidate.ManifestBytes!.LongLength,
            candidate.Manifest is not null
                ? CanonicalHash(
                    Convert.ToHexString(
                        SHA256.HashData(
                            candidate.ManifestBytes)))
                : string.Empty);
        var files = new List<ReleasePayloadFile>
        {
            manifest
        };
        files.AddRange(candidate.Manifest!.Files!);

        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var source =
                WindowsPreparationPathSafety.ResolveReleasePath(
                    local.CandidateRoot,
                    file.Path);
            if (source is null)
            {
                return false;
            }

            var copied = await workspace.CopyCandidateFileAsync(
                    source,
                    file,
                    cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (!copied)
            {
                return false;
            }
        }

        return true;
    }

    private bool HasProductVersion(
        PreparationPinnedFile pinned,
        SemanticVersion expected) =>
        RetainedProductVersionVerifier.Matches(
            _versionReader,
            pinned.Stream,
            expected,
            pinned.Revalidate);

    private bool HasProductVersion(
        ProtectedFileReadLease pinned,
        SemanticVersion expected) =>
        RetainedProductVersionVerifier.Matches(
            _versionReader,
            pinned.Stream,
            expected,
            pinned.Revalidate);

    private static bool TryValidateInstalledManifest(
        ReleaseManifest manifest,
        InstalledReleaseLocation installed,
        int supportedStateSchemaVersion,
        out SemanticVersion currentVersion,
        out SemanticVersion minimumVersion,
        out SemanticVersion rollbackVersion,
        out IReadOnlyList<ReleasePayloadFile> files)
    {
        currentVersion = default;
        minimumVersion = default;
        rollbackVersion = default;
        files = [];
        if (manifest.SchemaVersion != 1
            || manifest.StateSchemaVersion
                != supportedStateSchemaVersion
            || manifest.RuntimeIdentifier
                != UpdateReleaseContract
                    .WindowsRuntimeIdentifier
            || manifest.EntryPoint
                != UpdateReleaseContract
                    .WindowsApplicationPath
            || manifest.UpdaterEntryPoint
                != UpdateReleaseContract.WindowsUpdaterPath
            || !SemanticVersion.TryParseNormalized(
                manifest.Version,
                out currentVersion)
            || installed.Version != currentVersion
            || !SemanticVersion.TryParseNormalized(
                manifest.MinimumAutoUpdateVersion,
                out minimumVersion)
            || !SemanticVersion.TryParseNormalized(
                manifest.RollbackCompatibleFromVersion,
                out rollbackVersion)
            || currentVersion.CompareTo(minimumVersion) < 0
            || currentVersion.CompareTo(rollbackVersion) < 0
            || !HasExactLaunchers(
                manifest.RequiredLaunchers)
            || manifest.Files is null
            || manifest.Files.Count is < 1
                or > WindowsReleasePathPolicy
                    .MaximumArchiveEntries - 1)
        {
            return false;
        }

        var paths = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase);
        var exact = new HashSet<string>(
            StringComparer.Ordinal);
        var snapshot =
            new List<ReleasePayloadFile>(
                manifest.Files.Count);
        foreach (var file in manifest.Files)
        {
            var validation =
                WindowsReleasePathPolicy.Validate(file?.Path);
            if (file is null
                || !validation.Success
                || validation.CanonicalKey is null
                || ReleaseManagedPathPolicy
                    .IsProtectedPayloadPath(
                        validation.CanonicalKey)
                || file.Length < 0
                || !IsSha256(file.Sha256)
                || !paths.Add(validation.CanonicalKey)
                || !exact.Add(validation.CanonicalKey))
            {
                return false;
            }

            snapshot.Add(
                new ReleasePayloadFile(
                    validation.CanonicalKey,
                    file.Length,
                    CanonicalHash(file.Sha256)));
        }

        if (!paths.Contains(
                UpdateReleaseContract.WindowsApplicationPath)
            || !paths.Contains(
                UpdateReleaseContract.WindowsUpdaterPath)
            || !UpdateReleaseContract.RequiredLauncherPaths
                .All(paths.Contains))
        {
            return false;
        }

        files = snapshot;
        return true;
    }

    private static bool HasExactLaunchers(
        IReadOnlyList<string>? launchers) =>
        launchers is not null
        && launchers.Count
            == UpdateReleaseContract.RequiredLauncherPaths.Count
        && new HashSet<string>(
                launchers,
                StringComparer.Ordinal)
            .SetEquals(
                UpdateReleaseContract.RequiredLauncherPaths)
        && new HashSet<string>(
                launchers,
                StringComparer.OrdinalIgnoreCase)
            .Count == launchers.Count;

    private static bool HasExactCandidateFiles(
        IReadOnlyList<string> actual,
        IReadOnlyList<ReleasePayloadFile> payloads)
    {
        var expected = payloads
            .Select(file => file.Path)
            .Append(
                UpdateReleaseContract.ReleaseManifestPath)
            .ToArray();
        return actual.Count == expected.Length
            && new HashSet<string>(
                    actual,
                    StringComparer.Ordinal)
                .SetEquals(expected)
            && new HashSet<string>(
                    actual,
                    StringComparer.OrdinalIgnoreCase)
                .SetEquals(expected)
            && new HashSet<string>(
                    actual,
                    StringComparer.OrdinalIgnoreCase)
                .Count == actual.Count;
    }

    private static bool TryExpandedBytes(
        IReadOnlyList<SafeZipEntryMetadata> entries,
        out long expandedBytes)
    {
        expandedBytes = 0;
        try
        {
            foreach (var entry in entries)
            {
                if (!entry.IsDirectory)
                {
                    expandedBytes = checked(
                        expandedBytes + entry.Length);
                }
            }

            return expandedBytes > 0;
        }
        catch (OverflowException)
        {
            expandedBytes = 0;
            return false;
        }
    }

    private static CandidateSnapshotResult CandidateFailure(
        string detailCode) =>
        new(
            false,
            null,
            null,
            0,
            0,
            ProtectedTransactionPreparationError
                .VerificationFailed,
            detailCode);

    private static bool IsSha256(string? value) =>
        value is { Length: 64 }
        && value.All(character =>
            character is >= '0' and <= '9'
                or >= 'a' and <= 'f'
                or >= 'A' and <= 'F');

    private static bool IsCanonicalSha256(
        string? value) =>
        value is { Length: 64 }
        && value.All(character =>
            character is >= '0' and <= '9'
                or >= 'a' and <= 'f');

    private static string CanonicalHash(
        string value) =>
        value.ToLowerInvariant();

    private static bool HashesEqual(
        string? first,
        string? second)
    {
        if (!IsSha256(first)
            || !IsSha256(second))
        {
            return false;
        }

        try
        {
            return CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(first!),
                Convert.FromHexString(second!));
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
