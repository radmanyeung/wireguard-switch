using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate.Transactions;

public enum ProtectedTransactionPathError
{
    None,
    InvalidRoot,
    InvalidTransactionId,
    InvalidRelativePath,
    UnsafePath
}

public readonly record struct ProtectedTransactionId(Guid Value)
{
    public bool IsValid => Value != Guid.Empty;

    public string DirectoryName => Value.ToString("N").ToLowerInvariant();

    public static ProtectedTransactionId New() => new(Guid.NewGuid());

    public override string ToString() => DirectoryName;
}

public sealed record ProtectedTransactionRootLayout
{
    internal ProtectedTransactionRootLayout(
        string productRoot,
        string transactionsRoot,
        string activePointerPath)
    {
        ProductRoot = productRoot;
        TransactionsRoot = transactionsRoot;
        ActivePointerPath = activePointerPath;
    }

    public string ProductRoot { get; }
    public string TransactionsRoot { get; }
    public string ActivePointerPath { get; }
}

public sealed record ProtectedTransactionLayout
{
    internal ProtectedTransactionLayout(
        string productRoot,
        string transactionsRoot,
        string activePointerPath,
        string transactionRoot,
        string transactionRecordPath,
        string journalPath,
        string healthPath,
        string helperRoot,
        string helperPath,
        string candidateRoot,
        string backupsRoot)
    {
        ProductRoot = productRoot;
        TransactionsRoot = transactionsRoot;
        ActivePointerPath = activePointerPath;
        TransactionRoot = transactionRoot;
        TransactionRecordPath = transactionRecordPath;
        JournalPath = journalPath;
        HealthPath = healthPath;
        HelperRoot = helperRoot;
        HelperPath = helperPath;
        CandidateRoot = candidateRoot;
        BackupsRoot = backupsRoot;
    }

    public string ProductRoot { get; }
    public string TransactionsRoot { get; }
    public string ActivePointerPath { get; }
    public string TransactionRoot { get; }
    public string TransactionRecordPath { get; }
    public string JournalPath { get; }
    public string HealthPath { get; }
    public string HelperRoot { get; }
    public string HelperPath { get; }
    public string CandidateRoot { get; }
    public string BackupsRoot { get; }
}

public readonly record struct ProtectedTransactionRootResult(
    bool Success,
    ProtectedTransactionRootLayout? Layout,
    ProtectedTransactionPathError Error)
{
    internal static ProtectedTransactionRootResult Valid(ProtectedTransactionRootLayout layout) =>
        new(true, layout, ProtectedTransactionPathError.None);

    internal static ProtectedTransactionRootResult Failed(ProtectedTransactionPathError error) =>
        new(false, null, error);
}

public readonly record struct ProtectedTransactionLayoutResult(
    bool Success,
    ProtectedTransactionLayout? Layout,
    ProtectedTransactionPathError Error)
{
    internal static ProtectedTransactionLayoutResult Valid(ProtectedTransactionLayout layout) =>
        new(true, layout, ProtectedTransactionPathError.None);

    internal static ProtectedTransactionLayoutResult Failed(ProtectedTransactionPathError error) =>
        new(false, null, error);
}

public readonly record struct ProtectedTransactionResolvedPathResult(
    bool Success,
    string? Path,
    ProtectedTransactionPathError Error)
{
    internal static ProtectedTransactionResolvedPathResult Valid(string path) =>
        new(true, path, ProtectedTransactionPathError.None);

    internal static ProtectedTransactionResolvedPathResult Failed(ProtectedTransactionPathError error) =>
        new(false, null, error);
}

/// <summary>
/// Derives every protected update path from the fixed ProgramData authority.
/// Persisted child paths are never accepted by this type.
/// </summary>
public sealed class ProtectedTransactionPaths
{
    private const string ProductDirectoryName = "WireguardSplitTunnel";
    private const string TransactionsDirectoryName = "UpdateTransactions";
    private const string ActivePointerFileName = "active-transaction.json";
    private const string TransactionFileName = "transaction.json";
    private const string JournalFileName = "journal.json";
    private const string HealthFileName = "health.json";
    private const string HelperFileName = "WireguardSplitTunnel.Updater.exe";

    private readonly string? _productRoot;
    private readonly IPathSafetyInspector _pathSafetyInspector;
    private readonly Func<string, DriveType> _getDriveType;

    public ProtectedTransactionPaths()
        : this(
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                ProductDirectoryName),
            new WindowsPathSafetyInspector(),
            root => new DriveInfo(root).DriveType)
    {
    }

    internal ProtectedTransactionPaths(
        string? productRoot,
        IPathSafetyInspector pathSafetyInspector,
        Func<string, DriveType> getDriveType)
    {
        _productRoot = productRoot;
        _pathSafetyInspector = pathSafetyInspector ?? throw new ArgumentNullException(nameof(pathSafetyInspector));
        _getDriveType = getDriveType ?? throw new ArgumentNullException(nameof(getDriveType));
    }

    public ProtectedTransactionRootResult GetRoot()
    {
        if (!WindowsLocalPath.TryGetCanonicalLocalDosPath(
                _productRoot,
                _getDriveType,
                out var productRoot)
            || productRoot is null)
        {
            return ProtectedTransactionRootResult.Failed(
                ProtectedTransactionPathError.InvalidRoot);
        }

        var transactionsRoot = Path.Combine(
            productRoot,
            TransactionsDirectoryName);
        var activePointerPath = Path.Combine(
            transactionsRoot,
            ActivePointerFileName);

        if (!IsSafeProspectiveDirectory(productRoot)
            || !IsSafeProspectiveDirectory(transactionsRoot)
            || !IsSafeProspectiveFile(activePointerPath))
        {
            return ProtectedTransactionRootResult.Failed(
                ProtectedTransactionPathError.UnsafePath);
        }

        return ProtectedTransactionRootResult.Valid(
            new ProtectedTransactionRootLayout(
                productRoot,
                transactionsRoot,
                activePointerPath));
    }

    public ProtectedTransactionLayoutResult GetLayout(
        ProtectedTransactionId transactionId)
    {
        if (!transactionId.IsValid)
        {
            return ProtectedTransactionLayoutResult.Failed(
                ProtectedTransactionPathError.InvalidTransactionId);
        }

        var rootResult = GetRoot();
        if (!rootResult.Success || rootResult.Layout is null)
        {
            return ProtectedTransactionLayoutResult.Failed(rootResult.Error);
        }

        var root = rootResult.Layout;
        var transactionRoot = Path.Combine(
            root.TransactionsRoot,
            transactionId.DirectoryName);
        var helperRoot = Path.Combine(transactionRoot, "helper");
        var layout = new ProtectedTransactionLayout(
            root.ProductRoot,
            root.TransactionsRoot,
            root.ActivePointerPath,
            transactionRoot,
            Path.Combine(transactionRoot, TransactionFileName),
            Path.Combine(transactionRoot, JournalFileName),
            Path.Combine(transactionRoot, HealthFileName),
            helperRoot,
            Path.Combine(helperRoot, HelperFileName),
            Path.Combine(transactionRoot, "candidate"),
            Path.Combine(transactionRoot, "backups"));

        if (!HasCanonicalContainedLayout(layout)
            || !IsSafeProspectiveDirectory(layout.TransactionRoot)
            || !IsSafeProspectiveFile(layout.TransactionRecordPath)
            || !IsSafeProspectiveFile(layout.JournalPath)
            || !IsSafeProspectiveFile(layout.HealthPath)
            || !IsSafeProspectiveDirectory(layout.HelperRoot)
            || !IsSafeProspectiveFile(layout.HelperPath)
            || !IsSafeProspectiveDirectory(layout.CandidateRoot)
            || !IsSafeProspectiveDirectory(layout.BackupsRoot))
        {
            return ProtectedTransactionLayoutResult.Failed(
                ProtectedTransactionPathError.UnsafePath);
        }

        return ProtectedTransactionLayoutResult.Valid(layout);
    }

    public ProtectedTransactionResolvedPathResult ResolveCandidatePayload(
        ProtectedTransactionId transactionId,
        string? relativePath) =>
        ResolvePayload(transactionId, relativePath, candidate: true);

    public ProtectedTransactionResolvedPathResult ResolveBackupPayload(
        ProtectedTransactionId transactionId,
        string? relativePath) =>
        ResolvePayload(transactionId, relativePath, candidate: false);

    private ProtectedTransactionResolvedPathResult ResolvePayload(
        ProtectedTransactionId transactionId,
        string? relativePath,
        bool candidate)
    {
        var relative = WindowsReleasePathPolicy.Validate(relativePath);
        if (!relative.Success || relative.CanonicalKey is null)
        {
            return ProtectedTransactionResolvedPathResult.Failed(
                ProtectedTransactionPathError.InvalidRelativePath);
        }

        if (ReleaseManagedPathPolicy.IsProtectedPayloadPath(
                relative.CanonicalKey))
        {
            return ProtectedTransactionResolvedPathResult.Failed(
                ProtectedTransactionPathError.InvalidRelativePath);
        }

        var layoutResult = GetLayout(transactionId);
        if (!layoutResult.Success || layoutResult.Layout is null)
        {
            return ProtectedTransactionResolvedPathResult.Failed(
                layoutResult.Error);
        }

        var root = candidate
            ? layoutResult.Layout.CandidateRoot
            : layoutResult.Layout.BackupsRoot;

        try
        {
            var path = Path.GetFullPath(
                Path.Combine(
                    root,
                    relative.CanonicalKey.Replace(
                        '/',
                        Path.DirectorySeparatorChar)));
            if (!IsContainedBy(path, root)
                || !IsSafeProspectiveFile(path))
            {
                return ProtectedTransactionResolvedPathResult.Failed(
                    ProtectedTransactionPathError.UnsafePath);
            }

            return ProtectedTransactionResolvedPathResult.Valid(path);
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or IOException
                or NotSupportedException)
        {
            return ProtectedTransactionResolvedPathResult.Failed(
                ProtectedTransactionPathError.UnsafePath);
        }
    }

    private bool IsSafeProspectiveDirectory(string path)
    {
        try
        {
            for (var current = path; !string.IsNullOrEmpty(current);)
            {
                if (File.Exists(current)
                    || _pathSafetyInspector.IsReparsePoint(current))
                {
                    return false;
                }

                var parent = Path.GetDirectoryName(current);
                if (string.IsNullOrEmpty(parent)
                    || string.Equals(
                        parent,
                        current,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                current = parent;
            }
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or NotSupportedException)
        {
            return false;
        }

        return false;
    }

    private bool IsSafeProspectiveFile(string path)
    {
        try
        {
            if (Directory.Exists(path)
                || _pathSafetyInspector.IsReparsePoint(path))
            {
                return false;
            }

            var parent = Path.GetDirectoryName(path);
            return parent is not null
                && IsSafeProspectiveDirectory(parent);
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or NotSupportedException)
        {
            return false;
        }
    }

    private static bool HasCanonicalContainedLayout(
        ProtectedTransactionLayout layout)
    {
        try
        {
            var transactionRoot = Path.GetFullPath(layout.TransactionRoot);
            if (!string.Equals(
                    transactionRoot,
                    layout.TransactionRoot,
                    StringComparison.OrdinalIgnoreCase)
                || !IsContainedBy(
                    transactionRoot,
                    layout.TransactionsRoot))
            {
                return false;
            }

            return new[]
                {
                    layout.TransactionRecordPath,
                    layout.JournalPath,
                    layout.HealthPath,
                    layout.HelperRoot,
                    layout.HelperPath,
                    layout.CandidateRoot,
                    layout.BackupsRoot
                }
                .All(path => IsContainedBy(path, transactionRoot));
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or IOException
                or NotSupportedException)
        {
            return false;
        }
    }

    private static bool IsContainedBy(string path, string root)
    {
        var canonicalPath = Path.GetFullPath(path);
        var canonicalRoot = Path.GetFullPath(root);
        return canonicalPath.StartsWith(
            canonicalRoot + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase);
    }
}
