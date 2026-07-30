namespace WireguardSplitTunnel.Core.Updates;

public enum ProtectedUpdatePhase
{
    ProtectedStaged = 0,
    CloseAuthorized = 1,
    Prepared = 2,
    BackingUp = 3,
    Applying = 4,
    AppliedAwaitingHealth = 5,
    Committed = 6,
    RollingBack = 7,
    RolledBack = 8,
    RecoveryBlocked = 9
}

public sealed record UpdateCloseAuthorizationContext(
    ApplicationCloseIntent Intent,
    bool IsElevated,
    bool IsPostInstallSelfTest,
    int ProcessId,
    long CreationTimeFileTimeUtc,
    string ImagePath)
{
    public bool IsValid =>
        Enum.IsDefined(Intent) &&
        ProcessId > 0 &&
        CreationTimeFileTimeUtc > 0 &&
        IsStrictLocalWindowsDrivePath(ImagePath);

    public static bool TryCreate(
        ApplicationCloseIntent intent,
        bool isElevated,
        bool isPostInstallSelfTest,
        int processId,
        long creationTimeFileTimeUtc,
        string? imagePath,
        out UpdateCloseAuthorizationContext? context)
    {
        var candidate = new UpdateCloseAuthorizationContext(
            intent,
            isElevated,
            isPostInstallSelfTest,
            processId,
            creationTimeFileTimeUtc,
            imagePath ?? string.Empty);
        context = candidate.IsValid ? candidate : null;
        return context is not null;
    }

    private static bool IsStrictLocalWindowsDrivePath(string? imagePath) =>
        !string.IsNullOrWhiteSpace(imagePath) &&
        imagePath.Length > 3 &&
        ((imagePath[0] >= 'A' && imagePath[0] <= 'Z') ||
         (imagePath[0] >= 'a' && imagePath[0] <= 'z')) &&
        imagePath[1] == ':' &&
        imagePath[2] is '\\' or '/' &&
        !imagePath.Contains('\0');
}

public enum UpdateCloseAuthorizationOutcome
{
    NoProtectedTransaction = 0,
    HelperReady = 1,
    RecoverableFailure = 2
}

public sealed class UpdateCloseAuthorizationResult
{
    private const int MaximumErrorCodeLength = 64;

    private UpdateCloseAuthorizationResult(UpdateCloseAuthorizationOutcome outcome, string? errorCode)
    {
        Outcome = outcome;
        ErrorCode = errorCode;
    }

    public UpdateCloseAuthorizationOutcome Outcome { get; }
    public string? ErrorCode { get; }

    public static UpdateCloseAuthorizationResult NoProtectedTransaction() =>
        new(UpdateCloseAuthorizationOutcome.NoProtectedTransaction, null);

    public static UpdateCloseAuthorizationResult HelperReady() =>
        new(UpdateCloseAuthorizationOutcome.HelperReady, null);

    public static UpdateCloseAuthorizationResult RecoverableFailure(string? errorCode = null) =>
        new(UpdateCloseAuthorizationOutcome.RecoverableFailure,
            SanitizeErrorCode(errorCode));

    private static string? SanitizeErrorCode(string? errorCode)
    {
        var candidate = errorCode?.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(candidate) || candidate.Length > MaximumErrorCodeLength)
        {
            return null;
        }

        foreach (var character in candidate)
        {
            if ((character < 'a' || character > 'z') &&
                (character < '0' || character > '9') &&
                character != '_')
            {
                return null;
            }
        }

        return candidate;
    }
}

public static class UpdateCloseEligibility
{
    public static bool IsEligible(UpdateCloseAuthorizationContext? context) =>
        context is { IsValid: true, Intent: ApplicationCloseIntent.UserOrApplicationClose, IsElevated: true, IsPostInstallSelfTest: false };
}
