using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.WindowsUpdate.Staging;

public enum WindowsUpdateStatusKind
{
    Idle,
    Disabled,
    Checking,
    Current,
    Downloading,
    ReadyForClose,
    ReadyNeedsElevation,
    AutomaticInstallationUnavailable,
    CheckFailed,
    VerificationFailed,
    CleanupPending,
    Closing
}

public sealed record WindowsUpdateStatus
{
    private const int MaximumDetailCodeLength = 64;

    private WindowsUpdateStatus(
        WindowsUpdateStatusKind kind,
        SemanticVersion? version,
        string? detailCode)
    {
        Kind = kind;
        Version = version;
        DetailCode = detailCode;
    }

    public WindowsUpdateStatusKind Kind { get; }

    public SemanticVersion? Version { get; }

    public string? DetailCode { get; }

    public bool IsBusy =>
        Kind is
            WindowsUpdateStatusKind.Checking
                or WindowsUpdateStatusKind.Downloading;

    public string Message => Kind switch
    {
        WindowsUpdateStatusKind.Idle =>
            "Update checks are ready",
        WindowsUpdateStatusKind.Disabled =>
            "Automatic update checks are disabled",
        WindowsUpdateStatusKind.Checking =>
            "Checking for updates",
        WindowsUpdateStatusKind.Current =>
            $"Version v{Version} is current",
        WindowsUpdateStatusKind.Downloading =>
            $"Downloading v{Version}",
        WindowsUpdateStatusKind.ReadyForClose =>
            $"v{Version} is ready and will install after an eligible normal close",
        WindowsUpdateStatusKind.ReadyNeedsElevation =>
            "Update ready; run the application elevated before a later normal close",
        WindowsUpdateStatusKind.AutomaticInstallationUnavailable =>
            "Automatic installation is unavailable from this developer build",
        WindowsUpdateStatusKind.CheckFailed =>
            "Update check failed; retry when next due",
        WindowsUpdateStatusKind.VerificationFailed =>
            "Package verification failed; nothing was installed",
        WindowsUpdateStatusKind.CleanupPending =>
            "Automatic update cleanup is pending an elevated run",
        WindowsUpdateStatusKind.Closing =>
            "Stopping update work",
        _ => "Update status unavailable"
    };

    internal static WindowsUpdateStatus Create(
        WindowsUpdateStatusKind kind,
        SemanticVersion? version = null,
        string? detailCode = null) =>
        new(
            Enum.IsDefined(kind)
                ? kind
                : WindowsUpdateStatusKind.CheckFailed,
            version,
            SanitizeCode(detailCode));

    internal static string? SanitizeCode(string? value)
    {
        if (value is null)
        {
            return null;
        }

        if (value.Length is < 1 or > MaximumDetailCodeLength
            || value.Any(character =>
                character is not (
                    >= 'a' and <= 'z'
                    or >= '0' and <= '9'
                    or '_')))
        {
            return "invalid";
        }

        return value;
    }
}
