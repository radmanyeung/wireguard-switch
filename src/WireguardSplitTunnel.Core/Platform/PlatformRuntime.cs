namespace WireguardSplitTunnel.Core.Platform;

public static class PlatformRuntime
{
    public static bool IsWindows => OperatingSystem.IsWindows();
    public static bool IsMacOS => OperatingSystem.IsMacOS();

    public static string CurrentName =>
        IsWindows ? "windows" : IsMacOS ? "macos" : "unsupported";
}
