namespace WireguardSplitTunnel.Core.Updates;

public static class UpdateReleaseContract
{
    public const string Repository = "radmanyeung/wireguard-switch";
    public static readonly Uri LatestReleaseApiUri = new("https://api.github.com/repos/radmanyeung/wireguard-switch/releases/latest");
    public const string WindowsAssetName = "wireguard-split-tunnel-win-x64.zip";
    public const string WindowsChecksumAssetName = "wireguard-split-tunnel-win-x64.zip.sha256";
    public const string ReleaseManifestPath = "release-manifest.json";
    public const string WindowsRuntimeIdentifier = "win-x64";
    public const string WindowsApplicationPath = "WireguardSplitTunnel/WireguardSplitTunnel.App.exe";
    public const string WindowsUpdaterPath = "WireguardSplitTunnel/WireguardSplitTunnel.Updater.exe";
    public static readonly IReadOnlyList<string> RequiredLauncherPaths = Array.AsReadOnly(
    new[]
    {
        "install.cmd", "start.cmd", "start-admin.cmd", "start-safe.cmd", "scripts/install.ps1", "scripts/start.ps1"
    });
    public static readonly IReadOnlyList<string> RedirectHosts = Array.AsReadOnly(
    new[]
    {
        "api.github.com", "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"
    });
}
