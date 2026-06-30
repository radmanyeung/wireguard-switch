using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace WireguardSplitTunnel.MacApp.Views;

public sealed class MainWindowState : INotifyPropertyChanged
{
    public ObservableCollection<TunnelConfigRow> TunnelConfigs { get; } = [];

    public ObservableCollection<DomainRuleRow> Domains { get; } = [];

    public ObservableCollection<MacTunnelProfileRow> MacProfiles { get; } = [];

    public ObservableCollection<MacSoftwareRuleRow> MacSoftwareRules { get; } = [];

    public ObservableCollection<MonitorActivityRowView> MonitorActivities { get; } = [];

    public event PropertyChangedEventHandler? PropertyChanged;

    private void Raise([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed record TunnelConfigRow(string Path, string Display)
{
    public string ShortPath => ShortenPath(Path);

    public override string ToString() => Display;

    private static string ShortenPath(string path)
    {
        var directory = System.IO.Path.GetDirectoryName(path);
        var fileName = System.IO.Path.GetFileName(path);
        return string.IsNullOrWhiteSpace(directory) || string.IsNullOrWhiteSpace(fileName)
            ? path
            : $"{directory}/.../{fileName}";
    }
}

public sealed class DomainRuleRow : INotifyPropertyChanged
{
    private bool enabled = true;
    private string resolvedSummary = "(unresolved)";

    public DomainRuleRow(string domain) => Domain = domain;

    public string Domain { get; }

    public bool Enabled
    {
        get => enabled;
        set { if (enabled != value) { enabled = value; Raise(); } }
    }

    public string ResolvedSummary
    {
        get => resolvedSummary;
        set { if (resolvedSummary != value) { resolvedSummary = value; Raise(); } }
    }

    public List<string> ResolvedIps { get; set; } = [];

    public event PropertyChangedEventHandler? PropertyChanged;

    private void Raise([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed record MonitorActivityRowView(
    string ProcessName,
    string DomainOrAddress,
    string RemoteEndpoint,
    string Route,
    int Connections,
    string ShortPath,
    string LastSeen);

public sealed class MacTunnelProfileRow : INotifyPropertyChanged
{
    private bool enabled;

    public MacTunnelProfileRow(
        string id,
        string displayName,
        string configPath,
        string tunnelName,
        bool enabled)
    {
        Id = id;
        DisplayName = displayName;
        ConfigPath = configPath;
        TunnelName = tunnelName;
        this.enabled = enabled;
    }

    public string Id { get; }

    public string DisplayName { get; }

    public string ConfigPath { get; }

    public string TunnelName { get; }

    public string ShortConfigPath => ShortenPath(ConfigPath);

    public bool Enabled
    {
        get => enabled;
        set { if (enabled != value) { enabled = value; Raise(); } }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public override string ToString() => DisplayName;

    private void Raise([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private static string ShortenPath(string path)
    {
        var directory = Path.GetDirectoryName(path);
        var fileName = Path.GetFileName(path);
        return string.IsNullOrWhiteSpace(directory) || string.IsNullOrWhiteSpace(fileName)
            ? path
            : $"{directory}/.../{fileName}";
    }
}

public sealed class MacSoftwareRuleRow : INotifyPropertyChanged
{
    private bool enabled;

    public MacSoftwareRuleRow(
        string bundleIdentifier,
        string displayName,
        string? bundlePath,
        string profileId,
        string profileDisplayName,
        bool enabled)
    {
        BundleIdentifier = bundleIdentifier;
        DisplayName = displayName;
        BundlePath = bundlePath;
        ProfileId = profileId;
        ProfileDisplayName = profileDisplayName;
        this.enabled = enabled;
    }

    public string BundleIdentifier { get; }

    public string DisplayName { get; }

    public string? BundlePath { get; }

    public string ProfileId { get; }

    public string ProfileDisplayName { get; }

    public string ShortBundlePath => string.IsNullOrWhiteSpace(BundlePath)
        ? ""
        : ShortenPath(BundlePath);

    public bool Enabled
    {
        get => enabled;
        set { if (enabled != value) { enabled = value; Raise(); } }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void Raise([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private static string ShortenPath(string path)
    {
        var directory = Path.GetDirectoryName(path);
        var fileName = Path.GetFileName(path);
        return string.IsNullOrWhiteSpace(directory) || string.IsNullOrWhiteSpace(fileName)
            ? path
            : $"{directory}/.../{fileName}";
    }
}
