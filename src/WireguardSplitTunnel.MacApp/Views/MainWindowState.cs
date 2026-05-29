using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace WireguardSplitTunnel.MacApp.Views;

public sealed class MainWindowState : INotifyPropertyChanged
{
    public ObservableCollection<DomainRuleRow> Domains { get; } = [];

    public event PropertyChangedEventHandler? PropertyChanged;
    private void Raise([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
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
