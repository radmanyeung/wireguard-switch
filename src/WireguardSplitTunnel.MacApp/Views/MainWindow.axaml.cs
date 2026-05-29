using System.Diagnostics;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.MacApp.Views;

public partial class MainWindow : Window
{
    private readonly MainWindowState state = new();
    private readonly IWireguardDetector detector = new SystemWireguardDetector();
    private readonly IDomainResolver resolver = new SystemDomainResolver();
    private readonly ITunnelControlService tunnelControl = new TunnelControlService();
    private readonly IRouteService routeService = new RouteService();

    private string? selectedConfigPath;
    private string? activeTunnelName;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = state;
        DomainList.ItemsSource = state.Domains;
        RefreshTunnelStatus();
    }

    private async void OnPickConfigClick(object? sender, RoutedEventArgs e)
    {
        var initialFolder = await ResolveInitialFolderAsync();
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Select WireGuard config",
            AllowMultiple = false,
            SuggestedStartLocation = initialFolder,
            FileTypeFilter =
            [
                new FilePickerFileType("WireGuard config") { Patterns = ["*.conf"] },
                new FilePickerFileType("All files") { Patterns = ["*"] }
            ]
        });

        if (files.Count == 0)
        {
            return;
        }

        selectedConfigPath = files[0].Path.LocalPath;
        ConfigPathText.Text = selectedConfigPath;
        Log($"selected config: {selectedConfigPath}");
    }

    private async Task<IStorageFolder?> ResolveInitialFolderAsync()
    {
        foreach (var dir in WireguardConfigCatalog.DefaultConfigDirectories)
        {
            if (Directory.Exists(dir))
            {
                try
                {
                    return await StorageProvider.TryGetFolderFromPathAsync(new Uri(dir));
                }
                catch
                {
                    // best-effort
                }
            }
        }

        return null;
    }

    private async void OnEnableTunnelClick(object? sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(selectedConfigPath))
        {
            Log("pick a config first.");
            return;
        }

        await RunGuardedAsync("enable tunnel", async ct =>
        {
            await tunnelControl.InstallAndStartAsync(selectedConfigPath!, ct);
            await Task.Delay(500, ct); // give wg-quick a moment to populate /var/run/wireguard
            RefreshTunnelStatus();
        });
    }

    private async void OnDisableTunnelClick(object? sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(selectedConfigPath) && string.IsNullOrWhiteSpace(activeTunnelName))
        {
            Log("nothing to disable.");
            return;
        }

        var name = !string.IsNullOrWhiteSpace(selectedConfigPath)
            ? WireguardConfigCatalog.GetTunnelName(selectedConfigPath!)
            : activeTunnelName!;

        await RunGuardedAsync("disable tunnel", async ct =>
        {
            await tunnelControl.StopAndUninstallAsync(name, ct);
            await Task.Delay(300, ct);
            RefreshTunnelStatus();
        });
    }

    private void OnAddDomainClick(object? sender, RoutedEventArgs e)
    {
        var input = NewDomainBox.Text?.Trim();
        if (string.IsNullOrWhiteSpace(input))
        {
            return;
        }

        if (state.Domains.Any(row => string.Equals(row.Domain, input, StringComparison.OrdinalIgnoreCase)))
        {
            Log($"already in list: {input}");
            return;
        }

        state.Domains.Add(new DomainRuleRow(input));
        NewDomainBox.Text = string.Empty;
        Log($"added: {input}");
    }

    private void OnRemoveDomainClick(object? sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string domain })
        {
            var row = state.Domains.FirstOrDefault(r => string.Equals(r.Domain, domain, StringComparison.OrdinalIgnoreCase));
            if (row is not null)
            {
                state.Domains.Remove(row);
                Log($"removed: {domain}");
            }
        }
    }

    private async void OnApplyRoutesClick(object? sender, RoutedEventArgs e)
    {
        if (!detector.TryGetActiveInterface(out var iface))
        {
            Log("no active WireGuard interface detected. Enable the tunnel first.");
            return;
        }

        await RunGuardedAsync("apply routes", async ct =>
        {
            // Resolve every enabled domain.
            foreach (var row in state.Domains.Where(r => r.Enabled).ToList())
            {
                var ips = await resolver.ResolveAsync(row.Domain, ct);
                row.ResolvedIps = ips.ToList();
                row.ResolvedSummary = ips.Count == 0 ? "(unresolved)" : string.Join(", ", ips);
            }

            // Build add list from currently enabled rows; remove any IPs that belonged to
            // disabled rows (best-effort, no persisted snapshot in this minimal flow).
            var toAdd = state.Domains
                .Where(r => r.Enabled)
                .SelectMany(r => r.ResolvedIps)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            var toRemove = state.Domains
                .Where(r => !r.Enabled)
                .SelectMany(r => r.ResolvedIps)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            await routeService.ApplyAsync(iface, toAdd, toRemove, ct);
            Log($"applied {toAdd.Count} route(s) on {iface}; removed {toRemove.Count}.");
        });
    }

    private void RefreshTunnelStatus()
    {
        if (detector.TryGetActiveInterface(out var iface))
        {
            activeTunnelName = iface;
            TunnelStatusText.Text = $"connected via {iface}";
            TunnelStatusText.Foreground = Avalonia.Media.Brushes.SeaGreen;
        }
        else
        {
            activeTunnelName = null;
            TunnelStatusText.Text = "not connected";
            TunnelStatusText.Foreground = Avalonia.Media.Brushes.Gray;
        }
    }

    private async Task RunGuardedAsync(string label, Func<CancellationToken, Task> body)
    {
        try
        {
            Log($"{label}: running…");
            var cts = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            await body(cts.Token);
            Log($"{label}: done");
        }
        catch (Exception ex)
        {
            Log($"{label}: FAILED — {ex.Message}");
            Debug.WriteLine(ex);
        }
    }

    private void Log(string message)
    {
        var stamp = DateTime.Now.ToString("HH:mm:ss");
        var line = $"[{stamp}] {message}";
        Dispatcher.UIThread.Post(() =>
        {
            LogText.Text = LogText.Text is { Length: > 0 } current
                ? current + "\n" + line
                : line;
        });
    }
}
