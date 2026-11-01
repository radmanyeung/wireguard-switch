using FluentAssertions;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class WindowsBypassExitWiringTests
{
    [Fact]
    public void Close_CancelsRoutingWorkBeforeWaitingForCleanupGates()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "WireguardSplitTunnel.sln")))
            root = root.Parent;
        var source = File.ReadAllText(Path.Combine(root!.FullName,
            "src", "WireguardSplitTunnel.App", "MainWindow.xaml.cs"));
        var close = source[source.IndexOf("private async void OnWindowClosing", StringComparison.Ordinal)..
            source.IndexOf("private async void OnLoaded", StringComparison.Ordinal)];
        var cancel = close.IndexOf("routingWorkCts.Cancel();", StringComparison.Ordinal);
        cancel.Should().BeGreaterThanOrEqualTo(0);
        cancel.Should().BeLessThan(close.IndexOf("StopSoftwareLearningAsync()", StringComparison.Ordinal));
        var renew = source[source.IndexOf("private async Task<bool> RenewDomainRoutesAsync", StringComparison.Ordinal)..
            source.IndexOf("private async Task<IReadOnlyCollection<ResolvedRule>> LearnDnsCacheRulesAsync", StringComparison.Ordinal)];
        renew.Should().NotContain("CancellationToken.None", "startup routing must be interruptible on close");
    }

    [Fact]
    public void RestoreOnExit_ReleasesBypassRoutesBeforeRequiringAnActiveTunnel()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "WireguardSplitTunnel.sln")))
            root = root.Parent;
        root.Should().NotBeNull();
        var source = File.ReadAllText(Path.Combine(root!.FullName,
            "src", "WireguardSplitTunnel.App", "MainWindow.xaml.cs"));
        var start = source.IndexOf("private async Task RestoreNormalRoutingOnExitAsync", StringComparison.Ordinal);
        var end = source.IndexOf("private async Task RemoveWireGuardDnsHostRoutesAsync", start, StringComparison.Ordinal);
        var restore = source[start..end];

        var cleanup = restore.IndexOf("await RestoreBypassRoutesOnExitAsync(", StringComparison.Ordinal);
        cleanup.Should().BeGreaterThanOrEqualTo(0,
            "closing the app must release its bypass routes so standalone WireGuard can take over");
        cleanup.Should().BeLessThan(restore.IndexOf("detector.TryGetActiveInterface", StringComparison.Ordinal),
            "physical bypass routes outlive a disconnected WireGuard adapter");
    }
}
