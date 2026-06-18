using FluentAssertions;
using WireguardSplitTunnel.Core.Platform;

namespace WireguardSplitTunnel.Core.Tests;

[System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Interoperability",
    "CA1416:Validate platform compatibility",
    Justification = "These tests exercise platform-neutral script composition helpers without executing macOS commands.")]
public sealed class MacAdminShellTests
{
    [Fact]
    public void ResolvePreferredBashPath_UsesHomebrewBashBeforeSystemBash()
    {
        MacAdminShell.ResolvePreferredBashPath(path => path == "/opt/homebrew/bin/bash" || path == "/bin/bash")
            .Should().Be("/opt/homebrew/bin/bash");
    }

    [Fact]
    public void BuildScriptContent_PrependsHomebrewPathBeforeScriptBody()
    {
        var script = MacAdminShell.BuildScriptContent("wg-quick up /opt/homebrew/etc/wireguard/HK.conf");

        script.Should().Contain("export PATH=\"/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH\"");
        script.Should().EndWith("wg-quick up /opt/homebrew/etc/wireguard/HK.conf");
    }
}
