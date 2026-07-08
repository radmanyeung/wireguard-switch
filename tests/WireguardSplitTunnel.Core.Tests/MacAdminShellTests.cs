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

    [Fact]
    public void ScriptEncoding_EmitsNoByteOrderMark()
    {
        MacAdminShell.ScriptEncoding.GetPreamble().Should().BeEmpty();
    }

    [Fact]
    public async Task WriteScriptFileAsync_FileStartsWithShebangBytesNotBom()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wgst-test-{Guid.NewGuid():N}.sh");
        try
        {
            await MacAdminShell.WriteScriptFileAsync(path, "echo hi", CancellationToken.None);

            var bytes = await File.ReadAllBytesAsync(path);
            bytes.Length.Should().BeGreaterThan(2);
            // A UTF-8 BOM (EF BB BF) before "#!" makes the kernel ignore the shebang,
            // so the script silently runs under /bin/sh and stderr gains a bogus
            // "/opt/homebrew/bin/bash: No such file or directory" line.
            bytes[0].Should().Be((byte)'#');
            bytes[1].Should().Be((byte)'!');
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }
}
