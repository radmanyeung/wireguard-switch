using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class MacErrorPresenterTests
{
    private const string BomNoiseLine =
        "/private/tmp/wgst-abc.sh: line 1: ﻿#!/opt/homebrew/bin/bash: No such file or directory";

    [Fact]
    public void ToFriendly_BashNoiseButBashInstalled_KeepsRealErrorWithoutBashHint()
    {
        var raw = BomNoiseLine + "\nwg-quick: `wgst-split' already exists";

        var friendly = MacErrorPresenter.ToFriendly(raw, _ => true);

        friendly.Should().NotContain("Homebrew Bash is missing");
        friendly.Should().Contain("wgst-split' already exists");
    }

    [Fact]
    public void ToFriendly_BashActuallyMissing_AddsHintAndPreservesDetails()
    {
        var raw = BomNoiseLine + "\nsome underlying failure";

        var friendly = MacErrorPresenter.ToFriendly(raw, _ => false);

        friendly.Should().Contain("Homebrew Bash is missing. Run: brew install bash");
        friendly.Should().Contain("some underlying failure");
    }

    [Fact]
    public void ToFriendly_BadInterpreterAndBashMissing_AddsHint()
    {
        var raw = "/tmp/x.sh: /opt/homebrew/bin/bash: bad interpreter: No such file or directory";

        var friendly = MacErrorPresenter.ToFriendly(raw, _ => false);

        friendly.Should().Contain("Homebrew Bash is missing. Run: brew install bash");
        friendly.Should().Contain("bad interpreter");
    }

    [Fact]
    public void ToFriendly_WgQuickMissing_AddsHintAndPreservesDetails()
    {
        var friendly = MacErrorPresenter.ToFriendly("wg-quick not found. Install wireguard-tools.", _ => true);

        friendly.Should().Contain("WireGuard tools are missing. Run: brew install wireguard-tools bash");
        friendly.Should().Contain("wg-quick not found");
    }

    [Fact]
    public void ToFriendly_BlockedConfigPath_AddsHintAndPreservesDetails()
    {
        var raw = "cat: /Users/user/Downloads/SG.conf: Operation not permitted";

        var friendly = MacErrorPresenter.ToFriendly(raw, _ => true);

        friendly.Should().Contain("/opt/homebrew/etc/wireguard");
        friendly.Should().Contain("Operation not permitted");
    }

    [Fact]
    public void ToFriendly_OrdinaryError_ReturnsMessageUnchanged()
    {
        var raw = "wg-quick failed (exit 1): Unable to resolve host sg476.nordvpn.com";

        MacErrorPresenter.ToFriendly(raw, _ => true).Should().Be(raw);
    }
}
