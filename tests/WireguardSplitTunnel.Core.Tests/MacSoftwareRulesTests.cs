using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class MacSoftwareRulesTests
{
    [Fact]
    public void CreateProfile_DerivesStableIdAndTunnelNameFromConfigPath()
    {
        var first = MacTunnelProfileService.CreateProfile("/opt/homebrew/etc/wireguard/US.conf");
        var second = MacTunnelProfileService.CreateProfile("/opt/homebrew/etc/wireguard/US.conf");

        first.Id.Should().Be(second.Id);
        first.DisplayName.Should().Be("US");
        first.ConfigPath.Should().Be("/opt/homebrew/etc/wireguard/US.conf");
        first.Enabled.Should().BeTrue();
        first.TunnelName.Should().Be("US");
    }

    [Fact]
    public void AddProfile_SkipsDuplicateConfigPath()
    {
        var state = new AppState([], new Dictionary<string, List<string>>(), []);
        var profile = MacTunnelProfileService.CreateProfile("/opt/homebrew/etc/wireguard/HK.conf");

        var first = MacSoftwareRuleMutations.TryAddProfile(state, profile);
        var second = MacSoftwareRuleMutations.TryAddProfile(state, profile);

        first.Should().BeTrue();
        second.Should().BeFalse();
        state.MacTunnelProfiles.Should().ContainSingle();
    }

    [Fact]
    public void AddSoftwareRule_SkipsDuplicateBundleProfilePair()
    {
        var state = new AppState([], new Dictionary<string, List<string>>(), []);

        var first = MacSoftwareRuleMutations.TryAddSoftwareRule(
            state,
            bundleIdentifier: "com.openai.chat",
            displayName: "ChatGPT",
            bundlePath: "/Applications/ChatGPT.app",
            profileId: "profile-us");
        var second = MacSoftwareRuleMutations.TryAddSoftwareRule(
            state,
            bundleIdentifier: "COM.OPENAI.CHAT",
            displayName: "ChatGPT",
            bundlePath: "/Applications/ChatGPT.app",
            profileId: "profile-us");

        first.Should().BeTrue();
        second.Should().BeFalse();
        state.MacSoftwareRules.Should().ContainSingle(rule =>
            rule.BundleIdentifier == "com.openai.chat"
            && rule.DisplayName == "ChatGPT"
            && rule.BundlePath == "/Applications/ChatGPT.app"
            && rule.ProfileId == "profile-us"
            && rule.Enabled);
    }

    [Fact]
    public void ToggleAndDeleteSoftwareRule_TargetBundleAndProfile()
    {
        var state = new AppState([], new Dictionary<string, List<string>>(), []);
        MacSoftwareRuleMutations.TryAddSoftwareRule(state, "com.openai.chat", "ChatGPT", "/Applications/ChatGPT.app", "profile-us");
        MacSoftwareRuleMutations.TryAddSoftwareRule(state, "com.openai.chat", "ChatGPT", "/Applications/ChatGPT.app", "profile-hk");

        MacSoftwareRuleMutations.TrySetSoftwareRuleEnabled(state, "com.openai.chat", "profile-hk", false).Should().BeTrue();
        MacSoftwareRuleMutations.RemoveSoftwareRule(state, "com.openai.chat", "profile-us").Should().BeTrue();

        state.MacSoftwareRules.Should().ContainSingle(rule =>
            rule.BundleIdentifier == "com.openai.chat"
            && rule.ProfileId == "profile-hk"
            && !rule.Enabled);
    }

    [Fact]
    public void ParseInfoPlist_ReadsBundleIdentityFromXml()
    {
        var info = MacAppBundleInfoParser.ParseInfoPlistContent("""
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.openai.chat</string>
    <key>CFBundleDisplayName</key>
    <string>ChatGPT</string>
    <key>CFBundleExecutable</key>
    <string>ChatGPT</string>
</dict>
</plist>
""");

        info.Should().NotBeNull();
        info!.BundleIdentifier.Should().Be("com.openai.chat");
        info.DisplayName.Should().Be("ChatGPT");
        info.ExecutableName.Should().Be("ChatGPT");
    }

    [Theory]
    [InlineData("")]
    [InlineData("<plist><dict><key>CFBundleDisplayName</key><string>No Id</string></dict></plist>")]
    [InlineData("not xml")]
    public void ParseInfoPlist_ReturnsNullForMissingOrMalformedIdentity(string content)
    {
        MacAppBundleInfoParser.ParseInfoPlistContent(content).Should().BeNull();
    }

    [Fact]
    public void ApplyGuard_ReturnsNetworkExtensionUnavailable()
    {
        var result = MacSoftwareRuleApplyGuard.CheckCapability(hasNetworkExtensionEntitlement: false);

        result.CanApply.Should().BeFalse();
        result.Message.Should().Contain("Network Extension");
        result.Message.Should().Contain("Apple Developer");
    }
}
