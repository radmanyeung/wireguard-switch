using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class StateStoreTests
{
    private static string CreateTestPath()
    {
        var directory = Path.Combine(AppContext.BaseDirectory, "test-temp");
        Directory.CreateDirectory(directory);
        return Path.Combine(directory, $"{Guid.NewGuid():N}.json");
    }

    [Fact]
    public void Load_ReturnsDefaultState_WhenFileDoesNotExist()
    {
        var path = CreateTestPath();

        var store = new StateStore(path);

        var state = store.Load();

        state.DomainRules.Should().BeEmpty();
        state.LastKnownResolvedIps.Should().BeEmpty();
        state.ManagedRouteSnapshot.Should().BeEmpty();
        state.SoftwareRules.Should().NotBeNull();
        state.SoftwareRules.Should().BeEmpty();
        state.MacTunnelProfiles.Should().NotBeNull();
        state.MacTunnelProfiles.Should().BeEmpty();
        state.MacSoftwareRules.Should().NotBeNull();
        state.MacSoftwareRules.Should().BeEmpty();
        state.MacDomainProfileAssignments.Should().NotBeNull();
        state.MacDomainProfileAssignments.Should().BeEmpty();
        state.DomainGlobalDefaultMode.Should().Be(DomainRouteMode.BypassWireGuard);
        state.SoftwareGlobalDefaultMode.Should().Be(DomainRouteMode.BypassWireGuard);
    }

    [Fact]
    public void LoadWithMetadata_ReturnsDefaultStateAndEmptyPresence_WhenFileDoesNotExist()
    {
        var path = CreateTestPath();

        var result = new StateStore(path).LoadWithMetadata();

        result.State.AutoUpdateEnabled.Should().BeTrue();
        result.PresentPropertyNames.Should().BeEmpty();
    }

    [Fact]
    public void LoadWithMetadata_ReturnsDefaultStateAndEmptyPresence_WhenFileIsBlank()
    {
        var path = CreateTestPath();
        File.WriteAllText(path, "   \r\n");

        try
        {
            var result = new StateStore(path).LoadWithMetadata();

            result.State.AutoUpdateEnabled.Should().BeTrue();
            result.PresentPropertyNames.Should().BeEmpty();
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void LoadWithMetadata_TracksTopLevelPropertyNamesUsingOrdinalCaseSensitiveMatching()
    {
        var path = CreateTestPath();
        File.WriteAllText(path, """{ "AutoUpdateEnabled": false, "autoupdateenabled": true }""");

        try
        {
            var result = new StateStore(path).LoadWithMetadata();

            result.State.AutoUpdateEnabled.Should().BeFalse();
            result.PresentPropertyNames.Should().Contain("AutoUpdateEnabled");
            result.PresentPropertyNames.Should().Contain("autoupdateenabled");
            result.PresentPropertyNames.Contains("AUTOUPDATEENABLED").Should().BeFalse();
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void SaveAndLoad_RoundTripsState()
    {
        var path = CreateTestPath();

        var store = new StateStore(path);
        var original = new AppState(
            [
                new DomainRule("example.com", true),
                new DomainRule("test.example.com", false, DomainRouteMode.BypassWireGuard)
            ],
            new Dictionary<string, List<string>>
            {
                ["example.com"] = ["192.168.1.1", "192.168.1.2"],
                ["test.example.com"] = ["10.0.0.1"]
            },
            [
                new ManagedRouteEntry("example.com", "10.0.0.1")
            ],
            "C:\\Program Files\\WireGuard\\Data\\Configurations\\home.conf.dpapi",
            true,
            [
                new SoftwareRule("chrome.exe", true, DomainRouteMode.UseWireGuard, true),
                new SoftwareRule("steam.exe", false, DomainRouteMode.BypassWireGuard, false)
            ],
            DomainRouteMode.UseWireGuard,
            DomainRouteMode.BypassWireGuard,
            false,
            new Dictionary<string, List<ResolvedIpDetail>>(),
            [
                new MacTunnelProfile("profile-us", "US", "/opt/homebrew/etc/wireguard/US.conf", true, "US")
            ],
            [
                new MacSoftwareRule("com.openai.chat", "ChatGPT", "/Applications/ChatGPT.app", "profile-us", true)
            ],
            [
                new MacDomainProfileAssignment("chatgpt.com", "profile-us", true)
            ]);

        store.Save(original);

        var loaded = store.Load();

        loaded.Should().BeEquivalentTo(original);

        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void SaveAndLoad_RoundTripsActiveRawTunnelName()
    {
        var path = CreateTestPath();
        var store = new StateStore(path);
        var original = new AppState([], [], []) with { ActiveRawTunnelName = "SG" };

        store.Save(original);

        store.Load().ActiveRawTunnelName.Should().Be("SG");

        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Load_OldStateFileWithoutActiveRawTunnelName_DefaultsToNull()
    {
        var path = CreateTestPath();
        File.WriteAllText(path, """{ "DomainRules": [] }""");

        new StateStore(path).Load().ActiveRawTunnelName.Should().BeNull();

        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void SaveAndLoad_RoundTripsCustomConfigDirectories()
    {
        var path = CreateTestPath();
        var store = new StateStore(path);
        var original = new AppState([], [], []) with
        {
            CustomConfigDirectories = ["D:\\vpn-configs", "E:\\more\\configs"]
        };

        store.Save(original);

        store.Load().CustomConfigDirectories.Should().Equal("D:\\vpn-configs", "E:\\more\\configs");

        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Load_OldStateFileWithoutCustomConfigDirectories_DefaultsToEmpty()
    {
        var path = CreateTestPath();
        File.WriteAllText(path, """{ "DomainRules": [] }""");

        new StateStore(path).Load().CustomConfigDirectories.Should().BeEmpty();

        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void SaveAndLoad_RoundTripsActiveSplitTunnelCleanupDebt()
    {
        var path = CreateTestPath();
        var store = new StateStore(path);
        var original = new AppState([], [], []) with
        {
            ActiveSplitTunnelConfigPath = "/data/wgst-split.conf"
        };

        store.Save(original);

        store.Load().ActiveSplitTunnelConfigPath.Should().Be("/data/wgst-split.conf");

        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Load_OldStateFileWithoutSplitCleanupDebt_DefaultsToNull()
    {
        var path = CreateTestPath();
        File.WriteAllText(path, """{ "DomainRules": [] }""");

        new StateStore(path).Load().ActiveSplitTunnelConfigPath.Should().BeNull();

        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void SaveAndLoad_RoundTripsRawDnsCleanupDebtWithoutConfigText()
    {
        var path = CreateTestPath();
        var store = new StateStore(path);
        var debt = new MacRawTunnelDnsCleanupDebt(
            "SG",
            "/opt/homebrew/etc/wireguard/SG.conf",
            ["103.86.96.100"],
            ["tailnet.ts.net"],
            [new MacDnsServiceSnapshot("Wi-Fi", ["1.1.1.1"], ["home.arpa"])]);
        var original = new AppState([], [], []) with { RawTunnelDnsCleanupDebt = debt };

        store.Save(original);

        store.Load().RawTunnelDnsCleanupDebt.Should().BeEquivalentTo(debt);
        File.ReadAllText(path).Should().NotContain("PrivateKey");

        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void SaveAndLoad_RoundTripsPendingDnsJournalPathAndComponentDebt()
    {
        var path = CreateTestPath();
        var store = new StateStore(path);
        var journalPath = path + ".dns-journal";
        var debt = new MacRawTunnelDnsCleanupDebt(
            "SG",
            "/opt/homebrew/etc/wireguard/SG.conf",
            ["103.86.96.100"],
            ["tailnet.ts.net"],
            [new MacDnsServiceSnapshot(
                "Wi-Fi",
                ["1.1.1.1"],
                ["home.arpa"],
                RestoreDnsServersPending: false)],
            journalPath);

        store.Save(new AppState([], [], []) with { RawTunnelDnsCleanupDebt = debt });

        store.Load().RawTunnelDnsCleanupDebt.Should().BeEquivalentTo(debt);

        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Load_OldStateFileWithoutRawDnsCleanupDebt_DefaultsToNull()
    {
        var path = CreateTestPath();
        File.WriteAllText(path, """{ "DomainRules": [] }""");

        new StateStore(path).Load().RawTunnelDnsCleanupDebt.Should().BeNull();

        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Load_LegacyMacCleanupState_PreservesUnknownRouteAndBothDnsComponents()
    {
        var path = CreateTestPath();
        File.WriteAllText(path, """
            {
              "DomainRules": [],
              "LastKnownResolvedIps": {},
              "ManagedRouteSnapshot": [
                { "Domain": "legacy.example", "IpAddress": "198.51.100.10" }
              ],
              "RawTunnelDnsCleanupDebt": {
                "TunnelName": "SG",
                "ConfigPath": "/opt/homebrew/etc/wireguard/SG.conf",
                "TunnelDnsServers": ["103.86.96.100"],
                "TunnelSearchDomains": ["tailnet.ts.net"],
                "Services": [
                  {
                    "ServiceName": "Wi-Fi",
                    "DnsServers": ["1.1.1.1"],
                    "SearchDomains": ["home.arpa"]
                  }
                ]
              }
            }
            """);

        var state = new StateStore(path).Load();

        state.ManagedRouteSnapshot.Should().ContainSingle()
            .Which.InterfaceName.Should().BeNull();
        state.RawTunnelDnsCleanupDebt!.Services.Should().ContainSingle()
            .Which.Should().Match<MacDnsServiceSnapshot>(snapshot =>
                snapshot.RestoreDnsServersPending
                && snapshot.RestoreSearchDomainsPending);

        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Load_ThrowsInvalidDataException_ForCorruptNonEmptyJson()
    {
        var path = CreateTestPath();
        File.WriteAllText(path, "{\"DomainRules\": [");

        var store = new StateStore(path);

        Action act = () => store.Load();

        act.Should().Throw<InvalidDataException>();

        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void LoadWithMetadata_ThrowsInvalidDataException_ForCorruptNonEmptyJson()
    {
        var path = CreateTestPath();
        File.WriteAllText(path, "{\"DomainRules\": [");

        try
        {
            Action act = () => new StateStore(path).LoadWithMetadata();

            act.Should().Throw<InvalidDataException>();
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void Load_NormalizesNullCollections()
    {
        var path = CreateTestPath();
        File.WriteAllText(path, """
{
  "DomainRules": null,
  "LastKnownResolvedIps": null,
  "ManagedRouteSnapshot": null,
  "SoftwareRules": null
}
""");

        var store = new StateStore(path);

        var state = store.Load();

        state.DomainRules.Should().NotBeNull();
        state.LastKnownResolvedIps.Should().NotBeNull();
        state.ManagedRouteSnapshot.Should().NotBeNull();
        state.SoftwareRules.Should().NotBeNull();
        state.MacTunnelProfiles.Should().NotBeNull();
        state.MacSoftwareRules.Should().NotBeNull();
        state.MacDomainProfileAssignments.Should().NotBeNull();
        state.DomainRules.Should().BeEmpty();
        state.LastKnownResolvedIps.Should().BeEmpty();
        state.ManagedRouteSnapshot.Should().BeEmpty();
        state.SoftwareRules.Should().BeEmpty();
        state.MacTunnelProfiles.Should().BeEmpty();
        state.MacSoftwareRules.Should().BeEmpty();
        state.MacDomainProfileAssignments.Should().BeEmpty();

        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }
}
