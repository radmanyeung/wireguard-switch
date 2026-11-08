using System.Text.Json;
using FluentAssertions;
using WireguardSplitTunnel.Core.ConfigCheck;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class NordVpnMetadataTests
{
    private const string PublicKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    private const string OtherKey = "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=";
    private static readonly string ThirdKey = Convert.ToBase64String(Enumerable.Range(32, 32).Select(value => (byte)value).ToArray());

    [Theory]
    [InlineData("uk6000.nordvpn.com", "GB")]
    [InlineData("de12.nordvpn.com", "DE")]
    public void CountryFromHost_DerivesCountryFromTrustedHostname(string host, string expected)
    {
        NordVpnMetadata.CountryFromHost(host).Should().Be(expected);
    }

    [Theory]
    [InlineData("uk6000.nordvpn.com.attacker.example")]
    [InlineData("US1.nordvpn.com")]
    [InlineData("uk6000.example.com")]
    [InlineData("uk6000nordvpn.com")]
    [InlineData("uk.nordvpn.com")]
    public void CountryFromHost_RejectsLookalikes(string host)
    {
        Action parse = () => NordVpnMetadata.CountryFromHost(host);

        parse.Should().Throw<InvalidDataException>();
    }

    [Fact]
    public void SelectCandidates_RequiresOneTrustedSameCountryRecord()
    {
        using var records = JsonDocument.Parse(MetadataJsonWithOnlineOfflineDuplicateWrongCountryAndInvalidKeyRecords);

        var selected = NordVpnMetadata.SelectCandidates(records.RootElement, "GB", 3);

        selected.Should().ContainSingle();
        selected[0].HostName.Should().Be("uk6001.nordvpn.com");
        selected[0].PublicKey.Should().Be(PublicKey);
        selected[0].Country.Should().Be("GB");
    }

    [Fact]
    public void SelectCandidates_ReturnsAtMostTheBoundedLimitInMetadataOrder()
    {
        var json = Array(
            ValidRecord("uk6001.nordvpn.com", PublicKey),
            ValidRecord("uk6002.nordvpn.com", OtherKey),
            ValidRecord("uk6003.nordvpn.com", ThirdKey));

        var selected = Select(json, limit: 2);

        selected.Should().HaveCount(2);
        selected.Select(server => server.HostName).Should().Equal("uk6001.nordvpn.com", "uk6002.nordvpn.com");
    }

    [Fact]
    public void SelectCandidates_AcceptsOneOnlineWireGuardTechnologyAmongOtherTechnologies()
    {
        const string record = """
        {
          "status": "online",
          "hostname": "uk6001.nordvpn.com",
          "locations": [{ "country": { "code": "GB" } }, { "country": { "code": "GB" } }],
          "technologies": [
            { "identifier": "openvpn_udp", "pivot": { "status": "online" }, "metadata": [] },
            { "identifier": "wireguard_udp", "pivot": { "status": "offline" }, "metadata": [] },
            {
              "identifier": "wireguard_udp",
              "pivot": { "status": "online" },
              "metadata": [
                { "name": "public_key", "value": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=" },
                { "name": "other", "value": "retained only as metadata" }
              ]
            }
          ]
        }
        """;

        Select(Array(record)).Should().ContainSingle();
    }

    [Theory]
    [InlineData("offline")]
    [InlineData("Online")]
    [InlineData("maintenance")]
    public void SelectCandidates_RequiresOnlineServer(string status)
    {
        Select(Array(ValidRecord(status: status))).Should().BeEmpty();
    }

    [Fact]
    public void SelectCandidates_RequiresHostnameAndAllLocationCountriesToMatch()
    {
        var wrongHostCountry = ValidRecord("de6001.nordvpn.com", country: "DE");
        var wrongLocationCountry = ValidRecord("uk6001.nordvpn.com", country: "US");
        var multipleLocationCountries = """
        {
          "status": "online",
          "hostname": "uk6001.nordvpn.com",
          "locations": [{ "country": { "code": "GB" } }, { "country": { "code": "US" } }],
          "technologies": [{ "identifier": "wireguard_udp", "pivot": { "status": "online" }, "metadata": [{ "name": "public_key", "value": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=" }] }]
        }
        """;

        Select(Array(wrongHostCountry, wrongLocationCountry, multipleLocationCountries)).Should().BeEmpty();
    }

    [Fact]
    public void SelectCandidates_RejectsDuplicateHostnames()
    {
        var json = Array(
            ValidRecord("uk6001.nordvpn.com", PublicKey),
            ValidRecord("uk6001.nordvpn.com", OtherKey));

        var selected = Select(json);

        selected.Should().ContainSingle();
        selected[0].PublicKey.Should().Be(PublicKey);
    }

    [Fact]
    public void HostNameComparer_RejectsDifferentlyCasedDuplicateAtComparerBoundary()
    {
        var hosts = new HashSet<string>(NordVpnMetadata.HostNameComparer) { "uk6001.nordvpn.com" };

        hosts.Add("UK6001.NORDVPN.COM").Should().BeFalse();
        hosts.Should().ContainSingle();
    }

    [Fact]
    public void SelectCandidates_RequiresExactlyOneOnlineWireGuardTechnology()
    {
        var noWireGuard = RecordWithTechnologies("""{ "identifier": "openvpn_udp", "pivot": { "status": "online" }, "metadata": [] }""");
        var twoOnlineWireGuard = RecordWithTechnologies(
            OnlineWireGuardTechnology(PublicKey),
            OnlineWireGuardTechnology(OtherKey));

        Select(Array(noWireGuard, twoOnlineWireGuard)).Should().BeEmpty();
    }

    [Fact]
    public void SelectCandidates_RequiresExactlyOneCanonicalValidPublicKey()
    {
        var noKey = RecordWithTechnologies("""{ "identifier": "wireguard_udp", "pivot": { "status": "online" }, "metadata": [] }""");
        var duplicateKeys = RecordWithTechnologies($$"""
        {
          "identifier": "wireguard_udp", "pivot": { "status": "online" },
          "metadata": [{ "name": "public_key", "value": "{{PublicKey}}" }, { "name": "public_key", "value": "{{OtherKey}}" }]
        }
        """);
        var invalidKey = ValidRecord(key: "invalid");
        var nonCanonicalKey = ValidRecord(key: PublicKey[..^2] + (char)(PublicKey[^2] + 1) + "=");

        Select(Array(noKey, duplicateKeys, invalidKey, nonCanonicalKey)).Should().BeEmpty();
    }

    [Theory]
    [InlineData("null")]
    [InlineData("42")]
    [InlineData("{}")]
    [InlineData("{ \"status\": \"online\" }")]
    [InlineData("{ \"status\": 1, \"hostname\": \"uk6000.nordvpn.com\" }")]
    [InlineData("{ \"status\": \"online\", \"hostname\": 42 }")]
    [InlineData("{ \"status\": \"online\", \"hostname\": \"uk6000.nordvpn.com\", \"locations\": {} }")]
    [InlineData("{ \"status\": \"online\", \"hostname\": \"uk6000.nordvpn.com\", \"locations\": [null] }")]
    [InlineData("{ \"status\": \"online\", \"hostname\": \"uk6000.nordvpn.com\", \"locations\": [{ \"country\": 42 }] }")]
    [InlineData("{ \"status\": \"online\", \"hostname\": \"uk6000.nordvpn.com\", \"locations\": [{ \"country\": { \"code\": 42 } }] }")]
    [InlineData("{ \"status\": \"online\", \"hostname\": \"uk6000.nordvpn.com\", \"locations\": [{ \"country\": { \"code\": \"GB\" } }] }")]
    [InlineData("{ \"status\": \"online\", \"hostname\": \"uk6000.nordvpn.com\", \"locations\": [{ \"country\": { \"code\": \"GB\" } }], \"technologies\": {} }")]
    [InlineData("{ \"status\": \"online\", \"hostname\": \"uk6000.nordvpn.com\", \"locations\": [{ \"country\": { \"code\": \"GB\" } }], \"technologies\": [null] }")]
    [InlineData("{ \"status\": \"online\", \"hostname\": \"uk6000.nordvpn.com\", \"locations\": [{ \"country\": { \"code\": \"GB\" } }], \"technologies\": [{ \"identifier\": 42 }] }")]
    [InlineData("{ \"status\": \"online\", \"hostname\": \"uk6000.nordvpn.com\", \"locations\": [{ \"country\": { \"code\": \"GB\" } }], \"technologies\": [{ \"identifier\": \"wireguard_udp\", \"pivot\": null }] }")]
    [InlineData("{ \"status\": \"online\", \"hostname\": \"uk6000.nordvpn.com\", \"locations\": [{ \"country\": { \"code\": \"GB\" } }], \"technologies\": [{ \"identifier\": \"wireguard_udp\", \"pivot\": { \"status\": 42 } }] }")]
    [InlineData("{ \"status\": \"online\", \"hostname\": \"uk6000.nordvpn.com\", \"locations\": [{ \"country\": { \"code\": \"GB\" } }], \"technologies\": [{ \"identifier\": \"wireguard_udp\", \"pivot\": { \"status\": \"online\" } }] }")]
    [InlineData("{ \"status\": \"online\", \"hostname\": \"uk6000.nordvpn.com\", \"locations\": [{ \"country\": { \"code\": \"GB\" } }], \"technologies\": [{ \"identifier\": \"wireguard_udp\", \"pivot\": { \"status\": \"online\" }, \"metadata\": {} }] }")]
    [InlineData("{ \"status\": \"online\", \"hostname\": \"uk6000.nordvpn.com\", \"locations\": [{ \"country\": { \"code\": \"GB\" } }], \"technologies\": [{ \"identifier\": \"wireguard_udp\", \"pivot\": { \"status\": \"online\" }, \"metadata\": [null] }] }")]
    [InlineData("{ \"status\": \"online\", \"hostname\": \"uk6000.nordvpn.com\", \"locations\": [{ \"country\": { \"code\": \"GB\" } }], \"technologies\": [{ \"identifier\": \"wireguard_udp\", \"pivot\": { \"status\": \"online\" }, \"metadata\": [{ \"name\": 42 }] }] }")]
    [InlineData("{ \"status\": \"online\", \"hostname\": \"uk6000.nordvpn.com\", \"locations\": [{ \"country\": { \"code\": \"GB\" } }], \"technologies\": [{ \"identifier\": \"wireguard_udp\", \"pivot\": { \"status\": \"online\" }, \"metadata\": [{ \"name\": \"public_key\", \"value\": 42 }] }] }")]
    public void SelectCandidates_SkipsMalformedIndividualRecords(string malformedRecord)
    {
        var selected = Select(Array(malformedRecord, ValidRecord("uk6001.nordvpn.com", PublicKey)));

        selected.Should().ContainSingle();
        selected[0].HostName.Should().Be("uk6001.nordvpn.com");
    }

    [Theory]
    [InlineData("null")]
    [InlineData("{}")]
    [InlineData("\"not-an-array\"")]
    [InlineData("42")]
    public void SelectCandidates_RejectsNonArrayTopLevelMetadata(string json)
    {
        Action select = () => Select(json);

        select.Should().Throw<InvalidDataException>().WithMessage("Invalid metadata.");
    }

    [Fact]
    public void SelectCandidates_DoesNotHideMalformedTopLevelJson()
    {
        Action parse = () => JsonDocument.Parse("{ not-json");

        parse.Should().Throw<JsonException>();
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(6)]
    public void SelectCandidates_RejectsLimitsOutsideOneThroughFive(int limit)
    {
        Action select = () => Select("[]", limit);

        select.Should().Throw<InvalidDataException>().WithMessage("Invalid metadata.");
    }

    [Fact]
    public void SelectCandidates_ErrorsDoNotExposeRawJsonOrKeyMaterial()
    {
        var rawJson = $$"""{ "secret": "{{PublicKey}}" }""";

        var exception = Record.Exception(() => Select(rawJson, limit: 0));

        exception.Should().BeOfType<InvalidDataException>();
        exception!.Message.Should().NotContain(rawJson).And.NotContain(PublicKey).And.NotContain("secret");
    }

    private static IReadOnlyList<ConfigCheckServer> Select(string json, int limit = 3)
    {
        using var document = JsonDocument.Parse(json);
        return NordVpnMetadata.SelectCandidates(document.RootElement, "GB", limit);
    }

    private static string Array(params string[] records) => "[" + string.Join(",", records) + "]";

    private static string ValidRecord(string host = "uk6000.nordvpn.com", string key = PublicKey, string status = "online", string country = "GB") => $$"""
    {
      "status": "{{status}}",
      "hostname": "{{host}}",
      "locations": [{ "country": { "code": "{{country}}" } }],
      "technologies": [{{OnlineWireGuardTechnology(key)}}]
    }
    """;

    private static string RecordWithTechnologies(params string[] technologies) => $$"""
    {
      "status": "online",
      "hostname": "uk6000.nordvpn.com",
      "locations": [{ "country": { "code": "GB" } }],
      "technologies": [{{string.Join(",", technologies)}}]
    }
    """;

    private static string OnlineWireGuardTechnology(string key) => $$"""
    { "identifier": "wireguard_udp", "pivot": { "status": "online" }, "metadata": [{ "name": "public_key", "value": "{{key}}" }] }
    """;

    private static readonly string MetadataJsonWithOnlineOfflineDuplicateWrongCountryAndInvalidKeyRecords = $$"""
    [
      {
        "status": "offline",
        "hostname": "uk6000.nordvpn.com",
        "locations": [{ "country": { "code": "GB" } }],
        "technologies": [{{OnlineWireGuardTechnology(OtherKey)}}]
      },
      {
        "status": "online",
        "hostname": "uk6001.nordvpn.com",
        "locations": [{ "country": { "code": "GB" } }],
        "technologies": [{{OnlineWireGuardTechnology(PublicKey)}}]
      },
      {
        "status": "online",
        "hostname": "uk6001.nordvpn.com",
        "locations": [{ "country": { "code": "GB" } }],
        "technologies": [{{OnlineWireGuardTechnology(OtherKey)}}]
      },
      {
        "status": "online",
        "hostname": "de7000.nordvpn.com",
        "locations": [{ "country": { "code": "DE" } }],
        "technologies": [{{OnlineWireGuardTechnology(OtherKey)}}]
      },
      {
        "status": "online",
        "hostname": "uk6002.nordvpn.com",
        "locations": [{ "country": { "code": "US" } }],
        "technologies": [{{OnlineWireGuardTechnology(OtherKey)}}]
      },
      {
        "status": "online",
        "hostname": "uk6003.nordvpn.com",
        "locations": [{ "country": { "code": "GB" } }],
        "technologies": [{{OnlineWireGuardTechnology("invalid")}}]
      }
    ]
    """;
}
