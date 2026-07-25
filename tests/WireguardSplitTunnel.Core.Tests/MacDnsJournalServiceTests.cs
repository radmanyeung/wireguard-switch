using System.Text;
using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Platform;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

[System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Interoperability",
    "CA1416:Validate platform compatibility",
    Justification = "These tests exercise platform-neutral script composition helpers without executing macOS commands.")]
public sealed class MacDnsJournalServiceTests
{
    private const string JournalPath =
        "/Users/u/Application Support/WireguardSplitTunnel/.wgst-dns-journal-0123456789abcdef0123456789abcdef.v1";

    [Fact]
    public void BuildCaptureScript_AtomicallyPublishesOwnerReadableJournalBeforeReturning()
    {
        var script = MacDnsJournalService.BuildCaptureScript(JournalPath);

        script.Should().Contain("umask 077");
        script.Should().Contain("/usr/sbin/networksetup -listallnetworkservices");
        script.Should().Contain("/usr/sbin/networksetup -getdnsservers");
        script.Should().Contain("/usr/sbin/networksetup -getsearchdomains");
        script.Should().Contain("/usr/bin/stat -f '%u' \"/Users/u/Application Support/WireguardSplitTunnel\"");
        script.Should().Contain("/usr/sbin/chown \"$journal_uid:$journal_gid\" \"$journal_tmp\"");
        script.Should().Contain("/bin/chmod 0600 \"$journal_tmp\"");
        script.Should().Contain($"/bin/mv -f \"$journal_tmp\" \"{JournalPath}\"");
        script.Should().Contain("/bin/sync");
        script.Should().NotContain("PrivateKey");
    }

    [Fact]
    public void BuildCaptureScript_ExplicitlyChecksEnumerationAndRejectsEmptyServiceData()
    {
        var script = MacDnsJournalService.BuildCaptureScript(JournalPath);

        script.Should().Contain(
            "if ! journal_services=$(/usr/sbin/networksetup -listallnetworkservices); then");
        script.Should().NotContain("< <(");
        (script.Split(
                "[[ -n \"$journal_services\" ]] || exit 1",
                StringSplitOptions.None).Length - 1)
            .Should().Be(2);

        var enumerate = script.IndexOf(
            "journal_services=$(/usr/sbin/networksetup -listallnetworkservices)",
            StringComparison.Ordinal);
        var loop = script.IndexOf(
            "while IFS= read -r journal_service",
            StringComparison.Ordinal);
        var publish = script.IndexOf("/bin/mv -f", StringComparison.Ordinal);
        enumerate.Should().BeLessThan(loop);
        loop.Should().BeLessThan(publish);
    }

    [Fact]
    public void BuildCaptureScript_AllEncodingPipelinesFailClosedBeforePublishAndTunnelUp()
    {
        var capture = MacDnsJournalService.BuildCaptureScript(JournalPath);
        var executable = MacAdminShell.BuildScriptContent(
            capture + "/opt/homebrew/bin/wg-quick up \"/config/SG.conf\"\n");

        var setE = executable.IndexOf("set -e", StringComparison.Ordinal);
        var pipefail = executable.IndexOf("set -o pipefail", StringComparison.Ordinal);
        var serviceEncoding = executable.IndexOf(
            "journal_service_b64=$(/usr/bin/printf",
            StringComparison.Ordinal);
        var dnsEncoding = executable.IndexOf(
            "journal_dns_b64=$(/usr/bin/printf",
            StringComparison.Ordinal);
        var searchEncoding = executable.IndexOf(
            "journal_search_b64=$(/usr/bin/printf",
            StringComparison.Ordinal);
        var publish = executable.IndexOf("/bin/mv -f", StringComparison.Ordinal);
        var up = executable.IndexOf("wg-quick up", StringComparison.Ordinal);

        executable.Should().Contain(
            "if ! journal_service_b64=$(/usr/bin/printf");
        executable.Should().Contain(
            "if ! journal_dns_b64=$(/usr/bin/printf");
        executable.Should().Contain(
            "if ! journal_search_b64=$(/usr/bin/printf");
        setE.Should().BeLessThan(pipefail);
        pipefail.Should().BeLessThan(serviceEncoding);
        serviceEncoding.Should().BeLessThan(dnsEncoding);
        dnsEncoding.Should().BeLessThan(searchEncoding);
        searchEncoding.Should().BeLessThan(publish);
        publish.Should().BeLessThan(up);
    }

    [Fact]
    public void ParseJournal_PreservesOrderedResolverState()
    {
        var content = Journal(
            ("Wi-Fi", "1.1.1.1\n9.9.9.9\n", "home.arpa\ntailnet.ts.net\n"),
            ("Ethernet", "There aren't any DNS Servers set on Ethernet.\n", ""));

        var parsed = MacDnsJournalService.ParseJournal(content);

        parsed.Should().HaveCount(2);
        parsed[0].Should().BeEquivalentTo(
            new MacDnsServiceSnapshot(
                "Wi-Fi",
                ["1.1.1.1", "9.9.9.9"],
                ["home.arpa", "tailnet.ts.net"]));
        parsed[1].DnsServers.Should().BeEmpty();
        parsed[1].SearchDomains.Should().BeEmpty();
    }

    [Fact]
    public void ParseJournal_MalformedRowRejectsWholeSnapshot()
    {
        var malformed = "WGST_DNS_JOURNAL_V1\nnot-three-fields\n";

        var act = () => MacDnsJournalService.ParseJournal(malformed);

        act.Should().Throw<InvalidDataException>();
    }

    [Fact]
    public void RecoverDebt_UsesPrivilegedPostAuthorizationSnapshot()
    {
        var pending = PendingDebt();
        var stateBeforeAuthorization = new MacDnsServiceSnapshot(
            "Wi-Fi",
            ["1.1.1.1"],
            ["home.arpa"]);
        var changedWhileWaiting = Journal(
            ("Wi-Fi", "100.100.100.100\n", "tailnet.ts.net\n"));

        var recovered = MacDnsJournalService.RecoverDebt(
            pending,
            changedWhileWaiting,
            MacTunnelMappingPresence.Present);

        recovered.Should().NotBeNull();
        recovered!.Services.Should().ContainSingle()
            .Which.Should().BeEquivalentTo(
                new MacDnsServiceSnapshot(
                    "Wi-Fi",
                    ["100.100.100.100"],
                    ["tailnet.ts.net"]));
        recovered.Services.Should().NotContainEquivalentOf(stateBeforeAuthorization);
    }

    [Fact]
    public void RecoverDebt_MissingJournalBeforeAnyMutation_ClearsPendingDebt()
    {
        MacDnsJournalService.RecoverDebt(
                PendingDebt(),
                journalContent: null,
                MacTunnelMappingPresence.Absent)
            .Should().BeNull();
    }

    [Theory]
    [InlineData(MacTunnelMappingPresence.Present)]
    [InlineData(MacTunnelMappingPresence.Unknown)]
    public void RecoverDebt_MissingJournalWithPossibleTunnel_PreservesUnknownDebt(
        MacTunnelMappingPresence mappingPresence)
    {
        var pending = PendingDebt();

        MacDnsJournalService.RecoverDebt(pending, null, mappingPresence)
            .Should().BeSameAs(pending);
    }

    private static MacRawTunnelDnsCleanupDebt PendingDebt() =>
        new(
            "SG",
            "/opt/homebrew/etc/wireguard/SG.conf",
            ["103.86.96.100"],
            ["vpn.example"],
            [],
            JournalPath);

    private static string Journal(params (string Service, string Dns, string Search)[] rows)
    {
        var builder = new StringBuilder("WGST_DNS_JOURNAL_V1\n");
        foreach (var row in rows)
        {
            builder.Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(row.Service)));
            builder.Append('\t');
            builder.Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(row.Dns)));
            builder.Append('\t');
            builder.Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(row.Search)));
            builder.Append('\n');
        }

        return builder.ToString();
    }
}
