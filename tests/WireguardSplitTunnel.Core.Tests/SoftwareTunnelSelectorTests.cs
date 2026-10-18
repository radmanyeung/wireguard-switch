using FluentAssertions;
using WireguardSplitTunnel.Core.Services;
namespace WireguardSplitTunnel.Core.Tests;
public class SoftwareTunnelSelectorTests
{
    [Theory] [InlineData(@"C:\configs\Chosen.conf")] [InlineData(@"C:\configs\Chosen.conf.dpapi")]
    public void Selects_config_tunnel_case_insensitively_among_multiple_adapters(string path) =>
        SoftwareTunnelSelector.Select(path,["Other","chosen"]).Should().Be("chosen");
    [Fact] public void Missing_selected_tunnel_does_not_fall_back_to_another_vpn() =>
        SoftwareTunnelSelector.Select(@"C:\configs\Missing.conf",["Other"]).Should().BeNull();
    [Fact] public void No_selection_requires_a_single_unambiguous_active_tunnel()
    {
        SoftwareTunnelSelector.Select(null,["One"]).Should().Be("One");
        SoftwareTunnelSelector.Select(null,["One","Two"]).Should().BeNull();
        SoftwareTunnelSelector.Select(null,[]).Should().BeNull();
    }
}
