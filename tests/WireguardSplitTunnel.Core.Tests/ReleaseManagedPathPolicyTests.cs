using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class ReleaseManagedPathPolicyTests
{
    [Theory]
    [InlineData("logs/file.txt")]
    [InlineData("backup/file.txt")]
    [InlineData("backups/file.txt")]
    [InlineData("tmp/file.txt")]
    [InlineData("temp/file.txt")]
    [InlineData("data/state.json")]
    [InlineData("data/applied-state.json")]
    [InlineData("data/temp-lists.json")]
    [InlineData("data/install.status.txt")]
    [InlineData("data/runtime.log")]
    [InlineData("data/update-metadata.json")]
    [InlineData("data/wireguard.conf")]
    [InlineData("data/secret.dpapi")]
    [InlineData("data/file.bak")]
    [InlineData("data/file.backup")]
    [InlineData("data/file.tmp")]
    [InlineData("data/file.temp")]
    [InlineData("data/candidate-metadata.json")]
    [InlineData("data/staging-metadata.json")]
    [InlineData("data/updater-metadata.json")]
    [InlineData("data/local-metadata.json")]
    [InlineData("data/protected-metadata.json")]
    [InlineData("data/transaction-metadata.json")]
    public void IsProtectedPayloadPath_RejectsEveryProtectedCategory(string path)
    {
        ReleaseManagedPathPolicy.IsProtectedPayloadPath(path).Should().BeTrue();
    }

    [Theory]
    [InlineData("catalog/runtime-log.txt")]
    [InlineData("data/metadata-guide.json")]
    [InlineData("data/candidate-guide.json")]
    public void IsProtectedPayloadPath_AllowsNearMisses(string path)
    {
        ReleaseManagedPathPolicy.IsProtectedPayloadPath(path).Should().BeFalse();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void IsProtectedPayloadPath_FailsClosedForMissingInput(string? path)
    {
        ReleaseManagedPathPolicy.IsProtectedPayloadPath(path!).Should().BeTrue();
    }
}
