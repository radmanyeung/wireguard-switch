using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class RunningSoftwareDiscoveryTests
{
    [Fact]
    public void NormalizeCandidates_ReturnsOnlyExistingExePaths()
    {
        var tempDirectory = CreateTempDirectory();
        try
        {
            var chromePath = Path.Combine(tempDirectory, "chrome.exe");
            File.WriteAllText(chromePath, "");

            var rows = RunningSoftwareDiscovery.NormalizeCandidates([
                new RunningSoftwareRawCandidate("chrome", chromePath),
                new RunningSoftwareRawCandidate("missing", Path.Combine(tempDirectory, "missing.exe")),
                new RunningSoftwareRawCandidate("text", Path.Combine(tempDirectory, "note.txt")),
                new RunningSoftwareRawCandidate("", chromePath),
                new RunningSoftwareRawCandidate("blank", "")
            ]);

            rows.Should().Equal(new RunningSoftwareCandidate("chrome.exe", chromePath));
        }
        finally
        {
            Directory.Delete(tempDirectory, recursive: true);
        }
    }

    [Fact]
    public void NormalizeCandidates_DeduplicatesByExecutablePathAndOrdersByProcessName()
    {
        var tempDirectory = CreateTempDirectory();
        try
        {
            var alphaPath = Path.Combine(tempDirectory, "Alpha.exe");
            var betaPath = Path.Combine(tempDirectory, "beta.exe");
            File.WriteAllText(alphaPath, "");
            File.WriteAllText(betaPath, "");

            var rows = RunningSoftwareDiscovery.NormalizeCandidates([
                new RunningSoftwareRawCandidate("beta", betaPath),
                new RunningSoftwareRawCandidate("alpha", alphaPath),
                new RunningSoftwareRawCandidate("ALPHA", alphaPath)
            ]);

            rows.Select(row => row.ProcessName).Should().Equal("alpha.exe", "beta.exe");
            rows.Select(row => row.ExecutablePath).Should().Equal(alphaPath, betaPath);
        }
        finally
        {
            Directory.Delete(tempDirectory, recursive: true);
        }
    }

    private static string CreateTempDirectory()
    {
        var tempDirectory = Path.Combine(Path.GetTempPath(), $"wgst-running-apps-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDirectory);
        return tempDirectory;
    }
}
