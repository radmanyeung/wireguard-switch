using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class RuntimeLogCandidatePolicyTests
{
    private static readonly string Root = Path.GetFullPath(
        OperatingSystem.IsWindows() ? @"C:\wgst-tests" : "/wgst-tests");

    private static string P(params string[] parts) =>
        Path.Combine(new[] { Root }.Concat(parts).ToArray());

    [Fact]
    public void ExcludeProtectedRoots_DropsCandidatesInsideProtectedInstallRoots()
    {
        var programFiles = P("Program Files");
        var candidates = new[]
        {
            P("Program Files", "WireguardSplitTunnel", "runtime.log"),
            P("Program Files", "WireguardSplitTunnel", "WireguardSplitTunnel", "runtime.log"),
            P("Users", "me", "AppData", "Local", "WireguardSplitTunnel", "runtime.log")
        };

        var kept = RuntimeLogCandidatePolicy.ExcludeProtectedRoots(
            candidates,
            new[] { programFiles, P("Program Files (x86)") });

        kept.Should().Equal(candidates[2]);
    }

    [Fact]
    public void ExcludeProtectedRoots_MatchesWholePathSegmentsOnly()
    {
        var candidates = new[]
        {
            P("Program Files Extra", "runtime.log"),
            P("src", "runtime.log")
        };

        var kept = RuntimeLogCandidatePolicy.ExcludeProtectedRoots(
            candidates,
            new[] { P("Program Files") });

        kept.Should().Equal(candidates);
    }

    [Fact]
    public void ExcludeProtectedRoots_IgnoresBlankRootsAndCandidatesAndDeduplicates()
    {
        var candidate = P("src", "runtime.log");

        var kept = RuntimeLogCandidatePolicy.ExcludeProtectedRoots(
            new[] { candidate, null, "", "  ", candidate },
            new[] { null, "", "   " });

        kept.Should().Equal(candidate);
    }
}
