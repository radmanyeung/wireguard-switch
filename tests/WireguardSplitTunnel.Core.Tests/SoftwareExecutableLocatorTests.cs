using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class SoftwareExecutableLocatorTests
{
    [Fact]
    public void NormalizeResolvedPaths_ReturnsExistingMatchingExePathsInSourceOrder()
    {
        var tempDirectory = CreateTempDirectory();
        try
        {
            var runningPath = CreateExe(tempDirectory, "running", "codex.exe");
            var duplicateRunningPath = runningPath.ToUpperInvariant();
            var pathEnvironmentPath = CreateExe(tempDirectory, "path", "codex.exe");
            var wrongExePath = CreateExe(tempDirectory, "wrong", "other.exe");
            var missingPath = Path.Combine(tempDirectory, "missing", "codex.exe");

            var resolved = SoftwareExecutableLocator.NormalizeResolvedPaths(
                "codex",
                [runningPath, duplicateRunningPath, missingPath],
                [pathEnvironmentPath],
                [wrongExePath]);

            resolved.Should().Equal(runningPath, pathEnvironmentPath);
        }
        finally
        {
            Directory.Delete(tempDirectory, recursive: true);
        }
    }

    [Fact]
    public void NormalizeResolvedPaths_IncludesNewestCommandRunnerExtensionPath()
    {
        var tempDirectory = CreateTempDirectory();
        try
        {
            var olderPath = CreateExe(tempDirectory, Path.Combine("openai.chatgpt-26.325.31654-win32-x64", "bin", "windows-x86_64"), "codex-command-runner.exe");
            var newerPath = CreateExe(tempDirectory, Path.Combine("openai.chatgpt-26.513.21555-win32-x64", "bin", "windows-x86_64"), "codex-command-runner.exe");

            var resolved = SoftwareExecutableLocator.NormalizeResolvedPaths(
                "codex-command-runner.exe",
                [],
                [],
                [olderPath, newerPath]);

            resolved.Should().Equal(newerPath, olderPath);
        }
        finally
        {
            Directory.Delete(tempDirectory, recursive: true);
        }
    }

    private static string CreateTempDirectory()
    {
        var tempDirectory = Path.Combine(Path.GetTempPath(), $"wgst-locator-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDirectory);
        return tempDirectory;
    }

    private static string CreateExe(string root, string subdirectory, string exeName)
    {
        var directory = Path.Combine(root, subdirectory);
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, exeName);
        File.WriteAllText(path, "");
        return path;
    }
}
