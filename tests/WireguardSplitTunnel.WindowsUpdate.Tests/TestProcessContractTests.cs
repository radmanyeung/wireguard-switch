using System.Diagnostics;
using FluentAssertions;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class TestProcessContractTests
{
    private const int InvalidArgumentsExitCode = 64;
    private static readonly TimeSpan ExitTimeout = TimeSpan.FromSeconds(5);

    public static IEnumerable<object[]> InvalidArgumentCases()
    {
        yield return new object[] { Array.Empty<string>() };
        yield return new object[] { new[] { "unknown" } };
        yield return new object[] { new[] { "wait", "extra" } };
        yield return new object[] { new[] { "exit-before-health", "extra" } };
        yield return new object[] { new[] { "write-health-then-wait" } };
    }

    [Fact]
    public async Task WaitMode_RemainsAliveUntilTheExactStartedProcessIsKilled()
    {
        using var process = StartTestProcess("wait");

        try
        {
            await Task.Delay(TimeSpan.FromMilliseconds(500));

            process.HasExited.Should().BeFalse();
        }
        finally
        {
            await KillExactProcessAsync(process);
        }
    }

    [Fact]
    public async Task ExitBeforeHealthMode_ExitsWithCode23()
    {
        using var process = StartTestProcess("exit-before-health");

        try
        {
            (await WaitForExitCodeAsync(process)).Should().Be(23);
        }
        finally
        {
            await KillExactProcessAsync(process);
        }
    }

    [Theory]
    [MemberData(nameof(InvalidArgumentCases))]
    public async Task UnsupportedArgumentShapes_ExitWithCode64(string[] arguments)
    {
        using var process = StartTestProcess(arguments);

        try
        {
            (await WaitForExitCodeAsync(process)).Should().Be(InvalidArgumentsExitCode);
        }
        finally
        {
            await KillExactProcessAsync(process);
        }
    }

    [Fact]
    public async Task WriteHealthThenWait_WritesTheValidPreExistingMarkerAndRemainsAlive()
    {
        var directory = CreateGuidDirectory();
        var markerPath = Path.Combine(directory, "health.marker");
        using var process = StartTestProcess("write-health-then-wait", markerPath);

        try
        {
            var markerContents = await ReadFileWhenAvailableAsync(markerPath);

            markerContents.Should().Be("healthy");
            process.HasExited.Should().BeFalse();
        }
        finally
        {
            await KillExactProcessAsync(process);
            DeleteOwnedDirectory(directory);
        }
    }

    [Fact]
    public async Task WriteHealthThenWait_RejectsAMissingGuidDirectoryWithoutCreatingIt()
    {
        var directory = Path.Combine(GetTestProcessRoot(), Guid.NewGuid().ToString("N"));
        var markerPath = Path.Combine(directory, "health.marker");
        Directory.CreateDirectory(GetTestProcessRoot());
        using var process = StartTestProcess("write-health-then-wait", markerPath);

        try
        {
            (await WaitForExitCodeAsync(process)).Should().Be(InvalidArgumentsExitCode);
            Directory.Exists(directory).Should().BeFalse();
            File.Exists(markerPath).Should().BeFalse();
        }
        finally
        {
            await KillExactProcessAsync(process);
            DeleteOwnedDirectory(directory);
        }
    }

    [Fact]
    public async Task WriteHealthThenWait_RejectsANonCanonicalAliasWithoutWriting()
    {
        var directory = CreateGuidDirectory();
        var markerPath = Path.Combine(directory, "health.marker");
        var aliasedPath = Path.Combine(directory, ".", "health.marker");
        using var process = StartTestProcess("write-health-then-wait", aliasedPath);

        try
        {
            (await WaitForExitCodeAsync(process)).Should().Be(InvalidArgumentsExitCode);
            File.Exists(markerPath).Should().BeFalse();
        }
        finally
        {
            await KillExactProcessAsync(process);
            DeleteOwnedDirectory(directory);
        }
    }

    [Fact]
    public async Task WriteHealthThenWait_DoesNotOverwriteAnExistingMarker()
    {
        var directory = CreateGuidDirectory();
        var markerPath = Path.Combine(directory, "health.marker");
        File.WriteAllText(markerPath, "existing");
        using var process = StartTestProcess("write-health-then-wait", markerPath);

        try
        {
            (await WaitForExitCodeAsync(process)).Should().Be(InvalidArgumentsExitCode);
            File.ReadAllText(markerPath).Should().Be("existing");
        }
        finally
        {
            await KillExactProcessAsync(process);
            DeleteOwnedDirectory(directory);
        }
    }

    [Fact]
    public async Task WriteHealthThenWait_RejectsAReparseGuidDirectoryWhenTheTokenPermitsIt()
    {
        var root = GetTestProcessRoot();
        var link = Path.Combine(root, Guid.NewGuid().ToString("N"));
        var target = Path.Combine(Path.GetTempPath(), "WireguardSplitTunnel.TestProcess.Targets", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        Directory.CreateDirectory(target);

        try
        {
            try
            {
                Directory.CreateSymbolicLink(link, target);
            }
            catch (Exception exception) when (exception is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
            {
                return;
            }

            var markerPath = Path.Combine(link, "health.marker");
            using var process = StartTestProcess("write-health-then-wait", markerPath);

            try
            {
                (await WaitForExitCodeAsync(process)).Should().Be(InvalidArgumentsExitCode);
                File.Exists(Path.Combine(target, "health.marker")).Should().BeFalse();
            }
            finally
            {
                await KillExactProcessAsync(process);
            }
        }
        finally
        {
            DeleteOwnedLink(link);
            DeleteOwnedDirectory(target);
        }
    }

    private static Process StartTestProcess(params string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(AppContext.BaseDirectory, "WireguardSplitTunnel.TestProcess.exe"),
            UseShellExecute = false,
            CreateNoWindow = true
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        return Process.Start(startInfo) ?? throw new InvalidOperationException("The deterministic test process did not start.");
    }

    private static async Task<int> WaitForExitCodeAsync(Process process)
    {
        await process.WaitForExitAsync().WaitAsync(ExitTimeout);
        return process.ExitCode;
    }

    private static async Task<string> ReadFileWhenAvailableAsync(string path)
    {
        var timeoutAt = DateTime.UtcNow + ExitTimeout;
        IOException? lastSharingFailure = null;

        while (DateTime.UtcNow < timeoutAt)
        {
            try
            {
                if (File.Exists(path))
                {
                    return File.ReadAllText(path);
                }
            }
            catch (IOException exception)
            {
                lastSharingFailure = exception;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(25));
        }

        throw new TimeoutException("The health marker was not readable before the test timeout.", lastSharingFailure);
    }

    private static async Task KillExactProcessAsync(Process process)
    {
        if (!process.HasExited)
        {
            process.Kill(entireProcessTree: true);
        }

        await process.WaitForExitAsync().WaitAsync(ExitTimeout);
    }

    private static string CreateGuidDirectory()
    {
        var directory = Path.Combine(GetTestProcessRoot(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }

    private static string GetTestProcessRoot() =>
        Path.GetFullPath(Path.Combine(Path.GetTempPath(), "WireguardSplitTunnel.TestProcess"));

    private static void DeleteOwnedLink(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static void DeleteOwnedDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
