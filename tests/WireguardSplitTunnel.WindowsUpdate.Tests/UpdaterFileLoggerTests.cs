using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using FluentAssertions;
using WireguardSplitTunnel.WindowsUpdate.Logging;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class UpdaterFileLoggerTests
{
    [Fact]
    public void TryAppend_PreservesEveryExistingByteAsAnExactPrefix()
    {
        using var temporary = new TemporaryDirectory();
        var path = Path.Combine(temporary.Path, "updater.log");
        byte[] prefix = [0, 255, 10, 65, 13, 10];
        File.WriteAllBytes(path, prefix);
        var logger = new UpdaterFileLogger(
            path,
            new FixedTimeProvider(
                new DateTimeOffset(
                    2026,
                    7,
                    30,
                    1,
                    2,
                    3,
                    TimeSpan.Zero)));

        var appended = logger.TryAppend(
            "check_started",
            "automatic",
            "2.0.0");

        appended.Should().BeTrue();
        var bytes = File.ReadAllBytes(path);
        bytes.AsSpan(0, prefix.Length).ToArray()
            .Should()
            .Equal(prefix);
        Encoding.UTF8.GetString(bytes[prefix.Length..])
            .Should()
            .Be(
                "2026-07-30T01:02:03.0000000+00:00"
                + " event=check_started"
                + " detail=automatic"
                + " version=2.0.0"
                + Environment.NewLine);
    }

    [Fact]
    public void TryAppend_RejectsSensitiveOrMultilineFieldsWithoutLoggingThem()
    {
        using var temporary = new TemporaryDirectory();
        var path = Path.Combine(temporary.Path, "updater.log");
        var logger = new UpdaterFileLogger(
            path,
            new FixedTimeProvider(DateTimeOffset.UnixEpoch));
        const string secret =
            "Bearer credential\r\n"
            + "C:\\Users\\person\\staging\\state.json"
            + "{\"account\":\"peter@example.test\"}";

        var appended = logger.TryAppend(
            "download_failed",
            secret,
            secret);

        appended.Should().BeTrue();
        var text = File.ReadAllText(path);
        text.Should().NotContain("Bearer");
        text.Should().NotContain("C:\\Users");
        text.Should().NotContain("state.json");
        text.Should().NotContain("account");
        text.Should().NotContain("example.test");
        text.Should().Contain("event=download_failed");
        text.Should().Contain("detail=invalid");
        text.Should().Contain("version=invalid");
        text.Count(character => character == '\n')
            .Should()
            .Be(1);
    }

    [Fact]
    public void TryAppend_RejectsARealDirectoryJunctionWithoutTouchingItsTarget()
    {
        using var temporary = new TemporaryDirectory();
        var product = Path.Combine(temporary.Path, "product");
        var target = Path.Combine(temporary.Path, "target");
        var junction = Path.Combine(product, "logs");
        var targetLog = Path.Combine(target, "updater.log");
        Directory.CreateDirectory(product);
        Directory.CreateDirectory(target);
        File.WriteAllText(targetLog, "sentinel");
        TryCreateJunction(junction, target)
            .Should()
            .BeTrue(
                "real directory junction creation must run "
                + "on the Windows security-test host");

        try
        {
            var logger = new UpdaterFileLogger(
                Path.Combine(junction, "updater.log"),
                new FixedTimeProvider(DateTimeOffset.UnixEpoch));

            logger.TryAppend("check_started").Should().BeFalse();
            File.ReadAllText(targetLog).Should().Be("sentinel");
        }
        finally
        {
            DeleteDirectoryLink(junction);
        }
    }

    [Fact]
    public void TryAppend_RejectsAFileSymlinkWithoutTouchingItsTarget()
    {
        using var temporary = new TemporaryDirectory();
        var logs = Path.Combine(temporary.Path, "logs");
        var target = Path.Combine(temporary.Path, "target.log");
        var link = Path.Combine(logs, "updater.log");
        Directory.CreateDirectory(logs);
        File.WriteAllText(target, "sentinel");
        if (!TryCreateFileSymlink(link, target))
        {
            return;
        }

        try
        {
            var logger = new UpdaterFileLogger(
                link,
                new FixedTimeProvider(DateTimeOffset.UnixEpoch));

            logger.TryAppend("check_started").Should().BeFalse();
            File.ReadAllText(target).Should().Be("sentinel");
        }
        finally
        {
            DeleteFileLink(link);
        }
    }

    [Fact]
    public void TryAppend_RejectsAHardLinkWithoutTouchingItsAlias()
    {
        using var temporary = new TemporaryDirectory();
        var logs = Path.Combine(temporary.Path, "logs");
        var target = Path.Combine(temporary.Path, "target.log");
        var link = Path.Combine(logs, "updater.log");
        Directory.CreateDirectory(logs);
        File.WriteAllText(target, "sentinel");
        TryCreateHardLink(link, target)
            .Should()
            .BeTrue(
                "hardlink creation must run "
                + "on the Windows security-test host");

        try
        {
            var logger = new UpdaterFileLogger(
                link,
                new FixedTimeProvider(DateTimeOffset.UnixEpoch));

            logger.TryAppend("check_started").Should().BeFalse();
            File.ReadAllText(target).Should().Be("sentinel");
        }
        finally
        {
            DeleteFileLink(link);
        }
    }

    [Fact]
    public void TryAppend_WhenPinnedBoundaryRejectsPath_FailsClosed()
    {
        using var temporary = new TemporaryDirectory();
        var path = Path.Combine(temporary.Path, "updater.log");
        var appender = new RejectingAppender();
        var logger = new UpdaterFileLogger(
            path,
            new FixedTimeProvider(DateTimeOffset.UnixEpoch),
            appender);

        logger.TryAppend("check_started").Should().BeFalse();
        appender.Calls.Should().Be(1);
        File.Exists(path).Should().BeFalse();
    }

    [Fact]
    public void TryAppend_DoesNotThrowOrTruncateWhenDestinationCannotBeOpened()
    {
        using var temporary = new TemporaryDirectory();
        var path = Path.Combine(temporary.Path, "directory");
        Directory.CreateDirectory(path);
        var logger = new UpdaterFileLogger(
            path,
            new FixedTimeProvider(DateTimeOffset.UnixEpoch));

        var action = () => logger.TryAppend("check_failed");

        action.Should().NotThrow();
        action().Should().BeFalse();
        Directory.Exists(path).Should().BeTrue();
    }

    private static bool TryCreateJunction(
        string junction,
        string target)
    {
        try
        {
            using var process = Process.Start(
                new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    ArgumentList =
                    {
                        "/d",
                        "/c",
                        "mklink",
                        "/J",
                        junction,
                        target
                    }
                });
            if (process is null)
            {
                return false;
            }

            process.WaitForExit();
            return process.ExitCode == 0;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or PlatformNotSupportedException)
        {
            return false;
        }
    }

    private static bool TryCreateFileSymlink(
        string link,
        string target)
    {
        try
        {
            File.CreateSymbolicLink(link, target);
            return true;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or PlatformNotSupportedException)
        {
            return false;
        }
    }

    private static bool TryCreateHardLink(
        string link,
        string target) =>
        CreateHardLinkW(link, target, IntPtr.Zero);

    private static void DeleteDirectoryLink(string path)
    {
        try
        {
            Directory.Delete(path, recursive: false);
        }
        catch (DirectoryNotFoundException)
        {
        }
    }

    private static void DeleteFileLink(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (FileNotFoundException)
        {
        }
    }

    private sealed class FixedTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset _utcNow;

        public FixedTimeProvider(DateTimeOffset utcNow)
        {
            _utcNow = utcNow;
        }

        public override DateTimeOffset GetUtcNow() => _utcNow;
    }

    private sealed class RejectingAppender
        : IUpdaterLogAppender
    {
        public int Calls { get; private set; }

        public bool TryAppend(string path, byte[] bytes)
        {
            Calls++;
            return false;
        }
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "WireguardSplitTunnel-UpdaterLoggerTests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Path, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(
        string lpFileName,
        string lpExistingFileName,
        IntPtr lpSecurityAttributes);
}