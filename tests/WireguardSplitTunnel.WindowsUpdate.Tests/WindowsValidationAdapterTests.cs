using FluentAssertions;
using WireguardSplitTunnel.WindowsUpdate.Validation;
using System.ComponentModel;
using System.Security;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class WindowsValidationAdapterTests
{
    [Theory]
    [InlineData("1.2.3", "1.2.3")]
    [InlineData("01.2.3", null)]
    [InlineData("v1.2.3", null)]
    [InlineData("1.2.3.0", null)]
    public void ProductVersionReader_NormalizesOnlyStrictSemanticVersions(string rawVersion, string? expected)
    {
        var reader = new WindowsExecutableProductVersionReader(_ => rawVersion);

        reader.ReadProductVersion("ignored.exe").Should().Be(expected);
    }

    [Fact]
    public void DiskSpaceProvider_ReturnsActualAvailableBytesForTemporaryDrive()
    {
        var provider = new WindowsDiskSpaceProvider();

        provider.GetAvailableBytes(Path.GetTempPath()).Should().BeGreaterThan(0);
    }

    [Fact]
    public void PathSafetyInspector_DetectsARealTemporaryJunction_WhenTheTokenPermitsIt()
    {
        using var temporary = new TemporaryDirectory();
        var target = Path.Combine(temporary.Path, "target");
        var junction = Path.Combine(temporary.Path, "junction");
        Directory.CreateDirectory(target);

        try
        {
            Directory.CreateSymbolicLink(junction, target);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
            return;
        }

        var inspector = new WindowsPathSafetyInspector();

        inspector.IsReparsePoint(junction).Should().BeTrue();
    }

    [Fact]
    public void PathSafetyInspector_FailsClosedWhenAttributesCannotBeRead()
    {
        var inspector = new WindowsPathSafetyInspector(_ => throw new UnauthorizedAccessException());

        inspector.IsReparsePoint("C:\\unreadable").Should().BeTrue();
    }

    [Theory]
    [InlineData("relative")]
    [InlineData("C:relative")]
    [InlineData("\\rooted")]
    [InlineData("//server/share")]
    [InlineData("\\\\server\\share")]
    [InlineData("\\\\?\\C:\\path")]
    [InlineData("\\\\.\\C:\\path")]
    [InlineData("\\\\??\\C:\\path")]
    public void DiskSpaceProvider_RejectsNonCanonicalOrNetworkPaths(string path)
    {
        new WindowsDiskSpaceProvider().Invoking(provider => provider.GetAvailableBytes(path))
            .Should().Throw<IOException>();
    }

    [Theory]
    [InlineData("win32")]
    [InlineData("security")]
    [InlineData("unsupported")]
    public void ProductVersionReader_FailsClosedForOrdinaryVersionReadFailures(string failure)
    {
        var reader = new WindowsExecutableProductVersionReader(_ => throw failure switch
        {
            "win32" => new Win32Exception(),
            "security" => new SecurityException(),
            _ => new NotSupportedException()
        });

        reader.ReadProductVersion("ignored.exe").Should().BeNull();
    }

    [Fact]
    public void ProductVersionReader_ReadsTheCompiledTestProcessProductVersion()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "WireguardSplitTunnel.TestProcess.dll");

        new WindowsExecutableProductVersionReader().ReadProductVersion(path).Should().Be("0.2.0");
    }

    [Fact]
    public void ProductVersionReader_ReadsRetainedHandleWithoutChangingStreamPosition()
    {
        var path = Path.Combine(
            AppContext.BaseDirectory,
            "WireguardSplitTunnel.TestProcess.dll");
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read);
        stream.Position = Math.Min(17, stream.Length);
        var position = stream.Position;

        new WindowsExecutableProductVersionReader()
            .ReadProductVersion(stream)
            .Should().Be("0.2.0");

        stream.Position.Should().Be(position);
    }

    [Fact]
    public void ProductVersionReader_RetainedHandleFailsClosedForTruncatedImageAndPreservesPosition()
    {
        using var temporary = new TemporaryDirectory();
        var path = Path.Combine(
            temporary.Path,
            "truncated.exe");
        File.WriteAllBytes(
            path,
            [0x4d, 0x5a, 0x00, 0x00]);
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read);
        stream.Position = 2;

        new WindowsExecutableProductVersionReader()
            .ReadProductVersion(stream)
            .Should().BeNull();

        stream.Position.Should().Be(2);
    }

    [Fact]
    public void ProductVersionReader_RetainedHandleRejectsNonFileStreams()
    {
        using var stream = new MemoryStream([1, 2, 3]);
        stream.Position = 1;

        new WindowsExecutableProductVersionReader()
            .ReadProductVersion(stream)
            .Should().BeNull();

        stream.Position.Should().Be(1);
    }

    [Fact]
    public async Task ProductVersionReader_WhenStreamIsDisposedDuringRetainedRead_UsesTheCachedHandle()
    {
        var path = Path.Combine(
            AppContext.BaseDirectory,
            "WireguardSplitTunnel.TestProcess.dll");
        var enteredRead = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using var releaseRead =
            new ManualResetEventSlim();
        var reader = new WindowsExecutableProductVersionReader(
            _ => throw new InvalidOperationException(
                "The path overload must not be used."),
            _ =>
            {
                enteredRead.SetResult();
                if (!releaseRead.Wait(
                        TimeSpan.FromSeconds(5)))
                {
                    throw new TimeoutException();
                }

                return "0.1.9";
            });
        var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read);
        var read = Task.Run(
            () => reader.ReadProductVersion(stream));

        try
        {
            await enteredRead.Task.WaitAsync(
                TimeSpan.FromSeconds(5));
            stream.Dispose();
        }
        finally
        {
            releaseRead.Set();
        }

        (await read.WaitAsync(
                TimeSpan.FromSeconds(5)))
            .Should().Be("0.1.9");
    }

    [Fact]
    public void ProductVersionReader_WhenStreamPositionCannotBeRestored_FailsClosed()
    {
        var path = Path.Combine(
            AppContext.BaseDirectory,
            "WireguardSplitTunnel.TestProcess.dll");
        using var stream =
            new PositionRestoreFailureFileStream(path);
        var reader = new WindowsExecutableProductVersionReader(
            _ => throw new InvalidOperationException(
                "The path overload must not be used."),
            _ =>
            {
                stream.FailPositionWrites = true;
                return "0.1.9";
            });

        reader.ReadProductVersion(stream)
            .Should().BeNull();
    }

    [Fact]
    public void LocalPath_AcceptsOnlyFixedDrives()
    {
        WindowsLocalPath.TryGetCanonicalLocalDosPath("Z:\\release", _ => DriveType.Network, out var networkPath).Should().BeFalse();
        networkPath.Should().BeNull();
        WindowsLocalPath.TryGetCanonicalLocalDosPath("Z:\\release", _ => DriveType.Fixed, out var fixedPath).Should().BeTrue();
        fixedPath.Should().Be("Z:\\release");
    }

    [Fact]
    public void LocalPath_FailsClosedWhenDriveClassificationThrows()
    {
        WindowsLocalPath.TryGetCanonicalLocalDosPath("Z:\\release", _ => throw new UnauthorizedAccessException(), out _).Should().BeFalse();
        WindowsLocalPath.TryGetCanonicalLocalDosPath("Z:\\release", _ => throw new SecurityException(), out _).Should().BeFalse();
    }

    private sealed class PositionRestoreFailureFileStream(
        string path)
        : FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read)
    {
        public bool FailPositionWrites { get; set; }

        public override long Position
        {
            get => base.Position;
            set
            {
                if (FailPositionWrites)
                {
                    throw new ObjectDisposedException(
                        nameof(PositionRestoreFailureFileStream));
                }

                base.Position = value;
            }
        }
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "WireguardSplitTunnel.WindowsUpdate.Tests", Guid.NewGuid().ToString("N"));
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
}
