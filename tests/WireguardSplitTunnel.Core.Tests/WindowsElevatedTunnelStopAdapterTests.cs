using System.ComponentModel;
using System.Diagnostics;
using FluentAssertions;
using WireguardSplitTunnel.Core.Services;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class WindowsElevatedTunnelStopAdapterTests
{
    private const string ExePath = "C:\\Program Files\\WireGuard\\wireguard.exe";
    private const string SensitiveFailure =
        "C:\\secret\\customer.conf PrivateKey=secret stdout=raw stderr=raw "
        + "/uninstalltunnelservice SG C:\\Program Files\\WireGuard\\wireguard.exe";

    [Fact]
    public async Task StopAndUninstallAsync_StartsOneExactElevatedHiddenBatchForAllTargets()
    {
        var factory = new ControlledProcessFactory { ExitCode = 0 };
        var resolveCalls = 0;
        var adapter = new WindowsElevatedTunnelStopAdapter(
            factory,
            () =>
            {
                resolveCalls++;
                return ExePath;
            });

        await adapter.StopAndUninstallAsync(
            [
                WindowsTunnelServiceIdentity.FromTunnelName("TW"),
                WindowsTunnelServiceIdentity.FromServiceName("WireGuardTunnel$SG"),
                WindowsTunnelServiceIdentity.FromTunnelName("external")
            ],
            CancellationToken.None);

        resolveCalls.Should().Be(1);
        factory.StartCalls.Should().Be(1);
        factory.StartInfo.Should().NotBeNull();
        factory.StartInfo!.FileName.Should().Be(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"));
        factory.StartInfo.Arguments.Should().Be(
            "/c \""
            + "set \"__WST_CLOSE_DISCONNECT_FAILED=\""
            + " & \"C:\\Program Files\\WireGuard\\wireguard.exe\" /uninstalltunnelservice \"external\""
            + " || set \"__WST_CLOSE_DISCONNECT_FAILED=1\""
            + " & \"C:\\Program Files\\WireGuard\\wireguard.exe\" /uninstalltunnelservice \"SG\""
            + " || set \"__WST_CLOSE_DISCONNECT_FAILED=1\""
            + " & \"C:\\Program Files\\WireGuard\\wireguard.exe\" /uninstalltunnelservice \"TW\""
            + " || set \"__WST_CLOSE_DISCONNECT_FAILED=1\""
            + " & if defined __WST_CLOSE_DISCONNECT_FAILED exit /b 1"
            + "\"");
        factory.StartInfo.UseShellExecute.Should().BeTrue();
        factory.StartInfo.Verb.Should().Be("runas");
        factory.StartInfo.WindowStyle.Should().Be(ProcessWindowStyle.Hidden);
        factory.StartInfo.RedirectStandardOutput.Should().BeFalse();
        factory.StartInfo.RedirectStandardError.Should().BeFalse();
        factory.Process!.WaitToken.Should().Be(CancellationToken.None);
        factory.Process.DisposeCount.Should().Be(1);
    }

    [Fact]
    public async Task StopAndUninstallAsync_NoTargets_ReturnsWithoutResolvingOrStarting()
    {
        var factory = new ControlledProcessFactory();
        var resolveCalls = 0;
        var adapter = new WindowsElevatedTunnelStopAdapter(
            factory,
            () =>
            {
                resolveCalls++;
                return ExePath;
            });
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        var stop = adapter.StopAndUninstallAsync([], cancelled.Token);

        stop.IsCompletedSuccessfully.Should().BeTrue();
        await stop;
        resolveCalls.Should().Be(0);
        factory.StartCalls.Should().Be(0);
    }

    [Fact]
    public async Task StopAndUninstallAsync_NonzeroExit_ThrowsSanitizedStopFailure()
    {
        var factory = new ControlledProcessFactory { ExitCode = 23 };
        var adapter = new WindowsElevatedTunnelStopAdapter(factory, () => ExePath);

        var act = () => adapter.StopAndUninstallAsync(
            [WindowsTunnelServiceIdentity.FromTunnelName("SG")],
            CancellationToken.None);

        var exception = (await act.Should().ThrowAsync<WindowsTunnelStopException>()).Which;
        exception.Kind.Should().Be(CloseDisconnectFailureKind.Stop);
        exception.Message.Should().Be(
            "One or more WireGuard tunnel services could not be stopped; cleanup remains pending.");
        AssertSanitized(exception.Message);
        factory.Process!.DisposeCount.Should().Be(1);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task StopAndUninstallAsync_StartFailure_ThrowsSanitizedElevatedHelperStartFailure(
        bool useWin32Exception)
    {
        var factory = new ControlledProcessFactory
        {
            StartException = useWin32Exception
                ? new Win32Exception(5, SensitiveFailure)
                : new InvalidOperationException(SensitiveFailure)
        };
        var adapter = new WindowsElevatedTunnelStopAdapter(factory, () => ExePath);

        var act = () => adapter.StopAndUninstallAsync(
            [WindowsTunnelServiceIdentity.FromTunnelName("SG")],
            CancellationToken.None);

        var exception = (await act.Should().ThrowAsync<WindowsTunnelStopException>()).Which;
        exception.Kind.Should().Be(CloseDisconnectFailureKind.ElevatedHelperStart);
        exception.Message.Should().Be(
            "The elevated tunnel-stop helper could not be started; cleanup remains pending.");
        AssertSanitized(exception.Message);
    }

    [Fact]
    public async Task StopAndUninstallAsync_MissingExecutable_ThrowsHelperStartFailureWithoutStarting()
    {
        var factory = new ControlledProcessFactory();
        var adapter = new WindowsElevatedTunnelStopAdapter(factory, () => null);

        var act = () => adapter.StopAndUninstallAsync(
            [WindowsTunnelServiceIdentity.FromTunnelName("SG")],
            CancellationToken.None);

        var exception = (await act.Should().ThrowAsync<WindowsTunnelStopException>()).Which;
        exception.Kind.Should().Be(CloseDisconnectFailureKind.ElevatedHelperStart);
        exception.Message.Should().Be(
            "The elevated tunnel-stop helper could not be started; cleanup remains pending.");
        factory.StartCalls.Should().Be(0);
    }

    [Fact]
    public async Task StopAndUninstallAsync_WaitFailure_ThrowsSanitizedStopFailure()
    {
        var factory = new ControlledProcessFactory { AutoExit = false };
        var adapter = new WindowsElevatedTunnelStopAdapter(factory, () => ExePath);
        var stop = adapter.StopAndUninstallAsync(
            [WindowsTunnelServiceIdentity.FromTunnelName("SG")],
            CancellationToken.None);
        factory.Process!.FailWait(new IOException(SensitiveFailure));

        var act = () => stop;

        var exception = (await act.Should().ThrowAsync<WindowsTunnelStopException>()).Which;
        exception.Kind.Should().Be(CloseDisconnectFailureKind.Stop);
        exception.Message.Should().Be(
            "One or more WireGuard tunnel services could not be stopped; cleanup remains pending.");
        AssertSanitized(exception.Message);
        factory.Process.DisposeCount.Should().Be(1);
    }

    [Fact]
    public async Task StopAndUninstallAsync_WaitsNoncancelablyEvenWhenCallerTokenIsCancelled()
    {
        var factory = new ControlledProcessFactory { AutoExit = false };
        var adapter = new WindowsElevatedTunnelStopAdapter(factory, () => ExePath);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        var stop = adapter.StopAndUninstallAsync(
            [WindowsTunnelServiceIdentity.FromTunnelName("SG")],
            cancelled.Token);

        stop.IsCompleted.Should().BeFalse();
        factory.Process!.WaitToken.Should().Be(CancellationToken.None);
        factory.Process.Exit(0);
        await stop;
        factory.Process.DisposeCount.Should().Be(1);
    }

    private static void AssertSanitized(string message)
    {
        message.Should().NotBeNullOrWhiteSpace();
        message.Should().NotContain("C:\\secret");
        message.Should().NotContain("PrivateKey");
        message.Should().NotContain("stdout=raw");
        message.Should().NotContain("stderr=raw");
        message.Should().NotContain("wireguard.exe");
        message.Should().NotContain("/uninstalltunnelservice");
        message.Should().NotContain("SG");
    }

    private sealed class ControlledProcessFactory : IEnableTunnelProcessFactory
    {
        public Exception? StartException { get; init; }
        public int ExitCode { get; init; }
        public bool AutoExit { get; init; } = true;
        public int StartCalls { get; private set; }
        public ProcessStartInfo? StartInfo { get; private set; }
        public ControlledProcess? Process { get; private set; }

        public IEnableTunnelProcess Start(ProcessStartInfo startInfo)
        {
            StartCalls++;
            StartInfo = startInfo;
            if (StartException is not null) throw StartException;

            Process = new ControlledProcess();
            if (AutoExit) Process.Exit(ExitCode);
            return Process;
        }
    }

    private sealed class ControlledProcess : IEnableTunnelProcess
    {
        private readonly TaskCompletionSource exited =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int ExitCode { get; private set; }
        public CancellationToken WaitToken { get; private set; }
        public int DisposeCount { get; private set; }

        public Task WaitForExitAsync(CancellationToken cancellationToken)
        {
            WaitToken = cancellationToken;
            return exited.Task;
        }

        public void Exit(int exitCode)
        {
            ExitCode = exitCode;
            exited.TrySetResult();
        }

        public void FailWait(Exception exception) => exited.TrySetException(exception);

        public void Dispose() => DisposeCount++;
    }
}
