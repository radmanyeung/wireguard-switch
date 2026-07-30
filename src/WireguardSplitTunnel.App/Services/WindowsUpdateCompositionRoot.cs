using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate;
using WireguardSplitTunnel.WindowsUpdate.Staging;

namespace WireguardSplitTunnel.App.Services;

internal sealed record StampedWindowsUpdateStatus(
    WindowsUpdateStatus Status,
    LatestOperationStatusGate.Stamp GenerationStamp);

internal sealed class WindowsUpdateCompositionRoot
    : IApplicationUpdateStartupActions,
      IUpdateCloseParticipant,
      IDisposable
{
    private readonly WindowsUpdateRuntime runtime;
    private readonly LatestOperationSerializer
        automaticPreferenceOperations = new();
    private readonly LatestOperationStatusGate
        automaticStatusGate;
    private bool automaticEnabled;
    private bool lastAppliedAutomaticEnabled;
    private bool disposed;

    private WindowsUpdateCompositionRoot(
        WindowsUpdateRuntime runtime,
        bool isPostInstallSelfTest)
    {
        this.runtime = runtime;
        automaticStatusGate =
            new LatestOperationStatusGate(
                automaticPreferenceOperations);
        IsPostInstallSelfTest = isPostInstallSelfTest;
        runtime.StatusChanged += OnRuntimeStatusChanged;
    }

    internal event EventHandler<StampedWindowsUpdateStatus>?
        StatusChanged;

    internal bool IsPostInstallSelfTest { get; }

    internal bool LatestRuntimeStatusIsBusy =>
        automaticStatusGate.LatestStatusIsBusy;

    internal static WindowsUpdateCompositionRoot
        CreateProduction(bool isPostInstallSelfTest) =>
        new(
            WindowsUpdateRuntime.CreateProduction(
                new WindowsUpdateProductionOptions(
                    isPostInstallSelfTest)),
            isPostInstallSelfTest);

    internal void ConfigureAutomaticEnabled(bool enabled)
    {
        Volatile.Write(ref automaticEnabled, enabled);
        Volatile.Write(
            ref lastAppliedAutomaticEnabled,
            enabled);
    }

    internal Task CheckNowAsync(
        CancellationToken cancellationToken) =>
        IsPostInstallSelfTest
            ? Task.CompletedTask
            : runtime.CheckNowAsync(cancellationToken);

    internal LatestOperationSerializer.Operation
        BeginAutomaticEnabledChange() =>
        automaticPreferenceOperations.Begin();

    internal async Task SetAutomaticEnabledAsync(
        bool enabled,
        LatestOperationSerializer.Operation operation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);
        if (IsPostInstallSelfTest)
        {
            return;
        }

        try
        {
            await operation.RunSerializedAsync(
                    async token =>
                    {
                        automaticStatusGate.SetSource(operation);
                        await runtime
                            .SetAutomaticEnabledAsync(
                                enabled,
                                token)
                            .ConfigureAwait(false);
                        Volatile.Write(
                            ref lastAppliedAutomaticEnabled,
                            enabled);
                    },
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            if (operation.IsLatest)
            {
                Volatile.Write(
                    ref automaticEnabled,
                    Volatile.Read(
                        ref lastAppliedAutomaticEnabled));
            }

            throw;
        }

        if (operation.IsLatest)
        {
            Volatile.Write(ref automaticEnabled, enabled);
        }
    }

    public Task<UpdateStartupHealthResult>
        MarkMatchingTransactionHealthyAsync(
            UpdateStartupHealthContext context,
            CancellationToken cancellationToken) =>
        IsPostInstallSelfTest
            ? Task.FromResult(
                UpdateStartupHealthResult
                    .NoMatchingTransaction())
            : runtime.MarkMatchingTransactionHealthyAsync(
                context,
                cancellationToken);

    public Task StartUpdateChecksAsync(
        CancellationToken cancellationToken) =>
        IsPostInstallSelfTest
            ? Task.CompletedTask
            : runtime.StartAsync(
                Volatile.Read(ref automaticEnabled),
                cancellationToken);

    public Task StopForCloseAsync(
        CancellationToken cancellationToken) =>
        runtime.StopForCloseAsync(cancellationToken);

    public Task<UpdateCloseAuthorizationResult>
        TryAuthorizeAndLaunchAsync(
            UpdateCloseAuthorizationContext context,
            CancellationToken cancellationToken) =>
        IsPostInstallSelfTest
            ? Task.FromResult(
                UpdateCloseAuthorizationResult
                    .NoProtectedTransaction())
            : runtime.TryAuthorizeAndLaunchAsync(
                context,
                cancellationToken);

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        runtime.StatusChanged -= OnRuntimeStatusChanged;
        runtime.Dispose();
    }

    private void OnRuntimeStatusChanged(
        object? sender,
        WindowsUpdateStatus status)
        => StatusChanged?.Invoke(
            this,
            new StampedWindowsUpdateStatus(
                status,
                automaticStatusGate.CaptureStatus(status.IsBusy)));
}
