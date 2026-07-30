using WireguardSplitTunnel.Core.Services;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.App.Services;

internal sealed class WpfApplicationCloseActions
    : IApplicationCloseActions
{
    private readonly SemaphoreSlim softwareApplySemaphore;
    private readonly SemaphoreSlim renewSemaphore;
    private readonly Action _savePrimaryState;

    internal WpfApplicationCloseActions(
        SemaphoreSlim softwareApplySemaphore,
        SemaphoreSlim renewSemaphore,
        Action savePrimaryState)
    {
        this.softwareApplySemaphore =
            softwareApplySemaphore
            ?? throw new ArgumentNullException(
                nameof(softwareApplySemaphore));
        this.renewSemaphore = renewSemaphore
            ?? throw new ArgumentNullException(
                nameof(renewSemaphore));
        _savePrimaryState = savePrimaryState
            ?? throw new ArgumentNullException(
                nameof(savePrimaryState));
    }

    public async Task RunRoutingExclusiveAsync(
        Func<CancellationToken, Task> restoreAsync,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(restoreAsync);

        await softwareApplySemaphore.WaitAsync(
            cancellationToken);
        try
        {
            await DomainRouteOperationSerializer.RunAsync(
                renewSemaphore,
                () => restoreAsync(cancellationToken),
                cancellationToken);
        }
        finally
        {
            softwareApplySemaphore.Release();
        }
    }

    public void SavePrimaryState() =>
        _savePrimaryState();
}

internal sealed class NoOpUpdateCloseParticipant
    : IUpdateCloseParticipant
{
    internal static NoOpUpdateCloseParticipant Instance
    {
        get;
    } = new();

    private NoOpUpdateCloseParticipant()
    {
    }

    public Task StopForCloseAsync(
        CancellationToken cancellationToken) =>
        Task.CompletedTask;

    public Task<UpdateCloseAuthorizationResult>
        TryAuthorizeAndLaunchAsync(
            UpdateCloseAuthorizationContext context,
            CancellationToken cancellationToken) =>
        Task.FromResult(
            UpdateCloseAuthorizationResult
                .NoProtectedTransaction());
}
