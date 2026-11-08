namespace WireguardSplitTunnel.Core.ConfigCheck;

public static class ConfigCheckWorkflow
{
    /// <summary>Tests the original server and, when necessary, attempts a bounded repair.</summary>
    /// <remarks>
    /// <para>Persistent commits are atomic and non-cancelable: after <see cref="IConfigCheckAdapter.CommitAsync"/> starts, the adapter must finish the save before returning rather than abandoning it because of cancellation.</para>
    /// <para>If the main operation and restoration both fail, an <see cref="AggregateException"/> preserves the primary failure first and the restore failure second. A sole failure propagates unchanged.</para>
    /// </remarks>
    public static async Task<ConfigCheckResult> RunAsync(
        CheckedConfig config,
        IConfigCheckAdapter adapter,
        CancellationToken token,
        Func<CancellationToken, Task>? restoreRoutesAsync = null,
        string? derivedConfigPath = null,
        Func<ConfigCheckRestoreContext, CancellationToken, Task>? reconcileDerivedConfigAsync = null)
    {
        var original = config.OriginalServer;
        var candidates = await adapter.GetCandidatesAsync(config.Country, 3, token).ConfigureAwait(false);
        var session = await adapter.BeginAsync(config, token, derivedConfigPath).ConfigureAwait(false);
        Exception? primaryFailure = null;
        try
        {
            await adapter.StopOriginalAsync(session, token).ConfigureAwait(false);
            var probe = await adapter.TestAsync(session, config, original, token).ConfigureAwait(false);
            if (probe.Success && probe.ObservedCountry == config.Country)
                return new(ConfigCheckStatus.Healthy, config.Path, config.Endpoint, "HandshakeAndHttpsVerified") { ObservedCountry = probe.ObservedCountry };

            var reason = probe.Success && probe.ObservedCountry != config.Country ? "ExitCountryMismatch" : probe.Reason;
            foreach (var candidate in candidates.Take(3))
            {
                if (candidate.Country != config.Country || !CheckedConfig.IsValidKey(candidate.PublicKey)) continue;
                if (candidate.HostName.Equals(original.HostName, StringComparison.OrdinalIgnoreCase) && candidate.PublicKey == original.PublicKey) continue;
                probe = await adapter.TestAsync(session, config, candidate, token).ConfigureAwait(false);
                reason = probe.Success && probe.ObservedCountry != config.Country ? "ExitCountryMismatch" : probe.Reason;
                if (!probe.Success || probe.ObservedCountry != config.Country) continue;
                await adapter.CommitAsync(session, config, candidate, CancellationToken.None).ConfigureAwait(false);
                return new(ConfigCheckStatus.Repaired, config.Path, candidate.HostName + ":" + config.Port, "ReplacementVerifiedAndSaved") { ObservedCountry = probe.ObservedCountry };
            }
            return new(ConfigCheckStatus.Unrepaired, config.Path, config.Endpoint, reason) { ObservedCountry = probe.ObservedCountry };
        }
        catch (Exception exception)
        {
            primaryFailure = exception;
            throw;
        }
        finally
        {
            try
            {
                // Cancellation must never skip network restoration. Renew routes as soon
                // as the selected original service is verified, before later recovery fails.
                var routesRestored = false;
                var selectedServiceName = "WireGuardTunnel$" +
                    global::WireguardSplitTunnel.Core.Services.WireguardConfigCatalog.GetTunnelName(config.Path);
                Func<ConfigCheckRecoveredService, CancellationToken, Task>? serviceRestoredAsync = null;
                if (restoreRoutesAsync is not null)
                {
                    serviceRestoredAsync = async (service, _) =>
                    {
                        if (routesRestored || !PathsEqual(service.SourcePath, config.Path) ||
                            !string.Equals(service.ServiceName, selectedServiceName, StringComparison.OrdinalIgnoreCase)) return;
                        await restoreRoutesAsync(CancellationToken.None).ConfigureAwait(false);
                        routesRestored = true;
                    };
                }
                await adapter.RestoreAsync(
                    session,
                    CancellationToken.None,
                    reconcileDerivedConfigAsync,
                    serviceRestoredAsync).ConfigureAwait(false);
            }
            catch (Exception restoreFailure)
            {
                if (primaryFailure is not null)
                    throw new AggregateException(primaryFailure, restoreFailure);
                throw;
            }
        }
    }

    private static bool PathsEqual(string left, string right) =>
        string.Equals(Path.GetFullPath(left), Path.GetFullPath(right),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
}
