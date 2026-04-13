using System.Text.Json;
using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public sealed class StateStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly string filePath;

    public StateStore(string filePath)
    {
        this.filePath = filePath;
    }

    public AppState Load()
    {
        if (!File.Exists(filePath))
        {
            return CreateDefaultState();
        }

        var json = File.ReadAllText(filePath);
        if (string.IsNullOrWhiteSpace(json))
        {
            return CreateDefaultState();
        }

        try
        {
            return NormalizeState(JsonSerializer.Deserialize<AppState>(json, JsonOptions));
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"State file '{filePath}' contains invalid JSON.", ex);
        }
    }

    public void Save(AppState state)
    {
        var directory = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var tempFilePath = Path.Combine(
            directory ?? string.Empty,
            $".{Path.GetFileName(filePath)}.{Guid.NewGuid():N}.tmp");

        var json = JsonSerializer.Serialize(NormalizeState(state), JsonOptions);
        File.WriteAllText(tempFilePath, json);

        if (File.Exists(filePath))
        {
            File.Replace(tempFilePath, filePath, destinationBackupFileName: null);
        }
        else
        {
            File.Move(tempFilePath, filePath);
        }
    }

    private static AppState NormalizeState(AppState? state)
    {
        if (state is null)
        {
            return CreateDefaultState();
        }

        var domainMode = Enum.IsDefined(state.DomainGlobalDefaultMode)
            ? state.DomainGlobalDefaultMode
            : DomainRouteMode.BypassWireGuard;

        var softwareMode = Enum.IsDefined(state.SoftwareGlobalDefaultMode)
            ? state.SoftwareGlobalDefaultMode
            : DomainRouteMode.BypassWireGuard;

        return state with
        {
            DomainRules = state.DomainRules ?? [],
            LastKnownResolvedIps = state.LastKnownResolvedIps ?? new Dictionary<string, List<string>>(),
            ManagedRouteSnapshot = state.ManagedRouteSnapshot ?? [],
            SoftwareRules = state.SoftwareRules ?? [],
            DomainGlobalDefaultMode = domainMode,
            SoftwareGlobalDefaultMode = softwareMode,
            RestoreNormalRoutingOnExit = state.RestoreNormalRoutingOnExit
        };
    }

    private static AppState CreateDefaultState() =>
        new([], new Dictionary<string, List<string>>(), [], null, false, [], DomainRouteMode.BypassWireGuard, DomainRouteMode.BypassWireGuard, false);
}

