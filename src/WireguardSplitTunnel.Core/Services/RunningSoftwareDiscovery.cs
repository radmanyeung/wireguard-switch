using System.Diagnostics;
using System.Runtime.Versioning;

namespace WireguardSplitTunnel.Core.Services;

public sealed record RunningSoftwareCandidate(string ProcessName, string ExecutablePath);

public sealed record RunningSoftwareRawCandidate(string ProcessName, string? ExecutablePath);

public interface IRunningSoftwareDiscovery
{
    IReadOnlyList<RunningSoftwareCandidate> DiscoverRunningSoftware();
}

public sealed class SystemRunningSoftwareDiscovery : IRunningSoftwareDiscovery
{
    public IReadOnlyList<RunningSoftwareCandidate> DiscoverRunningSoftware()
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        var rawCandidates = Process.GetProcesses()
            .Select(TryReadProcess)
            .Where(candidate => candidate is not null)
            .Select(candidate => candidate!)
            .ToArray();

        return RunningSoftwareDiscovery.NormalizeCandidates(rawCandidates);
    }

    [SupportedOSPlatform("windows")]
    private static RunningSoftwareRawCandidate? TryReadProcess(Process process)
    {
        using (process)
        {
            try
            {
                return new RunningSoftwareRawCandidate(process.ProcessName, process.MainModule?.FileName);
            }
            catch
            {
                return null;
            }
        }
    }
}

public static class RunningSoftwareDiscovery
{
    public static IReadOnlyList<RunningSoftwareCandidate> NormalizeCandidates(
        IEnumerable<RunningSoftwareRawCandidate> rawCandidates)
    {
        return rawCandidates
            .Select(NormalizeCandidate)
            .Where(candidate => candidate is not null)
            .Select(candidate => candidate!)
            .GroupBy(candidate => candidate.ExecutablePath, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderBy(candidate => candidate.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(candidate => candidate.ExecutablePath, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static RunningSoftwareCandidate? NormalizeCandidate(RunningSoftwareRawCandidate raw)
    {
        if (string.IsNullOrWhiteSpace(raw.ProcessName) || string.IsNullOrWhiteSpace(raw.ExecutablePath))
        {
            return null;
        }

        var executablePath = raw.ExecutablePath.Trim();
        if (!executablePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || !File.Exists(executablePath))
        {
            return null;
        }

        var processName = Path.GetFileName(executablePath);
        if (string.IsNullOrWhiteSpace(processName))
        {
            return null;
        }

        return new RunningSoftwareCandidate(processName.ToLowerInvariant(), executablePath);
    }
}
