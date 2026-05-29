using System.Diagnostics;
using System.Text.Json;

namespace WireguardSplitTunnel.Core.Services;

public interface IDnsCacheReader
{
    Task<IReadOnlyCollection<DnsCacheEntry>> ReadAsync(CancellationToken cancellationToken);
}

public sealed class NoOpDnsCacheReader : IDnsCacheReader
{
    public Task<IReadOnlyCollection<DnsCacheEntry>> ReadAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyCollection<DnsCacheEntry>>([]);
}

public sealed class WindowsDnsCacheReader : IDnsCacheReader
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };
    private const string Script = """
$ErrorActionPreference = 'Stop'
$items = @(Get-DnsClientCache |
    Where-Object { ($_.Type -eq 1 -or $_.Type -eq 'A') -and $_.Data -match '^\d{1,3}(\.\d{1,3}){3}$' } |
    ForEach-Object {
        $hostName = if ($_.Entry) { $_.Entry } elseif ($_.Name) { $_.Name } else { $_.RecordName }
        [pscustomobject]@{ HostName = $hostName; IpAddress = $_.Data }
    })
$items | ConvertTo-Json -Compress
""";

    public async Task<IReadOnlyCollection<DnsCacheEntry>> ReadAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        using var process = new Process();
        process.StartInfo.FileName = "powershell.exe";
        process.StartInfo.UseShellExecute = false;
        process.StartInfo.CreateNoWindow = true;
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.RedirectStandardError = true;
        process.StartInfo.ArgumentList.Add("-NoProfile");
        process.StartInfo.ArgumentList.Add("-ExecutionPolicy");
        process.StartInfo.ArgumentList.Add("Bypass");
        process.StartInfo.ArgumentList.Add("-Command");
        process.StartInfo.ArgumentList.Add(Script);

        process.Start();
        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        var stdout = await stdoutTask;
        var stderr = await stderrTask;

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"Get-DnsClientCache failed with exit code {process.ExitCode}: {stderr.Trim()}");
        }

        if (string.IsNullOrWhiteSpace(stdout))
        {
            return [];
        }

        return ParseRows(stdout);
    }

    private static IReadOnlyCollection<DnsCacheEntry> ParseRows(string json)
    {
        try
        {
            var rows = JsonSerializer.Deserialize<List<DnsCacheJsonRow>>(json, JsonOptions) ?? [];
            return rows
                .Where(row => !string.IsNullOrWhiteSpace(row.HostName) && !string.IsNullOrWhiteSpace(row.IpAddress))
                .Select(row => new DnsCacheEntry(row.HostName!, row.IpAddress!))
                .ToArray();
        }
        catch (JsonException)
        {
            var row = JsonSerializer.Deserialize<DnsCacheJsonRow>(json, JsonOptions);
            if (string.IsNullOrWhiteSpace(row?.HostName) || string.IsNullOrWhiteSpace(row.IpAddress))
            {
                return [];
            }

            return [new DnsCacheEntry(row.HostName, row.IpAddress)];
        }
    }

    private sealed record DnsCacheJsonRow(string? HostName, string? IpAddress);
}
