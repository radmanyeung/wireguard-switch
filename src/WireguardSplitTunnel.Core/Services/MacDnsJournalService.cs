using System.Text;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Platform;

namespace WireguardSplitTunnel.Core.Services;

/// <summary>
/// Builds and reads the resolver-only journal written by the elevated raw
/// tunnel startup transaction immediately before wg-quick changes DNS.
/// </summary>
public static class MacDnsJournalService
{
    private const string Header = "WGST_DNS_JOURNAL_V1";
    private const string FilePrefix = ".wgst-dns-journal-";
    private const string FileSuffix = ".v1";
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static string CreateJournalPath(string applicationDataDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationDataDirectory);
        Directory.CreateDirectory(applicationDataDirectory);
        return Path.Combine(
            Path.GetFullPath(applicationDataDirectory),
            $"{FilePrefix}{Guid.NewGuid():N}{FileSuffix}");
    }

    public static string BuildCaptureScript(string journalPath)
    {
        ValidateJournalPath(journalPath);
        var directory = Path.GetDirectoryName(journalPath)
            ?? throw new ArgumentException("DNS journal path must have a parent directory.", nameof(journalPath));
        var quotedPath = ShellQuoting.Quote(journalPath);
        var quotedDirectory = ShellQuoting.Quote(directory);
        var quotedTemplate = ShellQuoting.Quote(journalPath + ".tmp.XXXXXX");
        var script = new StringBuilder();

        script.AppendLine("umask 077");
        script.AppendLine($"journal_tmp=$(/usr/bin/mktemp {quotedTemplate})");
        script.AppendLine("trap '/bin/rm -f \"$journal_tmp\"' EXIT");
        script.AppendLine("/bin/chmod 0600 \"$journal_tmp\"");
        script.AppendLine($"/usr/bin/printf '%s\\n' '{Header}' > \"$journal_tmp\"");
        script.AppendLine("while IFS= read -r journal_service; do");
        script.AppendLine("  journal_service=$(/usr/bin/printf '%s' \"$journal_service\" | /usr/bin/sed 's/^[*[:space:]]*//; s/[[:space:]]*$//')");
        script.AppendLine("  [[ -n \"$journal_service\" ]] || continue");
        script.AppendLine("  journal_dns=$(/usr/sbin/networksetup -getdnsservers \"$journal_service\")");
        script.AppendLine("  journal_search=$(/usr/sbin/networksetup -getsearchdomains \"$journal_service\")");
        script.AppendLine("  journal_service_b64=$(/usr/bin/printf '%s' \"$journal_service\" | /usr/bin/base64 | /usr/bin/tr -d '\\n')");
        script.AppendLine("  journal_dns_b64=$(/usr/bin/printf '%s' \"$journal_dns\" | /usr/bin/base64 | /usr/bin/tr -d '\\n')");
        script.AppendLine("  journal_search_b64=$(/usr/bin/printf '%s' \"$journal_search\" | /usr/bin/base64 | /usr/bin/tr -d '\\n')");
        script.AppendLine("  /usr/bin/printf '%s\\t%s\\t%s\\n' \"$journal_service_b64\" \"$journal_dns_b64\" \"$journal_search_b64\" >> \"$journal_tmp\"");
        script.AppendLine("done < <(/usr/sbin/networksetup -listallnetworkservices | /usr/bin/tail -n +2)");
        script.AppendLine($"journal_uid=$(/usr/bin/stat -f '%u' {quotedDirectory})");
        script.AppendLine($"journal_gid=$(/usr/bin/stat -f '%g' {quotedDirectory})");
        script.AppendLine("/usr/sbin/chown \"$journal_uid:$journal_gid\" \"$journal_tmp\"");
        script.AppendLine("/bin/chmod 0600 \"$journal_tmp\"");
        script.AppendLine($"/bin/mv -f \"$journal_tmp\" {quotedPath}");
        script.AppendLine("/bin/sync");
        script.AppendLine("trap - EXIT");
        return script.ToString();
    }

    public static IReadOnlyList<MacDnsServiceSnapshot> ParseJournal(string journalContent)
    {
        ArgumentNullException.ThrowIfNull(journalContent);
        var lines = journalContent
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Split('\n');
        if (lines.Length == 0 || !string.Equals(lines[0], Header, StringComparison.Ordinal))
        {
            throw new InvalidDataException("DNS journal header is invalid.");
        }

        var snapshots = new List<MacDnsServiceSnapshot>();
        var serviceNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1).Where(line => line.Length > 0))
        {
            var fields = line.Split('\t');
            if (fields.Length != 3)
            {
                throw new InvalidDataException("DNS journal row is invalid.");
            }

            try
            {
                var service = Decode(fields[0]);
                var dnsOutput = Decode(fields[1]);
                var searchOutput = Decode(fields[2]);
                if (string.IsNullOrWhiteSpace(service)
                    || service.Any(char.IsControl)
                    || !serviceNames.Add(service))
                {
                    throw new InvalidDataException("DNS journal service is invalid.");
                }

                snapshots.Add(new MacDnsServiceSnapshot(
                    service,
                    MacDnsRepairService.ParseDnsServers(dnsOutput).ToList(),
                    MacDnsRepairService.ParseSearchDomains(searchOutput).ToList()));
            }
            catch (Exception ex) when (ex is FormatException or DecoderFallbackException)
            {
                throw new InvalidDataException("DNS journal encoding is invalid.", ex);
            }
        }

        return snapshots;
    }

    public static MacRawTunnelDnsCleanupDebt? RecoverDebt(
        MacRawTunnelDnsCleanupDebt debt,
        string? journalContent,
        MacTunnelMappingPresence mappingPresence)
    {
        ArgumentNullException.ThrowIfNull(debt);
        if (journalContent is not null)
        {
            var services = ParseJournal(journalContent).ToList();
            return services.Count == 0 && mappingPresence == MacTunnelMappingPresence.Absent
                ? null
                : debt with { Services = services };
        }

        if (debt.Services.Count > 0 || mappingPresence != MacTunnelMappingPresence.Absent)
        {
            return debt;
        }

        // The script makes the journal durable before wg-quick up. If neither
        // journal nor exact mapping exists, the privileged mutation did not run.
        return null;
    }

    public static bool TryDeleteJournal(string? journalPath)
    {
        if (string.IsNullOrWhiteSpace(journalPath))
        {
            return false;
        }

        try
        {
            ValidateJournalPath(journalPath);
            File.Delete(journalPath);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string Decode(string value) =>
        StrictUtf8.GetString(Convert.FromBase64String(value));

    private static void ValidateJournalPath(string journalPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(journalPath);
        if (!Path.IsPathFullyQualified(journalPath))
        {
            throw new ArgumentException("DNS journal path must be absolute.", nameof(journalPath));
        }

        var fileName = Path.GetFileName(journalPath);
        var id = fileName.StartsWith(FilePrefix, StringComparison.Ordinal)
                 && fileName.EndsWith(FileSuffix, StringComparison.Ordinal)
            ? fileName[FilePrefix.Length..^FileSuffix.Length]
            : string.Empty;
        if (!Guid.TryParseExact(id, "N", out _))
        {
            throw new ArgumentException("DNS journal path is not app-owned.", nameof(journalPath));
        }
    }
}
