using System.Text.RegularExpressions;

namespace WireguardSplitTunnel.Core.Services;

public static class DomainValidator
{
    private static readonly Regex DomainPattern = new(
        @"^(\*\.)?([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static bool IsValidDomain(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && !value.Contains("://", StringComparison.Ordinal)
        && DomainPattern.IsMatch(value);
}

