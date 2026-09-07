using System.Text.Json;

namespace WireguardSplitTunnel.Core.Updates;

public sealed class InstallStartupHandshake
{
    private const string TokenArgument = "--install-health-token";
    private const string PathArgument = "--install-health-path";

    public InstallStartupHandshake(Guid token, string healthPath)
    {
        if (token == Guid.Empty)
        {
            throw new ArgumentException("Install health token cannot be empty.", nameof(token));
        }

        Token = token;
        HealthPath = Path.GetFullPath(
            healthPath ?? throw new ArgumentNullException(nameof(healthPath)));
    }

    public Guid Token { get; }
    public string HealthPath { get; }
    public string CommitEventName =>
        $"Local\\WireguardSplitTunnel.InstallCommit.{Token:N}";

    public static bool TryParse(
        IReadOnlyList<string> arguments,
        out InstallStartupHandshake? handshake)
    {
        handshake = null;
        string? tokenText = null;
        string? path = null;

        for (var index = 0; index < arguments.Count; index++)
        {
            var argument = arguments[index];
            if (argument is not (TokenArgument or PathArgument))
            {
                continue;
            }

            if (index + 1 >= arguments.Count)
            {
                return false;
            }

            var value = arguments[++index];
            if (argument == TokenArgument)
            {
                if (tokenText is not null)
                {
                    return false;
                }
                tokenText = value;
            }
            else
            {
                if (path is not null)
                {
                    return false;
                }
                path = value;
            }
        }

        if (tokenText is null
            || path is null
            || tokenText != tokenText.ToLowerInvariant()
            || !Guid.TryParseExact(tokenText, "N", out var token)
            || token == Guid.Empty)
        {
            return false;
        }

        try
        {
            var expectedPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "WireguardSplitTunnel",
                "install-health",
                $"{token:N}.json");
            if (!string.Equals(
                    Path.GetFullPath(path),
                    Path.GetFullPath(expectedPath),
                    StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            handshake = new InstallStartupHandshake(token, path);
            return true;
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or IOException
                or NotSupportedException)
        {
            return false;
        }
    }

    public void WriteReady(string version, int processId, string executablePath)
    {
        if (string.IsNullOrWhiteSpace(version)
            || processId <= 0
            || string.IsNullOrWhiteSpace(executablePath))
        {
            throw new ArgumentException("Install startup health data is incomplete.");
        }

        var parent = Path.GetDirectoryName(HealthPath)
            ?? throw new InvalidOperationException("Install health path has no parent.");
        Directory.CreateDirectory(parent);
        var temporary = HealthPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var payload = JsonSerializer.Serialize(new
            {
                token = Token.ToString("N"),
                version,
                processId,
                executablePath = Path.GetFullPath(executablePath),
                settingsLoaded = true,
                mainWindowInitialized = true,
                readyAtUtc = DateTimeOffset.UtcNow
            });
            File.WriteAllText(temporary, payload);
            File.Move(temporary, HealthPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }
}
