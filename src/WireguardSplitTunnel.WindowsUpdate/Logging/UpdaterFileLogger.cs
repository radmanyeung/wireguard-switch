using System.Text;
using WireguardSplitTunnel.WindowsUpdate.Staging;

namespace WireguardSplitTunnel.WindowsUpdate.Logging;

internal interface IUpdaterEventLogger
{
    bool TryAppend(
        string eventCode,
        string? detailCode = null,
        string? version = null);
}

internal interface IUpdaterLogAppender
{
    bool TryAppend(string path, byte[] bytes);
}

internal sealed class PinnedUpdaterLogAppender
    : IUpdaterLogAppender
{
    private readonly WindowsPinnedLocalDirectoryService
        _directories = new();

    public bool TryAppend(string path, byte[] bytes)
    {
        var directory = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(directory))
        {
            return false;
        }

        var root = Path.GetPathRoot(directory);
        if (string.IsNullOrEmpty(root)
            || root.StartsWith(
                @"\\",
                StringComparison.Ordinal))
        {
            return false;
        }

        var segments = directory[root.Length..].Split(
            [
                Path.DirectorySeparatorChar,
                Path.AltDirectorySeparatorChar
            ],
            StringSplitOptions.RemoveEmptyEntries);
        if (_directories.EnsureDirectory(root, segments)
            != PinnedDirectoryStatus.Opened)
        {
            return false;
        }

        var opened = _directories.OpenExisting(directory);
        using var lease = opened.Lease;
        if (opened.Status != PinnedDirectoryStatus.Opened
            || lease is null)
        {
            return false;
        }

        return _directories.TryAppendFile(
            lease,
            Path.GetFileName(path),
            path,
            bytes);
    }
}

public sealed class UpdaterFileLogger : IUpdaterEventLogger
{
    private const int MaximumFieldLength = 64;
    private static readonly Encoding Utf8WithoutBom =
        new UTF8Encoding(
            encoderShouldEmitUTF8Identifier: false,
            throwOnInvalidBytes: true);

    private readonly object _gate = new();
    private readonly string _path;
    private readonly TimeProvider _timeProvider;
    private readonly IUpdaterLogAppender _appender;

    public UpdaterFileLogger()
        : this(GetProductionPath(), TimeProvider.System)
    {
    }

    internal UpdaterFileLogger(
        string path,
        TimeProvider timeProvider)
        : this(
            path,
            timeProvider,
            new PinnedUpdaterLogAppender())
    {
    }

    internal UpdaterFileLogger(
        string path,
        TimeProvider timeProvider,
        IUpdaterLogAppender appender)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
        _timeProvider = timeProvider
            ?? throw new ArgumentNullException(nameof(timeProvider));
        _appender = appender
            ?? throw new ArgumentNullException(nameof(appender));
    }

    public bool TryAppend(
        string eventCode,
        string? detailCode = null,
        string? version = null)
    {
        var safeEvent = Sanitize(eventCode);
        var safeDetail = detailCode is null
            ? null
            : Sanitize(detailCode);
        var safeVersion = version is null
            ? null
            : SanitizeVersion(version);
        var line = string.Concat(
            _timeProvider.GetUtcNow().ToString("O"),
            " event=",
            safeEvent,
            safeDetail is null
                ? string.Empty
                : " detail=" + safeDetail,
            safeVersion is null
                ? string.Empty
                : " version=" + safeVersion,
            Environment.NewLine);
        var bytes = Utf8WithoutBom.GetBytes(line);

        lock (_gate)
        {
            try
            {
                return _appender.TryAppend(_path, bytes);
            }
            catch (Exception exception) when (
                exception is IOException
                    or UnauthorizedAccessException
                    or ArgumentException
                    or NotSupportedException
                    or System.Security.SecurityException)
            {
                return false;
            }
        }
    }

    private static string GetProductionPath()
    {
        var localAppData = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(
            localAppData,
            "WireguardSplitTunnel",
            "logs",
            "updater.log");
    }

    private static string Sanitize(string? value)
    {
        if (string.IsNullOrEmpty(value)
            || value.Length > MaximumFieldLength
            || value.Any(character =>
                character is not (
                    >= 'a' and <= 'z'
                    or >= '0' and <= '9'
                    or '_')))
        {
            return "invalid";
        }

        return value;
    }

    private static string SanitizeVersion(string value)
    {
        if (value.Length is < 5 or > MaximumFieldLength
            || value[0] is < '0' or > '9'
            || value[^1] is < '0' or > '9'
            || value.Any(character =>
                character is not (
                    >= '0' and <= '9'
                    or '.'
                    or '-'
                    or '+'
                    or >= 'a' and <= 'z')))
        {
            return "invalid";
        }

        return value;
    }
}
