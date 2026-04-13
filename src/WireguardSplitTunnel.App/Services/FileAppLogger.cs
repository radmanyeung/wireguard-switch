using System.IO;
using System.Text;

namespace WireguardSplitTunnel.App.Services;

public interface IAppLogger
{
    void Info(string message);
    void Error(string message, Exception? ex = null);
    string LogPath { get; }
}

public sealed class FileAppLogger : IAppLogger
{
    private static readonly object Sync = new();
    private readonly List<string> targetPaths;

    public string LogPath { get; }

    public FileAppLogger(params string[] logPaths)
    {
        targetPaths = logPaths
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(path => path.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (targetPaths.Count == 0)
        {
            throw new ArgumentException("At least one log path is required.", nameof(logPaths));
        }

        LogPath = targetPaths[0];

        foreach (var path in targetPaths)
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(dir))
            {
                Directory.CreateDirectory(dir);
            }
        }
    }

    public void Info(string message) => Write("INFO", message, null);

    public void Error(string message, Exception? ex = null) => Write("ERROR", message, ex);

    private void Write(string level, string message, Exception? ex)
    {
        var ts = DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss zzz");
        var sb = new StringBuilder();
        sb.Append('[').Append(ts).Append("] [").Append(level).Append("] ").AppendLine(message);

        if (ex is not null)
        {
            sb.AppendLine(ex.ToString());
        }

        var line = sb.ToString();

        lock (Sync)
        {
            foreach (var path in targetPaths)
            {
                try
                {
                    File.AppendAllText(path, line, Encoding.UTF8);
                }
                catch
                {
                    // Never crash app because of logging failure.
                }
            }
        }
    }
}
