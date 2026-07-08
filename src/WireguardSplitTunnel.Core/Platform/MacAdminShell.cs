using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;

namespace WireguardSplitTunnel.Core.Platform;

[SupportedOSPlatform("macos")]
public static class MacAdminShell
{
    private const string AdminPathPrefix = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

    // No BOM: a UTF-8 BOM before "#!" defeats shebang detection and the script
    // falls back to /bin/sh with a bogus "bash: No such file or directory" on stderr.
    internal static readonly Encoding ScriptEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    public static async Task<MacShellResult> RunAsAdminAsync(
        string scriptBody,
        string promptReason,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(scriptBody))
        {
            return new MacShellResult(0, string.Empty, string.Empty);
        }

        // osascript expects the script body as a single AppleScript string with
        // embedded backslashes/quotes escaped. We bounce through a temp file so
        // very long batches don't bump into the AppleScript literal-length cap.
        var tempScript = Path.Combine(Path.GetTempPath(), $"wgst-{Guid.NewGuid():N}.sh");
        await WriteScriptFileAsync(tempScript, scriptBody, cancellationToken);

        try
        {
            var chmod = await RunAsync("/bin/chmod", $"700 \"{tempScript}\"", cancellationToken);
            if (chmod.ExitCode != 0)
            {
                return chmod;
            }

            var prompt = string.IsNullOrWhiteSpace(promptReason) ? "WireGuard split tunnel" : promptReason;
            var appleScript =
                $"do shell script \"{Escape(tempScript)}\" " +
                $"with prompt \"{Escape(prompt)}\" " +
                "with administrator privileges";

            return await RunAsync("/usr/bin/osascript", $"-e \"{Escape(appleScript)}\"", cancellationToken);
        }
        finally
        {
            try { File.Delete(tempScript); } catch { }
        }
    }

    public static async Task<MacShellResult> RunAsync(
        string fileName,
        string arguments,
        CancellationToken cancellationToken)
    {
        var info = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        using var process = Process.Start(info)
            ?? throw new InvalidOperationException($"Unable to start process: {fileName}");

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);

        return new MacShellResult(process.ExitCode, await stdoutTask, await stderrTask);
    }

    private static string Escape(string value) => value
        .Replace("\\", "\\\\", StringComparison.Ordinal)
        .Replace("\"", "\\\"", StringComparison.Ordinal);

    internal static Task WriteScriptFileAsync(string path, string scriptBody, CancellationToken cancellationToken)
        => File.WriteAllTextAsync(path, BuildScriptContent(scriptBody), ScriptEncoding, cancellationToken);

    internal static string BuildScriptContent(string scriptBody)
    {
        return $"#!{ResolvePreferredBashPath(File.Exists)}\n"
            + "set -e\n"
            + $"export PATH=\"{AdminPathPrefix}:$PATH\"\n"
            + scriptBody;
    }

    internal static string ResolvePreferredBashPath(Func<string, bool> fileExists)
    {
        foreach (var candidate in new[] { "/opt/homebrew/bin/bash", "/usr/local/bin/bash", "/bin/bash" })
        {
            if (fileExists(candidate))
            {
                return candidate;
            }
        }

        return "/bin/bash";
    }
}

// Pure string helper kept outside MacAdminShell so callers composing scripts
// on any platform (including unit tests) don't trip CA1416.
internal static class ShellQuoting
{
    internal static string Quote(string value) =>
        "\"" + value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("$", "\\$", StringComparison.Ordinal)
            .Replace("`", "\\`", StringComparison.Ordinal) + "\"";
}

public readonly record struct MacShellResult(int ExitCode, string StandardOutput, string StandardError)
{
    public string Combined =>
        string.IsNullOrEmpty(StandardError) ? StandardOutput : (StandardOutput + "\n" + StandardError).Trim();
}
