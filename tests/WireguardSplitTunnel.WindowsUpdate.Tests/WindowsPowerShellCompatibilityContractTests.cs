using FluentAssertions;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

/// <summary>
/// The bundled installer runs under Windows PowerShell 5.1 on stock
/// Windows machines, while CI executes script tests under PowerShell 7.
/// Guard against syntax that only parses/runs on PowerShell 7
/// (e.g. the C#-style checked($x) overflow operator) from leaking into
/// PowerShell code paths.
/// </summary>
public sealed class WindowsPowerShellCompatibilityContractTests
{
    [Fact]
    public void ReleaseScripts_DoNotUsePowerShell7OnlyCheckedOperator()
    {
        var scriptsRoot = Path.Combine(FindRepositoryRoot(), "scripts");
        var offenders = new List<string>();

        foreach (var file in Directory.EnumerateFiles(scriptsRoot, "*.ps*1", SearchOption.AllDirectories))
        {
            var text = File.ReadAllText(file);
            // C# here-strings use checked((int)x); PowerShell code must not
            // use checked($x) / unchecked($x) because Windows PowerShell 5.1
            // treats them as commands and fails at runtime.
            if (text.Contains("checked($", StringComparison.Ordinal))
            {
                offenders.Add(Path.GetFileName(file));
            }
        }

        offenders.Should().BeEmpty(
            "Windows PowerShell 5.1 cannot run the C#-style checked/unchecked operator: {0}",
            string.Join(", ", offenders));
    }

    private static string FindRepositoryRoot()
    {
        var directory = AppContext.BaseDirectory;
        while (!string.IsNullOrWhiteSpace(directory))
        {
            if (File.Exists(Path.Combine(directory, "README.md"))
                && Directory.Exists(Path.Combine(directory, "src"))
                && Directory.Exists(Path.Combine(directory, "scripts")))
            {
                return directory;
            }

            directory = Directory.GetParent(directory)?.FullName;
        }

        throw new InvalidOperationException("Repository root was not found.");
    }
}
