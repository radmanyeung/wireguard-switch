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

    [Fact]
    public void ReleaseScripts_DoNotArraySplatDashStringsIntoScriptInvocations()
    {
        // Windows PowerShell 5.1 binds array-splatted dash-strings such as
        // @('-Elevated') as POSITIONAL arguments instead of parameter names
        // when the invoked command is a .ps1 script. The bundled installer's
        // elevated bootstrap did `& $installedScript @childArguments` with an
        // array of dash-strings, so the child never received -Elevated and
        // re-entered the bootstrap recursively until CallDepthOverflow.
        // Native executables are unaffected (argv is positional anyway), so
        // only flag `& $var @arrayVar` where the array is built from
        // dash-leading string literals.
        var scriptsRoot = Path.Combine(FindRepositoryRoot(), "scripts");
        var offenders = new List<string>();
        var arrayAssignment = new System.Text.RegularExpressions.Regex(
            @"\$(\w+)\s*=\s*@\(\s*'-[A-Za-z]",
            System.Text.RegularExpressions.RegexOptions.Compiled);

        foreach (var file in Directory.EnumerateFiles(scriptsRoot, "*.ps*1", SearchOption.AllDirectories))
        {
            var text = File.ReadAllText(file);
            foreach (System.Text.RegularExpressions.Match match in arrayAssignment.Matches(text))
            {
                var variable = match.Groups[1].Value;
                var splatInvocation = new System.Text.RegularExpressions.Regex(
                    @"&\s*\$\w+(?:\.\w+)?\s+@" + variable + @"\b",
                    System.Text.RegularExpressions.RegexOptions.Compiled);
                if (splatInvocation.IsMatch(text))
                {
                    offenders.Add($"{Path.GetFileName(file)} (${variable})");
                }
            }
        }

        offenders.Should().BeEmpty(
            "array-splatting dash-strings into a script invocation binds them " +
            "positionally under Windows PowerShell 5.1; splat a hashtable instead: {0}",
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
