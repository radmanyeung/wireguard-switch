using System.Xml.Linq;
using FluentAssertions;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class ReleaseVersionMetadataTests
{
    [Fact]
    public void CentralVersion_IsCurrentReleaseVersion()
    {
        ReadCentralVersion().Should().Be("0.1.8");
    }

    [Fact]
    public void WindowsAppProject_UsesCentralVersionMetadata()
    {
        var project = ReadRepositoryFile("src/WireguardSplitTunnel.App/WireguardSplitTunnel.App.csproj");

        project.Should().NotContain("<Version>0.1.4</Version>");
        project.Should().NotContain("<AssemblyVersion>0.1.4.0</AssemblyVersion>");
        project.Should().NotContain("<FileVersion>0.1.4.0</FileVersion>");
        project.Should().NotContain("<InformationalVersion>0.1.4</InformationalVersion>");
    }

    [Fact]
    public void MacPackageScript_UsesProjectVersionForInfoPlist()
    {
        var script = ReadRepositoryFile("scripts/package-mac.sh");

        script.Should().Contain("dotnet msbuild");
        script.Should().Contain("CFBundleShortVersionString");
        script.Should().Contain("$app_version");
        script.Should().NotContain("<string>0.1.0</string>");
    }

    [Fact]
    public void MacPackageScript_IncludesDoubleClickLauncher()
    {
        var script = ReadRepositoryFile("scripts/package-mac.sh");

        script.Should().Contain("Start WireGuard Split Tunnel.command");
        script.Should().Contain("xattr -dr com.apple.quarantine");
        script.Should().Contain("WireguardSplitTunnel.app/Contents/MacOS/WireguardSplitTunnel");
    }

    private static string ReadCentralVersion()
    {
        var document = XDocument.Parse(ReadRepositoryFile("Directory.Build.props"));
        return document
            .Descendants("VersionPrefix")
            .Single()
            .Value;
    }

    private static string ReadRepositoryFile(string relativePath)
    {
        var root = FindRepositoryRoot();
        return File.ReadAllText(Path.Combine(root, relativePath.Replace('/', Path.DirectorySeparatorChar)));
    }

    private static string FindRepositoryRoot()
    {
        var directory = AppContext.BaseDirectory;
        while (!string.IsNullOrWhiteSpace(directory))
        {
            if (File.Exists(Path.Combine(directory, "README.md"))
                && Directory.Exists(Path.Combine(directory, "src"))
                && Directory.Exists(Path.Combine(directory, "tests")))
            {
                return directory;
            }

            directory = Directory.GetParent(directory)?.FullName;
        }

        throw new InvalidOperationException("Repository root was not found.");
    }
}
