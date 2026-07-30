using System.Text.RegularExpressions;
using System.Xml.Linq;
using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class ReleaseWorkflowContractTests
{
    private const string CheckoutSha = "11d5960a326750d5838078e36cf38b85af677262";
    private const string SetupDotnetSha = "67a3573c9a986a3f9c594539f4ab511d57bb3ce9";
    private const string UploadArtifactSha = "ea165f8d65b6e75b540449e92b4886f43607fa02";
    private const string DownloadArtifactSha = "d3f86a106a0bac45b974a628896c90dbdf5c8093";
    private const string ReleaseSha = "3bb12739c298aeb8a4eeaf626c5b8d85266b0e65";

    [Fact]
    public void Workflow_UsesLeastPrivilegeAndPinsEveryActionToAnExactCommit()
    {
        var workflow = ReadRepositoryFile(".github/workflows/release-prebuilt.yml");

        workflow.Should().MatchRegex(
            @"(?ms)^permissions:\s*\r?\n\s+contents:\s*read\s*$");
        workflow.Should().Contain($"actions/checkout@{CheckoutSha} # v4");
        workflow.Should().Contain($"actions/setup-dotnet@{SetupDotnetSha} # v4");
        workflow.Should().Contain($"actions/upload-artifact@{UploadArtifactSha} # v4");
        workflow.Should().Contain($"actions/download-artifact@{DownloadArtifactSha} # v4");
        workflow.Should().Contain($"softprops/action-gh-release@{ReleaseSha} # v2");
        Regex.Matches(workflow, @"persist-credentials:\s*false")
            .Should()
            .HaveCount(3);

        var actionReferences = Regex.Matches(
            workflow,
            @"(?m)^\s*uses:\s*[^@\s]+@(?<reference>[^\s#]+)");
        actionReferences.Should().NotBeEmpty();
        actionReferences
            .Select(match => match.Groups["reference"].Value)
            .Should()
            .OnlyContain(reference =>
                Regex.IsMatch(reference, "^[0-9a-f]{40}$"));
    }

    [Fact]
    public void Workflow_RunsThePlatformSpecificTestMatrixBeforePackaging()
    {
        var workflow = ReadRepositoryFile(".github/workflows/release-prebuilt.yml");

        workflow.Should().Contain("FullyQualifiedName!~Mac");
        workflow.Should().Contain(
            "tests/WireguardSplitTunnel.WindowsUpdate.Tests/WireguardSplitTunnel.WindowsUpdate.Tests.csproj");
        workflow.Should().Contain("FullyQualifiedName~Mac");
        workflow.Should().Contain("runs-on: windows-latest");
        workflow.Should().Contain("runs-on: macos-latest");

        IndexOf(workflow, "FullyQualifiedName!~Mac")
            .Should()
            .BeLessThan(IndexOf(workflow, "scripts/package-windows.ps1"));
        IndexOf(workflow, "FullyQualifiedName~Mac")
            .Should()
            .BeLessThan(IndexOf(workflow, "scripts/package-mac.sh"));
    }

    [Fact]
    public void Workflow_ValidatesVersionCompatibilityAndPublishesBothWindowsExecutables()
    {
        var workflow = ReadRepositoryFile(".github/workflows/release-prebuilt.yml");

        workflow.Should().Contain("$env:GITHUB_REF_NAME");
        workflow.Should().Contain("PropertyGroup.VersionPrefix");
        workflow.Should().Contain("PropertyGroup.MinimumAutoUpdateVersion");
        workflow.Should().Contain("PropertyGroup.RollbackCompatibleFromVersion");
        workflow.Should().Contain("PropertyGroup.StateSchemaVersion");
        workflow.Should().Contain("src/WireguardSplitTunnel.App/WireguardSplitTunnel.App.csproj");
        workflow.Should().Contain("src/WireguardSplitTunnel.Updater/WireguardSplitTunnel.Updater.csproj");
        Regex.Matches(workflow, @"--self-contained\s+true")
            .Count
            .Should()
            .BeGreaterThanOrEqualTo(2);
        Regex.Matches(workflow, @"(?:-r|--runtime)\s+win-x64")
            .Count
            .Should()
            .BeGreaterThanOrEqualTo(2);
    }

    [Fact]
    public void Workflow_ValidatesTheProductionPackageAndDryRunBeforeUploadingExactArtifacts()
    {
        var workflow = ReadRepositoryFile(".github/workflows/release-prebuilt.yml");
        var packageScript = ReadRepositoryFile("scripts/package-windows.ps1");

        packageScript.Should().Contain("New-WgstReleaseManifest");
        workflow.Should().Contain("scripts/validate-release-package.ps1");
        workflow.Should().Contain(
            "WorkflowProducedZipAndSidecar_AreAcceptedByProductionValidation");
        workflow.Should().Contain("WGST_REQUIRE_PRODUCED_ARTIFACT");
        workflow.Should().Contain("WGST_PRODUCED_ARCHIVE");
        workflow.Should().Contain("WGST_PRODUCED_SIDECAR");
        workflow.Should().Contain("WGST_PRODUCED_VERSION");
        workflow.Should().Contain("scripts/start.ps1");
        workflow.Should().Contain("-DryRun");
        workflow.Should().Contain("wireguard-split-tunnel-win-x64.zip");
        workflow.Should().Contain("wireguard-split-tunnel-win-x64.zip.sha256");
        workflow.Should().Contain("wireguard-split-tunnel-mac-arm64.zip");
        workflow.Should().Contain("actions/upload-artifact@");
        IndexOf(
                workflow,
                "WorkflowProducedZipAndSidecar_AreAcceptedByProductionValidation")
            .Should()
            .BeGreaterThan(IndexOf(workflow, "scripts/package-windows.ps1"))
            .And
            .BeLessThan(IndexOf(workflow, "Upload validated Windows artifacts"));
    }

    [Fact]
    public void Workflow_HasOneFinalPublisherThatNeedsBothValidatedBuilds()
    {
        var workflow = ReadRepositoryFile(".github/workflows/release-prebuilt.yml");

        Regex.Matches(workflow, "softprops/action-gh-release@")
            .Should()
            .ContainSingle();
        workflow.Should().MatchRegex(
            @"(?ms)^\s*publish-release:\s*\r?\n(?:(?!^\s{2}\S).)*" +
            @"needs:\s*\[\s*build-windows-release\s*,\s*build-mac-release\s*\]" +
            @"(?:(?!^\s{2}\S).)*permissions:\s*\r?\n\s+contents:\s*write");
        workflow.Should().Contain("actions/download-artifact@");
        workflow.Should().Contain("Validate downloaded release artifacts");
    }

    [Fact]
    public void CompatibilityProperties_AreStrictAndNotNewerThanTheRelease()
    {
        var document = XDocument.Parse(
            ReadRepositoryFile("Directory.Build.props"));
        var properties = document.Root!
            .Elements("PropertyGroup")
            .SelectMany(group => group.Elements())
            .ToDictionary(element => element.Name.LocalName, element => element.Value);

        properties.Should().ContainKeys(
            "VersionPrefix",
            "MinimumAutoUpdateVersion",
            "RollbackCompatibleFromVersion",
            "StateSchemaVersion");
        SemanticVersion.TryParseNormalized(
            properties["VersionPrefix"],
            out var release).Should().BeTrue();
        SemanticVersion.TryParseNormalized(
            properties["MinimumAutoUpdateVersion"],
            out var minimum).Should().BeTrue();
        SemanticVersion.TryParseNormalized(
            properties["RollbackCompatibleFromVersion"],
            out var rollback).Should().BeTrue();
        minimum.CompareTo(release).Should().BeLessThanOrEqualTo(0);
        rollback.CompareTo(release).Should().BeLessThanOrEqualTo(0);
        int.TryParse(
            properties["StateSchemaVersion"],
            out var schema).Should().BeTrue();
        schema.Should().BePositive();
    }

    [Fact]
    public void CompatibilityFloor_SelectsTheNextStableReleaseForAnUpdaterCapableInstall()
    {
        var current = new SemanticVersion(0, 2, 0);
        var candidate = new SemanticVersion(0, 2, 1);
        var launchers = UpdateReleaseContract.RequiredLauncherPaths.ToList();
        var files = new List<ReleasePayloadFile>
        {
            new(UpdateReleaseContract.WindowsApplicationPath, 1, new string('a', 64)),
            new(UpdateReleaseContract.WindowsUpdaterPath, 1, new string('b', 64))
        };
        files.AddRange(
            launchers.Select(
                path =>
                    new ReleasePayloadFile(
                        path,
                        1,
                        new string('c', 64))));
        var manifest = new ReleaseManifest(
            1,
            candidate.ToString(),
            UpdateReleaseContract.WindowsRuntimeIdentifier,
            current.ToString(),
            current.ToString(),
            1,
            UpdateReleaseContract.WindowsApplicationPath,
            UpdateReleaseContract.WindowsUpdaterPath,
            launchers,
            files);
        var archive = files
            .Select(file => (string?)file.Path)
            .Append(UpdateReleaseContract.ReleaseManifestPath)
            .ToList();

        ReleaseManifestValidator
            .Validate(manifest, candidate, current, 1, archive)
            .IsValid
            .Should()
            .BeTrue();
    }

    [Fact]
    public void TestScript_AppliesTheHostSpecificCoreFilter()
    {
        var script = ReadRepositoryFile("scripts/test.ps1");

        script.Should().Contain("$IsWindows");
        script.Should().Contain("FullyQualifiedName!~Mac");
        script.Should().Contain("FullyQualifiedName~Mac");
        script.Should().Contain("WireguardSplitTunnel.WindowsUpdate.Tests");
    }

    private static int IndexOf(string text, string value)
    {
        var index = text.IndexOf(value, StringComparison.Ordinal);
        index.Should().BeGreaterThanOrEqualTo(0, $"'{value}' must exist");
        return index;
    }

    private static string ReadRepositoryFile(string relativePath)
    {
        var path = Path.Combine(
            FindRepositoryRoot(),
            relativePath.Replace('/', Path.DirectorySeparatorChar));
        return File.ReadAllText(path);
    }

    private static string FindRepositoryRoot()
    {
        var configuredRoot = Environment.GetEnvironmentVariable(
            "WGST_REPOSITORY_ROOT");
        if (!string.IsNullOrWhiteSpace(configuredRoot)
            && File.Exists(
                Path.Combine(
                    configuredRoot,
                    "WireguardSplitTunnel.sln")))
        {
            return configuredRoot;
        }

        var workingDirectory = Directory.GetCurrentDirectory();
        if (File.Exists(
                Path.Combine(
                    workingDirectory,
                    "WireguardSplitTunnel.sln")))
        {
            return workingDirectory;
        }

        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(
                    Path.Combine(
                        current.FullName,
                        "WireguardSplitTunnel.sln")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException(
            "Could not locate repository root.");
    }
}
