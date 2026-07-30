using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class ReleasePackageScriptTests : IDisposable
{
    private readonly ReleaseScriptFixture _fixture = new();

    [Fact]
    public void PackageAssembly_UsesOnlyTheExplicitRuntimeAllowlist()
    {
        var result = _fixture.Package();

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        _fixture.PackageFiles().Should().Equal(
            ReleaseScriptFixture.ExpectedPackageFiles);
        _fixture.PackageFiles().Should().NotContain(path =>
            path.Contains("/bin/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/obj/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("logs/", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase)
            || path.Contains("Tests", StringComparison.OrdinalIgnoreCase)
            || path == "state.json"
            || path == "runtime.log"
            || path == "scripts/package-windows.ps1"
            || path == "scripts/package-mac.sh"
            || path == "scripts/build.ps1");
    }

    [Fact]
    public void PackageAssembly_RefusesANonEmptyOutputDirectory()
    {
        File.WriteAllText(
            Path.Combine(_fixture.OutputRoot, "foreign.txt"),
            "do not delete");

        var result = _fixture.Package();

        result.ExitCode.Should().NotBe(0);
        File.ReadAllText(
                Path.Combine(_fixture.OutputRoot, "foreign.txt"))
            .Should().Be("do not delete");
    }

    [Fact]
    public void GeneratedManifest_IsDeterministicSortedAndHashesEveryPayload()
    {
        _fixture.Package().ExitCode.Should().Be(0);
        var manifestPath = Path.Combine(
            _fixture.PackageRoot,
            UpdateReleaseContract.ReleaseManifestPath);
        var firstBytes = File.ReadAllBytes(manifestPath);
        using var document = JsonDocument.Parse(firstBytes);
        var root = document.RootElement;

        root.GetProperty("version").GetString()
            .Should().Be(_fixture.Version);
        root.GetProperty("runtimeIdentifier").GetString()
            .Should().Be(UpdateReleaseContract.WindowsRuntimeIdentifier);
        root.GetProperty("minimumAutoUpdateVersion").GetString()
            .Should().Be(_fixture.CompatibilityVersion);
        root.GetProperty("rollbackCompatibleFromVersion").GetString()
            .Should().Be(_fixture.CompatibilityVersion);
        root.GetProperty("stateSchemaVersion").GetInt32()
            .Should().Be(1);
        root.GetProperty("entryPoint").GetString()
            .Should().Be(UpdateReleaseContract.WindowsApplicationPath);
        root.GetProperty("updaterEntryPoint").GetString()
            .Should().Be(UpdateReleaseContract.WindowsUpdaterPath);
        root.GetProperty("requiredLaunchers")
            .EnumerateArray()
            .Select(value => value.GetString())
            .Should().Equal(UpdateReleaseContract.RequiredLauncherPaths);

        var files = root.GetProperty("files")
            .EnumerateArray()
            .Select(element => new
            {
                Path = element.GetProperty("path").GetString()!,
                Length = element.GetProperty("length").GetInt64(),
                Sha256 = element.GetProperty("sha256").GetString()!
            })
            .ToArray();
        files.Select(file => file.Path).Should().Equal(
            files.Select(file => file.Path)
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase));
        files.Select(file => file.Path)
            .Should().NotContain(UpdateReleaseContract.ReleaseManifestPath);
        files.Should().HaveCount(
            ReleaseScriptFixture.ExpectedPackageFiles.Count - 1);
        foreach (var file in files)
        {
            var payload = Path.Combine(
                _fixture.PackageRoot,
                file.Path.Replace('/', Path.DirectorySeparatorChar));
            var bytes = File.ReadAllBytes(payload);
            file.Length.Should().Be(bytes.LongLength);
            file.Sha256.Should().Be(
                Convert.ToHexString(SHA256.HashData(bytes))
                    .ToLowerInvariant());
        }

        var regenerated = _fixture.GenerateManifest();
        regenerated.ExitCode.Should().Be(0, regenerated.CombinedOutput);
        File.ReadAllBytes(manifestPath).Should().Equal(firstBytes);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("extra")]
    [InlineData("changed")]
    public void PackageValidator_RejectsMissingExtraOrChangedPayload(
        string mutation)
    {
        _fixture.Package().ExitCode.Should().Be(0);
        var target = Path.Combine(
            _fixture.PackageRoot,
            "scripts",
            "start.ps1");
        switch (mutation)
        {
            case "missing":
                File.Delete(target);
                break;
            case "extra":
                File.WriteAllText(
                    Path.Combine(_fixture.PackageRoot, "unexpected.txt"),
                    "unexpected");
                break;
            default:
                File.AppendAllText(target, "tampered");
                break;
        }

        var validation = _fixture.ValidatePackage();

        validation.ExitCode.Should().NotBe(0);
    }

    [Fact]
    public void PackageValidator_RejectsExecutableProductVersionMismatch()
    {
        _fixture.Package().ExitCode.Should().Be(0);
        var app = Path.Combine(
            _fixture.PackageRoot,
            UpdateReleaseContract.WindowsApplicationPath
                .Replace('/', Path.DirectorySeparatorChar));
        File.WriteAllText(app, "not a versioned executable");
        _fixture.GenerateManifest().ExitCode.Should().Be(0);

        var validation = _fixture.ValidatePackage();

        validation.ExitCode.Should().NotBe(0);
        validation.CombinedOutput.Should().ContainEquivalentOf(
            "ProductVersion");
    }

    [Fact]
    public async Task FixtureProducedZipAndSidecar_AreAcceptedByProductionConsumer()
    {
        _fixture.Package().ExitCode.Should().Be(0);
        var candidateRoot = Path.Combine(
            _fixture.Root,
            "consumer-candidate");
        var validator = new UpdatePackageValidator(
            new WindowsExecutableProductVersionReader(),
            new UnlimitedDiskSpace(),
            new WindowsPathSafetyInspector());

        var result = await validator.ValidateAsync(
            new UpdatePackageValidationRequest(
                _fixture.ArchivePath,
                await File.ReadAllBytesAsync(_fixture.SidecarPath),
                SemanticVersionTestExtensions.ParseForTest(
                    _fixture.Version),
                SemanticVersionTestExtensions.ParseForTest(
                    _fixture.CompatibilityVersion),
                SupportedStateSchemaVersion: 1,
                CurrentManagedBytes: 0,
                candidateRoot,
                _fixture.Root,
                UpdatePackageLimits.Default));

        result.Success.Should().BeTrue(
            $"{result.ErrorCode}: {result.DetailCode}");
        result.Package!.Manifest.Version.Should().Be(_fixture.Version);
    }

    [Fact]
    public async Task WorkflowProducedZipAndSidecar_AreAcceptedByProductionValidation()
    {
        var required = Environment.GetEnvironmentVariable(
            "WGST_REQUIRE_PRODUCED_ARTIFACT");
        var archive = Environment.GetEnvironmentVariable(
            "WGST_PRODUCED_ARCHIVE");
        var sidecar = Environment.GetEnvironmentVariable(
            "WGST_PRODUCED_SIDECAR");
        var versionText = Environment.GetEnvironmentVariable(
            "WGST_PRODUCED_VERSION");
        if (!string.Equals(required, "1", StringComparison.Ordinal)
            && new[] { archive, sidecar, versionText }
                .Any(string.IsNullOrWhiteSpace))
        {
            return;
        }

        archive.Should().NotBeNullOrWhiteSpace();
        sidecar.Should().NotBeNullOrWhiteSpace();
        versionText.Should().NotBeNullOrWhiteSpace();
        File.Exists(archive).Should().BeTrue(
            "the workflow must pass its generated Windows ZIP to this test");
        File.Exists(sidecar).Should().BeTrue(
            "the workflow must pass the generated checksum sidecar to this test");
        Path.GetFileName(archive).Should().Be(
            UpdateReleaseContract.WindowsAssetName);
        Path.GetFileName(sidecar).Should().Be(
            UpdateReleaseContract.WindowsChecksumAssetName);
        SemanticVersion.TryParseNormalized(
                versionText,
                out var candidateVersion)
            .Should()
            .BeTrue();

        var scratch = Path.Combine(
            Path.GetTempPath(),
            "wgst-workflow-consumer",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(scratch);
        try
        {
            var sidecarBytes = await File.ReadAllBytesAsync(sidecar!);
            var manifest = await ValidateProducedArchiveAsync(
                archive!,
                sidecarBytes,
                candidateVersion,
                Path.Combine(scratch, "producer-candidate"));

            var minimum = SemanticVersionTestExtensions.ParseForTest(
                manifest.MinimumAutoUpdateVersion!);
            var rollback = SemanticVersionTestExtensions.ParseForTest(
                manifest.RollbackCompatibleFromVersion!);
            var compatibleCurrent = minimum.CompareTo(rollback) >= 0
                ? minimum
                : rollback;
            var validator = new UpdatePackageValidator(
                new WindowsExecutableProductVersionReader(),
                new UnlimitedDiskSpace(),
                new WindowsPathSafetyInspector());
            var consumerResult = await validator.ValidateAsync(
                new UpdatePackageValidationRequest(
                    archive!,
                    sidecarBytes,
                    candidateVersion,
                    compatibleCurrent,
                    manifest.StateSchemaVersion,
                    CurrentManagedBytes: 0,
                    Path.Combine(scratch, "consumer-candidate"),
                    scratch,
                    UpdatePackageLimits.Default));

            if (candidateVersion == new SemanticVersion(0, 2, 0))
            {
                compatibleCurrent.Should().Be(candidateVersion,
                    "v0.2.0 is the one-time manual bootstrap whose compatibility floors equal itself");
                consumerResult.Success.Should().BeFalse();
                consumerResult.ErrorCode.Should().Be(
                    UpdatePackageValidationError.InvalidManifest);
                consumerResult.DetailCode.Should().Be("version",
                    "the production consumer must reject a non-newer candidate after authenticating and preflighting it");
            }
            else
            {
                compatibleCurrent.CompareTo(candidateVersion)
                    .Should()
                    .BeLessThan(0,
                        "post-bootstrap release floors must name an older updater-capable version");
                consumerResult.Success.Should().BeTrue(
                    $"{consumerResult.ErrorCode}: {consumerResult.DetailCode}");
                consumerResult.Package!.Version.Should().Be(candidateVersion);
            }
        }
        finally
        {
            if (Directory.Exists(scratch))
            {
                Directory.Delete(scratch, recursive: true);
            }
        }
    }

    private static async Task<ReleaseManifest> ValidateProducedArchiveAsync(
        string archive,
        byte[] sidecarBytes,
        SemanticVersion candidateVersion,
        string candidateRoot)
    {
        using var opened = SafeZipExtractor.Open(
            archive,
            UpdatePackageLimits.Default,
            new WindowsPathSafetyInspector());
        opened.Success.Should().BeTrue(opened.ErrorCode.ToString());
        opened.Session.Should().NotBeNull();
        opened.Session!.ArchiveLength.Should().BeLessThanOrEqualTo(
            UpdateNetworkLimits.ArchiveBytes);

        var archiveHash = await opened.Session.ComputeSha256Async();
        archiveHash.Success.Should().BeTrue(
            archiveHash.ErrorCode.ToString());
        var parsedSidecar = Sha256SidecarParser.Parse(sidecarBytes);
        parsedSidecar.Success.Should().BeTrue(
            parsedSidecar.ErrorCode.ToString());
        CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(archiveHash.Digest!),
                Convert.FromHexString(parsedSidecar.Digest!))
            .Should()
            .BeTrue();

        var preflight = opened.Session.Preflight();
        preflight.Success.Should().BeTrue(preflight.ErrorCode.ToString());
        var manifestRead = opened.Session.ReadManifest();
        manifestRead.Success.Should().BeTrue(
            manifestRead.ErrorCode.ToString());
        var manifest = JsonSerializer.Deserialize<ReleaseManifest>(
            manifestRead.Bytes!,
            new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = false,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
                AllowTrailingCommas = false,
                ReadCommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 32
            });
        manifest.Should().NotBeNull();
        var regularFiles = opened.Session.Entries
            .Where(entry => !entry.IsDirectory)
            .Select(entry => (string?)entry.Path)
            .ToArray();
        var manifestValidation = ReleaseManifestValidator.ValidateForProducer(
            manifest,
            candidateVersion,
            manifest!.StateSchemaVersion,
            regularFiles);
        manifestValidation.IsValid.Should().BeTrue(
            $"{manifestValidation.ErrorCode}: {manifestValidation.ErrorMessage}");

        using var extraction = opened.Session.ExtractTo(candidateRoot);
        extraction.Success.Should().BeTrue(extraction.ErrorCode.ToString());
        var extractedManifest = Path.Combine(
            candidateRoot,
            UpdateReleaseContract.ReleaseManifestPath);
        (await File.ReadAllBytesAsync(extractedManifest))
            .Should()
            .Equal(manifestRead.Bytes!);
        foreach (var payload in manifestValidation.Manifest!.Files!)
        {
            var path = Path.Combine(
                candidateRoot,
                payload.Path.Replace('/', Path.DirectorySeparatorChar));
            var info = new FileInfo(path);
            info.Exists.Should().BeTrue(payload.Path);
            info.Length.Should().Be(payload.Length, payload.Path);
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 81920,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            var digest = Convert.ToHexString(
                    await SHA256.HashDataAsync(stream))
                .ToLowerInvariant();
            digest.Should().Be(payload.Sha256, payload.Path);
        }

        var versionReader = new WindowsExecutableProductVersionReader();
        foreach (var executable in new[]
                 {
                     UpdateReleaseContract.WindowsApplicationPath,
                     UpdateReleaseContract.WindowsUpdaterPath
                 })
        {
            var path = Path.Combine(
                candidateRoot,
                executable.Replace('/', Path.DirectorySeparatorChar));
            versionReader.ReadProductVersion(path)
                .Should()
                .Be(candidateVersion.ToString(), executable);
        }

        return manifestValidation.Manifest;
    }

    [Fact]
    public void SafeExtractor_RejectsCentralLengthThatDoesNotMatchCopiedBytes()
    {
        var archive = Path.Combine(_fixture.Root, "length-lie.zip");
        using (var zip = ZipFile.Open(
                   archive,
                   ZipArchiveMode.Create))
        {
            var entry = zip.CreateEntry("payload.txt");
            using var writer = new StreamWriter(
                entry.Open(),
                new UTF8Encoding(false));
            writer.Write("payload");
        }
        IncrementCentralUncompressedLength(archive);
        var destination = Path.Combine(_fixture.Root, "length-lie-output");
        var modulePath = Path.Combine(
            _fixture.ActualRepositoryRoot,
            "scripts",
            "WindowsRelease.psm1");
        var source = $$"""
            $ErrorActionPreference = 'Stop'
            $module = Import-Module '{{PsEscape(modulePath)}}' -Force -PassThru
            & $module {
                param($Archive, $Destination)
                Expand-WgstSafeArchive `
                    -ArchivePath $Archive `
                    -DestinationRoot $Destination
            } '{{PsEscape(archive)}}' '{{PsEscape(destination)}}'
            """;

        var result = _fixture.RunInlinePowerShell(source);

        result.ExitCode.Should().NotBe(0);
    }

    public void Dispose() => _fixture.Dispose();

    private static void IncrementCentralUncompressedLength(
        string archive)
    {
        var bytes = File.ReadAllBytes(archive);
        var signature = new byte[] { 0x50, 0x4b, 0x01, 0x02 };
        var index = Enumerable.Range(0, bytes.Length - signature.Length)
            .Single(offset =>
                bytes.AsSpan(offset, signature.Length)
                    .SequenceEqual(signature));
        var lengthOffset = index + 24;
        var length = BitConverter.ToUInt32(bytes, lengthOffset);
        BitConverter.GetBytes(checked(length + 1))
            .CopyTo(bytes, lengthOffset);
        File.WriteAllBytes(archive, bytes);
    }

    private static string PsEscape(string value) =>
        value.Replace("'", "''", StringComparison.Ordinal);

    private sealed class UnlimitedDiskSpace : IDiskSpaceProvider
    {
        public long GetAvailableBytes(string path) => long.MaxValue;
    }
}

internal static class SemanticVersionTestExtensions
{
    internal static SemanticVersion ParseForTest(string value)
    {
        SemanticVersion.TryParseNormalized(value, out var parsed)
            .Should().BeTrue();
        return parsed;
    }
}

internal sealed class ReleaseScriptFixture : IDisposable
{
    internal static readonly IReadOnlyList<string> RootRuntimeFiles =
    [
        "install.cmd",
        "start.cmd",
        "start-admin.cmd",
        "start-safe.cmd",
        "test.cmd",
        "diagnose.cmd",
        "fix-dns.cmd",
        "reset-network.cmd",
        "README.md"
    ];

    internal static readonly IReadOnlyList<string> ScriptRuntimeFiles =
    [
        "bootstrap-env.ps1",
        "diagnose-status.ps1",
        "ensure-prebuilt.ps1",
        "fix-dns.ps1",
        "install.ps1",
        "reset-network.ps1",
        "start.ps1",
        "test.ps1",
        "update-launcher.ps1",
        "WindowsRelease.psm1"
    ];

    internal static readonly IReadOnlyList<string> RuntimeLibraryFiles =
    [
        "release-package.ps1"
    ];

    internal static readonly IReadOnlyList<string> ExpectedPackageFiles =
        RootRuntimeFiles
            .Concat(ScriptRuntimeFiles.Select(path => $"scripts/{path}"))
            .Concat(RuntimeLibraryFiles.Select(path => $"scripts/lib/{path}"))
            .Concat(
            [
                UpdateReleaseContract.WindowsApplicationPath,
                UpdateReleaseContract.WindowsUpdaterPath,
                UpdateReleaseContract.ReleaseManifestPath
            ])
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    internal ReleaseScriptFixture()
    {
        ActualRepositoryRoot = FindRepositoryRoot();
        Root = Path.Combine(
            Path.GetTempPath(),
            "wgst-task13-tests",
            Guid.NewGuid().ToString("N"));
        RepositoryRoot = Path.Combine(Root, "repository");
        OutputRoot = Path.Combine(Root, "output");
        AppPublishRoot = Path.Combine(Root, "app-publish");
        UpdaterPublishRoot = Path.Combine(Root, "updater-publish");
        Directory.CreateDirectory(RepositoryRoot);
        Directory.CreateDirectory(OutputRoot);
        Directory.CreateDirectory(AppPublishRoot);
        Directory.CreateDirectory(UpdaterPublishRoot);
        Directory.CreateDirectory(Path.Combine(RepositoryRoot, "scripts"));

        var executable = Path.Combine(
            AppContext.BaseDirectory,
            "WireguardSplitTunnel.TestProcess.exe");
        File.Exists(executable).Should().BeTrue();
        Version = FileVersionInfo
            .GetVersionInfo(executable)
            .ProductVersion!
            .Split('+', 2)[0];
        SemanticVersion.TryParseNormalized(
                Version,
                out var version)
            .Should().BeTrue();
        CompatibilityVersion = new SemanticVersion(
                version.Major,
                version.Minor,
                Math.Max(0, version.Patch - 1))
            .ToString();
        if (CompatibilityVersion == Version)
        {
            CompatibilityVersion = "0.0.0";
        }

        foreach (var file in RootRuntimeFiles)
        {
            File.WriteAllText(
                Path.Combine(RepositoryRoot, file),
                $"fixture:{file}\r\n");
        }

        foreach (var file in ScriptRuntimeFiles)
        {
            File.WriteAllText(
                Path.Combine(RepositoryRoot, "scripts", file),
                $"# fixture:{file}\r\n");
        }
        Directory.CreateDirectory(
            Path.Combine(RepositoryRoot, "scripts", "lib"));
        foreach (var file in RuntimeLibraryFiles)
        {
            File.WriteAllText(
                Path.Combine(
                    RepositoryRoot,
                    "scripts",
                    "lib",
                    file),
                $"# fixture:{file}\r\n");
        }

        File.WriteAllText(
            Path.Combine(RepositoryRoot, "runtime.log"),
            "must not package");
        File.WriteAllText(
            Path.Combine(RepositoryRoot, "state.json"),
            "must not package");
        Directory.CreateDirectory(
            Path.Combine(RepositoryRoot, "logs"));
        File.WriteAllText(
            Path.Combine(RepositoryRoot, "logs", "start.log"),
            "must not package");
        Directory.CreateDirectory(
            Path.Combine(RepositoryRoot, "src", "bin"));
        File.WriteAllText(
            Path.Combine(RepositoryRoot, "src", "bin", "bad.dll"),
            "must not package");
        File.WriteAllText(
            Path.Combine(RepositoryRoot, "scripts", "build.ps1"),
            "must not package");
        File.WriteAllText(
            Path.Combine(RepositoryRoot, "scripts", "package-mac.sh"),
            "must not package");
        File.WriteAllText(
            Path.Combine(RepositoryRoot, "scripts", "package-windows.ps1"),
            "must not package");

        PropsPath = Path.Combine(
            RepositoryRoot,
            "Directory.Build.props");
        File.WriteAllText(
            PropsPath,
            $"""
             <Project>
               <PropertyGroup>
                 <VersionPrefix>{Version}</VersionPrefix>
                 <MinimumAutoUpdateVersion>{CompatibilityVersion}</MinimumAutoUpdateVersion>
                 <RollbackCompatibleFromVersion>{CompatibilityVersion}</RollbackCompatibleFromVersion>
                 <StateSchemaVersion>1</StateSchemaVersion>
               </PropertyGroup>
             </Project>
             """);
        File.Copy(
            executable,
            Path.Combine(
                AppPublishRoot,
                "WireguardSplitTunnel.App.exe"));
        File.Copy(
            executable,
            Path.Combine(
                UpdaterPublishRoot,
                "WireguardSplitTunnel.Updater.exe"));
        File.WriteAllText(
            Path.Combine(AppPublishRoot, "app.pdb"),
            "must not package");
        File.WriteAllText(
            Path.Combine(
                UpdaterPublishRoot,
                "WireguardSplitTunnel.Tests.dll"),
            "must not package");
    }

    internal string ActualRepositoryRoot { get; }
    internal string Root { get; }
    internal string RepositoryRoot { get; }
    internal string OutputRoot { get; }
    internal string AppPublishRoot { get; }
    internal string UpdaterPublishRoot { get; }
    internal string PropsPath { get; }
    internal string Version { get; }
    internal string CompatibilityVersion { get; }
    internal string PackageRoot =>
        Path.Combine(OutputRoot, "package");
    internal string ArchivePath =>
        Path.Combine(
            OutputRoot,
            UpdateReleaseContract.WindowsAssetName);
    internal string SidecarPath =>
        Path.Combine(
            OutputRoot,
            UpdateReleaseContract.WindowsChecksumAssetName);

    internal ScriptProcessResult Package() =>
        RunPowerShell(
            Path.Combine(
                ActualRepositoryRoot,
                "scripts",
                "package-windows.ps1"),
            "-Tag",
            $"v{Version}",
            "-OutputRoot",
            OutputRoot,
            "-RepositoryRoot",
            RepositoryRoot,
            "-AppPublishRoot",
            AppPublishRoot,
            "-UpdaterPublishRoot",
            UpdaterPublishRoot,
            "-Props",
            PropsPath);

    internal ScriptProcessResult GenerateManifest() =>
        RunPowerShell(
            Path.Combine(
                ActualRepositoryRoot,
                "scripts",
                "new-release-manifest.ps1"),
            "-PackageRoot",
            PackageRoot,
            "-Props",
            PropsPath,
            "-ExpectedTag",
            $"v{Version}");

    internal ScriptProcessResult ValidatePackage() =>
        RunPowerShell(
            Path.Combine(
                ActualRepositoryRoot,
                "scripts",
                "validate-release-package.ps1"),
            "-PackageRoot",
            PackageRoot,
            "-Props",
            PropsPath,
            "-ExpectedTag",
            $"v{Version}");

    internal IReadOnlyList<string> PackageFiles() =>
        Directory.EnumerateFiles(
                PackageRoot,
                "*",
                SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(PackageRoot, path)
                .Replace(Path.DirectorySeparatorChar, '/'))
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    internal ScriptProcessResult RunInlinePowerShell(
        string source,
        IReadOnlyDictionary<string, string>? environment = null)
    {
        var path = Path.Combine(
            Root,
            $"inline-{Guid.NewGuid():N}.ps1");
        File.WriteAllText(path, source, new UTF8Encoding(false));
        return RunPowerShell(path, environment: environment);
    }

    internal static ScriptProcessResult RunPowerShell(
        string scriptPath,
        params string[] arguments) =>
        RunPowerShell(
            scriptPath,
            arguments,
            environment: null);

    internal static ScriptProcessResult RunPowerShell(
        string scriptPath,
        IReadOnlyList<string>? arguments = null,
        IReadOnlyDictionary<string, string>? environment = null)
    {
        var start = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        start.ArgumentList.Add("-NoLogo");
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-ExecutionPolicy");
        start.ArgumentList.Add("Bypass");
        start.ArgumentList.Add("-File");
        start.ArgumentList.Add(scriptPath);
        foreach (var argument in arguments ?? [])
        {
            start.ArgumentList.Add(argument);
        }

        foreach (var pair in environment
                     ?? new Dictionary<string, string>())
        {
            start.Environment[pair.Key] = pair.Value;
        }

        using var process = Process.Start(start);
        process.Should().NotBeNull();
        var stdout = process!.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit(60_000).Should().BeTrue();
        return new ScriptProcessResult(
            process.ExitCode,
            stdout,
            stderr);
    }

    public void Dispose()
    {
        if (Directory.Exists(Root))
        {
            Directory.Delete(Root, recursive: true);
        }
    }

    private static string FindRepositoryRoot()
    {
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

internal sealed record ScriptProcessResult(
    int ExitCode,
    string StandardOutput,
    string StandardError)
{
    internal string CombinedOutput =>
        $"{StandardOutput}{Environment.NewLine}{StandardError}";
}
