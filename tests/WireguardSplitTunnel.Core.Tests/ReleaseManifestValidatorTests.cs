using System.Collections;
using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class ReleaseManifestValidatorTests
{
    private static readonly SemanticVersion Current = new(1, 0, 0);
    private static readonly SemanticVersion Candidate = new(1, 1, 0);

    [Fact]
    public void Validate_AcceptsExactManifestAndArchiveSetAndReturnsDefensiveSnapshot()
    {
        var inputLaunchers = Launchers();
        var inputFiles = PayloadFiles();
        var manifest = new ReleaseManifest(1, "1.1.0", "win-x64", "1.0.0", "1.0.0", 3,
            UpdateReleaseContract.WindowsApplicationPath, UpdateReleaseContract.WindowsUpdaterPath, inputLaunchers, inputFiles);
        var archive = ArchivePaths(manifest);

        var result = ReleaseManifestValidator.Validate(manifest, Candidate, Current, 3, archive);
        var validated = result.Manifest!;

        result.IsValid.Should().BeTrue();
        result.Manifest.Should().NotBeSameAs(manifest);
        validated.Files!.Should().HaveCount(manifest.Files!.Count);
        inputFiles[0] = inputFiles[0] with { Path = "changed.exe" };
        inputLaunchers[0] = "changed.cmd";
        validated.Files![0].Path.Should().NotBe("changed.exe");
        validated.RequiredLaunchers.Should().NotContain("changed.cmd");
        ((IList<string>)validated.RequiredLaunchers!).Invoking(list => list.Add("evil.cmd")).Should().Throw<NotSupportedException>();
        ((IList<ReleasePayloadFile>)validated.Files).Invoking(list => list.Clear()).Should().Throw<NotSupportedException>();
        validated.Files.Should().HaveCount(manifest.Files!.Count);
    }

    [Theory]
    [InlineData(0, "1.1.0", "win-x64", "1.0.0", "1.0.0", 3)]
    [InlineData(1, "v1.1.0", "win-x64", "1.0.0", "1.0.0", 3)]
    [InlineData(1, "1.0.0", "win-x64", "1.0.0", "1.0.0", 3)]
    [InlineData(1, "1.1.0", "win-arm64", "1.0.0", "1.0.0", 3)]
    [InlineData(1, "1.1.0", "win-x64", "x", "1.0.0", 3)]
    [InlineData(1, "1.1.0", "win-x64", "1.2.0", "1.0.0", 3)]
    [InlineData(1, "1.1.0", "win-x64", "1.0.0", "1.2.0", 3)]
    [InlineData(1, "1.1.0", "win-x64", "1.0.0", "1.0.0", 0)]
    public void Validate_RejectsInvalidVersionRuntimeOrSchemaFields(int schema, string version, string runtime, string minimum, string rollback, int stateSchema)
    {
        var manifest = ValidManifest() with { SchemaVersion = schema, Version = version, RuntimeIdentifier = runtime, MinimumAutoUpdateVersion = minimum, RollbackCompatibleFromVersion = rollback, StateSchemaVersion = stateSchema };

        Invalid(manifest).ErrorCode.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Validate_RejectsWrongEntrypointsLaunchersAndPayloadContract()
    {
        Invalid(ValidManifest() with { EntryPoint = "app.exe" }).IsValid.Should().BeFalse();
        Invalid(ValidManifest() with { UpdaterEntryPoint = "updater.exe" }).IsValid.Should().BeFalse();
        Invalid(ValidManifest() with { RequiredLaunchers = ["start.cmd"] }).IsValid.Should().BeFalse();
        Invalid(ValidManifest() with { RequiredLaunchers = Launchers().Append("START.CMD").ToList() }).IsValid.Should().BeFalse();
        Invalid(ValidManifest() with { Files = [] }).IsValid.Should().BeFalse();
        Invalid(ValidManifest() with { Files = [new ReleasePayloadFile(UpdateReleaseContract.WindowsApplicationPath, 1, Hash())] }).IsValid.Should().BeFalse();
    }

    [Theory]
    [InlineData("logs/runtime.log")]
    [InlineData("data/state.json")]
    [InlineData("data/APPLIED-STATE.JSON")]
    [InlineData("runtime.conf")]
    [InlineData("secret.dpapi")]
    [InlineData("backup/file.txt")]
    [InlineData("file.bak")]
    [InlineData("tmp/file.txt")]
    [InlineData("file.temp")]
    [InlineData("candidate-metadata.json")]
    [InlineData("install.status.txt")]
    public void Validate_RejectsProtectedTemporaryAndBackupPayloadNames(string path)
    {
        var manifest = WithExtra(path);

        Invalid(manifest).IsValid.Should().BeFalse();
    }

    [Fact]
    public void Validate_RejectsUpdateMetadataButAllowsGuideNearMiss()
    {
        Invalid(WithExtra("data/UPDATE-METADATA.JSON")).IsValid.Should().BeFalse();
        var allowed = WithExtra("data/update-metadata-guide.json");
        ReleaseManifestValidator.Validate(allowed, Candidate, Current, 3, ArchivePaths(allowed)).IsValid.Should().BeTrue();
    }

    [Theory]
    [InlineData("catalog/runtime-log.txt")]
    [InlineData("templates/state.json.example")]
    [InlineData("configs/runtime.conf.txt")]
    [InlineData("backup-file.txt")]
    [InlineData("temporary/file.txt")]
    public void Validate_AllowsNearMissPayloadNames(string path)
    {
        var manifest = WithExtra(path);

        ReleaseManifestValidator.Validate(manifest, Candidate, Current, 3, ArchivePaths(manifest)).IsValid.Should().BeTrue();
    }

    [Fact]
    public void Validate_RejectsBadHashesDuplicatePathsAndManifestSelfHashing()
    {
        Invalid(WithExtra("readme.txt", sha256: "xyz")).IsValid.Should().BeFalse();
        Invalid(WithExtra("readme.txt", length: -1)).IsValid.Should().BeFalse();
        Invalid(WithExtra(UpdateReleaseContract.WindowsApplicationPath)).IsValid.Should().BeFalse();
        Invalid(WithExtra(UpdateReleaseContract.ReleaseManifestPath)).IsValid.Should().BeFalse();
    }

    [Fact]
    public void Validate_RejectsArchiveManifestSetMismatchAndCaseCollision()
    {
        var manifest = ValidManifest();
        var archive = ArchivePaths(manifest);

        ReleaseManifestValidator.Validate(manifest, Candidate, Current, 3, archive.Where(path => path != UpdateReleaseContract.ReleaseManifestPath).ToList()).IsValid.Should().BeFalse();
        ReleaseManifestValidator.Validate(manifest, Candidate, Current, 3, archive.Append("extra.txt").ToList()).IsValid.Should().BeFalse();
        ReleaseManifestValidator.Validate(manifest, Candidate, Current, 3, archive.Select(path => path == "scripts/start.ps1" ? "scripts/START.ps1" : path).ToList()).IsValid.Should().BeFalse();
        ReleaseManifestValidator.Validate(manifest, Candidate, Current, 3, archive.Append("scripts/START.ps1").ToList()).IsValid.Should().BeFalse();
    }

    [Fact]
    public void Validate_RejectsOverLimitPayloadCountBeforeConstructionOrElementAccess()
    {
        var action = () =>
        {
            var manifest = new ReleaseManifest(1, "1.1.0", "win-x64", "1.0.0", "1.0.0", 3,
                UpdateReleaseContract.WindowsApplicationPath, UpdateReleaseContract.WindowsUpdaterPath, Launchers(),
                new ThrowingReadOnlyList<ReleasePayloadFile>(WindowsReleasePathPolicy.MaximumArchiveEntries));
            return ReleaseManifestValidator.Validate(manifest, Candidate, Current, 3, [UpdateReleaseContract.ReleaseManifestPath]);
        };

        action.Should().NotThrow();
        action().ErrorCode.Should().Be("too_many_entries");
    }

    [Fact]
    public void Validate_RejectsOverLimitArchiveCountBeforeElementAccess()
    {
        var archive = new ThrowingReadOnlyList<string?>(WindowsReleasePathPolicy.MaximumArchiveEntries + 1);

        var result = ReleaseManifestValidator.Validate(ValidManifest(), Candidate, Current, 3, archive);

        result.IsValid.Should().BeFalse();
        result.ErrorCode.Should().Be("too_many_entries");
    }

    [Fact]
    public void Validate_AcceptsMaximumPayloadAndArchiveEntryBoundary()
    {
        var files = PayloadFiles();
        for (var index = files.Count; index < WindowsReleasePathPolicy.MaximumArchiveEntries - 1; index++)
        {
            files.Add(new ReleasePayloadFile($"payload/file-{index}.bin", index, Hash()));
        }

        var manifest = ValidManifest() with { Files = files };
        var archive = ArchivePaths(manifest);

        var result = ReleaseManifestValidator.Validate(manifest, Candidate, Current, 3, archive);

        result.IsValid.Should().BeTrue();
        result.Manifest!.Files.Should().HaveCount(WindowsReleasePathPolicy.MaximumArchiveEntries - 1);
        archive.Should().HaveCount(WindowsReleasePathPolicy.MaximumArchiveEntries);
    }

    private static ManifestValidationResult Invalid(ReleaseManifest manifest) =>
        ReleaseManifestValidator.Validate(manifest, Candidate, Current, 3, ArchivePaths(manifest));

    private static ReleaseManifest WithExtra(string path, long length = 1, string? sha256 = null)
    {
        var manifest = ValidManifest();
        return manifest with { Files = manifest.Files!.Append(new ReleasePayloadFile(path, length, sha256 ?? Hash())).ToList() };
    }

    private static ReleaseManifest ValidManifest() => new(
        1, "1.1.0", "win-x64", "1.0.0", "1.0.0", 3,
        UpdateReleaseContract.WindowsApplicationPath, UpdateReleaseContract.WindowsUpdaterPath,
        Launchers(), PayloadFiles());

    private static List<string> Launchers() => UpdateReleaseContract.RequiredLauncherPaths.ToList();

    private static List<ReleasePayloadFile> PayloadFiles() =>
        new List<ReleasePayloadFile>
        {
            new(UpdateReleaseContract.WindowsApplicationPath, 1, Hash()),
            new(UpdateReleaseContract.WindowsUpdaterPath, 1, Hash())
        }.Concat(Launchers().Select(path => new ReleasePayloadFile(path, 1, Hash()))).ToList();

    private static List<string?> ArchivePaths(ReleaseManifest manifest) =>
        manifest.Files!.Select(file => (string?)file.Path).Append(UpdateReleaseContract.ReleaseManifestPath).ToList();

    private static string Hash() => new('a', 64);

    private sealed class ThrowingReadOnlyList<T>(int count) : IReadOnlyList<T>
    {
        public int Count => count;
        public T this[int index] => throw new InvalidOperationException("Indexer must not be accessed.");
        public IEnumerator<T> GetEnumerator() => throw new InvalidOperationException("Enumerator must not be accessed.");
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
