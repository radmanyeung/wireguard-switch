using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class UpdatePackageValidatorTests : IDisposable
{
    private static readonly SemanticVersion CurrentVersion = new(1, 0, 0);
    private static readonly SemanticVersion CandidateVersion = new(1, 1, 0);
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "update-package-validator-tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task ValidateAsync_StopsAtInvalidSidecarBeforeLaterStages()
    {
        var fixture = CreateValidFixture();
        var reader = new FakeVersionReader(CandidateVersion.ToString());
        var disk = new FakeDiskSpaceProvider(long.MaxValue);
        var validator = new UpdatePackageValidator(reader, disk);
        var request = fixture.Request with { ChecksumSidecarBytes = Encoding.UTF8.GetBytes("bad") };

        var result = await validator.ValidateAsync(request);

        result.ErrorCode.Should().Be(UpdatePackageValidationError.InvalidChecksumSidecar);
        disk.CallCount.Should().Be(0);
        reader.Paths.Should().BeEmpty();
        Directory.Exists(request.CandidateRoot).Should().BeFalse();
    }

    [Fact]
    public async Task ValidateAsync_StopsAtArchiveHashMismatch()
    {
        var fixture = CreateValidFixture();
        var reader = new FakeVersionReader(CandidateVersion.ToString());
        var disk = new FakeDiskSpaceProvider(long.MaxValue);
        var validator = new UpdatePackageValidator(reader, disk);
        var request = fixture.Request with
        {
            ChecksumSidecarBytes = Sidecar(new string('0', 64))
        };

        var result = await validator.ValidateAsync(request);

        result.ErrorCode.Should().Be(UpdatePackageValidationError.ArchiveHashMismatch);
        disk.CallCount.Should().Be(0);
        reader.Paths.Should().BeEmpty();
    }

    [Fact]
    public async Task ValidateAsync_RejectsOversizedArchiveBeforeHashing()
    {
        Directory.CreateDirectory(_root);
        var archive = Path.Combine(_root, "oversized.zip");
        using (var stream = new FileStream(archive, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            stream.SetLength(UpdateNetworkLimits.ArchiveBytes + 1);
        var request = new UpdatePackageValidationRequest(
            archive,
            Sidecar(new string('0', 64)),
            CandidateVersion,
            CurrentVersion,
            1,
            0,
            Path.Combine(_root, "candidate"),
            _root,
            new UpdatePackageLimits(4096, 1024, 1024, 10, 0));
        var validator = new UpdatePackageValidator(
            new FakeVersionReader(CandidateVersion.ToString()),
            new FakeDiskSpaceProvider(long.MaxValue));

        var result = await validator.ValidateAsync(request);

        result.ErrorCode.Should().Be(UpdatePackageValidationError.ArchiveTooLarge);
    }

    [Fact]
    public async Task ValidateAsync_StopsAtZipPreflightFailureWithoutWrites()
    {
        var fixture = CreateValidFixture(extraEntries: [("../escape.txt", "bad")]);
        var reader = new FakeVersionReader(CandidateVersion.ToString());
        var disk = new FakeDiskSpaceProvider(long.MaxValue);
        var validator = new UpdatePackageValidator(reader, disk);

        var result = await validator.ValidateAsync(fixture.Request);

        result.ErrorCode.Should().Be(UpdatePackageValidationError.ZipPreflightFailed);
        Directory.Exists(fixture.Request.CandidateRoot).Should().BeFalse();
        disk.CallCount.Should().Be(0);
    }

    [Theory]
    [InlineData("malformed")]
    [InlineData("unknown")]
    [InlineData("case_variant")]
    [InlineData("duplicate")]
    [InlineData("root_array")]
    [InlineData("missing")]
    [InlineData("wrong_kind")]
    public async Task ValidateAsync_RejectsNonStrictManifestJson(string mutation)
    {
        var fixture = CreateValidFixture(manifestMutation: mutation);
        var disk = new FakeDiskSpaceProvider(long.MaxValue);
        var validator = new UpdatePackageValidator(
            new FakeVersionReader(CandidateVersion.ToString()), disk);

        var result = await validator.ValidateAsync(fixture.Request);

        result.ErrorCode.Should().Be(UpdatePackageValidationError.InvalidManifestJson);
        Directory.Exists(fixture.Request.CandidateRoot).Should().BeFalse();
        disk.CallCount.Should().Be(0);
    }

    [Fact]
    public async Task ValidateAsync_RejectsBounded4096FileJsonBombBeforeLaterStages()
    {
        var fixture = CreateValidFixture(manifestMutation: "files_bomb");
        new FileInfo(fixture.Request.ArchivePath).Length.Should().BeLessThan(UpdateNetworkLimits.MetadataBytes);
        var disk = new FakeDiskSpaceProvider(long.MaxValue);
        var reader = new FakeVersionReader(CandidateVersion.ToString());
        var validator = new UpdatePackageValidator(reader, disk);

        var result = await validator.ValidateAsync(fixture.Request);

        result.ErrorCode.Should().Be(UpdatePackageValidationError.InvalidManifestJson);
        disk.CallCount.Should().Be(0);
        reader.Paths.Should().BeEmpty();
        Directory.Exists(fixture.Request.CandidateRoot).Should().BeFalse();
    }

    [Theory]
    [InlineData("schema")]
    [InlineData("rid")]
    [InlineData("compatibility")]
    public async Task ValidateAsync_RejectsManifestContractFailures(string mutation)
    {
        var fixture = CreateValidFixture(manifestMutation: mutation);
        var disk = new FakeDiskSpaceProvider(long.MaxValue);
        var validator = new UpdatePackageValidator(
            new FakeVersionReader(CandidateVersion.ToString()), disk);

        var result = await validator.ValidateAsync(fixture.Request);

        result.ErrorCode.Should().Be(UpdatePackageValidationError.InvalidManifest);
        Directory.Exists(fixture.Request.CandidateRoot).Should().BeFalse();
        disk.CallCount.Should().Be(0);
    }

    [Fact]
    public async Task ValidateAsync_AcceptsExactDiskBoundary()
    {
        var fixture = CreateValidFixture();
        var required = fixture.ArchiveBytes
            + fixture.ExpandedBytes
            + fixture.Request.CurrentManagedBytes
            + fixture.Request.Limits.ReserveBytes;
        var validator = new UpdatePackageValidator(
            new FakeVersionReader(CandidateVersion.ToString()),
            new FakeDiskSpaceProvider(required));

        var result = await validator.ValidateAsync(fixture.Request);

        result.Success.Should().BeTrue();
        result.Package!.RequiredDiskBytes.Should().Be(required);
    }

    [Fact]
    public async Task ValidateAsync_RejectsOneByteBelowDiskBoundaryBeforeExtraction()
    {
        var fixture = CreateValidFixture();
        var required = fixture.ArchiveBytes
            + fixture.ExpandedBytes
            + fixture.Request.CurrentManagedBytes
            + fixture.Request.Limits.ReserveBytes;
        var validator = new UpdatePackageValidator(
            new FakeVersionReader(CandidateVersion.ToString()),
            new FakeDiskSpaceProvider(required - 1));

        var result = await validator.ValidateAsync(fixture.Request);

        result.ErrorCode.Should().Be(UpdatePackageValidationError.InsufficientDiskSpace);
        Directory.Exists(fixture.Request.CandidateRoot).Should().BeFalse();
    }

    [Theory]
    [InlineData("length", UpdatePackageValidationError.PayloadLengthMismatch)]
    [InlineData("hash", UpdatePackageValidationError.PayloadHashMismatch)]
    public async Task ValidateAsync_PostExtractionPayloadFailureRollsBackCandidate(
        string mutation,
        UpdatePackageValidationError expected)
    {
        var fixture = CreateValidFixture(manifestMutation: mutation);
        var reader = new FakeVersionReader(CandidateVersion.ToString());
        var validator = new UpdatePackageValidator(
            reader,
            new FakeDiskSpaceProvider(long.MaxValue));

        var result = await validator.ValidateAsync(fixture.Request);

        result.ErrorCode.Should().Be(expected);
        Directory.Exists(fixture.Request.CandidateRoot).Should().BeFalse();
        reader.Paths.Should().BeEmpty();
    }

    [Theory]
    [InlineData("app")]
    [InlineData("helper")]
    [InlineData("suffix")]
    [InlineData("null")]
    public async Task ValidateAsync_RejectsWrongExecutableProductVersionAndRollsBack(
        string mutation)
    {
        var fixture = CreateValidFixture();
        var reader = new FakeVersionReader(CandidateVersion.ToString(), mutation);
        var validator = new UpdatePackageValidator(
            reader,
            new FakeDiskSpaceProvider(long.MaxValue));

        var result = await validator.ValidateAsync(fixture.Request);

        result.ErrorCode.Should().Be(UpdatePackageValidationError.ProductVersionMismatch);
        Directory.Exists(fixture.Request.CandidateRoot).Should().BeFalse();
    }

    [Fact]
    public async Task ValidateAsync_CancellationAfterExtractionRollsBackCandidate()
    {
        var fixture = CreateValidFixture();
        using var cancellation = new CancellationTokenSource();
        var reader = new FakeVersionReader(
            CandidateVersion.ToString(),
            cancelOnFirstRead: cancellation);
        var validator = new UpdatePackageValidator(
            reader,
            new FakeDiskSpaceProvider(long.MaxValue));

        var result = await validator.ValidateAsync(
            fixture.Request,
            cancellation.Token);

        result.ErrorCode.Should().Be(UpdatePackageValidationError.Cancelled);
        Directory.Exists(fixture.Request.CandidateRoot).Should().BeFalse();
    }

    [Fact]
    public async Task ValidateAsync_SuccessReturnsImmutablePackageAndDoesNotTouchLiveRoot()
    {
        var fixture = CreateValidFixture();
        var liveRoot = Path.Combine(_root, "live");
        Directory.CreateDirectory(liveRoot);
        File.WriteAllText(Path.Combine(liveRoot, "keep.txt"), "live");
        var reader = new FakeVersionReader(CandidateVersion.ToString());
        var disk = new FakeDiskSpaceProvider(long.MaxValue);
        var validator = new UpdatePackageValidator(reader, disk);

        var result = await validator.ValidateAsync(fixture.Request);

        result.Success.Should().BeTrue();
        result.Package!.Version.Should().Be(CandidateVersion);
        result.Package.ArchiveSha256.Should().Be(fixture.ArchiveSha256);
        result.Package.NewManifestSha256.Should().HaveLength(64);
        result.Package.ManifestPath.Should().Be(
            Path.GetFullPath(Path.Combine(
                fixture.Request.CandidateRoot,
                UpdateReleaseContract.ReleaseManifestPath)));
        SHA256.HashData(File.ReadAllBytes(result.Package.ManifestPath))
            .Should().Equal(Convert.FromHexString(result.Package.NewManifestSha256));
        result.Package.CandidateRoot.Should().Be(Path.GetFullPath(fixture.Request.CandidateRoot));
        result.Package.Manifest.Files.Should().NotBeSameAs(fixture.ManifestFiles);
        Directory.GetFiles(fixture.Request.CandidateRoot, "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(fixture.Request.CandidateRoot, path).Replace('\\', '/'))
            .Should().BeEquivalentTo(
                fixture.ManifestFiles.Select(file => file.Path)
                    .Append(UpdateReleaseContract.ReleaseManifestPath));
        File.ReadAllText(Path.Combine(liveRoot, "keep.txt")).Should().Be("live");
        disk.CallCount.Should().Be(1);
        reader.Paths.Should().HaveCount(2);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private Fixture CreateValidFixture(
        string? manifestMutation = null,
        IReadOnlyList<(string path, string content)>? extraEntries = null)
    {
        Directory.CreateDirectory(_root);
        var payloads = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            [UpdateReleaseContract.WindowsApplicationPath] = Encoding.UTF8.GetBytes("app"),
            [UpdateReleaseContract.WindowsUpdaterPath] = Encoding.UTF8.GetBytes("helper"),
            ["install.cmd"] = Encoding.UTF8.GetBytes("install"),
            ["start.cmd"] = Encoding.UTF8.GetBytes("start"),
            ["start-admin.cmd"] = Encoding.UTF8.GetBytes("admin"),
            ["start-safe.cmd"] = Encoding.UTF8.GetBytes("safe"),
            ["scripts/install.ps1"] = Encoding.UTF8.GetBytes("install-ps"),
            ["scripts/start.ps1"] = Encoding.UTF8.GetBytes("start-ps")
        };
        var manifestFiles = payloads
            .Select(pair => new ReleasePayloadFile(
                pair.Key,
                pair.Value.LongLength,
                Hex(SHA256.HashData(pair.Value))))
            .ToArray();

        if (manifestMutation == "length")
        {
            manifestFiles[0] = manifestFiles[0] with
            {
                Length = manifestFiles[0].Length + 1
            };
        }
        else if (manifestMutation == "hash")
        {
            manifestFiles[0] = manifestFiles[0] with { Sha256 = new string('0', 64) };
        }

        var manifest = new ReleaseManifest(
            manifestMutation == "schema" ? 2 : 1,
            CandidateVersion.ToString(),
            manifestMutation == "rid" ? "linux-x64" : UpdateReleaseContract.WindowsRuntimeIdentifier,
            manifestMutation == "compatibility" ? "1.0.1" : CurrentVersion.ToString(),
            CurrentVersion.ToString(),
            1,
            UpdateReleaseContract.WindowsApplicationPath,
            UpdateReleaseContract.WindowsUpdaterPath,
            UpdateReleaseContract.RequiredLauncherPaths,
            manifestFiles);
        var manifestBytes = SerializeManifest(manifest, manifestMutation);
        var archive = Path.Combine(_root, Guid.NewGuid().ToString("N") + ".zip");
        using (var file = new FileStream(archive, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        using (var zip = new ZipArchive(file, ZipArchiveMode.Create))
        {
            WriteEntry(zip, UpdateReleaseContract.ReleaseManifestPath, manifestBytes);
            foreach (var payload in payloads)
            {
                WriteEntry(zip, payload.Key, payload.Value);
            }

            foreach (var extra in extraEntries ?? [])
            {
                WriteEntry(zip, extra.path, Encoding.UTF8.GetBytes(extra.content));
            }
        }

        var archiveBytes = new FileInfo(archive).Length;
        var archiveSha = Hex(SHA256.HashData(File.ReadAllBytes(archive)));
        var expanded = manifestBytes.LongLength + payloads.Values.Sum(value => value.LongLength)
            + (extraEntries?.Sum(entry => Encoding.UTF8.GetByteCount(entry.content)) ?? 0);
        var request = new UpdatePackageValidationRequest(
            archive,
            Sidecar(archiveSha),
            CandidateVersion,
            CurrentVersion,
            1,
            CurrentManagedBytes: 7,
            Path.Combine(_root, "candidate-" + Guid.NewGuid().ToString("N")),
            _root,
            new UpdatePackageLimits(4096, 4 * 1024 * 1024, 8 * 1024 * 1024, 1000d, 11));
        return new Fixture(
            request,
            archiveSha,
            archiveBytes,
            expanded,
            manifestFiles);
    }

    private static byte[] SerializeManifest(ReleaseManifest manifest, string? mutation)
    {
        var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        var json = JsonSerializer.Serialize(manifest, options);
        if (mutation == "files_bomb")
        {
            var files = Enumerable.Range(0, 4096)
                .Select(index => new ReleasePayloadFile($"f{index}", 0, new string('0', 64)))
                .ToArray();
            return JsonSerializer.SerializeToUtf8Bytes(manifest with { Files = files }, options);
        }

        return mutation switch
        {
            "malformed" => Encoding.UTF8.GetBytes("{"),
            "unknown" => Encoding.UTF8.GetBytes(json[..^1] + ",\"unknown\":1}"),
            "case_variant" => Encoding.UTF8.GetBytes(
                json.Replace("\"schemaVersion\":", "\"SchemaVersion\":", StringComparison.Ordinal)),
            "duplicate" => Encoding.UTF8.GetBytes(
                json[..^1] + ",\"schemaVersion\":1}"),
            "root_array" => Encoding.UTF8.GetBytes("[]"),
            "missing" => Encoding.UTF8.GetBytes(
                json.Replace("\"schemaVersion\":1,", string.Empty, StringComparison.Ordinal)),
            "wrong_kind" => Encoding.UTF8.GetBytes(
                json.Replace("\"schemaVersion\":1", "\"schemaVersion\":\"1\"", StringComparison.Ordinal)),
            _ => Encoding.UTF8.GetBytes(json)
        };
    }

    private static void WriteEntry(ZipArchive zip, string path, byte[] content)
    {
        var entry = zip.CreateEntry(path, CompressionLevel.NoCompression);
        using var output = entry.Open();
        output.Write(content);
    }

    private static byte[] Sidecar(string digest) =>
        Encoding.UTF8.GetBytes(
            $"{digest}  {UpdateReleaseContract.WindowsAssetName}\n");

    private static string Hex(byte[] bytes) =>
        Convert.ToHexString(bytes).ToLowerInvariant();

    private sealed record Fixture(
        UpdatePackageValidationRequest Request,
        string ArchiveSha256,
        long ArchiveBytes,
        long ExpandedBytes,
        IReadOnlyList<ReleasePayloadFile> ManifestFiles);

    private sealed class FakeDiskSpaceProvider(long availableBytes) : IDiskSpaceProvider
    {
        public int CallCount { get; private set; }

        public long GetAvailableBytes(string path)
        {
            CallCount++;
            return availableBytes;
        }
    }

    private sealed class FakeVersionReader : IExecutableProductVersionReader
    {
        private readonly string _validVersion;
        private readonly string? _mutation;
        private readonly CancellationTokenSource? _cancelOnFirstRead;

        public FakeVersionReader(
            string validVersion,
            string? mutation = null,
            CancellationTokenSource? cancelOnFirstRead = null)
        {
            _validVersion = validVersion;
            _mutation = mutation;
            _cancelOnFirstRead = cancelOnFirstRead;
        }

        public IReadOnlyList<string> Paths => _paths.AsReadOnly();
        private readonly List<string> _paths = [];

        public string? ReadProductVersion(string executablePath)
        {
            _paths.Add(executablePath);
            _cancelOnFirstRead?.Cancel();
            if (_mutation == "null")
            {
                return null;
            }

            if (_mutation == "suffix")
            {
                return _validVersion + "+build";
            }

            if (_mutation == "app"
                && executablePath.EndsWith(
                    UpdateReleaseContract.WindowsApplicationPath.Replace('/', Path.DirectorySeparatorChar),
                    StringComparison.OrdinalIgnoreCase))
            {
                return "9.9.9";
            }

            if (_mutation == "helper"
                && executablePath.EndsWith(
                    UpdateReleaseContract.WindowsUpdaterPath.Replace('/', Path.DirectorySeparatorChar),
                    StringComparison.OrdinalIgnoreCase))
            {
                return "9.9.9";
            }

            return _validVersion;
        }
    }
}
