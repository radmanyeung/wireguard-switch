using System.Text.Json;
using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Staging;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class LocalUpdateMetadataStoreTests
{
    [Fact]
    public void Load_MissingMetadataReturnsEmpty()
    {
        using var fixture = new StoreFixture();

        fixture.Store.Load().Should().Be(LocalUpdateMetadata.Empty);
    }

    [Fact]
    public void SaveAndLoad_RoundTripsAllCoreFieldsAndNormalizesAutomaticTimeToUtc()
    {
        using var fixture = new StoreFixture();
        var staged = fixture.Staged(PendingUpdateSource.Automatic);
        var metadata = new LocalUpdateMetadata(new DateTimeOffset(2026, 7, 29, 9, 0, 0, TimeSpan.FromHours(8)), staged, "download_failed", true);

        var save = fixture.Store.Save(metadata);
        save.Success.Should().BeTrue($"the secure metadata save returned {save.Error}");
        var loaded = fixture.Store.Load();

        loaded.LastAutomaticAttemptUtc.Should().Be(new DateTimeOffset(2026, 7, 29, 1, 0, 0, TimeSpan.Zero));
        loaded.StagedUpdate.Should().Be(staged);
        loaded.LastError.Should().Be("download_failed");
        loaded.ProtectedRemovalPending.Should().BeTrue();
    }

    [Fact]
    public void SaveAndLoad_SecondSaveAtomicallyReplacesTheExistingMetadataFile()
    {
        using var fixture = new StoreFixture();
        var first = new LocalUpdateMetadata(null, fixture.Staged(PendingUpdateSource.Automatic));
        var second = new LocalUpdateMetadata(null, fixture.Staged(PendingUpdateSource.Manual), "download_failed", true);

        fixture.Store.Save(first).Success.Should().BeTrue();
        var firstBytes = File.ReadAllBytes(fixture.MetadataPath);

        var replacement = fixture.Store.Save(second);

        replacement.Success.Should().BeTrue($"the secure metadata replacement returned {replacement.Error}");
        File.ReadAllBytes(fixture.MetadataPath).Should().NotEqual(firstBytes);
        fixture.Store.Load().Should().Be(second);
        Directory.GetFiles(Path.GetDirectoryName(fixture.MetadataPath)!, "update-metadata.json.*.tmp")
            .Should().BeEmpty();
    }

    [Fact]
    public void Save_PreservesAutomaticTimestampForManualSchedulingMetadata()
    {
        using var fixture = new StoreFixture();
        var last = DateTimeOffset.UtcNow;
        var metadata = new LocalUpdateMetadata(last, fixture.Staged(PendingUpdateSource.Manual));

        fixture.Store.Save(metadata).Success.Should().BeTrue();

        fixture.Store.Load().LastAutomaticAttemptUtc.Should().Be(last);
    }

    [Theory]
    [InlineData("")]
    [InlineData("{")]
    [InlineData("{\"lastError\":\"a\",\"lastError\":\"b\",\"stagedUpdate\":null,\"lastAutomaticAttemptUtc\":null,\"protectedRemovalPending\":false}")]
    [InlineData("{\"lastAutomaticAttemptUtc\":null,\"stagedUpdate\":null,\"lastError\":5,\"protectedRemovalPending\":false}")]
    public void Load_CorruptMetadataReturnsEmptyWithoutChangingBytes(string payload)
    {
        using var fixture = new StoreFixture();
        File.WriteAllText(fixture.MetadataPath, payload);

        fixture.Store.Load().Should().Be(LocalUpdateMetadata.Empty);
        File.ReadAllText(fixture.MetadataPath).Should().Be(payload);
    }

    [Fact]
    public void Load_OversizedMetadataReturnsEmptyWithoutChangingBytes()
    {
        using var fixture = new StoreFixture();
        var bytes = new byte[(2 * 1024 * 1024) + 1];
        File.WriteAllBytes(fixture.MetadataPath, bytes);

        fixture.Store.Load().Should().Be(LocalUpdateMetadata.Empty);
        new FileInfo(fixture.MetadataPath).Length.Should().Be(bytes.Length);
    }

    [Theory]
    [InlineData("UPPER")]
    [InlineData("error-url_https")]
    [InlineData("error-secret-token")]
    [InlineData("secret_token_abc123")]
    [InlineData("download_failed_extra")]
    public void Load_RejectsInvalidOrSensitiveErrorCodes(string error)
    {
        using var fixture = new StoreFixture();
        fixture.WriteWithError(error);

        fixture.Store.Load().Should().Be(LocalUpdateMetadata.Empty);
    }

    [Fact]
    public void Save_SanitizesArbitraryErrorText()
    {
        using var fixture = new StoreFixture();
        var unsafeText = "https://user:secret@example.test/route";

        fixture.Store.Save(new LocalUpdateMetadata(null, null, unsafeText)).Success.Should().BeTrue();

        File.ReadAllText(fixture.MetadataPath).Should().NotContain(unsafeText);
        fixture.Store.Load().LastError.Should().BeNull();
    }

    [Fact]
    public void Save_SanitizesCredentialShapedAllowedSyntaxErrorCode()
    {
        using var fixture = new StoreFixture();
        const string unsafeCode = "secret_token_abc123";

        fixture.Store.Save(new LocalUpdateMetadata(null, null, unsafeCode)).Success.Should().BeTrue();

        File.ReadAllText(fixture.MetadataPath).Should().NotContain(unsafeCode);
        fixture.Store.Load().LastError.Should().BeNull();
    }

    [Theory]
    [InlineData("archive")]
    [InlineData("checksum")]
    [InlineData("manifest")]
    [InlineData("candidate")]
    public void Load_RejectsEveryForgedSerializedStagedPath(string mutation)
    {
        using var fixture = new StoreFixture();
        fixture.WriteValidRaw(mutation);

        fixture.Store.Load().Should().Be(LocalUpdateMetadata.Empty);
    }

    [Theory]
    [InlineData("versionLeadingZero")]
    [InlineData("versionNegative")]
    [InlineData("versionOverflow")]
    [InlineData("archiveHashUppercase")]
    [InlineData("archiveHashShort")]
    [InlineData("manifestHashNonHex")]
    [InlineData("manifestHashLong")]
    [InlineData("sourceNumber")]
    [InlineData("sourceNumericString")]
    public void Load_RejectsVersionHashAndEnumBoundaryViolations(string mutation)
    {
        using var fixture = new StoreFixture();
        fixture.WriteValidRaw(mutation);

        fixture.Store.Load().Should().Be(LocalUpdateMetadata.Empty);
    }

    [Theory]
    [InlineData("rootUnknown")]
    [InlineData("rootDuplicate")]
    [InlineData("stagedUnknown")]
    [InlineData("stagedDuplicate")]
    public void Load_RejectsUnknownAndDuplicatePropertiesAtEveryObjectLevel(string mutation)
    {
        using var fixture = new StoreFixture();
        fixture.WriteValidRaw(mutation);

        fixture.Store.Load().Should().Be(LocalUpdateMetadata.Empty);
    }

    [Theory]
    [InlineData("2026-07-29T01:00:00.0000000Z")]
    [InlineData("2026-07-29T09:00:00.0000000+08:00")]
    [InlineData("0000-01-01T00:00:00.0000000+00:00")]
    [InlineData("10000-01-01T00:00:00.0000000+00:00")]
    [InlineData("2026-07-29T01:00:00+00:00")]
    public void Load_RejectsNonCanonicalOrOutOfRangeUtcTimestamps(string timestamp)
    {
        using var fixture = new StoreFixture();
        fixture.WriteValidRaw(lastAutomaticAttemptUtc: timestamp);

        fixture.Store.Load().Should().Be(LocalUpdateMetadata.Empty);
    }

    [Theory]
    [InlineData("0001-01-01T00:00:00.0000000+00:00")]
    [InlineData("9999-12-31T23:59:59.9999999+00:00")]
    public void Load_AcceptsCanonicalUtcRangeBoundaries(string timestamp)
    {
        using var fixture = new StoreFixture();
        fixture.WriteValidRaw(lastAutomaticAttemptUtc: timestamp);

        fixture.Store.Load().LastAutomaticAttemptUtc.Should().Be(DateTimeOffset.Parse(timestamp));
    }

    [Fact]
    public void Load_AcceptsTheUnmutatedStrictRawDto()
    {
        using var fixture = new StoreFixture();
        fixture.WriteValidRaw();

        fixture.Store.Load().StagedUpdate.Should().Be(fixture.Staged(PendingUpdateSource.Automatic));
    }

    [Fact]
    public void Save_WritesAtomicallyWithoutLeavingOwnedTemporaryFiles()
    {
        using var fixture = new StoreFixture();

        fixture.Store.Save(new LocalUpdateMetadata(null, fixture.Staged(PendingUpdateSource.Automatic))).Success.Should().BeTrue();

        File.Exists(fixture.MetadataPath).Should().BeTrue();
        Directory.GetFiles(Path.GetDirectoryName(fixture.MetadataPath)!, "update-metadata.json.*.tmp").Should().BeEmpty();
    }

    [Fact]
    public void SecureFileSystem_FirstMoveCommitsTheExactCreatedHandleInThePinnedDirectory()
    {
        using var fixture = new StoreFixture();
        var fileSystem = new WindowsLocalUpdateMetadataFileSystem();
        var productRoot = Path.GetDirectoryName(fixture.MetadataPath)!;
        var temporaryPath = Path.Combine(productRoot, $"update-metadata.json.{Guid.NewGuid():N}.tmp");
        fileSystem.OpenDirectory(productRoot, out var directory).Should().Be(LocalUpdateMetadataOpenStatus.Opened);
        using (directory!)
        {
            fileSystem.CreateNewTemp(directory!, temporaryPath, out var temporary).Should().Be(LocalUpdateMetadataOpenStatus.Opened);
            using (temporary!)
            {
                fileSystem.Write(temporary!, "metadata"u8.ToArray());
                fileSystem.FlushToDisk(temporary!);

                fileSystem.Move(directory!, temporary!, fixture.MetadataPath).Should().BeTrue();
                fileSystem.IsCommitted(directory!, temporary!, fixture.MetadataPath).Should().BeTrue();
            }
        }
    }

    [Fact]
    public void Load_HoldsAndRevalidatesTheDirectoryAndFileLeaseAroundTheBoundedRead()
    {
        var fileSystem = new RecordingMetadataFileSystem();
        using var fixture = new StoreFixture(fileSystem);
        fileSystem.DestinationBytes = fixture.ValidMetadataBytes();

        var loaded = fixture.Store.Load();

        loaded.StagedUpdate.Should().Be(fixture.Staged(PendingUpdateSource.Automatic));
        fileSystem.Calls.Should().ContainInOrder(
            "OpenDirectory", "IsSafeDirectory", "OpenRead", "IsSafeRead",
            "ReadBounded", "IsSafeRead", "IsSafeDirectory");
    }

    [Fact]
    public void Load_RejectsAFileIdentitySwapAfterTheBoundedRead()
    {
        var fileSystem = new RecordingMetadataFileSystem { SwapReadIdentityAfterRead = true };
        using var fixture = new StoreFixture(fileSystem);
        fileSystem.DestinationBytes = fixture.ValidMetadataBytes();

        fixture.Store.Load().Should().Be(LocalUpdateMetadata.Empty);

        fileSystem.Calls.Should().ContainInOrder("ReadBounded", "IsSafeRead");
    }

    [Fact]
    public void Load_RejectsAnAncestorFinalPathSwapAfterTheBoundedRead()
    {
        var fileSystem = new RecordingMetadataFileSystem { SwapDirectoryAfterRead = true };
        using var fixture = new StoreFixture(fileSystem);
        fileSystem.DestinationBytes = fixture.ValidMetadataBytes();

        fixture.Store.Load().Should().Be(LocalUpdateMetadata.Empty);

        fileSystem.Calls.Should().ContainInOrder("ReadBounded", "IsSafeRead", "IsSafeDirectory");
    }

    [Fact]
    public void Load_RejectsAnUnsafeNoFollowOpenWithoutReadingIt()
    {
        var fileSystem = new RecordingMetadataFileSystem { ReadOpenIsUnsafe = true };
        using var fixture = new StoreFixture(fileSystem);
        fileSystem.DestinationBytes = fixture.ValidMetadataBytes();

        fixture.Store.Load().Should().Be(LocalUpdateMetadata.Empty);

        fileSystem.Calls.Should().NotContain("ReadBounded");
    }

    [Theory]
    [InlineData(false, "Move")]
    [InlineData(true, "Replace")]
    public void Save_UsesTheCorrectAtomicCommitForFirstWriteAndReplacement(bool destinationExists, string expectedCommit)
    {
        var fileSystem = new RecordingMetadataFileSystem
        {
            DestinationBytes = destinationExists ? "old-bytes"u8.ToArray() : null
        };
        using var fixture = new StoreFixture(fileSystem);

        fixture.Store.Save(new LocalUpdateMetadata(null, null, "download_failed")).Success.Should().BeTrue();

        fileSystem.CommitOperation.Should().Be(expectedCommit);
        fileSystem.DestinationBytes.Should().NotBeNull().And.NotEqual("old-bytes"u8.ToArray());
        fileSystem.OwnedTempExists.Should().BeFalse();
        fileSystem.DeleteOwnedCalled.Should().BeFalse();
        Path.GetDirectoryName(fileSystem.CreatedTempPath).Should().Be(Path.GetDirectoryName(fixture.MetadataPath));
        Path.GetFileName(fileSystem.CreatedTempPath).Should().MatchRegex("^update-metadata\\.json\\.[0-9a-f]{32}\\.tmp$");
    }

    [Theory]
    [InlineData(MetadataFailurePoint.Write, true, "Write")]
    [InlineData(MetadataFailurePoint.Flush, true, "Flush")]
    [InlineData(MetadataFailurePoint.Move, false, "Move")]
    [InlineData(MetadataFailurePoint.Replace, true, "Replace")]
    public void Save_EveryOrderedIoFailurePreservesDestinationAndDeletesOnlyTheOwnedTemp(
        MetadataFailurePoint failurePoint,
        bool destinationExists,
        string failureCall)
    {
        var oldBytes = destinationExists ? "old-destination"u8.ToArray() : null;
        var fileSystem = new RecordingMetadataFileSystem
        {
            DestinationBytes = oldBytes?.ToArray(),
            FailurePoint = failurePoint
        };
        using var fixture = new StoreFixture(fileSystem);

        var result = fixture.Store.Save(new LocalUpdateMetadata(null, null, "download_failed"));

        result.Error.Should().Be(LocalUpdateMetadataStoreError.IoFailure);
        fileSystem.DestinationBytes.Should().Equal(oldBytes);
        fileSystem.Calls.Should().ContainInOrder("CreateNewTemp", failureCall, "DeleteOwned");
        fileSystem.DeleteOwnedCalled.Should().BeTrue();
        fileSystem.OwnedTempExists.Should().BeFalse();
    }

    [Fact]
    public void Save_RejectsADestinationIdentitySwapImmediatelyBeforeReplace()
    {
        var fileSystem = new RecordingMetadataFileSystem
        {
            DestinationBytes = "old-destination"u8.ToArray(),
            SwapDestinationBeforeCommit = true,
            SwappedDestinationBytes = "attacker-replacement"u8.ToArray()
        };
        using var fixture = new StoreFixture(fileSystem);

        var result = fixture.Store.Save(new LocalUpdateMetadata(null, null, "download_failed"));

        result.Error.Should().Be(LocalUpdateMetadataStoreError.UnsafePath);
        fileSystem.DestinationBytes.Should().Equal("attacker-replacement"u8.ToArray());
        fileSystem.DeleteOwnedCalled.Should().BeTrue();
    }

    [Fact]
    public void Save_RejectsADestinationIdentitySwapOnlyInTheHighHalfOfThe128BitFileId()
    {
        var oldBytes = "old-destination"u8.ToArray();
        var fileSystem = new RecordingMetadataFileSystem
        {
            DestinationBytes = oldBytes.ToArray(),
            SwapDestinationHighFileIdBeforeCommit = true
        };
        using var fixture = new StoreFixture(fileSystem);

        var result = fixture.Store.Save(new LocalUpdateMetadata(null, null, "download_failed"));

        result.Error.Should().Be(LocalUpdateMetadataStoreError.UnsafePath);
        fileSystem.DestinationBytes.Should().Equal(oldBytes);
        fileSystem.DeleteOwnedCalled.Should().BeTrue();
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void Save_PostCommitVerificationFailureLeavesTheCommittedDestinationAndNeverDeletesIt(
        bool destinationExists,
        bool verificationThrows)
    {
        var oldBytes = destinationExists
            ? "old-destination"u8.ToArray()
            : null;
        var fileSystem = new RecordingMetadataFileSystem
        {
            DestinationBytes = oldBytes,
            CommitVerificationFails = !verificationThrows,
            CommitVerificationThrows = verificationThrows
        };
        using var fixture = new StoreFixture(fileSystem);

        var result = fixture.Store.Save(
            new LocalUpdateMetadata(
                null,
                null,
                "download_failed"));

        result.Success.Should().BeFalse();
        fileSystem.DestinationBytes.Should().NotBeNull();
        if (oldBytes is not null)
        {
            fileSystem.DestinationBytes.Should().NotEqual(
                oldBytes);
        }
        fileSystem.CommitOperation.Should().Be(
            destinationExists ? "Replace" : "Move");
        fileSystem.DeleteOwnedCalled.Should().BeFalse();
        fileSystem.OwnedTempExists.Should().BeFalse();
    }

    [Fact]
    public void Save_RejectsADestinationAppearingImmediatelyBeforeFirstMove()
    {
        var fileSystem = new RecordingMetadataFileSystem
        {
            DestinationAppearsBeforeMove = true,
            SwappedDestinationBytes = "appeared-destination"u8.ToArray()
        };
        using var fixture = new StoreFixture(fileSystem);

        var result = fixture.Store.Save(new LocalUpdateMetadata(null, null, "download_failed"));

        result.Error.Should().Be(LocalUpdateMetadataStoreError.UnsafePath);
        fileSystem.DestinationBytes.Should().Equal("appeared-destination"u8.ToArray());
        fileSystem.DeleteOwnedCalled.Should().BeTrue();
    }

    [Fact]
    public void Save_RejectsAnAncestorSwapAfterFlushBeforeCommit()
    {
        var oldBytes = "old-destination"u8.ToArray();
        var fileSystem = new RecordingMetadataFileSystem
        {
            DestinationBytes = oldBytes.ToArray(),
            SwapDirectoryAfterFlush = true
        };
        using var fixture = new StoreFixture(fileSystem);

        var result = fixture.Store.Save(new LocalUpdateMetadata(null, null, "download_failed"));

        result.Error.Should().Be(LocalUpdateMetadataStoreError.UnsafePath);
        fileSystem.DestinationBytes.Should().Equal(oldBytes);
        fileSystem.Calls.Should().NotContain("Replace");
        fileSystem.DeleteOwnedCalled.Should().BeTrue();
    }

    [Fact]
    public void Save_TempIdentitySwapCannotCauseCleanupToDeleteTheReplacementPath()
    {
        var oldBytes = "old-destination"u8.ToArray();
        var fileSystem = new RecordingMetadataFileSystem
        {
            DestinationBytes = oldBytes.ToArray(),
            SwapTempAfterFlush = true
        };
        using var fixture = new StoreFixture(fileSystem);

        var result = fixture.Store.Save(new LocalUpdateMetadata(null, null, "download_failed"));

        result.Error.Should().Be(LocalUpdateMetadataStoreError.UnsafePath);
        fileSystem.DestinationBytes.Should().Equal(oldBytes);
        fileSystem.DeleteOwnedCalled.Should().BeTrue();
        fileSystem.OwnedTempExists.Should().BeFalse();
        fileSystem.UnownedTempReplacementExists.Should().BeTrue();
        fileSystem.UnownedTempReplacementDeleted.Should().BeFalse();
    }

    [Fact]
    public void Save_RejectsAnUnsafeDestinationBeforeCreatingATempFile()
    {
        var fileSystem = new RecordingMetadataFileSystem { DestinationIsUnsafe = true };
        using var fixture = new StoreFixture(fileSystem);

        fixture.Store.Save(new LocalUpdateMetadata()).Error.Should().Be(LocalUpdateMetadataStoreError.UnsafePath);

        fileSystem.Calls.Should().NotContain("CreateNewTemp");
    }

    private sealed class StoreFixture : IDisposable
    {
        private readonly string _root;
        private readonly LocalUpdatePaths _paths;

        public StoreFixture(ILocalUpdateMetadataFileSystem? fileSystem = null)
        {
            _root = Path.Combine(Path.GetTempPath(), "WireguardSplitTunnel.WindowsUpdate.Tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_root);
            _paths = new LocalUpdatePaths(_root, new NeverReparse(), _ => DriveType.Fixed);
            Store = fileSystem is null
                ? new LocalUpdateMetadataStore(_paths)
                : new LocalUpdateMetadataStore(_paths, fileSystem);
            MetadataPath = _paths.GetLayout(new SemanticVersion(1, 2, 3)).Layout!.MetadataPath;
            Directory.CreateDirectory(Path.GetDirectoryName(MetadataPath)!);
        }

        public LocalUpdateMetadataStore Store { get; }
        public string MetadataPath { get; }

        public LocalStagedUpdate Staged(PendingUpdateSource source)
        {
            var layout = _paths.GetLayout(new SemanticVersion(1, 2, 3)).Layout!;
            return new LocalStagedUpdate(new SemanticVersion(1, 2, 3), layout.ArchivePath, layout.ChecksumPath, layout.ManifestPath, layout.CandidateRoot, Hash('a'), Hash('b'), source);
        }

        public byte[] ValidMetadataBytes()
        {
            WriteValidRaw();
            return File.ReadAllBytes(MetadataPath);
        }

        public void WriteWithError(string error)
        {
            var staged = Staged(PendingUpdateSource.Automatic);
            var dto = new
            {
                lastAutomaticAttemptUtc = (string?)null,
                stagedUpdate = new
                {
                    version = "1.2.3",
                    archivePath = staged.ArchivePath,
                    checksumPath = staged.ChecksumPath,
                    manifestPath = staged.ManifestPath,
                    candidateRoot = staged.CandidateRoot,
                    archiveSha256 = staged.ArchiveSha256,
                    newManifestSha256 = staged.NewManifestSha256,
                    source = "Automatic"
                },
                lastError = error,
                protectedRemovalPending = false
            };
            Directory.CreateDirectory(Path.GetDirectoryName(MetadataPath)!);
            File.WriteAllText(MetadataPath, JsonSerializer.Serialize(dto));
        }

        public void WriteValidRaw(string? mutation = null, string? lastAutomaticAttemptUtc = null)
        {
            var staged = Staged(PendingUpdateSource.Automatic);
            var stagedDto = new Dictionary<string, object?>
            {
                ["version"] = mutation switch
                {
                    "versionLeadingZero" => "01.2.3",
                    "versionNegative" => "-1.2.3",
                    "versionOverflow" => "2147483648.2.3",
                    _ => "1.2.3"
                },
                ["archivePath"] = mutation == "archive" ? "forged-archive" : staged.ArchivePath,
                ["checksumPath"] = mutation == "checksum" ? "forged-checksum" : staged.ChecksumPath,
                ["manifestPath"] = mutation == "manifest" ? "forged-manifest" : staged.ManifestPath,
                ["candidateRoot"] = mutation == "candidate" ? "forged-candidate" : staged.CandidateRoot,
                ["archiveSha256"] = mutation switch
                {
                    "archiveHashUppercase" => new string('A', 64),
                    "archiveHashShort" => new string('a', 63),
                    _ => staged.ArchiveSha256
                },
                ["newManifestSha256"] = mutation switch
                {
                    "manifestHashNonHex" => new string('g', 64),
                    "manifestHashLong" => new string('b', 65),
                    _ => staged.NewManifestSha256
                },
                ["source"] = mutation switch
                {
                    "sourceNumber" => 1,
                    "sourceNumericString" => "0",
                    _ => "Automatic"
                }
            };
            if (mutation == "stagedUnknown") stagedDto["unknown"] = true;

            var dto = new Dictionary<string, object?>
            {
                ["lastAutomaticAttemptUtc"] = lastAutomaticAttemptUtc,
                ["stagedUpdate"] = stagedDto,
                ["lastError"] = "download_failed",
                ["protectedRemovalPending"] = false
            };
            if (mutation == "rootUnknown") dto["unknown"] = true;

            Directory.CreateDirectory(Path.GetDirectoryName(MetadataPath)!);
            var json = JsonSerializer.Serialize(dto);
            if (mutation == "rootDuplicate")
            {
                json = json.Replace("\"lastError\":", "\"lastError\":null,\"lastError\":", StringComparison.Ordinal);
            }
            else if (mutation == "stagedDuplicate")
            {
                json = json.Replace("\"archivePath\":", "\"archivePath\":\"duplicate\",\"archivePath\":", StringComparison.Ordinal);
            }

            File.WriteAllText(MetadataPath, json);
        }

        public void Dispose()
        {
            try { Directory.Delete(_root, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        private static string Hash(char value) => new(value, 64);
    }

    private sealed class NeverReparse : IPathSafetyInspector
    {
        public bool IsReparsePoint(string path) => false;
    }

    public enum MetadataFailurePoint
    {
        None,
        Write,
        Flush,
        Move,
        Replace
    }

    private sealed class RecordingMetadataFileSystem : ILocalUpdateMetadataFileSystem
    {
        private readonly FakeDirectoryLease _directory = new();
        private int _nextIdentity = 10;
        private FakeWriteLease? _writeLease;
        private bool _readCompleted;

        public List<string> Calls { get; } = [];
        public byte[]? DestinationBytes { get; set; }
        public byte[]? SwappedDestinationBytes { get; set; }
        public MetadataFailurePoint FailurePoint { get; set; }
        public bool ReadOpenIsUnsafe { get; set; }
        public bool DestinationIsUnsafe { get; set; }
        public bool SwapReadIdentityAfterRead { get; set; }
        public bool SwapDirectoryAfterRead { get; set; }
        public bool SwapDirectoryAfterFlush { get; set; }
        public bool SwapDestinationBeforeCommit { get; set; }
        public bool SwapDestinationHighFileIdBeforeCommit { get; set; }
        public bool DestinationAppearsBeforeMove { get; set; }
        public bool SwapTempAfterFlush { get; set; }
        public bool CommitVerificationFails { get; set; }
        public bool CommitVerificationThrows { get; set; }
        public bool DeleteOwnedCalled { get; private set; }
        public bool OwnedTempExists => _writeLease is { OwnedDeleted: false, Committed: false };
        public bool UnownedTempReplacementExists { get; private set; }
        public bool UnownedTempReplacementDeleted { get; private set; }
        public string? CommitOperation { get; private set; }
        public string? CreatedTempPath { get; private set; }
        private LocalUpdateMetadataFileIdentity DestinationIdentity { get; set; } = new(1, 1, ulong.MaxValue);

        public LocalUpdateMetadataOpenStatus OpenDirectory(
            string expectedPath,
            out ILocalUpdateMetadataDirectoryLease? lease)
        {
            Calls.Add("OpenDirectory");
            lease = _directory;
            return LocalUpdateMetadataOpenStatus.Opened;
        }

        public bool IsSafeDirectory(ILocalUpdateMetadataDirectoryLease lease, string expectedPath)
        {
            Calls.Add("IsSafeDirectory");
            return !(SwapDirectoryAfterRead && _readCompleted)
                && !(SwapDirectoryAfterFlush && _writeLease?.Flushed == true);
        }

        public LocalUpdateMetadataOpenStatus OpenRead(
            ILocalUpdateMetadataDirectoryLease directory,
            string expectedPath,
            out ILocalUpdateMetadataReadLease? lease)
        {
            Calls.Add("OpenRead");
            if (ReadOpenIsUnsafe)
            {
                lease = null;
                return LocalUpdateMetadataOpenStatus.Unsafe;
            }

            if (DestinationBytes is null)
            {
                lease = null;
                return LocalUpdateMetadataOpenStatus.Missing;
            }

            lease = new FakeReadLease(DestinationBytes.ToArray(), DestinationIdentity);
            return LocalUpdateMetadataOpenStatus.Opened;
        }

        public bool IsSafeRead(
            ILocalUpdateMetadataDirectoryLease directory,
            ILocalUpdateMetadataReadLease file,
            string expectedPath)
        {
            Calls.Add("IsSafeRead");
            return !(SwapReadIdentityAfterRead && _readCompleted);
        }

        public byte[]? ReadBounded(ILocalUpdateMetadataReadLease file, long maximumBytes)
        {
            Calls.Add("ReadBounded");
            var read = (FakeReadLease)file;
            _readCompleted = true;
            return read.Bytes.LongLength <= maximumBytes ? read.Bytes.ToArray() : null;
        }

        public LocalUpdateMetadataDestination InspectDestination(
            ILocalUpdateMetadataDirectoryLease directory,
            string expectedPath)
        {
            Calls.Add("InspectDestination");
            if (DestinationIsUnsafe)
            {
                return new LocalUpdateMetadataDestination(LocalUpdateMetadataEntryState.Unsafe, default);
            }

            return DestinationBytes is null
                ? new LocalUpdateMetadataDestination(LocalUpdateMetadataEntryState.Missing, default)
                : new LocalUpdateMetadataDestination(LocalUpdateMetadataEntryState.File, DestinationIdentity);
        }

        public LocalUpdateMetadataOpenStatus CreateNewTemp(
            ILocalUpdateMetadataDirectoryLease directory,
            string expectedPath,
            out ILocalUpdateMetadataWriteLease? lease)
        {
            Calls.Add("CreateNewTemp");
            CreatedTempPath = expectedPath;
            var identitySequence = (ulong)_nextIdentity++;
            _writeLease = new FakeWriteLease(
                new LocalUpdateMetadataFileIdentity(1, identitySequence, ~identitySequence));
            lease = _writeLease;
            return LocalUpdateMetadataOpenStatus.Opened;
        }

        public bool IsSafeTemp(
            ILocalUpdateMetadataDirectoryLease directory,
            ILocalUpdateMetadataWriteLease file,
            string expectedPath)
        {
            Calls.Add("IsSafeTemp");
            var write = (FakeWriteLease)file;
            if (SwapTempAfterFlush && write.Flushed && !write.TempSwapped)
            {
                write.TempSwapped = true;
                UnownedTempReplacementExists = true;
            }

            return !write.TempSwapped;
        }

        public void Write(ILocalUpdateMetadataWriteLease file, byte[] bytes)
        {
            Calls.Add("Write");
            ThrowIf(MetadataFailurePoint.Write);
            ((FakeWriteLease)file).Bytes = bytes.ToArray();
        }

        public void FlushToDisk(ILocalUpdateMetadataWriteLease file)
        {
            Calls.Add("Flush");
            ThrowIf(MetadataFailurePoint.Flush);
            ((FakeWriteLease)file).Flushed = true;
        }

        public bool Move(
            ILocalUpdateMetadataDirectoryLease directory,
            ILocalUpdateMetadataWriteLease file,
            string destinationPath)
        {
            Calls.Add("Move");
            ThrowIf(MetadataFailurePoint.Move);
            if (DestinationAppearsBeforeMove)
            {
                DestinationBytes = SwappedDestinationBytes?.ToArray() ?? "appeared"u8.ToArray();
                var identitySequence = (ulong)_nextIdentity++;
                DestinationIdentity = new LocalUpdateMetadataFileIdentity(1, identitySequence, ~identitySequence);
                return false;
            }

            if (DestinationBytes is not null) return false;
            Commit((FakeWriteLease)file, "Move");
            return true;
        }

        public bool Replace(
            ILocalUpdateMetadataDirectoryLease directory,
            ILocalUpdateMetadataWriteLease file,
            string destinationPath,
            LocalUpdateMetadataFileIdentity expectedDestinationIdentity)
        {
            Calls.Add("Replace");
            ThrowIf(MetadataFailurePoint.Replace);
            if (SwapDestinationBeforeCommit)
            {
                DestinationBytes = SwappedDestinationBytes?.ToArray() ?? "swapped"u8.ToArray();
                var identitySequence = (ulong)_nextIdentity++;
                DestinationIdentity = new LocalUpdateMetadataFileIdentity(1, identitySequence, ~identitySequence);
            }
            else if (SwapDestinationHighFileIdBeforeCommit)
            {
                DestinationIdentity = DestinationIdentity with
                {
                    FileIdHigh = DestinationIdentity.FileIdHigh ^ 1
                };
            }

            if (DestinationBytes is null || DestinationIdentity != expectedDestinationIdentity) return false;
            Commit((FakeWriteLease)file, "Replace");
            return true;
        }

        public bool IsCommitted(
            ILocalUpdateMetadataDirectoryLease directory,
            ILocalUpdateMetadataWriteLease file,
            string destinationPath)
        {
            Calls.Add("IsCommitted");
            if (CommitVerificationThrows)
            {
                throw new IOException(
                    "Injected post-commit verification failure.");
            }

            if (CommitVerificationFails)
            {
                return false;
            }

            return ((FakeWriteLease)file).Committed;
        }

        public void DeleteOwned(ILocalUpdateMetadataWriteLease file)
        {
            Calls.Add("DeleteOwned");
            DeleteOwnedCalled = true;
            ((FakeWriteLease)file).OwnedDeleted = true;
        }

        private void Commit(FakeWriteLease lease, string operation)
        {
            DestinationBytes = lease.Bytes?.ToArray();
            DestinationIdentity = lease.Identity;
            lease.Committed = true;
            CommitOperation = operation;
        }

        private void ThrowIf(MetadataFailurePoint point)
        {
            if (FailurePoint == point) throw new IOException($"Injected {point} failure.");
        }

        private sealed class FakeDirectoryLease : ILocalUpdateMetadataDirectoryLease
        {
            public void Dispose() { }
        }

        private sealed class FakeReadLease(byte[] bytes, LocalUpdateMetadataFileIdentity identity) : ILocalUpdateMetadataReadLease
        {
            public byte[] Bytes { get; } = bytes;
            public LocalUpdateMetadataFileIdentity Identity { get; } = identity;
            public void Dispose() { }
        }

        private sealed class FakeWriteLease(LocalUpdateMetadataFileIdentity identity) : ILocalUpdateMetadataWriteLease
        {
            public LocalUpdateMetadataFileIdentity Identity { get; } = identity;
            public byte[]? Bytes { get; set; }
            public bool Flushed { get; set; }
            public bool TempSwapped { get; set; }
            public bool OwnedDeleted { get; set; }
            public bool Committed { get; set; }
            public void Dispose() { }
        }
    }
}
