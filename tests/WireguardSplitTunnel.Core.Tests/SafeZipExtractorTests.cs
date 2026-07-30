using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class SafeZipExtractorTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "safe-zip-tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public void PreflightAndExtract_HandlesNestedFilesAndExplicitDirectories()
    {
        var archive = CreateZip(("bin/", null), ("bin/app.txt", "ok"));
        using var opened = SafeZipExtractor.OpenPreflight(archive, Limits());

        opened.Success.Should().BeTrue();
        opened.Session!.Entries.Should().Contain(e => e.Path == "bin" && e.IsDirectory);
        opened.Session.ExtractTo(Path.Combine(_root, "candidate")).Success.Should().BeTrue();
        File.ReadAllText(Path.Combine(_root, "candidate", "bin", "app.txt")).Should().Be("ok");
    }

    [Fact]
    public async Task Session_HashesThenPreflightsAndExtractsWithoutReopening()
    {
        var archive = CreateZip(("a.txt", "payload"));
        var expected = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(archive))).ToLowerInvariant();
        using var opened = SafeZipExtractor.Open(archive, Limits());

        opened.Success.Should().BeTrue();
        opened.Session!.ArchiveLength.Should().Be(new FileInfo(archive).Length);
        opened.Session.Preflight().ErrorCode.Should().Be(SafeZipError.InvalidOrder);
        var deleteWhileOpen = () => File.Delete(archive);
        deleteWhileOpen.Should().Throw<IOException>();
        (await opened.Session.ComputeSha256Async()).Digest.Should().Be(expected);
        opened.Session.Preflight().Success.Should().BeTrue();
        var extraction = opened.Session.ExtractTo(Path.Combine(_root, "candidate"));
        extraction.Success.Should().BeTrue();
        extraction.Artifacts!.Commit();
        File.ReadAllText(Path.Combine(_root, "candidate", "a.txt")).Should().Be("payload");
    }

    [Fact]
    public async Task RetainedStreamOverload_LeavesCallerOpenAndPreservesItsPosition()
    {
        var archive = CreateZip(("trusted.txt", "trusted"));
        var bytes = File.ReadAllBytes(archive);
        var expected = Convert.ToHexString(
                SHA256.HashData(bytes))
            .ToLowerInvariant();
        using var stream = new MemoryStream(bytes);
        stream.Position = 7;

        using (var opened = SafeZipExtractor.Open(
            stream,
            Limits()))
        {
            opened.Success.Should().BeTrue();
            stream.Position.Should().Be(7);

            (await opened.Session!.ComputeSha256Async())
                .Digest.Should().Be(expected);
            stream.Position.Should().Be(7);

            opened.Session.Preflight().Success
                .Should().BeTrue();
            opened.Session.Entries.Should().ContainSingle(
                entry => entry.Path == "trusted.txt");
            stream.Position.Should().Be(7);
        }

        stream.CanRead.Should().BeTrue();
        stream.Position.Should().Be(7);
    }

    [Fact]
    public async Task RetainedStreamOverload_WhenPositionCannotBeRestored_FailsClosedWithoutDisposingCaller()
    {
        var archive = CreateZip(("trusted.txt", "trusted"));
        using var stream = new RestoreFailingStream(
            File.ReadAllBytes(archive),
            originalPosition: 7);

        using var opened = SafeZipExtractor.Open(
            stream,
            Limits());
        opened.Success.Should().BeTrue();
        stream.ArmRestoreFailure();

        var hash = await opened.Session!
            .ComputeSha256Async();

        hash.Success.Should().BeFalse();
        hash.ErrorCode.Should().Be(SafeZipError.IoFailure);
        stream.DisposeCount.Should().Be(0);
    }

    [Fact]
    public async Task RetainedStreamOverload_ReadsTheOriginalHandleAfterThePathIsReplaced()
    {
        var trustedPath = CreateZip(
            ("trusted.txt", "trusted"));
        var replacementPath = CreateZip(
            ("attacker.txt", "attacker"));
        var trustedBytes = File.ReadAllBytes(trustedPath);
        var replacementBytes = File.ReadAllBytes(
            replacementPath);
        using var retained = new FileStream(
            trustedPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        retained.Position = 7;

        ReplacePathWhileHandleRemainsOpen(
            replacementPath,
            trustedPath);

        using var retainedOpen = SafeZipExtractor.Open(
            retained,
            Limits());
        var retainedHash = await retainedOpen.Session!
            .ComputeSha256Async();
        retainedHash.Digest.Should().Be(
            Convert.ToHexString(
                    SHA256.HashData(trustedBytes))
                .ToLowerInvariant());
        retained.Position.Should().Be(7);

        using var pathOpen = SafeZipExtractor.Open(
            trustedPath,
            Limits());
        var pathHash = await pathOpen.Session!
            .ComputeSha256Async();
        pathHash.Digest.Should().Be(
            Convert.ToHexString(
                    SHA256.HashData(replacementBytes))
                .ToLowerInvariant());
        pathHash.Digest.Should().NotBe(
            retainedHash.Digest);
    }

    private static void ReplacePathWhileHandleRemainsOpen(
        string replacementPath,
        string targetPath)
    {
        var retainedPath = Path.Combine(
            Path.GetDirectoryName(targetPath)!,
            $"{Path.GetFileName(targetPath)}.{Guid.NewGuid():N}.retained");

        // Rename the still-open file out of the way first, then give the
        // replacement its old name. This establishes the same retained-handle
        // condition without relying on FILE_RENAME_POSIX_SEMANTICS, whose
        // replace-if-open visibility is nondeterministic on some Windows file
        // system/filter-driver combinations.
        File.Move(targetPath, retainedPath);
        File.Move(replacementPath, targetPath);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void OpenOwnedStream_DisposesExactlyOnceWhenLengthThrows(int exceptionKind)
    {
        var stream = new ThrowingLengthStream(exceptionKind);

        using var opened = SafeZipExtractor.OpenOwnedStream(stream, Limits());

        opened.ErrorCode.Should().Be(SafeZipError.ArchiveOpenFailed);
        stream.DisposeCount.Should().Be(1);
    }

    [Fact]
    public void ExtractionLease_RollsBackExactArtifactsUnlessCommitted()
    {
        using var first = SafeZipExtractor.OpenPreflight(CreateZip(("a.txt", "payload")), Limits());
        var rollbackRoot = Path.Combine(_root, "rollback");
        using (var extraction = first.Session!.ExtractTo(rollbackRoot)) extraction.Success.Should().BeTrue();
        Directory.Exists(rollbackRoot).Should().BeFalse();

        using var second = SafeZipExtractor.OpenPreflight(CreateZip(("a.txt", "payload")), Limits());
        var committedRoot = Path.Combine(_root, "committed");
        using (var extraction = second.Session!.ExtractTo(committedRoot))
        {
            extraction.Artifacts!.Commit();
        }
        File.Exists(Path.Combine(committedRoot, "a.txt")).Should().BeTrue();
    }

    [Fact]
    public void Extract_RejectsAnyPreexistingCandidateRootWithoutChangingIt()
    {
        using var opened = SafeZipExtractor.OpenPreflight(CreateZip(("a.txt", "new")), Limits());
        var candidate = Path.Combine(_root, "candidate");
        Directory.CreateDirectory(candidate);
        File.WriteAllText(Path.Combine(candidate, "keep.txt"), "keep");

        opened.Session!.ExtractTo(candidate).ErrorCode.Should().Be(SafeZipError.DestinationExists);
        File.ReadAllText(Path.Combine(candidate, "keep.txt")).Should().Be("keep");
        File.Exists(Path.Combine(candidate, "a.txt")).Should().BeFalse();
    }

    [Fact]
    public void PreflightFailure_ReleasesArchiveHandleWhenResultIsDisposed()
    {
        var archive = CreateZip(("../bad", "x"));
        using (var opened = SafeZipExtractor.OpenPreflight(archive, Limits())) opened.Success.Should().BeFalse();

        File.Delete(archive);
        File.Exists(archive).Should().BeFalse();
    }

    [Theory]
    [InlineData("../escape.txt")]
    [InlineData("/absolute.txt")]
    [InlineData("dir\\backslash.txt")]
    public void Preflight_RejectsUnsafePathsBeforeAnyWrite(string entry)
    {
        var archive = CreateZip((entry, "x"));
        using var opened = SafeZipExtractor.OpenPreflight(archive, Limits());

        opened.Success.Should().BeFalse();
        opened.ErrorCode.Should().Be(SafeZipError.InvalidPath);
        Directory.Exists(Path.Combine(_root, "candidate")).Should().BeFalse();
    }

    [Fact]
    public void Preflight_RejectsCaseCollisionAndFileDirectoryCollision()
    {
        using var collision = SafeZipExtractor.OpenPreflight(CreateZip(("A.txt", "x"), ("a.txt", "y")), Limits());
        using var prefix = SafeZipExtractor.OpenPreflight(CreateZip(("bin", "x"), ("bin/app.txt", "y")), Limits());

        collision.ErrorCode.Should().Be(SafeZipError.PathCollision);
        prefix.ErrorCode.Should().Be(SafeZipError.PathCollision);
    }

    [Fact]
    public void Preflight_RejectsUnixSymlinkAndWindowsReparseAttributes()
    {
        var symlink = CreateZip(("link", "x", unchecked((int)0xA0000000)));
        var reparse = CreateZip(("link", "x", 0x400));

        using var symlinkResult = SafeZipExtractor.OpenPreflight(symlink, Limits());
        using var reparseResult = SafeZipExtractor.OpenPreflight(reparse, Limits());

        symlinkResult.ErrorCode.Should().Be(SafeZipError.SpecialFile);
        reparseResult.ErrorCode.Should().Be(SafeZipError.SpecialFile);
    }

    [Fact]
    public void Preflight_UsesExactEntryBoundary()
    {
        using var accepted = SafeZipExtractor.OpenPreflight(CreateMany(4096), UpdatePackageLimits.Default);
        using var rejected = SafeZipExtractor.OpenPreflight(CreateMany(4097), UpdatePackageLimits.Default);

        accepted.Success.Should().BeTrue();
        rejected.ErrorCode.Should().Be(SafeZipError.TooManyEntries);
    }

    [Fact]
    public void Preflight_RejectsOversizedDeclaredEntryCountBeforeZipArchiveMaterialization()
    {
        var archive = CreateZip(("a.txt", "x"));
        var bytes = File.ReadAllBytes(archive);
        var end = FindLastSignature(bytes, 0x06054b50);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(end + 8, 2), 4097);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(end + 10, 2), 4097);
        File.WriteAllBytes(archive, bytes);

        using var opened = SafeZipExtractor.OpenPreflight(archive, UpdatePackageLimits.Default);

        opened.ErrorCode.Should().Be(SafeZipError.TooManyEntries);
    }

    [Fact]
    public void Preflight_EnforcesExactFileTotalAndCompressionRatioBoundaries()
    {
        using var file = SafeZipExtractor.OpenPreflight(CreateZip(("a", "1234")), Limits(file: 4, expanded: 4, ratio: 1000));
        using var total = SafeZipExtractor.OpenPreflight(CreateZip(("a", "12"), ("b", "34")), Limits(file: 4, expanded: 4, ratio: 1000));
        using var oversized = SafeZipExtractor.OpenPreflight(CreateZip(("a", "12345")), Limits(file: 4, expanded: 10, ratio: 1000));

        file.Success.Should().BeTrue();
        total.Success.Should().BeTrue();
        oversized.ErrorCode.Should().Be(SafeZipError.FileTooLarge);
    }

    [Fact]
    public void Preflight_AcceptsExactCompressionRatioAndRejectsGreater()
    {
        var archive = CreateZip(("a", "123456789"));
        double exact;
        using (var source = ZipFile.OpenRead(archive))
        {
            var entry = source.GetEntry("a")!;
            exact = (double)entry.Length / entry.CompressedLength;
        }
        using var accepted = SafeZipExtractor.OpenPreflight(archive, Limits(ratio: exact));
        using var rejected = SafeZipExtractor.OpenPreflight(archive, Limits(ratio: Math.BitDecrement(exact)));

        accepted.Success.Should().BeTrue();
        rejected.ErrorCode.Should().Be(SafeZipError.CompressionRatio);
    }

    [Fact]
    public void Extract_RejectsReportedReparseAncestorBeforeCreatingCandidateRoot()
    {
        var archive = CreateZip(("a.txt", "new"));
        var candidate = Path.Combine(_root, "candidate");
        using var opened = SafeZipExtractor.OpenPreflight(archive, Limits(), new ReparseInspector(_root));

        var result = opened.Session!.ExtractTo(candidate);

        result.ErrorCode.Should().Be(SafeZipError.ReparsePoint);
        Directory.Exists(candidate).Should().BeFalse();
    }

    [Fact]
    public void Extract_CreateNewFailurePreservesPreexistingFile()
    {
        var archive = CreateZip(("a.txt", "new"));
        var candidate = Path.Combine(_root, "candidate");
        Directory.CreateDirectory(candidate);
        File.WriteAllText(Path.Combine(candidate, "a.txt"), "old");
        using var opened = SafeZipExtractor.OpenPreflight(archive, Limits());

        opened.Session!.ExtractTo(candidate).ErrorCode.Should().Be(SafeZipError.DestinationExists);
        File.ReadAllText(Path.Combine(candidate, "a.txt")).Should().Be("old");
    }

    [Fact]
    public void Extract_FailureAfterFirstWriteCleansOnlyCreatedArtifacts()
    {
        var archive = CreateZip(("a.txt", "first"), ("b.txt", "second"));
        var candidate = Path.Combine(_root, "candidate");
        var sibling = Path.Combine(_root, "keep.txt");
        File.WriteAllText(sibling, "keep");
        using var opened = SafeZipExtractor.OpenPreflight(archive, Limits(), new ReparseInspector(Path.Combine(candidate, "b.txt")));

        opened.Session!.ExtractTo(candidate).ErrorCode.Should().Be(SafeZipError.ReparsePoint);
        Directory.Exists(candidate).Should().BeFalse();
        File.ReadAllText(sibling).Should().Be("keep");
    }

    [Fact]
    public void Extract_ShortEntryDisposesHandlesBeforeExactCleanup()
    {
        var archive = CreateZip(("a.txt", "abc"));
        PatchCentralEntrySizes(archive, 0, compressedBytes: 3, expandedBytes: 4);
        var sibling = Path.Combine(_root, "keep.txt");
        File.WriteAllText(sibling, "keep");
        using var opened = SafeZipExtractor.OpenPreflight(archive, Limits());
        var candidate = Path.Combine(_root, "candidate");

        opened.Session!.ExtractTo(candidate).Success.Should().BeFalse();
        Directory.Exists(candidate).Should().BeFalse();
        File.ReadAllText(sibling).Should().Be("keep");
    }

    [Fact]
    public void Extract_CancellationCleansCreatedArtifacts()
    {
        var archive = CreateZip(("a.txt", new string('x', 8192)));
        using var opened = SafeZipExtractor.OpenPreflight(archive, Limits());
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        opened.Session!.ExtractTo(Path.Combine(_root, "candidate"), cancellation.Token).ErrorCode.Should().Be(SafeZipError.Cancelled);
        Directory.Exists(Path.Combine(_root, "candidate")).Should().BeFalse();
    }

    [Fact]
    public void ManifestRead_IsBoundedAndRejectsMissingDuplicateAndOversized()
    {
        using var missing = SafeZipExtractor.OpenPreflight(CreateZip(("a.txt", "x")), Limits());
        using var duplicate = SafeZipExtractor.OpenPreflight(CreateZip(("release-manifest.json", "a"), ("RELEASE-MANIFEST.JSON", "b")), Limits());
        using var oversized = SafeZipExtractor.OpenPreflight(CreateZip(("release-manifest.json", new string('x', (int)UpdateNetworkLimits.MetadataBytes + 1))), Limits(file: UpdateNetworkLimits.MetadataBytes + 1, expanded: UpdateNetworkLimits.MetadataBytes + 1));

        missing.Session!.ReadManifest().ErrorCode.Should().Be(SafeZipError.ManifestMissing);
        duplicate.ErrorCode.Should().Be(SafeZipError.ManifestDuplicate);
        oversized.Session!.ReadManifest().ErrorCode.Should().Be(SafeZipError.ManifestTooLarge);
    }

    [Fact]
    public void ManifestRead_RejectsActualLengthThatDiffersFromDeclaredLength()
    {
        var archive = CreateZip(("release-manifest.json", "abcdef"));
        var bytes = File.ReadAllBytes(archive);
        var centralHeader = FindSignature(bytes, 0x02014b50);
        centralHeader.Should().BeGreaterThanOrEqualTo(0);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(centralHeader + 24, 4), 3);
        File.WriteAllBytes(archive, bytes);
        using var opened = SafeZipExtractor.OpenPreflight(archive, Limits());

        opened.Success.Should().BeTrue();
        opened.Session!.ReadManifest().ErrorCode.Should().Be(SafeZipError.ArchiveOpenFailed);
    }

    [Fact]
    public void DefaultLimits_ApplyExactMaximumFileMetadataBoundary()
    {
        var equalArchive = CreateZip(("a", "x"));
        PatchCentralEntrySizes(equalArchive, 0, 512U * 1024 * 1024, 512U * 1024 * 1024);
        var greaterArchive = CreateZip(("a", "x"));
        PatchCentralEntrySizes(greaterArchive, 0, 512U * 1024 * 1024 + 1, 512U * 1024 * 1024 + 1);

        using var equal = SafeZipExtractor.OpenPreflight(equalArchive, UpdatePackageLimits.Default);
        using var greater = SafeZipExtractor.OpenPreflight(greaterArchive, UpdatePackageLimits.Default);

        equal.Success.Should().BeTrue();
        greater.ErrorCode.Should().Be(SafeZipError.FileTooLarge);
    }

    [Fact]
    public void DefaultLimits_ApplyExactMaximumExpandedMetadataBoundary()
    {
        var equalArchive = CreateZip(("a", "x"), ("b", "x"));
        PatchCentralEntrySizes(equalArchive, 0, 512U * 1024 * 1024, 512U * 1024 * 1024);
        PatchCentralEntrySizes(equalArchive, 1, 512U * 1024 * 1024, 512U * 1024 * 1024);
        var greaterArchive = CreateZip(("a", "x"), ("b", "x"), ("c", "x"));
        PatchCentralEntrySizes(greaterArchive, 0, 512U * 1024 * 1024, 512U * 1024 * 1024);
        PatchCentralEntrySizes(greaterArchive, 1, 512U * 1024 * 1024, 512U * 1024 * 1024);
        PatchCentralEntrySizes(greaterArchive, 2, 1, 1);

        using var equal = SafeZipExtractor.OpenPreflight(equalArchive, UpdatePackageLimits.Default);
        using var greater = SafeZipExtractor.OpenPreflight(greaterArchive, UpdatePackageLimits.Default);

        equal.Success.Should().BeTrue();
        greater.ErrorCode.Should().Be(SafeZipError.ExpandedTooLarge);
    }

    [Fact]
    public void DefaultLimits_ApplyExactCompressionRatioMetadataBoundary()
    {
        var equalArchive = CreateZip(("a", "x"));
        PatchCentralEntrySizes(equalArchive, 0, compressedBytes: 1, expandedBytes: 200);
        var greaterArchive = CreateZip(("a", "x"));
        PatchCentralEntrySizes(greaterArchive, 0, compressedBytes: 1, expandedBytes: 201);

        using var equal = SafeZipExtractor.OpenPreflight(equalArchive, UpdatePackageLimits.Default);
        using var greater = SafeZipExtractor.OpenPreflight(greaterArchive, UpdatePackageLimits.Default);

        equal.Success.Should().BeTrue();
        greater.ErrorCode.Should().Be(SafeZipError.CompressionRatio);
    }

    public void Dispose() { if (Directory.Exists(_root)) Directory.Delete(_root, true); }

    private UpdatePackageLimits Limits(long file = 1024 * 1024, long expanded = 1024 * 1024, double ratio = 1000) => new(4096, file, expanded, ratio, 0);
    private string CreateMany(int count) => CreateZip(Enumerable.Range(0, count).Select(i => (path: $"f{i}.txt", content: (string?)"x")).ToArray());
    private string CreateZip(params (string path, string? content, int attributes)[] entries)
    {
        Directory.CreateDirectory(_root);
        var path = Path.Combine(_root, Guid.NewGuid().ToString("N") + ".zip");
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        using var zip = new ZipArchive(file, ZipArchiveMode.Create);
        foreach (var (name, content, attributes) in entries)
        {
            var entry = zip.CreateEntry(name, CompressionLevel.NoCompression);
            entry.ExternalAttributes = attributes;
            if (content is not null) using (var writer = new StreamWriter(entry.Open())) writer.Write(content);
        }
        return path;
    }
    private string CreateZip(params (string path, string? content)[] entries) => CreateZip(entries.Select(e => (e.path, e.content, 0)).ToArray());
    private static int FindSignature(byte[] bytes, uint signature)
    {
        for (var index = 0; index <= bytes.Length - 4; index++)
            if (BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(index, 4)) == signature) return index;
        return -1;
    }
    private static int FindLastSignature(byte[] bytes, uint signature)
    {
        for (var index = bytes.Length - 4; index >= 0; index--)
            if (BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(index, 4)) == signature) return index;
        return -1;
    }
    private static void PatchCentralEntrySizes(string archive, int entryIndex, uint compressedBytes, uint expandedBytes)
    {
        var bytes = File.ReadAllBytes(archive);
        var matches = new List<int>();
        for (var index = 0; index <= bytes.Length - 4; index++)
            if (BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(index, 4)) == 0x02014b50) matches.Add(index);
        var header = matches[entryIndex];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(header + 20, 4), compressedBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(header + 24, 4), expandedBytes);
        File.WriteAllBytes(archive, bytes);
    }
    private sealed class ReparseInspector(string reparsePath) : IPathSafetyInspector { public bool IsReparsePoint(string path) => string.Equals(path, reparsePath, StringComparison.OrdinalIgnoreCase); }
    private sealed class ThrowingLengthStream(int exceptionKind) : Stream
    {
        public int DisposeCount { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => throw exceptionKind switch
        {
            0 => new IOException("length failed"),
            1 => new InvalidOperationException("length unavailable"),
            _ => new ObjectDisposedException(nameof(ThrowingLengthStream))
        };
        public override long Position { get => 0; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => 0;
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) DisposeCount++; base.Dispose(disposing); }
    }

    private sealed class RestoreFailingStream : Stream
    {
        private readonly MemoryStream _inner;
        private readonly long _originalPosition;
        private bool _armed;
        private bool _readObserved;

        public RestoreFailingStream(
            byte[] bytes,
            long originalPosition)
        {
            _inner = new MemoryStream(bytes);
            _originalPosition = originalPosition;
            _inner.Position = originalPosition;
        }

        public int DisposeCount { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _inner.Length;

        public override long Position
        {
            get => _inner.Position;
            set
            {
                if (_armed
                    && _readObserved
                    && value == _originalPosition)
                {
                    throw new IOException(
                        "Injected position restore failure.");
                }

                _inner.Position = value;
            }
        }

        public void ArmRestoreFailure() =>
            _armed = true;

        public override void Flush()
        {
        }

        public override int Read(
            byte[] buffer,
            int offset,
            int count)
        {
            var read = _inner.Read(buffer, offset, count);
            _readObserved = true;
            return read;
        }

        public override long Seek(
            long offset,
            SeekOrigin origin) =>
            _inner.Seek(offset, origin);

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        public override void Write(
            byte[] buffer,
            int offset,
            int count) =>
            throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                DisposeCount++;
                _inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
