using System.Collections;
using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class WindowsReleasePathPolicyTests
{
    [Theory]
    [InlineData("WireguardSplitTunnel/WireguardSplitTunnel.App.exe")]
    [InlineData("scripts/start.ps1")]
    [InlineData("folder-1/file_2.txt")]
    public void Validate_AcceptsForwardSlashRelativeRegularFiles(string path)
    {
        var result = WindowsReleasePathPolicy.Validate(path);

        result.Success.Should().BeTrue();
        result.CanonicalKey.Should().Be(path);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("/root/file.txt")]
    [InlineData("\\\\server\\share\\file.txt")]
    [InlineData("C:/file.txt")]
    [InlineData("C:file.txt")]
    [InlineData("folder\\file.txt")]
    [InlineData("folder:stream/file.txt")]
    [InlineData("folder/")]
    [InlineData("/folder")]
    [InlineData("folder//file.txt")]
    [InlineData("./file.txt")]
    [InlineData("folder/../file.txt")]
    [InlineData("folder /file.txt")]
    [InlineData("folder./file.txt")]
    [InlineData("folder/fi<le.txt")]
    [InlineData("folder/fi\0le.txt")]
    public void Validate_RejectsUnsafePathGrammar(string path)
    {
        var action = () => WindowsReleasePathPolicy.Validate(path);

        action.Should().NotThrow();
        var result = action();
        result.Success.Should().BeFalse();
        result.ErrorCode.Should().NotBe(WindowsReleasePathError.None);
        result.ErrorMessage.Should().NotBeNullOrWhiteSpace();
    }

    [Theory]
    [InlineData("CON/file.txt")]
    [InlineData("folder/prn.log")]
    [InlineData("AUX.txt")]
    [InlineData("NUL ")]
    [InlineData("CLOCK$/file.txt")]
    [InlineData("CONIN$.txt")]
    [InlineData("CONOUT$.txt")]
    [InlineData("COM1.txt")]
    [InlineData("LPT9/file.txt")]
    public void Validate_RejectsWindowsReservedDeviceNamesInAnySegment(string path)
    {
        WindowsReleasePathPolicy.Validate(path).Success.Should().BeFalse();
    }

    [Theory]
    [InlineData("console.txt")]
    [InlineData("com10.txt")]
    [InlineData("lpt0.txt")]
    public void Validate_DoesNotOverrejectOrdinaryNames(string path)
    {
        WindowsReleasePathPolicy.Validate(path).Success.Should().BeTrue();
    }

    [Fact]
    public void Validate_RejectsNullAndNonNfcInputWithoutThrowing()
    {
        var nullAction = () => WindowsReleasePathPolicy.Validate(null);
        var nfdAction = () => WindowsReleasePathPolicy.Validate("cafe\u0301/file.txt");

        nullAction.Should().NotThrow();
        nfdAction.Should().NotThrow();
        nullAction().ErrorCode.Should().Be(WindowsReleasePathError.NullInput);
        nfdAction().ErrorCode.Should().Be(WindowsReleasePathError.NonCanonicalUnicode);
    }

    [Fact]
    public void Validate_RejectsUnpairedSurrogate()
    {
        WindowsReleasePathPolicy.Validate("folder/\uD800.txt").ErrorCode.Should().Be(WindowsReleasePathError.InvalidUnicode);
    }

    [Fact]
    public void ValidateCollection_RejectsDuplicatesAndCaseInsensitiveCollisionsWithoutMutatingInput()
    {
        IReadOnlyList<string?> paths = ["App/App.exe", "app/app.exe"];

        var result = WindowsReleasePathPolicy.ValidateCollection(paths);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be(WindowsReleasePathError.Collision);
        paths.Should().Equal("App/App.exe", "app/app.exe");
    }

    [Fact]
    public void ValidateCollection_RejectsNullEntryAndReturnsCanonicalForwardSlashKeys()
    {
        var nullResult = WindowsReleasePathPolicy.ValidateCollection(["scripts/start.ps1", null]);
        var validResult = WindowsReleasePathPolicy.ValidateCollection(["scripts/start.ps1", "App/main.exe"]);

        nullResult.Success.Should().BeFalse();
        nullResult.ErrorCode.Should().Be(WindowsReleasePathError.NullInput);
        validResult.Success.Should().BeTrue();
        validResult.CanonicalKeys.Should().Equal("scripts/start.ps1", "App/main.exe");
    }

    [Fact]
    public void ValidateCollection_RejectsOverLimitCountBeforeElementAccess()
    {
        var paths = new ThrowingReadOnlyList<string?>(WindowsReleasePathPolicy.MaximumArchiveEntries + 1);

        var result = WindowsReleasePathPolicy.ValidateCollection(paths);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be(WindowsReleasePathError.TooManyEntries);
    }

    [Fact]
    public void ValidateCollection_AcceptsExactlyTheArchiveEntryCeiling()
    {
        var paths = Enumerable.Range(0, WindowsReleasePathPolicy.MaximumArchiveEntries)
            .Select(index => (string?)$"files/file-{index}.bin").ToList();

        var result = WindowsReleasePathPolicy.ValidateCollection(paths);

        result.Success.Should().BeTrue();
        result.CanonicalKeys.Should().HaveCount(WindowsReleasePathPolicy.MaximumArchiveEntries);
    }

    private sealed class ThrowingReadOnlyList<T>(int count) : IReadOnlyList<T>
    {
        public int Count => count;
        public T this[int index] => throw new InvalidOperationException("Indexer must not be accessed.");
        public IEnumerator<T> GetEnumerator() => throw new InvalidOperationException("Enumerator must not be accessed.");
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
