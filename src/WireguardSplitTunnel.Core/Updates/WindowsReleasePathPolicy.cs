using System.Text;

namespace WireguardSplitTunnel.Core.Updates;

public enum WindowsReleasePathError
{
    None,
    NullInput,
    Empty,
    InvalidUnicode,
    NonCanonicalUnicode,
    InvalidFormat,
    ReservedDeviceName,
    Collision,
    TooManyEntries
}

public readonly record struct WindowsReleasePathResult(
    bool Success,
    string? CanonicalKey,
    WindowsReleasePathError ErrorCode,
    string? ErrorMessage)
{
    public static WindowsReleasePathResult Failure(WindowsReleasePathError errorCode, string message) => new(false, null, errorCode, message);
    public static WindowsReleasePathResult Valid(string canonicalKey) => new(true, canonicalKey, WindowsReleasePathError.None, null);
}

public readonly record struct WindowsReleasePathCollectionResult(
    bool Success,
    IReadOnlyList<string> CanonicalKeys,
    WindowsReleasePathError ErrorCode,
    string? ErrorMessage)
{
    public static WindowsReleasePathCollectionResult Failure(WindowsReleasePathError errorCode, string message) => new(false, [], errorCode, message);
    public static WindowsReleasePathCollectionResult Valid(IReadOnlyList<string> canonicalKeys) => new(true, canonicalKeys, WindowsReleasePathError.None, null);
}

public static class WindowsReleasePathPolicy
{
    public const int MaximumArchiveEntries = 4096;

    public static WindowsReleasePathResult Validate(string? path)
    {
        if (path is null)
        {
            return Fail(WindowsReleasePathError.NullInput, "Path is required.");
        }

        if (path.Length == 0 || string.IsNullOrWhiteSpace(path))
        {
            return Fail(WindowsReleasePathError.Empty, "Path must not be empty or whitespace.");
        }

        if (!HasValidUtf16(path))
        {
            return Fail(WindowsReleasePathError.InvalidUnicode, "Path contains an unpaired surrogate.");
        }

        if (!path.IsNormalized(NormalizationForm.FormC))
        {
            return Fail(WindowsReleasePathError.NonCanonicalUnicode, "Path must be normalized to NFC.");
        }

        if (path[0] == '/' || path[^1] == '/' || path.IndexOf('\\') >= 0 || path.IndexOf(':') >= 0)
        {
            return Fail(WindowsReleasePathError.InvalidFormat, "Path must be a forward-slash relative file path.");
        }

        foreach (var segment in path.Split('/'))
        {
            if (segment.Length == 0 || segment is "." or ".." || EndsWithDotOrAsciiSpace(segment) || HasInvalidCharacter(segment))
            {
                return Fail(WindowsReleasePathError.InvalidFormat, "Path contains an invalid segment.");
            }

            if (IsReservedDeviceName(segment))
            {
                return Fail(WindowsReleasePathError.ReservedDeviceName, "Path contains a Windows reserved device name.");
            }
        }

        return WindowsReleasePathResult.Valid(path);
    }

    public static WindowsReleasePathCollectionResult ValidateCollection(IReadOnlyList<string?>? paths)
    {
        if (paths is null)
        {
            return WindowsReleasePathCollectionResult.Failure(WindowsReleasePathError.NullInput, "Path collection is required.");
        }

        int count;
        try
        {
            count = paths.Count;
        }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentOutOfRangeException or IndexOutOfRangeException or NotSupportedException)
        {
            return WindowsReleasePathCollectionResult.Failure(WindowsReleasePathError.InvalidFormat, "Path collection could not be read safely.");
        }

        if (count < 0 || count > MaximumArchiveEntries)
        {
            return WindowsReleasePathCollectionResult.Failure(WindowsReleasePathError.TooManyEntries, "Path collection exceeds the archive entry limit.");
        }

        var keys = new List<string>(count);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < count; index++)
        {
            string? path;
            try
            {
                path = paths[index];
            }
            catch (Exception exception) when (exception is InvalidOperationException or ArgumentOutOfRangeException or IndexOutOfRangeException or NotSupportedException)
            {
                return WindowsReleasePathCollectionResult.Failure(WindowsReleasePathError.InvalidFormat, "Path collection changed during validation.");
            }

            var result = Validate(path);
            if (!result.Success)
            {
                return WindowsReleasePathCollectionResult.Failure(result.ErrorCode, result.ErrorMessage!);
            }

            if (!seen.Add(result.CanonicalKey!))
            {
                return WindowsReleasePathCollectionResult.Failure(WindowsReleasePathError.Collision, "Path collection contains a duplicate or case-insensitive collision.");
            }

            keys.Add(result.CanonicalKey!);
        }

        try
        {
            if (paths.Count != count)
            {
                return WindowsReleasePathCollectionResult.Failure(WindowsReleasePathError.InvalidFormat, "Path collection changed during validation.");
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentOutOfRangeException or IndexOutOfRangeException or NotSupportedException)
        {
            return WindowsReleasePathCollectionResult.Failure(WindowsReleasePathError.InvalidFormat, "Path collection changed during validation.");
        }

        return WindowsReleasePathCollectionResult.Valid(keys.AsReadOnly());
    }

    private static bool HasValidUtf16(string value)
    {
        for (var index = 0; index < value.Length; index++)
        {
            if (!char.IsSurrogate(value[index]))
            {
                continue;
            }

            if (!char.IsHighSurrogate(value[index]) || index + 1 == value.Length || !char.IsLowSurrogate(value[index + 1]))
            {
                return false;
            }

            index++;
        }

        return true;
    }

    private static bool EndsWithDotOrAsciiSpace(string value) => value[^1] is '.' or ' ';

    private static bool HasInvalidCharacter(string value)
    {
        foreach (var character in value)
        {
            if (character < ' ' || character is '<' or '>' or '"' or '|' or '?' or '*')
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsReservedDeviceName(string segment)
    {
        var baseName = segment.Split('.', 2)[0];
        var upper = baseName.ToUpperInvariant();
        if (upper is "CON" or "PRN" or "AUX" or "NUL" or "CLOCK$" or "CONIN$" or "CONOUT$")
        {
            return true;
        }

        return IsPortDevice(upper, "COM") || IsPortDevice(upper, "LPT");
    }

    private static bool IsPortDevice(string value, string prefix) =>
        value.Length == prefix.Length + 1
        && value.StartsWith(prefix, StringComparison.Ordinal)
        && value[^1] is >= '1' and <= '9' or '¹' or '²' or '³';

    private static WindowsReleasePathResult Fail(WindowsReleasePathError errorCode, string message) =>
        WindowsReleasePathResult.Failure(errorCode, message);
}
