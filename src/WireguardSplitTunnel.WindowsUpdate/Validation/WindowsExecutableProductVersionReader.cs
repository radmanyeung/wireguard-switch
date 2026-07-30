using System.Diagnostics;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32.SafeHandles;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.WindowsUpdate.Validation;

public sealed class WindowsExecutableProductVersionReader : IExecutableProductVersionReader
{
    private const uint LoadLibrarySearchSystem32 = 0x00000800;
    private const uint MaximumVersionBufferBytes =
        16 * 1024 * 1024;
    private const uint MaximumTranslationBytes = 1024;
    private const uint MaximumProductVersionCharacters = 128;
    private const string VersionLibrary = "version.dll";
    private const string HandleExport =
        "GetFileVersionInfoByHandle";

    private readonly Func<string, string?> _readProductVersion;
    private readonly Func<
        SafeFileHandle,
        string?> _readRetainedProductVersion;

    public WindowsExecutableProductVersionReader()
        : this(
            path => FileVersionInfo
                .GetVersionInfo(path)
                .ProductVersion,
            ReadProductVersionFromHandle)
    {
    }

    internal WindowsExecutableProductVersionReader(
        Func<string, string?> readProductVersion)
        : this(
            readProductVersion,
            ReadProductVersionFromHandle)
    {
    }

    internal WindowsExecutableProductVersionReader(
        Func<string, string?> readProductVersion,
        Func<SafeFileHandle, string?>
            readRetainedProductVersion)
    {
        _readProductVersion = readProductVersion
            ?? throw new ArgumentNullException(
                nameof(readProductVersion));
        _readRetainedProductVersion =
            readRetainedProductVersion
            ?? throw new ArgumentNullException(
                nameof(readRetainedProductVersion));
    }

    public string? ReadProductVersion(string executablePath)
    {
        try
        {
            var value = _readProductVersion(executablePath);
            return SemanticVersion.TryParseNormalized(value, out var version) ? version.ToString() : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or InvalidOperationException or Win32Exception or SecurityException or NotSupportedException)
        {
            return null;
        }
    }

    public string? ReadProductVersion(
        Stream executableStream)
    {
        if (executableStream is not FileStream fileStream
            || !fileStream.CanRead
            || !fileStream.CanSeek)
        {
            return null;
        }

        long? originalPosition = null;
        var handleAdded = false;
        var positionRestored = false;
        SafeFileHandle? retainedHandle = null;
        string? result = null;
        try
        {
            originalPosition = fileStream.Position;

            retainedHandle =
                fileStream.SafeFileHandle;
            if (!retainedHandle.IsInvalid
                && !retainedHandle.IsClosed)
            {
                retainedHandle.DangerousAddRef(
                    ref handleAdded);
                var value =
                    _readRetainedProductVersion(
                        retainedHandle);
                result =
                    SemanticVersion.TryParseNormalized(
                        value,
                        out var version)
                        ? version.ToString()
                        : null;
            }
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or InvalidOperationException
                or Win32Exception
                or SecurityException
                or NotSupportedException
                or ObjectDisposedException
                or ExternalException
                or OverflowException)
        {
            return null;
        }
        finally
        {
            if (originalPosition is { } position)
            {
                try
                {
                    fileStream.Position = position;
                    positionRestored =
                        fileStream.Position == position;
                }
                catch (Exception exception) when (
                    exception is IOException
                        or ObjectDisposedException
                        or NotSupportedException)
                {
                }
            }

            if (handleAdded)
            {
                retainedHandle!.DangerousRelease();
            }
        }

        return positionRestored
            ? result
            : null;
    }

    private static string? ReadProductVersionFromHandle(
        SafeFileHandle handle)
    {
        IntPtr library = IntPtr.Zero;
        IntPtr versionBuffer = IntPtr.Zero;
        try
        {
            library = LoadLibraryExW(
                VersionLibrary,
                IntPtr.Zero,
                LoadLibrarySearchSystem32);
            if (library == IntPtr.Zero)
            {
                return null;
            }

            var export = GetProcAddress(
                library,
                HandleExport);
            if (export == IntPtr.Zero)
            {
                return null;
            }

            var getVersionInfo =
                Marshal.GetDelegateForFunctionPointer<
                    GetFileVersionInfoByHandleDelegate>(
                        export);
            var succeeded = getVersionInfo(
                flags: 0,
                handle.DangerousGetHandle(),
                out versionBuffer,
                out var bufferLength);
            if (!succeeded
                || versionBuffer == IntPtr.Zero
                || bufferLength == 0
                || bufferLength
                    > MaximumVersionBufferBytes)
            {
                return null;
            }

            return TryReadProductVersion(
                versionBuffer,
                bufferLength);
        }
        finally
        {
            if (versionBuffer != IntPtr.Zero)
            {
                _ = LocalFree(versionBuffer);
            }

            if (library != IntPtr.Zero)
            {
                _ = FreeLibrary(library);
            }
        }
    }

    private static string? TryReadProductVersion(
        IntPtr versionBuffer,
        uint bufferLength)
    {
        if (!VerQueryValueW(
                versionBuffer,
                @"\VarFileInfo\Translation",
                out var translations,
                out var translationLength)
            || translations == IntPtr.Zero
            || translationLength < 4
            || translationLength % 4 != 0
            || translationLength
                > MaximumTranslationBytes
            || !IsRangeWithinBuffer(
                versionBuffer,
                bufferLength,
                translations,
                translationLength))
        {
            return null;
        }

        var translationCount =
            checked((int)translationLength / 4);
        for (var index = 0;
             index < translationCount;
             index++)
        {
            var offset = checked(index * 4);
            var language = unchecked(
                (ushort)Marshal.ReadInt16(
                    translations,
                    offset));
            var codePage = unchecked(
                (ushort)Marshal.ReadInt16(
                    translations,
                    offset + 2));
            var query =
                $@"\StringFileInfo\{language:x4}{codePage:x4}\ProductVersion";
            if (!VerQueryValueW(
                    versionBuffer,
                    query,
                    out var value,
                    out var characterCount)
                || value == IntPtr.Zero
                || characterCount == 0
                || characterCount
                    > MaximumProductVersionCharacters)
            {
                continue;
            }

            var valueBytes = checked(
                characterCount * sizeof(char));
            if (!IsRangeWithinBuffer(
                    versionBuffer,
                    bufferLength,
                    value,
                    valueBytes))
            {
                continue;
            }

            var raw = Marshal.PtrToStringUni(
                    value,
                    checked((int)characterCount))
                ?.TrimEnd('\0');
            if (!string.IsNullOrEmpty(raw))
            {
                return raw;
            }
        }

        return null;
    }

    private static bool IsRangeWithinBuffer(
        IntPtr buffer,
        uint bufferLength,
        IntPtr value,
        uint valueLength)
    {
        try
        {
            var start = (nuint)buffer;
            var end = checked(start + bufferLength);
            var valueStart = (nuint)value;
            var valueEnd = checked(
                valueStart + valueLength);
            return valueStart >= start
                && valueEnd >= valueStart
                && valueEnd <= end;
        }
        catch (OverflowException)
        {
            return false;
        }
    }

    [UnmanagedFunctionPointer(
        CallingConvention.Winapi,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool
        GetFileVersionInfoByHandleDelegate(
            uint flags,
            IntPtr file,
            out IntPtr versionInformation,
            out uint length);

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern IntPtr LoadLibraryExW(
        string libraryFileName,
        IntPtr file,
        uint flags);

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Ansi,
        ExactSpelling = true,
        SetLastError = true)]
    private static extern IntPtr GetProcAddress(
        IntPtr module,
        string procedureName);

    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FreeLibrary(
        IntPtr module);

    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    private static extern IntPtr LocalFree(
        IntPtr memory);

    [DllImport(
        "version.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VerQueryValueW(
        IntPtr block,
        string subBlock,
        out IntPtr buffer,
        out uint length);
}
