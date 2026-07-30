using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.WindowsUpdate.Validation;

public sealed class WindowsPathSafetyInspector : IPathSafetyInspector
{
    private readonly Func<string, FileAttributes> _getAttributes;

    public WindowsPathSafetyInspector()
        : this(File.GetAttributes)
    {
    }

    internal WindowsPathSafetyInspector(Func<string, FileAttributes> getAttributes)
    {
        _getAttributes = getAttributes ?? throw new ArgumentNullException(nameof(getAttributes));
    }

    public bool IsReparsePoint(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return true;
        }

        try
        {
            return (_getAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return true;
        }
    }
}
