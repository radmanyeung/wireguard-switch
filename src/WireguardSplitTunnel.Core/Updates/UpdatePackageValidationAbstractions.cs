namespace WireguardSplitTunnel.Core.Updates;

public interface IExecutableProductVersionReader
{
    string? ReadProductVersion(string executablePath);

    string? ReadProductVersion(Stream executableStream) =>
        null;
}

public interface IPathSafetyInspector
{
    bool IsReparsePoint(string path);
}

public interface IDiskSpaceProvider
{
    long GetAvailableBytes(string path);
}
