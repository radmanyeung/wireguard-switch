using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
namespace WireguardSplitTunnel.Core.Services;

public interface ISoftwareConnectionSnapshotReader
{
    Task<SoftwareConnectionSnapshot> ReadAsync(CancellationToken cancellationToken);
}

[SupportedOSPlatform("windows")]
public sealed class WindowsSoftwareConnectionSnapshotReader : ISoftwareConnectionSnapshotReader
{
    public Task<SoftwareConnectionSnapshot> ReadAsync(CancellationToken cancellationToken) => Task.Run(() =>
    {
        cancellationToken.ThrowIfCancellationRequested();
        var before = ReadProcesses();
        var connections = ReadTcpConnections();
        var after = ReadProcesses();
        cancellationToken.ThrowIfCancellationRequested();
        return SoftwareConnectionSnapshot.Validate(before, connections, after);
    }, cancellationToken);

    public static IReadOnlyList<SoftwareProcess> ReadProcesses()
    {
        var snapshot = CreateToolhelp32Snapshot(2, 0);
        if (snapshot == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Process snapshot failed");
        try
        {
            var entry = new ProcessEntry { Size = (uint)Marshal.SizeOf<ProcessEntry>() };
            if (!Process32First(snapshot, ref entry)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Process enumeration failed");
            var result = new List<SoftwareProcess>();
            do
            {
                var handle = OpenProcess(0x1000, false, entry.ProcessId);
                if (handle == IntPtr.Zero) continue; // Protected/exited processes are deliberately unidentifiable.
                try
                {
                    var path = new StringBuilder(32768); var length = path.Capacity;
                    if (QueryFullProcessImageName(handle, 0, path, ref length) && GetProcessTimes(handle, out var created, out _, out _, out _))
                        result.Add(new((int)entry.ProcessId, (int)entry.ParentProcessId, created, path.ToString()));
                }
                finally { CloseHandle(handle); }
            } while (Process32Next(snapshot, ref entry));
            var error = Marshal.GetLastWin32Error();
            if (error != 18) throw new Win32Exception(error, "Process enumeration incomplete");
            return result;
        }
        finally { CloseHandle(snapshot); }
    }

    private static IReadOnlyList<SoftwareTcpConnection> ReadTcpConnections()
    {
        var size = 0; var status = GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 5, 0);
        if (status != 122 && status != 0) throw new Win32Exception((int)status, "TCP owner table size failed");
        for (var attempt = 0; attempt < 4; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(Math.Max(size, 4));
            try
            {
                status = GetExtendedTcpTable(buffer, ref size, false, 2, 5, 0);
                if (status == 122) continue;
                if (status != 0) throw new Win32Exception((int)status, "TCP owner table failed");
                var count = Marshal.ReadInt32(buffer); var stride = Marshal.SizeOf<TcpRow>();
                if (count < 0 || (long)count * stride + 4 > size) throw new InvalidOperationException("Invalid TCP owner table size");
                var rows = new List<SoftwareTcpConnection>();
                for (var i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<TcpRow>(buffer + 4 + i * stride);
                    // SYN_SENT is essential: the existing application firewall may block the initial connection.
                    if (row.State != 2 && row.RemoteAddress != 0)
                        rows.Add(new((int)row.ProcessId, new IPAddress(BitConverter.GetBytes(row.RemoteAddress)).ToString()));
                }
                return rows;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        throw new InvalidOperationException("TCP owner table changed repeatedly; snapshot discarded");
    }

    // Read only endpoint output, never `wg show ... dump` (which contains private keys).
    public static async Task<IReadOnlyList<string>> ReadTransportEndpointsAsync(CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        cancellationToken = timeout.Token;
        var executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WireGuard", "wg.exe");
        if (!File.Exists(executable)) throw new InvalidOperationException("wg.exe is unavailable; endpoint-safe software learning is paused");
        using var process = Process.Start(new ProcessStartInfo(executable, "show all endpoints")
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true })
            ?? throw new InvalidOperationException("Unable to inspect WireGuard transport endpoints");
        var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        using var registration = cancellationToken.Register(() => { try { if (!process.HasExited) process.Kill(true); } catch (InvalidOperationException) { } });
        await process.WaitForExitAsync(cancellationToken);
        if (process.ExitCode != 0) throw new InvalidOperationException("Unable to inspect WireGuard transport endpoints: " + await error);
        var result = new HashSet<string>();
        foreach (var line in (await output).Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var endpoint = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).LastOrDefault();
            if (endpoint == "(none)" || endpoint is null) continue;
            if (!IPEndPoint.TryParse(endpoint, out var parsed)) throw new InvalidOperationException("Unrecognized WireGuard endpoint; software learning paused");
            result.Add(parsed.Address.ToString());
        }
        return result.ToArray();
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry
    {
        public uint Size, Usage, ProcessId; public UIntPtr DefaultHeapId; public uint ModuleId, Threads, ParentProcessId; public int Priority; public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string ExeFile;
    }
    [StructLayout(LayoutKind.Sequential)] private struct TcpRow { public uint State, LocalAddress, LocalPort, RemoteAddress, RemotePort, ProcessId; }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);
    [DllImport("kernel32.dll", EntryPoint = "Process32FirstW", SetLastError = true)] private static extern bool Process32First(IntPtr snapshot, ref ProcessEntry entry);
    [DllImport("kernel32.dll", EntryPoint = "Process32NextW", SetLastError = true)] private static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry entry);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, uint processId);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool QueryFullProcessImageName(IntPtr handle, uint flags, StringBuilder path, ref int size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetProcessTimes(IntPtr handle, out long creation, out long exit, out long kernel, out long user);
    [DllImport("iphlpapi.dll")] private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, uint family, int tableClass, uint reserved);
}
