Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http

$script:WgstContract = [pscustomobject]@{
    repository = 'radmanyeung/wireguard-switch'
    latestReleaseApi =
        'https://api.github.com/repos/radmanyeung/wireguard-switch/releases/latest'
    archiveAsset = 'wireguard-split-tunnel-win-x64.zip'
    checksumAsset = 'wireguard-split-tunnel-win-x64.zip.sha256'
    manifest = 'release-manifest.json'
    applicationPath =
        'WireguardSplitTunnel/WireguardSplitTunnel.App.exe'
    updaterPath =
        'WireguardSplitTunnel/WireguardSplitTunnel.Updater.exe'
    redirectHosts = @(
        'api.github.com',
        'github.com',
        'objects.githubusercontent.com',
        'release-assets.githubusercontent.com'
    )
    maximumRedirects = 5
    metadataBytes = 2MB
    checksumBytes = 4KB
    archiveBytes = 256MB
    metadataTimeoutSeconds = 30
    downloadTimeoutSeconds = 900
    noProgressTimeoutSeconds = 60
    maximumEntries = 4096
    maximumFileBytes = 512MB
    maximumExpandedBytes = 1GB
    maximumCompressionRatio = 200.0
}

if ($null -eq (
        'WireguardSplitTunnel.ReleaseScripts.NativeFileIdentity' -as
            [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace WireguardSplitTunnel.ReleaseScripts
{
    public sealed class NativeFileSnapshot
    {
        public uint VolumeSerialNumber { get; set; }
        public ulong FileIndex { get; set; }
        public uint LinkCount { get; set; }
        public FileAttributes Attributes { get; set; }
        public string FinalPath { get; set; }
    }

    public static class NativeFileIdentity
    {
        private const uint TokenAdjustPrivileges = 0x20;
        private const uint TokenQuery = 0x8;
        private const uint PrivilegeEnabled = 0x2;
        private const int ErrorNotAllAssigned = 1300;
        private static readonly object PrivilegeAdjustmentGate = new object();

        [StructLayout(LayoutKind.Sequential)]
        private struct Luid
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TokenPrivileges
        {
            public uint PrivilegeCount;
            public Luid Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport(
            "kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName,
            uint desiredAccess,
            FileShare shareMode,
            IntPtr securityAttributes,
            FileMode creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation information);

        [DllImport(
            "kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(
            SafeFileHandle file,
            StringBuilder path,
            uint pathLength,
            uint flags);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(
            IntPtr processHandle,
            uint desiredAccess,
            out IntPtr tokenHandle);

        [DllImport(
            "advapi32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeValueW(
            string systemName,
            string name,
            out Luid luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdjustTokenPrivileges(
            IntPtr tokenHandle,
            [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
            ref TokenPrivileges newState,
            uint bufferLength,
            out TokenPrivileges previousState,
            out uint returnLength);

        public static IDisposable EnableRestorePrivilege()
        {
            IntPtr token = IntPtr.Zero;
            bool gateHeld = false;
            try
            {
                Monitor.Enter(PrivilegeAdjustmentGate, ref gateHeld);
                if (!OpenProcessToken(
                    GetCurrentProcess(),
                    TokenAdjustPrivileges | TokenQuery,
                    out token))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Could not open the process token.");
                }

                Luid luid;
                if (!LookupPrivilegeValueW(
                    null,
                    "SeRestorePrivilege",
                    out luid))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Could not resolve SeRestorePrivilege.");
                }

                TokenPrivileges requested = new TokenPrivileges
                {
                    PrivilegeCount = 1,
                    Luid = luid,
                    Attributes = PrivilegeEnabled
                };
                TokenPrivileges previous;
                uint returned;
                if (!AdjustTokenPrivileges(
                    token,
                    false,
                    ref requested,
                    (uint)Marshal.SizeOf(typeof(TokenPrivileges)),
                    out previous,
                    out returned))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Could not enable SeRestorePrivilege.");
                }
                int error = Marshal.GetLastWin32Error();
                if (error == ErrorNotAllAssigned)
                {
                    throw new Win32Exception(
                        error,
                        "SeRestorePrivilege is not assigned to this token.");
                }
                RestorePrivilegeScope scope =
                    new RestorePrivilegeScope(
                        token,
                        previous,
                        gateHeld,
                        false);
                token = IntPtr.Zero;
                gateHeld = false;
                return scope;
            }
            catch
            {
                if (token != IntPtr.Zero)
                {
                    CloseHandle(token);
                }
                if (gateHeld)
                {
                    Monitor.Exit(PrivilegeAdjustmentGate);
                }
                throw;
            }
        }

        public static bool RestoreFailureIsFailClosedForTests()
        {
            RestorePrivilegeScope scope =
                new RestorePrivilegeScope(
                    new IntPtr(1),
                    new TokenPrivileges(),
                    false,
                    true);
            try
            {
                scope.Dispose();
                return false;
            }
            catch (Win32Exception)
            {
                return true;
            }
        }

        public static bool CanOpenDirectoryForMutation(string path)
        {
            const uint fileWriteData = 0x00000002;
            const uint fileAddSubdirectory = 0x00000004;
            const uint fileDeleteChild = 0x00000040;
            const uint fileFlagBackupSemantics = 0x02000000;
            const uint fileFlagOpenReparsePoint = 0x00200000;
            string fullPath = Path.GetFullPath(path);
            using (SafeFileHandle handle = CreateFileW(
                fullPath,
                fileWriteData | fileAddSubdirectory | fileDeleteChild,
                FileShare.Read | FileShare.Write | FileShare.Delete,
                IntPtr.Zero,
                FileMode.Open,
                fileFlagBackupSemantics | fileFlagOpenReparsePoint,
                IntPtr.Zero))
            {
                if (!handle.IsInvalid)
                {
                    return true;
                }

                int error = Marshal.GetLastWin32Error();
                if (error == 5)
                {
                    return false;
                }

                throw new Win32Exception(
                    error,
                    "Could not evaluate directory mutation access.");
            }
        }

        public static NativeFileSnapshot Read(string path)
        {
            const uint fileReadAttributes = 0x80;
            const uint fileFlagBackupSemantics = 0x02000000;
            const uint fileFlagOpenReparsePoint = 0x00200000;
            string fullPath = Path.GetFullPath(path);
            using (SafeFileHandle handle = CreateFileW(
                fullPath,
                fileReadAttributes,
                FileShare.Read | FileShare.Write | FileShare.Delete,
                IntPtr.Zero,
                FileMode.Open,
                fileFlagBackupSemantics | fileFlagOpenReparsePoint,
                IntPtr.Zero))
            {
                if (handle.IsInvalid)
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Could not open a filesystem object for identity validation.");
                }

                ByHandleFileInformation information;
                if (!GetFileInformationByHandle(handle, out information))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Could not read filesystem identity.");
                }

                string finalPath = ReadFinalPath(handle);
                return new NativeFileSnapshot
                {
                    VolumeSerialNumber = information.VolumeSerialNumber,
                    FileIndex =
                        ((ulong)information.FileIndexHigh << 32)
                        | information.FileIndexLow,
                    LinkCount = information.NumberOfLinks,
                    Attributes =
                        (FileAttributes)information.FileAttributes,
                    FinalPath = Path.GetFullPath(finalPath)
                };
            }
        }

        private static string ReadFinalPath(SafeFileHandle handle)
        {
            int capacity = 512;
            while (capacity <= 32768)
            {
                StringBuilder buffer = new StringBuilder(capacity);
                uint length = GetFinalPathNameByHandleW(
                    handle,
                    buffer,
                    (uint)buffer.Capacity,
                    0);
                if (length == 0)
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Could not resolve final filesystem path.");
                }
                if (length < buffer.Capacity)
                {
                    string value = buffer.ToString();
                    if (value.StartsWith(
                        @"\\?\UNC\",
                        StringComparison.OrdinalIgnoreCase))
                    {
                        return @"\\" + value.Substring(8);
                    }
                    if (value.StartsWith(
                        @"\\?\",
                        StringComparison.OrdinalIgnoreCase))
                    {
                        return value.Substring(4);
                    }
                    return value;
                }
                capacity = checked((int)length + 1);
            }
            throw new IOException("Resolved filesystem path is too long.");
        }

        private sealed class RestorePrivilegeScope : IDisposable
        {
            private IntPtr token;
            private TokenPrivileges previous;
            private readonly bool gateHeld;
            private readonly bool simulateRestoreFailure;
            private bool disposed;

            public RestorePrivilegeScope(
                IntPtr tokenHandle,
                TokenPrivileges previousState,
                bool ownsGate,
                bool simulateFailure)
            {
                token = tokenHandle;
                previous = previousState;
                gateHeld = ownsGate;
                simulateRestoreFailure = simulateFailure;
            }

            public void Dispose()
            {
                if (disposed)
                {
                    return;
                }
                disposed = true;
                Exception restoreFailure = null;
                try
                {
                    bool restored;
                    int error;
                    if (simulateRestoreFailure)
                    {
                        restored = false;
                        error = 5;
                    }
                    else
                    {
                        TokenPrivileges ignored;
                        uint returned;
                        restored = AdjustTokenPrivileges(
                            token,
                            false,
                            ref previous,
                            (uint)Marshal.SizeOf(
                                typeof(TokenPrivileges)),
                            out ignored,
                            out returned);
                        error = Marshal.GetLastWin32Error();
                    }
                    if (!restored || error != 0)
                    {
                        restoreFailure = new Win32Exception(
                            error,
                            "Failed to restore SeRestorePrivilege.");
                    }
                }
                finally
                {
                    if (!simulateRestoreFailure
                        && token != IntPtr.Zero
                        && !CloseHandle(token)
                        && restoreFailure == null)
                    {
                        restoreFailure = new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "Failed to close the process token.");
                    }
                    token = IntPtr.Zero;
                    if (gateHeld)
                    {
                        Monitor.Exit(PrivilegeAdjustmentGate);
                    }
                }

                if (restoreFailure != null)
                {
                    throw restoreFailure;
                }
            }
        }
    }

    public static class NativeFileAcl
    {
        private const AccessControlSections ReadSections =
            AccessControlSections.Access |
            AccessControlSections.Owner |
            AccessControlSections.Group;

        public static byte[] ReadSecurityDescriptor(
            string path,
            bool directory)
        {
            FileSystemSecurity security = directory
                ? (FileSystemSecurity)new DirectoryInfo(path)
                    .GetAccessControl(ReadSections)
                : new FileInfo(path).GetAccessControl(ReadSections);
            return security.GetSecurityDescriptorBinaryForm();
        }

        public static void WriteSecurityDescriptor(
            string path,
            bool directory,
            byte[] descriptor)
        {
            if (descriptor == null)
            {
                throw new ArgumentNullException("descriptor");
            }

            if (directory)
            {
                DirectorySecurity security = new DirectorySecurity();
                security.SetSecurityDescriptorBinaryForm(descriptor);
                new DirectoryInfo(path).SetAccessControl(security);
                return;
            }

            FileSecurity fileSecurity = new FileSecurity();
            fileSecurity.SetSecurityDescriptorBinaryForm(descriptor);
            new FileInfo(path).SetAccessControl(fileSecurity);
        }
    }

    public enum NativeUpdateMutexWaitResult
    {
        Acquired,
        AbandonedAcquired,
        Busy
    }

    public sealed class NativeUpdateMutex : IDisposable
    {
        public const string Name =
            @"Global\WireguardSplitTunnel.UpdateTransaction";

        private const uint MutexAllAccess = 0x001F0001;
        private const uint OwnerSecurityInformation = 0x00000001;
        private const uint DaclSecurityInformation = 0x00000004;
        private const int KernelObject = 6;
        private const uint WaitObject0 = 0x00000000;
        private const uint WaitAbandoned = 0x00000080;
        private const uint WaitTimeout = 0x00000102;
        private const uint WaitFailed = 0xFFFFFFFF;

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            public int Length;
            public IntPtr SecurityDescriptor;

            [MarshalAs(UnmanagedType.Bool)]
            public bool InheritHandle;
        }

        [DllImport(
            "kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern IntPtr CreateMutexExW(
            ref SecurityAttributes attributes,
            string name,
            uint flags,
            uint desiredAccess);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(
            IntPtr handle,
            uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ReleaseMutex(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint GetSecurityInfo(
            IntPtr handle,
            int objectType,
            uint securityInformation,
            out IntPtr owner,
            out IntPtr group,
            out IntPtr dacl,
            out IntPtr sacl,
            out IntPtr securityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint GetSecurityDescriptorLength(
            IntPtr securityDescriptor);

        private IntPtr handle;
        private bool acquired;
        private int ownerThreadId;

        private NativeUpdateMutex(IntPtr handle)
        {
            this.handle = handle;
        }

        public static byte[] ExpectedSecurityDescriptor()
        {
            RawSecurityDescriptor descriptor =
                new RawSecurityDescriptor(
                    "O:SYD:P" +
                    "(A;;0x1f0001;;;BA)" +
                    "(A;;0x1f0001;;;SY)");
            byte[] bytes = new byte[descriptor.BinaryLength];
            descriptor.GetBinaryForm(bytes, 0);
            return bytes;
        }

        public static bool HasExactSecurityDescriptor(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                return false;
            }

            try
            {
                RawSecurityDescriptor descriptor =
                    new RawSecurityDescriptor(bytes, 0);
                if ((descriptor.ControlFlags &
                        ControlFlags.DiscretionaryAclProtected) == 0
                    || (descriptor.ControlFlags &
                        ControlFlags.DiscretionaryAclPresent) == 0
                    || descriptor.Owner == null
                    || descriptor.Owner.Value != "S-1-5-18"
                    || descriptor.DiscretionaryAcl == null
                    || descriptor.DiscretionaryAcl.Count != 2)
                {
                    return false;
                }

                bool administrators = false;
                bool system = false;
                foreach (GenericAce genericAce
                    in descriptor.DiscretionaryAcl)
                {
                    CommonAce ace = genericAce as CommonAce;
                    if (ace == null
                        || ace.IsCallback
                        || ace.AceQualifier
                            != AceQualifier.AccessAllowed
                        || ace.AccessMask != (int)MutexAllAccess
                        || ace.AceFlags != AceFlags.None
                        || ace.OpaqueLength != 0
                        || ace.SecurityIdentifier == null)
                    {
                        return false;
                    }

                    if (ace.SecurityIdentifier.Value ==
                        "S-1-5-32-544")
                    {
                        if (administrators)
                        {
                            return false;
                        }
                        administrators = true;
                    }
                    else if (ace.SecurityIdentifier.Value ==
                        "S-1-5-18")
                    {
                        if (system)
                        {
                            return false;
                        }
                        system = true;
                    }
                    else
                    {
                        return false;
                    }
                }

                return administrators && system;
            }
            catch (ArgumentException)
            {
                return false;
            }
        }

        public static NativeUpdateMutex OpenExact()
        {
            byte[] descriptor = ExpectedSecurityDescriptor();
            IntPtr descriptorPointer = Marshal.AllocHGlobal(
                descriptor.Length);
            IntPtr opened = IntPtr.Zero;
            try
            {
                Marshal.Copy(
                    descriptor,
                    0,
                    descriptorPointer,
                    descriptor.Length);
                SecurityAttributes attributes =
                    new SecurityAttributes
                    {
                        Length = Marshal.SizeOf(
                            typeof(SecurityAttributes)),
                        SecurityDescriptor = descriptorPointer,
                        InheritHandle = false
                    };
                opened = CreateMutexExW(
                    ref attributes,
                    Name,
                    0,
                    MutexAllAccess);
                if (opened == IntPtr.Zero)
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Could not create or open the protected update mutex.");
                }

                NativeUpdateMutex result =
                    new NativeUpdateMutex(opened);
                opened = IntPtr.Zero;
                if (!result.ValidateSecurity())
                {
                    result.Dispose();
                    throw new InvalidOperationException(
                        "The protected update mutex security is not exact.");
                }
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(descriptorPointer);
                if (opened != IntPtr.Zero)
                {
                    CloseHandle(opened);
                }
            }
        }

        public bool ValidateSecurity()
        {
            ThrowIfDisposed();
            IntPtr owner;
            IntPtr group;
            IntPtr dacl;
            IntPtr sacl;
            IntPtr descriptor;
            uint error = GetSecurityInfo(
                handle,
                KernelObject,
                OwnerSecurityInformation | DaclSecurityInformation,
                out owner,
                out group,
                out dacl,
                out sacl,
                out descriptor);
            if (error != 0)
            {
                throw new Win32Exception(
                    (int)error,
                    "Could not inspect the protected update mutex.");
            }

            try
            {
                uint length = GetSecurityDescriptorLength(descriptor);
                if (length == 0 || length > 65536)
                {
                    return false;
                }
                byte[] bytes = new byte[(int)length];
                Marshal.Copy(descriptor, bytes, 0, bytes.Length);
                return HasExactSecurityDescriptor(bytes);
            }
            finally
            {
                if (descriptor != IntPtr.Zero)
                {
                    LocalFree(descriptor);
                }
            }
        }

        public NativeUpdateMutexWaitResult Wait(int milliseconds)
        {
            ThrowIfDisposed();
            if (milliseconds < 0 || acquired)
            {
                throw new ArgumentOutOfRangeException("milliseconds");
            }

            uint result = WaitForSingleObject(
                handle,
                (uint)milliseconds);
            if (result == WaitObject0 || result == WaitAbandoned)
            {
                acquired = true;
                ownerThreadId = Thread.CurrentThread.ManagedThreadId;
                return result == WaitAbandoned
                    ? NativeUpdateMutexWaitResult.AbandonedAcquired
                    : NativeUpdateMutexWaitResult.Acquired;
            }
            if (result == WaitTimeout)
            {
                return NativeUpdateMutexWaitResult.Busy;
            }
            if (result == WaitFailed)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not wait for the protected update mutex.");
            }
            throw new InvalidOperationException(
                "The protected update mutex returned an unknown wait result.");
        }

        public void Release()
        {
            ThrowIfDisposed();
            if (!acquired
                || ownerThreadId
                    != Thread.CurrentThread.ManagedThreadId)
            {
                throw new InvalidOperationException(
                    "The current thread does not own the protected update mutex.");
            }
            if (!ReleaseMutex(handle))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not release the protected update mutex.");
            }
            acquired = false;
            ownerThreadId = 0;
        }

        public void Dispose()
        {
            IntPtr current = handle;
            handle = IntPtr.Zero;
            if (current != IntPtr.Zero && !CloseHandle(current))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not close the protected update mutex.");
            }
        }

        private void ThrowIfDisposed()
        {
            if (handle == IntPtr.Zero)
            {
                throw new ObjectDisposedException("NativeUpdateMutex");
            }
        }
    }
}
'@
}

function Get-WgstFileSystemSecurity {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$Directory
    )

    $bytes =
        [WireguardSplitTunnel.ReleaseScripts.NativeFileAcl]::
            ReadSecurityDescriptor($Path, $Directory)
    $security = if ($Directory) {
        [Security.AccessControl.DirectorySecurity]::new()
    }
    else {
        [Security.AccessControl.FileSecurity]::new()
    }
    $security.SetSecurityDescriptorBinaryForm($bytes)
    return $security
}

function Set-WgstFileSystemSecurity {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$Directory,
        [Parameter(Mandatory = $true)]
        [Security.AccessControl.FileSystemSecurity]$Security
    )

    [WireguardSplitTunnel.ReleaseScripts.NativeFileAcl]::
        WriteSecurityDescriptor(
            $Path,
            $Directory,
            $Security.GetSecurityDescriptorBinaryForm())
}

function Get-WgstFixedReleaseContract {
    [CmdletBinding()]
    param()

    return [pscustomobject]@{
        repository = $script:WgstContract.repository
        latestReleaseApi = $script:WgstContract.latestReleaseApi
        archiveAsset = $script:WgstContract.archiveAsset
        checksumAsset = $script:WgstContract.checksumAsset
        redirectHosts = @($script:WgstContract.redirectHosts)
        maximumRedirects = $script:WgstContract.maximumRedirects
        metadataBytes = $script:WgstContract.metadataBytes
        checksumBytes = $script:WgstContract.checksumBytes
        archiveBytes = $script:WgstContract.archiveBytes
        metadataTimeoutSeconds =
            $script:WgstContract.metadataTimeoutSeconds
        downloadTimeoutSeconds =
            $script:WgstContract.downloadTimeoutSeconds
        noProgressTimeoutSeconds =
            $script:WgstContract.noProgressTimeoutSeconds
    }
}

function Test-WgstAllowedRedirectUri {
    param([Parameter(Mandatory = $true)][Uri]$Uri)

    return $Uri.IsAbsoluteUri -and
        $Uri.Scheme -ceq 'https' -and
        [string]::IsNullOrEmpty($Uri.UserInfo) -and
        $Uri.IsDefaultPort -and
        ($script:WgstContract.redirectHosts -ccontains $Uri.DnsSafeHost)
}

function Test-WgstStableTag {
    param([string]$Tag)

    return $Tag -cmatch '^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$'
}

function Test-WgstInitialAssetUri {
    param(
        [Parameter(Mandatory = $true)][Uri]$Uri,
        [Parameter(Mandatory = $true)][string]$Tag,
        [Parameter(Mandatory = $true)][string]$AssetName
    )

    if (-not (Test-WgstAllowedRedirectUri $Uri) -or
        $Uri.DnsSafeHost -cne 'github.com' -or
        -not [string]::IsNullOrEmpty($Uri.Query) -or
        -not [string]::IsNullOrEmpty($Uri.Fragment)) {
        return $false
    }

    $expected = '/radmanyeung/wireguard-switch/releases/download/{0}/{1}' -f
        $Tag,
        $AssetName
    return $Uri.AbsolutePath -ceq $expected
}

function New-WgstHttpClient {
    Add-Type -AssemblyName System.Net.Http
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.AutomaticDecompression = [Net.DecompressionMethods](
        [int][Net.DecompressionMethods]::GZip -bor
        [int][Net.DecompressionMethods]::Deflate)
    $client = [Net.Http.HttpClient]::new($handler, $true)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd(
        'WireguardSplitTunnelInstaller/2.0')
    return $client
}

function Invoke-WgstBoundedHttpGet {
    param(
        [Parameter(Mandatory = $true)][Net.Http.HttpClient]$Client,
        [Parameter(Mandatory = $true)][Uri]$Uri,
        [Parameter(Mandatory = $true)][long]$MaximumBytes,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [string]$OutputPath
    )

    $current = $Uri
    for ($redirects = 0; ; $redirects++) {
        if (-not (Test-WgstAllowedRedirectUri $current)) {
            throw "Release URI is not allowed: $current"
        }

        $request = [Net.Http.HttpRequestMessage]::new(
            [Net.Http.HttpMethod]::Get,
            $current)
        $timeout = [Threading.CancellationTokenSource]::new(
            [TimeSpan]::FromSeconds($TimeoutSeconds))
        try {
            $response = $Client.SendAsync(
                $request,
                [Net.Http.HttpCompletionOption]::ResponseHeadersRead,
                $timeout.Token).GetAwaiter().GetResult()
        }
        finally {
            $request.Dispose()
        }

        $status = [int]$response.StatusCode
        if ($status -in @(301, 302, 303, 307, 308)) {
            try {
                if ($redirects -ge $script:WgstContract.maximumRedirects -or
                    $null -eq $response.Headers.Location) {
                    throw 'Release redirect limit was exceeded.'
                }

                $next = if ($response.Headers.Location.IsAbsoluteUri) {
                    $response.Headers.Location
                }
                else {
                    [Uri]::new($current, $response.Headers.Location)
                }
                if (-not (Test-WgstAllowedRedirectUri $next)) {
                    throw "Release redirect is not allowed: $next"
                }
                $current = $next
            }
            finally {
                $response.Dispose()
                $timeout.Dispose()
            }
            continue
        }

        try {
            if (-not $response.IsSuccessStatusCode) {
                throw "Release request failed with HTTP $status."
            }

            $contentLength = $response.Content.Headers.ContentLength
            if ($null -ne $contentLength -and
                $contentLength -gt $MaximumBytes) {
                throw 'Release response exceeds its byte limit.'
            }

            $input = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $output = if ([string]::IsNullOrWhiteSpace($OutputPath)) {
                [IO.MemoryStream]::new()
            }
            else {
                [IO.FileStream]::new(
                    $OutputPath,
                    [IO.FileMode]::CreateNew,
                    [IO.FileAccess]::Write,
                    [IO.FileShare]::None)
            }
            try {
                $buffer = New-Object byte[] 81920
                [long]$total = 0
                while ($true) {
                    $progress = [Threading.CancellationTokenSource]::CreateLinkedTokenSource(
                        $timeout.Token)
                    $progress.CancelAfter(
                        [TimeSpan]::FromSeconds(
                            $script:WgstContract.noProgressTimeoutSeconds))
                    try {
                        $read = $input.ReadAsync(
                            $buffer,
                            0,
                            $buffer.Length,
                            $progress.Token).GetAwaiter().GetResult()
                    }
                    finally {
                        $progress.Dispose()
                    }
                    if ($read -eq 0) {
                        break
                    }

                    $total += $read
                    if ($total -gt $MaximumBytes) {
                        throw 'Release response exceeds its byte limit.'
                    }
                    $output.Write($buffer, 0, $read)
                }

                if ($output -is [IO.MemoryStream]) {
                    return $output.ToArray()
                }
                return $OutputPath
            }
            finally {
                $output.Dispose()
                $input.Dispose()
            }
        }
        finally {
            $response.Dispose()
            $timeout.Dispose()
        }
    }
}

function Get-WgstStableRelease {
    param([Parameter(Mandatory = $true)][Net.Http.HttpClient]$Client)

    $bytes = Invoke-WgstBoundedHttpGet `
        -Client $Client `
        -Uri ([Uri]$script:WgstContract.latestReleaseApi) `
        -MaximumBytes $script:WgstContract.metadataBytes `
        -TimeoutSeconds $script:WgstContract.metadataTimeoutSeconds
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $release = ($utf8.GetString($bytes)) | ConvertFrom-Json
    if ($null -eq $release -or
        -not (Test-WgstStableTag $release.tag_name) -or
        [bool]$release.draft -or
        [bool]$release.prerelease) {
        throw 'Latest GitHub Release is not a strict stable Release.'
    }

    $assets = @($release.assets)
    $archive = @($assets | Where-Object {
        $_.name -ceq $script:WgstContract.archiveAsset
    })
    $checksum = @($assets | Where-Object {
        $_.name -ceq $script:WgstContract.checksumAsset
    })
    if ($archive.Count -ne 1 -or $checksum.Count -ne 1) {
        throw 'Release must contain exactly one Windows archive and checksum asset.'
    }

    $archiveUri = [Uri]$archive[0].browser_download_url
    $checksumUri = [Uri]$checksum[0].browser_download_url
    if (-not (Test-WgstInitialAssetUri `
            -Uri $archiveUri `
            -Tag $release.tag_name `
            -AssetName $script:WgstContract.archiveAsset) -or
        -not (Test-WgstInitialAssetUri `
            -Uri $checksumUri `
            -Tag $release.tag_name `
            -AssetName $script:WgstContract.checksumAsset)) {
        throw 'Release asset URL does not match the fixed repository/tag/name contract.'
    }

    return [pscustomobject]@{
        Tag = [string]$release.tag_name
        ArchiveUri = $archiveUri
        ChecksumUri = $checksumUri
    }
}

function Get-WgstStrictSidecarDigest {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $text = $utf8.GetString($Bytes)
    $asset = [Regex]::Escape($script:WgstContract.archiveAsset)
    $match = [Regex]::Match(
        $text,
        "^([0-9a-f]{64})  $asset(?:\r?\n)?$",
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $match.Success) {
        throw 'Release checksum sidecar has invalid grammar.'
    }
    return $match.Groups[1].Value
}

function Get-WgstFileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = $sha.ComputeHash($stream)
            return (($digest | ForEach-Object {
                $_.ToString('x2')
            }) -join '')
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Test-WgstSafeArchivePath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path.StartsWith('/') -or
        $Path.EndsWith('/') -or
        $Path.Contains('\') -or
        -not $Path.IsNormalized([Text.NormalizationForm]::FormC) -or
        $Path.Contains(':')) {
        return $false
    }

    $invalid = [IO.Path]::GetInvalidFileNameChars()
    foreach ($segment in $Path.Split('/')) {
        if ([string]::IsNullOrWhiteSpace($segment) -or
            $segment -in @('.', '..') -or
            $segment.EndsWith('.') -or
            $segment.EndsWith(' ') -or
            $segment.IndexOfAny($invalid) -ge 0) {
            return $false
        }
        $stem = $segment.Split('.')[0]
        if ($stem -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
            return $false
        }
    }
    return $true
}

function Test-WgstNormalizedVersion {
    param([string]$Version)

    return $Version -cmatch '^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$'
}

function Compare-WgstVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )

    if (-not (Test-WgstNormalizedVersion $Left) -or
        -not (Test-WgstNormalizedVersion $Right)) {
        throw 'Release version is not strict normalized SemVer.'
    }
    $leftParts = @($Left.Split('.') | ForEach-Object {
        [uint64]::Parse($_, [Globalization.CultureInfo]::InvariantCulture)
    })
    $rightParts = @($Right.Split('.') | ForEach-Object {
        [uint64]::Parse($_, [Globalization.CultureInfo]::InvariantCulture)
    })
    for ($index = 0; $index -lt 3; $index++) {
        if ($leftParts[$index] -lt $rightParts[$index]) {
            return -1
        }
        if ($leftParts[$index] -gt $rightParts[$index]) {
            return 1
        }
    }
    return 0
}

function Get-WgstCanonicalManifestJson {
    param([Parameter(Mandatory = $true)]$Manifest)

    $files = @($Manifest.files | ForEach-Object {
        [ordered]@{
            path = [string]$_.path
            length = [long]$_.length
            sha256 = [string]$_.sha256
        }
    })
    $canonical = [ordered]@{
        schemaVersion = [int]$Manifest.schemaVersion
        version = [string]$Manifest.version
        runtimeIdentifier = [string]$Manifest.runtimeIdentifier
        minimumAutoUpdateVersion =
            [string]$Manifest.minimumAutoUpdateVersion
        rollbackCompatibleFromVersion =
            [string]$Manifest.rollbackCompatibleFromVersion
        stateSchemaVersion = [int]$Manifest.stateSchemaVersion
        entryPoint = [string]$Manifest.entryPoint
        updaterEntryPoint = [string]$Manifest.updaterEntryPoint
        requiredLaunchers = @($Manifest.requiredLaunchers |
            ForEach-Object { [string]$_ })
        files = $files
    }
    return ($canonical | ConvertTo-Json -Depth 8 -Compress)
}

function Test-WgstReleasePackageNoSdk {
    param(
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedTag,
        [string]$Props,
        [switch]$AllowRuntimeExtras,
        [switch]$AllowInstalledExtras
    )

    if (-not (Test-WgstStableTag $ExpectedTag) -or
        -not (Test-Path -LiteralPath $PackageRoot -PathType Container)) {
        throw 'Release package request is invalid.'
    }
    $root = [IO.Path]::GetFullPath($PackageRoot)
    $rootItem = Get-Item -LiteralPath $root -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Release package root cannot be a reparse point.'
    }
    $manifestPath = Join-Path $root $script:WgstContract.manifest
    $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
    if ($manifestBytes.LongLength -gt $script:WgstContract.metadataBytes) {
        throw 'Release manifest exceeds its byte limit.'
    }
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $manifestText = $utf8.GetString($manifestBytes)
    $manifest = $manifestText | ConvertFrom-Json
    $expectedProperties = @(
        'schemaVersion',
        'version',
        'runtimeIdentifier',
        'minimumAutoUpdateVersion',
        'rollbackCompatibleFromVersion',
        'stateSchemaVersion',
        'entryPoint',
        'updaterEntryPoint',
        'requiredLaunchers',
        'files'
    )
    if (@($manifest.PSObject.Properties.Name).Count -ne
            $expectedProperties.Count -or
        (Compare-Object `
            -ReferenceObject $expectedProperties `
            -DifferenceObject @($manifest.PSObject.Properties.Name) `
            -CaseSensitive)) {
        throw 'Release manifest properties are not exact.'
    }
    if ($manifestText -cne (Get-WgstCanonicalManifestJson $manifest)) {
        throw 'Release manifest bytes are not canonical.'
    }
    if ([int]$manifest.schemaVersion -ne 1 -or
        [int]$manifest.stateSchemaVersion -le 0 -or
        [string]$manifest.runtimeIdentifier -cne 'win-x64' -or
        [string]$manifest.entryPoint -cne
            $script:WgstContract.applicationPath -or
        [string]$manifest.updaterEntryPoint -cne
            $script:WgstContract.updaterPath -or
        "v$($manifest.version)" -cne $ExpectedTag -or
        -not (Test-WgstNormalizedVersion $manifest.version) -or
        -not (Test-WgstNormalizedVersion `
            $manifest.minimumAutoUpdateVersion) -or
        -not (Test-WgstNormalizedVersion `
            $manifest.rollbackCompatibleFromVersion) -or
        (Compare-WgstVersion `
            $manifest.minimumAutoUpdateVersion `
            $manifest.version) -gt 0 -or
        (Compare-WgstVersion `
            $manifest.rollbackCompatibleFromVersion `
            $manifest.version) -gt 0) {
        throw 'Release manifest identity or compatibility is invalid.'
    }
    if (-not [string]::IsNullOrWhiteSpace($Props)) {
        [xml]$propsXml = Get-Content -LiteralPath $Props -Raw
        $group = @($propsXml.Project.PropertyGroup | Where-Object {
            $null -ne $_.VersionPrefix
        })
        if ($group.Count -ne 1 -or
            [string]$group[0].VersionPrefix -cne
                [string]$manifest.version -or
            [string]$group[0].MinimumAutoUpdateVersion -cne
                [string]$manifest.minimumAutoUpdateVersion -or
            [string]$group[0].RollbackCompatibleFromVersion -cne
                [string]$manifest.rollbackCompatibleFromVersion -or
            [int]$group[0].StateSchemaVersion -ne
                [int]$manifest.stateSchemaVersion) {
            throw 'Release manifest does not match Directory.Build.props.'
        }
    }
    $expectedLaunchers = @(
        'install.cmd',
        'start.cmd',
        'start-admin.cmd',
        'start-safe.cmd',
        'scripts/install.ps1',
        'scripts/start.ps1'
    )
    $launchers = @($manifest.requiredLaunchers)
    if ($launchers.Count -ne $expectedLaunchers.Count) {
        throw 'Release manifest launcher set is invalid.'
    }
    for ($index = 0; $index -lt $expectedLaunchers.Count; $index++) {
        if ([string]$launchers[$index] -cne $expectedLaunchers[$index]) {
            throw 'Release manifest launcher set is invalid.'
        }
    }

    $payloads = @($manifest.files)
    if ($payloads.Count -lt 1 -or
        $payloads.Count -gt ($script:WgstContract.maximumEntries - 1)) {
        throw 'Release manifest payload count is invalid.'
    }
    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $declared = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $lastSortKey = $null
    foreach ($payload in $payloads) {
        $names = @($payload.PSObject.Properties.Name)
        if ($names.Count -ne 3 -or
            (Compare-Object `
                -ReferenceObject @('path', 'length', 'sha256') `
                -DifferenceObject $names `
                -CaseSensitive)) {
            throw 'Release manifest payload properties are invalid.'
        }
        $relative = [string]$payload.path
        $sortKey = "$($relative.ToLowerInvariant())`0$relative"
        if (-not [string]::IsNullOrEmpty($lastSortKey) -and
            [string]::CompareOrdinal($lastSortKey, $sortKey) -gt 0) {
            throw 'Release manifest payloads are not deterministically sorted.'
        }
        $lastSortKey = $sortKey
        if (-not (Test-WgstSafeArchivePath $relative) -or
            $relative -ceq $script:WgstContract.manifest -or
            -not $seen.Add($relative) -or
            [long]$payload.length -lt 0 -or
            [string]$payload.sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'Release manifest payload is invalid.'
        }
        $declared.Add($relative, $payload)
    }
    foreach ($required in @(
        $script:WgstContract.applicationPath,
        $script:WgstContract.updaterPath
    ) + $expectedLaunchers) {
        if (-not $declared.ContainsKey($required)) {
            throw "Release manifest is missing required payload: $required"
        }
    }

    $actual = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($item in Get-ChildItem -LiteralPath $root -Recurse -Force) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Release package contains a reparse point.'
        }
        if ($item.PSIsContainer) {
            continue
        }
        $relative = (Get-WgstContainedRelativePath `
            -Root $root `
            -Path $item.FullName).Replace('\', '/')
        if (-not (Test-WgstSafeArchivePath $relative)) {
            throw "Release package contains an unsafe path: $relative"
        }
        if ($relative -ceq $script:WgstContract.manifest) {
            [void]$actual.Add($relative)
            continue
        }
        if ($AllowRuntimeExtras -and (
            $relative.StartsWith('logs/', [StringComparison]::OrdinalIgnoreCase) -or
            $relative -in @('runtime.log', 'install.status.txt'))) {
            continue
        }
        if ($AllowInstalledExtras -and
            $item -is [IO.FileInfo] -and
            -not $declared.ContainsKey($relative)) {
            continue
        }
        if (-not $declared.ContainsKey($relative) -or
            -not $actual.Add($relative)) {
            throw "Release package contains an undeclared payload: $relative"
        }
        $payload = $declared[$relative]
        if ($item.Length -ne [long]$payload.length -or
            (Get-WgstFileSha256 $item.FullName) -cne
                [string]$payload.sha256) {
            throw "Release payload hash/length mismatch: $relative"
        }
    }
    if (-not $actual.Contains($script:WgstContract.manifest)) {
        throw 'Release package manifest is missing.'
    }
    foreach ($relative in $declared.Keys) {
        if (-not $actual.Contains($relative)) {
            throw "Release payload is missing: $relative"
        }
    }
    foreach ($executable in @(
        $script:WgstContract.applicationPath,
        $script:WgstContract.updaterPath)) {
        $path = Join-Path $root $executable.Replace(
            '/',
            [IO.Path]::DirectorySeparatorChar)
        $productVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo(
            $path).ProductVersion
        if ([string]::IsNullOrWhiteSpace($productVersion)) {
            throw "ProductVersion is missing: $executable"
        }
        $normalized = $productVersion.Split('+')[0]
        if ($normalized -cne [string]$manifest.version) {
            throw "ProductVersion mismatch: $executable"
        }
    }
    return $true
}

function Expand-WgstSafeArchive {
    param(
        [Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][string]$DestinationRoot
    )

    if (Test-Path -LiteralPath $DestinationRoot) {
        if (@(Get-ChildItem -LiteralPath $DestinationRoot -Force).Count -ne 0) {
            throw 'Archive destination must be empty.'
        }
    }
    else {
        New-Item -ItemType Directory -Path $DestinationRoot | Out-Null
    }

    Add-Type -AssemblyName System.IO.Compression
    $destination = [IO.Path]::GetFullPath($DestinationRoot)
    $prefix = $destination + [IO.Path]::DirectorySeparatorChar
    $stream = [IO.File]::OpenRead($ArchivePath)
    try {
        $zip = [IO.Compression.ZipArchive]::new(
            $stream,
            [IO.Compression.ZipArchiveMode]::Read,
            $false)
        try {
            if ($zip.Entries.Count -gt $script:WgstContract.maximumEntries) {
                throw 'Release archive contains too many entries.'
            }
            $seen = [Collections.Generic.HashSet[string]]::new(
                [StringComparer]::OrdinalIgnoreCase)
            [long]$expanded = 0
            [long]$actualExpanded = 0
            foreach ($entry in $zip.Entries) {
                if ([string]::IsNullOrEmpty($entry.Name)) {
                    continue
                }
                $relative = $entry.FullName
                if (-not (Test-WgstSafeArchivePath $relative) -or
                    -not $seen.Add($relative)) {
                    throw "Release archive contains an unsafe path: $relative"
                }
                $unixType = ($entry.ExternalAttributes -shr 16) -band 0xF000
                if ($unixType -eq 0xA000 -or
                    (($entry.ExternalAttributes -band
                        [int][IO.FileAttributes]::ReparsePoint) -ne 0)) {
                    throw "Release archive contains a link: $relative"
                }
                if ($entry.Length -gt $script:WgstContract.maximumFileBytes) {
                    throw 'Release archive file exceeds its size limit.'
                }
                $expanded += $entry.Length
                if ($expanded -gt $script:WgstContract.maximumExpandedBytes) {
                    throw 'Release archive exceeds its expanded size limit.'
                }
                if ($entry.CompressedLength -eq 0) {
                    if ($entry.Length -gt 0) {
                        throw 'Release archive compression ratio is invalid.'
                    }
                }
                elseif (($entry.Length / [double]$entry.CompressedLength) -gt
                    $script:WgstContract.maximumCompressionRatio) {
                    throw 'Release archive compression ratio is invalid.'
                }

                $target = [IO.Path]::GetFullPath(
                    (Join-Path $destination (
                        $relative.Replace(
                            '/',
                            [IO.Path]::DirectorySeparatorChar))))
                if (-not $target.StartsWith(
                        $prefix,
                        [StringComparison]::OrdinalIgnoreCase)) {
                    throw "Release archive path escapes its destination: $relative"
                }
                New-Item -ItemType Directory -Path (
                    Split-Path -Parent $target) -Force | Out-Null
                $input = $entry.Open()
                $output = [IO.File]::Open(
                    $target,
                    [IO.FileMode]::CreateNew,
                    [IO.FileAccess]::Write,
                    [IO.FileShare]::None)
                try {
                    $buffer = New-Object byte[] 81920
                    [long]$actualEntryLength = 0
                    while (($read = $input.Read(
                                $buffer,
                                0,
                                $buffer.Length)) -gt 0) {
                        $actualEntryLength += $read
                        $actualExpanded += $read
                        if ($actualEntryLength -gt $entry.Length -or
                            $actualEntryLength -gt
                                $script:WgstContract.maximumFileBytes -or
                            $actualExpanded -gt
                                $script:WgstContract.maximumExpandedBytes) {
                            throw 'Release archive expanded data exceeds its declared limits.'
                        }
                        $output.Write($buffer, 0, $read)
                    }
                    if ($actualEntryLength -ne $entry.Length) {
                        throw 'Release archive entry length does not match copied bytes.'
                    }
                }
                finally {
                    $output.Dispose()
                    $input.Dispose()
                }
            }
        }
        finally {
            $zip.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function New-WgstPropsFromManifest {
    param(
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    $manifestPath = Join-Path $PackageRoot $script:WgstContract.manifest
    $manifest = Get-Content -LiteralPath $manifestPath -Raw |
        ConvertFrom-Json
    if ($null -eq $manifest -or
        -not (Test-WgstStableTag ("v" + $manifest.version))) {
        throw 'Downloaded Release manifest version is invalid.'
    }
    $xml = @"
<Project>
  <PropertyGroup>
    <VersionPrefix>$($manifest.version)</VersionPrefix>
    <MinimumAutoUpdateVersion>$($manifest.minimumAutoUpdateVersion)</MinimumAutoUpdateVersion>
    <RollbackCompatibleFromVersion>$($manifest.rollbackCompatibleFromVersion)</RollbackCompatibleFromVersion>
    <StateSchemaVersion>$($manifest.stateSchemaVersion)</StateSchemaVersion>
  </PropertyGroup>
</Project>
"@
    [IO.File]::WriteAllText(
        $OutputPath,
        $xml,
        [Text.UTF8Encoding]::new($false))
    return $OutputPath
}

function Get-WgstNativeFileSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$Directory,
        [switch]$RequireSingleLink
    )

    $expected = [IO.Path]::GetFullPath($Path)
    $snapshot =
        [WireguardSplitTunnel.ReleaseScripts.NativeFileIdentity]::Read(
            $expected)
    $isDirectory =
        ($snapshot.Attributes -band [IO.FileAttributes]::Directory) -ne 0
    if ($snapshot.FinalPath -ine $expected -or
        ($snapshot.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $isDirectory -ne [bool]$Directory -or
        ($RequireSingleLink -and $snapshot.LinkCount -ne 1)) {
        throw "Filesystem identity validation failed: $expected"
    }
    return $snapshot
}

function Test-WgstSameNativeFileSnapshot {
    param(
        [Parameter(Mandatory = $true)]$Before,
        [Parameter(Mandatory = $true)]$After
    )

    return $Before.VolumeSerialNumber -eq $After.VolumeSerialNumber -and
        $Before.FileIndex -eq $After.FileIndex -and
        $Before.FinalPath -ieq $After.FinalPath -and
        $Before.Attributes -eq $After.Attributes
}

function Copy-WgstValidatedApplicationSubtree {
    param(
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [Parameter(Mandatory = $true)][string]$DestinationRoot
    )

    $source = Join-Path $PackageRoot 'WireguardSplitTunnel'
    if (-not (Test-Path -LiteralPath $source -PathType Container)) {
        throw 'Validated package application subtree is missing.'
    }
    $manifestPath = Join-Path $PackageRoot $script:WgstContract.manifest
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw 'Validated package manifest is missing.'
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw |
        ConvertFrom-Json
    $expectedPayloads =
        [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::OrdinalIgnoreCase)
    foreach ($payload in @($manifest.files)) {
        $packageRelative = [string]$payload.path
        if ($packageRelative.StartsWith(
                'WireguardSplitTunnel/',
                [StringComparison]::Ordinal)) {
            if (-not (Test-WgstSafeArchivePath $packageRelative) -or
                $expectedPayloads.ContainsKey($packageRelative)) {
                throw 'Validated application manifest payload is invalid.'
            }
            $expectedPayloads.Add($packageRelative, $payload)
        }
    }
    if ($expectedPayloads.Count -lt 2) {
        throw 'Validated application manifest subtree is incomplete.'
    }
    $sourceFull = [IO.Path]::GetFullPath($source)
    $sourceItem = Get-Item -LiteralPath $sourceFull -Force
    if (($sourceItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Validated application subtree root is a reparse point.'
    }
    foreach ($item in Get-ChildItem -LiteralPath $source -Recurse -Force) {
        if (($item.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Validated application subtree contains a reparse point.'
        }
    }

    $destinationFull = [IO.Path]::GetFullPath($DestinationRoot)
    if (Test-Path -LiteralPath $destinationFull) {
        throw 'Bootstrap destination must not already exist.'
    }
    $ancestor = Split-Path -Parent $destinationFull
    while (-not [string]::IsNullOrWhiteSpace($ancestor)) {
        if (Test-Path -LiteralPath $ancestor) {
            $ancestorItem = Get-Item -LiteralPath $ancestor -Force
            if (-not $ancestorItem.PSIsContainer -or
                ($ancestorItem.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Bootstrap destination has an unsafe ancestor.'
            }
        }
        $parent = Split-Path -Parent $ancestor
        if ($parent -eq $ancestor) {
            break
        }
        $ancestor = $parent
    }
    New-Item -ItemType Directory -Path $destinationFull | Out-Null
    $createdDestination = Get-Item -LiteralPath $destinationFull -Force
    if (($createdDestination.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Bootstrap destination became unsafe.'
    }
    $destinationRootIdentity = Get-WgstNativeFileSnapshot `
        -Path $destinationFull `
        -Directory

    $createdDirectories = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    [void]$createdDirectories.Add($destinationFull)
    $copiedPayloads = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($file in Get-ChildItem -LiteralPath $source -Recurse -File -Force) {
        if (($file.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Validated application payload became unsafe.'
        }
        $relative = Get-WgstContainedRelativePath `
            -Root $sourceFull `
            -Path $file.FullName
        $manifestRelative =
            "WireguardSplitTunnel/$($relative.Replace('\', '/'))"
        if (-not $expectedPayloads.ContainsKey($manifestRelative) -or
            -not $copiedPayloads.Add($manifestRelative)) {
            throw 'Application payload is not bound to the validated manifest.'
        }
        $expectedPayload = $expectedPayloads[$manifestRelative]
        if ([string]$expectedPayload.path -cne $manifestRelative -or
            $file.Length -ne [long]$expectedPayload.length -or
            (Get-WgstFileSha256 $file.FullName) -cne
                [string]$expectedPayload.sha256) {
            throw 'Application payload no longer matches the validated manifest.'
        }
        $sourceIdentity = Get-WgstNativeFileSnapshot `
            -Path $file.FullName `
            -RequireSingleLink
        $target = Join-Path $destinationFull $relative
        $relativeParent = Split-Path -Parent $relative
        $currentDirectory = $destinationFull
        if (-not [string]::IsNullOrWhiteSpace($relativeParent)) {
            foreach ($segment in $relativeParent.Split(
                    [IO.Path]::DirectorySeparatorChar)) {
                $currentDirectory = Join-Path $currentDirectory $segment
                if (Test-Path -LiteralPath $currentDirectory) {
                    if (-not $createdDirectories.Contains(
                            [IO.Path]::GetFullPath($currentDirectory))) {
                        throw 'Bootstrap destination directory appeared unexpectedly.'
                    }
                }
                else {
                    New-Item `
                        -ItemType Directory `
                        -Path $currentDirectory | Out-Null
                    [void]$createdDirectories.Add(
                        [IO.Path]::GetFullPath($currentDirectory))
                }
                $directoryItem = Get-Item `
                    -LiteralPath $currentDirectory `
                    -Force
                if (-not $directoryItem.PSIsContainer -or
                    ($directoryItem.Attributes -band
                        [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw 'Bootstrap destination directory became unsafe.'
                }
            }
        }
        if (Test-Path -LiteralPath $target) {
            throw 'Bootstrap destination payload already exists.'
        }
        $targetParent = Split-Path -Parent $target
        $targetParentIdentity = Get-WgstNativeFileSnapshot `
            -Path $targetParent `
            -Directory
        [IO.File]::Copy($file.FullName, $target, $false)
        $copiedIdentity = Get-WgstNativeFileSnapshot `
            -Path $target `
            -RequireSingleLink
        $sourceIdentityAfter = Get-WgstNativeFileSnapshot `
            -Path $file.FullName `
            -RequireSingleLink
        $targetParentIdentityAfter = Get-WgstNativeFileSnapshot `
            -Path $targetParent `
            -Directory
        if (-not (Test-WgstSameNativeFileSnapshot `
                -Before $sourceIdentity `
                -After $sourceIdentityAfter) -or
            -not (Test-WgstSameNativeFileSnapshot `
                -Before $targetParentIdentity `
                -After $targetParentIdentityAfter) -or
            $copiedIdentity.LinkCount -ne 1 -or
            (Get-WgstFileSha256 $file.FullName) -cne
                [string]$expectedPayload.sha256 -or
            (Get-WgstFileSha256 $target) -cne
                [string]$expectedPayload.sha256) {
            throw 'Bootstrap destination payload copy could not be certified.'
        }
    }
    if ($copiedPayloads.Count -ne $expectedPayloads.Count) {
        throw 'Validated application manifest payload is missing from the copy.'
    }
    foreach ($item in Get-ChildItem `
            -LiteralPath $destinationFull `
            -Recurse `
            -Force) {
        if (($item.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Bootstrap destination contains a reparse point.'
        }
    }
    $destinationRootIdentityAfter = Get-WgstNativeFileSnapshot `
        -Path $destinationFull `
        -Directory
    if (-not (Test-WgstSameNativeFileSnapshot `
            -Before $destinationRootIdentity `
            -After $destinationRootIdentityAfter)) {
        throw 'Bootstrap destination root identity changed during copy.'
    }

    $app = Join-Path $destinationFull 'WireguardSplitTunnel.App.exe'
    $updater = Join-Path $destinationFull 'WireguardSplitTunnel.Updater.exe'
    if (-not (Test-Path -LiteralPath $app -PathType Leaf) -or
        -not (Test-Path -LiteralPath $updater -PathType Leaf)) {
        throw 'Validated application subtree is incomplete.'
    }
    return $app
}

function Test-WgstBundledRelease {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$PackageRoot)

    $manifestPath = Join-Path $PackageRoot $script:WgstContract.manifest
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        return $false
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw |
        ConvertFrom-Json
    $tag = "v$($manifest.version)"
    if (-not (Test-WgstStableTag $tag)) {
        return $false
    }
    try {
        [void](Test-WgstReleasePackageNoSdk `
            -PackageRoot $PackageRoot `
            -ExpectedTag $tag `
            -AllowRuntimeExtras)
        return $true
    }
    catch {
        return $false
    }
}

function Test-WgstPackageTreesEqual {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )

    $leftFull = [IO.Path]::GetFullPath($Left)
    $rightFull = [IO.Path]::GetFullPath($Right)
    $leftManifest = Join-Path $leftFull $script:WgstContract.manifest
    $rightManifest = Join-Path $rightFull $script:WgstContract.manifest
    if (-not (Test-Path -LiteralPath $leftManifest -PathType Leaf) -or
        -not (Test-Path -LiteralPath $rightManifest -PathType Leaf) -or
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($leftManifest)) -cne
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($rightManifest))) {
        return $false
    }

    $manifest = Get-Content -LiteralPath $rightManifest -Raw |
        ConvertFrom-Json
    foreach ($payload in @($manifest.files)) {
        $relative = [string]$payload.path
        if (-not (Test-WgstSafeArchivePath $relative)) {
            return $false
        }
        $nativeRelative = $relative.Replace(
            '/',
            [IO.Path]::DirectorySeparatorChar)
        $leftPath = Join-Path $leftFull $nativeRelative
        $rightPath = Join-Path $rightFull $nativeRelative
        if (-not (Test-Path -LiteralPath $leftPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $rightPath -PathType Leaf)) {
            return $false
        }
        $leftItem = Get-Item -LiteralPath $leftPath -Force
        $rightItem = Get-Item -LiteralPath $rightPath -Force
        if (($leftItem.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($rightItem.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $leftItem.Length -ne $rightItem.Length -or
            (Get-WgstFileSha256 $leftPath) -cne
                (Get-WgstFileSha256 $rightPath)) {
            return $false
        }
    }
    return $true
}

function Get-WgstContainedRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $prefix = $rootFull + [IO.Path]::DirectorySeparatorChar
    $pathFull = [IO.Path]::GetFullPath($Path)
    if (-not $pathFull.StartsWith(
            $prefix,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes its declared root: $Path"
    }
    return $pathFull.Substring($prefix.Length)
}

function New-WgstExactInstalledReleaseSecurity {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'RootDirectory',
            'DescendantDirectory',
            'ManagedFile')]
        [string]$Scope
    )

    $sddl = switch ($Scope) {
        'RootDirectory' {
            'O:SYD:P' +
                '(A;OICI;FA;;;BA)' +
                '(A;OICI;FA;;;SY)' +
                '(A;OICI;0x1200a9;;;BU)'
        }
        'DescendantDirectory' {
            'O:SYD:AI' +
                '(A;OICIID;FA;;;BA)' +
                '(A;OICIID;FA;;;SY)' +
                '(A;OICIID;0x1200a9;;;BU)'
        }
        'ManagedFile' {
            'O:SYD:AI' +
                '(A;ID;FA;;;BA)' +
                '(A;ID;FA;;;SY)' +
                '(A;ID;0x1200a9;;;BU)'
        }
    }
    $raw =
        [Security.AccessControl.RawSecurityDescriptor]::new($sddl)
    $bytes = New-Object byte[] $raw.BinaryLength
    $raw.GetBinaryForm($bytes, 0)
    $security = if ($Scope -ceq 'ManagedFile') {
        [Security.AccessControl.FileSecurity]::new()
    }
    else {
        [Security.AccessControl.DirectorySecurity]::new()
    }
    $security.SetSecurityDescriptorBinaryForm($bytes)
    return $security
}

function Test-WgstExactInstalledReleaseSecurity {
    param(
        [Parameter(Mandatory = $true)]
        [Security.AccessControl.FileSystemSecurity]$Security,
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'RootDirectory',
            'DescendantDirectory',
            'ManagedFile')]
        [string]$Scope
    )

    try {
        $directory = $Scope -cne 'ManagedFile'
        $root = $Scope -ceq 'RootDirectory'
        if (($directory -and -not ($Security -is
                    [Security.AccessControl.DirectorySecurity])) -or
            (-not $directory -and -not ($Security -is
                    [Security.AccessControl.FileSecurity])) -or
            $Security.AreAccessRulesProtected -ne $root -or
            -not $Security.AreAccessRulesCanonical) {
            return $false
        }
        $descriptor =
            [Security.AccessControl.RawSecurityDescriptor]::new(
                $Security.GetSecurityDescriptorBinaryForm(),
                0)
    }
    catch {
        return $false
    }

    $daclPresent =
        [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent
    $daclProtected =
        [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
    if (($descriptor.ControlFlags -band $daclPresent) -eq 0 -or
        ((($descriptor.ControlFlags -band $daclProtected) -ne 0) -ne
            $root) -or
        $null -eq $descriptor.Owner -or
        $descriptor.Owner.Value -cne 'S-1-5-18' -or
        $null -eq $descriptor.DiscretionaryAcl -or
        $descriptor.DiscretionaryAcl.Count -ne 3) {
        return $false
    }

    $expectedFlags = if ($root) {
        [Security.AccessControl.AceFlags](
            [int][Security.AccessControl.AceFlags]::ContainerInherit -bor
            [int][Security.AccessControl.AceFlags]::ObjectInherit)
    }
    elseif ($directory) {
        [Security.AccessControl.AceFlags](
            [int][Security.AccessControl.AceFlags]::ContainerInherit -bor
            [int][Security.AccessControl.AceFlags]::ObjectInherit -bor
            [int][Security.AccessControl.AceFlags]::Inherited)
    }
    else {
        [Security.AccessControl.AceFlags]::Inherited
    }
    $expected =
        [Collections.Generic.Dictionary[string, int]]::new(
            [StringComparer]::Ordinal)
    $expected.Add(
        'S-1-5-18',
        [int][Security.AccessControl.FileSystemRights]::FullControl)
    $expected.Add(
        'S-1-5-32-544',
        [int][Security.AccessControl.FileSystemRights]::FullControl)
    $expected.Add(
        'S-1-5-32-545',
        [int](
            [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
            [Security.AccessControl.FileSystemRights]::Synchronize))
    foreach ($genericAce in $descriptor.DiscretionaryAcl) {
        if (-not ($genericAce -is
                [Security.AccessControl.CommonAce])) {
            return $false
        }
        $ace = [Security.AccessControl.CommonAce]$genericAce
        if ($ace.IsCallback -or
            $ace.AceQualifier -ne
                [Security.AccessControl.AceQualifier]::AccessAllowed -or
            $ace.AceFlags -ne $expectedFlags -or
            $ace.OpaqueLength -ne 0 -or
            $null -eq $ace.SecurityIdentifier -or
            -not $expected.ContainsKey(
                $ace.SecurityIdentifier.Value) -or
            $ace.AccessMask -ne
                $expected[$ace.SecurityIdentifier.Value]) {
            return $false
        }
        [void]$expected.Remove($ace.SecurityIdentifier.Value)
    }
    return $expected.Count -eq 0
}

function Test-WgstSafeInstalledReleaseRootAuthority {
    param([Parameter(Mandatory = $true)][string]$PackageRoot)

    try {
        $fullRoot = [IO.Path]::GetFullPath($PackageRoot)
        $root = $fullRoot.TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        if ($root.StartsWith('\\')) {
            return $false
        }
        $driveRoot = [IO.Path]::GetPathRoot($fullRoot)
        if ([string]::IsNullOrWhiteSpace($driveRoot) -or
            $root -ieq $driveRoot.TrimEnd(
                [IO.Path]::DirectorySeparatorChar,
                [IO.Path]::AltDirectorySeparatorChar) -or
            [IO.DriveInfo]::new($driveRoot).DriveType -ne
                [IO.DriveType]::Fixed) {
            return $false
        }
        $current = $root
        while (-not [string]::IsNullOrWhiteSpace($current)) {
            $item = Get-Item -LiteralPath $current -Force
            if (-not $item.PSIsContainer -or
                ($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $false
            }
            $parent = Split-Path -Parent $current
            if ($parent -eq $current) {
                break
            }
            $current = $parent
        }
        return $true
    }
    catch {
        return $false
    }
}

function Get-WgstProtectedInstallRoot {
    [CmdletBinding()]
    param()

    $programFiles = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFiles)
    if ([string]::IsNullOrWhiteSpace($programFiles)) {
        throw 'Program Files could not be resolved.'
    }
    return [IO.Path]::GetFullPath(
        (Join-Path $programFiles 'WireguardSplitTunnel'))
}

function Test-WgstProtectedInstallParentAuthority {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)

    try {
        $expectedRoot = Get-WgstProtectedInstallRoot
        $root = [IO.Path]::GetFullPath($InstallRoot).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        if ($root -ine $expectedRoot) {
            return $false
        }
        $parent = Split-Path -Parent $root
        [void](Get-WgstNativeFileSnapshot -Path $parent -Directory)
        $security = Get-WgstFileSystemSecurity `
            -Path $parent `
            -Directory $true
        return Test-WgstProtectedInstallParentDescriptorAuthority `
            -Security $security
    }
    catch {
        return $false
    }
}

function Test-WgstProtectedInstallParentDescriptorAuthority {
    param(
        [Parameter(Mandatory = $true)]
        [Security.AccessControl.DirectorySecurity]$Security
    )

    try {
        if (-not $Security.AreAccessRulesProtected -or
            -not $Security.AreAccessRulesCanonical) {
            return $false
        }
        $descriptor =
            [Security.AccessControl.RawSecurityDescriptor]::new(
                $Security.GetSecurityDescriptorBinaryForm(),
                0)
        if ($null -eq $descriptor.Owner -or
            $null -eq $descriptor.DiscretionaryAcl) {
            return $false
        }

        $trustedAuthorities =
            [Collections.Generic.HashSet[string]]::new(
                [StringComparer]::Ordinal)
        foreach ($sid in @(
                'S-1-5-18',
                'S-1-5-32-544',
                'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')) {
            [void]$trustedAuthorities.Add($sid)
        }
        if (-not $trustedAuthorities.Contains(
                $descriptor.Owner.Value)) {
            return $false
        }

        $dangerousMask = 0x00000002 -bor
            0x00000004 -bor
            0x00000040 -bor
            0x00010000 -bor
            0x00040000 -bor
            0x00080000 -bor
            0x10000000 -bor
            0x40000000
        foreach ($genericAce in $descriptor.DiscretionaryAcl) {
            if (-not ($genericAce -is
                    [Security.AccessControl.CommonAce])) {
                return $false
            }
            $ace = [Security.AccessControl.CommonAce]$genericAce
            if ($ace.IsCallback -or
                $ace.OpaqueLength -ne 0 -or
                $null -eq $ace.SecurityIdentifier) {
                return $false
            }
            if (([int]$ace.AceFlags -band
                    [int][Security.AccessControl.AceFlags]::InheritOnly) -ne 0) {
                continue
            }
            if ($ace.AceQualifier -eq
                    [Security.AccessControl.AceQualifier]::AccessAllowed -and
                -not $trustedAuthorities.Contains(
                    $ace.SecurityIdentifier.Value) -and
                ($ace.AccessMask -band $dangerousMask) -ne 0) {
                return $false
            }
        }
        return $true
    }
    catch {
        return $false
    }
}

function Assert-WgstInstalledReleaseTreeHasNoReparsePoints {
    param([Parameter(Mandatory = $true)][string]$PackageRoot)

    $pending =
        [Collections.Generic.Stack[string]]::new()
    $pending.Push([IO.Path]::GetFullPath($PackageRoot))
    $count = 0
    while ($pending.Count -gt 0) {
        $current = $pending.Pop()
        [void](Get-WgstNativeFileSnapshot `
            -Path $current `
            -Directory)
        foreach ($item in Get-ChildItem `
                -LiteralPath $current `
                -Force) {
            $count++
            if ($count -gt ($script:WgstContract.maximumEntries * 2) -or
                ($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Installed Release tree is unsafe.'
            }
            if ($item.PSIsContainer) {
                $pending.Push($item.FullName)
            }
        }
    }
}

function Get-WgstAuthenticatedBundledReleaseAclPlan {
    param(
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [switch]$AllowInstalledExtras
    )

    $root = [IO.Path]::GetFullPath($PackageRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    if (-not (Test-WgstSafeInstalledReleaseRootAuthority $root)) {
        throw 'Installed Release root has an unsafe authority.'
    }
    Assert-WgstInstalledReleaseTreeHasNoReparsePoints `
        -PackageRoot $root

    $manifestPath = Join-Path $root $script:WgstContract.manifest
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw 'Installed Release manifest is missing.'
    }
    $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
    if ($manifestBytes.LongLength -gt $script:WgstContract.metadataBytes) {
        throw 'Installed Release manifest exceeds its byte limit.'
    }
    $manifestText =
        [Text.UTF8Encoding]::new($false, $true).GetString(
            $manifestBytes)
    $manifest = $manifestText | ConvertFrom-Json
    $tag = "v$($manifest.version)"
    if (-not (Test-WgstStableTag $tag)) {
        throw 'Installed Release manifest version is invalid.'
    }
    [void](Test-WgstReleasePackageNoSdk `
        -PackageRoot $root `
        -ExpectedTag $tag `
        -AllowRuntimeExtras `
        -AllowInstalledExtras:$AllowInstalledExtras)

    $directoryPaths =
        [Collections.Generic.Dictionary[string, string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
    $filePaths =
        [Collections.Generic.Dictionary[string, string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
    $payloads =
        [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::OrdinalIgnoreCase)
    foreach ($payload in @($manifest.files)) {
        $payloads.Add([string]$payload.path, $payload)
    }
    $directoryPaths.Add($root, [string]::Empty)
    $managedRelativePaths = @($script:WgstContract.manifest) +
        @($payloads.Keys)
    foreach ($relative in $managedRelativePaths) {
        if (-not (Test-WgstSafeArchivePath $relative)) {
            throw 'Installed Release managed path is unsafe.'
        }
        $nativeRelative = $relative.Replace(
            '/',
            [IO.Path]::DirectorySeparatorChar)
        $path = [IO.Path]::GetFullPath((Join-Path $root $nativeRelative))
        $contained = (Get-WgstContainedRelativePath `
            -Root $root `
            -Path $path).Replace(
                [IO.Path]::DirectorySeparatorChar,
                '/')
        if ($contained -ine $relative -or
            $filePaths.ContainsKey($path)) {
            throw 'Installed Release managed path is ambiguous.'
        }
        $filePaths.Add($path, $relative)

        $parent = Split-Path -Parent $path
        while ($parent -ine $root) {
            [void](Get-WgstContainedRelativePath `
                -Root $root `
                -Path $parent)
            if (-not $directoryPaths.ContainsKey($parent)) {
                $directoryPaths.Add(
                    $parent,
                    (Get-WgstContainedRelativePath `
                        -Root $root `
                        -Path $parent))
            }
            $next = Split-Path -Parent $parent
            if ([string]::IsNullOrWhiteSpace($next) -or
                $next -eq $parent) {
                throw 'Installed Release parent path is unsafe.'
            }
            $parent = $next
        }
    }

    $directories = @($directoryPaths.GetEnumerator() | ForEach-Object {
        $snapshot = Get-WgstNativeFileSnapshot `
            -Path $_.Key `
            -Directory
        [pscustomobject]@{
            FullPath = $_.Key
            RelativePath = $_.Value
            Directory = $true
            Scope = if ([string]::IsNullOrEmpty($_.Value)) {
                'RootDirectory'
            }
            else {
                'DescendantDirectory'
            }
            Snapshot = $snapshot
        }
    } | Sort-Object `
        @{ Expression = {
            if ([string]::IsNullOrEmpty($_.RelativePath)) {
                0
            }
            else {
                $_.RelativePath.Split(
                    [IO.Path]::DirectorySeparatorChar).Count
            }
        } }, `
        @{ Expression = { $_.RelativePath } })
    $files = @($filePaths.GetEnumerator() | ForEach-Object {
        $snapshot = Get-WgstNativeFileSnapshot `
            -Path $_.Key `
            -RequireSingleLink
        $length = if ($_.Value -ceq $script:WgstContract.manifest) {
            $manifestBytes.LongLength
        }
        else {
            [long]$payloads[$_.Value].length
        }
        $sha256 = if ($_.Value -ceq $script:WgstContract.manifest) {
            Get-WgstFileSha256 $manifestPath
        }
        else {
            [string]$payloads[$_.Value].sha256
        }
        [pscustomobject]@{
            FullPath = $_.Key
            RelativePath = $_.Value
            Directory = $false
            Scope = 'ManagedFile'
            Snapshot = $snapshot
            Length = $length
            Sha256 = $sha256
        }
    } | Sort-Object @{ Expression = { $_.RelativePath } })

    $rootParent = Split-Path -Parent $root
    if ([string]::IsNullOrWhiteSpace($rootParent)) {
        throw 'Installed Release root parent is invalid.'
    }
    return [pscustomobject]@{
        Root = $root
        Tag = $tag
        RootParent = [pscustomobject]@{
            FullPath = $rootParent
            Directory = $true
            Snapshot = Get-WgstNativeFileSnapshot `
                -Path $rootParent `
                -Directory
        }
        Directories = $directories
        Files = $files
    }
}

function Get-WgstAuthenticatedBundledReleaseBinding {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$PackageRoot)

    $plan = Get-WgstAuthenticatedBundledReleaseAclPlan `
        -PackageRoot $PackageRoot
    $manifest = @($plan.Files | Where-Object {
        $_.RelativePath -ceq $script:WgstContract.manifest
    })
    if ($manifest.Count -ne 1) {
        throw 'Installed Release manifest binding is ambiguous.'
    }
    return [pscustomobject]@{
        packageRoot = $plan.Root
        volumeSerialNumber =
            [uint32]$plan.Directories[0].Snapshot.VolumeSerialNumber
        fileIndex = [uint64]$plan.Directories[0].Snapshot.FileIndex
        manifestLength = [long]$manifest[0].Length
        manifestSha256 = [string]$manifest[0].Sha256
        tag = [string]$plan.Tag
    }
}

function Assert-WgstAuthenticatedBundledReleaseBinding {
    param(
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [Parameter(Mandatory = $true)]
        [uint32]$ExpectedVolumeSerialNumber,
        [Parameter(Mandatory = $true)]
        [uint64]$ExpectedFileIndex,
        [Parameter(Mandatory = $true)]
        [long]$ExpectedManifestLength,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedManifestSha256
    )

    if ($ExpectedVolumeSerialNumber -eq 0 -or
        $ExpectedFileIndex -eq 0 -or
        $ExpectedManifestLength -le 0 -or
        $ExpectedManifestSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Installed Release binding request is invalid.'
    }
    $plan = Get-WgstAuthenticatedBundledReleaseAclPlan `
        -PackageRoot $PackageRoot
    $root = @($plan.Directories | Where-Object {
        $_.Scope -ceq 'RootDirectory'
    })
    $manifest = @($plan.Files | Where-Object {
        $_.RelativePath -ceq $script:WgstContract.manifest
    })
    if ($root.Count -ne 1 -or
        $manifest.Count -ne 1 -or
        [uint32]$root[0].Snapshot.VolumeSerialNumber -ne
            $ExpectedVolumeSerialNumber -or
        [uint64]$root[0].Snapshot.FileIndex -ne
            $ExpectedFileIndex -or
        [long]$manifest[0].Length -ne $ExpectedManifestLength -or
        [string]$manifest[0].Sha256 -cne
            $ExpectedManifestSha256) {
        throw 'Installed Release binding changed before elevation.'
    }
    return $plan
}

function Assert-WgstInstalledReleaseAclTargetIdentity {
    param([Parameter(Mandatory = $true)]$Target)

    $current = if ($Target.Directory) {
        Get-WgstNativeFileSnapshot `
            -Path $Target.FullPath `
            -Directory
    }
    else {
        Get-WgstNativeFileSnapshot `
            -Path $Target.FullPath `
            -RequireSingleLink
    }
    if (-not (Test-WgstSameNativeFileSnapshot `
            -Before $Target.Snapshot `
            -After $current) -or
        (-not $Target.Directory -and $current.LinkCount -ne 1)) {
        throw 'Installed Release filesystem identity changed.'
    }
}

function Get-WgstInstalledReleaseAclPlanParent {
    param(
        [Parameter(Mandatory = $true)]$Plan,
        [Parameter(Mandatory = $true)]$Target
    )

    if ($Target.Scope -ceq 'RootDirectory') {
        return $Plan.RootParent
    }
    $parentPath = Split-Path -Parent $Target.FullPath
    $matches = @($Plan.Directories | Where-Object {
        $_.FullPath -ieq $parentPath
    })
    if ($matches.Count -ne 1) {
        throw 'Installed Release ACL parent plan is incomplete.'
    }
    return $matches[0]
}

function Test-WgstExactInstalledReleaseAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'RootDirectory',
            'DescendantDirectory',
            'ManagedFile')]
        [string]$Scope
    )

    try {
        $directory = $Scope -cne 'ManagedFile'
        $before = if ($directory) {
            Get-WgstNativeFileSnapshot -Path $Path -Directory
        }
        else {
            Get-WgstNativeFileSnapshot -Path $Path -RequireSingleLink
        }
        $security = Get-WgstFileSystemSecurity `
            -Path $Path `
            -Directory $directory
        $after = if ($directory) {
            Get-WgstNativeFileSnapshot -Path $Path -Directory
        }
        else {
            Get-WgstNativeFileSnapshot -Path $Path -RequireSingleLink
        }
        return (Test-WgstSameNativeFileSnapshot `
                -Before $before `
                -After $after) -and
            (Test-WgstExactInstalledReleaseSecurity `
                -Security $security `
                -Scope $Scope)
    }
    catch {
        return $false
    }
}

function Set-WgstAuthenticatedBundledReleaseAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [switch]$AllowInstalledExtras
    )

    $plan = Get-WgstAuthenticatedBundledReleaseAclPlan `
        -PackageRoot $PackageRoot `
        -AllowInstalledExtras:$AllowInstalledExtras
    foreach ($target in @($plan.Directories) + @($plan.Files)) {
        Assert-WgstInstalledReleaseAclTargetIdentity -Target $target
    }
    Assert-WgstInstalledReleaseAclTargetIdentity `
        -Target $plan.RootParent

    $privilege =
        [WireguardSplitTunnel.ReleaseScripts.NativeFileIdentity]::
            EnableRestorePrivilege()
    try {
        foreach ($target in @($plan.Directories) + @($plan.Files)) {
            $parent = Get-WgstInstalledReleaseAclPlanParent `
                -Plan $plan `
                -Target $target
            Assert-WgstInstalledReleaseAclTargetIdentity -Target $parent
            Assert-WgstInstalledReleaseAclTargetIdentity -Target $target
            $security = New-WgstExactInstalledReleaseSecurity `
                -Scope $target.Scope
            Set-WgstFileSystemSecurity `
                -Path $target.FullPath `
                -Directory ([bool]$target.Directory) `
                -Security $security
            Assert-WgstInstalledReleaseAclTargetIdentity -Target $target
            Assert-WgstInstalledReleaseAclTargetIdentity -Target $parent
            if (-not (Test-WgstExactInstalledReleaseAcl `
                    -Path $target.FullPath `
                    -Scope $target.Scope)) {
                throw 'Installed Release ACL mutation failed validation.'
            }
        }
    }
    finally {
        $privilege.Dispose()
    }

    foreach ($target in @($plan.Directories) + @($plan.Files)) {
        Assert-WgstInstalledReleaseAclTargetIdentity -Target $target
        if (-not (Test-WgstExactInstalledReleaseAcl `
                -Path $target.FullPath `
                -Scope $target.Scope)) {
            throw 'Installed Release ACL final validation failed.'
        }
    }
    Assert-WgstInstalledReleaseAclTargetIdentity `
        -Target $plan.RootParent
    [void](Test-WgstReleasePackageNoSdk `
        -PackageRoot $plan.Root `
        -ExpectedTag $plan.Tag `
        -AllowRuntimeExtras `
        -AllowInstalledExtras:$AllowInstalledExtras)
    foreach ($target in @($plan.Directories) + @($plan.Files)) {
        Assert-WgstInstalledReleaseAclTargetIdentity -Target $target
    }
    return $true
}

function Copy-WgstBoundManagedFile {
    param(
        [Parameter(Mandatory = $true)]$Source,
        [Parameter(Mandatory = $true)][string]$TargetPath
    )

    Assert-WgstInstalledReleaseAclTargetIdentity -Target $Source
    if (Test-Path -LiteralPath $TargetPath) {
        throw 'Protected install target already exists.'
    }
    $targetParent = Split-Path -Parent $TargetPath
    $targetParentBefore = Get-WgstNativeFileSnapshot `
        -Path $targetParent `
        -Directory
    $input = [IO.File]::Open(
        $Source.FullPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    $output = $null
    $hash =
        [Security.Cryptography.IncrementalHash]::CreateHash(
            [Security.Cryptography.HashAlgorithmName]::SHA256)
    try {
        Assert-WgstInstalledReleaseAclTargetIdentity -Target $Source
        $output = [IO.File]::Open(
            $TargetPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        $buffer = New-Object byte[] 81920
        [long]$length = 0
        while (($read = $input.Read(
                    $buffer,
                    0,
                    $buffer.Length)) -gt 0) {
            $length = checked($length + $read)
            if ($length -gt [long]$Source.Length) {
                throw 'Bound Release payload exceeded its declared length.'
            }
            $hash.AppendData($buffer, 0, $read)
            $output.Write($buffer, 0, $read)
        }
        $output.Flush($true)
        $digest = [BitConverter]::ToString(
            $hash.GetHashAndReset()).Replace('-', '').ToLowerInvariant()
        if ($length -ne [long]$Source.Length -or
            $digest -cne [string]$Source.Sha256) {
            throw 'Bound Release payload bytes changed during copy.'
        }
        Assert-WgstInstalledReleaseAclTargetIdentity -Target $Source
    }
    finally {
        if ($null -ne $output) {
            $output.Dispose()
        }
        $hash.Dispose()
        $input.Dispose()
    }

    $target = Get-WgstNativeFileSnapshot `
        -Path $TargetPath `
        -RequireSingleLink
    $targetParentAfter = Get-WgstNativeFileSnapshot `
        -Path $targetParent `
        -Directory
    if (-not (Test-WgstSameNativeFileSnapshot `
            -Before $targetParentBefore `
            -After $targetParentAfter) -or
        $target.LinkCount -ne 1 -or
        (Get-Item -LiteralPath $TargetPath -Force).Length -ne
            [long]$Source.Length -or
        (Get-WgstFileSha256 $TargetPath) -cne
            [string]$Source.Sha256) {
        throw 'Protected install payload copy could not be certified.'
    }
}

function Remove-WgstProtectedInstallStaging {
    param(
        [Parameter(Mandatory = $true)][string]$InstallRoot,
        [Parameter(Mandatory = $true)][string]$StagingRoot
    )

    $expected = Get-WgstProtectedInstallRoot
    $install = [IO.Path]::GetFullPath($InstallRoot)
    $staging = [IO.Path]::GetFullPath($StagingRoot)
    $parent = Split-Path -Parent $expected
    if ($install -ine $expected -or
        (Split-Path -Parent $staging) -ine $parent -or
        -not (Split-Path -Leaf $staging).StartsWith(
            'WireguardSplitTunnel.install-',
            [StringComparison]::Ordinal) -or
        -not (Test-WgstProtectedInstallParentAuthority `
            -InstallRoot $install)) {
        throw 'Protected install cleanup boundary is invalid.'
    }
    [void](Get-WgstNativeFileSnapshot -Path $parent -Directory)
    Assert-WgstInstalledReleaseTreeHasNoReparsePoints `
        -PackageRoot $staging
    Remove-Item -LiteralPath $staging -Recurse -Force
}

function Test-WgstInstalledReleaseAclPlanExact {
    param([Parameter(Mandatory = $true)]$Plan)

    foreach ($target in @($Plan.Directories) + @($Plan.Files)) {
        Assert-WgstInstalledReleaseAclTargetIdentity -Target $target
        if (-not (Test-WgstExactInstalledReleaseAcl `
                -Path $target.FullPath `
                -Scope $target.Scope)) {
            return $false
        }
    }
    return $true
}

function Install-WgstAuthenticatedBundledReleaseToProtectedAnchor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [Parameter(Mandatory = $true)]
        [uint32]$ExpectedVolumeSerialNumber,
        [Parameter(Mandatory = $true)]
        [uint64]$ExpectedFileIndex,
        [Parameter(Mandatory = $true)]
        [long]$ExpectedManifestLength,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedManifestSha256,
        [switch]$RepairBootstrap
    )

    $sourcePlan = Assert-WgstAuthenticatedBundledReleaseBinding `
        -PackageRoot $PackageRoot `
        -ExpectedVolumeSerialNumber $ExpectedVolumeSerialNumber `
        -ExpectedFileIndex $ExpectedFileIndex `
        -ExpectedManifestLength $ExpectedManifestLength `
        -ExpectedManifestSha256 $ExpectedManifestSha256
    $installRoot = Get-WgstProtectedInstallRoot
    if (-not (Test-WgstProtectedInstallParentAuthority `
            -InstallRoot $installRoot)) {
        throw 'Program Files install authority is unsafe.'
    }
    $installParent = Split-Path -Parent $installRoot
    $installParentIdentity = Get-WgstNativeFileSnapshot `
        -Path $installParent `
        -Directory

    if (-not $RepairBootstrap -and
        (Test-Path -LiteralPath $installRoot)) {
        $existing = Get-WgstAuthenticatedBundledReleaseAclPlan `
            -PackageRoot $installRoot
        if (-not (Test-WgstPackageTreesEqual `
                -Left $sourcePlan.Root `
                -Right $installRoot) -or
            -not (Test-WgstInstalledReleaseAclPlanExact `
                -Plan $existing)) {
            throw (
                'Protected install root already exists with different or ' +
                'unsafe managed content.')
        }
        return $installRoot
    }

    $staging = Join-Path $installParent (
        'WireguardSplitTunnel.install-' +
        [Guid]::NewGuid().ToString('N'))
    $created = $false
    try {
        $security = New-WgstExactProtectedSecurity -Directory $true
        $privilege =
            [WireguardSplitTunnel.ReleaseScripts.NativeFileIdentity]::
                EnableRestorePrivilege()
        try {
            [IO.DirectoryInfo]::new($staging).Create($security)
        }
        finally {
            $privilege.Dispose()
        }
        $created = $true
        if (-not (Test-WgstProtectedRepairAcl $staging)) {
            throw 'Protected install staging ACL validation failed.'
        }
        $installParentAfterCreate = Get-WgstNativeFileSnapshot `
            -Path $installParent `
            -Directory
        if (-not (Test-WgstSameNativeFileSnapshot `
                -Before $installParentIdentity `
                -After $installParentAfterCreate)) {
            throw 'Program Files identity changed during staging creation.'
        }

        $protectedDirectorySecurity =
            New-WgstExactProtectedSecurity -Directory $true
        $directoryPrivilege =
            [WireguardSplitTunnel.ReleaseScripts.NativeFileIdentity]::
                EnableRestorePrivilege()
        try {
            foreach ($directory in @($sourcePlan.Directories | Where-Object {
                    $_.Scope -ceq 'DescendantDirectory'
                })) {
                $target = Join-Path $staging $directory.RelativePath
                [IO.DirectoryInfo]::new($target).Create(
                    $protectedDirectorySecurity)
                if (-not (Test-WgstProtectedRepairAcl $target)) {
                    throw 'Protected install directory ACL validation failed.'
                }
            }
        }
        finally {
            $directoryPrivilege.Dispose()
        }

        foreach ($source in $sourcePlan.Files) {
            Assert-WgstInstalledReleaseAclTargetIdentity `
                -Target $sourcePlan.Directories[0]
            $target = Join-Path $staging (
                $source.RelativePath.Replace(
                    '/',
                    [IO.Path]::DirectorySeparatorChar))
            Copy-WgstBoundManagedFile `
                -Source $source `
                -TargetPath $target
        }
        foreach ($source in @($sourcePlan.Directories) +
                @($sourcePlan.Files)) {
            Assert-WgstInstalledReleaseAclTargetIdentity -Target $source
        }
        [void](Test-WgstReleasePackageNoSdk `
            -PackageRoot $staging `
            -ExpectedTag $sourcePlan.Tag)
        [void](Set-WgstAuthenticatedBundledReleaseAcl `
            -PackageRoot $staging)

        if ($RepairBootstrap) {
            $repairBootstrapPlan =
                Get-WgstAuthenticatedBundledReleaseAclPlan `
                    -PackageRoot $staging
            if (-not (Test-WgstPackageTreesEqual `
                    -Left $sourcePlan.Root `
                    -Right $staging) -or
                -not (Test-WgstInstalledReleaseAclPlanExact `
                    -Plan $repairBootstrapPlan) -or
                -not (Test-WgstProtectedInstallParentAuthority `
                    -InstallRoot $installRoot)) {
                throw 'Protected repair bootstrap validation failed.'
            }
            $created = $false
            return $staging
        }

        if (Test-Path -LiteralPath $installRoot) {
            throw 'Protected install root appeared during staging.'
        }
        $installParentBeforeMove = Get-WgstNativeFileSnapshot `
            -Path $installParent `
            -Directory
        Move-Item -LiteralPath $staging -Destination $installRoot
        $created = $false
        $installParentAfterMove = Get-WgstNativeFileSnapshot `
            -Path $installParent `
            -Directory
        if (-not (Test-WgstSameNativeFileSnapshot `
                -Before $installParentBeforeMove `
                -After $installParentAfterMove)) {
            throw 'Program Files identity changed during install publication.'
        }
        $installed = Get-WgstAuthenticatedBundledReleaseAclPlan `
            -PackageRoot $installRoot
        if (-not (Test-WgstPackageTreesEqual `
                -Left $sourcePlan.Root `
                -Right $installRoot) -or
            -not (Test-WgstInstalledReleaseAclPlanExact `
                -Plan $installed) -or
            -not (Test-WgstProtectedInstallParentAuthority `
                -InstallRoot $installRoot)) {
            throw 'Protected installed Release validation failed.'
        }
        return $installRoot
    }
    finally {
        if ($created -and (Test-Path -LiteralPath $staging)) {
            try {
                Remove-WgstProtectedInstallStaging `
                    -InstallRoot $installRoot `
                    -StagingRoot $staging
            }
            catch {
                Write-Warning (
                    'Protected install staging was preserved because safe ' +
                    "cleanup could not be certified: $($_.Exception.Message)")
            }
        }
    }
}

function Test-WgstProtectedRepairAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $item = Get-Item -LiteralPath $Path -Force
        if (($item.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            return $false
        }
        $acl = Get-WgstFileSystemSecurity `
            -Path $Path `
            -Directory ([bool]$item.PSIsContainer)
        if (-not $acl.AreAccessRulesProtected -or
            -not $acl.AreAccessRulesCanonical) {
            return $false
        }
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
            $acl.GetSecurityDescriptorBinaryForm(),
            0)
    }
    catch {
        return $false
    }
    $requiredFlags = [Security.AccessControl.ControlFlags](
        [int][Security.AccessControl.ControlFlags]::DiscretionaryAclPresent -bor
        [int][Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)
    if (($descriptor.ControlFlags -band $requiredFlags) -ne
            $requiredFlags -or
        $null -eq $descriptor.DiscretionaryAcl -or
        $descriptor.DiscretionaryAcl.Count -ne 2 -or
        $null -eq $descriptor.Owner -or
        $descriptor.Owner.Value -cne 'S-1-5-18') {
        return $false
    }
    $expectedFlags = if ($item.PSIsContainer) {
        [Security.AccessControl.AceFlags](
            [int][Security.AccessControl.AceFlags]::ContainerInherit -bor
            [int][Security.AccessControl.AceFlags]::ObjectInherit)
    }
    else {
        [Security.AccessControl.AceFlags]::None
    }
    $expected = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    [void]$expected.Add('S-1-5-18')
    [void]$expected.Add('S-1-5-32-544')
    foreach ($genericAce in $descriptor.DiscretionaryAcl) {
        if (-not ($genericAce -is
                [Security.AccessControl.CommonAce])) {
            return $false
        }
        $ace = [Security.AccessControl.CommonAce]$genericAce
        if ($ace.IsCallback -or
            $ace.AceQualifier -ne
                [Security.AccessControl.AceQualifier]::AccessAllowed -or
            $ace.AccessMask -ne
                [int][Security.AccessControl.FileSystemRights]::FullControl -or
            $ace.AceFlags -ne $expectedFlags -or
            $ace.OpaqueLength -ne 0 -or
            $null -eq $ace.SecurityIdentifier -or
            -not $expected.Remove($ace.SecurityIdentifier.Value)) {
            return $false
        }
    }
    return $expected.Count -eq 0
}

function New-WgstExactProtectedSecurity {
    param([Parameter(Mandatory = $true)][bool]$Directory)

    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administrators =
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $inheritance = if ($Directory) {
        [Security.AccessControl.InheritanceFlags](
            [int][Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [int][Security.AccessControl.InheritanceFlags]::ObjectInherit)
    }
    else {
        [Security.AccessControl.InheritanceFlags]::None
    }
    $security = if ($Directory) {
        [Security.AccessControl.DirectorySecurity]::new()
    }
    else {
        [Security.AccessControl.FileSecurity]::new()
    }
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($system)
    foreach ($identity in @($administrators, $system)) {
        [void]$security.AddAccessRule(
            [Security.AccessControl.FileSystemAccessRule]::new(
                $identity,
                [Security.AccessControl.FileSystemRights]::FullControl,
                $inheritance,
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow))
    }
    return $security
}

function Write-WgstNewProtectedUtf8File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )

    $security = New-WgstExactProtectedSecurity -Directory $false
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text)
    $privilege =
        [WireguardSplitTunnel.ReleaseScripts.NativeFileIdentity]::
            EnableRestorePrivilege()
    $stream = $null
    try {
        $stream = [IO.FileStream]::new(
            $Path,
            [IO.FileMode]::CreateNew,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::WriteThrough,
            $security)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        $privilege.Dispose()
    }
    if (-not (Test-WgstProtectedRepairAcl $Path)) {
        throw 'Protected repair file failed exact ACL validation.'
    }
    return $Path
}

function Test-WgstSafeProtectedRootAuthority {
    param([Parameter(Mandatory = $true)][string]$ProtectedRoot)

    try {
        $root = [IO.Path]::GetFullPath($ProtectedRoot).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        if ($root.StartsWith('\\')) {
            return $false
        }
        $driveRoot = [IO.Path]::GetPathRoot($root)
        if ([string]::IsNullOrWhiteSpace($driveRoot) -or
            [IO.DriveInfo]::new($driveRoot).DriveType -ne
                [IO.DriveType]::Fixed) {
            return $false
        }
        $current = Split-Path -Parent $root
        while (-not [string]::IsNullOrWhiteSpace($current)) {
            $item = Get-Item -LiteralPath $current -Force
            if (-not $item.PSIsContainer -or
                ($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $false
            }
            $parent = Split-Path -Parent $current
            if ($parent -eq $current) {
                break
            }
            $current = $parent
        }
        return $true
    }
    catch {
        return $false
    }
}

function New-WgstProtectedWorkspace {
    param(
        [Parameter(Mandatory = $true)][string]$ProtectedRoot,
        [Parameter(Mandatory = $true)]
        [ValidateSet('bootstrap', 'repair')]
        [string]$Purpose,
        [switch]$CreateProtectedRoot
    )

    $root = [IO.Path]::GetFullPath($ProtectedRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    if (-not (Test-WgstSafeProtectedRootAuthority $root)) {
        throw 'Protected workspace root has an unsafe authority.'
    }
    if (-not (Test-Path -LiteralPath $root)) {
        if (-not $CreateProtectedRoot) {
            throw 'Protected update root is missing.'
        }
        $parent = Split-Path -Parent $root
        $parentIdentity = Get-WgstNativeFileSnapshot `
            -Path $parent `
            -Directory
        $rootSecurity = New-WgstExactProtectedSecurity -Directory $true
        $rootPrivilege =
            [WireguardSplitTunnel.ReleaseScripts.NativeFileIdentity]::
                EnableRestorePrivilege()
        try {
            [IO.DirectoryInfo]::new($root).Create($rootSecurity)
        }
        finally {
            $rootPrivilege.Dispose()
        }
        $parentIdentityAfter = Get-WgstNativeFileSnapshot `
            -Path $parent `
            -Directory
        if (-not (Test-WgstSameNativeFileSnapshot `
                -Before $parentIdentity `
                -After $parentIdentityAfter)) {
            throw 'Protected workspace parent identity changed during creation.'
        }
    }
    if (-not (Test-WgstProtectedRepairAcl $root)) {
        throw 'Protected update root failed ACL validation.'
    }
    $rootIdentity = Get-WgstNativeFileSnapshot `
        -Path $root `
        -Directory
    $working = Join-Path $root (
        "$Purpose-$([Guid]::NewGuid().ToString('N'))")
    if (Test-Path -LiteralPath $working) {
        throw 'Protected workspace already exists.'
    }
    $security = New-WgstExactProtectedSecurity -Directory $true
    $workspacePrivilege =
        [WireguardSplitTunnel.ReleaseScripts.NativeFileIdentity]::
            EnableRestorePrivilege()
    try {
        [IO.DirectoryInfo]::new($working).Create($security)
    }
    finally {
        $workspacePrivilege.Dispose()
    }
    $rootIdentityAfter = Get-WgstNativeFileSnapshot `
        -Path $root `
        -Directory
    if (-not (Test-WgstProtectedRepairAcl $root) -or
        -not (Test-WgstProtectedRepairAcl $working) -or
        -not (Test-WgstSameNativeFileSnapshot `
            -Before $rootIdentity `
            -After $rootIdentityAfter)) {
        throw 'Protected workspace failed exact ACL validation.'
    }
    [void](Get-WgstNativeFileSnapshot -Path $working -Directory)
    return $working
}

function Remove-WgstProtectedWorkspace {
    param(
        [Parameter(Mandatory = $true)][string]$ProtectedRoot,
        [Parameter(Mandatory = $true)][string]$WorkingRoot
    )

    $root = [IO.Path]::GetFullPath($ProtectedRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $working = [IO.Path]::GetFullPath($WorkingRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    if ((Split-Path -Parent $working) -cne $root -or
        -not (Test-WgstProtectedRepairAcl $root) -or
        -not (Test-WgstProtectedRepairAcl $working)) {
        throw 'Protected workspace cleanup boundary is invalid.'
    }
    [void](Get-WgstNativeFileSnapshot -Path $root -Directory)
    [void](Get-WgstNativeFileSnapshot -Path $working -Directory)
    foreach ($item in Get-ChildItem -LiteralPath $working -Recurse -Force) {
        if (($item.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Protected workspace contains a reparse point.'
        }
    }
    Remove-Item -LiteralPath $working -Recurse -Force
}

function Test-WgstProtectedInstalledReleaseMatches {
    param(
        [Parameter(Mandatory = $true)][string]$InstallRoot,
        [Parameter(Mandatory = $true)][string]$AuthenticatedPackageRoot
    )

    try {
        $expected = Get-WgstProtectedInstallRoot
        $root = [IO.Path]::GetFullPath($InstallRoot).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        if ($root -ine $expected -or
            -not (Test-WgstProtectedInstallParentAuthority `
                -InstallRoot $root) -or
            -not (Test-WgstPackageTreesEqual `
                -Left $AuthenticatedPackageRoot `
                -Right $root)) {
            return $false
        }
        $plan = Get-WgstAuthenticatedBundledReleaseAclPlan `
            -PackageRoot $root `
            -AllowInstalledExtras
        return Test-WgstInstalledReleaseAclPlanExact -Plan $plan
    }
    catch {
        return $false
    }
}

function Repair-WgstProtectedInstalledRelease {
    param(
        [Parameter(Mandatory = $true)][string]$InstallRoot,
        [Parameter(Mandatory = $true)][string]$AuthenticatedPackageRoot
    )

    $expected = Get-WgstProtectedInstallRoot
    $root = [IO.Path]::GetFullPath($InstallRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    if ($root -ine $expected -or
        -not (Test-WgstProtectedInstallParentAuthority `
            -InstallRoot $root) -or
        -not (Test-Path -LiteralPath $root -PathType Container) -or
        -not (Test-WgstExactInstalledReleaseAcl `
            -Path $root `
            -Scope RootDirectory)) {
        throw 'Recorded installed Release root is not an exact protected anchor.'
    }
    Assert-WgstInstalledReleaseTreeHasNoReparsePoints `
        -PackageRoot $root
    $sourcePlan = Get-WgstAuthenticatedBundledReleaseAclPlan `
        -PackageRoot $AuthenticatedPackageRoot

    foreach ($directory in @($sourcePlan.Directories | Where-Object {
            $_.Scope -ceq 'DescendantDirectory'
        })) {
        $target = Join-Path $root $directory.RelativePath
        if (-not (Test-Path -LiteralPath $target -PathType Container) -or
            -not (Test-WgstExactInstalledReleaseAcl `
                -Path $target `
                -Scope DescendantDirectory)) {
            throw 'Recorded installed Release managed directory is unsafe.'
        }
    }

    $orderedSources = @($sourcePlan.Files | Sort-Object @{
        Expression = {
            if ($_.RelativePath -ceq $script:WgstContract.manifest) {
                1
            }
            else {
                0
            }
        }
    }, @{ Expression = { $_.RelativePath } })
    foreach ($source in $orderedSources) {
        $target = Join-Path $root (
            $source.RelativePath.Replace(
                '/',
                [IO.Path]::DirectorySeparatorChar))
        $parent = Split-Path -Parent $target
        if (-not (Test-WgstExactInstalledReleaseAcl `
                -Path $parent `
                -Scope $(if ($parent -ieq $root) {
                    'RootDirectory'
                }
                else {
                    'DescendantDirectory'
                }))) {
            throw 'Recorded installed Release managed parent is unsafe.'
        }
        $parentBefore = Get-WgstNativeFileSnapshot `
            -Path $parent `
            -Directory
        $targetExists = Test-Path -LiteralPath $target -PathType Leaf
        $targetBefore = $null
        if ($targetExists) {
            if (-not (Test-WgstExactInstalledReleaseAcl `
                    -Path $target `
                    -Scope ManagedFile)) {
                throw 'Recorded installed Release managed file ACL is unsafe.'
            }
            $targetBefore = Get-WgstNativeFileSnapshot `
                -Path $target `
                -RequireSingleLink
        }

        $temporary = "$target.repair-$([Guid]::NewGuid().ToString('N')).tmp"
        try {
            Copy-WgstBoundManagedFile `
                -Source $source `
                -TargetPath $temporary
            $privilege =
                [WireguardSplitTunnel.ReleaseScripts.NativeFileIdentity]::
                    EnableRestorePrivilege()
            try {
                Set-WgstFileSystemSecurity `
                    -Path $temporary `
                    -Directory $false `
                    -Security (New-WgstExactInstalledReleaseSecurity `
                        -Scope ManagedFile)
            }
            finally {
                $privilege.Dispose()
            }
            if (-not (Test-WgstExactInstalledReleaseAcl `
                    -Path $temporary `
                    -Scope ManagedFile)) {
                throw 'Replacement managed file ACL is unsafe.'
            }

            if ($targetExists) {
                $targetCurrent = Get-WgstNativeFileSnapshot `
                    -Path $target `
                    -RequireSingleLink
                if (-not (Test-WgstSameNativeFileSnapshot `
                        -Before $targetBefore `
                        -After $targetCurrent)) {
                    throw 'Installed managed file changed during repair.'
                }
                [IO.File]::Replace($temporary, $target, $null)
            }
            else {
                [IO.File]::Move($temporary, $target)
            }
        }
        finally {
            if (Test-Path -LiteralPath $temporary) {
                Remove-Item -LiteralPath $temporary -Force
            }
        }

        $parentAfter = Get-WgstNativeFileSnapshot `
            -Path $parent `
            -Directory
        if (-not (Test-WgstSameNativeFileSnapshot `
                -Before $parentBefore `
                -After $parentAfter) -or
            -not (Test-WgstExactInstalledReleaseAcl `
                -Path $target `
                -Scope ManagedFile) -or
            (Get-Item -LiteralPath $target -Force).Length -ne
                [long]$source.Length -or
            (Get-WgstFileSha256 $target) -cne
                [string]$source.Sha256) {
            throw 'Installed managed file repair could not be certified.'
        }
    }

    [void](Test-WgstReleasePackageNoSdk `
        -PackageRoot $root `
        -ExpectedTag $sourcePlan.Tag `
        -AllowRuntimeExtras `
        -AllowInstalledExtras)
    [void](Set-WgstAuthenticatedBundledReleaseAcl `
        -PackageRoot $root `
        -AllowInstalledExtras)
    if (-not (Test-WgstProtectedInstalledReleaseMatches `
            -InstallRoot $root `
            -AuthenticatedPackageRoot $sourcePlan.Root)) {
        throw 'Protected installed Release repair failed final validation.'
    }
    return $root
}

function Test-WgstExistingRepairResolution {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$TransactionId,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$InstallRoot,
        [Parameter(Mandatory = $true)][string]$ArchiveSha256,
        [Parameter(Mandatory = $true)][string]$ManifestSha256,
        [Parameter(Mandatory = $true)][scriptblock]$AclValidator
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }
    if (-not (& $AclValidator $Path)) {
        throw 'Existing repair resolution failed ACL validation.'
    }
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.LongLength -gt 4096) {
        throw 'Existing repair resolution exceeds its byte limit.'
    }
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    $resolution = $text | ConvertFrom-Json
    $expectedProperties = @(
        'schemaVersion',
        'transactionId',
        'resolution',
        'version',
        'installRoot',
        'authenticatedArchiveSha256',
        'authenticatedManifestSha256',
        'resolvedAtUtc'
    )
    $actualProperties = @($resolution.PSObject.Properties.Name)
    if ($actualProperties.Count -ne $expectedProperties.Count) {
        throw 'Existing repair resolution properties are not exact.'
    }
    for ($index = 0; $index -lt $expectedProperties.Count; $index++) {
        if ($actualProperties[$index] -cne $expectedProperties[$index]) {
            throw 'Existing repair resolution properties are not exact.'
        }
    }
    $canonical = [ordered]@{
        schemaVersion = [int]$resolution.schemaVersion
        transactionId = [string]$resolution.transactionId
        resolution = [string]$resolution.resolution
        version = [string]$resolution.version
        installRoot = [string]$resolution.installRoot
        authenticatedArchiveSha256 =
            [string]$resolution.authenticatedArchiveSha256
        authenticatedManifestSha256 =
            [string]$resolution.authenticatedManifestSha256
        resolvedAtUtc = [string]$resolution.resolvedAtUtc
    } | ConvertTo-Json -Compress
    try {
        $resolvedAt = [DateTimeOffset]::ParseExact(
            [string]$resolution.resolvedAtUtc,
            'O',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind)
    }
    catch {
        throw 'Existing repair resolution timestamp is invalid.'
    }
    if ($text -cne $canonical -or
        [int]$resolution.schemaVersion -ne 1 -or
        [string]$resolution.transactionId -cne $TransactionId -or
        [string]$resolution.resolution -cne
            'VerifiedBundledReleaseRepair' -or
        [string]$resolution.version -cne $Version -or
        [string]$resolution.installRoot -cne $InstallRoot -or
        [string]$resolution.authenticatedArchiveSha256 -cne
            $ArchiveSha256 -or
        [string]$resolution.authenticatedManifestSha256 -cne
            $ManifestSha256 -or
        $resolvedAt.Offset -ne [TimeSpan]::Zero) {
        throw 'Existing repair resolution binding is invalid.'
    }
    return $true
}

function Invoke-WgstRepairBlockedState {
    param(
        [Parameter(Mandatory = $true)][string]$ProtectedRoot,
        [Parameter(Mandatory = $true)][string]$BundledPackageRoot,
        [Parameter(Mandatory = $true)][string]$AuthenticatedPackageRoot,
        [Parameter(Mandatory = $true)][string]$AuthenticatedArchivePath,
        [Parameter(Mandatory = $true)][string]$Props,
        [Parameter(Mandatory = $true)][string]$ExpectedTag,
        [Parameter(Mandatory = $true)][bool]$ExplicitRepair,
        [string]$ExpectedInstallRoot = (Get-WgstProtectedInstallRoot),
        [scriptblock]$AclValidator = ${function:Test-WgstProtectedRepairAcl},
        [scriptblock]$ProtectedFileWriter =
            ${function:Write-WgstNewProtectedUtf8File},
        [scriptblock]$InstallRootValidator = {
            param($Path)
            $expected = Get-WgstProtectedInstallRoot
            $canonical = [IO.Path]::GetFullPath($Path).TrimEnd(
                [IO.Path]::DirectorySeparatorChar,
                [IO.Path]::AltDirectorySeparatorChar)
            return $canonical -ieq $expected -and
                (Test-WgstProtectedInstallParentAuthority `
                    -InstallRoot $canonical) -and
                (Test-WgstExactInstalledReleaseAcl `
                    -Path $canonical `
                    -Scope RootDirectory)
        },
        [scriptblock]$InstalledReleaseRepairAction =
            ${function:Repair-WgstProtectedInstalledRelease},
        [scriptblock]$InstalledReleaseValidator =
            ${function:Test-WgstProtectedInstalledReleaseMatches},
        [scriptblock]$BeforePointerReplace = {}
    )

    if (-not $ExplicitRepair) {
        throw 'RecoveryBlocked requires explicit -RepairBlockedUpdate.'
    }
    if (-not (& $AclValidator $ProtectedRoot)) {
        throw 'Protected update root failed ACL validation.'
    }

    [void](Test-WgstReleasePackageNoSdk `
        -PackageRoot $BundledPackageRoot `
        -Props $Props `
        -ExpectedTag $ExpectedTag `
        -AllowRuntimeExtras)
    [void](Test-WgstReleasePackageNoSdk `
        -PackageRoot $AuthenticatedPackageRoot `
        -Props $Props `
        -ExpectedTag $ExpectedTag)
    if (-not (Test-WgstPackageTreesEqual `
            -Left $BundledPackageRoot `
            -Right $AuthenticatedPackageRoot)) {
        throw 'Bundled Release does not match the authenticated GitHub package.'
    }
    if (-not (Test-Path `
            -LiteralPath $AuthenticatedArchivePath `
            -PathType Leaf)) {
        throw 'Authenticated Release archive is missing.'
    }
    $authenticatedArchiveSha256 = Get-WgstFileSha256 `
        $AuthenticatedArchivePath
    $authenticatedManifestSha256 = Get-WgstFileSha256 (
        Join-Path $AuthenticatedPackageRoot $script:WgstContract.manifest)
    $expectedInstall = [IO.Path]::GetFullPath(
        $ExpectedInstallRoot).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)

    $transactions = Join-Path $ProtectedRoot 'UpdateTransactions'
    $pointer = Join-Path $transactions 'active-transaction.json'
    foreach ($path in @($transactions, $pointer)) {
        if (-not (& $AclValidator $path)) {
            throw 'Protected update state failed ACL validation.'
        }
    }
    $activeBytes = [IO.File]::ReadAllBytes($pointer)
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $activeText = $utf8.GetString($activeBytes)
    $match = [Regex]::Match(
        $activeText,
        '^\{"schemaVersion":1,"transactionId":"([0-9a-f]{32})"\}$',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $match.Success) {
        throw 'Protected active pointer is not canonical.'
    }
    $transactionId = $match.Groups[1].Value
    $transactionRoot = Join-Path $transactions $transactionId
    $recordPath = Join-Path $transactionRoot 'transaction.json'
    foreach ($path in @($transactionRoot, $recordPath)) {
        if (-not (& $AclValidator $path)) {
            throw 'Protected transaction failed ACL validation.'
        }
    }
    $record = Get-Content -LiteralPath $recordPath -Raw |
        ConvertFrom-Json
    if ($record.transactionId -cne $transactionId -or
        $record.phase -cne 'RecoveryBlocked' -or
        [string]$record.version -cne $ExpectedTag.Substring(1) -or
        $null -eq $record.installedRelease -or
        $null -eq $record.candidate -or
        [string]$record.installedRelease.installRoot -cne
            $expectedInstall -or
        [string]$record.candidate.archiveSha256 -cne
            $authenticatedArchiveSha256 -or
        [string]$record.candidate.newManifestSha256 -cne
            $authenticatedManifestSha256 -or
        -not (& $InstallRootValidator $expectedInstall)) {
        throw 'Active transaction is not exact RecoveryBlocked evidence.'
    }

    $intentPath = Join-Path $transactionRoot 'repair-intent.json'
    $intent = [ordered]@{
        schemaVersion = 1
        transactionId = $transactionId
        installRoot = $expectedInstall
        authenticatedArchiveSha256 = $authenticatedArchiveSha256
        authenticatedManifestSha256 = $authenticatedManifestSha256
    } | ConvertTo-Json -Compress
    if (Test-Path -LiteralPath $intentPath -PathType Leaf) {
        if (-not (& $AclValidator $intentPath) -or
            [IO.File]::ReadAllText(
                $intentPath,
                [Text.UTF8Encoding]::new($false, $true)) -cne $intent) {
            throw 'Existing protected repair intent is invalid.'
        }
    }
    else {
        $intentTemp =
            "$intentPath.$([Guid]::NewGuid().ToString('N')).tmp"
        [void](& $ProtectedFileWriter $intentTemp $intent)
        if (-not (& $AclValidator $intentTemp)) {
            throw 'Protected repair intent temp failed ACL validation.'
        }
        [IO.File]::Move($intentTemp, $intentPath)
        if (-not (& $AclValidator $intentPath)) {
            throw 'Protected repair intent failed ACL validation.'
        }
    }
    if ([Convert]::ToBase64String(
            [IO.File]::ReadAllBytes($pointer)) -cne
            [Convert]::ToBase64String($activeBytes)) {
        throw 'Protected active pointer changed before installed repair.'
    }

    # Production default: Repair-WgstProtectedInstalledRelease replaces only
    # manifest-managed paths and publishes the manifest last.
    [void](& $InstalledReleaseRepairAction `
        $expectedInstall `
        $AuthenticatedPackageRoot)
    if (-not (& $InstalledReleaseValidator `
            $expectedInstall `
            $AuthenticatedPackageRoot)) {
        throw 'Protected installed Release failed post-repair validation.'
    }

    $resolutionPath = Join-Path $transactionRoot 'repair-resolution.json'
    $hasResolution = Test-WgstExistingRepairResolution `
        -Path $resolutionPath `
        -TransactionId $transactionId `
        -Version ([string]$record.version) `
        -InstallRoot $expectedInstall `
        -ArchiveSha256 $authenticatedArchiveSha256 `
        -ManifestSha256 $authenticatedManifestSha256 `
        -AclValidator $AclValidator
    if (-not $hasResolution) {
        $resolution = [ordered]@{
            schemaVersion = 1
            transactionId = $transactionId
            resolution = 'VerifiedBundledReleaseRepair'
            version = [string]$record.version
            installRoot = $expectedInstall
            authenticatedArchiveSha256 =
                $authenticatedArchiveSha256
            authenticatedManifestSha256 = $authenticatedManifestSha256
            resolvedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        } | ConvertTo-Json -Compress
        $resolutionTemp =
            "$resolutionPath.$([Guid]::NewGuid().ToString('N')).tmp"
        [void](& $ProtectedFileWriter $resolutionTemp $resolution)
        if (-not (& $AclValidator $resolutionTemp)) {
            throw 'Protected repair resolution temp failed ACL validation.'
        }
        [IO.File]::Move($resolutionTemp, $resolutionPath)
        if (-not (& $AclValidator $resolutionPath)) {
            throw 'Protected repair resolution failed ACL validation.'
        }
    }

    if ([Convert]::ToBase64String(
            [IO.File]::ReadAllBytes($pointer)) -cne
            [Convert]::ToBase64String($activeBytes) -or
        -not (& $AclValidator $transactions) -or
        -not (& $AclValidator $transactionRoot) -or
        -not (& $AclValidator $pointer) -or
        -not (& $AclValidator $intentPath) -or
        -not (& $AclValidator $resolutionPath)) {
        throw 'Protected active pointer changed before repair commit.'
    }
    & $BeforePointerReplace
    $inactiveTemp = Join-Path $transactions (
        "active-transaction.$([Guid]::NewGuid().ToString('N')).tmp")
    $pointerBackup = Join-Path $transactionRoot (
        'active-pointer-before-repair.json')
    if (Test-Path -LiteralPath $pointerBackup) {
        throw 'Repair pointer evidence already exists.'
    }
    [void](& $ProtectedFileWriter `
        $inactiveTemp `
        '{"schemaVersion":1,"transactionId":null}')
    if (-not (& $AclValidator $inactiveTemp)) {
        throw 'Protected inactive pointer temp failed ACL validation.'
    }
    [IO.File]::Replace(
        $inactiveTemp,
        $pointer,
        $pointerBackup)

    if (-not (& $AclValidator $pointer) -or
        -not (& $AclValidator $pointerBackup) -or
        -not (& $AclValidator $intentPath) -or
        -not (& $AclValidator $resolutionPath)) {
        throw 'Protected repair output failed ACL validation.'
    }
    $inactive = [IO.File]::ReadAllText(
        $pointer,
        [Text.UTF8Encoding]::new($false, $true))
    if ($inactive -cne '{"schemaVersion":1,"transactionId":null}') {
        throw 'Protected pointer deactivation could not be certified.'
    }
    if ([Convert]::ToBase64String(
            [IO.File]::ReadAllBytes($pointerBackup)) -cne
        [Convert]::ToBase64String($activeBytes)) {
        throw 'Protected prior pointer evidence could not be certified.'
    }
    return $resolutionPath
}

function Invoke-WgstDownloadAndValidateRelease {
    param(
        [Parameter(Mandatory = $true)][string]$WorkingRoot,
        [string]$ExpectedTag
    )

    if (Test-Path -LiteralPath $WorkingRoot) {
        $workingItem = Get-Item -LiteralPath $WorkingRoot -Force
        if (-not $workingItem.PSIsContainer -or
            ($workingItem.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            @(Get-ChildItem -LiteralPath $WorkingRoot -Force).Count -ne 0) {
            throw 'Release working directory must be a safe empty directory.'
        }
    }
    else {
        New-Item -ItemType Directory -Path $WorkingRoot | Out-Null
    }
    $client = New-WgstHttpClient
    try {
        $release = if ([string]::IsNullOrWhiteSpace($ExpectedTag)) {
            Get-WgstStableRelease -Client $client
        }
        else {
            if (-not (Test-WgstStableTag $ExpectedTag)) {
                throw 'Expected repair tag is invalid.'
            }
            [pscustomobject]@{
                Tag = $ExpectedTag
                ArchiveUri = [Uri](
                    "https://github.com/$($script:WgstContract.repository)/releases/download/" +
                    "$ExpectedTag/$($script:WgstContract.archiveAsset)")
                ChecksumUri = [Uri](
                    "https://github.com/$($script:WgstContract.repository)/releases/download/" +
                    "$ExpectedTag/$($script:WgstContract.checksumAsset)")
            }
        }
        $archive = Join-Path $WorkingRoot $script:WgstContract.archiveAsset
        $sidecarBytes = Invoke-WgstBoundedHttpGet `
            -Client $client `
            -Uri $release.ChecksumUri `
            -MaximumBytes $script:WgstContract.checksumBytes `
            -TimeoutSeconds $script:WgstContract.metadataTimeoutSeconds
        $expectedDigest = Get-WgstStrictSidecarDigest $sidecarBytes
        [void](Invoke-WgstBoundedHttpGet `
            -Client $client `
            -Uri $release.ArchiveUri `
            -MaximumBytes $script:WgstContract.archiveBytes `
            -TimeoutSeconds $script:WgstContract.downloadTimeoutSeconds `
            -OutputPath $archive)
        if ((Get-WgstFileSha256 $archive) -cne $expectedDigest) {
            throw 'Release archive does not match its exact checksum sidecar.'
        }
        $packageRoot = Join-Path $WorkingRoot 'package'
        Expand-WgstSafeArchive `
            -ArchivePath $archive `
            -DestinationRoot $packageRoot
        $props = New-WgstPropsFromManifest `
            -PackageRoot $packageRoot `
            -OutputPath (Join-Path $WorkingRoot 'release.props')
        [void](Test-WgstReleasePackageNoSdk `
            -PackageRoot $packageRoot `
            -Props $props `
            -ExpectedTag $release.Tag)
        return [pscustomobject]@{
            Tag = $release.Tag
            PackageRoot = $packageRoot
            Props = $props
            Archive = $archive
        }
    }
    finally {
        $client.Dispose()
    }
}

function Invoke-WgstBootstrapRelease {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $publishRoot = Join-Path $RepoRoot 'WireguardSplitTunnel'
    $app = Join-Path $publishRoot 'WireguardSplitTunnel.App.exe'
    $updater = Join-Path $publishRoot 'WireguardSplitTunnel.Updater.exe'
    if ((Test-Path -LiteralPath $app -PathType Leaf) -and
        (Test-Path -LiteralPath $updater -PathType Leaf)) {
        return $app
    }
    if (Test-Path -LiteralPath $publishRoot) {
        throw 'Existing bootstrap destination is incomplete or untrusted.'
    }
    $protectedRoot = Join-Path (
        [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::CommonApplicationData)) (
        'WireguardSplitTunnel')
    $working = $null
    try {
        $working = New-WgstProtectedWorkspace `
            -ProtectedRoot $protectedRoot `
            -Purpose bootstrap `
            -CreateProtectedRoot
        $release = Invoke-WgstDownloadAndValidateRelease `
            -WorkingRoot $working
        return Copy-WgstValidatedApplicationSubtree `
            -PackageRoot $release.PackageRoot `
            -DestinationRoot $publishRoot
    }
    finally {
        if (-not [string]::IsNullOrWhiteSpace($working) -and
            (Test-Path -LiteralPath $working)) {
            try {
                Remove-WgstProtectedWorkspace `
                    -ProtectedRoot $protectedRoot `
                    -WorkingRoot $working
            }
            catch {
                Write-Warning (
                    'Protected bootstrap workspace was preserved because ' +
                    "safe cleanup could not be certified: $($_.Exception.Message)")
            }
        }
    }
}

function Invoke-WgstWithProtectedUpdateMutex {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [object[]]$ArgumentList = @()
    )

    $mutex = $null
    $acquired = $false
    $cleanupFailure = $null
    try {
        $privilege =
            [WireguardSplitTunnel.ReleaseScripts.NativeFileIdentity]::
                EnableRestorePrivilege()
        try {
            $mutex =
                [WireguardSplitTunnel.ReleaseScripts.NativeUpdateMutex]::
                    OpenExact()
        }
        finally {
            $privilege.Dispose()
        }

        $wait = $mutex.Wait(0)
        if ($wait -eq
                [WireguardSplitTunnel.ReleaseScripts.NativeUpdateMutexWaitResult]::
                    Busy) {
            throw 'Another protected update transaction is active.'
        }
        $acquired = $true
        if (-not $mutex.ValidateSecurity()) {
            throw 'The protected update mutex authority changed.'
        }
        return & $Action @ArgumentList
    }
    finally {
        if ($null -ne $mutex) {
            if ($acquired) {
                try {
                    if (-not $mutex.ValidateSecurity()) {
                        $cleanupFailure =
                            [InvalidOperationException]::new(
                                'The protected update mutex authority changed.')
                    }
                }
                catch {
                    $cleanupFailure = $_.Exception
                }
                try {
                    $mutex.Release()
                }
                catch {
                    if ($null -eq $cleanupFailure) {
                        $cleanupFailure = $_.Exception
                    }
                }
            }
            try {
                $mutex.Dispose()
            }
            catch {
                if ($null -eq $cleanupFailure) {
                    $cleanupFailure = $_.Exception
                }
            }
        }
        if ($null -ne $cleanupFailure) {
            throw $cleanupFailure
        }
    }
}

function Invoke-WgstAuthenticatedBlockedRepair {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$BundledPackageRoot,
        [Parameter(Mandatory = $true)][string]$ProtectedRoot
    )

    return Invoke-WgstWithProtectedUpdateMutex `
        -ArgumentList @($BundledPackageRoot, $ProtectedRoot) `
        -Action {
            param($BoundBundledPackageRoot, $BoundProtectedRoot)

            $manifest = Get-Content -LiteralPath (
                Join-Path $BoundBundledPackageRoot `
                    $script:WgstContract.manifest) -Raw |
                ConvertFrom-Json
            $tag = "v$($manifest.version)"
            if (-not (Test-WgstStableTag $tag)) {
                throw 'Bundled Release manifest version is invalid.'
            }
            $working = $null
            try {
                $working = New-WgstProtectedWorkspace `
                    -ProtectedRoot $BoundProtectedRoot `
                    -Purpose repair
                $authenticated = Invoke-WgstDownloadAndValidateRelease `
                    -WorkingRoot $working `
                    -ExpectedTag $tag
                return Invoke-WgstRepairBlockedState `
                    -ProtectedRoot $BoundProtectedRoot `
                    -BundledPackageRoot $BoundBundledPackageRoot `
                    -AuthenticatedPackageRoot $authenticated.PackageRoot `
                    -AuthenticatedArchivePath $authenticated.Archive `
                    -Props $authenticated.Props `
                    -ExpectedTag $tag `
                    -ExplicitRepair $true
            }
            finally {
                if (-not [string]::IsNullOrWhiteSpace($working) -and
                    (Test-Path -LiteralPath $working)) {
                    try {
                        Remove-WgstProtectedWorkspace `
                            -ProtectedRoot $BoundProtectedRoot `
                            -WorkingRoot $working
                    }
                    catch {
                        Write-Warning (
                            'Protected repair workspace was preserved because ' +
                            'safe cleanup could not be certified: ' +
                            $_.Exception.Message)
                    }
                }
            }
        }
}

Export-ModuleMember -Function @(
    'Get-WgstFixedReleaseContract',
    'Test-WgstBundledRelease',
    'Get-WgstAuthenticatedBundledReleaseBinding',
    'Install-WgstAuthenticatedBundledReleaseToProtectedAnchor',
    'Set-WgstAuthenticatedBundledReleaseAcl',
    'Invoke-WgstBootstrapRelease',
    'Invoke-WgstAuthenticatedBlockedRepair'
)
