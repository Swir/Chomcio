using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ChomcioRecovery.Core;

/// <summary>
/// Record a physical Windows file identity during the FIRST source inventory,
/// then require that SAME identity on both content reads. An attacker changing
/// an ordinary file between enumeration and open cannot import its bytes as
/// orphan ciphertext merely by copying size and timestamps. The full 128-bit
/// FILE_ID_INFO is used (including ReFS), rather than a truncated file index.
///
/// This is not a VSS/coherent snapshot. In particular, an attacker changing
/// directory ancestors or mutating a file through an existing writer handle
/// is not fully excluded. Missing/unsupported file IDs fail closed on Windows.
/// </summary>
internal static class WindowsSourceFileIdentity
{
    internal readonly record struct Identity(ulong VolumeSerial, ulong FileIdLow, ulong FileIdHigh);

    // FILE_INFO_BY_HANDLE_CLASS.FileIdInfo (Windows 8 / Server 2012+).
    private const int FileIdInfoClass = 18;

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInfo
    {
        public ulong VolumeSerialNumber;
        public ulong FileIdLow;
        public ulong FileIdHigh;
    }

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle handle, int fileInformationClass, out FileIdInfo fileInformation,
        uint bufferSize);

    internal static Identity? CaptureFile(string path)
    {
        if (!OperatingSystem.IsWindows()) return null;
        using FileStream stream = WindowsNoFollowSourceReader.Open(path);
        return Capture(stream);
    }

    internal static Identity Capture(FileStream stream) => Capture(stream.SafeFileHandle);

    // A retained DELETE-capable publication handle cannot be safely closed and
    // reopened by pathname merely to establish its identity. Read FileIdInfo
    // directly from the SAME OS handle that will perform the final rename.
    internal static Identity Capture(SafeFileHandle handle)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows native file IDs require Windows.");
        if (!GetFileInformationByHandleEx(handle, FileIdInfoClass,
                out FileIdInfo info, (uint)Marshal.SizeOf<FileIdInfo>()))
        {
            int code = Marshal.GetLastWin32Error();
            throw new IOException("Cannot read opened source file ID (Win32 " + code + ").",
                new Win32Exception(code));
        }
        // Zero is not a trustworthy physical file identity (some redirectors
        // return a placeholder). Fail closed, even if this excludes a volume.
        if ((info.FileIdLow | info.FileIdHigh) == 0)
            throw new IOException("Opened source did not provide a usable file ID.");
        return new Identity(info.VolumeSerialNumber, info.FileIdLow, info.FileIdHigh);
    }

    internal static void RequireMatches(FileStream openedSource, Identity? expected, string path)
    {
        if (!OperatingSystem.IsWindows()) return;
        if (!expected.HasValue || Capture(openedSource) != expected.Value)
            throw new IOException("Source file identity changed since initial inventory: " + path);
    }
}
