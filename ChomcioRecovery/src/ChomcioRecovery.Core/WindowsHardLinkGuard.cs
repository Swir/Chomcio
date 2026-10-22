using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ChomcioRecovery.Core;

/// <summary>
/// Current snapshot schema stores files as independent byte streams. Windows
/// hard-link topology cannot be restored from it. Refuse multi-linked files
/// instead of silently describing a lossy copy as a complete recovery point.
/// The count is checked using a real OS file handle, not a filename heuristic.
/// This does NOT solve concurrent reparse-point/file-identity swap attacks.
/// </summary>
internal static class WindowsHardLinkGuard
{
    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public uint Low;
        public uint High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint Attributes;
        public FileTime CreationTime;
        public FileTime LastAccessTime;
        public FileTime LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle handle, out ByHandleFileInformation fileInformation);

    internal static void RejectMultipleLinks(string path)
    {
        if (!OperatingSystem.IsWindows()) return;

        // Avoid granting sharing rights for a writer that would be denied by
        // the caller. This handle is short-lived; the caller still has to
        // check attributes / identity during the rest of the backup operation.
        using SafeFileHandle handle = File.OpenHandle(path, FileMode.Open,
            FileAccess.Read, FileShare.Read | FileShare.Delete);
        RejectMultipleLinks(handle, path);
    }

    // Reuse the *same* verified no-follow source handle. Checking the path
    // before the stream opens leaves a symlink/hardlink substitution window.
    internal static void RejectMultipleLinks(SafeFileHandle handle, string path)
    {
        if (!OperatingSystem.IsWindows()) return;
        if (!GetFileInformationByHandle(handle, out var info))
            throw new IOException("Cannot determine opened Windows source link count: " + path,
                new Win32Exception(Marshal.GetLastWin32Error()));
        RejectCount(info.NumberOfLinks, path);
    }

    // Explicit predicate so a native smoke can exercise the zero/unknown count
    // even on filesystems where creating actual hard links is unavailable.
    internal static void RejectCount(uint numberOfLinks, string path)
    {
        if (numberOfLinks != 1)
            throw new IOException("Unsupported hard-linked file (or unknown link count): " + path);
    }
}
