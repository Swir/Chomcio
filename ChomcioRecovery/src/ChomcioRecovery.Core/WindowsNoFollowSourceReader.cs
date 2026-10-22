using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ChomcioRecovery.Core;

/// <summary>
/// Windows-only source reader. A path-based reparse check followed by ordinary
/// FileStream.Open has a gap: an attacker can swap the source file for a link
/// between those calls. Following it ingests out-of-tree plaintext into a new
/// encrypted orphan chunk even if a later inventory check rejects the snapshot.
/// Open the reparse point ITSELF, inspect attributes on that opened handle,
/// and deny link/directory handles before reading any bytes. FileShare.Read
/// also denies newly-opened writers/renames while this handle is held.
/// Parent directory substitution and writers with pre-existing handles remain
/// outside this guard and require future Windows handle-based containment/VSS.
/// </summary>
internal static class WindowsNoFollowSourceReader
{
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x01;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagSequentialScan = 0x08000000;

    [StructLayout(LayoutKind.Sequential)]
    private struct FileBasicInfo
    {
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public long ChangeTime;
        public uint FileAttributes;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode,
        ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint desiredAccess, uint sharing,
        IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,
        int fileInformationClass, out FileBasicInfo fileInformation, uint bufferSize);

    /// <summary>
    /// beforeOpen exists only for deterministic fault injection in native smoke.
    /// Production callers pass null; no credentials or user files are changed.
    /// </summary>
    internal static FileStream Open(string path, Action? beforeOpen = null,bool allowDeleteSharing=false)
    {
        beforeOpen?.Invoke();
        if (!OperatingSystem.IsWindows())
            return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                bufferSize: 65_536, options: FileOptions.SequentialScan);

        SafeFileHandle handle = CreateFile(WindowsNativePath.FromPath(Path.GetFullPath(path)), GenericRead, FileShareRead|(allowDeleteSharing?4u:0u),
            IntPtr.Zero, OpenExisting, FileFlagOpenReparsePoint | FileFlagSequentialScan,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new IOException("Cannot open source without following links (Win32 " +
                error + ").", new Win32Exception(error));
        }
        try
        {
            if (!GetFileInformationByHandleEx(handle, 0, out FileBasicInfo info,
                    (uint)Marshal.SizeOf<FileBasicInfo>()))
                throw new IOException("Cannot inspect opened source handle.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            FileAttributes attributes = (FileAttributes)info.FileAttributes;
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                throw new IOException("Source changed to a directory or reparse point before read.");
            WindowsUnsupportedMetadataGuard.RejectUnsupported(attributes, path);
            WindowsHardLinkGuard.RejectMultipleLinks(handle, path);
            return new FileStream(handle, FileAccess.Read, bufferSize: 65_536, isAsync: false);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }
}
