using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ChomcioRecovery.Core;

/// <summary>
/// Reject physical repository/source/destination overlaps on Windows even when
/// an 8.3 DOS short name aliases a longer directory name. GetFullPath and a
/// lexical prefix comparison alone do not recognize those aliases.
///
/// This is a fail-closed preflight, NOT atomic filesystem isolation. Another
/// same-user process may change an ancestor after the check. The independent
/// no-follow and directory-pinning guards remain necessary during I/O.
/// </summary>
internal static class WindowsRepositoryOverlapGuard
{
    private const uint FileReadAttributes = 0x80;
    private const uint FileShareAll = 0x01 | 0x02 | 0x04;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const int FileBasicInfoClass = 0;
    private const int FileIdInfoClass = 18;

    internal readonly record struct Identity(ulong Volume, ulong Low, ulong High);

    [StructLayout(LayoutKind.Sequential)]
    private struct FileBasicInfo
    {
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public long ChangeTime;
        public uint FileAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInfo
    {
        public ulong VolumeSerialNumber;
        public ulong FileIdLow;
        public ulong FileIdHigh;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode,
        ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetBasicInfo(SafeFileHandle handle, int infoClass,
        out FileBasicInfo info, uint size);

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetIdInfo(SafeFileHandle handle, int infoClass,
        out FileIdInfo info, uint size);

    private static Identity ReadDirectoryId(string path)
    {
        using SafeFileHandle handle = CreateFile(WindowsNativePath.FromPath(path), FileReadAttributes, FileShareAll,
            IntPtr.Zero, OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            throw new IOException("Cannot inspect physical repository path (Win32 " + error + "): " + path,
                new Win32Exception(error));
        }
        if (!GetBasicInfo(handle, FileBasicInfoClass, out FileBasicInfo basic,
                (uint)Marshal.SizeOf<FileBasicInfo>()))
            throw new IOException("Cannot inspect directory attributes: " + path,
                new Win32Exception(Marshal.GetLastWin32Error()));
        FileAttributes attributes = (FileAttributes)basic.FileAttributes;
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != FileAttributes.Directory)
            throw new IOException("Physical repository path is not a real directory: " + path);
        if (!GetIdInfo(handle, FileIdInfoClass, out FileIdInfo info,
                (uint)Marshal.SizeOf<FileIdInfo>()))
            throw new IOException("Cannot identify physical repository path: " + path,
                new Win32Exception(Marshal.GetLastWin32Error()));
        if ((info.FileIdLow | info.FileIdHigh) == 0)
            throw new IOException("Physical repository path has an unusable file ID: " + path);
        return new Identity(info.VolumeSerialNumber, info.FileIdLow, info.FileIdHigh);
    }

    internal static void RejectPhysicalOverlap(string repository, string requestedPath)
    {
        if (!OperatingSystem.IsWindows()) return;
        string root = Path.GetFullPath(repository);
        string target = Path.GetFullPath(requestedPath);
        if (!Directory.Exists(root))
            throw new DirectoryNotFoundException("Encrypted repository does not exist: " + root);

        Identity rootId = ReadDirectoryId(root);
        // A source might be a physical ANCESTOR of the repository despite
        // having a different lexical spelling (e.g. 8.3 short path alias).
        // Only inspect the target ID for an actually existing directory:
        // using its nearest existing parent for a NEW output directory would
        // falsely reject an unrelated sibling created beside the repository.
        if (Directory.Exists(target))
        {
            Identity targetId = ReadDirectoryId(target);
            for (DirectoryInfo? ancestor = new(root); ancestor is not null;
                 ancestor = ancestor.Parent)
            {
                if (ReadDirectoryId(ancestor.FullName) == targetId)
                    throw new IOException("Selected path physically contains the encrypted repository.");
            }
        }

        // A selected path INSIDE the repository may not yet exist. Walk every
        // existing ancestor, rejecting physical aliases of the vault itself.
        for (DirectoryInfo? ancestor = new(target); ancestor is not null;
             ancestor = ancestor.Parent)
        {
            if (ancestor.Exists && ReadDirectoryId(ancestor.FullName) == rootId)
                throw new IOException("Selected path physically resides inside the encrypted repository.");
        }
    }
}
