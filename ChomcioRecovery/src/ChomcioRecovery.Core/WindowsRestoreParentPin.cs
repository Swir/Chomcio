using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ChomcioRecovery.Core;

/// <summary>
/// Retains handles and physical IDs of the EXISTING destination ancestors.
/// Requests FILE_LIST_DIRECTORY as well as attributes, without FILE_SHARE_DELETE.
/// An attributes-only handle is NOT an adequate rename exclusion primitive.
/// RequireMatches additionally checks the original physical IDs before publication.
/// Native Windows rename-denial tests remain mandatory; no fallback weakens them.
/// This deliberately does not pin the staging tree (which must be renamed) or
/// prevent same-user modification of its contents: not production isolation.
/// </summary>
internal sealed class WindowsRestoreParentPin : IDisposable
{
    // CreateFileW: attribute/EA-only requests are not governed by sharing modes.
    // Directory listing is read-data access for a directory. Do not silently
    // fall back to attributes-only access if this stronger open is refused.
    // https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilew
    private const uint FileListDirectory = 0x01;
    private const uint FileReadAttributes = 0x80;
    private const uint FileShareRead = 0x01;
    private const uint FileShareWrite = 0x02;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private readonly List<SafeFileHandle> _handles = new();
    private readonly List<(string Path, ulong Volume, ulong Low, ulong High)> _identities = new();
    private const int FileIdInfoClass = 18;
    private bool _disposed;

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInfo
    {
        public ulong VolumeSerialNumber;
        public ulong FileIdLow;
        public ulong FileIdHigh;
    }

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetIdInfo(SafeFileHandle handle, int informationClass,
        out FileIdInfo information, uint bufferSize);

    private static FileIdInfo ReadIdentity(SafeFileHandle handle, string path)
    {
        if (!GetIdInfo(handle, FileIdInfoClass, out FileIdInfo identity,
            (uint)Marshal.SizeOf<FileIdInfo>()))
            throw new IOException("Cannot identify restore ancestor: " + path,
                new Win32Exception(Marshal.GetLastWin32Error()));
        if ((identity.FileIdLow | identity.FileIdHigh) == 0)
            throw new IOException("Restore ancestor has zero file ID: " + path);
        return identity;
    }

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
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,
        int informationClass, out FileBasicInfo information, uint bufferSize);

    private WindowsRestoreParentPin() { }

    internal static WindowsRestoreParentPin Acquire(string existingParent)
    {
        var result = new WindowsRestoreParentPin();
        if (!OperatingSystem.IsWindows()) return result;
        try
        {
            // Root-to-leaf is intentional. Pinning the selected parent first
            // could allow a higher ancestor to be renamed in the interval
            // before we open its own handle. Every higher ancestor is already
            // pinned when we descend to the next component.
            var ancestry = new List<DirectoryInfo>();
            DirectoryInfo? directory = new(Path.GetFullPath(existingParent));
            while (directory != null)
            {
                ancestry.Add(directory);
                directory = directory.Parent;
            }
            ancestry.Reverse();
            foreach (DirectoryInfo ancestor in ancestry)
            {
                // OPEN_REPARSE_POINT opens a link itself, not its target. Require
                // a genuine directory from the kernel-provided handle attributes.
                SafeFileHandle handle = CreateFile(WindowsNativePath.FromPath(ancestor.FullName), FileListDirectory | FileReadAttributes,
                    FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting,
                    FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
                if (handle.IsInvalid)
                {
                    int error = Marshal.GetLastWin32Error();
                    handle.Dispose();
                    throw new IOException("Cannot pin restore ancestor '" + ancestor.FullName +
                        "' (Win32 error " + error + ").", new Win32Exception(error));
                }
                result._handles.Add(handle); // Ownership immediately transferred.
                if (!GetFileInformationByHandleEx(handle, 0, out FileBasicInfo info,
                        (uint)Marshal.SizeOf<FileBasicInfo>()))
                    throw new IOException("Cannot inspect pinned restore directory: " + ancestor.FullName,
                        new Win32Exception(Marshal.GetLastWin32Error()));
                var attributes = (FileAttributes)info.FileAttributes;
                if ((attributes & FileAttributes.Directory) == 0 ||
                    (attributes & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Restore ancestor is not a real directory: " + ancestor.FullName);
                FileIdInfo id = ReadIdentity(handle, ancestor.FullName);
                result._identities.Add((ancestor.FullName, id.VolumeSerialNumber, id.FileIdLow, id.FileIdHigh));
            }
            return result;
        }
        catch
        {
            result.Dispose();
            throw;
        }
    }

    // Fail closed if an ancestor was moved/replaced, even where no-share-delete
    // did not block the rename. Not an atomic defense against same-user races.
    internal void RequireMatches()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(WindowsRestoreParentPin));
        if (!OperatingSystem.IsWindows()) return;
        if (_handles.Count != _identities.Count || _handles.Count == 0)
            throw new ObjectDisposedException(nameof(WindowsRestoreParentPin));
        foreach (var expected in _identities)
        {
            using SafeFileHandle current = CreateFile(WindowsNativePath.FromPath(expected.Path), FileReadAttributes,
                FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting,
                FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
            if (current.IsInvalid)
                throw new IOException("Pinned restore ancestor disappeared or became inaccessible: " + expected.Path);
            if (!GetFileInformationByHandleEx(current, 0, out FileBasicInfo attributes,
                (uint)Marshal.SizeOf<FileBasicInfo>()) ||
                ((FileAttributes)attributes.FileAttributes & (FileAttributes.Directory | FileAttributes.ReparsePoint))
                    != FileAttributes.Directory)
                throw new IOException("Pinned restore ancestor is no longer a real directory: " + expected.Path);
            FileIdInfo id = ReadIdentity(current, expected.Path);
            if (id.VolumeSerialNumber != expected.Volume || id.FileIdLow != expected.Low ||
                id.FileIdHigh != expected.High)
                throw new IOException("Restore ancestor changed physical identity: " + expected.Path);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        // Release descendants first, so the ancestors remain pinned until last.
        for (int i = _handles.Count - 1; i >= 0; i--) _handles[i].Dispose();
        _handles.Clear();
        _identities.Clear();
    }
}
