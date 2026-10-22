using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ChomcioRecovery.Core;

/// <summary>
/// Verify the originally staged encrypted record by physical Windows file ID.
/// Failure cleanup MUST NOT perform a pathname-based File.Delete after this
/// check: another process could replace that pathname between check and delete.
/// Instead, open a no-follow DELETE handle that refuses sharing of DELETE/WRITE,
/// verify the same file ID and hardlink count, and mark THAT handle for deletion.
/// Unsupported systems/permissions fail closed and may leave a harmless temp.
/// This is not a full ancestor-directory race or crash-durability solution.
/// </summary>
internal static class WindowsRecordStageGuard
{
    private const uint GenericRead = 0x80000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint FileShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const int FileBasicInfoClass = 0;
    private const int FileDispositionInfoClass = 4;
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;

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
    private static extern bool GetBasicInfo(SafeFileHandle handle, int infoClass,
        out FileBasicInfo info, uint length);

    [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetDisposition(SafeFileHandle handle, int infoClass,
        [In] byte[] info, uint length);

    internal static void RequireOriginalTemp(string temp,
        WindowsSourceFileIdentity.Identity? original)
    {
        if (!OperatingSystem.IsWindows()) return;
        if (!original.HasValue || WindowsSourceFileIdentity.CaptureFile(temp) != original.Value)
            throw new IOException("Encrypted record temp identity changed; publication refused.");
    }

    internal static void CleanupOnlyOriginalTemp(string temp,
        WindowsSourceFileIdentity.Identity? original, Action<string>? whilePinned = null)
    {
        // A random temp is safer left on disk than an unrelated file removed.
        // Non-Windows has no verified native file ID in this implementation.
        if (!OperatingSystem.IsWindows() || !original.HasValue) return;

        // A retained FILE_OBJECT still leaves the directory namespace free to
        // move. Prevent ordinary parent/ancestor replacement during cleanup,
        // including when called directly rather than under WriteAtomic's pin.
        using var pinnedRecordParent = WindowsRestoreParentPin.Acquire(
            Path.GetDirectoryName(Path.GetFullPath(temp))!);
        pinnedRecordParent.RequireMatches();
        using SafeFileHandle owned = CreateFile(WindowsNativePath.FromPath(Path.GetFullPath(temp)),
            GenericRead | DeleteAccess, FileShareRead, IntPtr.Zero,
            OpenExisting, FileFlagOpenReparsePoint, IntPtr.Zero);
        if (owned.IsInvalid)
        {
            int openError = Marshal.GetLastWin32Error();
            // The original was already renamed/published or already removed.
            if (openError is ErrorFileNotFound or ErrorPathNotFound) return;
            throw new IOException("Cannot open original temp for handle-bound cleanup (Win32 " +
                openError + ").", new Win32Exception(openError));
        }
        if (!GetBasicInfo(owned, FileBasicInfoClass, out FileBasicInfo basic,
                (uint)Marshal.SizeOf<FileBasicInfo>()))
            throw WindowsError("Cannot inspect temporary cleanup file handle");
        FileAttributes attributes = (FileAttributes)basic.FileAttributes;
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new IOException("Cleanup target is not a regular encrypted-record temp.");
        WindowsUnsupportedMetadataGuard.RejectUnsupported(attributes, temp);
        WindowsHardLinkGuard.RejectMultipleLinks(owned, temp);
        if (WindowsSourceFileIdentity.Capture(owned) != original.Value)
            throw new IOException("Encrypted record temp was replaced; cleanup refused.");

        // Native tests attempt a concurrent rename at this exact point. Our
        // retained handle has no FILE_SHARE_DELETE: even a byte-identical
        // foreign pathname cannot be substituted before the kernel delete.
        whilePinned?.Invoke(temp);
        WindowsHardLinkGuard.RejectMultipleLinks(owned, temp);
        if (WindowsSourceFileIdentity.Capture(owned) != original.Value)
            throw new IOException("Encrypted record cleanup FileId changed.");
        pinnedRecordParent.RequireMatches();
        // FILE_DISPOSITION_INFO.DeleteFile is a single Win32 BOOLEAN byte,
        // not a 4-byte BOOL. The file is marked for deletion on handle close.
        byte[] disposition = { 1 };
        if (!SetDisposition(owned, FileDispositionInfoClass, disposition,
                (uint)disposition.Length))
            throw WindowsError("Handle-bound encrypted temp cleanup failed");
    }

    private static IOException WindowsError(string message)
    {
        int code = Marshal.GetLastWin32Error();
        return new IOException(message + " (Win32 " + code + ").", new Win32Exception(code));
    }
}
