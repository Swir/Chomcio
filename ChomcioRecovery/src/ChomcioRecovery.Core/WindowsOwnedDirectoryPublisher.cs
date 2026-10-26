using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ChomcioRecovery.Core;

/// <summary>
/// Publishes the original private staged DIRECTORY object, not whatever happens
/// to occupy its pathname after verification. The retained handle denies
/// FILE_SHARE_DELETE until the kernel's no-replace rename has completed.
/// The stage's creation-time FileId is independently pinned by the caller.
/// This is NOT an atomic tree-content snapshot: a writer with an already-open
/// handle could still mutate a descendant. Native NTFS acceptance is required.
/// </summary>
internal static class WindowsOwnedDirectoryPublisher
{
    private const uint ListDirectory = 0x0001;
    private const uint ReadAttributes = 0x0080;
    private const uint DeleteAccess = 0x00010000;
    private const uint FileShareRead = 0x01;
    private const uint FileShareWrite = 0x02;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const int FileBasicInfoClass = 0;
    private const int FileRenameInfoClass = 3;

    [StructLayout(LayoutKind.Sequential)]
    private struct FileBasicInfo
    {
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public long ChangeTime;
        public uint FileAttributes;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RenameInfoLayout
    {
        public uint ReplaceIfExists;
        public IntPtr RootDirectory;
        public uint FileNameLength;
        public char FileName;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode,
        ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetBasicInfo(SafeFileHandle handle, int infoClass,
        out FileBasicInfo info, uint size);

    [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle,
        int infoClass, byte[] info, uint size);

    internal static void Publish(string stagedDirectory, string destinationDirectory,
        WindowsPrivateRestoreStageGuard originalStage, CancellationToken cancellationToken,
        Action<string>? whilePinned = null)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Handle-bound directory rename requires Windows.");
        ArgumentNullException.ThrowIfNull(originalStage);
        cancellationToken.ThrowIfCancellationRequested();
        string source = Path.GetFullPath(stagedDirectory);
        string target = Path.GetFullPath(destinationDirectory);
        string? fromParent = Path.GetDirectoryName(source);
        string? toParent = Path.GetDirectoryName(target);
        if (fromParent is null || toParent is null ||
            !string.Equals(fromParent, toParent, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(source, target, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Directory publication must stay within its pinned parent.");
        // All existing parent ancestors are opened root-to-leaf without
        // FILE_SHARE_DELETE. The destination basename remains no-clobber.
        using var parentPin = WindowsRestoreParentPin.Acquire(fromParent);
        parentPin.RequireMatches();
        using SafeFileHandle owned = CreateFile(WindowsNativePath.FromPath(source),
            ListDirectory | ReadAttributes | DeleteAccess, FileShareRead | FileShareWrite,
            IntPtr.Zero, OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (owned.IsInvalid)
            throw WindowsError("Cannot own private staged directory for publication");
        if (!GetBasicInfo(owned, FileBasicInfoClass, out FileBasicInfo basic,
                (uint)Marshal.SizeOf<FileBasicInfo>()))
            throw WindowsError("Cannot inspect owned staged directory");
        FileAttributes attributes = (FileAttributes)basic.FileAttributes;
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) !=
            FileAttributes.Directory)
            throw new IOException("Owned publication source is not a genuine directory.");
        // Compare creation-time identity to the retained SAME kernel object.
        // Reopening just the pathname alone cannot securely bind the source.
        originalStage.RequireOwnedHandleMatches(source, owned);
        whilePinned?.Invoke(source);  // native test injection only
        cancellationToken.ThrowIfCancellationRequested();
        originalStage.RequireOwnedHandleMatches(source, owned);
        parentPin.RequireMatches();
        byte[] info = BuildNoReplaceRenameBuffer(target);
        cancellationToken.ThrowIfCancellationRequested();
        if (!SetFileInformationByHandle(owned, FileRenameInfoClass,
                info, (uint)info.Length))
            throw WindowsError("Owned no-replace staged directory rename failed");
        // No cancellation check AFTER commit. Destination readback is the
        // responsibility of the calling restore/export pipeline.
    }

    private static byte[] BuildNoReplaceRenameBuffer(string fullTarget)
    {
        if (fullTarget.Contains('\0'))
            throw new IOException("NUL in restore/export destination.");
        byte[] utf16 = Encoding.Unicode.GetBytes(WindowsNativePath.FromPath(fullTarget));
        int nameOffset = checked((int)Marshal.OffsetOf<RenameInfoLayout>(
            nameof(RenameInfoLayout.FileName)));
        int sizeOffset = checked((int)Marshal.OffsetOf<RenameInfoLayout>(
            nameof(RenameInfoLayout.FileNameLength)));
        byte[] info = new byte[checked(nameOffset + utf16.Length + sizeof(char))];
        // Zeroed ReplaceIfExists=FALSE, RootDirectory=NULL.
        BinaryPrimitives.WriteUInt32LittleEndian(info.AsSpan(sizeOffset, sizeof(uint)),
            checked((uint)utf16.Length));
        utf16.CopyTo(info, nameOffset);
        return info;
    }

    private static IOException WindowsError(string text)
    {
        int code = Marshal.GetLastWin32Error();
        return new IOException(text + " (Win32 " + code + ").", new Win32Exception(code));
    }
}
