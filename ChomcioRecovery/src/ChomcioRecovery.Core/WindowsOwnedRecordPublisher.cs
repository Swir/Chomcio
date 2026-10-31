using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ChomcioRecovery.Core;

/// <summary>
/// Windows-only immutable-record publisher. Rename the EXACT original temporary
/// FILE_OBJECT via its still-open DELETE handle, with ReplaceIfExists=FALSE.
/// The handle disallows FILE_SHARE_WRITE and FILE_SHARE_DELETE for its lifetime:
/// a concurrent pathname replacement cannot redirect this publication, and a
/// new writer cannot reopen the verified bytes before the rename. The file is
/// read back AGAIN from the retained handle immediately before publication.
///
/// This does not make the enclosing repository a transactional filesystem:
/// root/ancestor retargeting, hostile processes with existing privileged
/// handles, sudden power loss, and post-publication mutation still require
/// physical Windows/NTFS acceptance. Fail closed on unsupported filesystems.
/// </summary>
internal static class WindowsOwnedRecordPublisher
{
    private const uint GenericRead = 0x80000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint FileShareRead = 0x01;
    private const uint OpenExisting = 3;
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

    // Use Marshal.OffsetOf rather than assuming the filename starts at byte 12
    // or 20: FILE_RENAME_INFO contains a pointer-size/alignment dependent
    // RootDirectory field. ReplaceIfExists is the 4-byte union at offset 0.
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
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetBasicInfo(SafeFileHandle handle, int infoClass,
        out FileBasicInfo info, uint length);

    [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle,
        int fileInformationClass, byte[] fileInformation, uint bufferSize);

    internal static void Publish(string tempPath, string targetPath, byte[] expectedBytes,
        WindowsSourceFileIdentity.Identity? originalIdentity, CancellationToken cancellationToken,
        Action<string>? whilePinned = null)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Handle-bound record publication requires Windows.");
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(expectedBytes);
        if (!originalIdentity.HasValue)
            throw new IOException("Original record staging FileId missing; publication refused.");
        string source = Path.GetFullPath(tempPath);
        string target = Path.GetFullPath(targetPath);
        string? sourceParent = Path.GetDirectoryName(source);
        string? targetParent = Path.GetDirectoryName(target);
        if (sourceParent is null || targetParent is null ||
            !string.Equals(sourceParent, targetParent, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(source, target, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Record publication must rename within one verified directory.");

        // The source FILE_OBJECT pin alone does NOT keep the pathname of its
        // containing directory from being redirected. Reuse the strict root-to-
        // leaf no-SHARE_DELETE directory pin already required for file restores.
        // This also protects standalone internal calls to Publish().
        using var pinnedRecordParent = WindowsRestoreParentPin.Acquire(sourceParent);
        pinnedRecordParent.RequireMatches();
        using SafeFileHandle retained = CreateFile(WindowsNativePath.FromPath(source), GenericRead | DeleteAccess,
            FileShareRead, IntPtr.Zero, OpenExisting, FileFlagOpenReparsePoint, IntPtr.Zero);
        if (retained.IsInvalid)
            throw WindowsError("Cannot obtain exclusive owned record publication handle");
        if (!GetBasicInfo(retained, FileBasicInfoClass, out FileBasicInfo basic,
                (uint)Marshal.SizeOf<FileBasicInfo>()))
            throw WindowsError("Cannot inspect owned record publication handle");
        var attributes = (FileAttributes)basic.FileAttributes;
        if ((attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
            throw new IOException("Record staging handle is not a regular file.");
        WindowsUnsupportedMetadataGuard.RejectUnsupported(attributes, source);
        WindowsHardLinkGuard.RejectMultipleLinks(retained, source);
        if (WindowsSourceFileIdentity.Capture(retained) != originalIdentity.Value)
            throw new IOException("Owned record FILE_OBJECT changed; publication refused.");

        // A SECOND, handle-bound readback prevents a writer from changing the
        // ciphertext between the earlier TEMP check and acquiring our exclusive
        // DELETE handle. No plaintext or unverified bytes are ever published.
        using (var input = new FileStream(retained, FileAccess.Read,
                   bufferSize: 65_536, isAsync: false))
        {
            if (input.Length != expectedBytes.Length)
                throw new IOException("Owned record length changed before publication.");
            byte[] buffer = new byte[65_536];
            try
            {
                for (int offset = 0; offset < expectedBytes.Length;)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    int n = Math.Min(buffer.Length, expectedBytes.Length - offset);
                    input.ReadExactly(buffer.AsSpan(0, n));
                    cancellationToken.ThrowIfCancellationRequested();
                    if (!buffer.AsSpan(0, n).SequenceEqual(expectedBytes.AsSpan(offset, n)))
                        throw new IOException("Owned record bytes changed before publication.");
                    offset += n;
                }
                if (input.ReadByte() != -1 || input.Length != expectedBytes.Length)
                    throw new IOException("Owned record changed during publication readback.");
            }
            finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer); }
            // Only native smoke uses whilePinned. Attempted pathname swaps must
            // be rejected by the still-open no-share-delete handle; a competing
            // destination must cause the no-replace rename to fail, not overwrite.
            whilePinned?.Invoke(source);
            // Keep cancellation live until the FINAL syscall, not merely until
            // the first readback. Never report a cancellation after publication.
            cancellationToken.ThrowIfCancellationRequested();
            WindowsHardLinkGuard.RejectMultipleLinks(retained, source);
            pinnedRecordParent.RequireMatches();
            byte[] info = BuildNoReplaceRenameBuffer(target);
            cancellationToken.ThrowIfCancellationRequested();
            if (!SetFileInformationByHandle(retained, FileRenameInfoClass, info, (uint)info.Length))
                throw WindowsError("Handle-bound no-clobber record rename failed");
        }
    }

    private static byte[] BuildNoReplaceRenameBuffer(string fullDestination)
    {
        // SetFileInformationByHandle does not perform System.IO's long-path
        // conversion. Keep the same pinned/no-replace operation at any depth.
        byte[] path = Encoding.Unicode.GetBytes(WindowsNativePath.FromPath(fullDestination));
        int fileNameOffset = checked((int)Marshal.OffsetOf<RenameInfoLayout>(nameof(RenameInfoLayout.FileName)));
        int lengthOffset = checked((int)Marshal.OffsetOf<RenameInfoLayout>(nameof(RenameInfoLayout.FileNameLength)));
        byte[] buffer = new byte[checked(fileNameOffset + path.Length + sizeof(char))];
        // Buffer is zero-initialized: ReplaceIfExists=FALSE, RootDirectory=NULL.
        // The target name is an absolute path and must not contain NULs.
        if (fullDestination.Contains('\0'))
            throw new IOException("NUL in record publication destination.");
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(lengthOffset, sizeof(uint)),
            checked((uint)path.Length));
        path.CopyTo(buffer, fileNameOffset);
        return buffer;
    }

    private static IOException WindowsError(string message)
    {
        int code = Marshal.GetLastWin32Error();
        return new IOException(message + " (Win32 " + code + ").", new Win32Exception(code));
    }
}
