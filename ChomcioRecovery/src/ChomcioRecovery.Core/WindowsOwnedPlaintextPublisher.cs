using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ChomcioRecovery.Core;

/// <summary>
/// Windows-only single-file restore commit. The file re-read for SHA-256 is
/// EXACTLY the kernel FILE_OBJECT subsequently renamed without replacement.
/// Holding READ|DELETE access without FILE_SHARE_WRITE/DELETE denies ordinary
/// concurrent mutation and pathname replacement during the digest-to-commit
/// window. The private-stage parent and all its ancestors are pinned too.
///
/// This does NOT implement transactional post-commit durability, protect against
/// a previously opened privileged writer, or qualify untested NTFS semantics.
/// A failed operation leaves user-visible preexisting destinations untouched.
/// </summary>
internal static class WindowsOwnedPlaintextPublisher
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

    internal static void Publish(string stagedPath, string destinationPath,
        long expectedLength, string expectedSha256,
        WindowsSourceFileIdentity.Identity? originalWriterIdentity,
        CancellationToken cancellationToken, Action<string>? whilePinned = null,string? zoneIdentifierBase64=null)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows owned plaintext commit requires Windows.");
        cancellationToken.ThrowIfCancellationRequested();
        // The publisher must NEVER adopt a different file simply because its
        // contents re-hash to the authenticated plaintext digest. Capture this
        // FileId from the original FileStream writer BEFORE writer disposal.
        if (!originalWriterIdentity.HasValue)
            throw new IOException("Original plaintext writer identity missing; commit refused.");
        if (expectedLength < 0 || expectedSha256.Length != 64)
            throw new InvalidDataException("Invalid restored-file size or SHA-256.");
        byte[] expectedDigest;
        try { expectedDigest = Convert.FromHexString(expectedSha256); }
        catch (FormatException e) { throw new InvalidDataException("Invalid restored-file SHA-256.", e); }
        string source = Path.GetFullPath(stagedPath);
        string target = Path.GetFullPath(destinationPath);
        string sourceParent = Path.GetDirectoryName(source)
            ?? throw new IOException("Restore stage parent is missing.");
        string targetParent = Path.GetDirectoryName(target)
            ?? throw new IOException("Restore output parent is missing.");
        if (string.Equals(source, target, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(sourceParent, targetParent, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Restored-file stage must be in a separate private directory.");
        // Caller independently pins the public destination. Pin the private
        // stage root as well, so a parent rename cannot move its contents.
        using var pinnedSourceParent = WindowsRestoreParentPin.Acquire(sourceParent);
        pinnedSourceParent.RequireMatches();
        using SafeFileHandle retained = CreateFile(WindowsNativePath.FromPath(source), GenericRead | DeleteAccess,
            FileShareRead, IntPtr.Zero, OpenExisting, FileFlagOpenReparsePoint, IntPtr.Zero);
        if (retained.IsInvalid)
            throw WindowsError("Cannot acquire owned plaintext restore handle");
        if (!GetBasicInfo(retained, FileBasicInfoClass, out FileBasicInfo basic,
                (uint)Marshal.SizeOf<FileBasicInfo>()))
            throw WindowsError("Cannot inspect private plaintext restore handle");
        FileAttributes attributes = (FileAttributes)basic.FileAttributes;
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new IOException("Private restore handle is not a regular file.");
        WindowsUnsupportedMetadataGuard.RejectUnsupported(attributes, source);
        WindowsHardLinkGuard.RejectMultipleLinks(retained, source);
        var retainedId = WindowsSourceFileIdentity.Capture(retained);
        if (retainedId != originalWriterIdentity.Value)
            throw new IOException("Staged plaintext was replaced after writer close; commit refused.");
        // Verify the on-disk bytes from the same retained kernel FILE_OBJECT
        // that will perform SetFileInformationByHandle, not another pathname open.
        using (var input = new FileStream(retained, FileAccess.Read,
                   bufferSize: 65_536, isAsync: false))
        using (var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            if (input.Length != expectedLength)
                throw new IOException("Staged plaintext length changed before publication.");
            byte[] buffer = new byte[65_536];
            try
            {
                long remaining = expectedLength;
                while (remaining > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    int n = checked((int)Math.Min(remaining, buffer.Length));
                    input.ReadExactly(buffer.AsSpan(0, n));
                    sha.AppendData(buffer.AsSpan(0, n));
                    remaining -= n;
                }
                if (input.ReadByte() != -1 || input.Length != expectedLength)
                    throw new IOException("Staged plaintext changed while being authenticated.");
                byte[] actualDigest = sha.GetHashAndReset();
                try
                {
                    if (!CryptographicOperations.FixedTimeEquals(actualDigest, expectedDigest))
                        throw new InvalidDataException("Staged plaintext SHA-256 changed before publication.");
                }
                finally { CryptographicOperations.ZeroMemory(actualDigest); }
            }
            finally { CryptographicOperations.ZeroMemory(buffer); }

            // Only internal native smoke can supply this callback. The handle
            // must reject file rename, file overwrite and stage-parent rename.
            whilePinned?.Invoke(source);
            WindowsZoneIdentifier.Verify(source,zoneIdentifierBase64,cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            WindowsHardLinkGuard.RejectMultipleLinks(retained, source);
            if (WindowsSourceFileIdentity.Capture(retained) != originalWriterIdentity.Value)
                throw new IOException("Pinned restored-file no longer matches original writer.");
            pinnedSourceParent.RequireMatches();
            byte[] renameInfo = BuildNoReplaceRenameBuffer(target);
            cancellationToken.ThrowIfCancellationRequested();
            if (!SetFileInformationByHandle(retained, FileRenameInfoClass,
                    renameInfo, (uint)renameInfo.Length))
                throw WindowsError("Owned no-replace plaintext restore rename failed");
        }
        // Never check cancellation AFTER the kernel has made the restore visible.
    }

    private static byte[] BuildNoReplaceRenameBuffer(string fullDestination)
    {
        if (fullDestination.Contains('\0'))
            throw new IOException("NUL in restored-file destination.");
        byte[] name = Encoding.Unicode.GetBytes(fullDestination);
        int offset = checked((int)Marshal.OffsetOf<RenameInfoLayout>(nameof(RenameInfoLayout.FileName)));
        int lengthOffset = checked((int)Marshal.OffsetOf<RenameInfoLayout>(nameof(RenameInfoLayout.FileNameLength)));
        byte[] buffer = new byte[checked(offset + name.Length + sizeof(char))];
        // Zeroed header: ReplaceIfExists=FALSE and RootDirectory=NULL.
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(lengthOffset, sizeof(uint)),
            checked((uint)name.Length));
        name.CopyTo(buffer, offset);
        return buffer;
    }

    private static IOException WindowsError(string message)
    {
        int code = Marshal.GetLastWin32Error();
        return new IOException(message + " (Win32 " + code + ").", new Win32Exception(code));
    }
}
