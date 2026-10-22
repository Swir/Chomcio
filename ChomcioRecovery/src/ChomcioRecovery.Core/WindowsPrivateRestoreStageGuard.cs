using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ChomcioRecovery.Core;

/// <summary>
/// Pin the NTFS/ReFS identity of a private plaintext restore stage from creation
/// to publication/cleanup. If another same-user actor substitutes a DIFFERENT
/// directory at the staging pathname, recursive error cleanup MUST NOT delete
/// that directory. A share-delete handle permits the legitimate final rename.
///
/// This is a targeted guard against pre-cleanup substitution, not complete
/// same-user race isolation: recursively traversing a mutable directory from
/// its pathname is unsafe. On Windows we ONLY delete a verified empty stage
/// through a no-delete-share handle. A nonempty stage is retained for manual,
/// separately authenticated disposal (including cancelled restores). Native
/// Windows adversarial tests remain mandatory. Non-Windows has no native pin.
/// </summary>
internal sealed class WindowsPrivateRestoreStageGuard : IDisposable
{
    private const uint FileReadAttributes = 0x80;
    private const uint DeleteAccess = 0x00010000;
    private const uint FileShareRead = 0x01;
    private const uint FileShareWrite = 0x02;
    private const uint FileShareAll = 0x01 | 0x02 | 0x04;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const int FileBasicInfoClass = 0;
    private const int FileIdInfoClass = 18;
    private const int FileDispositionInfoClass = 4;
    private const int ErrorDirectoryNotEmpty = 145;

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

    private readonly string _path;
    private readonly (ulong Volume, ulong Low, ulong High) _identity;
    private readonly SafeFileHandle? _pinned;

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode,
        ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint sharing,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetBasicInfo(SafeFileHandle handle, int informationClass,
        out FileBasicInfo info, uint length);

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetIdInfo(SafeFileHandle handle, int informationClass,
        out FileIdInfo info, uint length);

    [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle,
        int infoClass, byte[] information, uint size);

    /// <summary>
    /// Windows intentionally NEVER recursively deletes a nonempty staging tree:
    /// descendants can be exchanged by a same-user attacker after a path scan,
    /// and recursive deletion could erase unrelated user data. An empty stage
    /// can be removed atomically using the SAME FileId-checked directory handle.
    /// Returns false for a nonempty stage: keep its private contents for a
    /// separately reviewed cleanup. This may consume disk space and requires
    /// an owner-side cleanup policy before production beta qualification.
    /// </summary>
    internal bool TryDeleteOriginalEmptyStage(string stage, Action<string>? whileOwned = null)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Owned directory cleanup requires Windows.");
        if (_pinned is null || _pinned.IsClosed)
            throw new ObjectDisposedException(nameof(WindowsPrivateRestoreStageGuard));
        if (Path.GetFullPath(stage) != _path)
            throw new IOException("Private cleanup path differs from original stage.");

        string parent = Path.GetDirectoryName(_path)
            ?? throw new IOException("Private stage has no parent directory.");
        // Parent ancestors cannot be replaced while this operation is active.
        using var parentPin = WindowsRestoreParentPin.Acquire(parent);
        parentPin.RequireMatches();
        // No FILE_SHARE_DELETE: the stage entry cannot be swapped between its
        // original FileId verification and kernel disposition, even by same UID.
        using SafeFileHandle owned = CreateFile(WindowsNativePath.FromPath(_path), FileReadAttributes | DeleteAccess,
            FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (owned.IsInvalid)
            throw new IOException("Cannot own private directory for empty cleanup: " + _path,
                new Win32Exception(Marshal.GetLastWin32Error()));
        if (!GetBasicInfo(owned, FileBasicInfoClass, out FileBasicInfo info,
                (uint)Marshal.SizeOf<FileBasicInfo>()))
            throw new IOException("Cannot inspect private directory for cleanup.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        FileAttributes attributes = (FileAttributes)info.FileAttributes;
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != FileAttributes.Directory)
            throw new IOException("Private cleanup source is not a real directory.");
        if (ReadId(owned, _path) != _identity)
            throw new IOException("Private cleanup source differs from creation-time FileId.");
        RequireMatches(_path);
        whileOwned?.Invoke(_path); // adversarial native smoke hook only
        RequireMatches(_path);
        parentPin.RequireMatches();
        // FILE_DISPOSITION_INFO has a single 1-byte BOOLEAN, no pathname.
        // Windows refuses removal of a directory which still has children.
        byte[] deleteOriginal = { 1 };
        if (!SetFileInformationByHandle(owned, FileDispositionInfoClass,
                deleteOriginal, (uint)deleteOriginal.Length))
        {
            int code = Marshal.GetLastWin32Error();
            if (code == ErrorDirectoryNotEmpty)
                return false; // fail closed; no recursive/pathname fallback
            throw new IOException("Owned private-stage empty disposition failed (Win32 " + code + ").",
                new Win32Exception(code));
        }
        // The identity-only ID handle otherwise delays final removal. Release
        // it only AFTER disposition succeeded on our exclusively owned object.
        _pinned?.Dispose();
        return true;
    }

    private WindowsPrivateRestoreStageGuard(string path, SafeFileHandle? pinned,
        (ulong Volume, ulong Low, ulong High) identity)
    {
        _path = path;
        _pinned = pinned;
        _identity = identity;
    }

    internal static WindowsPrivateRestoreStageGuard Acquire(string stage)
    {
        string path = Path.GetFullPath(stage);
        if (!OperatingSystem.IsWindows())
            return new WindowsPrivateRestoreStageGuard(path, null, default);
        using SafeFileHandle named = OpenRealDirectory(path);
        SafeFileHandle handle = WindowsIdentityOpen.Open(named, FileReadAttributes, FileShareAll,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint);
        try
        {
            var id = ReadId(handle, path);
            return new WindowsPrivateRestoreStageGuard(path, handle, id);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    /// <summary>
    /// The original FILE_CREATE handle still holds a no-delete-share lease,
    /// so a second pathname open cannot adopt a substituted directory between
    /// kernel creation and its physical FileId capture.
    /// </summary>
    internal static WindowsPrivateRestoreStageGuard AcquireFromOriginalCreation(
        string stage, SafeFileHandle originalCreator)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Original directory ownership requires Windows.");
        if (originalCreator.IsInvalid || originalCreator.IsClosed)
            throw new IOException("Original staged child creator handle is unavailable.");
        var originalId = ReadId(originalCreator, stage);
        WindowsPrivateRestoreStageGuard guard = Acquire(stage);
        try
        {
            if (guard._identity != originalId)
                throw new IOException("Staged child was replaced between creation and recording.");
            guard.RequireMatches(stage);
            return guard;
        }
        catch
        {
            guard.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Bind a DELETE-capable publication handle to the original stage FileId.
    /// The caller's handle forbids FILE_SHARE_DELETE; this makes the final
    /// identity check and owned-handle rename refer to the SAME FILE_OBJECT.
    /// </summary>
    internal void RequireOwnedHandleMatches(string path, SafeFileHandle owned)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Directory FileId pin requires Windows.");
        if (_pinned is null || _pinned.IsClosed || owned.IsInvalid || owned.IsClosed)
            throw new ObjectDisposedException(nameof(WindowsPrivateRestoreStageGuard));
        if (Path.GetFullPath(path) != _path || ReadId(owned, path) != _identity)
            throw new IOException("Owned staged directory differs from original FileId.");
        RequireMatches(path); // original path is still owned and no-delete pinned
    }

    /// <summary>
    /// AFTER the original owned-handle rename, the old private staging path
    /// intentionally no longer exists. Compare a NO-FOLLOW opened final directory
    /// with the ORIGINAL creation-time NTFS/ReFS FILE_ID_INFO, not a new owner
    /// inferred from the published pathname or its byte-identical contents.
    /// This check is fail-closed, but not an atomic NTFS tree snapshot.
    /// </summary>
    internal void RequireOriginalPublishedIdentity(string publishedPath)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Published directory identity requires Windows.");
        if (_pinned is null || _pinned.IsClosed)
            throw new ObjectDisposedException(nameof(WindowsPrivateRestoreStageGuard));
        using SafeFileHandle published = OpenRealDirectory(Path.GetFullPath(publishedPath));
        if (ReadId(published, publishedPath) != _identity)
            throw new IOException("Published directory differs from original creation-time FileId: " + publishedPath);
    }

    /// <summary>Refuse deletion of an unrelated directory substituted at stage.</summary>
    internal void RequireMatches(string stage)
    {
        if (Path.GetFullPath(stage) != _path)
            throw new IOException("Private restore stage path differs from the pinned path.");
        if (!OperatingSystem.IsWindows()) return;
        if (_pinned is null || _pinned.IsClosed)
            throw new ObjectDisposedException(nameof(WindowsPrivateRestoreStageGuard));
        using SafeFileHandle actual = OpenRealDirectory(_path);
        if (ReadId(actual, _path) != _identity)
            throw new IOException("Private restore stage was replaced; refusing recursive cleanup.");
    }

    private static SafeFileHandle OpenRealDirectory(string path)
    {
        SafeFileHandle handle = CreateFile(WindowsNativePath.FromPath(path), FileReadAttributes, FileShareAll,
            IntPtr.Zero, OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new IOException("Cannot pin private restore stage: " + path + " (Win32 " + error + ")",
                new Win32Exception(error));
        }
        try
        {
            if (!GetBasicInfo(handle, FileBasicInfoClass, out FileBasicInfo info,
                    (uint)Marshal.SizeOf<FileBasicInfo>()))
                throw new IOException("Cannot inspect private restore stage: " + path,
                    new Win32Exception(Marshal.GetLastWin32Error()));
            var attributes = (FileAttributes)info.FileAttributes;
            if ((attributes & FileAttributes.Directory) == 0 ||
                (attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Private restore stage is not a real directory: " + path);
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static (ulong Volume, ulong Low, ulong High) ReadId(SafeFileHandle handle, string path)
    {
        if (!GetIdInfo(handle, FileIdInfoClass, out FileIdInfo info,
                (uint)Marshal.SizeOf<FileIdInfo>()))
            throw new IOException("Cannot read private restore stage identity: " + path,
                new Win32Exception(Marshal.GetLastWin32Error()));
        if ((info.FileIdLow | info.FileIdHigh) == 0)
            throw new IOException("Private restore stage has an unusable file ID: " + path);
        return (info.VolumeSerialNumber, info.FileIdLow, info.FileIdHigh);
    }

    public void Dispose() => _pinned?.Dispose();
}
