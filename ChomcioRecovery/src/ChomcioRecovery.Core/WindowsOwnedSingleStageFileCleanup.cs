using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ChomcioRecovery.Core;

/// <summary>
/// Deletes only the ORIGINAL plaintext payload.tmp created for a single-file
/// restore. Its kernel FileId is recorded directly from the exclusive writer
/// handle, BEFORE the handle is closed and before a pathname can be swapped.
/// Cleanup opens a no-follow DELETE handle WITHOUT FILE_SHARE_DELETE, compares
/// identities on that same handle and sets FileDispositionInfo on that object.
/// An unexpected replacement is preserved (failure closed). The enclosing
/// private directory remains owned by WindowsPrivateRestoreStageGuard.
/// This is not guaranteed secure erasure of SSD media or crash recovery.
/// </summary>
internal sealed class WindowsOwnedSingleStageFileCleanup
{
    private const uint FileReadAttributes = 0x80;
    private const uint FileReadData = 0x01;
    private const uint DeleteAccess = 0x00010000;
    private const uint FileShareRead = 0x01;
    private const uint FileShareDelete = 0x04;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const int FileBasicInfoClass = 0;
    private const int FileStandardInfoClass = 1;
    private const int FileDispositionInfoClass = 4;
    private const int FileIdInfoClass = 18;

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
    private struct FileStandardInfo
    {
        public long AllocationSize;
        public long EndOfFile;
        public uint NumberOfLinks;
        [MarshalAs(UnmanagedType.U1)] public bool DeletePending;
        [MarshalAs(UnmanagedType.U1)] public bool Directory;
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
    private static extern bool GetStandardInfo(SafeFileHandle handle, int infoClass,
        out FileStandardInfo info, uint size);

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetIdInfo(SafeFileHandle handle, int infoClass,
        out FileIdInfo info, uint size);

    [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle,
        int infoClass, byte[] info, uint size);

    private readonly string _path;
    private readonly (ulong Volume, ulong Low, ulong High) _identity;

    // Bind final plaintext publication to the ORIGINAL exclusive writer, not
    // whichever byte-identical foreign file later occupies payload.tmp.
    internal WindowsSourceFileIdentity.Identity OriginalIdentity =>
        new(_identity.Volume, _identity.Low, _identity.High);

    // The original tracked stage pathname disappears after root publication;
    // only its creation-time FileId can identify the visible plaintext leaf.
    internal string OriginalPath => _path;

    internal void RequireOriginalPublishedIdentity(string publishedPath)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Published leaf identity requires Windows.");
        WindowsSourceFileIdentity.Identity? actual =
            WindowsSourceFileIdentity.CaptureFile(Path.GetFullPath(publishedPath));
        if (actual != OriginalIdentity)
            throw new IOException("Published restored leaf has a foreign FILE_OBJECT: " + publishedPath);
    }

    private WindowsOwnedSingleStageFileCleanup(string path, FileIdInfo identity)
    {
        _path = path;
        _identity = (identity.VolumeSerialNumber, identity.FileIdLow, identity.FileIdHigh);
    }

    internal static WindowsOwnedSingleStageFileCleanup CaptureCreatedFile(
        string path, SafeFileHandle originalExclusiveWriter)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Original stage FileId requires Windows.");
        if (originalExclusiveWriter.IsInvalid || originalExclusiveWriter.IsClosed)
            throw new IOException("Staged plaintext writer handle is already closed.");
        string fullPath = Path.GetFullPath(path);
        RequireRegularSingleLink(originalExclusiveWriter);
        return new WindowsOwnedSingleStageFileCleanup(fullPath, ReadId(originalExclusiveWriter));
    }

    internal bool TryDeleteOriginal(WindowsPrivateRestoreStageGuard parentStage,
        Action<string>? whileOwned = null) =>
        TryDeleteOriginal(parentStage, Path.GetDirectoryName(_path)!, whileOwned);

    // Nested restore-tree payloads are owned by a private root which may be
    // several directories above the actual file. The complete path must stay
    // inside that creation-time-pinned root: never accept an arbitrary path.
    internal bool TryDeleteOriginal(WindowsPrivateRestoreStageGuard parentStage,
        string privateStageRoot, Action<string>? whileOwned = null)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Owned plaintext deletion requires Windows.");
        ArgumentNullException.ThrowIfNull(parentStage);
        string parent = Path.GetDirectoryName(_path)
            ?? throw new IOException("Original staged plaintext path has no parent.");
        string root = Path.GetFullPath(privateStageRoot);
        string relative = Path.GetRelativePath(root, _path);
        if (Path.IsPathRooted(relative) || relative == "." || relative == ".." ||
            relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new IOException("Owned staged plaintext is outside the private staging root.");
        // Pin every ancestor, INCLUDING private stage, without delete sharing.
        // Prevent stage path redirection throughout the handle operation.
        using var parentPin = WindowsRestoreParentPin.Acquire(parent);
        parentStage.RequireMatches(root);
        parentPin.RequireMatches();

        // Missing after a successful owned-handle publication is expected.
        // A replacement name, if present, must NEVER be removed on that basis.
        using SafeFileHandle owned = CreateFile(WindowsNativePath.FromPath(_path), FileReadAttributes | DeleteAccess,
            FileShareRead, IntPtr.Zero, OpenExisting, FileFlagOpenReparsePoint, IntPtr.Zero);
        if (owned.IsInvalid)
        {
            int code = Marshal.GetLastWin32Error();
            owned.Dispose();
            if (code == 2 || code == 3) return false; // no file / path not found
            throw new IOException("Cannot exclusively own staged plaintext for cleanup (Win32 " +
                code + ").", new Win32Exception(code));
        }
        RequireRegularSingleLink(owned);
        FileIdInfo actual = ReadId(owned);
        if ((actual.VolumeSerialNumber, actual.FileIdLow, actual.FileIdHigh) != _identity)
            throw new IOException("Staged plaintext filename has been replaced; refusing deletion.");
        whileOwned?.Invoke(_path); // native adversarial-test injection only
        parentStage.RequireMatches(root);
        parentPin.RequireMatches();
        RequireRegularSingleLink(owned);
        actual = ReadId(owned);
        if ((actual.VolumeSerialNumber, actual.FileIdLow, actual.FileIdHigh) != _identity)
            throw new IOException("Staged plaintext object changed identity before deletion.");
        // This sets disposition on the ORIGINAL FILE_OBJECT, not its pathname.
        byte[] deleteOwned = { 1 };
        if (!SetFileInformationByHandle(owned, FileDispositionInfoClass,
                deleteOwned, (uint)deleteOwned.Length))
        {
            int code = Marshal.GetLastWin32Error();
            throw new IOException("Owned staged plaintext disposition failed (Win32 " +
                code + ").", new Win32Exception(code));
        }
        return true;
    }

    /// <summary>
    /// Before publishing a complete staged tree, refuse a staged leaf whose
    /// physical FILE_OBJECT differs from the original exclusive writer's
    /// creation-time FileId, EVEN IF the replacement has byte-identical data.
    /// This opens the actual no-follow file and verifies identity on that SAME
    /// handle under a complete non-delete-sharing parent lease. The handle
    /// closes after validation: a hostile writer with already-open handles
    /// or a swap after release remains a Windows-beta blocker, not a proven
    /// atomic tree snapshot.
    /// </summary>
    internal void RequireOriginalPresentForPublication(
        WindowsPrivateRestoreStageGuard originalRoot, string privateStageRoot)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Original staged file verification needs Windows.");
        ArgumentNullException.ThrowIfNull(originalRoot);
        string root = Path.GetFullPath(privateStageRoot);
        string relative = Path.GetRelativePath(root, _path);
        if (relative == "." || relative == ".." || Path.IsPathRooted(relative) ||
            relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new IOException("Staged publication leaf escapes original private root.");
        string parent = Path.GetDirectoryName(_path)
            ?? throw new IOException("Staged publication file has no parent.");
        using var ancestors = WindowsRestoreParentPin.Acquire(parent);
        originalRoot.RequireMatches(root);
        ancestors.RequireMatches();
        // Request FILE_READ_DATA, not metadata-only access: Windows share-mode
        // exclusion must prevent the opened file from being renamed or written
        // during the entire identity validation. No reparse traversal.
        using SafeFileHandle owned = CreateFile(WindowsNativePath.FromPath(_path), FileReadData | FileReadAttributes,
            FileShareRead, IntPtr.Zero, OpenExisting, FileFlagOpenReparsePoint, IntPtr.Zero);
        if (owned.IsInvalid)
        {
            int code = Marshal.GetLastWin32Error();
            owned.Dispose();
            throw new IOException("Cannot own staged leaf for original-file verification (Win32 " +
                code + ").", new Win32Exception(code));
        }
        RequireRegularSingleLink(owned);
        FileIdInfo actual = ReadId(owned);
        if ((actual.VolumeSerialNumber, actual.FileIdLow, actual.FileIdHigh) != _identity)
            throw new IOException("Foreign staged leaf substituted after original writer close; publication refused.");
        originalRoot.RequireMatches(root);
        ancestors.RequireMatches();
        RequireRegularSingleLink(owned);
        actual = ReadId(owned);
        if ((actual.VolumeSerialNumber, actual.FileIdLow, actual.FileIdHigh) != _identity)
            throw new IOException("Staged leaf changed physical FileId before publication.");
    }

    /// <summary>
    /// Read a tracked ORIGINAL leaf using a real FILE_READ_DATA request and
    /// FILE_SHARE_READ | FILE_SHARE_DELETE (NEVER FILE_SHARE_WRITE). Holding
    /// the returned handle stops new ordinary write opens and REFUSES a lease
    /// if an existing writer has the file open. Share-delete is deliberately
    /// allowed so a legitimate parent-tree rename can be attempted. This does
    /// NOT freeze the name of a leaf against a privileged/preopened rename:
    /// an atomic tree snapshot still needs native NTFS qualification.
    /// </summary>
    internal SafeFileHandle OpenWriteExcludingPublicationLease()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Content write exclusion needs Windows.");
        using SafeFileHandle hint = CreateFile(WindowsNativePath.FromPath(_path), FileReadAttributes,
            FileShareRead | FileShareDelete, IntPtr.Zero, OpenExisting, FileFlagOpenReparsePoint, IntPtr.Zero);
        if(hint.IsInvalid) throw new IOException("Cannot open staged volume hint.", new Win32Exception(Marshal.GetLastWin32Error()));
        // Open by physical ID so the read lease is independent of a directory
        // name being renamed. NTFS rejects a parent rename with named data opens.
        SafeFileHandle handle=WindowsIdentityOpen.Open(hint,FileReadData|FileReadAttributes,
            FileShareRead|FileShareDelete,FileFlagOpenReparsePoint);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new IOException("Cannot exclude concurrent staged writer (Win32 " + error + ").",
                new Win32Exception(error));
        }
        try
        {
            RequireRegularSingleLink(handle);
            FileIdInfo id = ReadId(handle);
            if ((id.VolumeSerialNumber, id.FileIdLow, id.FileIdHigh) != _identity)
                throw new IOException("Foreign staged leaf cannot receive an immutable-content lease.");
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }


    private static void RequireRegularSingleLink(SafeFileHandle handle)
    {
        if (!GetBasicInfo(handle, FileBasicInfoClass, out FileBasicInfo basic,
                (uint)Marshal.SizeOf<FileBasicInfo>()))
            throw new IOException("Cannot inspect staged plaintext attributes.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        FileAttributes attr = (FileAttributes)basic.FileAttributes;
        if ((attr & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new IOException("Stage payload is not an ordinary file.");
        if (!GetStandardInfo(handle, FileStandardInfoClass, out FileStandardInfo standard,
                (uint)Marshal.SizeOf<FileStandardInfo>()))
            throw new IOException("Cannot inspect staged plaintext hardlink count.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        if (standard.NumberOfLinks != 1 || standard.Directory || standard.DeletePending)
            throw new IOException("Staged plaintext is multiply linked or pending deletion.");
    }

    private static FileIdInfo ReadId(SafeFileHandle handle)
    {
        if (!GetIdInfo(handle, FileIdInfoClass, out FileIdInfo info,
                (uint)Marshal.SizeOf<FileIdInfo>()))
            throw new IOException("Cannot read staged plaintext FileId.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        if ((info.FileIdLow | info.FileIdHigh) == 0)
            throw new IOException("Staged plaintext FileId is unusable.");
        return info;
    }
}
