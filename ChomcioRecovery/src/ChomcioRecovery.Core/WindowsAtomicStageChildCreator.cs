using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ChomcioRecovery.Core;

/// <summary>
/// Atomically create a NEW staged child directory and expose its ORIGINAL
/// kernel handle to the ownership recorder before the handle is released.
/// Directory.CreateDirectory followed by a pathname FileId query has a gap
/// in which a same-user process can substitute a foreign directory, which
/// would then be incorrectly adopted for deletion. FILE_CREATE never opens
/// an existing entry; a no-FILE_SHARE_DELETE creator handle prevents a rename
/// until the callback has checked and pinned that exact original FileId.
/// This uses the Windows NT relative-directory API, and has NO path-based
/// fallback on Windows. Real Windows 10/11 NTFS testing remains mandatory.
/// </summary>
internal static class WindowsAtomicStageChildCreator
{
    private const uint ReadAttributes = 0x80;
    // A real directory-data request is essential for sharing-mode rename exclusion:
    // opening only metadata may bypass share-mode enforcement on Windows.
    private const uint ListDirectory = 0x01;
    private const uint ReadControl = 0x00020000;
    private const uint Traverse = 0x20;
    private const uint AddSubdirectory = 0x04;
    private const uint Synchronize = 0x00100000;
    private const uint ShareRead = 0x01;
    private const uint ShareWrite = 0x02;
    private const uint OpenExisting = 3;
    private const uint BackupSemantics = 0x02000000;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint ObjectCaseInsensitive = 0x40;
    private const uint FileDirectoryFile = 0x01;
    private const uint FileSynchronousIoNonAlert = 0x20;
    private const uint FileCreate = 2;
    private const long FileCreated = 2;
    private const int BasicInfoClass = 0;

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public uint Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        public IntPtr Status;
        public IntPtr Information;
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
    private static extern SafeFileHandle CreateFile(string path, uint desiredAccess,
        uint shareMode, IntPtr securityAttributes, uint creationDisposition,
        uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetBasicInfo(SafeFileHandle handle, int fileInformationClass,
        out FileBasicInfo info, uint bufferSize);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtCreateFile(out SafeFileHandle handle, uint desiredAccess,
        ref ObjectAttributes objectAttributes, out IoStatusBlock ioStatusBlock,
        IntPtr allocationSize, uint fileAttributes, uint shareAccess,
        uint createDisposition, uint createOptions, IntPtr eaBuffer, uint eaLength);

    internal static void Create(string parentDirectory, string leaf,
        Action<string, SafeFileHandle>? onCreated) =>
        CreateInternal(parentDirectory, leaf, IntPtr.Zero, onCreated);

    /// <summary>
    /// Create a PRIVATE root stage with its protected DACL as part of the SAME
    /// kernel FILE_CREATE operation. Never CreateDirectoryW then re-open by path:
    /// a same-user race could adopt someone else's substituted directory.
    /// securityDescriptor points to a caller-owned SD valid until return.
    /// </summary>
    internal static void CreateProtectedRoot(string parentDirectory, string leaf,
        IntPtr securityDescriptor, Action<string, SafeFileHandle> onCreated)
    {
        if (securityDescriptor == IntPtr.Zero)
            throw new InvalidDataException("Private stage root requires an explicit protected security descriptor.");
        ArgumentNullException.ThrowIfNull(onCreated);
        CreateInternal(parentDirectory, leaf, securityDescriptor, onCreated);
    }

    private static void CreateInternal(string parentDirectory, string leaf,
        IntPtr securityDescriptor, Action<string, SafeFileHandle>? onCreated)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Atomic stage child creation requires Windows.");
        if (string.IsNullOrEmpty(leaf) || leaf == "." || leaf == ".." ||
            leaf.IndexOfAny(['\\', '/', ':', '\0']) >= 0)
            throw new InvalidDataException("Invalid relative staged directory component.");
        string parentPath = Path.GetFullPath(parentDirectory);
        string childPath = Path.Combine(parentPath, leaf);
        using var parentPin = WindowsRestoreParentPin.Acquire(parentPath);
        parentPin.RequireMatches();
        // RootDirectory below must be an actual opened, non-reparse directory;
        // the complete ancestor chain is independently pinned above.
        using SafeFileHandle parent = CreateFile(WindowsNativePath.FromPath(parentPath),
            ReadAttributes | Traverse | AddSubdirectory, ShareRead | ShareWrite, IntPtr.Zero,
            OpenExisting, BackupSemantics | OpenReparsePoint, IntPtr.Zero);
        if (parent.IsInvalid)
            throw new IOException("Cannot open stage parent for atomic relative create.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        RequireOrdinaryDirectory(parent);
        parentPin.RequireMatches();
        IntPtr nameBuffer = IntPtr.Zero;
        IntPtr unicodeBuffer = IntPtr.Zero;
        try
        {
            int length = checked(leaf.Length * 2);
            if (length > ushort.MaxValue - 2)
                throw new InvalidDataException("Stage child component exceeds NT Unicode limit.");
            nameBuffer = Marshal.StringToHGlobalUni(leaf);
            var unicode = new UnicodeString
            {
                Length = (ushort)length,
                MaximumLength = (ushort)(length + 2),
                Buffer = nameBuffer
            };
            unicodeBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
            Marshal.StructureToPtr(unicode, unicodeBuffer, false);
            var objectAttributes = new ObjectAttributes
            {
                Length = (uint)Marshal.SizeOf<ObjectAttributes>(),
                RootDirectory = parent.DangerousGetHandle(),
                ObjectName = unicodeBuffer,
                Attributes = ObjectCaseInsensitive,
                SecurityDescriptor = securityDescriptor
            };
            // ListDirectory is intentionally requested (not attributes-only),
            // which enforces the absence of FILE_SHARE_DELETE while the creator
            // handle is held. READ_CONTROL permits querying the actual root DACL
            // from the SAME retained kernel handle before trusting the pathname.
            int status = NtCreateFile(out SafeFileHandle created,
                ListDirectory | ReadAttributes | ReadControl | Synchronize,
                ref objectAttributes, out IoStatusBlock iosb,
                IntPtr.Zero, (uint)FileAttributes.Directory, ShareRead | ShareWrite,
                FileCreate, FileDirectoryFile | FileSynchronousIoNonAlert,
                IntPtr.Zero, 0);
            if (status != 0)
            {
                created?.Dispose();
                throw new IOException("Atomic staged child creation rejected, NTSTATUS=0x" +
                    unchecked((uint)status).ToString("X8") + ".");
            }
            using (created)
            {
                if (created.IsInvalid || iosb.Information.ToInt64() != FileCreated)
                    throw new IOException("NT create did not return a new owned directory.");
                RequireOrdinaryDirectory(created);
                // The creator handle denies FILE_SHARE_DELETE. Until it closes,
                // nobody can rename the new child or swap its pathname, even if
                // another process runs with the SAME Windows account token.
                onCreated?.Invoke(childPath, created);
                parentPin.RequireMatches();
                RequireOrdinaryDirectory(created);
            }
        }
        finally
        {
            if (unicodeBuffer != IntPtr.Zero) Marshal.FreeHGlobal(unicodeBuffer);
            if (nameBuffer != IntPtr.Zero) Marshal.FreeHGlobal(nameBuffer);
        }
    }

    private static void RequireOrdinaryDirectory(SafeFileHandle handle)
    {
        if (!GetBasicInfo(handle, BasicInfoClass, out FileBasicInfo basic,
                (uint)Marshal.SizeOf<FileBasicInfo>()))
            throw new IOException("Cannot verify opened staged directory attributes.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        FileAttributes attributes = (FileAttributes)basic.FileAttributes;
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) !=
            FileAttributes.Directory)
            throw new IOException("Atomic staged directory must be real and not a reparse point.");
    }
}
