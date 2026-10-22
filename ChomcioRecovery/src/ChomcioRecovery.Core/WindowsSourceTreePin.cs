using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ChomcioRecovery.Core;

/// <summary>
/// Windows-only, fail-closed directory containment guard for a live file backup.
/// Pin every existing source ancestor and discovered source subdirectory with
/// NO FILE_SHARE_DELETE, BEFORE the first inventory or plaintext source read.
/// Opening with OPEN_REPARSE_POINT lets us inspect the actual directory handle
/// rather than traversing a substituted junction/symlink.
///
/// This is not a coherent filesystem snapshot. It cannot exclude writers with
/// pre-existing handles, changes to directory contents, or changes made before
/// handles were acquired. VSS/native Windows tests are still required.
/// </summary>
internal sealed class WindowsSourceTreePin : IDisposable
{
    // Avoid exhausting process/system handles on unexpectedly huge folder trees.
    // Refuse the backup rather than silently continuing without full coverage.
    private const int MaximumPinnedSubdirectories = 32_768;
    // Match the parent guard: attributes-only access cannot serve as a
    // rename exclusion primitive, including for an empty source directory.
    private const uint FileListDirectory = 0x01;
    private const uint FileReadAttributes = 0x80;
    private const uint FileShareRead = 0x01;
    private const uint FileShareWrite = 0x02;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;

    private WindowsRestoreParentPin? _ancestors;
    private readonly List<SafeFileHandle> _directories = new();
    // The first inventory is NOT necessarily the same tree that the earlier
    // directory-pin traversal encountered. Remember exactly WHICH directory
    // objects were actually pinned, not just which names appeared later.
    private readonly HashSet<string> _pinnedDirectoryNames =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly List<(string Path, WindowsSourceFileIdentity.Identity Identity)>
        _originalPinnedDirectories = new();

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
    private static extern SafeFileHandle CreateFile(string path, uint access, uint sharing,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,
        int informationClass, out FileBasicInfo fileInformation, uint bufferSize);

    private WindowsSourceTreePin() { }

    // A large source tree is scanned before the first inventory. Cancellation
    // must interrupt this Windows-only handle acquisition and close every
    // previously pinned handle. Optional callback is native-smoke-only.
    internal static WindowsSourceTreePin Acquire(string sourceRoot,
        CancellationToken cancellationToken = default, Action<int>? afterDiscoveredEntry = null,
        bool skipSystemDirectoryLinks = false)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var pin = new WindowsSourceTreePin();
        if (!OperatingSystem.IsWindows()) return pin;
        try
        {
            string root = Path.GetFullPath(sourceRoot);
            // Also pins the root itself, from volume root down. It cannot be
            // substituted while descendants are enumerated and pinned.
            pin._ancestors = WindowsRestoreParentPin.Acquire(root);
            pin._pinnedDirectoryNames.Add("d/.");
            var pending = new Stack<string>();
            pending.Push(root);
            int visitedEntries = 0;
            while (pending.Count != 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string folder = pending.Pop();
                foreach (string entry in Directory.EnumerateFileSystemEntries(folder))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    // This lookup is discovery only. The security decision for
                    // a directory is made from its OPENED HANDLE below.
                    FileAttributes attributes = File.GetAttributes(entry);
                    if(skipSystemDirectoryLinks&&LocalEncryptedVault.IsSystemDirectoryLink(attributes))
                    {
                        afterDiscoveredEntry?.Invoke(checked(++visitedEntries));
                        cancellationToken.ThrowIfCancellationRequested();
                        continue;
                    }
                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                        throw new IOException("Source contains an unsupported reparse point: " + entry);
                    if ((attributes & FileAttributes.Directory) == 0)
                    {
                        afterDiscoveredEntry?.Invoke(checked(++visitedEntries));
                        cancellationToken.ThrowIfCancellationRequested();
                        continue;
                    }
                    if (pin._directories.Count >= MaximumPinnedSubdirectories)
                        throw new IOException("Source has too many directories to pin safely.");
                    SafeFileHandle handle = CreateFile(WindowsNativePath.FromPath(entry), FileListDirectory | FileReadAttributes,
                        FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting,
                        FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
                    if (handle.IsInvalid)
                    {
                        int error = Marshal.GetLastWin32Error();
                        handle.Dispose();
                        throw new IOException("Cannot pin source subdirectory '" + entry +
                            "' (Win32 error " + error + ").", new Win32Exception(error));
                    }
                    // Take ownership BEFORE inspecting, so exceptional paths
                    // close this and all previously opened handles.
                    pin._directories.Add(handle);
                    if (!GetFileInformationByHandleEx(handle, 0, out FileBasicInfo info,
                            (uint)Marshal.SizeOf<FileBasicInfo>()))
                        throw new IOException("Cannot inspect pinned source directory: " + entry,
                            new Win32Exception(Marshal.GetLastWin32Error()));
                    var openedAttributes = (FileAttributes)info.FileAttributes;
                    if ((openedAttributes & FileAttributes.Directory) == 0 ||
                        (openedAttributes & FileAttributes.ReparsePoint) != 0)
                        throw new IOException("Source subdirectory was replaced before pin: " + entry);
                    // Bind the inventory to the real opened FileId, rather than
                    // adopting a later pathname's unrelated child directory.
                    var originalId = WindowsSourceFileIdentity.Capture(handle);
                    string relative = Path.GetRelativePath(root, entry).Replace('\\', '/');
                    if (!pin._pinnedDirectoryNames.Add("d/" + relative))
                        throw new IOException("Duplicate source directory during native pin traversal: " + entry);
                    pin._originalPinnedDirectories.Add((entry, originalId));
                    pending.Push(entry);
                    afterDiscoveredEntry?.Invoke(checked(++visitedEntries));
                    cancellationToken.ThrowIfCancellationRequested();
                }
            }
            cancellationToken.ThrowIfCancellationRequested();
            return pin;
        }
        catch
        {
            pin.Dispose();
            throw;
        }
    }

    /// <summary>
    /// A directory inserted after the native pin traversal is NOT pinned, even
    /// when the subsequent source inventory sees it. Never consume its files
    /// as a complete protected source tree. No catch-up pin is attempted:
    /// adding a late directory to the trusted set could adopt foreign contents.
    /// Reopen the already pinned children and compare their original 128-bit
    /// kernel identities, plus verify the pinned root's ancestor chain.
    /// This is still NOT atomic snapshot isolation against preopened writers.
    /// </summary>
    internal void RequireCoveredDirectoryInventory(IEnumerable<string> inventoryKeys,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows()) return;
        if (_ancestors is null || _pinnedDirectoryNames.Count != _originalPinnedDirectories.Count + 1 ||
            _directories.Count != _originalPinnedDirectories.Count)
            throw new IOException("Source tree does not have a complete original native directory pin.");
        _ancestors.RequireMatches();
        var observed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string key in inventoryKeys)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (key.StartsWith("d/", StringComparison.Ordinal) && !observed.Add(key))
                throw new IOException("Source directory inventory contains a case alias or duplicate.");
        }
        if (!observed.SetEquals(_pinnedDirectoryNames))
            throw new IOException("Source inventory contains an unpinned, missing or replaced directory.");
        foreach (var original in _originalPinnedDirectories)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using SafeFileHandle opened = CreateFile(WindowsNativePath.FromPath(original.Path), FileListDirectory | FileReadAttributes,
                FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting,
                FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
            if (opened.IsInvalid)
                throw new IOException("Originally pinned source directory is no longer accessible: " + original.Path);
            if (!GetFileInformationByHandleEx(opened, 0, out FileBasicInfo info,
                    (uint)Marshal.SizeOf<FileBasicInfo>()) ||
                ((FileAttributes)info.FileAttributes & (FileAttributes.Directory | FileAttributes.ReparsePoint))
                    != FileAttributes.Directory ||
                WindowsSourceFileIdentity.Capture(opened) != original.Identity)
                throw new IOException("Originally pinned source directory changed physical identity: " + original.Path);
        }
        _ancestors.RequireMatches();
        cancellationToken.ThrowIfCancellationRequested();
    }

    public void Dispose()
    {
        foreach (SafeFileHandle handle in _directories) handle.Dispose();
        _directories.Clear();
        _originalPinnedDirectories.Clear();
        _pinnedDirectoryNames.Clear();
        _ancestors?.Dispose();
        _ancestors = null;
    }
}
