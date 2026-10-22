using Microsoft.Win32.SafeHandles;

namespace ChomcioRecovery.Core;

/// <summary>
/// Best-effort, fail-closed disposal of ONLY the known original objects created
/// during a Windows directory restore. Their identities are captured at creation,
/// never inferred by recursively scanning a mutable staging pathname. Leaf
/// payload files are deleted with retained, no-delete-share Win32 handles;
/// empty owned child directories are disposed by verified directory handles,
/// deepest first. Any untracked/substituted child causes a retained private
/// stage rather than deletion of someone else's data.
///
/// New child directory FileIds are captured from original NtCreateFile
/// FILE_CREATE handles with no delete sharing, without a path-open adoption
/// gap. Power-loss durability and real NTFS behavior require native tests.
/// </summary>
internal sealed class WindowsOwnedRestoreTreeCleanup : IDisposable
{
    private readonly string _root;
    private readonly List<WindowsOwnedSingleStageFileCleanup> _files = new();
    // The set of names CREATED by the original writers. Correct FileIds for
    // known children are insufficient if an untracked file is added to stage.
    // Never learn ownership from the final directory enumeration.
    private readonly HashSet<string> _knownFilePaths = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<(string Path, WindowsPrivateRestoreStageGuard Guard)> _directories = new();
    // Every accepted child is bound to the ORIGINAL NT FILE_CREATE handle.
    // A later existing-by-name directory is not trusted merely because its
    // attributes look private. Reject substitutions and untracked children.
    private readonly Dictionary<string, WindowsPrivateRestoreStageGuard> _knownDirectoryGuards =
        new(StringComparer.OrdinalIgnoreCase);
    private bool _disposed;

    internal WindowsOwnedRestoreTreeCleanup(string privateStageRoot)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Owned restore-tree cleanup requires Windows.");
        _root = Path.GetFullPath(privateStageRoot);
    }

    private void RequireInsideRoot(string path)
    {
        string relative = Path.GetRelativePath(_root, Path.GetFullPath(path));
        if (relative == "." || relative == ".." || Path.IsPathRooted(relative) ||
            relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new IOException("Owned restore-tree entry escapes its private root.");
    }

    // Invoked before NtCreateFile's original no-delete-share handle closes.
    // Acquiring a guard by path alone used to be a TOCTOU ownership gap.
    internal void TrackNewDirectory(string path, SafeFileHandle originalCreator)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(WindowsOwnedRestoreTreeCleanup));
        RequireInsideRoot(path);
        string full = Path.GetFullPath(path);
        WindowsPrivateRestoreStageGuard guard =
            WindowsPrivateRestoreStageGuard.AcquireFromOriginalCreation(path, originalCreator);
        try
        {
            _knownDirectoryGuards.Add(full, guard);
            _directories.Add((full, guard));
        }
        catch
        {
            guard.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Pin the complete existing path against Windows rename and verify each
    /// staged descendant against its ORIGINAL creation-time FileId. A private
    /// ACL or Directory.Exists alone does not prove ownership: a same-account
    /// adversary may have replaced that pathname since directory creation.
    /// Keep this returned lease ALIVE throughout child creation or plaintext
    /// writing; no-delete-share directory handles block parent swaps while
    /// the file is created and flushed. NOT a defense against privileged
    /// pre-opened file writers or every post-release publication race.
    /// </summary>
    internal WindowsRestoreParentPin PinOwnedParentForWrite(
        string parentDirectory, WindowsPrivateRestoreStageGuard originalRoot)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(WindowsOwnedRestoreTreeCleanup));
        ArgumentNullException.ThrowIfNull(originalRoot);
        string parent = Path.GetFullPath(parentDirectory);
        string relative = Path.GetRelativePath(_root, parent);
        if (Path.IsPathRooted(relative) || relative == ".." ||
            relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new IOException("Stage writer parent escapes original private root.");

        // Acquire root-to-leaf with FILE_LIST_DIRECTORY and NO SHARE_DELETE,
        // THEN check against creation-pinned identities. The lease makes the
        // FileId checks stable until the caller closes its output file.
        WindowsRestoreParentPin lease = WindowsRestoreParentPin.Acquire(parent);
        try
        {
            lease.RequireMatches();
            originalRoot.RequireMatches(_root);
            if (relative == ".") return lease;
            string cursor = _root;
            foreach (string component in relative.Split(Path.DirectorySeparatorChar))
            {
                cursor = Path.Combine(cursor, component);
                if (!_knownDirectoryGuards.TryGetValue(cursor, out var owned))
                    throw new IOException("Untracked stage parent directory refuses plaintext write: " + cursor);
                owned.RequireMatches(cursor);
            }
            lease.RequireMatches();
            originalRoot.RequireMatches(_root);
            return lease;
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    // Capture identity directly from the still-open exclusive ORIGINAL writer.
    // Never adopt a file from its pathname after closing the writer.
    internal void TrackCreatedFile(string path, SafeFileHandle writer)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(WindowsOwnedRestoreTreeCleanup));
        RequireInsideRoot(path);
        string full = Path.GetFullPath(path);
        WindowsOwnedSingleStageFileCleanup original =
            WindowsOwnedSingleStageFileCleanup.CaptureCreatedFile(path, writer);
        if (!_knownFilePaths.Add(full))
            throw new IOException("A staged file name was registered twice: " + full);
        _files.Add(original);
    }

    /// <summary>
    /// Refuse publication if ANY extra child was introduced after the earlier
    /// content/inventory readback. The known original FileIds alone do not
    /// prove that a directory contains ONLY owned data; a late foreign file
    /// might otherwise be made visible without ever being authenticated.
    /// Enumerate only direct children of creation-tracked real directories,
    /// holding a no-delete-share parent pin while each directory is inspected.
    /// Never adopt an unknown file by enumeration; fail closed and preserve it.
    /// This is an additional late precommit check, NOT an atomic NTFS tree
    /// snapshot: preopened writers and a later insertion still need native
    /// adversarial validation before any beta can be qualified.
    /// </summary>
    private void RequireOnlyOriginalNamedEntries(
        WindowsPrivateRestoreStageGuard originalRoot)
    {
        var expected = new HashSet<string>(_knownFilePaths, StringComparer.OrdinalIgnoreCase);
        expected.UnionWith(_knownDirectoryGuards.Keys);
        var observed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pending = new Stack<string>();
        pending.Push(_root);
        while (pending.Count > 0)
        {
            string parent = pending.Pop();
            // Prevent renames of the inspected ancestor while enumerating.
            using var pinned = WindowsRestoreParentPin.Acquire(parent);
            pinned.RequireMatches();
            originalRoot.RequireMatches(_root);
            if (!string.Equals(parent, _root, StringComparison.OrdinalIgnoreCase))
            {
                if (!_knownDirectoryGuards.TryGetValue(parent, out var originalDirectory))
                    throw new IOException("Untracked staged directory: " + parent);
                originalDirectory.RequireMatches(parent);
            }
            foreach (string entry in Directory.EnumerateFileSystemEntries(parent))
            {
                string full = Path.GetFullPath(entry);
                // No recursive traversal into a name until its owner-tracked
                // directory identity is independently verified.
                RequireInsideRoot(full);
                if (!expected.Contains(full) || !observed.Add(full))
                    throw new IOException("Foreign or duplicate staged entry prevents publication: " + full);
                FileAttributes attributes = File.GetAttributes(full);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Reparse point in original staged inventory: " + full);
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    if (!_knownDirectoryGuards.TryGetValue(full, out var originalDirectory))
                        throw new IOException("Untracked staged child directory: " + full);
                    originalDirectory.RequireMatches(full);
                    pending.Push(full);
                }
                else if (!_knownFilePaths.Contains(full))
                    throw new IOException("Untracked staged file: " + full);
            }
            pinned.RequireMatches();
            originalRoot.RequireMatches(_root);
        }
        if (!observed.SetEquals(expected))
            throw new IOException("Original staged inventory has missing or untracked entries.");
    }

    /// <summary>
    /// A checksum alone does not establish who CREATED the staged file. All
    /// original descendant FILE_ID_INFO identities must still be present at
    /// the names that will become visible through directory publication.
    /// Also reject replacement of any recorded child directory. A race after
    /// release is explicitly NOT closed by these per-object checks, so native
    /// NTFS race tests remain a mandatory beta gate.
    /// </summary>
    internal void RequireOriginalInventoryForPublication(
        WindowsPrivateRestoreStageGuard originalRoot)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(WindowsOwnedRestoreTreeCleanup));
        ArgumentNullException.ThrowIfNull(originalRoot);
        originalRoot.RequireMatches(_root);
        // A correct list of original FileIds is not the same as a complete
        // list of children. An attacker may inject a NEW name, not replace one.
        RequireOnlyOriginalNamedEntries(originalRoot);
        foreach (var child in _directories)
            child.Guard.RequireMatches(child.Path);
        foreach (var file in _files)
            file.RequireOriginalPresentForPublication(originalRoot, _root);
        // Recheck names and originals after the complete inventory, not only
        // before it. Still non-atomic relative to final handle-bound rename.
        RequireOnlyOriginalNamedEntries(originalRoot);
        foreach (var child in _directories)
            child.Guard.RequireMatches(child.Path);
        originalRoot.RequireMatches(_root);
    }

    /// <summary>
    /// Re-attest the PHYSICAL original creator identities at the FINAL visible
    /// tree paths, after the native root-directory rename. A foreign ordinary
    /// file with byte-for-byte identical restored contents must not be accepted
    /// as our published original merely because a SHA-256 readback succeeds.
    /// Also reject late untracked published children. No deletion on failure.
    /// This cannot make a mutable NTFS tree atomic against preopened writers.
    /// </summary>
    internal void RequireOriginalPublishedInventory(string publishedRoot,
        WindowsPrivateRestoreStageGuard originalRoot,
        CancellationToken cancellationToken = default)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(WindowsOwnedRestoreTreeCleanup));
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Published tree FileId attestation requires Windows.");
        ArgumentNullException.ThrowIfNull(originalRoot);
        cancellationToken.ThrowIfCancellationRequested();
        string finalRoot = Path.GetFullPath(publishedRoot);
        string Project(string originalPath)
        {
            RequireInsideRoot(originalPath);
            string relative = Path.GetRelativePath(_root, Path.GetFullPath(originalPath));
            if (relative == "." || relative == ".." || Path.IsPathRooted(relative) ||
                relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                throw new IOException("Original staged child escapes its creator root.");
            return Path.GetFullPath(Path.Combine(finalRoot, relative));
        }
        var files = new Dictionary<string, WindowsOwnedSingleStageFileCleanup>(StringComparer.OrdinalIgnoreCase);
        foreach (var original in _files)
            files.Add(Project(original.OriginalPath), original);
        var directories = new Dictionary<string, WindowsPrivateRestoreStageGuard>(StringComparer.OrdinalIgnoreCase);
        foreach (var original in _directories)
            directories.Add(Project(original.Path), original.Guard);
        var expected = new HashSet<string>(files.Keys, StringComparer.OrdinalIgnoreCase);
        expected.UnionWith(directories.Keys);
        var observed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using var pinnedFinalRoot = WindowsRestoreParentPin.Acquire(finalRoot);
        pinnedFinalRoot.RequireMatches();
        originalRoot.RequireOriginalPublishedIdentity(finalRoot);
        var pending = new Stack<string>();
        pending.Push(finalRoot);
        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string folder = pending.Pop();
            using var pinnedFolder = WindowsRestoreParentPin.Acquire(folder);
            pinnedFolder.RequireMatches();
            if (!string.Equals(folder, finalRoot, StringComparison.OrdinalIgnoreCase))
            {
                if (!directories.TryGetValue(folder, out var originalDirectory))
                    throw new IOException("Untracked published restore directory: " + folder);
                originalDirectory.RequireOriginalPublishedIdentity(folder);
            }
            foreach (string child in Directory.EnumerateFileSystemEntries(folder))
            {
                cancellationToken.ThrowIfCancellationRequested();
                string path = Path.GetFullPath(child);
                string relative = Path.GetRelativePath(finalRoot, path);
                if (Path.IsPathRooted(relative) || relative is "." or ".." ||
                    relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
                    !expected.Contains(path) || !observed.Add(path))
                    throw new IOException("Unexpected or duplicate visible restore child: " + path);
                FileAttributes attributes = File.GetAttributes(path);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Published restore contains an unexpected reparse point: " + path);
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    if (!directories.TryGetValue(path, out var originalDirectory))
                        throw new IOException("Published restore contains a foreign directory: " + path);
                    originalDirectory.RequireOriginalPublishedIdentity(path);
                    pending.Push(path);
                }
                else
                {
                    if (!files.TryGetValue(path, out var originalFile))
                        throw new IOException("Published restore contains a foreign file: " + path);
                    originalFile.RequireOriginalPublishedIdentity(path);
                }
            }
            pinnedFolder.RequireMatches();
        }
        if (!observed.SetEquals(expected))
            throw new IOException("Published restore inventory differs from original creator-tracked names.");
        // Re-attest each original FILE_OBJECT after the full walk; keeping the
        // final root pin prevents ordinary ancestor renames during the check.
        foreach (var item in directories)
        {
            cancellationToken.ThrowIfCancellationRequested();
            item.Value.RequireOriginalPublishedIdentity(item.Key);
        }
        foreach (var item in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            item.Value.RequireOriginalPublishedIdentity(item.Key);
        }
        originalRoot.RequireOriginalPublishedIdentity(finalRoot);
        pinnedFinalRoot.RequireMatches();
        cancellationToken.ThrowIfCancellationRequested();
    }

    /// <summary>
    /// Retain read-data handles for EVERY original staged file from final
    /// authenticated verification through the native root-directory rename.
    /// FILE_SHARE_WRITE is forbidden: a preexisting ordinary writer makes
    /// acquisition fail; a future ordinary write open is denied while leased.
    /// FILE_SHARE_DELETE is allowed because a root directory containing open
    /// leaf handles still needs to be renamed. Native NTFS must verify that
    /// sharing choice permits the real directory rename. Names can still be
    /// swapped via delete-sharing, so the complete inventory is checked again
    /// after the handles are all acquired; do NOT claim an atomic NTFS tree.
    /// </summary>
    internal IDisposable AcquireImmutableContentLeases(
        WindowsPrivateRestoreStageGuard originalRoot)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(WindowsOwnedRestoreTreeCleanup));
        ArgumentNullException.ThrowIfNull(originalRoot);
        var leased = new List<SafeFileHandle>();
        try
        {
            RequireOriginalInventoryForPublication(originalRoot);
            foreach (var originalFile in _files)
                leased.Add(originalFile.OpenWriteExcludingPublicationLease());
            // Re-check original paths and unexpected added entries after the
            // last leaf opened. Keep every read lease until publication ends.
            RequireOriginalInventoryForPublication(originalRoot);
            return new ImmutableContentLeases(leased);
        }
        catch
        {
            for (int i = leased.Count - 1; i >= 0; --i) leased[i].Dispose();
            throw;
        }
    }

    private sealed class ImmutableContentLeases : IDisposable
    {
        private List<SafeFileHandle>? _handles;
        internal ImmutableContentLeases(List<SafeFileHandle> handles) => _handles = handles;
        public void Dispose()
        {
            var handles = _handles;
            _handles = null;
            if (handles is null) return;
            for (int i = handles.Count - 1; i >= 0; --i) handles[i].Dispose();
            handles.Clear();
        }
    }

    internal bool TryCleanup(WindowsPrivateRestoreStageGuard originalRoot)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(WindowsOwnedRestoreTreeCleanup));
        ArgumentNullException.ThrowIfNull(originalRoot);
        originalRoot.RequireMatches(_root);
        // A single swapped-in FOREIGN leaf used to abort this loop and strand
        // ALL other ORIGINAL plaintext leaves. Continue disposing independently
        // verified ORIGINAL FileIds. Each helper opens nofollow, locks its own
        // parent and deletes through that exact retained file handle only.
        // Failure is still reported: never claim a clean cancellation while an
        // untracked or substituted entry may remain in the private stage.
        var failures = new List<IOException>();
        foreach (WindowsOwnedSingleStageFileCleanup file in _files.AsEnumerable().Reverse())
        {
            try
            {
                file.TryDeleteOriginal(originalRoot, _root);
            }
            catch (IOException error)
            {
                failures.Add(error);
            }
        }
        // Children precede parents. Continue independent EMPTY-original-dir
        // attempts even if one child contains foreign data. Never recurse by
        // name, adopt an unknown entry or weaken original FileId comparison.
        bool complete = failures.Count == 0;
        for (int i = _directories.Count - 1; i >= 0; --i)
        {
            var child = _directories[i];
            try
            {
                if (!child.Guard.TryDeleteOriginalEmptyStage(child.Path))
                    complete = false;
            }
            catch (IOException error)
            {
                failures.Add(error);
                complete = false;
            }
            finally
            {
                child.Guard.Dispose();
            }
        }
        _directories.Clear();
        _knownDirectoryGuards.Clear();
        _knownFilePaths.Clear();
        originalRoot.RequireMatches(_root);
        // Preserve the historical native MustFail gate on FOREIGN replacement;
        // aggregating AFTER independent safe cleanup avoids leaving unrelated
        // owned plaintext behind just because the first name was substituted.
        if (failures.Count > 0)
            throw new IOException("Owned stage cleanup incomplete; foreign/unavailable entries preserved.",
                new AggregateException(failures));
        return originalRoot.TryDeleteOriginalEmptyStage(_root) && complete;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        foreach (var child in _directories) child.Guard.Dispose();
        _directories.Clear();
        _knownDirectoryGuards.Clear();
        _knownFilePaths.Clear();
    }
}
