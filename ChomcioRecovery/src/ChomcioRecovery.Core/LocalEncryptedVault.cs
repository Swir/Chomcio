using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

[assembly: InternalsVisibleTo("ChomcioRecovery.Core.Smoke")]

namespace ChomcioRecovery.Core;

/// <summary>
/// Local v1 prototype. Immutable encrypted chunks and encrypted snapshots;
/// never uploads data or changes a system partition. Not a system image tool.
/// </summary>
public sealed partial class LocalEncryptedVault : IDisposable
{
    public const int ChunkBytes = 4 * 1024 * 1024;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private const int HeaderBytes = 8 + NonceBytes + TagBytes;
    private const int MaxManifestBytes = 64 * 1024 * 1024;
    private const int Iterations = 310_000;
    private static readonly byte[] ObjectMagic = "CHMOBJ01"u8.ToArray();
    private static readonly byte[] SnapshotMagic = "CHMSNAP1"u8.ToArray();
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private readonly string _root;
    private readonly byte[] _key;
    // Hash of the EXACT repository configuration authenticated at unlock time.
    // A changed salt (even with an unchanged verifier) can make backups unrecoverable.
    private readonly byte[] _openedConfigFingerprint;
    private bool _disposed;

    private sealed record RepositoryConfig(string Format, string Salt, int Iterations, string Verifier);
    public sealed record FileEntry(string Path, long Size, string Sha256, List<string> Chunks,
        [property: System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
        string? ZoneIdentifierBase64=null);
    // v2 preserves empty directories; the optional fourth argument reads v1 manifests.
    // v1 blobs/AAD remain unchanged for backwards-compatible restore/export.
    public sealed record Snapshot(int Version, DateTimeOffset CreatedUtc, List<FileEntry> Files,
        List<string>? Directories = null, List<string>? SkippedSystemDirectoryLinks = null);
    public sealed record BackupResult(string SnapshotId, int Files, long TotalBytes, int NewChunks, int ReusedChunks);
    // A live-folder consistency guard; not a replacement for a VSS volume snapshot.
    internal sealed record SourceStamp(bool Directory, long Length, DateTime LastWriteUtc,
        DateTime CreationUtc, FileAttributes Attributes,
        WindowsSourceFileIdentity.Identity? FileIdentity = null,string? ZoneIdentifierSha256=null);

    private LocalEncryptedVault(string root, byte[] key, byte[] openedConfigFingerprint)
    {
        _root = root;
        _key = key;
        _openedConfigFingerprint = (byte[])openedConfigFingerprint.Clone();
    }

    public static void Initialize(string repositoryPath, string password) =>
        InitializeCore(repositoryPath, password, afterConfigPublished: null);

    // Fault-injection hook for the native disposable-vault smoke test only.
    // Public initialization never accepts a callback from untrusted input.
    internal static void InitializeCore(string repositoryPath, string password,
        Action<string>? afterConfigPublished)
    {
        if (password.Length < 12)
            throw new ArgumentException("Use a password with at least 12 characters.");
        string root = Path.GetFullPath(repositoryPath);
        if (File.Exists(root) || (Directory.Exists(root) && Directory.EnumerateFileSystemEntries(root).Any()))
            throw new IOException("New repository location must be empty.");
        EnsureNoReparsePointsInPath(root);
        Directory.CreateDirectory(root);
        Directory.CreateDirectory(Path.Combine(root, "objects"));
        Directory.CreateDirectory(Path.Combine(root, "snapshots"));
        byte[] salt = RandomNumberGenerator.GetBytes(32);
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);
        try
        {
            byte[] verifier = HMACSHA256.HashData(key, "ChomcioRecovery/key-check/v1"u8);
            var cfg = new RepositoryConfig("chomcio-local-v1", Convert.ToBase64String(salt),
                Iterations, Convert.ToBase64String(verifier));
            // Only an independently re-opened, authenticated repository counts
            // as initialized. A changed repo.json after the TEMP readback can
            // make every future snapshot unusable, or silently replace the
            // intended salt/key lineage with another valid repository.
            byte[] intendedConfig = JsonSerializer.SerializeToUtf8Bytes(cfg, JsonOptions);
            string configPath = Path.Combine(root, "repo.json");
            try
            {
                WriteAtomic(configPath, intendedConfig);
                afterConfigPublished?.Invoke(configPath); // native smoke only
                byte[] published = ReadBoundedFile(configPath, intendedConfig.Length);
                try
                {
                    if (!CryptographicOperations.FixedTimeEquals(published, intendedConfig))
                        throw new IOException("Newly published repository config changed; initialization refused.");
                }
                finally { CryptographicOperations.ZeroMemory(published); }
                // Re-derive the key FROM THE ACTUAL FINAL FILE and check the
                // complete layout. This is a finite readback, not an atomic
                // defense against later concurrent filesystem modifications.
                using var reopened = Open(root, password);
                reopened.EnsureCapturedConfigMatchesUnlock(intendedConfig);
            }
            finally { CryptographicOperations.ZeroMemory(intendedConfig); }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(salt);
        }
    }

    public static LocalEncryptedVault Open(string repositoryPath, string password)
    {
        string root = Path.GetFullPath(repositoryPath);
        EnsureNoReparsePointsInPath(root);
        string configPath = Path.Combine(root, "repo.json");
        if (!File.Exists(configPath))
            throw new InvalidDataException("Missing repository configuration.");
        EnsureNoReparsePoint(configPath);
        if (new FileInfo(configPath).Length > 16_384)
            throw new InvalidDataException("Missing or invalid repository configuration.");
        // Pin the precise bytes used to derive the unlocked key, rather than
        // trusting a second read of a potentially replaced config file.
        byte[] configBytes = ReadBoundedFile(configPath, 16_384);
        var cfg = JsonSerializer.Deserialize<RepositoryConfig>(configBytes)
                  ?? throw new InvalidDataException("Empty configuration.");
        if (cfg.Format != "chomcio-local-v1" || cfg.Iterations != Iterations)
            throw new InvalidDataException("Unknown or unsupported repository format.");
        byte[] salt = Convert.FromBase64String(cfg.Salt);
        byte[] expected = Convert.FromBase64String(cfg.Verifier);
        if (salt.Length != 32 || expected.Length != 32)
            throw new InvalidDataException("Invalid repository configuration fields.");
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);
        byte[] actual = HMACSHA256.HashData(key, "ChomcioRecovery/key-check/v1"u8);
        bool correct = CryptographicOperations.FixedTimeEquals(expected, actual);
        CryptographicOperations.ZeroMemory(actual);
        CryptographicOperations.ZeroMemory(salt);
        if (!correct)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new CryptographicException("Wrong password or modified repository configuration.");
        }
        // Storage directories must be real directories, not junctions pointing
        // outside the encrypted repository. Re-check on every operation too.
        var vault = new LocalEncryptedVault(root, key, SHA256.HashData(configBytes));
        try { vault.EnsureRepositoryLayoutSafe(); }
        catch { vault.Dispose(); throw; }
        return vault;
    }

    private void EnsureRepositoryLayoutSafe()
    {
        EnsureRepositoryConfigUnchanged();
        EnsureNoReparsePointsInPath(_root);
        foreach (string folder in new[] { "objects", "snapshots" })
        {
            string path = Path.Combine(_root, folder);
            EnsureNoReparsePointsInPath(path);
            if (!Directory.Exists(path))
                throw new IOException("Repository storage directory is missing: " + path);
        }
    }

    /// <summary>
    /// Fail closed if repo.json changes after unlock, including salt-only edits
    /// which would make the newly written recovery point impossible to reopen.
    /// This path-based check does NOT guarantee protection against hostile
    /// concurrent renames; Windows handle/ACL locking is still outstanding.
    /// </summary>
    internal void EnsureRepositoryConfigUnchanged()
    {
        CheckNotDisposed();
        EnsureNoReparsePointsInPath(_root);
        string path = Path.Combine(_root, "repo.json");
        EnsureNoReparsePoint(path);
        var info = new FileInfo(path);
        if (info.Length > 16_384)
            throw new InvalidDataException("Repository configuration changed after unlock.");
        byte[] currentHash = SHA256.HashData(ReadBoundedFile(path, 16_384));
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(currentHash, _openedConfigFingerprint))
                throw new InvalidDataException("Repository configuration changed after unlock; operation refused.");
        }
        finally { CryptographicOperations.ZeroMemory(currentHash); }
    }

    /// <summary>
    /// Authenticate the EXACT configuration byte array captured for an export or
    /// import. Checking repo.json only later is insufficient: a temporary
    /// salt-only swap can be reverted before the final filesystem re-read,
    /// leaving a published portable vault that its original password cannot open.
    /// </summary>
    internal void EnsureCapturedConfigMatchesUnlock(byte[] capturedConfigBytes)
    {
        CheckNotDisposed();
        ArgumentNullException.ThrowIfNull(capturedConfigBytes);
        if (capturedConfigBytes.Length > 16_384)
            throw new InvalidDataException("Captured repository config exceeds maximum size.");
        byte[] fingerprint = SHA256.HashData(capturedConfigBytes);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(fingerprint, _openedConfigFingerprint))
                throw new InvalidDataException("Captured repository config does not match unlock-time bytes.");
        }
        finally { CryptographicOperations.ZeroMemory(fingerprint); }
    }

    public BackupResult BackupDirectory(string sourceDirectory, CancellationToken cancellationToken = default,
        bool skipSystemDirectoryLinks = false,bool preserveZoneIdentifiers=false)
        => BackupDirectory(sourceDirectory,cancellationToken,skipSystemDirectoryLinks,preserveZoneIdentifiers,null);

    public BackupResult BackupDirectory(string sourceDirectory, CancellationToken cancellationToken,
        bool skipSystemDirectoryLinks,bool preserveZoneIdentifiers,IProgress<VaultProgress>? progress)
    {
        CheckNotDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        EnsureRepositoryLayoutSafe();
        string source = Path.GetFullPath(sourceDirectory);
        if (!Directory.Exists(source))
            throw new DirectoryNotFoundException(source);
        EnsureNoReparsePointsInPath(source);
        EnsureRepositoryPathDisjoint(_root, source);
        // Pin the complete existing source directory tree before the first
        // inventory: otherwise a renamed parent replaced with a junction can
        // redirect a later file open despite leaf-only no-follow and file IDs.
        // Hold every handle through verification and final manifest publish.
        using var pinnedSourceTree = WindowsSourceTreePin.Acquire(source, cancellationToken,
            skipSystemDirectoryLinks: skipSystemDirectoryLinks);

        List<FileEntry> entries = new();
        long total = 0;
        int created = 0, reused = 0;
        cancellationToken.ThrowIfCancellationRequested();
        var initialInventory = CaptureSourceInventory(source, cancellationToken,
            skipSystemDirectoryLinks: skipSystemDirectoryLinks,preserveZoneIdentifiers:preserveZoneIdentifiers);
        // The native preflight pinned ONLY directories present at pin-time. If
        // a new subtree arrived during its traversal, the following inventory
        // must not silently ingest files below that unpinned directory.
        // Refuse BEFORE encrypting any plaintext into orphan objects.
        pinnedSourceTree.RequireCoveredDirectoryInventory(initialInventory.Keys, cancellationToken);
        var paths = initialInventory.Keys.Where(x => x.StartsWith("f/", StringComparison.Ordinal))
            .Select(x => Path.Combine(source, x[2..].Replace('/', Path.DirectorySeparatorChar)))
            .OrderBy(x => x, StringComparer.Ordinal).ToArray();
        var preparationProgress=new VaultProgressReporter(progress,VaultProgressStage.Encrypting,
            progress is null?0:initialInventory.Where(x=>x.Key.StartsWith("f/",StringComparison.Ordinal)).Sum(x=>x.Value.Length));
        foreach (string path in paths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Never ingest a newly substituted symlink or silently drop NTFS ADS.
            EnsureNoReparsePoint(path);
            string? zone=null;
            if(preserveZoneIdentifiers)zone=WindowsZoneIdentifier.Read(path,cancellationToken);
            else WindowsAlternateStreamGuard.RejectUnsupportedStreams(path);
            WindowsHardLinkGuard.RejectMultipleLinks(path);
            FileInfo before = new(path);
            WindowsUnsupportedMetadataGuard.RejectUnsupported(before.Attributes, path);
            long originalLength = before.Length;
            DateTime originalWriteTime = before.LastWriteTimeUtc;
            FileAttributes originalAttributes = before.Attributes;
            string relative = Path.GetRelativePath(source, path).Replace('\\', '/');
            ValidateRelativePath(relative);
            if (!initialInventory.TryGetValue("f/" + relative, out SourceStamp? initialFile) ||
                initialFile.Directory)
                throw new IOException("Source file absent from initial inventory: " + relative);
            List<string> chunks = new();
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using var stream = WindowsNoFollowSourceReader.Open(path);
            // Match the INITIAL inventory handle, not a fresh path stat made
            // immediately before this open. Reject a swapped ordinary file
            // before it contributes even one byte to an encrypted object.
            WindowsSourceFileIdentity.RequireMatches(stream, initialFile.FileIdentity, path);
            if(WindowsZoneIdentifier.Fingerprint(zone)!=initialFile.ZoneIdentifierSha256)
                throw new IOException("Source Zone.Identifier changed since initial inventory.");
            byte[] buffer = new byte[ChunkBytes];
            long size = 0;
            try
            {
                int count;
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    count = ReadChunk(stream, buffer, cancellationToken);
                    if (count <= 0) break;
                    byte[] data = buffer.AsSpan(0, count).ToArray();
                    try
                    {
                        sha.AppendData(data);
                        string id = Convert.ToHexString(HMACSHA256.HashData(_key, data)).ToLowerInvariant();
                        string objectPath = GetObjectPath(id);
                        if (File.Exists(objectPath))
                        {
                            // Existing data are verified, never blindly trusted.
                            byte[] existing = ReadChunkAndValidate(id, cancellationToken);
                            try
                            {
                                if (!existing.AsSpan().SequenceEqual(data))
                                    throw new InvalidDataException("Existing encrypted chunk differs from source.");
                            }
                            finally { CryptographicOperations.ZeroMemory(existing); }
                            reused++;
                        }
                        else
                        {
                            byte[] encrypted = Encrypt(data, ObjectMagic, ObjectAad(id));
                            Directory.CreateDirectory(Path.GetDirectoryName(objectPath)!);
                            // Do not follow a replaced object-prefix junction/symlink.
                            EnsureNoReparsePointsInPath(Path.GetDirectoryName(objectPath)!);
                            try { WriteAtomic(objectPath, encrypted, cancellationToken: cancellationToken); created++; }
                            catch (IOException) when (File.Exists(objectPath))
                            {
                                byte[] existing = ReadChunkAndValidate(id, cancellationToken);
                                try
                                {
                                    if (!existing.AsSpan().SequenceEqual(data))
                                        throw new InvalidDataException("Conflicting chunk written concurrently.");
                                }
                                finally { CryptographicOperations.ZeroMemory(existing); }
                                reused++;
                            }
                        }
                        chunks.Add(id);
                        size += count;
                        preparationProgress.Advance(count);
                    }
                    finally { CryptographicOperations.ZeroMemory(data); }
                }
            }
            finally { CryptographicOperations.ZeroMemory(buffer); }
            before.Refresh();
            WindowsUnsupportedMetadataGuard.RejectUnsupported(before.Attributes, path);
            if (originalLength != size || before.Length != size ||
                originalWriteTime != before.LastWriteTimeUtc ||
                originalAttributes != before.Attributes)
                throw new IOException("Source file changed during backup: " + relative);
            // First stat must be checked against the opened file's final metadata too.
            string fileSha = Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
            entries.Add(new FileEntry(relative, size, fileSha, chunks,zone));
            total += size;
        }
        ValidateEntries(entries);
        var directories = initialInventory.Keys
            .Where(name => name.StartsWith("d/", StringComparison.Ordinal) && name != "d/.")
            .Select(name => name[2..]).OrderBy(name => name, StringComparer.Ordinal).ToList();
        ValidateDirectoryTree(entries, directories, version: 2);
        // Detect late additions, deletions and modifications to files already read.
        // This is best-effort on a live tree: VSS + handle identity are still needed.
        ThrowIfSourceInventoryChanged(source, initialInventory, cancellationToken,
            skipSystemDirectoryLinks: skipSystemDirectoryLinks,preserveZoneIdentifiers:preserveZoneIdentifiers);
        // Recheck root/subdirectory FILE_OBJECT ownership while original pin
        // handles are still live, before making a manifest visible.
        pinnedSourceTree.RequireCoveredDirectoryInventory(initialInventory.Keys, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        string snapshotId = Guid.NewGuid().ToString("N");
        var skippedLinks=initialInventory.Keys.Where(k=>k.StartsWith("s/",StringComparison.Ordinal))
            .Select(k=>k[2..]).OrderBy(k=>k,StringComparer.Ordinal).ToList();
        var snapshot = new Snapshot(entries.Any(f=>f.ZoneIdentifierBase64 is not null)?3:2, DateTimeOffset.UtcNow, entries, directories,
            skippedLinks.Count==0?null:skippedLinks);
        // No recovery point may become visible until its encrypted chunks have
        // been read back, authenticated and re-hashed as full restored files.
        // Repeat the source inventory check AFTER verification as it can take time.
        int sourcePass=0;
        PublishVerifiedSnapshot(snapshotId, snapshot,
            () => VerifySourceContents(source, entries, initialInventory, cancellationToken, skipSystemDirectoryLinks,preserveZoneIdentifiers,
                progress,++sourcePass==1?VaultProgressStage.CheckingSource:VaultProgressStage.CheckingSourceAfterPublish),
            cancellationToken: cancellationToken,progress:progress);
        return new BackupResult(snapshotId, entries.Count, total, created, reused);
    }

    /// <summary>
    /// Final fail-closed manifest commit for a live-source backup. This is a
    /// read-after-write check, not a durability guarantee (power loss) and not
    /// a substitute for VSS/open-handle snapshot isolation. No manifest file
    /// is created if a stored chunk or the source-inventory guard fails.
    /// The callback is executed after read-back and immediately before commit.
    /// </summary>
    internal void PublishVerifiedSnapshot(string snapshotId, Snapshot snapshot, Action preCommitCheck,
        Action<string>? afterPublished = null, CancellationToken cancellationToken = default,IProgress<VaultProgress>? progress=null)
    {
        CheckNotDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        ValidateSnapshotId(snapshotId);
        ArgumentNullException.ThrowIfNull(preCommitCheck);
        if (snapshot.Version is not (2 or 3) || snapshot.Files is null)
            throw new InvalidDataException("Only complete v2 snapshots can be published.");
        ValidateEntries(snapshot.Files);
        ValidateDirectoryTree(snapshot.Files, snapshot.Directories, snapshot.Version);
        ValidateSkippedSystemDirectoryLinks(snapshot);
        ValidateZoneIdentifierVersion(snapshot);
        byte[] serialized = JsonSerializer.SerializeToUtf8Bytes(snapshot, JsonOptions);
        try
        {
            if (serialized.Length > MaxManifestBytes)
                throw new IOException("Snapshot metadata too large.");
            VerifySnapshotContents(snapshot, cancellationToken,progress,VaultProgressStage.CheckingStoredData);  // Re-read STORED ciphertext, not source buffers.
            preCommitCheck();                  // Source still unchanged after the reread?
            EnsureRepositoryConfigUnchanged(); // Same key lineage as at unlock?
            cancellationToken.ThrowIfCancellationRequested();
            byte[] encryptedManifest = Encrypt(serialized, SnapshotMagic, SnapshotAad(snapshotId));
            // A successful TEMP-file readback does not prove that the bytes at
            // the FINAL snapshot pathname are still the same after the rename.
            // Never report a successful backup unless that published record
            // survives an independent no-follow, bounded read from its FINAL name.
            cancellationToken.ThrowIfCancellationRequested();
            WriteAtomicAndVerifyPublished(GetSnapshotPath(snapshotId), encryptedManifest,
                afterPublished, cancellationToken);
            // Final-path manifest readback is NOT enough: a referenced chunk
            // could be damaged after the pre-commit readback but before the
            // manifest becomes visible. Refuse to report a successful backup
            // until the COMMITTED snapshot and every stored dependency have
            // been read and authenticated through their final paths.
            // This is a bounded-window check, NOT atomic filesystem isolation;
            // a later adversarial mutation or power loss remains possible.
            // The final committed-dependency walk may scan gigabytes.  STOP
            // must propagate beyond the record publication/readback instead
            // of silently continuing a full uncancellable verification.
            // Cancellation AFTER publication leaves a committed recovery point
            // for explicit inspection; never delete a possibly shared name.
            VerifySnapshotWithProgress(snapshotId,cancellationToken,progress,VaultProgressStage.CheckingPublishedData);
            // A successful committed-manifest and ciphertext verification is
            // NOT proof that the live source remained unchanged. The source
            // can be rewritten while the encrypted snapshot is being published
            // or while the final dependency audit scans a large repository.
            // Re-run the caller's exact full-content/inventory attestation
            // AFTER publication, before reporting backup success. Any failure
            // is fail-closed for the API result, NOT a rollback: a committed
            // recovery point may still exist and must never be deleted by a
            // mutable pathname in response to post-commit validation failure.
            cancellationToken.ThrowIfCancellationRequested();
            preCommitCheck();
            cancellationToken.ThrowIfCancellationRequested();
            EnsureRepositoryConfigUnchanged();
        }
        finally { CryptographicOperations.ZeroMemory(serialized); }
    }

    public IReadOnlyList<string> ListSnapshotIds()
    {
        CheckNotDisposed();
        EnsureRepositoryConfigUnchanged();
        string dir = Path.Combine(_root, "snapshots");
        EnsureNoReparsePointsInPath(dir);
        var result = Directory.EnumerateFiles(dir, "*.snap", SearchOption.TopDirectoryOnly)
            .Select(Path.GetFileNameWithoutExtension)
            .Where(id => id is not null && IsValidId(id))
            .Select(id => id!).OrderByDescending(id => id, StringComparer.Ordinal).ToList();
        EnsureRepositoryConfigUnchanged();
        return result;
    }

    public Snapshot ReadSnapshot(string snapshotId) =>
        ReadSnapshotCore(snapshotId, CancellationToken.None);

    // STOP also interrupts an up-to-64 MiB encrypted manifest read before JSON
    // parsing and before any restore/export/import makes visible changes.
    public Snapshot ReadSnapshot(string snapshotId, CancellationToken cancellationToken) =>
        ReadSnapshotCore(snapshotId, cancellationToken);

    // Observer exists ONLY for deterministic native disposable-vault smoke;
    // public APIs cannot run code while a repository record is being read.
    internal Snapshot ReadSnapshotCore(string snapshotId, CancellationToken cancellationToken,
        Action<int>? afterManifestReadBlock = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        CheckNotDisposed();
        // Never claim an opened vault is readable after repo.json lineage changes.
        EnsureRepositoryConfigUnchanged();
        ValidateSnapshotId(snapshotId);
        string path = GetSnapshotPath(snapshotId);
        EnsureNoReparsePointsInPath(Path.GetDirectoryName(path)!);
        EnsureNoReparsePoint(path);
        // Bound the actual read from one opened file handle. A separate
        // FileInfo.Length check followed by ReadAllBytes(path) was vulnerable
        // to an oversized replacement between those two path lookups.
        var snapshot = DecodeSnapshotRecord(snapshotId,
            ReadBoundedFile(path, MaxManifestBytes + HeaderBytes,
                beforeHandleOpen: null, cancellationToken: cancellationToken,
                afterReadBlock: afterManifestReadBlock));
        cancellationToken.ThrowIfCancellationRequested();
        EnsureRepositoryConfigUnchanged(); // Record I/O may have overlapped config edits.
        cancellationToken.ThrowIfCancellationRequested();
        return snapshot;
    }

    private Snapshot DecodeSnapshotRecord(string snapshotId, byte[] encrypted)
    {
        if (encrypted.Length > MaxManifestBytes + HeaderBytes)
            throw new InvalidDataException("Snapshot metadata exceeds size limit.");
        byte[] plain = Decrypt(encrypted, SnapshotMagic, SnapshotAad(snapshotId));
        try
        {
            var snapshot = JsonSerializer.Deserialize<Snapshot>(plain)
                           ?? throw new InvalidDataException("Empty snapshot.");
            if (snapshot.Version is not (1 or 2 or 3) || snapshot.Files is null ||
                snapshot.CreatedUtc == default)
                throw new InvalidDataException("Unknown or incomplete snapshot schema.");
            ValidateEntries(snapshot.Files);
            ValidateDirectoryTree(snapshot.Files, snapshot.Directories, snapshot.Version);
            ValidateSkippedSystemDirectoryLinks(snapshot);
            ValidateZoneIdentifierVersion(snapshot);
            return snapshot;
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    public void VerifySnapshot(string snapshotId) => VerifySnapshot(snapshotId, CancellationToken.None);

    // The public verifier must propagate cancellation all the way into its
    // authenticated chunk walk; a GUI STOP cannot be a button-only animation.
    public void VerifySnapshot(string snapshotId, CancellationToken cancellationToken)
        => VerifySnapshot(snapshotId,cancellationToken,null);

    public void VerifySnapshot(string snapshotId,CancellationToken cancellationToken,IProgress<VaultProgress>? progress)
        => VerifySnapshotWithProgress(snapshotId,cancellationToken,progress,VaultProgressStage.VerifyingSnapshot);

    private void VerifySnapshotWithProgress(string snapshotId,CancellationToken cancellationToken,
        IProgress<VaultProgress>? progress,VaultProgressStage stage)
    {
        CheckNotDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        VerifySnapshotContents(ReadSnapshot(snapshotId, cancellationToken), cancellationToken,progress,stage);
        EnsureRepositoryConfigUnchanged(); // Long verification may outlive a config swap.
        cancellationToken.ThrowIfCancellationRequested();
    }

    private void VerifySnapshotContents(Snapshot snapshot, CancellationToken cancellationToken = default,
        IProgress<VaultProgress>? progress=null,VaultProgressStage stage=VaultProgressStage.VerifyingSnapshot)
    {
        var verificationProgress=new VaultProgressReporter(progress,stage,progress is null?0:snapshot.Files.Sum(x=>x.Size));
        foreach (FileEntry entry in snapshot.Files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            VerifyFileContents(entry, cancellationToken,verificationProgress);
        }
    }

    // Authenticated preflight of a SINGLE logical file. In restore, run this
    // before allocating any plaintext stage, then re-authenticate each chunk
    // while actually writing (preflight does not pin mutable repository files).
    private void VerifyFileContents(FileEntry entry, CancellationToken cancellationToken = default,VaultProgressReporter? progress=null)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long bytes = 0;
        for (int i = 0; i < entry.Chunks.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            byte[] data = ReadChunkAndValidate(entry.Chunks[i], cancellationToken);
            try
            {
                RequireCanonicalChunkLength(entry.Size, i, entry.Chunks.Count, data.Length);
                sha.AppendData(data);
                bytes = checked(bytes + data.Length);
                progress?.Advance(data.Length);
            }
            finally { CryptographicOperations.ZeroMemory(data); }
        }
        cancellationToken.ThrowIfCancellationRequested();
        string digest = Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
        if (bytes != entry.Size || !string.Equals(digest, entry.Sha256, StringComparison.Ordinal))
            throw new InvalidDataException("File checksum or length mismatch: " + entry.Path);
    }

    /// <summary>
    /// Export ONE complete encrypted recovery point as an independent v1 vault.
    /// Only the selected manifest, its referenced immutable chunks, and the
    /// existing repository config are included. No password or plaintext files
    /// are written to the export. A verified staging folder is published last.
    /// WARNING: this is local-media export, NOT an implemented cloud transport.
    /// </summary>
    public void ExportEncryptedSnapshot(string snapshotId, string destinationRepositoryDirectory) =>
        ExportEncryptedSnapshot(snapshotId, destinationRepositoryDirectory, CancellationToken.None);

    /// <summary>
    /// Cooperative cancellation of a large encrypted portable export. STOP also
    /// interrupts the potentially multi-GB final post-publication verification.
    /// It NEVER rolls back an already visible export; inspect/reconcile it after
    /// OperationCanceledException rather than assuming that nothing committed.
    /// </summary>
    public void ExportEncryptedSnapshot(string snapshotId, string destinationRepositoryDirectory,
        CancellationToken cancellationToken) =>
        ExportEncryptedSnapshot(snapshotId, destinationRepositoryDirectory, cancellationToken, null);

    public void ExportEncryptedSnapshot(string snapshotId, string destinationRepositoryDirectory,
        CancellationToken cancellationToken, IProgress<VaultProgress>? progress) =>
        ExportEncryptedSnapshotCore(snapshotId, destinationRepositoryDirectory, afterPublished: null,
            cancellationToken: cancellationToken, progress: progress);

    // Fault injection is internal to the native smoke fixture. No callback is
    // exposed by the public export API; progress contains only stage/byte counts.
    internal void ExportEncryptedSnapshotCore(string snapshotId, string destinationRepositoryDirectory,
        Action<string>? afterPublished, Action<string>? beforePublication = null,
        Action<string>? whileContentLeased = null,
        CancellationToken cancellationToken = default,
        Action<string, int>? afterPrivateRecordBlock = null,
        IProgress<VaultProgress>? progress = null)
    {
        CheckNotDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        ValidateSnapshotId(snapshotId);
        ValidatePublicationDestination(destinationRepositoryDirectory);
        string destination = Path.GetFullPath(destinationRepositoryDirectory);
        if (Directory.Exists(destination) || File.Exists(destination))
            throw new IOException("Encrypted export destination already exists.");
        EnsureRepositoryPathDisjoint(_root, destination);
        string parent = Path.GetDirectoryName(destination)
                        ?? throw new IOException("Invalid export destination.");
        if (!Directory.Exists(parent))
            throw new DirectoryNotFoundException("Export parent must already exist.");
        EnsureNoReparsePointsInPath(parent);
        EnsureNoReparsePointsInPath(_root);
        string configPath = Path.Combine(_root, "repo.json");
        string snapshotPath = GetSnapshotPath(snapshotId);
        EnsureNoReparsePoint(configPath);
        EnsureNoReparsePoint(Path.Combine(_root, "objects"));
        EnsureNoReparsePoint(Path.Combine(_root, "snapshots"));
        EnsureNoReparsePoint(snapshotPath);

        // Read and validate the current config against the live, unlocked key:
        // a changed or mismatched config must never create an unusable export.
        if (new FileInfo(configPath).Length > 16_384)
            throw new InvalidDataException("Repository configuration is oversized.");
        byte[] configBytes = ReadBoundedFile(configPath, 16_384, cancellationToken);
        // PIN WHAT IS ACTUALLY EXPORTED, not merely the same path at commit time.
        EnsureCapturedConfigMatchesUnlock(configBytes);
        var config = JsonSerializer.Deserialize<RepositoryConfig>(configBytes)
                     ?? throw new InvalidDataException("Invalid repository configuration.");
        if (config.Format != "chomcio-local-v1" || config.Iterations != Iterations)
            throw new InvalidDataException("Invalid repository configuration version.");
        byte[] salt = Convert.FromBase64String(config.Salt);
        byte[] verifier = Convert.FromBase64String(config.Verifier);
        try
        {
            byte[] actual = HMACSHA256.HashData(_key, "ChomcioRecovery/key-check/v1"u8);
            try
            {
                if (salt.Length != 32 || verifier.Length != 32 ||
                    !CryptographicOperations.FixedTimeEquals(verifier, actual))
                    throw new InvalidDataException("Repository configuration no longer matches key.");
            }
            finally { CryptographicOperations.ZeroMemory(actual); }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(verifier);
        }

        Snapshot snapshot = ReadSnapshot(snapshotId, cancellationToken);
        // The export must never be published with already-missing/corrupt data.
        VerifySnapshotWithProgress(snapshotId, cancellationToken, progress, VaultProgressStage.CheckingExportSource);
        cancellationToken.ThrowIfCancellationRequested();
        // Pin export parent so its path cannot be renamed while staging and
        // publishing. The stage itself must remain movable for final commit.
        using var pinnedParent = WindowsRestoreParentPin.Acquire(parent);
        // Exports also carry reusable encrypted recovery material and repo
        // configuration. Never expose partial records through a world-readable
        // staging directory inherited from the chosen export parent.
        // A protected, uniquely named stage remains private after publication.
        var protectedStage = PrivateRestoreStage.CreateOwned(parent, ".chomcio-export-");
        string stage = protectedStage.Stage;
        // Never recursively delete a DIFFERENT directory substituted into the
        // export staging name after a failed verification. File IDs are checked
        // before cleanup; hostile same-user TOCTOU races still need NTFS tests.
        using var stageGuard = protectedStage.Guard;
        // An interrupted encrypted export should not strand a nonempty stage
        // merely because recursive deletion is unsafe. Record each ORIGINAL
        // directory/record FileId at creation, never by a later path scan.
        using var ownedExport = OperatingSystem.IsWindows()
            ? new WindowsOwnedRestoreTreeCleanup(stage) : null;
        bool published = false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Enforce private permissions for every nested folder even when
            // the Unix umask is deliberately permissive. On Windows, create
            // original children atomically relative to the pinned parent.
            // All directory handles are bound to NtCreateFile(FILE_CREATE)
            // while the creator forbids rename/delete sharing. The callback
            // records original identities BEFORE the creator closes.
            PrivateRestoreStage.CreatePrivateSubdirectory(stage, Path.Combine(stage, "objects"),
                (created, creator) => ownedExport?.TrackNewDirectory(created, creator),
                pinKnownParent: OperatingSystem.IsWindows()
                    ? path => ownedExport!.PinOwnedParentForWrite(path, stageGuard)
                    : null);
            PrivateRestoreStage.CreatePrivateSubdirectory(stage, Path.Combine(stage, "snapshots"),
                (created, creator) => ownedExport?.TrackNewDirectory(created, creator),
                pinKnownParent: OperatingSystem.IsWindows()
                    ? path => ownedExport!.PinOwnedParentForWrite(path, stageGuard)
                    : null);
            string portableConfig = Path.Combine(stage, "repo.json");
            if (OperatingSystem.IsWindows())
                WriteOwnedPrivateExportRecord(stage, portableConfig, configBytes, ownedExport!, stageGuard, cancellationToken, afterPrivateRecordBlock);
            else
                WriteAtomic(portableConfig, configBytes, cancellationToken: cancellationToken);
            PrivateRestoreStage.RestrictRestoredFileOnUnix(portableConfig);
            // Copy counters cover unique encrypted chunks, including headers.
            // Shared chunks are copied once. Every later authenticated pass
            // still walks all logical file bytes, with its own separate total.
            long exportBytes = progress is null ? 0 : snapshot.Files
                .SelectMany(file => file.Chunks.Select((id, index) =>
                    (Id: id, Bytes: checked(Math.Min((long)ChunkBytes, file.Size - (long)index * ChunkBytes) + HeaderBytes))))
                .DistinctBy(chunk => chunk.Id).Sum(chunk => chunk.Bytes);
            var copyProgress = new VaultProgressReporter(progress, VaultProgressStage.CopyingEncryptedExport, exportBytes);
            foreach (string id in snapshot.Files.SelectMany(file => file.Chunks).Distinct(StringComparer.Ordinal))
            {
                cancellationToken.ThrowIfCancellationRequested();
                string originalObject = GetObjectPath(id);
                EnsureNoReparsePoint(Path.GetDirectoryName(originalObject)!);
                EnsureNoReparsePoint(originalObject);
                if (new FileInfo(originalObject).Length > ChunkBytes + HeaderBytes)
                    throw new InvalidDataException("Oversized chunk during export.");
                string exportedObject = Path.Combine(stage, "objects", id[..2], id + ".obj");
                PrivateRestoreStage.CreatePrivateSubdirectory(stage,
                    Path.GetDirectoryName(exportedObject)!,
                    (created, creator) => ownedExport?.TrackNewDirectory(created, creator),
                    pinKnownParent: OperatingSystem.IsWindows()
                        ? path => ownedExport!.PinOwnedParentForWrite(path, stageGuard)
                        : null);
                byte[] ciphertext = ReadBoundedFile(originalObject, ChunkBytes + HeaderBytes, cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                if (OperatingSystem.IsWindows())
                    WriteOwnedPrivateExportRecord(stage, exportedObject, ciphertext, ownedExport!, stageGuard, cancellationToken, afterPrivateRecordBlock);
                else
                    WriteAtomic(exportedObject, ciphertext, cancellationToken: cancellationToken);
                PrivateRestoreStage.RestrictRestoredFileOnUnix(exportedObject);
                copyProgress.Advance(ciphertext.Length);
            }
            cancellationToken.ThrowIfCancellationRequested();
            if (new FileInfo(snapshotPath).Length > MaxManifestBytes + HeaderBytes)
                throw new InvalidDataException("Oversized snapshot during export.");
            string exportedSnapshot = Path.Combine(stage, "snapshots", snapshotId + ".snap");
            byte[] encryptedSnapshot = ReadBoundedFile(snapshotPath, MaxManifestBytes + HeaderBytes, cancellationToken);
            if (OperatingSystem.IsWindows())
                WriteOwnedPrivateExportRecord(stage, exportedSnapshot, encryptedSnapshot, ownedExport!, stageGuard, cancellationToken, afterPrivateRecordBlock);
            else
                WriteAtomic(exportedSnapshot, encryptedSnapshot, cancellationToken: cancellationToken);
            PrivateRestoreStage.RestrictRestoredFileOnUnix(exportedSnapshot);

            // Critical: verify the COPIED encrypted bytes, not just source bytes.
            // Clone the key so disposing the verifier cannot lock this vault.
            using (var exported = new LocalEncryptedVault(stage, (byte[])_key.Clone(), _openedConfigFingerprint))
                exported.VerifySnapshotWithProgress(snapshotId, cancellationToken, progress, VaultProgressStage.CheckingExportData);
            string stagedConfigPath = Path.Combine(stage, "repo.json");
            EnsureNoReparsePoint(stagedConfigPath);
            if (new FileInfo(stagedConfigPath).Length > 16_384)
                throw new InvalidDataException("Exported config exceeds maximum size.");
            // Pin the EXPORTED on-disk config as well as the captured source bytes.
            // Chunk authentication alone cannot detect a salt-only substitution.
            EnsureCapturedConfigMatchesUnlock(ReadBoundedFile(stagedConfigPath, 16_384, cancellationToken));
            // An attacker can replace repo.json, a chunk or a manifest with a
            // new byte-identical file: authenticated bytes still validate, but
            // the original staged FILE_OBJECT is no longer ours to publish.
            ownedExport?.RequireOriginalInventoryForPublication(stageGuard);
            EnsureRepositoryConfigUnchanged(); // Source lineage must still be unlocked one.
            // Same parent, Windows File.Move/Directory.Move never overwrites a
            // destination. No other snapshots or unrelated objects were copied.
            pinnedParent.RequireMatches();
            cancellationToken.ThrowIfCancellationRequested();
            beforePublication?.Invoke(stage); // native fault injection only
            // The stage may still contain the ORIGINAL FileIds while a writer
            // mutates ciphertext or repo.json IN PLACE after the first readback.
            // Reauthenticate the complete staged export at this final boundary;
            // ownership checks alone cannot detect changed bytes on the same ID.
            using (var lateExport = new LocalEncryptedVault(stage,
                       (byte[])_key.Clone(), _openedConfigFingerprint))
                lateExport.VerifySnapshotWithProgress(snapshotId, cancellationToken, progress, VaultProgressStage.CheckingExportBeforePublish);
            string finalStagedConfig = Path.Combine(stage, "repo.json");
            EnsureNoReparsePoint(finalStagedConfig);
            EnsureCapturedConfigMatchesUnlock(ReadBoundedFile(finalStagedConfig, 16_384, cancellationToken));
            EnsureRepositoryConfigUnchanged();
            ownedExport?.RequireOriginalInventoryForPublication(stageGuard);
            // Final content verification must execute WHILE real FILE_READ_DATA
            // handles on ALL originals exclude concurrent ordinary write opens.
            // A preopened writer causes this lease acquisition to FAIL CLOSED.
            // Share-delete is retained to permit the final root-directory rename.
            // SCOPED to native commit, not post-publication verification:
            // release leases before existing afterPublished tamper-injection
            // regression runs, so post-commit corruption is still detectable.
            using (var exportContentLeases = ownedExport?.AcquireImmutableContentLeases(stageGuard))
            {
                whileContentLeased?.Invoke(stage); // native fault-injection only
                if (OperatingSystem.IsWindows())
                {
                    using (var immutableExport = new LocalEncryptedVault(stage,
                               (byte[])_key.Clone(), _openedConfigFingerprint))
                        immutableExport.VerifySnapshotWithProgress(snapshotId, cancellationToken, progress, VaultProgressStage.CheckingExportWithLeases);
                    EnsureCapturedConfigMatchesUnlock(ReadBoundedFile(
                        Path.Combine(stage, "repo.json"), 16_384, cancellationToken));
                    EnsureRepositoryConfigUnchanged();
                    ownedExport!.RequireOriginalInventoryForPublication(stageGuard);
                }
                // The original stage root must not be substituted, even if all
                // retained leaf content leases still point at original file objects.
                stageGuard.RequireMatches(stage);
                // LAST cancellable boundary: do not convert a completed commit
                // into a cancellation, and never publish a partially copied record.
                cancellationToken.ThrowIfCancellationRequested();
                if (OperatingSystem.IsWindows())
                    WindowsOwnedDirectoryPublisher.Publish(stage, destination, stageGuard,
                        cancellationToken: cancellationToken);
                else
                    Directory.Move(stage, destination);
            } // ALL original read leases released before the existing post-commit smoke.
            // Do not delete a published export during failure handling. A
            // final-name checksum failure leaves an untrusted visible folder;
            // preservation is safer than destructive or racy cleanup.
            published = true;
            afterPublished?.Invoke(destination); // native test fault injection only
            // STOP must propagate through potentially multi-GB FINAL export
            // dependency verification as well. A committed export may remain;
            // never attempt speculative deletion after the directory rename.
            cancellationToken.ThrowIfCancellationRequested();
            using (var publishedExport = new LocalEncryptedVault(destination,
                       (byte[])_key.Clone(), _openedConfigFingerprint))
                publishedExport.VerifySnapshotWithProgress(snapshotId, cancellationToken, progress, VaultProgressStage.CheckingPublishedExport);
            string publishedConfigPath = Path.Combine(destination, "repo.json");
            EnsureNoReparsePoint(publishedConfigPath);
            if (new FileInfo(publishedConfigPath).Length > 16_384)
                throw new InvalidDataException("Published export configuration exceeds maximum size.");
            EnsureCapturedConfigMatchesUnlock(ReadBoundedFile(publishedConfigPath, 16_384, cancellationToken));
            EnsureRepositoryConfigUnchanged();
            pinnedParent.RequireMatches();
            cancellationToken.ThrowIfCancellationRequested();
        }
        finally
        {
            if (!published && Directory.Exists(stage))
            {
                stageGuard.RequireMatches(stage);
                if (OperatingSystem.IsWindows())
                {
                    // Only ORIGINAL inventoried records/children are eligible
                    // for handle-bound deletion. A foreign or untracked entry
                    // fails closed and keeps the protected stage for review.
                    if (ownedExport is null || !ownedExport.TryCleanup(stageGuard))
                        System.Diagnostics.Trace.TraceWarning(
                            "Unverified private export stage retained for reviewed cleanup: " + stage);
                }
                else
                    Directory.Delete(stage, recursive: true);
            }
        }
    }

    /// <summary>
    /// Import one previously exported encrypted recovery point into its ORIGINAL
    /// repository lineage (identical repo.json). Intended as an offline building
    /// block for future authenticated cloud downloads; it does not connect to
    /// Chomikuj or replace existing snapshots. The snapshot record is published
    /// LAST, after every referenced encrypted object has been checked locally.
    /// Interrupted imports may leave unreferenced objects, never a valid-looking
    /// partial recovery point. Only use with trusted, non-writable local media:
    /// hostile concurrent filesystem modifications need native handle hardening.
    /// </summary>
    public void ImportEncryptedSnapshot(string snapshotId, string portableRepositoryDirectory) =>
        ImportEncryptedSnapshot(snapshotId, portableRepositoryDirectory, CancellationToken.None);

    // Multi-chunk import must honor STOP before manifest publication. Previously
    // the CLI import used a token-less multi-gigabyte authenticated walk and
    // Ctrl+C could terminate the process without a safe commit boundary.
    public void ImportEncryptedSnapshot(string snapshotId, string portableRepositoryDirectory,
        CancellationToken cancellationToken) =>
        ImportEncryptedSnapshotCore(snapshotId, portableRepositoryDirectory,
            afterPortablePreflight: null, cancellationToken: cancellationToken);

    // Native disposable-vault fault injection ONLY. Public import never accepts
    // callbacks from untrusted input or skips authenticated preflight.
    internal void ImportEncryptedSnapshotCore(string snapshotId, string portableRepositoryDirectory,
        Action? afterPortablePreflight, CancellationToken cancellationToken = default,
        Action<int>? afterVerifiedObject = null,
        Action<byte[]>? afterImportedTargetChunkRead = null)
    {
        CheckNotDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        ValidateSnapshotId(snapshotId);
        string sourceRoot = Path.GetFullPath(portableRepositoryDirectory);
        if (!Directory.Exists(sourceRoot))
            throw new DirectoryNotFoundException("Import source must exist: " + sourceRoot);
        EnsureRepositoryPathDisjoint(_root, sourceRoot);
        EnsureNoReparsePointsInPath(sourceRoot);
        EnsureNoReparsePointsInPath(_root);
        string sourceObjects = Path.Combine(sourceRoot, "objects");
        string sourceSnapshots = Path.Combine(sourceRoot, "snapshots");
        string targetObjects = Path.Combine(_root, "objects");
        string targetSnapshots = Path.Combine(_root, "snapshots");
        foreach (string folder in new[] { sourceObjects, sourceSnapshots, targetObjects, targetSnapshots })
        {
            if (!Directory.Exists(folder)) throw new DirectoryNotFoundException(folder);
            EnsureNoReparsePoint(folder);
        }
        string sourceConfig = Path.Combine(sourceRoot, "repo.json");
        string targetConfig = Path.Combine(_root, "repo.json");
        EnsureNoReparsePoint(sourceConfig);
        EnsureNoReparsePoint(targetConfig);
        if (new FileInfo(sourceConfig).Length > 16_384 ||
            new FileInfo(targetConfig).Length > 16_384)
            throw new InvalidDataException("Oversized import configuration.");
        byte[] sourceConfigBytes = ReadBoundedFile(sourceConfig, 16_384, cancellationToken);
        byte[] targetConfigBytes = ReadBoundedFile(targetConfig, 16_384, cancellationToken);
        // Require exactly the same original repository, not merely the same
        // passphrase. This prevents accidentally mixing distinct vault lineages.
        if (!sourceConfigBytes.AsSpan().SequenceEqual(targetConfigBytes))
            throw new InvalidDataException("Encrypted export belongs to another repository.");
        // Both CAPTURED config buffers must match the bytes authenticated at
        // unlock, even if an on-disk salt swap is later reverted before commit.
        EnsureCapturedConfigMatchesUnlock(sourceConfigBytes);
        var config = JsonSerializer.Deserialize<RepositoryConfig>(sourceConfigBytes)
                     ?? throw new InvalidDataException("Invalid import configuration.");
        if (config.Format != "chomcio-local-v1" || config.Iterations != Iterations)
            throw new InvalidDataException("Unsupported import configuration.");
        byte[] expected = Convert.FromBase64String(config.Verifier);
        byte[] salt = Convert.FromBase64String(config.Salt);
        byte[] actual = HMACSHA256.HashData(_key, "ChomcioRecovery/key-check/v1"u8);
        try
        {
            if (expected.Length != 32 || salt.Length != 32 ||
                !CryptographicOperations.FixedTimeEquals(expected, actual))
                throw new InvalidDataException("Import configuration does not match active encryption key.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(actual);
        }

        using var portable = new LocalEncryptedVault(sourceRoot, (byte[])_key.Clone(), _openedConfigFingerprint);
        string sourceSnapshotPath = portable.GetSnapshotPath(snapshotId);
        EnsureNoReparsePoint(sourceSnapshotPath);
        if (new FileInfo(sourceSnapshotPath).Length > MaxManifestBytes + HeaderBytes)
            throw new InvalidDataException("Oversized imported snapshot.");
        // Pin the authenticated snapshot bytes before copying objects. Never
        // re-read a different record after validating the original one.
        byte[] encryptedSnapshot = ReadBoundedFile(sourceSnapshotPath, MaxManifestBytes + HeaderBytes, cancellationToken);
        Snapshot snapshot = portable.DecodeSnapshotRecord(snapshotId, encryptedSnapshot);
        portable.VerifySnapshotContents(snapshot, cancellationToken);
        afterPortablePreflight?.Invoke(); // native smoke: mutate source AFTER initial preflight
        cancellationToken.ThrowIfCancellationRequested();
        string targetSnapshotPath = GetSnapshotPath(snapshotId);
        if (File.Exists(targetSnapshotPath))
        {
            EnsureNoReparsePoint(targetSnapshotPath);
            if (!ReadBoundedFile(targetSnapshotPath, MaxManifestBytes + HeaderBytes, cancellationToken).AsSpan().SequenceEqual(encryptedSnapshot))
                throw new InvalidDataException("Snapshot ID collision; existing record differs.");
            VerifySnapshot(snapshotId, cancellationToken);
            return; // Safe and idempotent; never replace an existing snapshot.
        }

        int verifiedObjects = 0;
        foreach (string id in snapshot.Files.SelectMany(file => file.Chunks)
                     .Distinct(StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            string input = portable.GetObjectPath(id);
            string target = GetObjectPath(id);
            EnsureNoReparsePoint(Path.GetDirectoryName(input)!);
            EnsureNoReparsePoint(input);
            if (new FileInfo(input).Length > ChunkBytes + HeaderBytes)
                throw new InvalidDataException("Oversized imported object.");
            byte[] ciphertext = ReadBoundedFile(input, ChunkBytes + HeaderBytes, cancellationToken);
            // The earlier portable.VerifySnapshotContents verified a DIFFERENT
            // read of mutable source files. Authenticate THESE captured bytes
            // BEFORE creating/publishing ANY target object; otherwise a late
            // ciphertext mutation leaves a poisoned, unreferenced object behind.
            try
            {
                AuthenticateCapturedImportedChunk(id, ciphertext);
                cancellationToken.ThrowIfCancellationRequested();
                if (!File.Exists(target))
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                    EnsureNoReparsePoint(Path.GetDirectoryName(target)!);
                    // Concurrent no-overwrite publication is handled by final
                    // verification; never overwrite an existing object.
                    try { WriteAtomic(target, ciphertext, cancellationToken: cancellationToken); }
                    catch (IOException) when (File.Exists(target)) { }
                }
                cancellationToken.ThrowIfCancellationRequested();
                EnsureNoReparsePoint(target);
                // The target chunk has already been authenticated and decrypted.
                // If the SECOND, mutable portable-source read fails (tampering,
                // I/O or STOP), the original code skipped the try/finally below
                // because expectedPlaintext was evaluated BEFORE entering it.
                // That stranded up to 4 MiB of decrypted target data in the heap.
                // Own each plaintext lifetime INDEPENDENTLY; there is no path
                // out of the second read that may bypass the target zeroization.
                byte[] actualPlaintext = ReadChunkAndValidate(id, cancellationToken);
                try
                {
                    // Deterministic native smoke hook only, not a public API.
                    // Allows source mutation AFTER target plaintext was returned
                    // but BEFORE the independent portable authentication begins.
                    afterImportedTargetChunkRead?.Invoke(actualPlaintext);
                    byte[] expectedPlaintext = portable.ReadChunkAndValidate(id, cancellationToken);
                    try
                    {
                        if (!actualPlaintext.AsSpan().SequenceEqual(expectedPlaintext))
                            throw new InvalidDataException("Imported object conflicts with existing ciphertext.");
                    }
                    finally { CryptographicOperations.ZeroMemory(expectedPlaintext); }
                }
                finally { CryptographicOperations.ZeroMemory(actualPlaintext); }
            }
            finally { CryptographicOperations.ZeroMemory(ciphertext); }
            // Native deterministic STOP injection AFTER one completely verified
            // immutable chunk, BEFORE the next chunk or manifest publication.
            afterVerifiedObject?.Invoke(++verifiedObjects);
            cancellationToken.ThrowIfCancellationRequested();
        }
        // Verify all target file digests, not just individual chunk authenticators.
        VerifySnapshotContents(snapshot, cancellationToken);
        EnsureRepositoryConfigUnchanged(); // Reject changed local unlock config before commit.
        cancellationToken.ThrowIfCancellationRequested();
        WriteAtomicAndVerifyPublished(targetSnapshotPath, encryptedSnapshot,
            cancellationToken: cancellationToken); // final, independently checked commit
        // Cancellation AFTER irreversible publication never deletes a possibly
        // shared final name: the committed point may require reconciliation.
        VerifySnapshot(snapshotId, cancellationToken);
    }

    public void RestoreSnapshot(string snapshotId, string destinationDirectory,
        CancellationToken cancellationToken = default) =>
        RestoreSnapshotCore(snapshotId, destinationDirectory, beforeStageReadback: null,
            cancellationToken: cancellationToken);

    // Fault injection for native smoke tests. Public restore always passes null.
    // The stage is not published unless its REAL on-disk bytes pass a second check.
    internal void RestoreSnapshotCore(string snapshotId, string destinationDirectory,
        Action<string>? beforeStageReadback, Func<string, long>? availableBytesOverride = null,
        Action? beforePrivateStageCreation = null, Action<string>? afterPublished = null,
        CancellationToken cancellationToken = default, Action<string>? beforePublication = null,
        Action<string>? whileContentLeased = null)
    {
        CheckNotDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        ValidatePublicationDestination(destinationDirectory);
        string destination = Path.GetFullPath(destinationDirectory);
        if (Directory.Exists(destination) || File.Exists(destination))
            throw new IOException("Restore destination already exists; nothing will be overwritten.");
        EnsureRepositoryPathDisjoint(_root, destination);
        string parent = Path.GetDirectoryName(destination)
                        ?? throw new IOException("Invalid restore directory.");
        if (!Directory.Exists(parent))
            throw new DirectoryNotFoundException("Restore parent must already exist.");
        EnsureNoReparsePointsInPath(parent);
        // Hold kernel handles on every existing ancestor through publication.
        // A concurrent parent-directory rename must fail on Windows, rather
        // than redirecting the staged plaintext outside the selected location.
        using var pinnedParent = WindowsRestoreParentPin.Acquire(parent);
        Snapshot snapshot = ReadSnapshot(snapshotId, cancellationToken);
        // Check TOTAL logical file bytes against the actual destination volume
        // before creating any plaintext stage. This is best-effort, not a
        // reservation: a concurrent writer may still exhaust disk space.
        if(snapshot.Files.Any(f=>f.ZoneIdentifierBase64 is not null)&&!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Restoring Zone.Identifier requires Windows and NTFS.");
        RestoreSpaceGuard.RequireAvailable(parent, snapshot.Files.Select(entry => checked(entry.Size+WindowsZoneIdentifier.Validate(entry.ZoneIdentifierBase64))),
            availableBytesOverride);
        // Validate ALL referenced ciphertext and complete-file SHA-256 digests
        // BEFORE creating the first private plaintext stage. In particular, a
        // damaged late file must not cause earlier plaintext to hit disk even
        // temporarily. Re-check while writing: preflight is not a file lock.
        VerifySnapshotContents(snapshot, cancellationToken);
        EnsureRepositoryConfigUnchanged();
        cancellationToken.ThrowIfCancellationRequested();
        // Native smoke observer; public callers cannot bypass the preflight.
        beforePrivateStageCreation?.Invoke();
        // Never expose staged plaintext through a destination parent's
        // potentially public inherited ACL or POSIX umask.
        var protectedStage = PrivateRestoreStage.CreateOwned(parent, ".chomcio-restore-");
        string stage = protectedStage.Stage;
        // Keep the newly created stage's physical Windows identity pinned.
        // Do not recursively delete a different folder substituted at its path.
        using var stageGuard = protectedStage.Guard;
        using var ownedTree = OperatingSystem.IsWindows()
            ? new WindowsOwnedRestoreTreeCleanup(stage) : null;
        bool success = false;
        try
        {
            // v1 had no directory inventory, and remains readable. v2 recreates
            // even directories with no files (not merely parents of file entries).
            foreach (string relativeDirectory in snapshot.Directories ?? Enumerable.Empty<string>())
            {
                cancellationToken.ThrowIfCancellationRequested();
                string directory = Path.GetFullPath(Path.Combine(stage,
                    relativeDirectory.Replace('/', Path.DirectorySeparatorChar)));
                if (!IsInside(stage, directory) || directory == stage)
                    throw new InvalidDataException("Unsafe restore directory path.");
                PrivateRestoreStage.CreatePrivateSubdirectory(stage, directory,
                    (created, creator) => ownedTree?.TrackNewDirectory(created, creator),
                    pinKnownParent: OperatingSystem.IsWindows()
                        ? path => ownedTree!.PinOwnedParentForWrite(path, stageGuard)
                        : null);
            }
            foreach (FileEntry entry in snapshot.Files)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string file = Path.GetFullPath(Path.Combine(stage, entry.Path.Replace('/', Path.DirectorySeparatorChar)));
                if (!IsInside(stage, file) || file == stage)
                    throw new InvalidDataException("Unsafe restore path.");
                PrivateRestoreStage.CreatePrivateSubdirectory(stage, Path.GetDirectoryName(file)!,
                    (created, creator) => ownedTree?.TrackNewDirectory(created, creator),
                    pinKnownParent: OperatingSystem.IsWindows()
                        ? path => ownedTree!.PinOwnedParentForWrite(path, stageGuard)
                        : null);
                // The trusted parent pin spans the WHOLE plaintext write and
                // flush, not only the initial File.Create or later cleanup.
                using var verifiedWriteParent = ownedTree?.PinOwnedParentForWrite(
                    Path.GetDirectoryName(file)!, stageGuard);
                using var output = new FileStream(file, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                    bufferSize: 65_536, options: FileOptions.WriteThrough);
                // Capture physical identity from the creator's exclusive handle,
                // not from a later pathname (which could have been swapped).
                ownedTree?.TrackCreatedFile(file, output.SafeFileHandle);
                using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                long size = 0;
                for (int i = 0; i < entry.Chunks.Count; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    byte[] data = ReadChunkAndValidate(entry.Chunks[i], cancellationToken);
                    try
                    {
                        // Validate authenticated chunk's actual length BEFORE writing
                        // any part of an invalid record to plaintext staging.
                        RequireCanonicalChunkLength(entry.Size, i, entry.Chunks.Count, data.Length);
                        output.Write(data);
                        sha.AppendData(data);
                        size = checked(size + data.Length);
                    }
                    finally { CryptographicOperations.ZeroMemory(data); }
                }
                output.Flush(flushToDisk: true);
                WindowsZoneIdentifier.WriteOwned(file,output.SafeFileHandle,entry.ZoneIdentifierBase64,cancellationToken);
                verifiedWriteParent?.RequireMatches();
                PrivateRestoreStage.RestrictRestoredFileOnUnix(file);
                string digest = Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
                if (size != entry.Size || !string.Equals(digest, entry.Sha256, StringComparison.Ordinal))
                    throw new InvalidDataException("Corrupted file: " + entry.Path);
            }
            // A successful SHA of source buffers does not prove that disk writes
            // persisted intact: independently re-read staged files and inventory.
            beforeStageReadback?.Invoke(stage);
            cancellationToken.ThrowIfCancellationRequested();
            VerifyRestoredStagingTree(stage, snapshot, cancellationToken);
            // SHA-only readback can pass a FOREIGN replacement containing
            // identical bytes. Bind every final child to the ORIGINAL writer
            // FileId from before plaintext was written.
            ownedTree?.RequireOriginalInventoryForPublication(stageGuard);
            // Fail closed when repo.json changed during potentially long readback.
            // This is not Windows handle-based atomic path pinning.
            EnsureRepositoryConfigUnchanged();
            // Only a complete, verified staging tree becomes user-visible.
            pinnedParent.RequireMatches();
            // Do not observe cancellation AFTER visibility: a committed restore
            // must receive its full post-publication verification instead.
            cancellationToken.ThrowIfCancellationRequested();
            beforePublication?.Invoke(stage); // native fault injection only
            // Original FileIds and an exact name set do not establish CONTENT
            // immutability. A same-account writer with a preopened or newly
            // acquired handle can alter the original leaf bytes without
            // changing its 128-bit FileId after the earlier authentication.
            // Rehash the complete staged plaintext immediately before commit.
            VerifyRestoredStagingTree(stage, snapshot, cancellationToken);
            EnsureRepositoryConfigUnchanged();
            // Recheck the complete ORIGINAL physical child inventory after
            // this last test-only hook, immediately before root publication.
            ownedTree?.RequireOriginalInventoryForPublication(stageGuard);
            // Hold every ORIGINAL leaf open for DATA READ, denying WRITE sharing
            // across the final authenticated readback and kernel root rename.
            // This makes an already-open ordinary writer fail lease acquisition
            // and blocks later ordinary opens, rather than relying on timing.
            // Scope read leases to authentication + native rename ONLY.
            // Earlier post-commit corruption smokes must still mutate and
            // detect damaged visible files after the handles are released.
            using (var restoreContentLeases = ownedTree?.AcquireImmutableContentLeases(stageGuard))
            {
                whileContentLeased?.Invoke(stage); // native fault-injection only
                if (OperatingSystem.IsWindows())
                {
                    VerifyRestoredStagingTree(stage, snapshot, cancellationToken);
                    EnsureRepositoryConfigUnchanged();
                    ownedTree!.RequireOriginalInventoryForPublication(stageGuard);
                }
                // A rename/delete-sharing adversary might still swap names; this
                // is NOT a fully atomic tree publication against privileged actors.
                stageGuard.RequireMatches(stage);
                if (OperatingSystem.IsWindows())
                    WindowsOwnedDirectoryPublisher.Publish(stage, destination, stageGuard,
                        cancellationToken: cancellationToken);
                else
                    Directory.Move(stage, destination);
            } // ORIGINAL leaf leases disposed before afterPublished smoke callback.
            // Detect a damaged FINAL published tree, not merely a correct
            // private staging tree. Never delete an already-published output
            // speculatively if this independent verification rejects it.
            afterPublished?.Invoke(destination); // native smoke fault injection only
            // Publication is irreversible. A STOP during the FINAL readback
            // must report cancellation, not false success, but must NEVER
            // delete the already-visible restored tree by its mutable path.
            cancellationToken.ThrowIfCancellationRequested();
            // SHA-only final readback can accept a foreign, byte-identical
            // FILE_OBJECT swapped in AFTER native directory publication.
            // Compare every published child and root to the ORIGINAL writer
            // FileIds before AND after full authenticated final readback.
            ownedTree?.RequireOriginalPublishedInventory(destination, stageGuard, cancellationToken);
            VerifyRestoredStagingTree(destination, snapshot, cancellationToken);
            ownedTree?.RequireOriginalPublishedInventory(destination, stageGuard, cancellationToken);
            EnsureRepositoryConfigUnchanged();
            pinnedParent.RequireMatches();
            cancellationToken.ThrowIfCancellationRequested();
            success = true;
        }
        finally
        {
            if (!success && Directory.Exists(stage))
            {
                stageGuard.RequireMatches(stage);
                if (OperatingSystem.IsWindows())
                {
                    // Only recorded ORIGINAL writer handles and child FileIds
                    // may be disposed. Foreign/moved-in entries are preserved;
                    // an incomplete cleanup retains the protected private stage.
                    if (ownedTree is null || !ownedTree.TryCleanup(stageGuard))
                        System.Diagnostics.Trace.TraceWarning(
                            "Private restore stage retained for reviewed cleanup: " + stage);
                }
                else
                    Directory.Delete(stage, recursive: true);
            }
        }
    }

    /// <summary>
    /// Restore exactly one snapshot file to a new user-selected filename. The output
    /// remains invisible until the entire file has passed authenticated chunk and
    /// SHA-256 verification. Never replaces an existing destination.
    /// </summary>
    public void RestoreFile(string snapshotId, string relativeFilePath, string destinationFile,
        CancellationToken cancellationToken = default) =>
        RestoreFileCore(snapshotId, relativeFilePath, destinationFile, beforeStageReadback: null,
            cancellationToken: cancellationToken);

    internal void RestoreFileCore(string snapshotId, string relativeFilePath, string destinationFile,
        Action<string>? beforeStageReadback, Func<string, long>? availableBytesOverride = null,
        Action? beforePrivateStageCreation = null, Action<string>? afterPublished = null,
        CancellationToken cancellationToken = default,
        Action<string>? whileOwnedRestoreHandlePinned = null)
    {
        CheckNotDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        ValidateRelativePath(relativeFilePath);
        ValidatePublicationDestination(destinationFile);
        string destination = Path.GetFullPath(destinationFile);
        if (File.Exists(destination) || Directory.Exists(destination))
            throw new IOException("Restore destination already exists; nothing will be overwritten.");
        EnsureRepositoryPathDisjoint(_root, destination);
        string parent = Path.GetDirectoryName(destination)
                        ?? throw new IOException("Invalid restore destination.");
        if (!Directory.Exists(parent))
            throw new DirectoryNotFoundException("Destination parent must already exist.");
        EnsureNoReparsePointsInPath(parent);
        using var pinnedParent = WindowsRestoreParentPin.Acquire(parent);
        // Match exactly; Windows case-insensitive aliases must not select other entries.
        FileEntry entry = ReadSnapshot(snapshotId, cancellationToken).Files.SingleOrDefault(
            f => string.Equals(f.Path, relativeFilePath, StringComparison.Ordinal))
            ?? throw new FileNotFoundException("File not present in this snapshot.", relativeFilePath);
        if(entry.ZoneIdentifierBase64 is not null&&!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Restoring Zone.Identifier requires Windows and NTFS.");
        RestoreSpaceGuard.RequireAvailable(parent, new[] { checked(entry.Size+WindowsZoneIdentifier.Validate(entry.ZoneIdentifierBase64)) }, availableBytesOverride);
        // Reject damaged selected-file ciphertext before allocating a private
        // plaintext staging folder. Verify again during real restore: objects
        // can change after this preflight on an untrusted shared filesystem.
        VerifyFileContents(entry, cancellationToken);
        EnsureRepositoryConfigUnchanged();
        cancellationToken.ThrowIfCancellationRequested();
        beforePrivateStageCreation?.Invoke(); // native smoke observer only
        // A plain .tmp file directly in the selected parent could inherit
        // Everyone/Users READ ACLs before authentication is complete.
        var protectedStage = PrivateRestoreStage.CreateOwned(parent, ".chomcio-file-restore-");
        string privateStage = protectedStage.Stage;
        using var stageGuard = protectedStage.Guard;
        string stage = Path.Combine(privateStage, "payload.tmp");
        // FileId must be captured from the ORIGINAL exclusive writer handle,
        // while a same-user process cannot replace this file's name.
        WindowsOwnedSingleStageFileCleanup? ownedStageFile = null;
        try
        {
            using (var output = new FileStream(stage, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                       bufferSize: 65_536, options: FileOptions.WriteThrough))
            {
                if (OperatingSystem.IsWindows())
                    ownedStageFile = WindowsOwnedSingleStageFileCleanup.CaptureCreatedFile(
                        stage, output.SafeFileHandle);
                using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                long size = 0;
                for (int i = 0; i < entry.Chunks.Count; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    byte[] data = ReadChunkAndValidate(entry.Chunks[i], cancellationToken);
                    try
                    {
                        RequireCanonicalChunkLength(entry.Size, i, entry.Chunks.Count, data.Length);
                        output.Write(data);
                        sha.AppendData(data);
                        size = checked(size + data.Length);
                    }
                    finally { CryptographicOperations.ZeroMemory(data); }
                }
                output.Flush(flushToDisk: true);
                WindowsZoneIdentifier.WriteOwned(stage,output.SafeFileHandle,entry.ZoneIdentifierBase64,cancellationToken);
                PrivateRestoreStage.RestrictRestoredFileOnUnix(stage);
                string digest = Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
                if (size != entry.Size || !string.Equals(digest, entry.Sha256, StringComparison.Ordinal))
                    throw new InvalidDataException("Restored file SHA-256/length mismatch.");
            }
            beforeStageReadback?.Invoke(stage);
            cancellationToken.ThrowIfCancellationRequested();
            VerifyStagedFileOnDisk(stage, entry, cancellationToken: cancellationToken);
            EnsureRepositoryConfigUnchanged(); // Recheck lineage immediately before exposure.
            // Win32 commit must rename the SAME FILE_OBJECT independently
            // authenticated by a streaming SHA-256 digest, not a pathname
            // reopened after the staged file's earlier readback.
            pinnedParent.RequireMatches();
            cancellationToken.ThrowIfCancellationRequested();
            if (OperatingSystem.IsWindows())
            {
                // Reject a foreign byte-identical payload substituted after
                // the original writer closes but before publication opens it.
                WindowsOwnedPlaintextPublisher.Publish(stage, destination,
                    entry.Size, entry.Sha256, ownedStageFile?.OriginalIdentity,
                    cancellationToken, whileOwnedRestoreHandlePinned,entry.ZoneIdentifierBase64);
            }
            else
            {
                File.Move(stage, destination);
            }
            // A verified staging file can still be corrupted in the rename
            // window. Final-name readback is required to claim restore success.
            // Failure leaves an untrusted published name for manual inspection.
            afterPublished?.Invoke(destination); // native smoke fault injection only
            // This final readback can take a long time for a large recovered
            // file; honor STOP after the no-clobber rename without deleting
            // the already-visible destination under any circumstances.
            cancellationToken.ThrowIfCancellationRequested();
            // The final on-disk bytes alone do not prove that this is the
            // ORIGINAL plaintext FILE_OBJECT created by our exclusive writer.
            // Reject a byte-identical foreign file substituted after rename.
            if (OperatingSystem.IsWindows() && ownedStageFile is null)
                throw new IOException("Original plaintext creator identity was not captured.");
            VerifyStagedFileOnDisk(destination, entry,
                cancellationToken: cancellationToken,
                expectedCreatorIdentity: ownedStageFile?.OriginalIdentity);
            EnsureRepositoryConfigUnchanged();
            pinnedParent.RequireMatches();
            cancellationToken.ThrowIfCancellationRequested();
        }
        finally
        {
            // Private staging must be cleaned whether validation failed or
            // successful File.Move published the checked plaintext file.
            if (Directory.Exists(privateStage))
            {
                stageGuard.RequireMatches(privateStage);
                if (OperatingSystem.IsWindows())
                {
                    // If the file was never created/captured, do NOT guess an
                    // owner from the pathname. A foreign replacement is preserved.
                    // A successfully published file is already absent from stage.
                    ownedStageFile?.TryDeleteOriginal(stageGuard);
                    if (!stageGuard.TryDeleteOriginalEmptyStage(privateStage))
                        System.Diagnostics.Trace.TraceWarning(
                            "Nonempty private stage retained for reviewed cleanup: " + privateStage);
                }
                else
                    Directory.Delete(privateStage, recursive: true);
            }
        }
    }

    /// <summary>
    /// Independently re-read the REAL restored bytes after the write handle has
    /// been closed, before making the output visible. Reject unexpected files,
    /// junctions, symlinks, missing empty folders, and late metadata changes.
    /// Still not a defense against an adversary actively swapping NTFS handles:
    /// shipping that guarantee requires Windows handle-based native hardening.
    /// </summary>
    internal static void VerifyRestoredStagingTree(string stage, Snapshot snapshot, CancellationToken cancellationToken = default)
    {
        ValidateEntries(snapshot.Files);
        ValidateDirectoryTree(snapshot.Files, snapshot.Directories, snapshot.Version);
        ValidateZoneIdentifierVersion(snapshot);
        var expected = new HashSet<string>(
            OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal)
        {
            "d/."
        };
        foreach (string directory in snapshot.Directories ?? Enumerable.Empty<string>())
            expected.Add("d/" + directory);
        foreach (FileEntry entry in snapshot.Files)
        {
            expected.Add("f/" + entry.Path);
            int slash = entry.Path.LastIndexOf('/');
            while (slash >= 0)
            {
                string directory = entry.Path[..slash];
                expected.Add("d/" + directory);
                slash = directory.LastIndexOf('/');
            }
        }
        cancellationToken.ThrowIfCancellationRequested();
        bool preserveZones=snapshot.Version==3;
        var before = CaptureSourceInventory(stage, cancellationToken,preserveZoneIdentifiers:preserveZones); // Still rejects reparse points.
        if (!expected.SetEquals(before.Keys))
            throw new InvalidDataException("Restored staging tree has missing or unexpected entries.");
        foreach (FileEntry entry in snapshot.Files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string path = Path.Combine(stage, entry.Path.Replace('/', Path.DirectorySeparatorChar));
            VerifyStagedFileOnDisk(path, entry, cancellationToken: cancellationToken);
        }
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfSourceInventoryChanged(stage, before, cancellationToken,preserveZoneIdentifiers:preserveZones);
    }

    // Optional callback is ONLY for the native regression test: it injects a
    // leaf-file replacement after the initial inventory, before the real open.
    internal static void VerifyStagedFileOnDisk(string path, FileEntry entry,
        Action? beforeReadbackHandleOpen = null, CancellationToken cancellationToken = default,
        WindowsSourceFileIdentity.Identity? expectedCreatorIdentity = null)
    {
        EnsureNoReparsePointsInPath(Path.GetDirectoryName(path)!);
        EnsureNoReparsePoint(path);
        WindowsHardLinkGuard.RejectMultipleLinks(path);
        // Single-file restore bypasses CaptureSourceInventory(), which already
        // checks these conditions for whole-folder restore. A named NTFS ADS
        // added to the staged output must not be silently published as a
        // complete restorable file even when its default stream SHA matches.
        WindowsZoneIdentifier.Verify(path,entry.ZoneIdentifierBase64,cancellationToken);
        var before = new FileInfo(path);
        if (!before.Exists || before.Length != entry.Size)
            throw new InvalidDataException("Staged file is missing or has wrong length: " + entry.Path);
        WindowsUnsupportedMetadataGuard.RejectUnsupported(before.Attributes, path);
        long expectedLength = before.Length;
        DateTime expectedWriteUtc = before.LastWriteTimeUtc;
        // The FileInfo/ADS/HARDLINK checks above are PATH-based. Reopening
        // through FileStream(path) could follow a junction/symlink swapped in
        // after those checks. On Windows pin the FIRST physical file identity,
        // then use a no-follow CreateFileW handle and require the SAME identity
        // before reading even one byte. A different regular file with the same
        // content/size/timestamps must also fail closed.
        // When confirming an already-published single-file restore, bind the
        // actual no-follow read handle to the identity captured from the
        // ORIGINAL exclusive payload.tmp writer. Never adopt a different
        // pathname FILE_OBJECT even if every byte and timestamp is identical.
        WindowsSourceFileIdentity.Identity? initialId = expectedCreatorIdentity ??
            WindowsSourceFileIdentity.CaptureFile(path);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using (var input = WindowsNoFollowSourceReader.Open(path, beforeReadbackHandleOpen))
        {
            WindowsSourceFileIdentity.RequireMatches(input, initialId, path);
            if (input.Length != expectedLength)
                throw new IOException("Staged file changed before read-back: " + entry.Path);
            byte[] buffer = new byte[65_536];
            long size = 0;
            int count;
            try
            {
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    count = input.Read(buffer, 0, buffer.Length);
                    if (count <= 0) break;
                    sha.AppendData(buffer, 0, count);
                    size = checked(size + count);
                }
                if (input.Length != expectedLength)
                    throw new IOException("Staged file length changed during read-back: " + entry.Path);
                // Check the SAME open handle after the last read, too. A
                // replaced pathname cannot redefine the original creator ID.
                WindowsSourceFileIdentity.RequireMatches(input, initialId, path);
                string digest = Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
                if (size != entry.Size || !string.Equals(digest, entry.Sha256, StringComparison.Ordinal))
                    throw new InvalidDataException("Staged file read-back checksum mismatch: " + entry.Path);
            }
            finally { CryptographicOperations.ZeroMemory(buffer); }
        }
        before.Refresh();
        // Recheck after reading because NTFS ADS do not change the unnamed
        // stream's SHA-256; likewise recheck unsupported EFS/sparse/offline
        // attributes. These checks are fail-closed, but still path-based and
        // do not close hostile concurrent rename races (Windows handles needed).
        EnsureNoReparsePoint(path);
        WindowsHardLinkGuard.RejectMultipleLinks(path);
        WindowsZoneIdentifier.Verify(path,entry.ZoneIdentifierBase64,cancellationToken);
        WindowsUnsupportedMetadataGuard.RejectUnsupported(before.Attributes, path);
        if (!before.Exists || before.Length != expectedLength || before.LastWriteTimeUtc != expectedWriteUtc)
            throw new IOException("Staged file changed during read-back: " + entry.Path);
    }

    /// <summary>
    /// Read a repository record (ciphertext OR repo.json) using the SAME opened
    /// file handle for its size and data. A pathname reparse check followed by
    /// FileStream.Open can follow a link swapped in BETWEEN the two operations.
    /// On Windows the actual read handle MUST come from CreateFileW with
    /// OPEN_REPARSE_POINT, and its attributes/link count must be inspected before
    /// reading even a byte. This still does not close parent-directory swaps;
    /// native handle-relative path traversal remains a pre-production blocker.
    /// beforeHandleOpen exists ONLY for deterministic native fault injection.
    /// </summary>
    internal static byte[] ReadBoundedFile(string path, int maxBytes) =>
        ReadBoundedFile(path, maxBytes, beforeHandleOpen: null);

    internal static byte[] ReadBoundedFile(string path, int maxBytes,
        CancellationToken cancellationToken) =>
        ReadBoundedFile(path, maxBytes, beforeHandleOpen: null,
            cancellationToken: cancellationToken);

    // afterReadBlock is an internal native-smoke hook only. A partial buffer
    // is NEVER returned; interruption clears the entire allocated ciphertext.
    internal static byte[] ReadBoundedFile(string path, int maxBytes, Action? beforeHandleOpen,
        CancellationToken cancellationToken = default, Action<int>? afterReadBlock = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (maxBytes < 0) throw new ArgumentOutOfRangeException(nameof(maxBytes));
        EnsureNoReparsePointsInPath(Path.GetDirectoryName(Path.GetFullPath(path))!);
        EnsureNoReparsePoint(path);
        using var stream = WindowsNoFollowSourceReader.Open(path, beforeHandleOpen);
        long expectedLength = stream.Length;
        if (expectedLength > maxBytes)
            throw new InvalidDataException("Encrypted record exceeds maximum size.");
        byte[] bytes = new byte[(int)expectedLength];
        try
        {
            int offset = 0;
            while (offset < bytes.Length)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int count = Math.Min(65_536, bytes.Length - offset);
                stream.ReadExactly(bytes.AsSpan(offset, count));
                offset += count;
                afterReadBlock?.Invoke(offset);
                cancellationToken.ThrowIfCancellationRequested();
            }
            cancellationToken.ThrowIfCancellationRequested();
            if (stream.ReadByte() != -1 || stream.Length != expectedLength)
                throw new InvalidDataException("Encrypted record changed during read.");
            cancellationToken.ThrowIfCancellationRequested();
            return bytes;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
    }

    // Verify the EXACT ciphertext captured from the portable source, not an
    // earlier preflight handle. This gate must precede any destination writes.
    // Decrypted data and HMAC output are cleared even when authentication fails.
    private void AuthenticateCapturedImportedChunk(string id, byte[] ciphertext)
    {
        ValidateObjectId(id);
        byte[] plaintext = Decrypt(ciphertext, ObjectMagic, ObjectAad(id));
        try
        {
            byte[] digest = HMACSHA256.HashData(_key, plaintext);
            try
            {
                if (plaintext.Length is < 1 or > ChunkBytes ||
                    !CryptographicOperations.FixedTimeEquals(digest, Convert.FromHexString(id)))
                    throw new InvalidDataException("Captured imported encrypted object failed authentication.");
            }
            finally { CryptographicOperations.ZeroMemory(digest); }
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    internal static void RequireSafeRepositoryReadPath(string path)=>EnsureNoReparsePointsInPath(path);

    internal byte[] ReadAuthenticatedChunkForReuse(string previousRepository,string id,CancellationToken token)
    {
        CheckNotDisposed();token.ThrowIfCancellationRequested();ValidateObjectId(id);
        byte[] captured=ReadBoundedFile(Path.Combine(previousRepository,"objects",id[..2],id+".obj"),ChunkBytes+HeaderBytes,token);
        try
        {
            AuthenticateCapturedImportedChunk(id,captured);
            token.ThrowIfCancellationRequested();
            return captured;
        }
        catch{CryptographicOperations.ZeroMemory(captured);throw;}
    }

    // Fault observer is ONLY available to friend-assembly native smoke tests.
    // A post-decryption exception/cancel must not strand authenticated plaintext
    // in the managed heap. Normal callers pass null and own the returned bytes.
    private byte[] ReadChunkAndValidate(string id,
        CancellationToken cancellationToken = default, Action<byte[]>? afterDecryption = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateObjectId(id);
        string path = GetObjectPath(id);
        EnsureNoReparsePointsInPath(Path.GetDirectoryName(path)!);
        EnsureNoReparsePoint(path);
        byte[] encrypted = ReadBoundedFile(path, ChunkBytes + HeaderBytes, cancellationToken);
        byte[] data;
        try
        {
            data = Decrypt(encrypted, ObjectMagic, ObjectAad(id));
        }
        finally
        {
            // Ciphertext is not plaintext, but it should not outlive the read.
            CryptographicOperations.ZeroMemory(encrypted);
        }
        try
        {
            afterDecryption?.Invoke(data); // deterministic native smoke only
            cancellationToken.ThrowIfCancellationRequested();
            byte[] digest = HMACSHA256.HashData(_key, data);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(digest, Convert.FromHexString(id)) ||
                    data.Length is < 1 or > ChunkBytes)
                    throw new InvalidDataException("Encrypted object integrity check failed.");
            }
            finally { CryptographicOperations.ZeroMemory(digest); }
            cancellationToken.ThrowIfCancellationRequested();
            return data;
        }
        catch
        {
            // Includes cancellation and any unexpected crypto/validation error
            // AFTER successful AES-GCM. Previously those paths could retain
            // a full 4 MiB plaintext chunk in managed memory.
            CryptographicOperations.ZeroMemory(data);
            throw;
        }
    }

    // Friend-assembly native smoke can deterministically interrupt the exact
    // decrypted-buffer lifetime without exposing the hook to CLI or GUI users.
    internal byte[] ReadChunkAndValidateForSmoke(string id, CancellationToken cancellationToken,
        Action<byte[]> afterDecryption) => ReadChunkAndValidate(id, cancellationToken, afterDecryption);

    private byte[] Encrypt(byte[] plain, byte[] magic, byte[] aad)
    {
        byte[] result = new byte[HeaderBytes + plain.Length];
        magic.CopyTo(result, 0);
        Span<byte> nonce = result.AsSpan(8, NonceBytes);
        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(_key, TagBytes);
        aes.Encrypt(nonce, plain, result.AsSpan(HeaderBytes), result.AsSpan(8 + NonceBytes, TagBytes), aad);
        return result;
    }

    private byte[] Decrypt(byte[] encrypted, byte[] magic, byte[] aad)
    {
        if (encrypted.Length < HeaderBytes || !encrypted.AsSpan(0, 8).SequenceEqual(magic))
            throw new InvalidDataException("Unrecognized encrypted record.");
        byte[] result = new byte[encrypted.Length - HeaderBytes];
        DecryptRecordInto(encrypted, magic, aad, result);
        return result;
    }

    /// <summary>
    /// Never leave a partially populated plaintext buffer in managed memory if
    /// AES-GCM authentication fails (or record shape is invalid). Native smoke
    /// tests inject invalid tags and verify the caller's buffer was cleared.
    /// This is memory hygiene, not an OS guarantee against swapping/dumps.
    /// </summary>
    internal void DecryptRecordInto(byte[] encrypted, byte[] magic, byte[] aad, byte[] result)
    {
        CheckNotDisposed();
        try
        {
            if (encrypted.Length < HeaderBytes || magic.Length != 8 ||
                !encrypted.AsSpan(0, 8).SequenceEqual(magic) ||
                result.Length != encrypted.Length - HeaderBytes)
                throw new InvalidDataException("Unrecognized or inconsistent encrypted record.");
            using var aes = new AesGcm(_key, TagBytes);
            aes.Decrypt(encrypted.AsSpan(8, NonceBytes), encrypted.AsSpan(HeaderBytes),
                encrypted.AsSpan(8 + NonceBytes, TagBytes), result, aad);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(result);
            throw;
        }
    }

    private string GetObjectPath(string id) => Path.Combine(_root, "objects", id[..2], id + ".obj");
    private string GetSnapshotPath(string id) => Path.Combine(_root, "snapshots", id + ".snap");
    private static byte[] ObjectAad(string id) => Encoding.UTF8.GetBytes("ChomcioRecovery/object/v1/" + id);
    private static byte[] SnapshotAad(string id) => Encoding.UTF8.GetBytes("ChomcioRecovery/snapshot/v1/" + id);
    private static bool IsValidId(string id) => id.Length == 32 && id.All(Uri.IsHexDigit) && id == id.ToLowerInvariant();
    private static void ValidateSnapshotId(string id)
    {
        if (!IsValidId(id)) throw new ArgumentException("Invalid snapshot id.");
    }
    private static void ValidateObjectId(string id)
    {
        if (id.Length != 64 || id != id.ToLowerInvariant() || !id.All(Uri.IsHexDigit))
            throw new InvalidDataException("Invalid chunk id.");
    }
    /// <summary>
    /// The caller also chooses the final output NAME. Reject device aliases,
    /// ADS separators, and names normalized by Win32 before any staged output
    /// is written. This check is lexical, not Windows handle-race protection.
    /// </summary>
    internal static void ValidatePublicationDestination(string destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        // Check the caller-supplied leaf BEFORE any OS path normalization. A
        // normalized path alone can conceal a trailing-dot/space alias.
        string leaf = Path.GetFileName(Path.TrimEndingDirectorySeparator(destination));
        try { ValidateRelativePath(leaf); }
        catch (InvalidDataException ex)
        {
            throw new InvalidDataException("Unsafe publication destination name.", ex);
        }
    }

    // Tested by the native smoke suite; reject Win32 DOS-device aliases
    // BEFORE any file path can reach a restore or backup FileStream.
    internal static void ValidateRelativePath(string value)
    {
        if (string.IsNullOrEmpty(value) || value.StartsWith('/') || value.Contains('\\') ||
            value.Any(x => x is '\0' or ':' or '<' or '>' or '"' or '|' or '?' or '*'))
            throw new InvalidDataException("Unsafe relative path in snapshot.");
        foreach (string component in value.Split('/'))
        {
            if (component is "" or "." or ".." || component.EndsWith(' ') || component.EndsWith('.') ||
                component.Any(char.IsControl))
                throw new InvalidDataException("Unsafe relative path component.");
            // Win32 can ignore spaces just before a file extension when
            // resolving reserved DOS-device aliases (e.g. COM1 .txt).
            string basename = component.Split('.')[0].TrimEnd(' ').ToUpperInvariant();
            // Win32 also treats the Latin-1 superscript digits ¹²³ as valid
            // serial/parallel device numbers; CONIN$ and CONOUT$ are console
            // device aliases. An extension does NOT make these names safe.
            // In particular COM¹.txt and conout$.txt must fail closed.
            if (basename is "CON" or "PRN" or "AUX" or "NUL" or "CONIN$" or "CONOUT$" ||
                basename is "COM1" or "COM2" or "COM3" or "COM4" or "COM5" or "COM6" or "COM7" or "COM8" or "COM9" ||
                basename is "LPT1" or "LPT2" or "LPT3" or "LPT4" or "LPT5" or "LPT6" or "LPT7" or "LPT8" or "LPT9" ||
                basename is "COM¹" or "COM²" or "COM³" or "LPT¹" or "LPT²" or "LPT³")
                throw new InvalidDataException("Windows reserved device filename.");
        }
    }
    /// <summary>
    /// The authenticated manifest gives the logical file size and ordered chunk
    /// IDs. A legitimate encoder emits exactly ChunkBytes for every nonfinal
    /// chunk and exactly the remaining bytes for the last one. Reject a signed
    /// but inconsistent layout BEFORE plaintext reaches the restore stage; also
    /// apply the same rule during VERIFY/backup publication/import.
    /// </summary>
    internal static void RequireCanonicalChunkLength(long fileSize, int index,
        int numberOfChunks, int actualBytes)
    {
        if (fileSize <= 0 || numberOfChunks <= 0 || index < 0 || index >= numberOfChunks ||
            numberOfChunks != (fileSize - 1) / ChunkBytes + 1 || actualBytes <= 0)
            throw new InvalidDataException("Invalid authenticated chunk layout.");
        long remaining = fileSize - (long)index * ChunkBytes;
        long expected = Math.Min((long)ChunkBytes, remaining);
        if (actualBytes != expected)
            throw new InvalidDataException("Noncanonical encrypted chunk length before restore write.");
    }

    internal static void ValidateEntries(IEnumerable<FileEntry> entries)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (FileEntry entry in entries)
        {
            ValidateRelativePath(entry.Path);
            if (!seen.Add(entry.Path) || entry.Size < 0 || entry.Sha256.Length != 64 ||
                !entry.Sha256.All(Uri.IsHexDigit) || entry.Chunks is null ||
                entry.Chunks.Count != (entry.Size == 0 ? 0 : (entry.Size - 1) / ChunkBytes + 1))
                throw new InvalidDataException("Invalid snapshot file entry.");
            foreach (string chunk in entry.Chunks) ValidateObjectId(chunk);
            WindowsZoneIdentifier.Validate(entry.ZoneIdentifierBase64);
        }
        // Legacy v1 snapshots do not list directories explicitly. Without this
        // check an authenticated manifest containing both file "a" and file
        // "a/b" passes VERIFY, but cannot ever be RESTORED on Windows or Linux.
        // Apply the same rule to all versions, ignoring Windows case aliases.
        foreach (string path in seen)
        {
            int slash = path.LastIndexOf('/');
            while (slash >= 0)
            {
                string ancestor = path[..slash];
                if (seen.Contains(ancestor))
                    throw new InvalidDataException("Snapshot file is also an ancestor directory: " + ancestor);
                slash = ancestor.LastIndexOf('/');
            }
        }
    }
    /// <summary>
    /// Reject a malformed authenticated directory inventory before any restore
    /// creates a visible tree. Every v2 parent must be explicitly represented;
    /// file-versus-folder aliases are forbidden under Windows case semantics.
    /// Legacy v1 intentionally carries no directories and is still restorable.
    /// </summary>
    internal static void ValidateDirectoryTree(IReadOnlyList<FileEntry> files,
        List<string>? directories, int version)
    {
        if (version == 1)
        {
            if (directories is { Count: > 0 })
                throw new InvalidDataException("v1 snapshot cannot contain directories.");
            return;
        }
        if (version is not (2 or 3) || directories is null)
            throw new InvalidDataException("v2 snapshot requires a directory inventory.");
        var directoryNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string directory in directories)
        {
            ValidateRelativePath(directory);
            if (!directoryNames.Add(directory))
                throw new InvalidDataException("Duplicate snapshot directory.");
        }
        var allNames = new HashSet<string>(directoryNames, StringComparer.OrdinalIgnoreCase);
        foreach (FileEntry file in files)
            if (!allNames.Add(file.Path))
                throw new InvalidDataException("Snapshot file collides with directory.");

        static void RequireParents(string path, HashSet<string> names)
        {
            int slash = path.LastIndexOf('/');
            while (slash >= 0)
            {
                string parent = path[..slash];
                if (!names.Contains(parent))
                    throw new InvalidDataException("Snapshot contains missing parent directory.");
                slash = parent.LastIndexOf('/');
            }
        }
        foreach (string directory in directoryNames)
            RequireParents(directory, directoryNames);
        foreach (FileEntry file in files)
            RequireParents(file.Path, directoryNames);
    }

    // The full-tree inventory can enumerate tens of thousands of files on slow
    // disks. STOP must interrupt enumeration, not wait until every path has
    // been visited. afterVisitedEntry is test-only deterministic fault injection.
    internal static Dictionary<string, SourceStamp> CaptureSourceInventory(string source,
        CancellationToken cancellationToken = default, Action<int>? afterVisitedEntry = null,
        bool skipSystemDirectoryLinks = false,bool preserveZoneIdentifiers=false)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string root = Path.GetFullPath(source);
        EnsureNoReparsePointsInPath(root);
        if (!Directory.Exists(root)) throw new DirectoryNotFoundException(root);
        var inventory = new Dictionary<string, SourceStamp>(
            OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        Stack<string> dirs = new();
        dirs.Push(root);
        int visitedEntries = 0;
        while (dirs.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string folder = dirs.Pop();
            EnsureNoReparsePoint(folder);
            WindowsAlternateStreamGuard.RejectUnsupportedStreams(folder, isDirectory: true);
            var dir = new DirectoryInfo(folder);
            WindowsUnsupportedMetadataGuard.RejectUnsupported(dir.Attributes, folder);
            string relativeDir = Path.GetRelativePath(root, folder).Replace('\\', '/');
            if (relativeDir != ".") ValidateRelativePath(relativeDir);
            inventory.Add("d/" + relativeDir, new SourceStamp(true, 0,
                dir.LastWriteTimeUtc, dir.CreationTimeUtc, dir.Attributes));
            cancellationToken.ThrowIfCancellationRequested();
            foreach (string child in Directory.EnumerateFileSystemEntries(folder))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var childAttributes=File.GetAttributes(child);
                if(skipSystemDirectoryLinks&&IsSystemDirectoryLink(childAttributes))
                {
                    // Never traverse the link or read its target. Keep its path
                    // in the encrypted manifest and every subsequent inventory.
                    // If it changes to a normal entry, inventory equality fails.
                    string skipped=Path.GetRelativePath(root,child).Replace('\\','/');
                    ValidateRelativePath(skipped);
                    inventory.Add("s/"+skipped,new SourceStamp(true,0,DateTime.MinValue,
                        DateTime.MinValue,childAttributes));
                    afterVisitedEntry?.Invoke(checked(++visitedEntries));
                    cancellationToken.ThrowIfCancellationRequested();
                    continue;
                }
                EnsureNoReparsePoint(child);
                if (Directory.Exists(child))
                {
                    dirs.Push(child);
                }
                else if (File.Exists(child))
                {
                    // The snapshot format does not encode named NTFS streams;
                    // refuse the source rather than claiming a complete backup.
                    string? zone=null;
                    if(preserveZoneIdentifiers)zone=WindowsZoneIdentifier.Read(child,cancellationToken);
                    else WindowsAlternateStreamGuard.RejectUnsupportedStreams(child);
                    WindowsHardLinkGuard.RejectMultipleLinks(child);
                    var info = new FileInfo(child);
                    WindowsUnsupportedMetadataGuard.RejectUnsupported(info.Attributes, child);
                    string relative = Path.GetRelativePath(root, child).Replace('\\', '/');
                    ValidateRelativePath(relative);
                    // Capture the physical NTFS/ReFS file identity via a
                    // no-follow handle. Stat-only stamps can be copied by a
                    // newly substituted ordinary file of identical metadata.
                    var fileIdentity = WindowsSourceFileIdentity.CaptureFile(child);
                    inventory.Add("f/" + relative, new SourceStamp(false, info.Length,
                        info.LastWriteTimeUtc, info.CreationTimeUtc, info.Attributes, fileIdentity,WindowsZoneIdentifier.Fingerprint(zone)));
                }
                else throw new IOException("Unsupported or disappearing source entry: " + child);
                afterVisitedEntry?.Invoke(checked(++visitedEntries));
                cancellationToken.ThrowIfCancellationRequested();
            }
        }
        cancellationToken.ThrowIfCancellationRequested();
        return inventory;
    }

    internal static void ThrowIfSourceInventoryChanged(string source,
        IReadOnlyDictionary<string, SourceStamp> expected,
        CancellationToken cancellationToken = default, Action<int>? afterVisitedEntry = null,
        bool skipSystemDirectoryLinks = false,bool preserveZoneIdentifiers=false)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var current = CaptureSourceInventory(source, cancellationToken, afterVisitedEntry, skipSystemDirectoryLinks,preserveZoneIdentifiers);
        if (current.Count != expected.Count)
            throw new IOException("Source file/directory inventory changed during backup.");
        foreach (var item in expected)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!current.TryGetValue(item.Key, out SourceStamp? actual) || actual != item.Value)
                throw new IOException("Source file/directory inventory changed during backup.");
        }
        cancellationToken.ThrowIfCancellationRequested();
    }

    /// <summary>
    /// Fail-closed final source content check: matching file names, sizes and
    /// timestamps is NOT sufficient. A writer can change bytes in place and
    /// restore the previous LastWriteTimeUtc, leaving SourceStamp identical.
    /// Rehash every source file immediately before publishing the manifest.
    /// This is a best-effort live-tree check; only a volume snapshot or pinned
    /// file handles provide coherent source isolation against active writers.
    /// </summary>
    internal static void VerifySourceContents(string sourceDirectory,
        IReadOnlyList<FileEntry> entries,
        IReadOnlyDictionary<string, SourceStamp> initialInventory,
        CancellationToken cancellationToken = default, bool skipSystemDirectoryLinks = false,bool preserveZoneIdentifiers=false,
        IProgress<VaultProgress>? progress=null,VaultProgressStage stage=VaultProgressStage.CheckingSource)
    {
        string source = Path.GetFullPath(sourceDirectory);
        ThrowIfSourceInventoryChanged(source, initialInventory, cancellationToken, skipSystemDirectoryLinks:skipSystemDirectoryLinks,preserveZoneIdentifiers:preserveZoneIdentifiers);
        var sourceProgress=new VaultProgressReporter(progress,stage,progress is null?0:entries.Sum(x=>x.Size));
        foreach (FileEntry entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ValidateRelativePath(entry.Path);
            string path = Path.GetFullPath(Path.Combine(source,
                entry.Path.Replace('/', Path.DirectorySeparatorChar)));
            if (!IsInside(source, path) || path == source)
                throw new InvalidDataException("Unsafe source file path.");
            EnsureNoReparsePointsInPath(Path.GetDirectoryName(path)!);
            EnsureNoReparsePoint(path);
            WindowsZoneIdentifier.Verify(path,entry.ZoneIdentifierBase64,cancellationToken);
            WindowsHardLinkGuard.RejectMultipleLinks(path);
            WindowsUnsupportedMetadataGuard.RejectUnsupported(File.GetAttributes(path), path);
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using var input = WindowsNoFollowSourceReader.Open(path);
            if (!initialInventory.TryGetValue("f/" + entry.Path, out SourceStamp? initialFile) ||
                initialFile.Directory)
                throw new IOException("Source file absent from initial inventory: " + entry.Path);
            WindowsSourceFileIdentity.RequireMatches(input, initialFile.FileIdentity, path);
            byte[] buffer = new byte[65_536];
            long totalBytes = 0;
            try
            {
                int count;
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    count = input.Read(buffer, 0, buffer.Length);
                    if (count <= 0) break;
                    sha.AppendData(buffer, 0, count);
                    totalBytes = checked(totalBytes + count);
                    sourceProgress.Advance(count);
                }
            }
            finally { CryptographicOperations.ZeroMemory(buffer); }
            string digest = Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
            if (totalBytes != entry.Size ||
                !string.Equals(digest, entry.Sha256, StringComparison.Ordinal))
                throw new IOException("Source contents changed during backup: " + entry.Path);
        }
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfSourceInventoryChanged(source, initialInventory, cancellationToken, skipSystemDirectoryLinks:skipSystemDirectoryLinks,preserveZoneIdentifiers:preserveZoneIdentifiers);
    }

    private static void ValidateZoneIdentifierVersion(Snapshot snapshot)
    {
        bool hasZone=snapshot.Files.Any(f=>f.ZoneIdentifierBase64 is not null);
        if((snapshot.Version==3)!=hasZone)
            throw new InvalidDataException("Zone.Identifier requires snapshot v3; older readers must refuse it.");
    }
    internal static bool IsSystemDirectoryLink(FileAttributes attributes)
    {
        const FileAttributes required=FileAttributes.Directory|FileAttributes.ReparsePoint|
            FileAttributes.System|FileAttributes.Hidden;
        return OperatingSystem.IsWindows()&&(attributes&required)==required;
    }
    private static void ValidateSkippedSystemDirectoryLinks(Snapshot snapshot)
    {
        if(snapshot.SkippedSystemDirectoryLinks is not {Count:>0} skipped)return;
        var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(string name in skipped)
        {
            ValidateRelativePath(name);
            if(!names.Add(name))throw new InvalidDataException("Duplicate skipped system link.");
            if(snapshot.Files.Any(f=>f.Path.Equals(name,StringComparison.OrdinalIgnoreCase)||
                    f.Path.StartsWith(name+"/",StringComparison.OrdinalIgnoreCase))||
                snapshot.Directories?.Any(d=>d.Equals(name,StringComparison.OrdinalIgnoreCase)||
                    d.StartsWith(name+"/",StringComparison.OrdinalIgnoreCase))==true)
                throw new InvalidDataException("Skipped system link conflicts with stored data.");
        }
    }

    private static void EnsureNoReparsePoint(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Symlinks/junctions are not supported: " + path);
    }
    private static void EnsureNoReparsePointsInPath(string path)
    {
        DirectoryInfo? directory = new(Path.GetFullPath(path));
        while (directory is not null)
        {
            if (directory.Exists && (directory.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Symlink/junction in directory ancestry: " + directory.FullName);
            directory = directory.Parent;
        }
    }

    /// <summary>
    /// Deny all source/destination operations when the selected path is inside
    /// (or contains) the encrypted repository. Canonicalize BOTH sides before
    /// comparison: a caller may supply `existing-folder/../repository/output`.
    /// On Windows additionally reject aliases using physical directory IDs,
    /// including NTFS 8.3 short names. The preflight is not atomic isolation
    /// against concurrent rename/reparse-point swaps or same-user writers.
    /// </summary>
    internal static void EnsureRepositoryPathDisjoint(string repository, string requestedPath)
    {
        string root = Path.GetFullPath(repository);
        string target = Path.GetFullPath(requestedPath);
        if (IsInside(root, target) || IsInside(target, root))
            throw new IOException("Selected source/destination overlaps repository.");
        // Windows short (8.3) names can denote an existing repository or its
        // ancestor without matching its long pathname lexically. Compare real
        // opened directory IDs before any backup/import/restore/export I/O.
        WindowsRepositoryOverlapGuard.RejectPhysicalOverlap(root, target);
    }

    private static bool IsInside(string directory, string path)
    {
        string d = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        string p = Path.GetFullPath(path);
        StringComparison comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        // Path.TrimEndingDirectorySeparator preserves volume roots (C:\, /,
        // \\server\share\). Adding ANOTHER separator turns C:\ into C:\\,
        // so a drive-root source was incorrectly treated as disjoint from
        // C:\users\...\repository and could trigger self-backup recursion.
        // Keep the existing root separator; add one only for non-root folders.
        string prefix = Path.EndsInDirectorySeparator(d) ? d : d + Path.DirectorySeparatorChar;
        return p.Equals(d, comparison) || p.StartsWith(prefix, comparison);
    }
    internal static int ReadChunk(Stream stream, byte[] buffer,
        CancellationToken cancellationToken = default)
    {
        // Bound each blocking read to 64 KiB and check cancellation both before
        // and AFTER it returns. A stop requested while the OS was reading must
        // not allow those returned bytes to proceed to encryption/publication.
        int count = 0;
        while (count < buffer.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int requested = Math.Min(65_536, buffer.Length - count);
            int read = stream.Read(buffer, count, requested);
            cancellationToken.ThrowIfCancellationRequested();
            if (read <= 0) break;
            count += read;
        }
        return count;
    }
    /// <summary>
    /// Writes an encrypted record DIRECTLY into an unpublished, ACL-protected
    /// portable-export stage so its ORIGINAL creator FileId can be registered
    /// before the exclusive writer closes. Unlike general WriteAtomic, a failed
    /// direct write is safe here because the entire stage stays private and
    /// NEVER reaches the final destination until all records are verified.
    /// Recording original file ownership makes non-destructive failure cleanup
    /// possible; no guessed path-recursive delete on Windows is permitted.
    /// </summary>
    private static void WriteOwnedPrivateExportRecord(string stageRoot, string path,
        byte[] data, WindowsOwnedRestoreTreeCleanup inventory,
        WindowsPrivateRestoreStageGuard originalRoot,
        CancellationToken cancellationToken = default,
        Action<string, int>? afterPrivateRecordBlock = null)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Original export record cleanup needs Windows.");
        ArgumentNullException.ThrowIfNull(data);
        cancellationToken.ThrowIfCancellationRequested();
        string parent = Path.GetDirectoryName(path)
            ?? throw new IOException("Private export record lacks parent.");
        using var parentLease = inventory.PinOwnedParentForWrite(parent, originalRoot);
        parentLease.RequireMatches();
        using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                   bufferSize: 65_536, options: FileOptions.WriteThrough))
        {
            // Before writing: record the FileId directly from the ORIGINAL
            // FileStream handle, not from a later pathname query.
            inventory.TrackCreatedFile(path, output.SafeFileHandle);
            int block = 0;
            for (int offset = 0; offset < data.Length;)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int count = Math.Min(65_536, data.Length - offset);
                output.Write(data.AsSpan(offset, count));
                offset += count;
                // Deterministic native smoke injection, never public API.
                // Even if cancellation arrives DURING a completed OS write,
                // it must prevent remaining ciphertext and stage publication.
                afterPrivateRecordBlock?.Invoke(path, ++block);
                cancellationToken.ThrowIfCancellationRequested();
            }
            cancellationToken.ThrowIfCancellationRequested();
            output.Flush(flushToDisk: true);
        }
        originalRoot.RequireMatches(stageRoot);
        parentLease.RequireMatches();
        // Independently re-open the STAGED bytes before the authenticated
        // exported-vault verification and eventual directory publication.
        byte[] buffer = new byte[65_536];
        try
        {
            using var reader = WindowsNoFollowSourceReader.Open(path);
            if (reader.Length != data.Length)
                throw new IOException("Owned private export record readback length mismatch.");
            for (int offset = 0; offset < data.Length;)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int count = Math.Min(buffer.Length, data.Length - offset);
                reader.ReadExactly(buffer.AsSpan(0, count));
                cancellationToken.ThrowIfCancellationRequested();
                if (!buffer.AsSpan(0, count).SequenceEqual(data.AsSpan(offset, count)))
                    throw new IOException("Owned private export record readback byte mismatch.");
                offset += count;
            }
            if (reader.ReadByte() != -1 || reader.Length != data.Length)
                throw new IOException("Owned private export record mutated during readback.");
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
        parentLease.RequireMatches();
        originalRoot.RequireMatches(stageRoot);
    }

    /// <summary>
    /// Publish an immutable ciphertext/configuration record only after a SECOND
    /// read of the flushed temporary file matches the bytes we intended to
    /// store. This catches torn/short/altered writes before the record becomes
    /// visible. It does not prove crash durability or atomic path isolation
    /// against another process which can modify the repository as this user.
    /// The optional callback is used only by the native smoke fault injector.
    /// </summary>
    internal static void WriteAtomic(string path, byte[] data, Action<string>? beforeReadback = null,
        CancellationToken cancellationToken = default, Action<string>? whileOwnedHandlePinned = null,
        Action<string>? afterOriginalWriterClosed = null,
        Action<WindowsSourceFileIdentity.Identity?>? afterOwnedPublished = null, Action? afterTempCreated = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(data);
        // The immutable object/snapshot must not be written through an existing
        // junction to an unrelated filesystem directory. This rejects links
        // already present at check time; full swap-race protection needs native
        // handle-based Windows primitives before production use.
        string parent = Path.GetDirectoryName(path)
                        ?? throw new IOException("Record has no parent directory.");
        EnsureNoReparsePointsInPath(parent);
        // Pin EVERY ancestor before creating the ciphertext temp. Holding
        // FILE_LIST_DIRECTORY (not attributes-only) without SHARE_DELETE blocks
        // ordinary directory/ancestor rename or junction retarget during the
        // entire write, readback, publication and failure cleanup. This is not
        // protection against pre-existing privileged handles or power loss.
        using var pinnedRecordParent = WindowsRestoreParentPin.Acquire(parent);
        pinnedRecordParent.RequireMatches();
        string temp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        WindowsSourceFileIdentity.Identity? originalTempIdentity = null;
        try
        {
            // The previously delayed CaptureFile(temp) after FileStream.Dispose
            // could ADOPT a foreign same-byte file that a same-user actor had
            // substituted between creator close and pathname capture. Bind
            // ownership to the exact FILE_OBJECT from FileMode.CreateNew,
            // while exclusive sharing still prevents rename/replacement.
            // ReadWrite includes FILE_READ_ATTRIBUTES for FILE_ID_INFO on NTFS.
            using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None,
                bufferSize: 65_536, options: FileOptions.WriteThrough))
            {
                if (OperatingSystem.IsWindows())
                    originalTempIdentity = WindowsSourceFileIdentity.Capture(output.SafeFileHandle);
                afterTempCreated?.Invoke();
                for (int offset = 0; offset < data.Length;)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    int count = Math.Min(65_536, data.Length - offset);
                    output.Write(data.AsSpan(offset, count));
                    offset += count;
                }
                output.Flush(flushToDisk: true);
            }
            // Native fault injection: move the just-closed original file and
            // put byte-identical foreign ciphertext under its old pathname.
            // No post-close pathname can establish our ORIGINAL ownership.
            afterOriginalWriterClosed?.Invoke(temp);
            beforeReadback?.Invoke(temp);
            cancellationToken.ThrowIfCancellationRequested();
            WindowsRecordStageGuard.RequireOriginalTemp(temp, originalTempIdentity);
            // A fresh opened handle is required: do not trust the output stream's
            // write counts or a separate path-based Length followed by Open().
            // Use the same no-follow metadata checks as encrypted record reads.
            EnsureNoReparsePointsInPath(parent);
            byte[] readback = new byte[65_536];
            try
            {
                using var input = WindowsNoFollowSourceReader.Open(temp);
                if (input.Length != data.Length)
                    throw new IOException("Atomic record read-back length mismatch; not published.");
                int offset = 0;
                while (offset < data.Length)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    int requested = Math.Min(readback.Length, data.Length - offset);
                    input.ReadExactly(readback.AsSpan(0, requested));
                    if (!readback.AsSpan(0, requested).SequenceEqual(data.AsSpan(offset, requested)))
                        throw new IOException("Atomic record read-back byte mismatch; not published.");
                    offset += requested;
                }
                if (input.ReadByte() != -1 || input.Length != data.Length)
                    throw new IOException("Atomic record read-back changed during verification; not published.");
            }
            finally { CryptographicOperations.ZeroMemory(readback); }
            EnsureNoReparsePointsInPath(parent);
            pinnedRecordParent.RequireMatches();
            WindowsRecordStageGuard.RequireOriginalTemp(temp, originalTempIdentity);
            // The final cancellable boundary is BEFORE the atomic no-clobber
            // publication. Never report cancellation after the name is visible.
            cancellationToken.ThrowIfCancellationRequested();
            if (OperatingSystem.IsWindows())
            {
                // The earlier pathname-only File.Move had a final TOCTOU gap:
                // another same-user actor could replace temp AFTER the last
                // identity check, but BEFORE File.Move resolved its pathname.
                // Use the verified ORIGINAL opened FileId + DELETE handle for
                // no-replace FileRenameInfo. Never fall back to File.Move if the
                // native identity, share mode or rename is rejected.
                WindowsOwnedRecordPublisher.Publish(temp, path, data,
                    originalTempIdentity, cancellationToken, whileOwnedHandlePinned);
            }
            else
            {
                File.Move(temp, path); // No overwrite on supported Unix filesystems.
            }
            // Report the ORIGINAL writer-created FILE_OBJECT identity, captured
            // before any bytes were written. A caller must never infer this
            // identity by opening a mutable final pathname after rename.
            afterOwnedPublished?.Invoke(originalTempIdentity);
        }
        finally
        {
            // Never speculatively unlink another actor's file swapped into
            // the randomized temporary name. An unverified leftover is safer
            // than deleting a user file. Windows identity checks are native.
            WindowsRecordStageGuard.CleanupOnlyOriginalTemp(temp, originalTempIdentity);
        }
    }
    /// <summary>
    /// Reopen the FINAL pathname after an immutable encrypted record was made
    /// visible, not just the .tmp stage verified by WriteAtomic. A changed,
    /// shortened, linked or unreadable published record must never be reported
    /// as a successful backup/import. On a readback failure the published name
    /// may still exist; never delete it blindly (another actor may own it).
    /// The callback is only for deterministic native smoke fault injection.
    /// This is not crash durability or adversarial rename-race isolation.
    /// </summary>
    internal static void WriteAtomicAndVerifyPublished(string path, byte[] data,
        Action<string>? afterPublished = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        WindowsSourceFileIdentity.Identity? originalPublishedIdentity = null;
        WriteAtomic(path, data, cancellationToken: cancellationToken,
            afterOwnedPublished: identity => originalPublishedIdentity = identity);
        // Keep the entire destination ancestor chain from being renamed while
        // the native fault hook and final readback resolve the final filename.
        // Do not claim success from a byte-identical FOREIGN FILE_OBJECT.
        string publishedParent = Path.GetDirectoryName(Path.GetFullPath(path))
            ?? throw new IOException("Published record has no parent directory.");
        using var pinnedPublishedParent = WindowsRestoreParentPin.Acquire(publishedParent);
        pinnedPublishedParent.RequireMatches();
        afterPublished?.Invoke(path);
        // Publication is already visible here. If STOP arrived at/after the
        // rename, refuse to report success but NEVER remove the published name
        // blindly: it could have been replaced by another FILE_OBJECT.
        cancellationToken.ThrowIfCancellationRequested();
        using var published = WindowsNoFollowSourceReader.Open(path);
        if (OperatingSystem.IsWindows() &&
            (!originalPublishedIdentity.HasValue ||
             WindowsSourceFileIdentity.Capture(published) != originalPublishedIdentity.Value))
            throw new IOException("Published record was replaced after the original no-replace rename.");
        if (published.Length != data.Length)
            throw new IOException("Published encrypted record length changed; operation not confirmed.");
        byte[] readback = new byte[65_536];
        try
        {
            for (int offset = 0; offset < data.Length;)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int count = Math.Min(readback.Length, data.Length - offset);
                published.ReadExactly(readback.AsSpan(0, count));
                if (!readback.AsSpan(0, count).SequenceEqual(data.AsSpan(offset, count)))
                    throw new IOException("Published encrypted record changed during final readback; operation not confirmed.");
                offset += count;
            }
            cancellationToken.ThrowIfCancellationRequested();
            if (published.ReadByte() != -1 || published.Length != data.Length)
                throw new IOException("Published encrypted record changed during final readback; operation not confirmed.");
            if (OperatingSystem.IsWindows() &&
                WindowsSourceFileIdentity.Capture(published) != originalPublishedIdentity!.Value)
                throw new IOException("Published record physical identity changed during final readback.");
            pinnedPublishedParent.RequireMatches();
            cancellationToken.ThrowIfCancellationRequested();
        }
        finally { CryptographicOperations.ZeroMemory(readback); }
    }

    private void CheckNotDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(LocalEncryptedVault));
    }
    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_key);
        CryptographicOperations.ZeroMemory(_openedConfigFingerprint);
        _disposed = true;
    }
}
