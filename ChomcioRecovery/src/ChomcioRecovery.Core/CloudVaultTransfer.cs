using System.Security.Cryptography;

namespace ChomcioRecovery.Core;

/// <summary>
/// Immutable encrypted records, resumable between objects (at most one 4-MiB
/// chunk is retransmitted). Re-download every reused/uploaded record before
/// publishing the snapshot last. No remote deletion or overwrite API exists.
/// </summary>
public sealed class CloudVaultTransfer(ICloudVault remote)
{
    private const int ManifestLimit = 64 * 1024 * 1024 + 36;
    private const int ObjectLimit = LocalEncryptedVault.ChunkBytes + 4096;

    public Task UploadSnapshotAsync(string repository, string password, string snapshotId,
        string newEncryptedStaging, IProgress<CloudProgress>? progress, CancellationToken token)
        => UploadSnapshotAsync(repository, password, snapshotId, newEncryptedStaging, progress, token, null);

    public async Task UploadSnapshotAsync(string repository, string password, string snapshotId,
        string newEncryptedStaging, IProgress<CloudProgress>? progress, CancellationToken token,
        IProgress<VaultProgress>? preparationProgress)
    {
        token.ThrowIfCancellationRequested();
        // Multi-GB local verification/export must not block the caller's UI
        // thread. Await its completion before the first remote operation.
        await Task.Run(() =>
        {
            using var vault = LocalEncryptedVault.Open(repository, password);
            vault.VerifySnapshot(snapshotId, token, preparationProgress);
            // Export is independently verified; cancellation is observed again
            // before any network operation. Its short local commit is atomic.
            vault.ExportEncryptedSnapshot(snapshotId, newEncryptedStaging, token, preparationProgress);
        }, token);
        token.ThrowIfCancellationRequested();
        var files = Directory.EnumerateFiles(newEncryptedStaging, "*", SearchOption.AllDirectories)
            .OrderBy(p => Path.GetFileName(p) == "repo.json" ? 0 : p.EndsWith(".snap", StringComparison.Ordinal) ? 2 : 1)
            .ThenBy(p => p, StringComparer.Ordinal).ToArray();
        var paths = files.ToDictionary(p => RemoteName(Path.GetRelativePath(newEncryptedStaging, p).Replace('\\', '/')),
            p => p, StringComparer.Ordinal);
        await UploadRecordsAsync(paths.Keys.ToArray(), name => LocalEncryptedVault.ReadBoundedFile(paths[name],
            name == "repo.json" ? 16_384 : name.EndsWith(".snap", StringComparison.Ordinal) ? ManifestLimit : ObjectLimit, token),
            progress, token);
    }

    /// <summary>
    /// Resume from a preserved export without allocating another full copy.
    /// Authenticate its lineage, selected manifest and complete contents before
    /// network I/O, and authenticate each captured record again before use.
    /// Existing inputs are never repaired, overwritten or deleted on failure.
    /// </summary>
    public async Task UploadPreparedSnapshotAsync(string repository, string password, string snapshotId,
        string existingEncryptedExport, IProgress<CloudProgress>? progress, CancellationToken token,
        IProgress<VaultProgress>? preparationProgress = null)
    {
        token.ThrowIfCancellationRequested();
        using var source = await Task.Run(() => LocalEncryptedVault.Open(repository, password), token);
        using var prepared = await Task.Run(() => source.OpenPreparedCloudExport(snapshotId,
            existingEncryptedExport, token, preparationProgress), token);
        await UploadRecordsAsync(prepared.Names, name => prepared.ReadRecord(name, token), progress, token);
    }

    private async Task UploadRecordsAsync(IReadOnlyList<string> names, Func<string, byte[]> readRecord,
        IProgress<CloudProgress>? progress, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var index = UniqueIndex(await remote.ListAsync(token));
        int completed = 0;
        long bytes = 0;
        foreach (string name in names)
        {
            token.ThrowIfCancellationRequested();
            byte[] expected = await Task.Run(() => readRecord(name), token);
            try
            {
                if (!index.TryGetValue(name, out var file))
                {
                    progress?.Report(new("Wysyłanie zaszyfrowanych danych", completed, names.Count, bytes));
                    token.ThrowIfCancellationRequested();
                    using var input = new MemoryStream(expected, writable: false);
                    file = await remote.UploadAsync(name, input, expected.Length, token);
                    if (file.Name != name || file.Length != expected.Length)
                        throw new InvalidDataException("Serwer nie potwierdził tożsamości przesłanego fragmentu.");
                    index.Add(name, file);
                }
                if (file.Length != expected.Length)
                    throw new InvalidDataException("W chmurze istnieje inny plik o tej samej nazwie. Niczego nie nadpisano.");
                progress?.Report(new("Sprawdzanie danych pobranych z Chomikuj", completed, names.Count, bytes));
                token.ThrowIfCancellationRequested();
                using var readback = new MemoryStream();
                await remote.DownloadAsync(file, readback, expected.Length, token);
                token.ThrowIfCancellationRequested();
                if (!readback.ToArray().AsSpan().SequenceEqual(expected))
                    throw new InvalidDataException("Dane pobrane z chmury różnią się od wysłanych. Kopia nie jest potwierdzona.");
                bytes = checked(bytes + expected.Length);
                completed++;
                progress?.Report(new("Sprawdzono", completed, names.Count, bytes));
            }
            finally { CryptographicOperations.ZeroMemory(expected); }
        }
    }

    public async Task<IReadOnlyList<string>> ListSnapshotsAsync(CancellationToken token)
    {
        var names=await remote.ListNamesAsync(token);
        var unique=new HashSet<string>(names,StringComparer.Ordinal);
        if(unique.Count!=names.Count)throw new InvalidDataException("Powielona nazwa w folderze kopii. Wybierz odrębny folder dla jednego sejfu.");
        if (!unique.Contains("repo.json")) return Array.Empty<string>();
        return unique.Where(n => n.Length == 37 && n.EndsWith(".snap", StringComparison.Ordinal)
            && n[..32].All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f'))
            .Select(n => n[..32]).OrderBy(n => n, StringComparer.Ordinal).ToArray();
    }

    public Task DownloadSnapshotAsync(string snapshotId, string password, string newRepository,
        IProgress<CloudProgress>? progress, CancellationToken token)
        => DownloadSnapshotAsync(snapshotId,password,newRepository,progress,token,null);

    // A failed attempt is a read-only source, never an output to reopen or
    // overwrite. Metadata is fetched afresh; reuse is authenticated with the
    // current cloud vault key and expected object ID before any copied write.
    public async Task DownloadSnapshotAsync(string snapshotId, string password, string newRepository,
        IProgress<CloudProgress>? progress, CancellationToken token,string? previousRepository)
    {
        token.ThrowIfCancellationRequested();
        if (snapshotId.Length != 32 || !snapshotId.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f'))
            throw new ArgumentException("Niepoprawny identyfikator kopii.");
        if (Directory.Exists(newRepository) || File.Exists(newRepository))
            throw new IOException("Pobieranie wymaga nowego katalogu.");
        if(previousRepository is not null)
        {
            previousRepository=Path.GetFullPath(previousRepository);
            if(!Directory.Exists(previousRepository))throw new DirectoryNotFoundException("Brak wcześniejszej próby pobierania.");
            LocalEncryptedVault.RequireSafeRepositoryReadPath(previousRepository);
            LocalEncryptedVault.EnsureRepositoryPathDisjoint(previousRepository,newRepository);
        }
        var index = UniqueIndex(await remote.ListAsync(token));
        if (!index.ContainsKey("repo.json") || !index.ContainsKey(snapshotId + ".snap"))
            throw new InvalidDataException("Niekompletna kopia w chmurze.");
        Directory.CreateDirectory(newRepository);
        Directory.CreateDirectory(Path.Combine(newRepository, "objects"));
        Directory.CreateDirectory(Path.Combine(newRepository, "snapshots"));
        await Fetch("repo.json", Path.Combine(newRepository, "repo.json"), 16_384);
        await Fetch(snapshotId + ".snap", Path.Combine(newRepository, "snapshots", snapshotId + ".snap"), ManifestLimit);
        using var vault = LocalEncryptedVault.Open(newRepository, password);
        var snapshot = vault.ReadSnapshot(snapshotId, token);
        var ids = snapshot.Files.SelectMany(f => f.Chunks).Distinct(StringComparer.Ordinal).ToArray();
        int completed = 0;
        long bytes = 0;
        foreach (string id in ids)
        {
            token.ThrowIfCancellationRequested();
            string parent = Path.Combine(newRepository, "objects", id[..2]);
            Directory.CreateDirectory(parent);
            bool reused=false;
            if(previousRepository is not null)
            {
                byte[]? captured=null;
                try
                {
                    captured=vault.ReadAuthenticatedChunkForReuse(previousRepository,id,token);
                    if(!index.TryGetValue(id+".obj",out var listed)||captured.Length!=listed.Length)
                        throw new InvalidDataException("Wcześniej pobrany fragment ma inny rozmiar.");
                }
                catch(Exception error) when(error is FileNotFoundException or DirectoryNotFoundException or InvalidDataException or CryptographicException)
                {if(captured is not null)CryptographicOperations.ZeroMemory(captured);captured=null;}
                if(captured is not null)
                {
                    try{token.ThrowIfCancellationRequested();LocalEncryptedVault.WriteAtomic(Path.Combine(parent,id+".obj"),captured,cancellationToken:token);reused=true;}
                    finally{CryptographicOperations.ZeroMemory(captured);}
                }
            }
            if(!reused)await Fetch(id + ".obj", Path.Combine(parent, id + ".obj"), ObjectLimit);
            bytes = checked(bytes + index[id + ".obj"].Length);
            progress?.Report(new(reused?"Sprawdzono wcześniej pobrany fragment":"Pobieranie zaszyfrowanych fragmentów", ++completed, ids.Length, bytes));
        }
        vault.VerifySnapshot(snapshotId, token);

        async Task Fetch(string name, string target, int limit)
        {
            if (!index.TryGetValue(name, out var file) || file.Length < 0 || file.Length > limit)
                throw new InvalidDataException("Brak fragmentu lub przekroczony rozmiar danych w chmurze.");
            using var buffer = new MemoryStream();
            await remote.DownloadAsync(file, buffer, limit, token);
            if (buffer.Length != file.Length) throw new InvalidDataException("Niepełny fragment z chmury.");
            LocalEncryptedVault.WriteAtomic(target, buffer.ToArray(), cancellationToken: token);
        }
    }

    private static Dictionary<string, CloudObject> UniqueIndex(IReadOnlyList<CloudObject> files)
    {
        var index = new Dictionary<string, CloudObject>(StringComparer.Ordinal);
        foreach (var f in files)
            if (!index.TryAdd(f.Name, f))
                throw new InvalidDataException("Powielona nazwa w folderze kopii. Wybierz odrębny folder dla jednego sejfu.");
        return index;
    }

    private static string RemoteName(string relative)
    {
        if (relative == "repo.json") return relative;
        string leaf = Path.GetFileName(relative);
        if ((relative.StartsWith("objects/", StringComparison.Ordinal) && leaf.Length == 68 && leaf.EndsWith(".obj", StringComparison.Ordinal)) ||
            (relative.StartsWith("snapshots/", StringComparison.Ordinal) && leaf.Length == 37 && leaf.EndsWith(".snap", StringComparison.Ordinal)))
            return leaf;
        throw new InvalidDataException("Eksport zawiera nieoczekiwany plik.");
    }
}
