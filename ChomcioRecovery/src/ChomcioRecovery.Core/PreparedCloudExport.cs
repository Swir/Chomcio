using System.Security.Cryptography;

namespace ChomcioRecovery.Core;

public sealed partial class LocalEncryptedVault
{
    // An existing export is an untrusted read-only input. Its password alone
    // does not identify the original vault. Bind both captured metadata records
    // to the source unlocked by the caller, then verify complete file contents.
    internal PreparedCloudExport OpenPreparedCloudExport(string snapshotId, string directory,
        CancellationToken token, IProgress<VaultProgress>? progress)
    {
        CheckNotDisposed();
        token.ThrowIfCancellationRequested();
        ValidateSnapshotId(snapshotId);
        string exportRoot = Path.GetFullPath(directory);
        EnsureRepositoryPathDisjoint(_root, exportRoot);
        RequireSafeRepositoryReadPath(exportRoot);
        if (!Directory.Exists(exportRoot)) throw new DirectoryNotFoundException("Prepared export is missing.");
        WindowsSourceTreePin? sourcePin = null, exportPin = null;
        LocalEncryptedVault? portable = null;
        byte[]? config = null, manifest = null;
        try
        {
            sourcePin = WindowsSourceTreePin.Acquire(_root, token);
            exportPin = WindowsSourceTreePin.Acquire(exportRoot, token);
            EnsureRepositoryPathDisjoint(_root, exportRoot);
            EnsureRepositoryConfigUnchanged();
            config = ReadBoundedFile(Path.Combine(exportRoot, "repo.json"), 16_384, token);
            EnsureCapturedConfigMatchesUnlock(config);
            manifest = ReadBoundedFile(GetSnapshotPath(snapshotId), MaxManifestBytes + HeaderBytes, token);
            Snapshot snapshot = DecodeSnapshotRecord(snapshotId, manifest);
            portable = new LocalEncryptedVault(exportRoot, (byte[])_key.Clone(), _openedConfigFingerprint);
            var prepared = new PreparedCloudExport(this, portable, sourcePin, exportPin,
                config, manifest, snapshotId, snapshot);
            // Ownership moves only on success; the catch below releases every
            // captured buffer/handle if verification or cancellation fails.
            prepared.RequireMetadataUnchanged(token);
            VerifySnapshotContents(snapshot, token, progress, VaultProgressStage.CheckingExportSource);
            portable.VerifySnapshotContents(snapshot, token, progress, VaultProgressStage.CheckingExportData);
            prepared.RequireMetadataUnchanged(token);
            return prepared;
        }
        catch
        {
            if (config is not null) CryptographicOperations.ZeroMemory(config);
            if (manifest is not null) CryptographicOperations.ZeroMemory(manifest);
            portable?.Dispose(); exportPin?.Dispose(); sourcePin?.Dispose();
            throw;
        }
    }

    internal sealed class PreparedCloudExport : IDisposable
    {
        private readonly LocalEncryptedVault source, portable;
        private readonly WindowsSourceTreePin sourcePin, exportPin;
        private readonly byte[] config, manifest;
        private readonly string snapshotId;
        private readonly HashSet<string> objectNames;
        private bool disposed;
        internal IReadOnlyList<string> Names { get; }

        internal PreparedCloudExport(LocalEncryptedVault source, LocalEncryptedVault portable,
            WindowsSourceTreePin sourcePin, WindowsSourceTreePin exportPin, byte[] config,
            byte[] manifest, string snapshotId, Snapshot snapshot)
        {
            this.source = source; this.portable = portable;
            this.sourcePin = sourcePin; this.exportPin = exportPin;
            this.config = config; this.manifest = manifest; this.snapshotId = snapshotId;
            string[] objects = snapshot.Files.SelectMany(f => f.Chunks).Distinct(StringComparer.Ordinal)
                .OrderBy(id => id, StringComparer.Ordinal).Select(id => id + ".obj").ToArray();
            objectNames = new(objects, StringComparer.Ordinal);
            // Never enumerate arbitrary files as upload inputs. Extra records
            // in the directory cannot become part of this cloud recovery point.
            Names = new[] { "repo.json" }.Concat(objects).Append(snapshotId + ".snap").ToArray();
        }

        internal void RequireMetadataUnchanged(CancellationToken token)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            token.ThrowIfCancellationRequested();
            source.EnsureRepositoryConfigUnchanged();
            portable.EnsureRepositoryConfigUnchanged();
            Match(source.GetSnapshotPath(snapshotId), manifest, MaxManifestBytes + HeaderBytes, token);
            Match(portable.GetSnapshotPath(snapshotId), manifest, MaxManifestBytes + HeaderBytes, token);
            token.ThrowIfCancellationRequested();
        }

        private static void Match(string path, byte[] expected, int limit, CancellationToken token)
        {
            byte[] actual = ReadBoundedFile(path, limit, token);
            try
            {
                if (!actual.AsSpan().SequenceEqual(expected))
                    throw new InvalidDataException("Prepared export manifest differs from the selected source snapshot.");
            }
            finally { CryptographicOperations.ZeroMemory(actual); }
        }

        internal byte[] ReadRecord(string name, CancellationToken token)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            token.ThrowIfCancellationRequested();
            if (name == "repo.json" || name == snapshotId + ".snap")
            {
                RequireMetadataUnchanged(token);
                return (byte[])(name == "repo.json" ? config : manifest).Clone();
            }
            if (!objectNames.Contains(name)) throw new InvalidDataException("Record is not part of the selected snapshot.");
            // Preflight read different, mutable file bytes. Authenticate the
            // EXACT captured ciphertext subsequently handed to the transport.
            return source.ReadAuthenticatedChunkForReuse(portable._root, name[..^4], token);
        }

        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            CryptographicOperations.ZeroMemory(config); CryptographicOperations.ZeroMemory(manifest);
            portable.Dispose(); exportPin.Dispose(); sourcePin.Dispose();
        }
    }
}
