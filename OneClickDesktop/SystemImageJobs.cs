using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using ChomcioRecovery.Core;

namespace ChomcioRecovery.Desktop;

// The transport runs as the user. A future installed capture broker must resolve
// PlanId from its own protected configuration, not from user-writable settings.
// It must reconcile CaptureId with protected broker state on EVERY retry: never
// start a second wbadmin for that ID, and never accept a user-written receipt as
// proof that wbadmin ran. OutputDirectory is only for an UNELEVATED export copy;
// the privileged broker must not receive or write to that caller-controlled path.
// Cancellation must not kill a native image writer mid-write.
internal interface ISystemImageCapture
{
    void ValidateStorage(BackupProfile profile);
    Task CaptureAsync(SystemImageCaptureRequest request, CancellationToken token);
}

internal sealed record SystemImageCaptureRequest(string PlanId, string CaptureId,
    DateTimeOffset RequestedUtc, string OutputDirectory);

internal sealed class SystemImageCaptureUnavailableException : IOException
{
    internal SystemImageCaptureUnavailableException() : base(
        "Automatyczne tworzenie obrazu Windows wymaga zainstalowanego modułu systemowego. Nie rozpoczęto kopii.") { }
}
internal sealed class SystemImageCaptureFailedException(bool interrupted,int? nativeExitCode) : IOException
{
    internal bool Interrupted { get; }=interrupted;
    internal int? NativeExitCode { get; }=nativeExitCode;
}

internal sealed class UnavailableSystemImageCapture : ISystemImageCapture
{
    public void ValidateStorage(BackupProfile profile)=>throw new SystemImageCaptureUnavailableException();
    public Task CaptureAsync(SystemImageCaptureRequest request, CancellationToken token)
        => Task.FromException(new SystemImageCaptureUnavailableException());
}

internal sealed record PendingSystemImage(string PlanId, string CaptureId, DateTimeOffset RequestedUtc)
{
    public SystemImageProof? Proof { get; set; }
}

// Included INSIDE the encrypted snapshot, so a different PC can identify the
// image without the original settings. This is a capture receipt, not proof of
// a successful bare-metal restore or a replacement for a trusted capture broker.
internal sealed record SystemImageReceipt(int Version, string PlanId, string CaptureId,
    DateTimeOffset RequestedUtc, DateTimeOffset CompletedUtc, int NativeBackupExitCode,
    bool AllCritical, bool VssCopy, long ArchiveBytes, string ArchiveSha256);

internal sealed record SystemImageProof(string CaptureId, long ArchiveBytes,
    string ArchiveSha256, long ReceiptBytes, string ReceiptSha256);

internal sealed class SystemImageLease : IDisposable
{
    internal const string ArchiveName = "WindowsImageBackup.zip";
    internal const string ReceiptName = "system-image.json";
    private readonly FileStream archive;
    private readonly FileStream receipt;
    internal SystemImageProof Proof { get; }
    private SystemImageLease(FileStream archive, FileStream receipt, SystemImageProof proof)
    { this.archive = archive; this.receipt = receipt; Proof = proof; }

    internal static string DirectoryFor(BackupProfile profile, PendingSystemImage pending)
    {
        if (!Guid.TryParseExact(profile.Id, "N", out _) || !Guid.TryParseExact(pending.PlanId, "N", out _) ||
            !Guid.TryParseExact(pending.CaptureId, "N", out _) || pending.PlanId != profile.SystemImagePlanId ||
            pending.RequestedUtc == default)
            throw new InvalidDataException("Niepoprawna tożsamość zadania obrazu Windows.");
        SystemImageStorage.ValidateShape(profile);
        string path = Path.Combine(profile.SystemImageCacheRoot!, "images", profile.Id, pending.CaptureId);
        StudioStore.RejectLinks(path);
        return path;
    }

    internal static async Task<SystemImageLease> OpenAsync(string directory, PendingSystemImage pending,
        CancellationToken token)
    {
        StudioStore.RejectLinks(directory);
        var entries = Directory.GetFileSystemEntries(directory);
        if (entries.Length != 2 || !entries.Select(Path.GetFileName).ToHashSet(StringComparer.Ordinal)
            .SetEquals(new[] { ArchiveName, ReceiptName }))
            throw new InvalidDataException("Niekompletny zestaw obrazu Windows.");
        foreach (string entry in entries) StudioStore.RejectLinks(entry);
        FileStream? archive = null, receipt = null;
        try
        {
            // Deny writers and deletion until BackupDirectory AND its manifest
            // comparison finish. Paths alone are not immutable capture evidence.
            archive = new(Path.Combine(directory, ArchiveName), FileMode.Open, FileAccess.Read,
                FileShare.Read, 1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            receipt = new(Path.Combine(directory, ReceiptName), FileMode.Open, FileAccess.Read, FileShare.Read);
            if (receipt.Length is <= 0 or > 16_384) throw new InvalidDataException("Niepoprawny opis obrazu.");
            byte[] json = new byte[checked((int)receipt.Length)];
            await receipt.ReadExactlyAsync(json, token);
            var description = JsonSerializer.Deserialize<SystemImageReceipt>(json,
                new JsonSerializerOptions { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow })
                ?? throw new InvalidDataException("Brak opisu obrazu.");
            if (description.Version != 1 || description.PlanId != pending.PlanId ||
                description.CaptureId != pending.CaptureId || description.RequestedUtc != pending.RequestedUtc ||
                description.CompletedUtc < pending.RequestedUtc ||
                description.CompletedUtc > DateTimeOffset.UtcNow.AddMinutes(5) ||
                description.NativeBackupExitCode != 0 || !description.AllCritical || !description.VssCopy ||
                description.ArchiveBytes <= 0 || description.ArchiveBytes != archive.Length ||
                !IsHash(description.ArchiveSha256))
                throw new InvalidDataException("Obraz nie potwierdza ukończenia tego zadania Windows/VSS.");
            string hash = Convert.ToHexString(await SHA256.HashDataAsync(archive, token)).ToLowerInvariant();
            if (!hash.Equals(description.ArchiveSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Suma kontrolna obrazu Windows jest niezgodna.");
            archive.Position = 0;
            CheckArchive(archive, token);
            var proof = new SystemImageProof(pending.CaptureId, archive.Length, hash, json.Length,
                Convert.ToHexString(SHA256.HashData(json)).ToLowerInvariant());
            if (pending.Proof is not null && pending.Proof != proof)
                throw new InvalidDataException("Przygotowany wcześniej obraz został zmieniony.");
            return new(archive, receipt, proof);
        }
        catch { archive?.Dispose(); receipt?.Dispose(); throw; }
    }

    private static bool IsHash(string? hash) => hash is { Length: 64 } && hash.All(char.IsAsciiHexDigit);

    internal static void CheckArchive(Stream stream, CancellationToken token)
    {
        using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        if (zip.Entries.Count is < 2 or > 32_768) throw new InvalidDataException("Niepoprawny spis obrazu.");
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        bool volume = false, catalog = false;
        foreach (var entry in zip.Entries)
        {
            token.ThrowIfCancellationRequested();
            string path = entry.FullName, trimmed = path.TrimEnd('/');
            bool directory = path.EndsWith('/');
            string[] parts = trimmed.Split('/');
            if (path.Length > 1024 || path.Contains("//", StringComparison.Ordinal) || !path.StartsWith("WindowsImageBackup/", StringComparison.Ordinal) ||
                !names.Add(trimmed) || parts.Any(p => p.Length == 0 || p is "." or ".." ||
                    p.EndsWith('.') || p.EndsWith(' ') || IsDeviceName(p) || p.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) ||
                ((entry.ExternalAttributes >> 16) & 0xF000) == 0xA000 ||
                (entry.ExternalAttributes & (int)FileAttributes.ReparsePoint) != 0 ||
                entry.Length < 0 || directory && entry.Length != 0)
                throw new InvalidDataException("Niebezpieczny lub niejednoznaczny spis obrazu.");
            if (!directory)
            {
                volume |= entry.Length > 0 && (path.EndsWith(".vhdx", StringComparison.OrdinalIgnoreCase) ||
                    path.EndsWith(".vhd", StringComparison.OrdinalIgnoreCase));
                catalog |= entry.Length > 0 && path.Contains("/Catalog/", StringComparison.OrdinalIgnoreCase);
            }
        }
        var files = zip.Entries.Where(e => !e.FullName.EndsWith('/'))
            .Select(e => e.FullName).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (string name in names)
        {
            for (int slash = name.LastIndexOf('/'); slash > 0; slash = name.LastIndexOf('/', slash - 1))
                if (files.Contains(name[..slash])) throw new InvalidDataException("Plik zastępuje katalog obrazu.");
        }
        if (!volume || !catalog) throw new InvalidDataException("Brak woluminów lub katalogu kopii Windows.");
    }

    private static bool IsDeviceName(string part)
    {
        string name=part.Split('.')[0].ToUpperInvariant();
        return name is "CON" or "PRN" or "AUX" or "NUL" or "CONIN$" or "CONOUT$" ||
            name.Length==4 && (name.StartsWith("COM",StringComparison.Ordinal)||name.StartsWith("LPT",StringComparison.Ordinal)) &&
            "123456789¹²³".Contains(name[3]);
    }

    internal static void VerifySnapshot(LocalEncryptedVault.Snapshot snapshot, PendingSystemImage pending)
    {
        var proof = pending.Proof ?? throw new InvalidDataException("Brak potwierdzonego obrazu do wznowienia.");
        if (proof.CaptureId != pending.CaptureId || !IsHash(proof.ArchiveSha256) || !IsHash(proof.ReceiptSha256) ||
            snapshot.Files.Count != 2 || (snapshot.Directories?.Count ?? 0) != 0 ||
            (snapshot.SkippedSystemDirectoryLinks?.Count ?? 0) != 0)
            throw new InvalidDataException("Punkt kopii nie jest kompletnym obrazem tego zadania.");
        bool Matches(string name, long bytes, string hash) => snapshot.Files.Count(f =>
            f.Path == name && f.Size == bytes && f.Sha256.Equals(hash, StringComparison.OrdinalIgnoreCase)) == 1;
        if (!Matches(ArchiveName, proof.ArchiveBytes, proof.ArchiveSha256) ||
            !Matches(ReceiptName, proof.ReceiptBytes, proof.ReceiptSha256))
            throw new InvalidDataException("Zaszyfrowana kopia nie zgadza się z przygotowanym obrazem Windows.");
    }

    public void Dispose() { archive.Dispose(); receipt.Dispose(); }
}
