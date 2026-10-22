namespace ChomcioRecovery.Core;

public sealed record CloudObject(string Id, string Name, long Length);
public sealed record CloudProgress(string Phase, int Completed, int Total, long Bytes);

// Providers transfer only encrypted records. They never receive the vault password.
public interface ICloudVault
{
    Task<IReadOnlyList<CloudObject>> ListAsync(CancellationToken cancellationToken);
    Task<CloudObject> UploadAsync(string name, Stream encryptedContent, long length, CancellationToken cancellationToken);
    Task DownloadAsync(CloudObject file, Stream destination, long maximumBytes, CancellationToken cancellationToken);
}
