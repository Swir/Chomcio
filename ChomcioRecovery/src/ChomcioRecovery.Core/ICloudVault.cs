namespace ChomcioRecovery.Core;

public sealed record CloudObject(string Id, string Name, long Length);
public sealed record CloudProgress(string Phase, int Completed, int Total, long Bytes);

// Providers transfer only encrypted records. They never receive the vault password.
public interface ICloudVault
{
    Task<IReadOnlyList<CloudObject>> ListAsync(CancellationToken cancellationToken);
    // Discovery only: names do not prove byte lengths or backup completeness.
    // Providers may avoid probing every object's body just to display dates.
    async Task<IReadOnlyList<string>> ListNamesAsync(CancellationToken cancellationToken)
        => (await ListAsync(cancellationToken)).Select(file=>file.Name).ToArray();
    Task<CloudObject> UploadAsync(string name, Stream encryptedContent, long length, CancellationToken cancellationToken);
    Task DownloadAsync(CloudObject file, Stream destination, long maximumBytes, CancellationToken cancellationToken);
}
