using ChomcioRecovery.Core;

internal static class SnapshotListingScenarios
{
    internal static async Task Run(Action<bool,string> check)
    {
        string id=Guid.NewGuid().ToString("N");
        check((await new CloudVaultTransfer(new Names("repo.json",id+".snap","ignored.obj")).ListSnapshotsAsync(default)).SequenceEqual(new[]{id}),"snapshot discovery uses names-only provider contract");
        check((await new CloudVaultTransfer(new Names(id+".snap")).ListSnapshotsAsync(default)).Count==0,"name-only discovery requires vault configuration");
        bool duplicate=false;try{await new CloudVaultTransfer(new Names("repo.json",id+".snap",id+".snap")).ListSnapshotsAsync(default);}catch(InvalidDataException){duplicate=true;}
        check(duplicate,"duplicate names remain ambiguous and rejected during fast discovery");
        using var stop=new CancellationTokenSource();stop.Cancel();bool cancelled=false;
        try{await new CloudVaultTransfer(new Names("repo.json",id+".snap")).ListSnapshotsAsync(stop.Token);}catch(OperationCanceledException){cancelled=true;}
        check(cancelled,"fast discovery preserves cancellation");
    }
    private sealed class Names(params string[] names):ICloudVault
    {
        public Task<IReadOnlyList<string>> ListNamesAsync(CancellationToken token){token.ThrowIfCancellationRequested();return Task.FromResult<IReadOnlyList<string>>(names);}
        public Task<IReadOnlyList<CloudObject>> ListAsync(CancellationToken token)=>throw new InvalidOperationException("Unexpected byte-accurate listing during discovery");
        public Task<CloudObject> UploadAsync(string name,Stream encryptedContent,long length,CancellationToken token)=>throw new InvalidOperationException();
        public Task DownloadAsync(CloudObject file,Stream destination,long maximumBytes,CancellationToken token)=>throw new InvalidOperationException();
    }
}
