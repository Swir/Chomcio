using ChomcioRecovery.Core;
using ChomcioRecovery.Desktop;
using System.Reflection;

internal static class RestoreDownloadScenarios
{
    internal static async Task Run(string root,Action<bool,string> check)
    {
        if(Directory.Exists(root))throw new IOException("Fresh test folder required");
        Directory.CreateDirectory(root);string source=Path.Combine(root,"source");Directory.CreateDirectory(source);
        File.WriteAllText(Path.Combine(source,"one.txt"),"synthetic first file");File.WriteAllText(Path.Combine(source,"two.txt"),"synthetic second file");
        var secrets=new JobSecrets("synthetic-test-key","synthetic-account","synthetic-password");
        var profile=new BackupProfile{Repository=Path.Combine(root,"source-vault"),Destination=BackupDestination.Chomikuj};
        LocalEncryptedVault.Initialize(profile.Repository,secrets.VaultPassword);string id;
        using(var vault=LocalEncryptedVault.Open(profile.Repository,secrets.VaultPassword))id=vault.BackupDirectory(source).SnapshotId;
        var remote=new FakeCloud();var transfer=new CloudVaultTransfer(remote);
        await transfer.UploadSnapshotAsync(profile.Repository,secrets.VaultPassword,id,Path.Combine(root,"export"),null,default);
        var store=new StudioStore(Path.Combine(root,"store"));store.Data.Profiles.Add(profile);store.Save();
        byte[] settings=File.ReadAllBytes(Path.Combine(store.Root,"settings.json"));
        remote.Reset();remote.FailAt=2;
        using(var first=Session(store))
        {
            bool failed=false;try{await first.PrepareAsync(id,true,null,default,root);}catch(IOException){failed=true;}
            check(failed,"product session reports network interruption");
        }
        var cache=new RestoreDownloadCache(store,profile.Id,id,secrets.CloudLogin);string? partial=cache.Find();
        check(partial is not null&&Directory.GetFiles(partial,"*.obj",SearchOption.AllDirectories).Length==1,"product remembers completed fragment before closing session");
        string saved=Directory.GetFiles(partial!,"*.obj",SearchOption.AllDirectories).Single();byte[] bytes=File.ReadAllBytes(saved);
        remote.Reset();var reloaded=new StudioStore(store.Root);
        using(var second=Session(reloaded))await second.RestoreAsync(id,true,Path.Combine(root,"restored"),null,null,default);
        check(remote.Reads.Count==3&&!remote.Reads.Contains(Path.GetFileName(saved)),"new session automatically reuses authenticated fragment");
        check(File.ReadAllText(Path.Combine(root,"restored","one.txt"))==File.ReadAllText(Path.Combine(source,"one.txt"))&&File.ReadAllText(Path.Combine(root,"restored","two.txt"))==File.ReadAllText(Path.Combine(source,"two.txt")),"session resume restores both exact files");
        check(File.ReadAllBytes(saved).SequenceEqual(bytes),"product never modifies previous partial");
        check(File.ReadAllBytes(Path.Combine(store.Root,"settings.json")).SequenceEqual(settings),"download locator does not overwrite settings/scheduler state");
        check(new RestoreDownloadCache(reloaded,profile.Id,id,"different-account").Find() is null,"locator scoped to account");
        check(new RestoreDownloadCache(reloaded,Guid.NewGuid().ToString("N"),id,secrets.CloudLogin).Find() is null,"locator scoped to profile");
        check(new RestoreDownloadCache(reloaded,profile.Id,Guid.NewGuid().ToString("N"),secrets.CloudLogin).Find() is null,"locator scoped to snapshot");
        string? complete=cache.Find();
        check(complete!=partial&&Directory.GetFiles(complete!,"*.obj",SearchOption.AllDirectories).Length==2,"more complete attempt remembered");
        check(cache.Remember(partial!)&&cache.Find()==complete,"less complete retry does not lose better saved progress");
        check(!cache.Remember(profile.Repository),"arbitrary source vault cannot be registered as download cache");
        string hint=Directory.GetFiles(Path.Combine(store.Root,"download-resume"),"*.json").Single();
        string text=File.ReadAllText(hint);check(!text.Contains(secrets.VaultPassword)&&!text.Contains(secrets.CloudPassword)&&!text.Contains(secrets.CloudLogin),"locator has no passwords or account name");
        File.WriteAllText(hint,"corrupt optional locator");check(cache.Find() is null,"bad optional locator ignored without deleting partial data");
        Console.WriteLine("PRODUCT_DOWNLOAD_RESUME=PASS; deterministic transport, no network");
        RestoreSession Session(StudioStore current)
        {
            var session=new RestoreSession(current,profile,secrets);
            var points=(Dictionary<string,CloudVaultTransfer>)typeof(RestoreSession).GetField("remotePoints",BindingFlags.NonPublic|BindingFlags.Instance)!.GetValue(session)!;
            points.Add(id,transfer);return session;
        }
    }
    private sealed class FakeCloud:ICloudVault
    {
        private readonly Dictionary<string,byte[]> files=new();internal List<string> Reads=new();internal int FailAt;private int objects;
        internal void Reset(){Reads.Clear();FailAt=0;objects=0;}
        public Task<IReadOnlyList<CloudObject>> ListAsync(CancellationToken token)=>Task.FromResult<IReadOnlyList<CloudObject>>(files.Select(f=>new CloudObject(f.Key,f.Key,f.Value.Length)).ToArray());
        public async Task<CloudObject> UploadAsync(string name,Stream source,long length,CancellationToken token)
        {using var data=new MemoryStream();await source.CopyToAsync(data,token);files.Add(name,data.ToArray());return new(name,name,length);}
        public async Task DownloadAsync(CloudObject file,Stream target,long maximumBytes,CancellationToken token)
        {Reads.Add(file.Name);if(file.Name.EndsWith(".obj",StringComparison.Ordinal)&&++objects==FailAt)throw new IOException("Synthetic disconnect");await target.WriteAsync(files[file.Name],token);}
    }
}
