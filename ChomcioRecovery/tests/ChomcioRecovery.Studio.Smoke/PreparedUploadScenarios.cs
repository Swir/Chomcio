using ChomcioRecovery.Core;
using ChomcioRecovery.Desktop;
using System.Security.Cryptography;

internal static class PreparedUploadScenarios
{
    internal static async Task Run(string root, Action<bool,string> check)
    {
        if(Directory.Exists(root))throw new IOException("Use a new synthetic test directory.");
        Directory.CreateDirectory(root);
        const string password="synthetic-prepared-upload-only";
        string source=Path.Combine(root,"source"), repo=Path.Combine(root,"vault"), export=Path.Combine(root,"export");
        Directory.CreateDirectory(Path.Combine(source,"empty"));
        byte[] original=RandomNumberGenerator.GetBytes(LocalEncryptedVault.ChunkBytes+137);
        File.WriteAllBytes(Path.Combine(source,"data.bin"),original);
        LocalEncryptedVault.Initialize(repo,password);
        string id;
        using(var vault=LocalEncryptedVault.Open(repo,password))
        {id=vault.BackupDirectory(source).SnapshotId;vault.ExportEncryptedSnapshot(id,export);}
        var before=Tree(export);
        var remote=new MemoryCloud();
        await Send(remote);
        check(remote.Uploads.First()=="repo.json"&&remote.Uploads.Last()==id+".snap","prepared upload publishes only the selected manifest, last");
        check(remote.Reads.Count==remote.Files.Count,"all prepared records are independently read back");
        check(before.SequenceEqual(Tree(export)),"prepared upload leaves every export byte unchanged");
        check(Directory.GetDirectories(root).Length==3,"prepared upload allocates no second staging directory");
        int writes=remote.Uploads.Count, reads=remote.Reads.Count;
        await Send(remote);
        check(remote.Uploads.Count==writes&&remote.Reads.Count==reads+remote.Files.Count,"reuse checks every remote byte without repeating writes");
        await Restore(remote,"independent");

        var fresh=new MemoryCloud();
        await new CloudVaultTransfer(fresh).UploadSnapshotAsync(repo,password,id,Path.Combine(root,"fresh"),null,default);
        check(fresh.Uploads.SequenceEqual(remote.Uploads)&&fresh.Files.All(p=>p.Value.SequenceEqual(remote.Files[p.Key])),"fresh API still exports and transfers the same exact records");
        var refuse=new MemoryCloud();
        await Reject(()=>new CloudVaultTransfer(refuse).UploadSnapshotAsync(repo,password,id,export,null,default),"fresh API still refuses an existing output");
        check(refuse.Lists==0,"fresh refusal precedes network activity");

        string obj=Directory.GetFiles(Path.Combine(export,"objects"),"*.obj",SearchOption.AllDirectories).First();
        string manifest=Path.Combine(export,"snapshots",id+".snap"), config=Path.Combine(export,"repo.json");
        foreach(string path in new[]{obj,manifest,config})
        {
            byte[] saved=File.ReadAllBytes(path);
            try
            {
                byte[] changed=(byte[])saved.Clone();changed[^1]^=1;File.WriteAllBytes(path,changed);
                var bad=new MemoryCloud();await Reject(()=>Send(bad),"corrupt prepared record refused during preflight");
                check(bad.Lists==0&&bad.Uploads.Count==0,"invalid export performs no cloud calls");
            }
            finally{File.WriteAllBytes(path,saved);}
        }
        File.Move(obj,obj+".held");
        try{var bad=new MemoryCloud();await Reject(()=>Send(bad),"missing chunk refused");check(bad.Lists==0,"missing chunk refuses before network");}
        finally{File.Move(obj+".held",obj);}
        var wrongPassword=new MemoryCloud();
        await Reject(()=>new CloudVaultTransfer(wrongPassword).UploadPreparedSnapshotAsync(repo,"wrong",id,export,null,default),"wrong source password refused");
        check(wrongPassword.Lists==0,"wrong password makes no cloud calls");
        string other=Path.Combine(root,"other-vault");LocalEncryptedVault.Initialize(other,password);
        byte[] savedConfig=File.ReadAllBytes(config);
        try
        {
            File.Copy(Path.Combine(other,"repo.json"),config,true);
            var bad=new MemoryCloud();await Reject(()=>Send(bad),"another vault with same password is not the same lineage");
            check(bad.Lists==0,"foreign lineage makes no cloud calls");
        }
        finally{File.WriteAllBytes(config,savedConfig);}
        var overlap=new MemoryCloud();
        await Reject(()=>new CloudVaultTransfer(overlap).UploadPreparedSnapshotAsync(repo,password,id,repo,null,default),"source vault cannot be adopted as its own export");
        check(overlap.Lists==0,"overlap refuses before network");
        string alias=Path.Combine(root,"export-link");
        Directory.CreateSymbolicLink(alias,export);
        try{var bad=new MemoryCloud();await Reject(()=>new CloudVaultTransfer(bad).UploadPreparedSnapshotAsync(repo,password,id,alias,null,default),"linked export refused");check(bad.Lists==0,"linked export makes no cloud calls");}
        finally{Directory.Delete(alias);}
        File.Move(obj,obj+".held");File.CreateSymbolicLink(obj,obj+".held");
        try{var bad=new MemoryCloud();await Reject(()=>Send(bad),"linked chunk refused even when it points to correct bytes");check(bad.Lists==0,"linked chunk makes no cloud calls");}
        finally{File.Delete(obj);File.Move(obj+".held",obj);}
        bool renameDenied=false;
        var pinned=new MemoryCloud{OnList=()=>{try{Directory.Move(export,export+"-moved");Directory.Move(export+"-moved",export);}catch(IOException){renameDenied=true;}}};
        await Send(pinned);
        check(renameDenied&&pinned.Files.ContainsKey(id+".snap"),"native directory pin prevents export replacement throughout remote I/O");

        // Extra local files (including valid-looking object/manifest names)
        // are not selected by enumerating the export tree for upload.
        string extraObject=Path.Combine(export,"objects","ff",new string('f',64)+".obj");
        Directory.CreateDirectory(Path.GetDirectoryName(extraObject)!);File.WriteAllText(extraObject,"untrusted extra");
        string extraManifest=Path.Combine(export,"snapshots",new string('e',32)+".snap");File.WriteAllText(extraManifest,"untrusted extra");
        File.WriteAllText(Path.Combine(export,"private-note.txt"),"not for upload");
        var extras=new MemoryCloud();await Send(extras);
        check(extras.Files.Keys.Order().SequenceEqual(remote.Files.Keys.Order()),"unreferenced objects, snapshots and arbitrary files never reach remote");

        foreach(string path in new[]{obj,manifest,config,Path.Combine(repo,"snapshots",id+".snap"),Path.Combine(repo,"repo.json")})
        {
            byte[] saved=File.ReadAllBytes(path);
            try
            {
                var changed=new MemoryCloud{OnList=()=>{byte[] value=(byte[])saved.Clone();value[^1]^=1;File.WriteAllBytes(path,value);}};
                await Reject(()=>Send(changed),"mutation after preflight refused before snapshot publication");
                check(!changed.Files.ContainsKey(id+".snap"),"late mutation never publishes the manifest");
                if(path==obj)check(!changed.Files.ContainsKey(Path.GetFileName(obj)),"late corrupt chunk itself is never uploaded");
            }
            finally{File.WriteAllBytes(path,saved);}
        }
        // The transfer must use the authenticated captured buffer, even when
        // the same file is changed after ReadRecord and before UploadAsync.
        byte[] savedObject=File.ReadAllBytes(obj);
        try
        {
            var captured=new MemoryCloud{BeforeUpload=name=>{if(name==Path.GetFileName(obj)){byte[] value=(byte[])savedObject.Clone();value[^1]^=1;File.WriteAllBytes(obj,value);}}};
            await Send(captured);
            check(captured.Files[Path.GetFileName(obj)].SequenceEqual(savedObject),"post-capture mutation cannot replace the ciphertext passed to transport");
            await Restore(captured,"captured");
        }
        finally{File.WriteAllBytes(obj,savedObject);}
        var readback=new MemoryCloud{CorruptRead=true};
        await Reject(()=>Send(readback),"corrupted remote readback refused");
        check(!readback.Files.ContainsKey(id+".snap"),"bad readback prevents final manifest");
        var existing=new MemoryCloud();foreach(var pair in remote.Files)if(!pair.Key.EndsWith(".snap",StringComparison.Ordinal))existing.Files.Add(pair.Key,(byte[])pair.Value.Clone());
        existing.Files[Path.GetFileName(obj)][^1]^=1;
        await Reject(()=>Send(existing),"existing same-length remote corruption refused");
        check(existing.Uploads.Count==0,"remote collision is never overwritten or retried");

        using(var stop=new CancellationTokenSource())
        {
            stop.Cancel();var cancelled=new MemoryCloud();await Reject(()=>Send(cancelled,stop.Token),"cancel before preparation");
            check(cancelled.Lists==0,"cancel before preparation has no cloud calls");
        }
        using(var stop=new CancellationTokenSource())
        {
            var cancelled=new MemoryCloud();var progress=new Inline<VaultProgress>(p=>{if(p.Stage==VaultProgressStage.CheckingExportData&&p.ProcessedBytes>0)stop.Cancel();});
            await Reject(()=>new CloudVaultTransfer(cancelled).UploadPreparedSnapshotAsync(repo,password,id,export,null,stop.Token,progress),"cancel during full prepared verification");
            check(cancelled.Lists==0,"cancelled preflight does not reach cloud");
        }
        using(var stop=new CancellationTokenSource())
        {
            var cancelled=new MemoryCloud();var progress=new Inline<CloudProgress>(p=>{if(p.Phase=="Wysyłanie zaszyfrowanych danych"&&p.Completed==1)stop.Cancel();});
            await Reject(()=>new CloudVaultTransfer(cancelled).UploadPreparedSnapshotAsync(repo,password,id,export,progress,stop.Token),"cancel immediately before object write");
            check(cancelled.Uploads.SequenceEqual(new[]{"repo.json"})&&!cancelled.Files.ContainsKey(id+".snap"),"cancellation prevents the next write and manifest");
            await Send(cancelled);
            check(cancelled.Uploads.Count==cancelled.Files.Count,"resuming cancelled transfer does not repeat successful writes");
        }
        check(File.ReadAllBytes(obj).SequenceEqual(savedObject),"all failure and cancellation cases preserve original export objects");
        await JobCases(root,check);
        Console.WriteLine("PREPARED_UPLOAD=PASS; synthetic local data and in-memory transport only; no VM or live cloud");

        Task Send(MemoryCloud cloud,CancellationToken token=default)=>new CloudVaultTransfer(cloud).UploadPreparedSnapshotAsync(repo,password,id,export,null,token);
        async Task Reject(Func<Task> action,string label)
        {
            bool failed=false;try{await action();}catch(Exception e)when(e is IOException or InvalidDataException or CryptographicException or OperationCanceledException or System.Text.Json.JsonException){failed=true;}
            check(failed,label);
        }
        async Task Restore(MemoryCloud cloud,string label)
        {
            string downloaded=Path.Combine(root,label+"-download"), restored=Path.Combine(root,label+"-restore");
            await new CloudVaultTransfer(cloud).DownloadSnapshotAsync(id,password,downloaded,null,default);
            using(var vault=LocalEncryptedVault.Open(downloaded,password))vault.RestoreSnapshot(id,restored);
            check(File.ReadAllBytes(Path.Combine(restored,"data.bin")).SequenceEqual(original)&&Directory.Exists(Path.Combine(restored,"empty")),"independent download restores exact data and empty directories");
        }
    }

    private static async Task JobCases(string root,Action<bool,string> check)
    {
        string source=Path.Combine(root,"job-source");Directory.CreateDirectory(source);File.WriteAllText(Path.Combine(source,"marker.txt"),"synthetic job resume");
        var secrets=new JobSecrets("synthetic-job-vault-key","synthetic-login","synthetic-cloud-password");
        var profile=new BackupProfile{Name="Prepared upload",Source=source,Repository=Path.Combine(root,"job-vault"),Destination=BackupDestination.Chomikuj,CloudDateFolders=true};
        var store=new StudioStore(Path.Combine(root,"job-settings"));store.Data.Profiles.Add(profile);store.Save();
        var cloud=new MemoryCloud{OnList=()=>throw new IOException("synthetic first listing failure")};
        var engine=new JobEngine(store,()=>new Connection(cloud));
        DateTimeOffset now=new(2026,10,29,10,0,0,TimeSpan.Zero);
        var first=await engine.RunAsync(profile,secrets,now);
        string pending=profile.PendingSnapshot!, day=profile.PendingCloudDate!;
        string transferParent=Path.GetDirectoryName(SystemImageStorage.TransferDirectory(store,profile,Guid.NewGuid().ToString("N")))!;
        string export=Directory.GetDirectories(transferParent).Single();var originalTree=Tree(export);
        check(first?.State==RunState.Failed&&pending is not null,"failed listing retains the pending snapshot and completed export");
        // A later attempt with a changed source must still use the old point.
        File.WriteAllText(Path.Combine(source,"marker.txt"),"changed after pending");
        var failed=await engine.RunAsync(profile,secrets,now.AddDays(1));
        check(failed?.Snapshot==pending&&profile.PendingCloudDate==day&&Directory.GetDirectories(transferParent).Length==1,"another failure keeps date and snapshot and creates no additional export");
        check(originalTree.SequenceEqual(Tree(export)),"failed resume leaves original export bytes unchanged");
        cloud.OnList=null;
        var loaded=new StudioStore(store.Root);var resumedProfile=loaded.Data.Profiles.Single();
        var success=await new JobEngine(loaded,()=>new Connection(cloud)).RunAsync(resumedProfile,secrets,now.AddDays(2));
        check(success?.State==RunState.Success&&success.Snapshot==pending&&resumedProfile.LastSnapshot==pending&&resumedProfile.PendingSnapshot is null&&resumedProfile.PendingCloudDate is null&&resumedProfile.RemoteFolderHasConfirmedCopy,"reloaded job completes the same pending point and clears pending only after verification");
        check(loaded.Data.History.Count==3&&loaded.Data.History.Take(2).All(h=>h.State==RunState.Failed),"resumed success retains both historical failures");
        check(Directory.GetDirectories(transferParent).Length==1&&originalTree.SequenceEqual(Tree(export)),"successful reloaded job uses existing export without replacing it");
        // Restore pending only in this synthetic fixture to test corruption refusal.
        resumedProfile.PendingSnapshot=pending;resumedProfile.PendingCloudDate=day;loaded.Save();
        string chunk=Directory.GetFiles(Path.Combine(export,"objects"),"*.obj",SearchOption.AllDirectories).Single();byte[] bytes=File.ReadAllBytes(chunk);bytes[^1]^=1;File.WriteAllBytes(chunk,bytes);
        int lists=cloud.Lists,writes=cloud.Uploads.Count;
        var corrupt=await new JobEngine(loaded,()=>new Connection(cloud)).RunAsync(resumedProfile,secrets,now.AddDays(3));
        check(corrupt?.State==RunState.Failed&&resumedProfile.PendingSnapshot==pending&&Directory.GetDirectories(transferParent).Length==1,"corrupt existing export fails closed without a replacement export");
        check(cloud.Lists==lists&&cloud.Uploads.Count==writes,"corrupt prepared job does not reach list or write");
        string manifest=Path.Combine(export,"snapshots",pending+".snap");File.Move(manifest,manifest+".held");
        var missing=await new JobEngine(loaded,()=>new Connection(cloud)).RunAsync(resumedProfile,secrets,now.AddDays(4));
        check(missing?.State==RunState.Failed&&Directory.GetDirectories(transferParent).Length==1,"missing published manifest does not silently trigger a fresh export");
        // Discovery must stay under the selected Windows cache, independently
        // of the settings directory. This does not capture a Windows image.
        string cache=Path.Combine(root,"synthetic-windows-cache");
        var windows=new BackupProfile{Content=BackupContent.WindowsSystem,SystemImageCacheRoot=cache};
        windows.Repository=SystemImageStorage.Repository(cache,windows.Id);
        string published=SystemImageStorage.TransferDirectory(loaded,windows,Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(published,"snapshots"));File.WriteAllText(Path.Combine(published,"repo.json"),"untrusted metadata stub");
        File.WriteAllText(Path.Combine(published,"snapshots",pending+".snap"),"must still be authenticated by Core");
        check(SystemImageStorage.FindPreparedTransfer(loaded,windows,pending!,default)==published,"Windows discovery uses selected off-system cache rather than settings storage");
        string privateStage=Path.Combine(Path.GetDirectoryName(published)!,".chomcio-export-incomplete");Directory.CreateDirectory(privateStage);
        check(SystemImageStorage.FindPreparedTransfer(loaded,windows,pending!,default)==published,"unpublished private export staging cannot be adopted");
        check(SystemImageStorage.FindPreparedTransfer(loaded,windows,Guid.NewGuid().ToString("N"),default) is null,"an older snapshot export is not reused for a new point");
    }

    private static string[] Tree(string root)=>Directory.GetFiles(root,"*",SearchOption.AllDirectories).OrderBy(p=>p,StringComparer.Ordinal)
        .Select(p=>Path.GetRelativePath(root,p)+":"+Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(p)))).ToArray();
    private sealed class Inline<T>(Action<T> action):IProgress<T>{public void Report(T value)=>action(value);}
    private sealed class Connection(MemoryCloud cloud):IJobCloud
    {public Task<ICloudVault> ConnectAsync(BackupProfile p,JobSecrets s,CancellationToken t)=>Task.FromResult<ICloudVault>(cloud);public void Dispose(){}}
    private sealed class MemoryCloud:ICloudVault
    {
        internal readonly Dictionary<string,byte[]> Files=new(StringComparer.Ordinal);
        internal readonly List<string> Uploads=new(), Reads=new();
        internal Action? OnList;internal Action<string>? BeforeUpload;internal int Lists;internal bool CorruptRead;
        public Task<IReadOnlyList<CloudObject>> ListAsync(CancellationToken token)
        {token.ThrowIfCancellationRequested();Lists++;OnList?.Invoke();return Task.FromResult<IReadOnlyList<CloudObject>>(Files.Select(p=>new CloudObject(p.Key,p.Key,p.Value.Length)).ToArray());}
        public async Task<CloudObject> UploadAsync(string name,Stream data,long length,CancellationToken token)
        {token.ThrowIfCancellationRequested();BeforeUpload?.Invoke(name);using var buffer=new MemoryStream();await data.CopyToAsync(buffer,token);Files.Add(name,buffer.ToArray());Uploads.Add(name);return new(name,name,length);}
        public async Task DownloadAsync(CloudObject file,Stream target,long maximumBytes,CancellationToken token)
        {token.ThrowIfCancellationRequested();Reads.Add(file.Name);byte[] bytes=(byte[])Files[file.Name].Clone();if(CorruptRead)bytes[^1]^=1;await target.WriteAsync(bytes,token);}
    }
}
