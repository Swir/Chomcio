using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using ChomcioRecovery.Core;
using ChomcioRecovery.Desktop;
using ChomcioRecovery.SystemImages;

internal static class SystemImageJobScenarios
{
    // Synthetic ZIP shapes exercise orchestration, never wbadmin or any disk image.
    internal static async Task Run(string root, Action<bool,string> check)
    {
        var secrets=new JobSecrets("synthetic-image-key-only","synthetic-user","synthetic-password");
        var now=DateTimeOffset.Now;
        string volume=@"\\?\Volume{"+Guid.NewGuid().ToString("D")+@"}\";
        check(BrokerFiles.IsVolume(volume),"broker accepts a canonical volume GUID");
        foreach(string value in new[]{"C:",@"\\server\share",volume+"folder",volume+" & command",volume.Replace("Volume","volume")})
            check(!BrokerFiles.IsVolume(value),"broker rejects arbitrary elevated target syntax");
        bool rejectedUnknown=false;
        try{JsonSerializer.Deserialize<CaptureRequest>("{\"Version\":1,\"CaptureId\":\""+Guid.NewGuid().ToString("N")+"\",\"RequestedUtc\":\"2026-10-21T00:00:00Z\",\"Command\":\"ignored-command\"}",BrokerFiles.Json);}
        catch(JsonException){rejectedUnknown=true;}
        check(rejectedUnknown,"request protocol rejects executable/command fields instead of ignoring them");
        bool rejectedWritable=false;
        try{BrokerFiles.RequireProtected(root);}
        catch(UnauthorizedAccessException){rejectedWritable=true;}
        check(rejectedWritable,"user-writable settings directory cannot impersonate protected broker state");
        System.Security.AccessControl.DirectorySecurity NativeAcl(string owner,string writer)
        {
            var acl=new System.Security.AccessControl.DirectorySecurity();
            acl.SetOwner(new System.Security.Principal.SecurityIdentifier(owner));
            acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                new System.Security.Principal.SecurityIdentifier(writer),System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.AccessControlType.Allow));return acl;
        }
        foreach(string sid in new[]{"S-1-5-18","S-1-5-32-544","S-1-5-32-551","S-1-3-0"})
        {NativeImageFiles.ValidateNativeAcl(NativeAcl("S-1-5-18",sid));check(true,"known native Windows ACL can be sealed: "+sid);}
        foreach(string sid in new[]{"S-1-1-0","S-1-5-11","S-1-5-32-545",System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value})
        {
            bool rejected=false;try{NativeImageFiles.ValidateNativeAcl(NativeAcl("S-1-5-18",sid));}catch(UnauthorizedAccessException){rejected=true;}
            check(rejected,"ordinary native-image writers remain rejected before sealing: "+sid);
        }
        bool ownerRejected=false;
        try{NativeImageFiles.ValidateNativeAcl(NativeAcl(System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value,"S-1-5-18"));}
        catch(UnauthorizedAccessException){ownerRejected=true;}
        check(ownerRejected,"an ordinary-account owner cannot be adopted as native Windows output");
        string recordPath=Path.Combine(root,"broker-atomic-record.json");
        var accepted=new CaptureState(1,Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"Accepted");
        BrokerFiles.Save(recordPath,accepted);
        using(var reader=BrokerFiles.OpenRecordRead(recordPath))
        {
            BrokerFiles.Save(recordPath,accepted with{Stage="NativeRunning",NativePid=123},true);
            check(JsonSerializer.Deserialize<CaptureState>(reader,BrokerFiles.Json)==accepted&&
                BrokerFiles.Read<CaptureState>(recordPath).Stage=="NativeRunning",
                "status commit succeeds during a reader lease; each reader sees a complete record");
        }
        var transientLock=new FileStream(recordPath,FileMode.Open,FileAccess.Read,FileShare.None);
        using(var reading=new ManualResetEventSlim())
        {
            var pendingRead=Task.Run(()=>{reading.Set();return BrokerFiles.Read<CaptureState>(recordPath);});
            if(!reading.Wait(TimeSpan.FromSeconds(5)))throw new TimeoutException("Reader did not start.");
            await Task.Delay(75);transientLock.Dispose();
            check((await pendingRead).Stage=="NativeRunning","temporary status sharing conflict recovers without changing or caching the record");
        }
        using(var permanentLock=new FileStream(recordPath,FileMode.Open,FileAccess.Read,FileShare.None))
        {
            var clock=System.Diagnostics.Stopwatch.StartNew();bool denied=false;
            try{await Task.Run(()=>BrokerFiles.Read<CaptureState>(recordPath));}
            catch(IOException e)when(e.HResult==unchecked((int)0x80070020)){denied=true;}
            check(denied&&clock.Elapsed<TimeSpan.FromSeconds(3),"permanently locked status fails within a bounded time");
        }
        bool protectedRejected=false;
        try{BrokerFiles.ReadProtected<CaptureState>(recordPath);}catch(UnauthorizedAccessException){protectedRejected=true;}
        check(protectedRejected,"retry never accepts an unprotected status record");
        string invalidRecord=Path.Combine(root,"invalid-broker-record.json");File.WriteAllText(invalidRecord,"{invalid}");
        bool invalidRejected=false;try{BrokerFiles.Read<CaptureState>(invalidRecord);}catch(JsonException){invalidRejected=true;}
        check(invalidRejected,"retry never turns malformed status data into success");
        foreach(string stage in new[]{"Launching","NativeRunning","Interrupted"})
        {
            var uncertain=accepted with{Stage=stage,NativePid=123};
            var failed=BrokerFiles.RecordFailure(uncertain,"IOException");
            check(failed.Stage=="Interrupted"&&failed.NativePid==123,
                "post-launch failure preserves uncertain writer fence: "+stage);
        }
        check(BrokerFiles.RecordFailure(accepted,"IOException").Stage=="Failed",
            "pre-launch rejection cannot claim that a native writer is running");
        (StudioStore Store,BackupProfile Profile) New(string name,BackupDestination destination=BackupDestination.Chomikuj)
        {
            string path=Path.Combine(root,"system-image-jobs",name);
            var store=new StudioStore(Path.Combine(path,"store"));
            var profile=new BackupProfile{Name=name,Content=BackupContent.WindowsSystem,
                SystemImagePlanId=Guid.NewGuid().ToString("N"),SystemImageCacheRoot=Path.Combine(path,"cache"),
                Destination=destination,Daily=true,DailyMinute=0,CloudDateFolders=true,
                ProtectedSecrets=WindowsSecrets.Protect(secrets)};
            profile.Repository=SystemImageStorage.Repository(profile.SystemImageCacheRoot,profile.Id);
            store.Data.Profiles.Add(profile);store.Save();return(store,profile);
        }
        var legacy=JsonSerializer.Deserialize<BackupProfile>("{}")!;
        check(legacy.Content==BackupContent.Files&&legacy.PendingSystemImage is null,"old profiles remain file backups");
        var moved=New("unapproved-storage");var movedCapture=new Capture();int movedContacts=0;
        moved.Profile.Repository=Path.Combine(moved.Store.Root,"vault");moved.Store.Save();
        var movedResult=await new JobEngine(moved.Store,()=>{movedContacts++;return new Connection(new Remote());},movedCapture).RunAsync(moved.Profile,secrets,now);
        check(movedResult?.State==RunState.Failed&&movedCapture.Requests.Count==0&&movedContacts==0&&
            !Directory.Exists(moved.Profile.Repository),"fresh image rejects an unapproved repository before capture or writes");
        var plan=new ImagePlan(1,moved.Profile.SystemImagePlanId!,System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value,
            volume,@"\\?\Volume{"+Guid.NewGuid().ToString("D")+@"}\",Environment.MachineName);
        moved.Profile.Repository=SystemImageStorage.Repository(moved.Profile.SystemImageCacheRoot!,moved.Profile.Id);
        bool cacheRejected=false;
        try{SystemImageStorage.ValidateApproved(moved.Profile,plan);}catch(InvalidDataException){cacheRejected=true;}
        check(cacheRejected,"user settings cannot redirect approved volume-GUID storage to an arbitrary directory");
        var filesProfile=new BackupProfile{Source=root,Repository=Path.Combine(root,"file-vault")};
        string fileTransfer=SystemImageStorage.TransferDirectory(moved.Store,filesProfile,Guid.NewGuid().ToString("N"));
        check(fileTransfer.StartsWith(Path.Combine(moved.Store.Root,"transfers")+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase),
            "file backup transfer layout remains compatible");
        var unavailable=New("not-installed");
        int connections=0;
        var notInstalled=new JobEngine(unavailable.Store,()=>{connections++;return new Connection(new Remote());});
        var absent=await notInstalled.RunAsync(unavailable.Profile,secrets,now);
        check(absent?.FailureCode=="SYSTEM-CAPTURE-NOT-INSTALLED"&&connections==0&&
            !Directory.Exists(unavailable.Profile.Repository),"missing privileged worker fails before cloud or empty vault initialization");
        var untrusted=unavailable.Profile.PendingSystemImage!;
        await new Capture().CaptureAsync(new(untrusted.PlanId,untrusted.CaptureId,untrusted.RequestedUtc,
            SystemImageLease.DirectoryFor(unavailable.Profile,untrusted)),default);
        var forged=await notInstalled.RunAsync(unavailable.Profile,secrets,now);
        check(forged?.FailureCode=="SYSTEM-CAPTURE-NOT-INSTALLED"&&connections==0,
            "user-written capture receipt cannot bypass the trusted capture provider");

        var local=New("daily-local",BackupDestination.Local);var capture=new Capture();
        var engine=new JobEngine(local.Store,systemImages:capture);
        var first=await engine.RunAsync(local.Profile,secrets,now);
        check(first?.State==RunState.Success&&first.Content==BackupContent.WindowsSystem&&first.ImageCaptureId is not null,
            "image job records capture identity only after verified encrypted snapshot");
        check(capture.Requests[0].OutputDirectory.StartsWith(local.Profile.SystemImageCacheRoot!+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)&&
            !capture.Requests[0].OutputDirectory.StartsWith(local.Store.Root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase),
            "large image export stays in the image cache instead of AppData settings");
        string transfer=SystemImageStorage.TransferDirectory(local.Store,local.Profile,Guid.NewGuid().ToString("N"));
        check(transfer.StartsWith(local.Profile.SystemImageCacheRoot!+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase),
            "system image upload staging also stays outside the settings directory");
        string firstId=first!.Snapshot!,firstCapture=first.ImageCaptureId!;
        check(SchedulePolicy.Due(local.Profile,now.AddDays(1),null,false),"next daily system image becomes due");
        var next=await engine.RunAsync(local.Profile,secrets,now.AddDays(1));
        check(next?.State==RunState.Success&&capture.Requests.Count==2&&
            next.ImageCaptureId!=firstCapture&&next.Snapshot!=firstId,"next day requests a new capture, never resends yesterday's image");
        using(var vault=LocalEncryptedVault.Open(local.Profile.Repository,secrets.VaultPassword))
        {
            check(vault.ListSnapshotIds().Contains(firstId),"daily image retains prior encrypted snapshot");
            string restored=Path.Combine(root,"system-image-first-restore");vault.RestoreSnapshot(firstId,restored);
            var receipt=JsonSerializer.Deserialize<SystemImageReceipt>(File.ReadAllText(Path.Combine(restored,SystemImageLease.ReceiptName)))!;
            check(receipt.CaptureId==firstCapture&&Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(
                Path.Combine(restored,SystemImageLease.ArchiveName)))).Equals(receipt.ArchiveSha256,StringComparison.OrdinalIgnoreCase),
                "restored first image carries its own capture receipt and exact archive hash");
        }

        var cloud=New("resume-cloud");var cloudCapture=new Capture();var remote=new Remote{Block=true};
        var cloudEngine=new JobEngine(cloud.Store,()=>new Connection(remote),cloudCapture);
        var running=cloudEngine.RunAsync(cloud.Profile,secrets,now);
        await remote.Started.Task.WaitAsync(TimeSpan.FromSeconds(30));
        cloudEngine.Cancel();var interrupted=await running;
        check(interrupted?.State==RunState.Cancelled&&cloud.Profile.PendingSystemImage?.Proof is not null&&
            cloud.Profile.PendingSnapshot is not null,"interrupted upload persists capture proof and immutable snapshot");
        string pending=cloud.Profile.PendingSnapshot!,captureId=cloud.Profile.PendingSystemImage!.CaptureId;
        string day=cloud.Profile.PendingCloudDate!;
        check(!remote.Files.Keys.Any(n=>n.EndsWith(".snap")),"image manifest is not published while transfer is incomplete");
        var unsafeStore=new StudioStore(Path.Combine(root,"unsafe-image-storage"));
        var unsafeProfile=JsonSerializer.Deserialize<BackupProfile>(JsonSerializer.Serialize(cloud.Profile))!;
        unsafeProfile.Repository=Path.Combine(unsafeStore.Root,"vault");
        unsafeStore.Data.Profiles.Add(unsafeProfile);unsafeStore.Save();int unsafeContacts=0;
        var unsafeResult=await new JobEngine(unsafeStore,()=>{unsafeContacts++;return new Connection(remote);},cloudCapture).RunAsync(unsafeProfile,secrets,now);
        check(unsafeResult?.State==RunState.Failed&&unsafeContacts==0&&cloudCapture.Requests.Count==1&&
            !Directory.Exists(unsafeProfile.Repository),"resumed image rejects relocated vault before creating data, capturing or networking");
        foreach(bool missingProof in new[]{false,true})
        {
            // Corrupt a COPY of the saved settings, preserving the real pending
            // snapshot and its original store for the subsequent successful retry.
            var damagedStore=new StudioStore(Path.Combine(root,"damaged-image-proof-"+missingProof));
            var damaged=JsonSerializer.Deserialize<BackupProfile>(JsonSerializer.Serialize(cloud.Profile))!;
            damaged.PendingSystemImage!.Proof=missingProof?null:damaged.PendingSystemImage.Proof! with{ArchiveSha256=new string('0',64)};
            damagedStore.Data.Profiles.Add(damaged);damagedStore.Save();int contacts=0;
            var failed=await new JobEngine(damagedStore,()=>{contacts++;return new Connection(remote);},cloudCapture).RunAsync(damaged,secrets,now);
            check(failed?.State==RunState.Failed&&contacts==0&&cloudCapture.Requests.Count==1,
                "resumed image rejects missing or mismatched binding proof before cloud: "+missingProof);
        }
        remote.Block=false;
        var reload=new StudioStore(cloud.Store.Root);var reloaded=reload.Data.Profiles.Single();
        var resumed=await new JobEngine(reload,()=>new Connection(remote),cloudCapture).RunAsync(reloaded,secrets,now.AddDays(1));
        check(resumed?.State==RunState.Success&&resumed.Snapshot==pending&&resumed.ImageCaptureId==captureId&&
            cloudCapture.Requests.Count==1,"restart across midnight resumes same image without starting another native capture");
        check(remote.Days.Distinct().SequenceEqual(new[]{day}),"resumed image keeps original cloud folder day");
        check(reloaded.PendingSystemImage is null&&reloaded.PendingSnapshot is null,"successful verified upload commits and clears pending capture");
        check(remote.Uploads==remote.Files.Count,"resume does not duplicate confirmed encrypted records");
        string download=Path.Combine(root,"system-image-independent-download"),restore=Path.Combine(root,"system-image-cloud-restore");
        await new CloudVaultTransfer(remote).DownloadSnapshotAsync(pending,secrets.VaultPassword,download,null,default);
        using(var vault=LocalEncryptedVault.Open(download,secrets.VaultPassword))vault.RestoreSnapshot(pending,restore);
        var description=JsonSerializer.Deserialize<SystemImageReceipt>(File.ReadAllText(Path.Combine(restore,SystemImageLease.ReceiptName)))!;
        check(description.CaptureId==captureId&&Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(restore,SystemImageLease.ArchiveName)))).Equals(description.ArchiveSha256,StringComparison.OrdinalIgnoreCase),
            "independent cloud repository decrypts archive and receipt without original profile");
        var newDay=await new JobEngine(reload,()=>new Connection(remote),cloudCapture).RunAsync(reloaded,secrets,now.AddDays(2));
        check(newDay?.State==RunState.Success&&cloudCapture.Requests.Count==2&&newDay.ImageCaptureId!=captureId,
            "fresh capture resumes only after pending cloud image has completed");

        foreach(string fault in new[]{"wrong-id","wrong-plan","native-failed","no-critical","no-vss","stale-time","changed-bytes","extra-file","no-catalog","zip-traversal","zip-case-alias","file-parent","device-name","double-slash","zip-symlink"})
        {
            var state=New(fault);var bad=new Capture{Fault=fault};int contacts=0;
            var result=await new JobEngine(state.Store,()=>{contacts++;return new Connection(new Remote());},bad).RunAsync(state.Profile,secrets,now);
            check(result?.State==RunState.Failed&&result.Snapshot is null&&contacts==0&&state.Profile.LastSuccess is null,
                "invalid system image cannot reach cloud or success: "+fault);
        }

        // Cancellation after native completion must keep the completed result and
        // let the next process consume it, not request a second capture.
        var cancelled=New("cancel-after-capture",BackupDestination.Local);var completed=new Capture();
        var cancelEngine=new JobEngine(cancelled.Store,systemImages:completed);
        completed.AfterCapture=()=>cancelEngine.Cancel();
        var cancelledResult=await cancelEngine.RunAsync(cancelled.Profile,secrets,now);
        string completedId=cancelled.Profile.PendingSystemImage!.CaptureId;
        check(cancelledResult?.State==RunState.Cancelled&&completed.Requests.Count==1,"cancel after native completion keeps capture identity");
        var completeStore=new StudioStore(cancelled.Store.Root);var completeProfile=completeStore.Data.Profiles.Single();
        var recovered=await new JobEngine(completeStore,systemImages:completed).RunAsync(completeProfile,secrets,now);
        check(recovered?.State==RunState.Success&&recovered.ImageCaptureId==completedId&&completed.Requests.Count==1,
            "completed receipt after cancellation is recovered without another capture");
        check(completed.Reconciliations==2,"retry checks broker completion even when user staging already has a receipt");

        // File leases must actually deny changes for the entire encryption phase.
        var pendingLease=new PendingSystemImage(capture.Requests[0].PlanId,firstCapture,capture.Requests[0].RequestedUtc);
        using(var lease=await SystemImageLease.OpenAsync(capture.Requests[0].OutputDirectory,pendingLease,default))
        {
            bool denied=false;
            try{using var writer=File.OpenWrite(Path.Combine(capture.Requests[0].OutputDirectory,SystemImageLease.ArchiveName));}
            catch(IOException){denied=true;}
            check(denied,"Windows read lease denies changes during verification and encryption");
        }

        var missing=New("missing-pending-proof");missing.Profile.PendingSnapshot=firstId;missing.Store.Save();int missingContacts=0;
        var missingResult=await new JobEngine(missing.Store,()=>{missingContacts++;return new Connection(new Remote());},new Capture()).RunAsync(missing.Profile,secrets,now);
        check(missingResult?.State==RunState.Failed&&missingContacts==0,"pending image without binding proof fails closed");
        Console.WriteLine("SYSTEM_IMAGE_JOB_PIPELINE=PASS (synthetic capture provider and in-memory cloud; no Windows image created)");
    }

    private sealed class Capture : ISystemImageCapture
    {
        public void ValidateStorage(BackupProfile profile)=>SystemImageStorage.ValidateShape(profile);
        internal readonly List<SystemImageCaptureRequest> Requests=new();
        internal int Reconciliations;
        internal string? Fault;internal Action? AfterCapture;
        public Task CaptureAsync(SystemImageCaptureRequest request,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();Reconciliations++;
            var previous=Requests.SingleOrDefault(r=>r.CaptureId==request.CaptureId);
            if(previous is not null)
            {
                if(previous!=request)throw new InvalidDataException("Capture ID was rebound to a different request.");
                return Task.CompletedTask; // Test provider's own ledger, NOT a file existence check.
            }
            Requests.Add(request);
            if(Directory.Exists(request.OutputDirectory))throw new IOException("Never overwrite a prior capture.");
            Directory.CreateDirectory(request.OutputDirectory);
            string path=Path.Combine(request.OutputDirectory,SystemImageLease.ArchiveName);
            using(var zip=new ZipArchive(new FileStream(path,FileMode.CreateNew),ZipArchiveMode.Create))
            {
                void Entry(string name){using var output=zip.CreateEntry(name).Open();output.Write(RandomNumberGenerator.GetBytes(1024));}
                Entry("WindowsImageBackup/SYNTH/Backup/volume.vhdx");
                if(Fault!="no-catalog")Entry("WindowsImageBackup/SYNTH/Catalog/GlobalCatalog");
                if(Fault=="zip-traversal")Entry("WindowsImageBackup/../outside.bin");
                if(Fault=="zip-case-alias")Entry("WindowsImageBackup/SYNTH/backup/VOLUME.vhdx");
                if(Fault=="file-parent")Entry("WindowsImageBackup/SYNTH/Backup");
                if(Fault=="device-name")Entry("WindowsImageBackup/SYNTH/NUL.txt");
                if(Fault=="double-slash")zip.CreateEntry("WindowsImageBackup/SYNTH//");
                if(Fault=="zip-symlink")zip.CreateEntry("WindowsImageBackup/SYNTH/link").ExternalAttributes=unchecked((int)0xA1FF0000);
            }
            var receipt=new SystemImageReceipt(1,Fault=="wrong-plan"?Guid.NewGuid().ToString("N"):request.PlanId,
                Fault=="wrong-id"?Guid.NewGuid().ToString("N"):request.CaptureId,request.RequestedUtc,
                Fault=="stale-time"?request.RequestedUtc.AddDays(-1):DateTimeOffset.UtcNow,Fault=="native-failed"?1:0,
                Fault!="no-critical",Fault!="no-vss",new FileInfo(path).Length,Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))));
            File.WriteAllText(Path.Combine(request.OutputDirectory,SystemImageLease.ReceiptName),JsonSerializer.Serialize(receipt));
            if(Fault=="changed-bytes"){byte[] bytes=File.ReadAllBytes(path);bytes[40]^=1;File.WriteAllBytes(path,bytes);}
            if(Fault=="extra-file")File.WriteAllText(Path.Combine(request.OutputDirectory,"unrelated.txt"),"do not upload");
            AfterCapture?.Invoke();return Task.CompletedTask;
        }
    }
    private sealed class Connection(Remote remote):IJobCloud
    {
        public Task<ICloudVault> ConnectAsync(BackupProfile profile,JobSecrets secrets,CancellationToken token)
        {remote.Days.Add(profile.PendingCloudDate!);return Task.FromResult<ICloudVault>(remote);}
        public void Dispose(){}
    }
    private sealed class Remote:ICloudVault
    {
        internal readonly Dictionary<string,byte[]> Files=new();internal readonly List<string> Days=new();
        internal readonly TaskCompletionSource Started=new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool Block;internal int Uploads;
        public Task<IReadOnlyList<CloudObject>> ListAsync(CancellationToken token)=>Task.FromResult<IReadOnlyList<CloudObject>>(
            Files.Select(p=>new CloudObject(p.Key,p.Key,p.Value.Length)).ToArray());
        public async Task<CloudObject> UploadAsync(string name,Stream input,long length,CancellationToken token)
        {
            using var memory=new MemoryStream();await input.CopyToAsync(memory,token);Files.Add(name,memory.ToArray());Uploads++;
            Started.TrySetResult();if(Block)await Task.Delay(Timeout.Infinite,token);return new(name,name,length);
        }
        public async Task DownloadAsync(CloudObject file,Stream output,long maximum,CancellationToken token)
        {if(Files[file.Name].LongLength>maximum)throw new InvalidDataException();await output.WriteAsync(Files[file.Name],token);}
    }
}
