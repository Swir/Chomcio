using ChomcioRecovery.Core;
using ChomcioRecovery.Desktop;
using System.Security.Cryptography;

internal static class LocalJobProgressScenarios
{
    internal static async Task Run(string root,Action<bool,string> check)
    {
        string area=Path.Combine(root,"local-job-progress"),source=Path.Combine(area,"source");Directory.CreateDirectory(source);
        File.WriteAllBytes(Path.Combine(source,"synthetic.bin"),RandomNumberGenerator.GetBytes(2*LocalEncryptedVault.ChunkBytes+17));
        var profile=new BackupProfile{Name="Local progress test",Source=source,Repository=Path.Combine(area,"vault"),Destination=BackupDestination.Local};
        var store=new StudioStore(Path.Combine(area,"settings"));store.Data.Profiles.Add(profile);store.Save();
        var secrets=new JobSecrets("synthetic-progress-test-key","","");
        var engine=new JobEngine(store);
        var observed=new List<VaultProgress>();
        engine.Changed+=()=>{if(engine.LocalProgress is {} value)observed.Add(value);};
        var result=await engine.RunAsync(profile,secrets,DateTimeOffset.Now);
        check(result?.State==RunState.Success,"local job with byte progress succeeds");
        check(observed.Any(x=>x.Stage==VaultProgressStage.Encrypting&&x.ProcessedBytes>0&&x.ProcessedBytes<x.TotalBytes),"job exposes in-file encryption progress to the window");
        check(observed.Any(x=>x.Stage==VaultProgressStage.VerifyingSnapshot&&x.ProcessedBytes==x.TotalBytes),"job exposes independent local verification pass");
        check(engine.LocalProgress is null&&engine.TotalRecords==0&&!engine.IsBusy,"finished job clears byte and transfer counters");
        string snapshot=result!.Snapshot!;bool requested=false;
        engine.Changed+=()=>
        {
            if(!requested&&engine.LocalProgress is {Stage:VaultProgressStage.Encrypting,ProcessedBytes:>0})
            {requested=true;engine.Cancel();}
        };
        var cancelled=await engine.RunAsync(profile,secrets,DateTimeOffset.Now.AddMinutes(1));
        check(requested&&cancelled?.State==RunState.Cancelled,"user cancellation during byte progress is reported as cancelled");
        check(engine.LocalProgress is null&&!engine.IsBusy,"cancelled job does not leave a completed-looking progress bar");
        using var vault=LocalEncryptedVault.Open(profile.Repository,secrets.VaultPassword);vault.VerifySnapshot(snapshot);
        check(vault.ListSnapshotIds().Count==1,"cancelled local preparation preserves the previous verified snapshot");
        await CloudPreparation(area,source,secrets,check);
    }

    private static async Task CloudPreparation(string area,string source,JobSecrets localSecrets,Action<bool,string> check)
    {
        var profile=new BackupProfile{Name="Cloud preparation",Source=source,Repository=Path.Combine(area,"cloud-vault"),Destination=BackupDestination.Chomikuj};
        var secrets=localSecrets with{CloudLogin="synthetic-user",CloudPassword="synthetic-cloud-password"};
        var store=new StudioStore(Path.Combine(area,"cloud-settings"));store.Data.Profiles.Add(profile);store.Save();
        var remote=new MemoryCloud();var engine=new JobEngine(store,()=>new Connection(remote));
        using var entered=new ManualResetEventSlim();using var release=new ManualResetEventSlim();
        int blocked=0;bool timerCancelled=false;
        engine.Changed+=()=>
        {
            if(engine.LocalProgress is {Stage:VaultProgressStage.CheckingExportSource,ProcessedBytes:>0}&&Interlocked.CompareExchange(ref blocked,1,0)==0)
            {
                entered.Set();
                if(!release.Wait(TimeSpan.FromSeconds(10)))throw new TimeoutException("UI did not process cancellation during local export.");
            }
        };
        // A real WinForms message-loop timer must remain responsive while the
        // worker is held inside verification. No mouse/keyboard or live account.
        using var timer=new System.Windows.Forms.Timer{Interval=20};
        timer.Tick+=(_,_)=>{if(entered.IsSet){timer.Stop();timerCancelled=true;engine.Cancel();release.Set();}};
        RunRecord? cancelled;
        timer.Start();
        try{cancelled=await engine.RunAsync(profile,secrets,DateTimeOffset.Now);}
        finally{timer.Stop();release.Set();}
        check(timerCancelled&&cancelled?.State==RunState.Cancelled,"Windows message loop handles stop while cloud preparation is busy");
        check(remote.Calls==0&&profile.LastSuccess is null&&profile.PendingSnapshot is not null,"preparation cancellation retains pending snapshot without cloud file operations or success");
        check(engine.LocalProgress is null&&engine.TotalRecords==0&&!engine.IsBusy,"cancelled cloud preparation clears its byte counters");
        string pending=profile.PendingSnapshot!;
        var observed=new System.Collections.Concurrent.ConcurrentQueue<VaultProgress>();
        engine.Changed+=()=>{if(engine.LocalProgress is {} value)observed.Enqueue(value);};
        var resumed=await engine.RunAsync(profile,secrets,DateTimeOffset.Now.AddMinutes(1));
        check(resumed?.State==RunState.Success&&resumed.Snapshot==pending&&profile.PendingSnapshot is null,"resuming cancelled preparation uploads the same snapshot");
        check(observed.Any(p=>p.Stage==VaultProgressStage.CopyingEncryptedExport&&p.ProcessedBytes>0)&&
            observed.Any(p=>p.Stage==VaultProgressStage.CheckingPublishedExport&&p.ProcessedBytes==p.TotalBytes),"job forwards byte progress through export copying and final verification");
        check(remote.Downloads==remote.Files.Count&&remote.Files.ContainsKey(pending+".snap"),"resumed cloud job reads back every record before success");
        using var vault=LocalEncryptedVault.Open(profile.Repository,secrets.VaultPassword);
        check(vault.ListSnapshotIds().Count==1,"resume after preparation cancellation creates no duplicate snapshot");
    }

    private sealed class Connection(MemoryCloud remote):IJobCloud
    {public Task<ICloudVault> ConnectAsync(BackupProfile profile,JobSecrets secrets,CancellationToken token)=>Task.FromResult<ICloudVault>(remote);public void Dispose(){}}
    private sealed class MemoryCloud:ICloudVault
    {
        internal Dictionary<string,byte[]> Files=new(StringComparer.Ordinal);
        internal int Calls,Downloads;
        public Task<IReadOnlyList<CloudObject>> ListAsync(CancellationToken token)
        {token.ThrowIfCancellationRequested();Calls++;return Task.FromResult<IReadOnlyList<CloudObject>>(Files.Select(p=>new CloudObject(p.Key,p.Key,p.Value.Length)).ToArray());}
        public async Task<CloudObject> UploadAsync(string name,Stream input,long length,CancellationToken token)
        {Calls++;using var buffer=new MemoryStream();await input.CopyToAsync(buffer,token);Files.Add(name,buffer.ToArray());return new(name,name,length);}
        public async Task DownloadAsync(CloudObject file,Stream output,long maximumBytes,CancellationToken token)
        {Calls++;Downloads++;var data=Files[file.Name];if(data.LongLength>maximumBytes)throw new InvalidDataException();await output.WriteAsync(data,token);}
    }
}
