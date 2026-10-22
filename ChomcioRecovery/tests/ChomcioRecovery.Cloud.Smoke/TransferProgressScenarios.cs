using ChomcioRecovery.Core;

internal static class TransferProgressScenarios
{
    internal static async Task Run(string repository,string password,string snapshot,Func<string,string> path,Action<bool,string> check)
    {
        // Hold a real verification callback to prove the async API returns to
        // its caller before finishing local work, without relying on file size
        // or machine speed. Cancellation must still precede all remote calls.
        using(var entered=new ManualResetEventSlim())
        using(var release=new ManualResetEventSlim())
        using(var cancel=new CancellationTokenSource())
        {
            var remote=new ProbeCloud();var returned=new TaskCompletionSource<Task>(TaskCreationOptions.RunContinuationsAsynchronously);
            int callerThread=0,workerThread=0;
            var observer=new Inline(p=>
            {
                if(entered.IsSet)return;
                workerThread=Environment.CurrentManagedThreadId;entered.Set();
                if(!release.Wait(TimeSpan.FromSeconds(15)))throw new TimeoutException("Test did not release local verification.");
            });
            var caller=new Thread(()=>
            {
                callerThread=Environment.CurrentManagedThreadId;
                try{returned.SetResult(new CloudVaultTransfer(remote).UploadSnapshotAsync(repository,password,snapshot,path("responsive"),null,cancel.Token,observer));}
                catch(Exception error){returned.SetException(error);}
            }){IsBackground=true};
            caller.Start();Task? operation=null;
            try
            {
                operation=await returned.Task.WaitAsync(TimeSpan.FromSeconds(5));
                check(entered.Wait(TimeSpan.FromSeconds(5))&&!operation.IsCompleted&&workerThread!=callerThread,"async upload returns while local verification runs on a worker");
                check(remote.Calls==0,"no remote call while local preparation is incomplete");
                cancel.Cancel();
            }
            finally{release.Set();}
            bool stopped=false;
            try{await operation!;}catch(OperationCanceledException){stopped=true;}
            check(stopped&&remote.Calls==0,"caller can cancel local preparation before remote access");
        }
        foreach(var phase in new[]{VaultProgressStage.CopyingEncryptedExport,VaultProgressStage.CheckingPublishedExport})
        {
            using var cancel=new CancellationTokenSource();var remote=new ProbeCloud();bool stopped=false;
            string target=path("cancel-"+phase);
            var observer=new Inline(p=>{if(p.Stage==phase&&p.ProcessedBytes>0)cancel.Cancel();});
            try{await new CloudVaultTransfer(remote).UploadSnapshotAsync(repository,password,snapshot,target,null,cancel.Token,observer);}
            catch(OperationCanceledException){stopped=true;}
            check(stopped&&remote.Calls==0,"no cloud writes after cancellation in "+phase);
            bool committed=phase==VaultProgressStage.CheckingPublishedExport;
            check(Directory.Exists(target)==committed,"cancelled transfer preserves only an already published export: "+phase);
            if(committed){using var exported=LocalEncryptedVault.Open(target,password);exported.VerifySnapshot(snapshot);}
        }
        var corruptRemote=new ProbeCloud();string corrupt=path("corrupt-export");bool changed=false,refused=false;
        var tamper=new Inline(p=>
        {
            if(changed||p.Stage!=VaultProgressStage.CheckingPublishedExport||p.ProcessedBytes!=0)return;
            string item=Directory.EnumerateFiles(Path.Combine(corrupt,"objects"),"*.obj",SearchOption.AllDirectories).First();
            var data=File.ReadAllBytes(item);data[^1]^=1;File.WriteAllBytes(item,data);changed=true;
        });
        try{await new CloudVaultTransfer(corruptRemote).UploadSnapshotAsync(repository,password,snapshot,corrupt,null,default,tamper);}
        catch(System.Security.Cryptography.CryptographicException){refused=true;}
        catch(InvalidDataException){refused=true;}
        check(changed&&refused&&corruptRemote.Calls==0,"final export corruption is rejected before any cloud operation");
        using var original=LocalEncryptedVault.Open(repository,password);original.VerifySnapshot(snapshot);
        check(true,"export cancellation and corruption preserve the original verified snapshot");
    }

    private sealed class Inline(Action<VaultProgress> report):IProgress<VaultProgress>
    {public void Report(VaultProgress value)=>report(value);}
    private sealed class ProbeCloud:ICloudVault
    {
        internal int Calls;
        public Task<IReadOnlyList<CloudObject>> ListAsync(CancellationToken token){Interlocked.Increment(ref Calls);throw new IOException("Unexpected network access before preparation completed.");}
        public Task<CloudObject> UploadAsync(string name,Stream input,long length,CancellationToken token){Interlocked.Increment(ref Calls);throw new IOException("Unexpected upload.");}
        public Task DownloadAsync(CloudObject file,Stream output,long maximumBytes,CancellationToken token){Interlocked.Increment(ref Calls);throw new IOException("Unexpected download.");}
    }
}
