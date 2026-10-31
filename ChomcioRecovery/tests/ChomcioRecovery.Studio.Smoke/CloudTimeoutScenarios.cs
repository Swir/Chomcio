using ChomcioRecovery.Chomikuj;
using ChomcioRecovery.Core;
using ChomcioRecovery.Desktop;
using System.Net;
using System.Text.Json;
using System.Xml.Linq;

internal static class CloudTimeoutScenarios
{
    internal static async Task Run(string root,Action<bool,string> check)
    {
        if(Directory.Exists(root))throw new IOException("Use a new test directory.");
        Directory.CreateDirectory(root);
        string source=Path.Combine(root,"source");Directory.CreateDirectory(source);
        File.WriteAllText(Path.Combine(source,"fixture.txt"),"synthetic timeout fixture");
        var profile=new BackupProfile{Name="Timeout diagnostics",Source=source,Repository=Path.Combine(root,"vault"),Destination=BackupDestination.Chomikuj};
        var store=new StudioStore(Path.Combine(root,"settings"));store.Data.Profiles.Add(profile);store.Save();
        var secrets=new JobSecrets("synthetic-vault-secret","synthetic-login","synthetic-password");
        const string listing="Sprawdzanie listy i rozmiarów plików w chmurze";
        string? seen=null;
        JobEngine? engine=null;
        var remote=new FaultCloud(()=>{seen=engine!.Phase;throw new OperationCanceledException();});
        engine=new JobEngine(store,()=>new Connection(remote));
        var first=await engine.RunAsync(profile,secrets,DateTimeOffset.UtcNow);
        check(first is {State:RunState.Failed,FailureCode:"TIMEOUT"}&&seen==listing&&first.FailureStage==listing,
            "listing timeout is identified before the first cloud callback, not as local export checking");
        string pending=profile.PendingSnapshot!;
        check(pending is not null&&remote.Writes==0&&remote.Reads==0,"listing failure preserves the snapshot and never enters transfer");
        foreach(var operation in new[]{ChomikujClient.HttpOperation.WebSession,ChomikujClient.HttpOperation.UploadAddress,
            ChomikujClient.HttpOperation.UploadContent,ChomikujClient.HttpOperation.DownloadContent})
        {
            using var handler=new CancelResponse(operation);
            using var client=new ChomikujClient(handler);
            await client.LoginAsync("synthetic-user","synthetic-password",default);
            OperationCanceledException? error=null;
            try
            {
                var folder=client.OpenFolder(new("7","Synthetic"));
                if(operation==ChomikujClient.HttpOperation.DownloadContent)await folder.ListAsync(default);
                else {using var input=new MemoryStream(new byte[]{1,2,3});await folder.UploadAsync("repo.json",input,3,default);}
            }
            catch(OperationCanceledException value){error=value;}
            var metadata=error is null?null:ChomikujClient.GetTransportFailure(error);
            check(metadata is {Error:HttpRequestError.Unknown,CauseKind:"Cancellation",NativeErrorCode:null}
                &&metadata.Operation==operation&&metadata.CauseHResult is not null,"cancellation preserves a closed operation and numeric cause");
            check(handler.FailureCalls==(operation==ChomikujClient.HttpOperation.DownloadContent?3:1),
                "read retry budget is unchanged and session/address/content writes are not repeated");
            check(error?.InnerException is null&&error is not null&&!error.ToString().Contains("private-timeout-secret"),
                "raw timeout exception and signed URL are not retained");
            var failed=new FaultCloud(()=>throw error!);
            var run=await new JobEngine(store,()=>new Connection(failed)).RunAsync(profile,secrets,DateTimeOffset.UtcNow);
            var saved=new StudioStore(store.Root).Data.History.Last();
            check(run is {State:RunState.Failed,FailureCode:"TIMEOUT",HttpStatus:null,RetryAfterSeconds:null}
                &&saved.HttpOperation==operation.ToString()&&saved.CauseKind=="Cancellation"&&saved.FailureStage==listing,
                "timeout operation survives history persistence without an invented HTTP response");
            check(saved.Snapshot==pending&&profile.PendingSnapshot==pending&&!JsonSerializer.Serialize(saved).Contains("private-timeout-secret"),
                "timeout retains the same snapshot and sanitized history");
        }
        foreach(bool download in new[]{false,true})
        {
            var instant=new InstantTransferFailure(download);
            var run=await new JobEngine(store,()=>new Connection(instant)).RunAsync(profile,secrets,DateTimeOffset.UtcNow);
            check(run?.FailureStage==(download?"Sprawdzanie danych pobranych z Chomikuj":"Wysyłanie zaszyfrowanych danych"),
                "immediate transfer failure records the current phase synchronously");
        }
        using(var caller=new CancellationTokenSource())
        using(var handler=new CancelResponse(ChomikujClient.HttpOperation.WebSession,caller.Cancel))
        using(var client=new ChomikujClient(handler))
        {
            await client.LoginAsync("synthetic-user","synthetic-password",caller.Token);
            using var input=new MemoryStream(new byte[]{1,2,3});
            OperationCanceledException? error=null;
            try{await client.OpenFolder(new("7","Synthetic")).UploadAsync("repo.json",input,3,caller.Token);}
            catch(OperationCanceledException value){error=value;}
            check(error?.CancellationToken.IsCancellationRequested==true&&handler.FailureCalls==1,
                "adapter cancellation retains the cancelled token and never retries a write");
        }
        JobEngine? cancelled=null;
        var cancelRemote=new FaultCloud(()=>{cancelled!.Cancel();throw new OperationCanceledException();});
        cancelled=new JobEngine(store,()=>new Connection(cancelRemote));
        var stopped=await cancelled.RunAsync(profile,secrets,DateTimeOffset.UtcNow);
        check(stopped is {State:RunState.Cancelled,FailureCode:null,HttpOperation:null,TransportError:null},"caller cancellation remains cancellation, not a network timeout");
        check(ChomikujClient.GetTransportFailure(new OperationCanceledException()) is null,"unknown cancellation does not invent an operation");
        check(new StudioStore(store.Root).Data.History.First() is {HttpOperation:null,CauseKind:null},
            "later classified failures do not fill in unknown historical metadata");
        using var vault=LocalEncryptedVault.Open(profile.Repository,secrets.VaultPassword);
        check(vault.ListSnapshotIds().Count==1&&profile.PendingSnapshot==pending&&profile.LastSuccess is null,"all diagnostic paths preserve one pending snapshot without success");
    }
    private sealed class Connection(ICloudVault remote):IJobCloud
    {
        public Task<ICloudVault> ConnectAsync(BackupProfile profile,JobSecrets secrets,CancellationToken token)=>Task.FromResult(remote);
        public void Dispose(){}
    }
    private sealed class FaultCloud(Action fail):ICloudVault
    {
        internal int Writes,Reads;
        public Task<IReadOnlyList<CloudObject>> ListAsync(CancellationToken token){fail();throw new InvalidOperationException();}
        public Task<CloudObject> UploadAsync(string name,Stream input,long length,CancellationToken token){Writes++;throw new InvalidOperationException();}
        public Task DownloadAsync(CloudObject file,Stream output,long max,CancellationToken token){Reads++;throw new InvalidOperationException();}
    }
    private sealed class InstantTransferFailure(bool download):ICloudVault
    {
        public Task<IReadOnlyList<CloudObject>> ListAsync(CancellationToken token)=>Task.FromResult<IReadOnlyList<CloudObject>>(Array.Empty<CloudObject>());
        public Task<CloudObject> UploadAsync(string name,Stream input,long length,CancellationToken token)
            =>download?Task.FromResult(new CloudObject(name,name,length)):Task.FromException<CloudObject>(new OperationCanceledException());
        public Task DownloadAsync(CloudObject file,Stream output,long max,CancellationToken token)=>Task.FromException(new OperationCanceledException());
    }
    private sealed class CancelResponse(ChomikujClient.HttpOperation failure,Action? beforeCancel=null):HttpMessageHandler
    {
        internal int FailureCalls;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            var uri=request.RequestUri!;
            if(uri.AbsolutePath.Contains("LoginFromBox",StringComparison.Ordinal))
                return Reply(ChomikujClient.HttpOperation.WebSession,"<input name='__RequestVerificationToken' value='synthetic'>",token);
            if(uri.AbsolutePath.Contains("/Upload/GetUrl/",StringComparison.Ordinal))
                return Reply(ChomikujClient.HttpOperation.UploadAddress,"{\"Url\":\"https://upload.chomikuj.pl/fixture?token=private-timeout-secret\"}",token);
            if(uri.IdnHost=="upload.chomikuj.pl")return Reply(ChomikujClient.HttpOperation.UploadContent,"",token);
            if(uri.IdnHost=="download.chomikuj.pl")return Reply(ChomikujClient.HttpOperation.DownloadContent,"",token);
            string xml=await request.Content!.ReadAsStringAsync(token);
            string action=XDocument.Parse(xml).Root!.Elements().Single().Elements().Single().Name.LocalName;
            string file="<FileEntry><id>42</id><name>repo.json</name><size>3</size><url>https://download.chomikuj.pl/fixture?token=private-timeout-secret</url></FileEntry>";
            string payload=action switch
            {
                "Auth"=>"<token>synthetic-token</token><hamsterId>123</hamsterId><hamsterName>synthetic-user</hamsterName>",
                "Download"=>"<list><DownloadFolder><files>"+(failure==ChomikujClient.HttpOperation.DownloadContent?file:"")+"</files></DownloadFolder></list>",
                _=>throw new InvalidOperationException("Unexpected synthetic request")
            };
            return new(HttpStatusCode.OK){Content=new StringContent($"<Envelope><Body><{action}Response><{action}Result><status>Ok</status>{payload}</{action}Result></{action}Response></Body></Envelope>")};
        }
        private HttpResponseMessage Reply(ChomikujClient.HttpOperation operation,string body,CancellationToken token)
        {
            if(operation==failure){FailureCalls++;beforeCancel?.Invoke();throw new OperationCanceledException("https://example.invalid/?token=private-timeout-secret",new TimeoutException("private-timeout-secret"),token);}
            return new(HttpStatusCode.OK){Content=new StringContent(body)};
        }
    }
}
