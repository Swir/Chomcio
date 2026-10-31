using ChomcioRecovery.Chomikuj;
using ChomcioRecovery.Core;
using ChomcioRecovery.Desktop;
using System.Net;
using System.Text.Json;
using System.Xml.Linq;

internal static class CloudHttpFailureScenarios
{
    internal static async Task Run(string root,Action<bool,string> check)
    {
        if(Directory.Exists(root))throw new IOException("Use a new test directory.");
        Directory.CreateDirectory(root);
        string source=Path.Combine(root,"source");Directory.CreateDirectory(source);
        File.WriteAllText(Path.Combine(source,"fixture.txt"),"synthetic HTTP diagnostics fixture");
        var profile=new BackupProfile{Name="HTTP diagnostics",Source=source,Repository=Path.Combine(root,"vault"),Destination=BackupDestination.Chomikuj};
        var store=new StudioStore(Path.Combine(root,"settings"));store.Data.Profiles.Add(profile);store.Save();
        var secrets=new JobSecrets("synthetic-vault-secret","synthetic-login","synthetic-password");
        string? pending=null;
        foreach(var (status,delay) in new[]{(403,(int?)null),(429,(int?)300),(503,(int?)180)})
        {
            using var handler=new ErrorResponse((HttpStatusCode)status,delay);
            using var client=new ChomikujClient(handler);
            ChomikujClient.CloudHttpException? error=null;
            try{await client.LoginAsync(secrets.CloudLogin,secrets.CloudPassword,default);}
            catch(ChomikujClient.CloudHttpException e){error=e;}
            check(error is not null&&(int)error.StatusCode==status&&error.RetryAfter?.TotalSeconds==delay&&error.Operation==ChomikujClient.HttpOperation.SoapRequest,"transport preserves HTTP, operation and optional Retry-After");
            check(handler.Calls==1,"permanent failure or long Retry-After is not retried early");
            var engine=new JobEngine(store,()=>new FailedConnection(error!));
            var run=await engine.RunAsync(profile,secrets,DateTimeOffset.UtcNow);
            check(run?.State==RunState.Failed&&run.HttpStatus==status&&run.RetryAfterSeconds==delay,"job records safe response metadata");
            check(run?.Detail.Contains("HTTP "+status)==true&&(delay is null||run.Detail.Contains(delay+" s")),"history text explains HTTP and requested delay");
            pending??=profile.PendingSnapshot;
            check(pending is not null&&profile.PendingSnapshot==pending&&run?.Snapshot==pending&&profile.LastSuccess is null,"failed retries preserve one immutable pending snapshot without success");
            var loaded=new StudioStore(store.Root);var saved=loaded.Data.History.Last();
            check(saved.HttpStatus==status&&saved.RetryAfterSeconds==delay&&saved.HttpOperation=="SoapRequest"&&saved.FailureStage=="Łączenie z Chomikuj","reload retains diagnostics and failure phase");
            check(!JsonSerializer.Serialize(saved).Contains("private-response-secret")&&!error!.ToString().Contains("private-response-secret"),"response body and signed URL absent from recorded error");
        }
        foreach(var operation in new[]{ChomikujClient.HttpOperation.WebSession,ChomikujClient.HttpOperation.UploadAddress,ChomikujClient.HttpOperation.UploadContent})
        {
            using var handler=new UploadErrorResponse(operation);
            using var client=new ChomikujClient(handler);
            await client.LoginAsync("synthetic-user","synthetic-password",default);
            using var content=new MemoryStream(new byte[]{1,2,3});
            ChomikujClient.CloudHttpException? error=null;
            try{await client.OpenFolder(new("7","Synthetic")).UploadAsync("repo.json",content,3,default);}
            catch(ChomikujClient.CloudHttpException e){error=e;}
            check(error is {StatusCode:HttpStatusCode.InternalServerError,RetryAfter:null}&&error.Operation==operation,"HTTP 500 identifies the exact upload boundary");
            check(handler.SessionCalls==1&&handler.AddressCalls==(operation==ChomikujClient.HttpOperation.WebSession?0:1)&&handler.UploadCalls==(operation==ChomikujClient.HttpOperation.UploadContent?1:0),"no write or upload-address retry, later boundaries are not entered");
            var run=await new JobEngine(store,()=>new FailedConnection(error!)).RunAsync(profile,secrets,DateTimeOffset.UtcNow);
            check(run?.HttpOperation==operation.ToString()&&run.HttpStatus==500&&run.Snapshot==pending&&profile.PendingSnapshot==pending,"operation metadata preserves the existing snapshot");
            var loaded=new StudioStore(store.Root).Data.History.Last();
            check(loaded.HttpOperation==operation.ToString()&&loaded.HttpStatus==500,"HTTP operation survives history persistence");
            check(!JsonSerializer.Serialize(loaded).Contains("private-response-secret")&&!error!.ToString().Contains("private-response-secret"),"operation diagnostics contain neither response nor signed endpoint");
        }
        check(new ChomikujClient.CloudHttpException(HttpStatusCode.InternalServerError,null).Operation==ChomikujClient.HttpOperation.Unknown,"legacy exception constructor remains compatible");
        check(new ChomikujClient.CloudHttpException(HttpStatusCode.InternalServerError,null,(ChomikujClient.HttpOperation)999).Operation==ChomikujClient.HttpOperation.Unknown,"undefined operation is not reported as a known boundary");
        foreach(var operation in new[]{ChomikujClient.HttpOperation.SoapRequest,ChomikujClient.HttpOperation.WebSession,ChomikujClient.HttpOperation.UploadAddress,ChomikujClient.HttpOperation.UploadContent})
        {
            using var handler=new UploadErrorResponse(operation,transport:true);
            using var client=new ChomikujClient(handler);
            Exception? error=null;
            try
            {
                await client.LoginAsync("synthetic-user","synthetic-password",default);
                using var content=new MemoryStream(new byte[]{1,2,3});
                await client.OpenFolder(new("7","Synthetic")).UploadAsync("repo.json",content,3,default);
            }
            catch(IOException e){error=e;}
            var metadata=error is null?null:ChomikujClient.GetTransportFailure(error);
            check(metadata is {Error:HttpRequestError.Unknown,NativeErrorCode:123,CauseKind:"Windows"}&&metadata.Operation==operation&&metadata.CauseHResult==new System.ComponentModel.Win32Exception(123).HResult,"transport preserves the actual boundary and bounded native cause");
            check(handler.FailureCalls==1&&handler.UploadCalls==(operation==ChomikujClient.HttpOperation.UploadContent?1:0),"unknown transport failures do not replay requests or enter subsequent writes");
            var run=await new JobEngine(store,()=>new FailedConnection(error!)).RunAsync(profile,secrets,DateTimeOffset.UtcNow);
            check(run is {State:RunState.Failed,HttpStatus:null,RetryAfterSeconds:null,TransportError:"Unknown",NativeErrorCode:123,CauseKind:"Windows"}&&run.HttpOperation==operation.ToString(),"transport failure history has native metadata without an invented HTTP response");
            var saved=new StudioStore(store.Root).Data.History.Last();
            check(saved.TransportError=="Unknown"&&saved.NativeErrorCode==123&&saved.CauseHResult==metadata!.CauseHResult&&saved.CauseKind=="Windows"&&saved.HttpOperation==operation.ToString(),"transport diagnostics survive persistence");
            check(saved.Snapshot==pending&&profile.PendingSnapshot==pending&&profile.LastSuccess is null,"transport failures retain the original pending snapshot");
            string encoded=JsonSerializer.Serialize(saved);
            check(!encoded.Contains("private-response-secret")&&!encoded.Contains("chomikuj.pl")&&!error!.ToString().Contains("private-response-secret"),"history retains no exception text, endpoint, token or inner exception");
        }
        using(var vault=LocalEncryptedVault.Open(profile.Repository,secrets.VaultPassword))
            check(vault.ListSnapshotIds().Count==1,"diagnostic runs never create another snapshot");
        check(JsonSerializer.Deserialize<RunRecord>("{\"FailureCode\":\"FAILED-CloudHttpException\"}") is {HttpStatus:null,RetryAfterSeconds:null,HttpOperation:null,TransportError:null,NativeErrorCode:null,CauseHResult:null,CauseKind:null},"old history stays readable without invented HTTP or transport data");
        var unknown=new JobEngine(store,()=>new FailedConnection(new IOException("https://example.invalid/?token=private-response-secret")));
        var unknownRun=await unknown.RunAsync(profile,secrets,DateTimeOffset.UtcNow);
        check(unknownRun is {HttpStatus:null,RetryAfterSeconds:null,HttpOperation:null,TransportError:null,NativeErrorCode:null,CauseHResult:null,CauseKind:null}&&!unknownRun.Detail.Contains("private-response-secret"),"unknown errors remain unclassified and sanitized");
        check(store.Data.History.Count==11&&store.Data.History.All(r=>r.State==RunState.Failed),"prior failed attempts retained independently");
    }
    private sealed class FailedConnection(Exception error):IJobCloud
    {
        public Task<ICloudVault> ConnectAsync(BackupProfile profile,JobSecrets secrets,CancellationToken token)=>Task.FromException<ICloudVault>(error);
        public void Dispose(){}
    }
    private sealed class ErrorResponse(HttpStatusCode status,int? delay):HttpMessageHandler
    {
        internal int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            Calls++;var response=new HttpResponseMessage(status){Content=new StringContent("https://example.invalid/?token=private-response-secret")};
            if(delay is {} seconds)response.Headers.RetryAfter=new(System.TimeSpan.FromSeconds(seconds));
            return Task.FromResult(response);
        }
    }
    private sealed class UploadErrorResponse(ChomikujClient.HttpOperation failure,bool transport=false):HttpMessageHandler
    {
        internal int SessionCalls,AddressCalls,UploadCalls,FailureCalls;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            var uri=request.RequestUri!;
            if(uri.AbsolutePath.Contains("LoginFromBox",StringComparison.Ordinal))
            {SessionCalls++;return Reply(ChomikujClient.HttpOperation.WebSession,"<input name='__RequestVerificationToken' value='synthetic'>");}
            if(uri.AbsolutePath.Contains("/Upload/GetUrl/",StringComparison.Ordinal))
            {AddressCalls++;return Reply(ChomikujClient.HttpOperation.UploadAddress,"{\"Url\":\"https://upload.chomikuj.pl/fixture?token=private-response-secret\"}");}
            if(uri.IdnHost=="upload.chomikuj.pl")
            {UploadCalls++;return Reply(ChomikujClient.HttpOperation.UploadContent,"unexpected-success");}
            string xml=await request.Content!.ReadAsStringAsync(token);
            string action=XDocument.Parse(xml).Root!.Elements().Single().Elements().Single().Name.LocalName;
            if(action=="Auth"&&failure==ChomikujClient.HttpOperation.SoapRequest&&transport)ThrowTransport();
            string payload=action switch
            {
                "Auth"=>"<token>synthetic-token</token><hamsterId>123</hamsterId><hamsterName>synthetic-user</hamsterName>",
                "Download"=>"<list><DownloadFolder><files/></DownloadFolder></list>",
                _=>throw new InvalidOperationException("Unexpected synthetic request")
            };
            return new(HttpStatusCode.OK){Content=new StringContent($"<Envelope><Body><{action}Response><{action}Result><status>Ok</status>{payload}</{action}Result></{action}Response></Body></Envelope>")};
        }
        private HttpResponseMessage Reply(ChomikujClient.HttpOperation operation,string body)
        {
            if(operation==failure&&transport)ThrowTransport();
            return new(operation==failure?HttpStatusCode.InternalServerError:HttpStatusCode.OK)
                {Content=new StringContent(operation==failure?"private-response-secret":body)};
        }
        private void ThrowTransport()
        {
            FailureCalls++;
            throw new HttpRequestException(HttpRequestError.Unknown,"https://example.invalid/?token=private-response-secret",
                new System.ComponentModel.Win32Exception(123,"private-response-secret"));
        }
    }
}
