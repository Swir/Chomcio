using ChomcioRecovery.Chomikuj;
using ChomcioRecovery.Core;
using ChomcioRecovery.Desktop;
using System.Net;
using System.Text.Json;

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
            check(error is not null&&(int)error.StatusCode==status&&error.RetryAfter?.TotalSeconds==delay,"transport preserves HTTP and optional Retry-After");
            check(handler.Calls==1,"permanent failure or long Retry-After is not retried early");
            var engine=new JobEngine(store,()=>new FailedConnection(error!));
            var run=await engine.RunAsync(profile,secrets,DateTimeOffset.UtcNow);
            check(run?.State==RunState.Failed&&run.HttpStatus==status&&run.RetryAfterSeconds==delay,"job records safe response metadata");
            check(run?.Detail.Contains("HTTP "+status)==true&&(delay is null||run.Detail.Contains(delay+" s")),"history text explains HTTP and requested delay");
            pending??=profile.PendingSnapshot;
            check(pending is not null&&profile.PendingSnapshot==pending&&run?.Snapshot==pending&&profile.LastSuccess is null,"failed retries preserve one immutable pending snapshot without success");
            var loaded=new StudioStore(store.Root);var saved=loaded.Data.History.Last();
            check(saved.HttpStatus==status&&saved.RetryAfterSeconds==delay&&saved.FailureStage=="Łączenie z Chomikuj","reload retains diagnostics and failure phase");
            check(!JsonSerializer.Serialize(saved).Contains("private-response-secret")&&!error!.ToString().Contains("private-response-secret"),"response body and signed URL absent from recorded error");
        }
        using(var vault=LocalEncryptedVault.Open(profile.Repository,secrets.VaultPassword))
            check(vault.ListSnapshotIds().Count==1,"diagnostic runs never create another snapshot");
        check(JsonSerializer.Deserialize<RunRecord>("{\"FailureCode\":\"FAILED-CloudHttpException\"}") is {HttpStatus:null,RetryAfterSeconds:null},"old history stays readable without invented HTTP data");
        var unknown=new JobEngine(store,()=>new FailedConnection(new IOException("https://example.invalid/?token=private-response-secret")));
        var unknownRun=await unknown.RunAsync(profile,secrets,DateTimeOffset.UtcNow);
        check(unknownRun is {HttpStatus:null,RetryAfterSeconds:null}&&!unknownRun.Detail.Contains("private-response-secret"),"unknown errors remain unclassified and sanitized");
        check(store.Data.History.Count==4&&store.Data.History.All(r=>r.State==RunState.Failed),"prior failed attempts retained independently");
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
}
