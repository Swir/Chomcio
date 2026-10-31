using ChomcioRecovery.Chomikuj;
using ChomcioRecovery.Core;
using ChomcioRecovery.Desktop;
using System.Net;
using System.Text.Json;
using System.Xml.Linq;

internal static class ResponseFailureScenarios
{
    private const string Secret="private-response-secret";
    // Reflection keeps this regression runnable against the previous candidate.
    private static object? Metadata(Exception error)=>typeof(ChomikujClient)
        .GetMethod("GetResponseFailure")?.Invoke(null,new object[]{error});
    private static string? Field(object value,string name)=>value.GetType().GetProperty(name)?.GetValue(value)?.ToString();
    internal static async Task Run(string root,Action<bool,string> check)
    {
        if(Directory.Exists(root))throw new IOException("Use a new synthetic directory.");
        Directory.CreateDirectory(root);
        string source=Path.Combine(root,"source");Directory.CreateDirectory(source);
        File.WriteAllText(Path.Combine(source,"fixture.txt"),"small response-validation fixture");
        var profile=new BackupProfile{Name="Response diagnostics",Source=source,Repository=Path.Combine(root,"vault"),Destination=BackupDestination.Chomikuj};
        var store=new StudioStore(Path.Combine(root,"settings"));store.Data.Profiles.Add(profile);store.Save();
        var secrets=new JobSecrets("synthetic-vault-key","synthetic-login","synthetic-password");
        string? pending=null;
        var cases=new[]{
            ("UploadAddress","json","WebJsonMalformed"),("UploadContent","json","WebJsonMalformed"),
            ("WebSession","large","WebBodyTooLarge"),("UploadAddress","large","WebBodyTooLarge"),
            ("UploadContent","large","WebBodyTooLarge"),("FolderProtection","json","WebJsonMalformed"),
            ("FolderProtection","large","WebBodyTooLarge"),("SoapRequest","large","SoapBodyTooLarge"),
            ("SoapRequest","result","SoapResultMissing"),("SoapRequest","list","FileListMissing"),
            ("SoapRequest","structure","FileListStructure"),("SoapRequest","record","FileRecordStructure"),
            ("SoapRequest","incomplete","FileRecordIncomplete"),("SoapRequest","length","FileLengthInvalid")};
        foreach(var (operation,mode,reason) in cases)
        {
            using var server=new Server(operation,mode);using var client=new ChomikujClient(server);
            await client.LoginAsync("synthetic-user","synthetic-password",default);
            InvalidDataException? error=null;
            try
            {
                if(operation=="FolderProtection")await client.EnsureFolderPasswordAsync(new("7","Synthetic"),"SyntheticFolderPassword123",default);
                else {using var input=new MemoryStream(new byte[]{1,2,3});await client.OpenFolder(new("7","Synthetic")).UploadAsync("repo.json",input,3,default);}
            }
            catch(InvalidDataException e){error=e;}
            var metadata=error is null?null:Metadata(error);
            check(metadata is not null&&Field(metadata,"Reason")==reason&&Field(metadata,"Operation")==operation,
                "response rejection retains exact category and operation: "+operation+"/"+mode);
            check(server.Failures==1&&server.Uploads==(operation=="UploadContent"?1:0)&&server.PasswordWrites==0,
                "no validation retry, repeat upload or protection write: "+operation+"/"+mode);
            check(error!.InnerException is null&&!error.ToString().Contains(Secret),"raw response and JSON parser exception are discarded");
            var cloud=new FaultCloud(error);var run=await new JobEngine(store,()=>new Connection(cloud)).RunAsync(profile,secrets,DateTimeOffset.UtcNow);
            var saved=new StudioStore(store.Root).Data.History.Last();
            var json=JsonSerializer.SerializeToElement(saved);
            check(run is {State:RunState.Failed,FailureCode:"INTEGRITY",HttpStatus:null,RetryAfterSeconds:null}
                &&saved.FailureStage=="Wysyłanie zaszyfrowanych danych"&&saved.HttpOperation==operation
                &&json.GetProperty("ResponseFailure").GetString()==reason,"history persists category without inventing status or transport cause");
            pending??=profile.PendingSnapshot;
            check(profile.PendingSnapshot==pending&&saved.Snapshot==pending&&!profile.RemoteFolderHasConfirmedCopy
                &&profile.LastSnapshot is null&&cloud.Reads==0&&!json.ToString().Contains(Secret),"failure preserves pending and never publishes success or raw response");
        }
        using(var server=new Server("None","valid"))
        using(var client=new ChomikujClient(server))
        {
            await client.LoginAsync("synthetic-user","synthetic-password",default);
            using var input=new MemoryStream(new byte[]{1,2,3});
            var result=await client.OpenFolder(new("7","Synthetic")).UploadAsync("repo.json",input,3,default);
            check(result==new CloudObject("42","repo.json",3)&&server.Uploads==1&&server.Failures==0,
                "valid JSON upload receipt still succeeds with one send; receipt is not a full-copy qualification");
        }
        var legacyError=new InvalidDataException("Chomikuj zwrócił nierozpoznaną odpowiedź strony (WebJson).");
        check(Metadata(legacyError) is null,"matching message alone does not fabricate historical context");
        legacyError.Data["ResponseFailure"]="WebJsonMalformed";
        check(Metadata(legacyError) is null,"arbitrary string metadata is not accepted");
        await new JobEngine(store,()=>new Connection(new FaultCloud(legacyError))).RunAsync(profile,secrets,DateTimeOffset.UtcNow);
        var legacy=new StudioStore(store.Root).Data.History.Last();
        check(legacy.HttpOperation is null&&JsonSerializer.SerializeToElement(legacy).GetProperty("ResponseFailure").ValueKind==JsonValueKind.Null,
            "unclassified integrity failures remain unknown");
        using var old=JsonDocument.Parse("{\"FailureCode\":\"INTEGRITY\",\"State\":2}");
        var oldRecord=JsonSerializer.Deserialize<RunRecord>(old.RootElement.GetRawText())!;
        check(JsonSerializer.SerializeToElement(oldRecord).GetProperty("ResponseFailure").ValueKind==JsonValueKind.Null,"old records without response category remain compatible");
        using var vault=LocalEncryptedVault.Open(profile.Repository,secrets.VaultPassword);
        check(vault.ListSnapshotIds().Count==1,"synthetic failures preserve one snapshot");
        Console.WriteLine("CHOMCIO_RESPONSE_FAILURES=PASS (synthetic transport only)");
    }
    private sealed class Connection(ICloudVault remote):IJobCloud
    {
        public Task<ICloudVault> ConnectAsync(BackupProfile profile,JobSecrets secrets,CancellationToken token)=>Task.FromResult(remote);
        public void Dispose(){}
    }
    private sealed class FaultCloud(Exception error):ICloudVault
    {
        internal int Reads;
        public Task<IReadOnlyList<CloudObject>> ListAsync(CancellationToken token)=>Task.FromResult<IReadOnlyList<CloudObject>>(Array.Empty<CloudObject>());
        public Task<CloudObject> UploadAsync(string name,Stream input,long length,CancellationToken token)=>Task.FromException<CloudObject>(error);
        public Task DownloadAsync(CloudObject file,Stream output,long max,CancellationToken token){Reads++;throw new InvalidOperationException();}
    }
    private sealed class Server(string operation,string mode):HttpMessageHandler
    {
        internal int Failures,Uploads,PasswordWrites;
        private static HttpResponseMessage Reply(string body)=>new(HttpStatusCode.OK){Content=new StringContent(body)};
        private HttpResponseMessage Fail(){Failures++;return Reply(mode=="large"?new string('x',(operation=="SoapRequest"?64:2)*1024*1024+1):"<html>"+Secret+"</html>");}
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            var uri=request.RequestUri!;
            if(uri.Host=="upload.chomikuj.pl")
            {Uploads++;return operation=="None"?Reply("{\"files\":[{\"fileId\":42,\"name\":\"repo.json\",\"size\":3}]}"):Fail();}
            if(uri.Host=="chomikuj.pl")
            {
                if(uri.AbsolutePath.Contains("LoginFromBox"))return operation=="WebSession"?Fail():Reply("<input name='__RequestVerificationToken' value='synthetic'/>");
                if(uri.AbsolutePath.Contains("ChangePasswordAction")){PasswordWrites++;throw new InvalidOperationException("Unexpected protection mutation");}
                if(uri.AbsolutePath.Contains("ChangePassword"))return Fail();
                if(uri.AbsolutePath.Contains("GetUrl"))return operation=="UploadAddress"?Fail():Reply("{\"Url\":\"https://upload.chomikuj.pl/synthetic\"}");
                throw new InvalidOperationException("Unexpected portal action");
            }
            string action=request.Headers.GetValues("SOAPAction").Single().Split('/')[^1];
            _=await request.Content!.ReadAsStringAsync(token);
            string payload;
            if(action=="Auth")payload="<token>synthetic</token><hamsterId>123</hamsterId><hamsterName>synthetic-user</hamsterName>";
            else if(action=="Folders")payload="<folder><folders><FolderInfo><id>7</id><name>Synthetic</name></FolderInfo></folders></folder>";
            else if(action=="Download")
            {
                if(operation=="SoapRequest")
                {
                    if(mode=="large")return Fail();
                    Failures++;
                    if(mode=="result")return Reply("<Envelope><Body>"+Secret+"</Body></Envelope>");
                    payload=mode switch
                    {
                        "list"=>"<missing/>","structure"=>"<list><DownloadFolder/></list>",
                        "record"=>"<list><DownloadFolder><files><Unexpected/></files></DownloadFolder></list>",
                        "incomplete"=>"<list><DownloadFolder><files><FileEntry><size>3</size></FileEntry></files></DownloadFolder></list>",
                        "length"=>"<list><DownloadFolder><files><FileEntry><id>1</id><name>repo.json</name><size>invalid</size></FileEntry></files></DownloadFolder></list>",
                        _=>throw new InvalidOperationException()
                    };
                }
                else payload="<list><DownloadFolder><files/></DownloadFolder></list>";
            }
            else throw new InvalidOperationException("Unexpected SOAP action");
            return Reply($"<Envelope><Body><{action}Response><{action}Result><status>Ok</status>{payload}</{action}Result></{action}Response></Body></Envelope>");
        }
    }
}
