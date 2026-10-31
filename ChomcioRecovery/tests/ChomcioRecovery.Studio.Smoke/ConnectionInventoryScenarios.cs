using ChomcioRecovery.Chomikuj;
using ChomcioRecovery.Desktop;
using System.Net;
using System.Text.Json;
using System.Xml.Linq;

internal static class ConnectionInventoryScenarios
{
    private const string Folder="Chomciore_29_10_2026",Password="SyntheticFolderPassword123456";
    internal static async Task Run(string root,Action<bool,string> check)
    {
        if(Directory.Exists(root))throw new IOException("Test requires a new directory.");
        Directory.CreateDirectory(root);
        var secrets=new JobSecrets("synthetic-vault-key","synthetic-user","synthetic-password",Password);
        BackupProfile Profile(bool protect=false)=>new(){Id=Guid.NewGuid().ToString("N"),
            RemoteFolderId="17",RemoteFolderName=Folder,PendingSnapshot=Guid.NewGuid().ToString("N"),
            CloudDateFolders=true,PendingCloudDate="2026-10-29",RemoteFolderDate="2026-10-29",ProtectCloudFolder=protect};
        async Task<bool> Reject(Func<Task> action)
        {try{await action();return false;}catch(Exception e)when(e is IOException or InvalidDataException or OperationCanceledException){return true;}}

        using(var server=new Server(128){RejectPayload=true})
        using(var connection=new AccountJobCloud(new ChomikujClient(server)))
        {
            var p=Profile();string pending=p.PendingSnapshot!;
            var remote=await connection.ConnectAsync(p,secrets,default);
            check(server.Lists==1&&server.FileRequests==0&&server.Gets==0,"connection discovers 128 names without resolving any representation length");
            check(p.RemoteFolderId=="17"&&p.RemoteFolderName==Folder&&server.Adds==0,"existing partial folder is retained");
            check(p.PendingSnapshot==pending&&p.PendingCloudDate=="2026-10-29"&&!p.RemoteFolderHasConfirmedCopy&&p.LastSnapshot is null,"name discovery does not claim a backup or clear pending state");
            server.RejectPayload=false;
            var files=await remote.ListAsync(default);
            check(files.Count==128&&server.FileRequests==128&&server.Gets==128,"subsequent transfer listing still resolves every exact HTTP length");
            check(files.All(f=>f.Length==server.Bytes(f.Id).Length&&f.Length!=1),"SOAP size hints never replace actual representation sizes");
            using var downloaded=new MemoryStream();
            await remote.DownloadAsync(files[0],downloaded,files[0].Length,default);
            check(downloaded.ToArray().SequenceEqual(server.Bytes(files[0].Id)),"subsequent readback still returns the complete expected bytes");
            server.ShortBody=true;
            using var truncated=new MemoryStream();
            check(await Reject(()=>remote.DownloadAsync(files[0],truncated,files[0].Length,default)),"truncated body is still refused after name-only connection");
            check(truncated.Length==0,"failed readback exposes no partial bytes to its caller");
            check(server.Adds==0&&server.PasswordWrites==0,"connection and verification perform no cloud writes");
        }
        foreach(bool foreign in new[]{false,true})
        {
            using var server=new Server(2){RejectPayload=true,ForeignPassword=foreign};
            using var connection=new AccountJobCloud(new ChomikujClient(server));var p=Profile(true);
            bool rejected=await Reject(async()=>{await connection.ConnectAsync(p,secrets,default);});
            check(rejected==foreign,"folder password remains authoritative: foreign="+foreign);
            check(server.PasswordReads==1&&server.PasswordWrites==0&&server.Gets==0,"existing folder password is inspected without payload reads or password changes");
            check(server.Adds==0&&p.RemoteFolderId=="17"&&p.PreviousUnconfirmedCloudFolders.Count==0,"protection check preserves folder association");
        }
        foreach(string failure in new[]{"malformed","unknown","unavailable"})
        {
            using var server=new Server(2){Failure=failure,RejectPayload=true};
            using var connection=new AccountJobCloud(new ChomikujClient(server));var p=Profile();
            bool rejected=await Reject(async()=>{await connection.ConnectAsync(p,secrets,default);});
            check(rejected==(failure!="unavailable"),"existing unavailable-folder recovery classification retained: "+failure);
            check(server.Gets==0&&server.FileRequests==0,"failed discovery never requests payload: "+failure);
            if(failure=="unavailable")
                check(server.Adds==1&&p.RemoteFolderId=="18"&&p.PreviousUnconfirmedCloudFolders.Single()==new UnconfirmedCloudFolder("17",Folder),"previous unconfirmed association remains preserved when legacy recovery creates a distinct folder");
            else check(server.Adds==0&&p.RemoteFolderId=="17","unknown or malformed response never creates replacement folder");
        }
        using(var server=new Server(2){Failure="unavailable",RejectPayload=true})
        using(var connection=new AccountJobCloud(new ChomikujClient(server)))
        {
            var p=Profile();p.PreviousUnconfirmedCloudFolders.AddRange(Enumerable.Range(1,3).Select(i=>new UnconfirmedCloudFolder(i.ToString(),"previous")));
            check(await Reject(async()=>{await connection.ConnectAsync(p,secrets,default);}),"existing replacement bound remains enforced");
            check(server.Adds==0&&p.RemoteFolderId=="17","replacement bound preserves original association");
        }
        using(var cancelled=new CancellationTokenSource())
        using(var server=new Server(2){BeforeList=cancelled.Cancel,RejectPayload=true})
        using(var connection=new AccountJobCloud(new ChomikujClient(server)))
        {
            var p=Profile();
            check(await Reject(async()=>{await connection.ConnectAsync(p,secrets,cancelled.Token);}),"cancellation interrupts discovery before the next operation");
            check(server.Gets==0&&server.Adds==0&&p.RemoteFolderId=="17","cancelled connection has no payload reads or folder changes");
        }
        Console.WriteLine("CHOMCIO_CONNECTION_INVENTORY=PASS (synthetic transport only)");
    }
    private sealed class Server(int count):HttpMessageHandler
    {
        internal int Lists,FileRequests,Gets,Adds,PasswordReads,PasswordWrites;
        internal bool RejectPayload,ForeignPassword,ShortBody;
        internal string? Failure;
        internal Action? BeforeList;
        private string? replacement;
        internal byte[] Bytes(string id)=>Enumerable.Range(0,17+int.Parse(id)).Select(i=>(byte)i).ToArray();
        private static string Name(string id)=>id=="1"?"repo.json":int.Parse(id).ToString("x64")+".obj";
        private static XElement Entry(string id)=>new("FileEntry",new XElement("id",id),new XElement("name",Name(id)),
            new XElement("size",1),new XElement("url","https://download.chomikuj.pl/"+id));
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();var uri=request.RequestUri!;
            if(uri.Host=="download.chomikuj.pl")
            {
                Gets++;if(RejectPayload)throw new InvalidOperationException("Representation requested during connection discovery.");
                byte[] bytes=Bytes(uri.AbsolutePath.Trim('/'));
                var reply=new HttpResponseMessage(HttpStatusCode.OK){Content=new ByteArrayContent(ShortBody?bytes[..^1]:bytes)};
                reply.Content.Headers.ContentLength=bytes.Length;return reply;
            }
            if(uri.Host=="chomikuj.pl")
            {
                if(uri.AbsolutePath.Contains("LoginFromBox",StringComparison.Ordinal))return Text("<input name='__RequestVerificationToken' value='synthetic'/>");
                if(uri.AbsolutePath.EndsWith("/ChangePasswordAction",StringComparison.Ordinal)){PasswordWrites++;throw new InvalidOperationException("Unexpected password write.");}
                if(uri.AbsolutePath.EndsWith("/ChangePassword",StringComparison.Ordinal))
                {
                    PasswordReads++;
                    return Text(JsonSerializer.Serialize(new{Content=$"<form action='/action/FolderOptions/ChangePasswordAction'><input name='FolderId' value='17'/><input name='ChomikName' value='synthetic-user'/><input name='Password' value='{(ForeignPassword?"DifferentExistingPassword123":Password)}'/></form>"}));
                }
                throw new InvalidOperationException("Unexpected portal action.");
            }
            var body=XDocument.Parse(await request.Content!.ReadAsStringAsync(ct));
            string action=request.Headers.GetValues("SOAPAction").Single().Split('/')[^1],status="Ok",error="";object payload;
            switch(action)
            {
                case "Auth":payload=new object[]{new XElement("token","synthetic-token"),new XElement("hamsterId",123),new XElement("hamsterName","synthetic-user")};break;
                case "Folders":payload=new XElement("folder",new XElement("folders",new XElement("FolderInfo",new XElement("id",17),new XElement("name",Folder)),replacement is null?null:new XElement("FolderInfo",new XElement("id",18),new XElement("name",replacement))));break;
                case "AddFolder":Adds++;replacement=body.Descendants().Single(e=>e.Name.LocalName=="name").Value;payload=new XElement("folderId",18);break;
                case "Download":
                    string id=body.Descendants().Single(e=>e.Name.LocalName=="id").Value;
                    if(id.StartsWith('/'))
                    {
                        Lists++;BeforeList?.Invoke();ct.ThrowIfCancellationRequested();
                        if(Failure is "unknown" or "unavailable"){status="Rejected";error=Failure=="unknown"?"unknown":"failed : requested file(s) not available";payload="";}
                        else payload=new XElement("list",new XElement("DownloadFolder",Failure=="malformed"?null:new XElement("files",Enumerable.Range(1,count).Select(i=>Entry(i.ToString())))));
                    }
                    else{FileRequests++;payload=new XElement("list",new XElement("DownloadFolder",new XElement("files",Entry(id))));}
                    break;
                default:throw new InvalidOperationException("Unexpected synthetic cloud operation.");
            }
            return Text(new XElement("Envelope",new XElement("Body",new XElement(action+"Response",new XElement(action+"Result",new XElement("status",status),new XElement("errorMessage",error),payload)))).ToString());
        }
        private static HttpResponseMessage Text(string value)=>new(HttpStatusCode.OK){Content=new StringContent(value)};
    }
}
