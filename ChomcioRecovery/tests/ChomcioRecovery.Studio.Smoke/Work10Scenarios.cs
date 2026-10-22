using ChomcioRecovery.Desktop;
using ChomcioRecovery.Chomikuj;
using System.Net;
using System.Text;
using System.Xml.Linq;

internal static class Work10Scenarios
{
    internal static async Task Run(Action<bool,string> check)
    {
        BackupProfile Profile()=>new(){RemoteFolderId="17",RemoteFolderName="ChomcioRecovery_Old",PendingSnapshot=Guid.NewGuid().ToString("N")};
        var secrets=new JobSecrets("synthetic-key-only","synthetic-user","synthetic-password");
        using(var server=new Server())
        using(var connection=new AccountJobCloud(new ChomikujClient(server)))
        {
            var p=Profile();var remote=await connection.ConnectAsync(p,secrets,default);
            check(p.RemoteFolderId=="18"&&server.Adds==1,"unconfirmed first upload recovers into distinct new folder");
            check(p.PreviousUnconfirmedCloudFolders.Single()==new UnconfirmedCloudFolder("17","ChomcioRecovery_Old"),"old ambiguous folder association retained");
            check((await remote.ListAsync(default)).Count==0,"newly created recovery folder has session-scoped empty proof");
            check(p.LastSuccess is null&&p.LastSnapshot is null&&p.PendingSnapshot is not null,"recovery never claims success or replaces pending point");
            check(!server.UnexpectedAction,"recovery never deletes, renames or changes old folder");
        }
        foreach(bool success in new[]{false,true})
        {
            using var server=new Server();using var connection=new AccountJobCloud(new ChomikujClient(server));
            var p=Profile();if(success)p.LastSuccess=DateTimeOffset.UtcNow;else p.LastSnapshot=Guid.NewGuid().ToString("N");
            var remote=await connection.ConnectAsync(p,secrets,default);
            bool rejected=false;try{await remote.ListAsync(default);}catch(ChomikujServiceException){rejected=true;}
            check(rejected&&server.Adds==0&&p.RemoteFolderId=="17","confirmed cloud history never silently moves to a new folder");
        }
        foreach(string failure in new[]{"unknown","limit","create"})
        {
            using var server=new Server{Unknown=failure=="unknown",RejectCreate=failure=="create"};
            using var connection=new AccountJobCloud(new ChomikujClient(server));
            var p=Profile();if(failure=="limit")p.PreviousUnconfirmedCloudFolders.AddRange(Enumerable.Range(0,3).Select(i=>new UnconfirmedCloudFolder(i.ToString(),"previous")));
            bool rejected=false;try{await connection.ConnectAsync(p,secrets,default);}catch(IOException){rejected=true;}
            check(rejected&&p.RemoteFolderId=="17"&&(failure=="create"||server.Adds==0),"unknown failures, limits and failed creation retain original association: "+failure);
        }
        foreach(bool confirmed in new[]{false,true})
        {
            using var server=new Server();using var connection=new AccountJobCloud(new ChomikujClient(server));
            var p=Profile();p.CloudDateFolders=true;p.PendingCloudDate=p.RemoteFolderDate="2026-10-20";
            p.RemoteFolderHasConfirmedCopy=confirmed;p.LastSuccess=DateTimeOffset.UtcNow.AddDays(-1);p.LastSnapshot=Guid.NewGuid().ToString("N");
            p.ArchivedCloudFolders.Add(new("16","Confirmed_Yesterday"));
            var remote=await connection.ConnectAsync(p,secrets,default);
            check(server.Adds==(confirmed?0:1),"interrupted daily folder recovery depends on this folder's confirmation");
            check(p.ArchivedCloudFolders.Single().Id=="16"&&p.LastSuccess is not null,"daily recovery preserves confirmed previous-day folder");
            if(!confirmed)check(p.RemoteFolderName=="Chomciore_20_10_2026"&&(await remote.ListAsync(default)).Count==0,"daily resumed upload uses date and a confirmed new empty folder");
        }
        var native=new IOException("private-path-must-not-escape",new System.ComponentModel.Win32Exception(50));
        foreach(var failure in Enum.GetValues<ChomikujReadFailure>())
        {
            var readError=new ChomikujReadException(failure);
            check(JobEngine.FailureId(readError)=="CLOUD-READ-"+failure && JobEngine.SafeError(readError)==readError.Message,
                "cloud TLS read failure is described as transport, never local write permission: "+failure);
        }
        check(JobEngine.FailureId(native)=="WINDOWS-50"&&!JobEngine.SafeError(native).Contains("private-path"),"native failure code retained without private paths");
        check(!JobEngine.SafeError(new InvalidDataException("https://secret.invalid/token")).Contains("secret"),"invalid server data never leaked in user error");
        Console.WriteLine("CHOMCIO_WORK11_INITIAL_UPLOAD_RECOVERY=PASS");
    }
    private sealed class Server:HttpMessageHandler
    {
        internal int Adds;
        internal bool Unknown,RejectCreate,UnexpectedAction;
        private string? replacement;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            string action=request.Headers.GetValues("SOAPAction").Single().Split('/')[^1];
            var body=XDocument.Parse(await request.Content!.ReadAsStringAsync(token));
            string payload="",status="Ok",error="";
            switch(action)
            {
                case "Auth":payload="<token>synthetic-token</token><hamsterId>123</hamsterId><hamsterName>synthetic-user</hamsterName>";break;
                case "Folders":
                    payload="<folder><folders><FolderInfo><id>17</id><name>ChomcioRecovery_Old</name></FolderInfo>"+
                        (replacement is null?"":"<FolderInfo><id>18</id><name>"+replacement+"</name></FolderInfo>")+"</folders></folder>";break;
                case "AddFolder":
                    Adds++;if(RejectCreate){status="Rejected";break;}
                    replacement=body.Descendants().Single(e=>e.Name.LocalName=="name").Value;payload="<folderId>18</folderId>";break;
                case "Download":status="Rejected";error=Unknown?"unknown":"failed : requested file(s) not available";break;
                default:UnexpectedAction=true;throw new IOException("Unexpected test action");
            }
            string xml=$"<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'><s:Body><{action}Response><{action}Result><status>{status}</status><errorMessage>{error}</errorMessage>{payload}</{action}Result></{action}Response></s:Body></s:Envelope>";
            return new(HttpStatusCode.OK){Content=new StringContent(xml,Encoding.UTF8,"text/xml")};
        }
    }
}
