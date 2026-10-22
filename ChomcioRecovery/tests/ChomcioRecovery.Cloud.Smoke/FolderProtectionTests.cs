using ChomcioRecovery.Chomikuj;
using System.Net;
using System.Text.Json;
using System.Xml.Linq;

internal static class FolderProtectionTests
{
    internal static async Task Run(Action<bool,string> check,Func<Func<Task>,string,Task> fails)
    {
        const string secret="SeparateFolderPassword1234567890";
        var folder=new ChomikujFolder("7","Chomciore_20_10_2026");
        foreach(string mode in new[]{"success","foreign","wrong-id","no-readback","rejected","wrong-action"})
        {
            using var handler=new ProtectionHandler(mode);
            using var client=new ChomikujClient(handler);
            await client.LoginAsync("synthetic-user","synthetic-account-password",default);
            if(mode=="success")
            {
                await client.EnsureFolderPasswordAsync(folder,secret,default);
                await client.EnsureFolderPasswordAsync(folder,secret,default);
                check(handler.Writes==1&&handler.Reads==3,"folder protection verified and repeat is read-only");
                check(handler.Password==secret,"only independent folder password reaches portal");
            }
            else
            {
                await fails(()=>client.EnsureFolderPasswordAsync(folder,secret,default),"folder protection refuses "+mode);
                if(mode is "foreign" or "wrong-id" or "wrong-action")check(handler.Writes==0,"refusal happens before changing folder "+mode);
            }
        }
    }
    private sealed class ProtectionHandler(string mode):HttpMessageHandler
    {
        internal int Reads,Writes;
        internal string Password=mode=="foreign"?"DifferentExistingPassword123":"";
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if(request.RequestUri!.Host=="chomikuj.pl")
            {
                if(request.Method==HttpMethod.Get)return Response("<input name='__RequestVerificationToken' value='test-csrf'/>");
                var fields=(await request.Content!.ReadAsStringAsync(ct)).Split('&').Select(s=>s.Split('=',2))
                    .ToDictionary(a=>WebUtility.UrlDecode(a[0]),a=>WebUtility.UrlDecode(a.Length>1?a[1]:""));
                if(fields.GetValueOrDefault("FolderId")!="7"||fields.GetValueOrDefault("ChomikName")!="synthetic-user"||
                    fields.GetValueOrDefault("__RequestVerificationToken")!="test-csrf")throw new IOException("Scope or CSRF missing.");
                if(request.RequestUri.AbsolutePath.EndsWith("/ChangePasswordAction"))
                {
                    Writes++;
                    if(mode=="rejected")return Json(new{Data=new{Status="1"}});
                    if(mode!="no-readback")Password=fields["Password"];
                    return Json(new{Data=new{Status="0"}});
                }
                Reads++;
                string id=mode=="wrong-id"?"8":"7";
                string action=mode=="wrong-action"?"/unrelated":"/action/FolderOptions/ChangePasswordAction";
                return Json(new{Content=$"<form action='{action}'><input name='FolderId' value='{id}'/><input name='ChomikName' value='synthetic-user'/><input name='Password' value='{Password}'/></form>"});
            }
            string actionName=request.Headers.GetValues("SOAPAction").Single().Split('/')[^1];
            string payload=actionName switch{
                "Auth"=>"<token>test-token</token><hamsterId>123</hamsterId><hamsterName>synthetic-user</hamsterName>",
                "Folders"=>"<folder><folders><FolderInfo><id>7</id><name>Chomciore_20_10_2026</name></FolderInfo></folders></folder>",
                _=>throw new IOException("Unexpected operation.")
            };
            return Response($"<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'><s:Body><{actionName}Response><{actionName}Result><status>Ok</status>{payload}</{actionName}Result></{actionName}Response></s:Body></s:Envelope>");
        }
        private static HttpResponseMessage Json(object value)=>Response(JsonSerializer.Serialize(value));
        private static HttpResponseMessage Response(string content)=>new(HttpStatusCode.OK){Content=new StringContent(content)};
    }
}
