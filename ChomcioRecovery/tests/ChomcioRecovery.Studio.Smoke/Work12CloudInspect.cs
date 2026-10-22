using ChomcioRecovery.Desktop;
using ChomcioRecovery.Chomikuj;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Net;

internal static class Work12CloudInspect
{
    internal static async Task Run()
    {
        var account=StudioCredentials.Account(new StudioStore(StudioStore.DefaultRoot))??throw new IOException("Missing test account.");
        using var client=new ChomikujClient();
        await client.LoginAsync(account.CloudLogin,account.CloudPassword,default);
        await (Task)typeof(ChomikujClient).GetMethod("EnsureWebSessionAsync",BindingFlags.NonPublic|BindingFlags.Instance)!.Invoke(client,new object[]{CancellationToken.None})!;
        var http=(HttpClient)typeof(ChomikujClient).GetField("http",BindingFlags.NonPublic|BindingFlags.Instance)!.GetValue(client)!;
        string html=await http.GetStringAsync("https://chomikuj.pl/"+Uri.EscapeDataString(account.CloudLogin));
        // Print only static script paths and action names, never HTML, cookies,
        // hidden input values, credentials, file lists or signed URLs.
        foreach(Match match in Regex.Matches(html,"<script[^>]+src=[\"']([^\"']+)",RegexOptions.IgnoreCase))
        {
            string path=WebUtility.HtmlDecode(match.Groups[1].Value);
            if(Uri.TryCreate(new Uri("https://chomikuj.pl/"),path,out var uri)&&uri.Host.EndsWith("chomikuj.pl",StringComparison.Ordinal)&&uri.AbsolutePath.EndsWith(".js"))
                Console.WriteLine("SCRIPT "+uri.GetLeftPart(UriPartial.Path));
        }
        foreach(Match match in Regex.Matches(html,@"(?:/action/|/Folder/)[A-Za-z/]+"))
            Console.WriteLine("ACTION "+match.Value);
        var folder=await client.CreateFolderAsync("ChomcioRecovery_Test_WORK12_Privacy_"+Guid.NewGuid().ToString("N"),default);
        // The service's own public JS (FolderOptions.actions.beginProcessOption)
        // opens the editor with POST. No password or save/action field is sent.
        // Scope is exclusively the empty synthetic folder created above.
        string csrf=(string)typeof(ChomikujClient).GetField("webVerificationToken",BindingFlags.NonPublic|BindingFlags.Instance)!.GetValue(client)!;
        using var request=new HttpRequestMessage(HttpMethod.Post,"https://chomikuj.pl/action/FolderOptions/ChangePassword");
        request.Headers.Add("X-Requested-With","XMLHttpRequest");
        request.Content=new FormUrlEncodedContent(new Dictionary<string,string>{{"chomikName",account.CloudLogin},{"folderId",folder.Id},{"__RequestVerificationToken",csrf}});
        using var response=await http.SendAsync(request);
        string result=await response.Content.ReadAsStringAsync();
        Console.WriteLine("FORM_HTTP "+(int)response.StatusCode);
        using var json=System.Text.Json.JsonDocument.Parse(result);
        Console.WriteLine("JSON_FIELDS "+string.Join(",",json.RootElement.EnumerateObject().Select(p=>p.Name)));
        foreach(var property in json.RootElement.EnumerateObject().Where(p=>p.Value.ValueKind==System.Text.Json.JsonValueKind.String))
        {
            string fragment=property.Value.GetString()!;
            foreach(Match match in Regex.Matches(fragment,"<(?:form|input)\\b[^>]*>",RegexOptions.IgnoreCase))
            {
                string tag=match.Value;
                var fields=Regex.Matches(tag,"(?:name|action|type)=[\"']([^\"']*)",RegexOptions.IgnoreCase).Select(m=>m.Value);
                Console.WriteLine("FORM_FIELD "+string.Join(" ",fields));
            }
        }
    }
}
