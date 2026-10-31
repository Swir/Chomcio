using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ChomcioRecovery.Chomikuj;

public sealed class ChomikujFolderProtectionException : IOException
{
    public bool DifferentPassword { get; }
    internal ChomikujFolderProtectionException(bool different=false):base(different?
        "Folder w Chomikuj ma inne hasło. Zachowano jego ochronę; nie rozpoczęto wysyłania.":
        "Chomikuj nie potwierdził ochrony folderu hasłem. Nie rozpoczęto wysyłania; możesz ponowić próbę.")
    {DifferentPassword=different;}
}

public sealed partial class ChomikujClient
{
    // This is a separate portal password. NEVER pass the encryption key here.
    public async Task EnsureFolderPasswordAsync(ChomikujFolder folder,string password,CancellationToken ct)
    {
        RequireLogin();
        if(password.Length is <16 or >64||!password.All(char.IsAsciiLetterOrDigit))
            throw new ArgumentException("Hasło folderu musi być odrębnym losowym hasłem programu.");
        if(!(await ListFoldersAsync(ct)).Any(f=>f.Id==folder.Id&&f.Name==folder.Name))
            throw new IOException("Nie potwierdzono folderu na własnym koncie.");
        await EnsureWebSessionAsync(ct);
        string before=await ReadFolderPasswordAsync(folder,ct);
        if(before==password)return;
        if(before.Length>0)throw new ChomikujFolderProtectionException(true);
        using var result=await FolderFormAsync("ChangePasswordAction",folder,password,ct);
        if(!result.RootElement.TryGetProperty("Data",out var data)||data.ValueKind!=JsonValueKind.Object||
            JsonScalar(data,"Status")!="0")
            throw new ChomikujFolderProtectionException();
        if(await ReadFolderPasswordAsync(folder,ct)!=password)
            throw new ChomikujFolderProtectionException();
    }

    private async Task<string> ReadFolderPasswordAsync(ChomikujFolder folder,CancellationToken ct)
    {
        using var form=await FolderFormAsync("ChangePassword",folder,null,ct);
        if(!form.RootElement.TryGetProperty("Content",out var content)||content.ValueKind!=JsonValueKind.String)
            throw new InvalidDataException("Nie rozpoznano formularza ochrony folderu.");
        string html=content.GetString()!;
        var action=Regex.Match(html,"<form\\b[^>]*\\baction=[\"']([^\"']+)",RegexOptions.IgnoreCase,TimeSpan.FromSeconds(1));
        if(!action.Success||WebUtility.HtmlDecode(action.Groups[1].Value)!="/action/FolderOptions/ChangePasswordAction")
            throw new InvalidDataException("Nie rozpoznano operacji ochrony folderu.");
        var values=new Dictionary<string,string>(StringComparer.Ordinal);
        foreach(Match tag in Regex.Matches(html,"<input\\b[^>]*>",RegexOptions.IgnoreCase,TimeSpan.FromSeconds(1)))
        {
            var attrs=Regex.Matches(tag.Value,"([\\w-]+)\\s*=\\s*([\"'])(.*?)\\2",RegexOptions.Singleline,TimeSpan.FromSeconds(1))
                .Cast<Match>().ToDictionary(m=>m.Groups[1].Value,m=>WebUtility.HtmlDecode(m.Groups[3].Value),StringComparer.OrdinalIgnoreCase);
            if(attrs.TryGetValue("name",out var name)&&!values.TryAdd(name,attrs.GetValueOrDefault("value","")))
                throw new InvalidDataException("Powielone pole formularza ochrony.");
        }
        if(values.GetValueOrDefault("FolderId")!=folder.Id||
            !string.Equals(values.GetValueOrDefault("ChomikName"),accountName,StringComparison.OrdinalIgnoreCase)||
            !values.TryGetValue("Password",out var current))
            throw new InvalidDataException("Formularz nie potwierdził tożsamości folderu.");
        return current;
    }

    private async Task<JsonDocument> FolderFormAsync(string action,ChomikujFolder folder,string? password,CancellationToken ct)
    {
        using var request=new HttpRequestMessage(HttpMethod.Post,"https://chomikuj.pl/action/FolderOptions/"+action);
        request.Headers.TryAddWithoutValidation("X-Requested-With","XMLHttpRequest");
        request.Headers.Referrer=new Uri("https://chomikuj.pl/");
        var fields=new Dictionary<string,string>{{"ChomikName",accountName},{"FolderId",folder.Id},{"__RequestVerificationToken",webVerificationToken}};
        if(password is not null)fields.Add("Password",password);
        request.Content=new FormUrlEncodedContent(fields);
        using var response=await SendTransferAsync(request,"Ochrona folderu",ct,HttpOperation.FolderProtection);
        if(!response.IsSuccessStatusCode)throw SafeHttpError(response,HttpOperation.FolderProtection);
        return await ReadWebJsonAsync(response,ct,HttpOperation.FolderProtection);
    }
}
