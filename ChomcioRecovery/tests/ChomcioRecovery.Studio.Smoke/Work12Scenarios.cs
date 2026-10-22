using ChomcioRecovery.Desktop;
using ChomcioRecovery.Core;
using ChomcioRecovery.Chomikuj;
using System.Text.Json;
using System.Security.Cryptography;

internal static class Work12Scenarios
{
    internal static void Run(Action<bool,string> check)
    {
        const string id="0123456789abcdef0123456789abcdef";
        var now=new DateTimeOffset(2026,10,20,23,59,0,TimeSpan.FromHours(2));
        check(CloudFolderPlan.Name(CloudFolderPlan.Day(now),id,Array.Empty<ChomikujFolder>())=="Chomciore_20_10_2026","folder date follows local day");
        check(CloudFolderPlan.Name("2026-10-20",id,new[]{new ChomikujFolder("1","Chomciore_20_10_2026")})=="Chomciore_20_10_2026_01234567","same-date foreign folder is never adopted");
        check(CloudFolderPlan.Name("2026-10-20",id,new[]{new ChomikujFolder("1","Chomciore_20_10_2026"),new ChomikujFolder("2","Chomciore_20_10_2026_01234567")}).EndsWith("_2"),"same-date collisions preserve both existing folders");
        var legacy=JsonSerializer.Deserialize<BackupProfile>("{\"Id\":\""+id+"\"}")!;
        check(!legacy.CloudDateFolders&&legacy.ArchivedCloudFolders.Count==0,"existing profiles keep their folder layout");
        legacy.RemoteFolderId="2";legacy.RemoteFolderName="current";legacy.ArchivedCloudFolders.Add(new("1","old"));
        check(CloudFolderPlan.All(legacy).Select(f=>f.Id).SequenceEqual(new[]{"1","2"}),"restore retains prior cloud folder associations");
        var pending=new BackupProfile{PendingCloudDate=CloudFolderPlan.Day(now),PendingSnapshot=Guid.NewGuid().ToString("N")};
        SchedulePolicy.MarkAttempt(pending,now.AddDays(1),null);
        check(pending.PendingCloudDate=="2026-10-20","scheduler retry after midnight preserves pending upload day");
        pending.CloudDateFolders=true;pending.LastSuccess=now.AddDays(-1);pending.LastSnapshot=Guid.NewGuid().ToString("N");
        check(CloudFolderPlan.CanReplaceUnconfirmed(pending),"new daily folder can recover after interruption despite successful older day");
        pending.RemoteFolderHasConfirmedCopy=true;
        check(!CloudFolderPlan.CanReplaceUnconfirmed(pending),"confirmed daily folder is never replaced after a listing failure");
        check(CloudFolderPlan.FolderDate("Chomciore_01_11_2026_deadbeef")==new DateOnly(2026,11,1),"catalog parses the date independently of collision suffix");
    }
    internal static async Task Live(string root,bool restoreOnly,bool protect=false)
    {
        var store=new StudioStore(Path.Combine(root,"store"));
        if(!restoreOnly)
        {
            if(store.Data.Profiles.Count!=0)throw new IOException("New test directory required.");
            var account=StudioCredentials.Account(new StudioStore(StudioStore.DefaultRoot))??throw new IOException("No test account.");
            string source=Path.Combine(root,"source");Directory.CreateDirectory(source);
            File.WriteAllBytes(Path.Combine(source,"synthetic.bin"),RandomNumberGenerator.GetBytes(131091));
            File.WriteAllText(Path.Combine(source,"note.txt"),"Synthetic first daily backup.");
            var secrets=account with{VaultPassword=VaultKeys.Generate(),FolderPassword=protect?VaultKeys.Generate():null};
            var profile=new BackupProfile{Name="WORK12 synthetic daily",Source=source,Repository=Path.Combine(root,"vault"),Destination=BackupDestination.Chomikuj,CloudDateFolders=true,ProtectCloudFolder=protect,Daily=true,ProtectedSecrets=WindowsSecrets.Protect(secrets)};
            store.Data.Profiles.Add(profile);store.Save();
            var engine=new JobEngine(store);
            var first=await engine.RunAsync(profile,secrets,DateTimeOffset.Now);
            if(first?.State!=RunState.Success)throw new IOException("First cloud date failed: "+first?.Detail);
            File.WriteAllText(Path.Combine(source,"note.txt"),"Synthetic second daily backup.");
            // Simulated next day exercises actual rotation without changing the PC clock.
            var second=await engine.RunAsync(profile,secrets,DateTimeOffset.Now.AddDays(1));
            if(second?.State!=RunState.Success||profile.ArchivedCloudFolders.Count!=1||second.Snapshot==first.Snapshot)throw new IOException("Second cloud date failed: "+second?.Detail);
            Console.WriteLine("DATED_CLOUD_UPLOAD=PASS two separate folders, two verified versions");
        }
        else
        {
            var profile=store.Data.Profiles.Single();var secrets=WindowsSecrets.Unprotect(profile.ProtectedSecrets!);
            using var session=new RestoreSession(store,profile,secrets);
            var points=await session.ListAsync(true,default);
            if(points.Count!=2)throw new IOException("Both cloud dates must be listed.");
            foreach(var record in store.Data.History.OrderBy(h=>h.Started))
            {
                string target=Path.Combine(root,"restored-"+record.Id);
                await session.RestoreAsync(record.Snapshot!,true,target,null,null,default);
                if(!SHA256.HashData(File.ReadAllBytes(Path.Combine(target,"synthetic.bin"))).SequenceEqual(SHA256.HashData(File.ReadAllBytes(Path.Combine(profile.Source,"synthetic.bin")))))throw new IOException("Restored binary mismatch.");
                string expected=record==store.Data.History[0]?"Synthetic first daily backup.":"Synthetic second daily backup.";
                if(File.ReadAllText(Path.Combine(target,"note.txt"))!=expected)throw new IOException("Wrong daily version restored.");
            }
            File.WriteAllText(Path.Combine(root,"DATED_CLOUD_PASS.json"),JsonSerializer.Serialize(new{passed=true,versions=2,filesPerVersion=2,separateRestoreProcess=true,simulatedNextDay=true,realCloud=true,time=DateTimeOffset.UtcNow}));
            Console.WriteLine("DATED_CLOUD_RESTORE=PASS both dates restored independently with exact content");
        }
    }
    internal static async Task Privacy(string root)
    {
        var store=new StudioStore(Path.Combine(root,"store"));var profile=store.Data.Profiles.Single();
        var secrets=WindowsSecrets.Unprotect(profile.ProtectedSecrets!);
        if(!profile.ProtectCloudFolder||secrets.FolderPassword is null||secrets.FolderPassword==secrets.VaultPassword)
            throw new IOException("Independent portal protection is required.");
        using var owner=new ChomikujClient();await owner.LoginAsync(secrets.CloudLogin,secrets.CloudPassword,default);
        var controlStore=new StudioStore(Path.Combine(Path.GetDirectoryName(root)!,"WORK12-dates","store"));
        var control=controlStore.Data.Profiles.Single();
        if(control.ProtectCloudFolder)throw new IOException("Unprotected synthetic control folder required.");
        using(var anonymous=new HttpClient(new HttpClientHandler{AllowAutoRedirect=false,UseCookies=false}))
        {
            using var response=await anonymous.GetAsync("https://chomikuj.pl/"+Uri.EscapeDataString(secrets.CloudLogin)+"/"+Uri.EscapeDataString(control.RemoteFolderName!));
            if(!response.IsSuccessStatusCode)throw new IOException("Anonymous control folder unavailable; HTTP="+(int)response.StatusCode);
            Console.WriteLine("ANONYMOUS_CONTROL=PUBLIC");
        }
        foreach(var folder in CloudFolderPlan.All(profile))
        {
            // Owner readback must recognize the SAME password without changing it.
            await owner.EnsureFolderPasswordAsync(new(folder.Id,folder.Name),secrets.FolderPassword,default);
            using var anonymous=new HttpClient(new HttpClientHandler{AllowAutoRedirect=false,UseCookies=false});
            var uri=new Uri("https://chomikuj.pl/"+Uri.EscapeDataString(secrets.CloudLogin)+"/"+Uri.EscapeDataString(folder.Name));
            using var response=await anonymous.GetAsync(uri);
            string html=await response.Content.ReadAsStringAsync();
            bool locked=response.StatusCode==System.Net.HttpStatusCode.Unauthorized||
                (response.IsSuccessStatusCode&&System.Text.RegularExpressions.Regex.IsMatch(html,
                "<form\\b[^>]*\\bid=[\"']LoginToFolder[\"']",System.Text.RegularExpressions.RegexOptions.IgnoreCase));
            if(!locked)throw new IOException("Anonymous request did not confirm the folder password form. HTTP="+(int)response.StatusCode);
        }
        File.WriteAllText(Path.Combine(root,"FOLDER_PRIVACY_PASS.json"),JsonSerializer.Serialize(new{passed=true,folders=CloudFolderPlan.All(profile).Count(),independentPassword=true,anonymousAccessDenied=true,unprotectedControlAccessible=true,ownerReadback=true,timeUtc=DateTimeOffset.UtcNow}));
        Console.WriteLine("FOLDER_PRIVACY=PASS owner recognizes same password; anonymous access denied while control stays public");
    }
    internal static async Task NewPc(string root)
    {
        var original=new StudioStore(Path.Combine(root,"store"));var source=original.Data.Profiles.Single();
        var recoveredKey=WindowsSecrets.Unprotect(source.ProtectedSecrets!);
        var fresh=new StudioStore(Path.Combine(root,"new-pc","settings"));
        if(Directory.Exists(fresh.Root))throw new IOException("New PC test requires a fresh store.");
        StudioCredentials.RememberAccount(fresh,recoveredKey);fresh.Save();
        var account=StudioCredentials.Account(fresh)!;
        if(account.VaultPassword!=""||account.FolderPassword is not null||fresh.Data.Profiles.Count!=0)throw new IOException("Fresh PC must have account only.");
        var found=await CloudCatalogWindow.DiscoverAsync(account,default);
        foreach(var location in CloudFolderPlan.All(source))
        {
            var folder=found.Single(f=>f.Id==location.Id&&f.Name==location.Name);
            var profile=new BackupProfile{Name=folder.Name,Destination=BackupDestination.Chomikuj,RemoteFolderId=folder.Id,RemoteFolderName=folder.Name,
                Repository=Path.Combine(fresh.Root,"no-original-vault")};
            using var session=new RestoreSession(fresh,profile,account with{VaultPassword=recoveredKey.VaultPassword});
            var points=await session.ListAsync(true,default);
            if(points.Count!=1)throw new IOException("Expected one cloud copy in each daily folder.");
            string target=Path.Combine(root,"new-pc","restored-"+folder.Id);
            await session.RestoreAsync(points[0].Id,true,target,null,null,default);
            if(!File.ReadAllBytes(Path.Combine(target,"synthetic.bin")).SequenceEqual(File.ReadAllBytes(Path.Combine(source.Source,"synthetic.bin"))))
                throw new IOException("Independent PC binary mismatch.");
            string expected=folder.Id==source.RemoteFolderId?"Synthetic second daily backup.":"Synthetic first daily backup.";
            if(File.ReadAllText(Path.Combine(target,"note.txt"))!=expected)throw new IOException("Independent PC version mismatch.");
        }
        File.WriteAllText(Path.Combine(root,"NEW_PC_RESTORE_PASS.json"),JsonSerializer.Serialize(new{passed=true,folders=2,localProfiles=0,originalVaultUsed=false,onlyAccountAndRecoveryKey=true,timeUtc=DateTimeOffset.UtcNow}));
        Console.WriteLine("NEW_PC_RESTORE=PASS discovered account folders and restored both versions without original vault or profiles");
    }
    internal static async Task CatalogUi(string root)
    {
        var store=new StudioStore(Path.Combine(root,"store"));
        var profile=store.Data.Profiles.Single();var secrets=WindowsSecrets.Unprotect(profile.ProtectedSecrets!);
        using var window=new CloudCatalogWindow(store,secrets with{VaultPassword="",FolderPassword=null});
        window.Opacity=0;window.ShowInTaskbar=false;window.Show();
        var list=Work9Scenarios.All(window).OfType<ListBox>().Single();
        var open=Work9Scenarios.All(window).OfType<Button>().Single(b=>b.Name=="OpenCloudCatalogCopy");
        DateTime until=DateTime.UtcNow.AddSeconds(60);
        while(!open.Enabled&&DateTime.UtcNow<until)await Task.Delay(100);
        if(list.Items.Count==0)throw new IOException("Catalog window did not load account folders.");
        list.SelectedItem=list.Items.Cast<object>().Single(f=>f.ToString()==profile.RemoteFolderName);
        var key=Work9Scenarios.All(window).OfType<TextBox>().Single(t=>t.Name=="CloudRecoveryKey");
        if(!key.UseSystemPasswordChar||key.Text!=secrets.VaultPassword)throw new IOException("Known key must be remembered and masked.");
        using var bitmap=new Bitmap(window.Width,window.Height);window.DrawToBitmap(bitmap,new Rectangle(0,0,bitmap.Width,bitmap.Height));
        bitmap.Save(Path.Combine(root,"catalog-window.png"));
        Console.WriteLine("CLOUD_CATALOG_UI=PASS actual account list loaded; known recovery key masked and prefilled");
    }
}
