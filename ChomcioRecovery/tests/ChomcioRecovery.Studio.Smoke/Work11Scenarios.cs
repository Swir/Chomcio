using ChomcioRecovery.Desktop;
using ChomcioRecovery.Core;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

internal static class Work11Scenarios
{
    private static TextBox Input(Form form,string field)=>(TextBox)form.GetType().GetField(field,BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(form)!;
    private static RadioButton Choice(Form form,string name)=>Work9Scenarios.All(form).OfType<RadioButton>().Single(c=>c.Name==name);
    private static void Show(Form form){form.Opacity=0;form.ShowInTaskbar=false;form.Show();}
    private static void Capture(Form form,string file){using var bmp=new Bitmap(form.Width,form.Height);form.DrawToBitmap(bmp,new Rectangle(0,0,bmp.Width,bmp.Height));bmp.Save(file);}
    internal static async Task Run(string root,Action<bool,string> check)
    {
        string area=Path.Combine(root,"own-key");Directory.CreateDirectory(area);
        string source=Path.Combine(area,"source");Directory.CreateDirectory(source);File.WriteAllText(Path.Combine(source,"sample.txt"),"Synthetic own-key roundtrip");
        var store=new StudioStore(Path.Combine(area,"store"));
        check(!store.Data.UseOwnKeyForNewCopies,"legacy settings default to generated keys");
        const string custom="  Własne testowe hasło WORK11!  ";
        BackupProfile profile;JobSecrets secrets;
        using(var wizard=new ProfileEditor(store.Root,newDestination:BackupDestination.Local,useOwnKey:true))
        {
            Show(wizard);Input(wizard,"source").Text=source;wizard.Advance();wizard.Advance();
            check(Choice(wizard,"OwnKeyChoice").Checked&&Input(wizard,"password").Visible,"custom default exposes password and confirmation");
            Input(wizard,"password").Text=custom;Input(wizard,"confirmation").Text=custom+"x";wizard.Advance();
            check(wizard.ResultProfile is null&&wizard.ValidationMessage.Contains("różnią"),"mismatched custom keys are refused inline");
            Input(wizard,"password").Text=Input(wizard,"confirmation").Text=new string(' ',16);wizard.Advance();
            check(wizard.ResultProfile is null&&wizard.ValidationMessage.Contains("spacje"),"whitespace-only keys refused");
            Input(wizard,"password").Text=Input(wizard,"confirmation").Text=custom;
            Choice(wizard,"GeneratedKeyChoice").Checked=true;
            check(!Work9Scenarios.All(wizard).Contains(Input(wizard,"password")),"generated option hides custom fields");
            Choice(wizard,"OwnKeyChoice").Checked=true;
            check(Input(wizard,"password").Text==custom,"switching choices retains entered key");
            Capture(wizard,Path.Combine(area,"custom-key-wizard.png"));
            wizard.Advance();profile=wizard.ResultProfile!;secrets=wizard.ResultSecrets!;
            check(secrets.VaultPassword==custom,"custom Unicode key preserved exactly, including spaces");
        }
        store.Data.Profiles.Add(profile);store.Save();
        check(!File.ReadAllText(Path.Combine(store.Root,"settings.json")).Contains(custom),"custom key is absent from plaintext settings");
        var engine=new JobEngine(store);
        var result=await engine.RunAsync(profile,secrets,DateTimeOffset.Now);
        check(result?.State==RunState.Success,"custom-key profile makes a verified real local backup");
        string originalProtected=profile.ProtectedSecrets!;
        using(var window=new StudioWindow(store,engine,true))
        {
            Show(window);window.ShowPage("Ustawienia");
            var choice=Work9Scenarios.All(window).OfType<ComboBox>().Single(c=>c.Name=="DefaultKeyChoice");
            choice.SelectedIndex=1;Work9Scenarios.All(window).OfType<Button>().Single(c=>c.Text=="Zapisz ustawienia").PerformClick();
            Capture(window,Path.Combine(area,"key-settings.png"));
        }
        var reloaded=new StudioStore(store.Root);var existing=reloaded.Data.Profiles.Single();
        check(reloaded.Data.UseOwnKeyForNewCopies&&existing.ProtectedSecrets==originalProtected,"default setting persists without changing existing profile key");
        using(var wizard=new ProfileEditor(store.Root,existing,useOwnKey:false))
        {
            Show(wizard);wizard.Advance();wizard.Advance();
            check(!Work9Scenarios.All(wizard).OfType<RadioButton>().Any(),"existing known key cannot be replaced by a preference change");
            wizard.Advance();check(wizard.ResultSecrets?.VaultPassword==custom,"saving existing settings keeps the exact old key");
        }
        using(var vault=LocalEncryptedVault.Open(existing.Repository,WindowsSecrets.Unprotect(existing.ProtectedSecrets!).VaultPassword))
            vault.RestoreSnapshot(existing.LastSnapshot!,Path.Combine(area,"restored"));
        check(File.ReadAllBytes(Path.Combine(area,"restored","sample.txt")).SequenceEqual(File.ReadAllBytes(Path.Combine(source,"sample.txt"))),"custom key reload restores original bytes");
        var missing=JsonSerializer.Deserialize<BackupProfile>(JsonSerializer.Serialize(existing))!;missing.ProtectedSecrets=null;
        using(var wizard=new ProfileEditor(store.Root,missing))
        {
            Show(wizard);wizard.Advance();wizard.Advance();
            check(Choice(wizard,"OwnKeyChoice").Checked&&!Choice(wizard,"GeneratedKeyChoice").Enabled,"missing existing key never offers generation of a replacement");
        }
        Console.WriteLine("CHOMCIO_CUSTOM_KEY_SETTINGS=PASS");
    }
    internal static async Task Live(string root,bool restoreOnly)
    {
        var store=new StudioStore(Path.Combine(root,"store"));
        if(!restoreOnly)
        {
            if(store.Data.Profiles.Count>0)throw new IOException("Use a new isolated live directory.");
            var account=StudioCredentials.Account(new StudioStore(StudioStore.DefaultRoot))??throw new IOException("Test account missing.");
            string source=Path.Combine(root,"source");Directory.CreateDirectory(source);
            File.WriteAllBytes(Path.Combine(source,"synthetic.bin"),RandomNumberGenerator.GetBytes(131091));
            File.WriteAllText(Path.Combine(source,"notatka.txt"),"Tylko sztuczne dane do próby własnego hasła.");
            string custom="Sztuczne własne hasło "+Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            using var wizard=new ProfileEditor(store.Root,account:account,newDestination:BackupDestination.Chomikuj,useOwnKey:true);
            Show(wizard);Input(wizard,"source").Text=source;wizard.Advance();wizard.Advance();
            Input(wizard,"password").Text=Input(wizard,"confirmation").Text=custom;wizard.Advance();
            var profile=wizard.ResultProfile??throw new IOException("Custom wizard failed.");
            if(wizard.ResultSecrets!.VaultPassword!=custom)throw new IOException("Wizard changed custom key.");
            store.Data.Profiles.Add(profile);StudioCredentials.RememberAccount(store,account);store.Save();
            var result=await new JobEngine(store).RunAsync(profile,wizard.ResultSecrets,DateTimeOffset.Now);
            if(result?.State!=RunState.Success)throw new IOException("Custom upload failed: "+result?.FailureCode);
            Console.WriteLine("CHOMCIO_LIVE_CUSTOM_KEY_UPLOAD=PASS files="+result.Files);
        }
        else
        {
            var profile=store.Data.Profiles.Single();
            var secrets=WindowsSecrets.Unprotect(profile.ProtectedSecrets!);
            using var session=new RestoreSession(store,profile,secrets);
            var points=await session.ListAsync(true,default);
            if(!points.Any(p=>p.Id==profile.LastSnapshot))throw new IOException("Custom cloud point missing.");
            string restored=Path.Combine(root,"independent-restored");
            await session.RestoreAsync(profile.LastSnapshot!,true,restored,null,null,default);
            foreach(var file in Directory.GetFiles(profile.Source))
                if(!SHA256.HashData(File.ReadAllBytes(file)).SequenceEqual(SHA256.HashData(File.ReadAllBytes(Path.Combine(restored,Path.GetFileName(file))))))
                    throw new IOException("Custom-key cloud restore mismatch.");
            File.WriteAllText(Path.Combine(root,"CUSTOM_KEY_LIVE_PASS.json"),JsonSerializer.Serialize(new{pass=true,files=2,bytes=Directory.GetFiles(profile.Source).Sum(p=>new FileInfo(p).Length),timeUtc=DateTimeOffset.UtcNow,realChomikuj=true,separateRestoreProcess=true}));
            Console.WriteLine("CHOMCIO_LIVE_CUSTOM_KEY_RESTART_RESTORE=PASS files=2");
        }
    }
}
