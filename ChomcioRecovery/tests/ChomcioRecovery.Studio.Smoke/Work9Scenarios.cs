using ChomcioRecovery.Desktop;
using ChomcioRecovery.Core;
using System.Reflection;

internal static class Work9Scenarios
{
    internal static IEnumerable<Control> All(Control parent)=>parent.Controls.Cast<Control>().SelectMany(c=>new[]{c}.Concat(All(c)));
    private static TextBox Input(Form f,string name)=>(TextBox)f.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(f)!;
    internal static async Task Run(string root,Action<bool,string> check)
    {
        string sandbox=Path.Combine(root,"work11");Directory.CreateDirectory(sandbox);
        string source=Path.Combine(sandbox,"source");Directory.CreateDirectory(source);File.WriteAllText(Path.Combine(source,"sample.txt"),"WORK11 synthetic cloud button");
        var account=new JobSecrets("","synthetic-login","synthetic-account-secret");
        var store=new StudioStore(Path.Combine(sandbox,"store"));StudioCredentials.RememberAccount(store,account);store.Save();
        using(var wizard=new ProfileEditor(store.Root,account:account,newDestination:BackupDestination.Chomikuj))
        {
            wizard.Opacity=0;wizard.ShowInTaskbar=false;wizard.Show();Input(wizard,"source").Text=source;wizard.Advance();wizard.Advance();wizard.Advance();
            check(wizard.ResultProfile?.Destination==BackupDestination.Chomikuj&&wizard.StartAfterSave,"dedicated Chomikuj wizard creates an upload task");
            check(wizard.ResultSecrets?.VaultPassword.Length==64&&wizard.ResultProfile!.ProtectedSecrets is not null,"default wizard generates and protects 256-bit recovery key without password input");
            check(wizard.ResultSecrets!.VaultPassword!=account.CloudPassword,"vault key is independent of account password");
            check(WindowsSecrets.Unprotect(wizard.ResultProfile!.ProtectedSecrets!).VaultPassword==wizard.ResultSecrets.VaultPassword,"generated key survives protected storage");
        }
        var oldSecrets=new JobSecrets("old-key","synthetic-login","synthetic-account-secret");
        var profile=new BackupProfile{Name="Legacy never-created vault",Source=source,Repository=Path.Combine(sandbox,"vault"),Destination=BackupDestination.Chomikuj,ProtectedSecrets=WindowsSecrets.Protect(oldSecrets)};
        store.Data.Profiles.Add(profile);store.Save();
        var repaired=VaultKeys.Prepare(store,profile,oldSecrets);
        check(repaired.VaultPassword.Length==64&&repaired.CloudPassword==oldSecrets.CloudPassword,"short legacy key repaired without changing account password");
        var reloaded=new StudioStore(store.Root);check(WindowsSecrets.Unprotect(reloaded.Data.Profiles.Single().ProtectedSecrets!)==repaired,"repaired key persists before upload");
        check(VaultKeys.Prepare(store,profile,repaired)==repaired,"subsequent operations retain generated key");
        profile.PendingSnapshot=Guid.NewGuid().ToString("N");
        check(VaultKeys.Prepare(store,profile,oldSecrets)==oldSecrets,"pending upload key is never replaced");
        profile.PendingSnapshot=null;profile.RemoteFolderId="already-created";
        check(VaultKeys.Prepare(store,profile,oldSecrets)==oldSecrets,"known remote vault key is never replaced");
        profile.RemoteFolderId=null;Directory.CreateDirectory(profile.Repository);
        check(VaultKeys.Prepare(store,profile,oldSecrets)==oldSecrets,"existing local vault key is never replaced");
        string exported=VaultKeys.RecoveryText(profile,repaired);
        check(exported.Contains(repaired.VaultPassword)&&!exported.Contains(repaired.CloudPassword),"recovery export contains vault key but never account password");
        using(var keys=new RecoveryKeyWindow(profile,repaired))
        {
            keys.Opacity=0;keys.ShowInTaskbar=false;keys.Show();
            check(All(keys).OfType<TextBox>().Single().UseSystemPasswordChar,"recovery key is masked by default");
        }
        // A real click in the real main form must use the production job engine.
        // Give it an isolated transport so this regression is deterministic.
        profile.Repository=Path.Combine(sandbox,"button-vault");
        var remote=new MemoryCloud();var engine=new JobEngine(store,()=>new Connection(remote));
        using(var window=new StudioWindow(store,engine,true))
        {
            window.Opacity=0;window.ShowInTaskbar=false;window.Show();
            check(All(window).Any(c=>c.Text=="Moje kopie w Chomikuj"),"first screen is Chomikuj");
            check(All(window).Any(c=>c.Name=="NewChomikujBackup"&&c.Visible),"new Chomikuj backup entry is visible");
            var run=All(window).OfType<Button>().Single(c=>c.Name=="RunBackup_"+profile.Id);
            check(run.Text=="Wyślij na Chomikuj","profile action explicitly says upload to Chomikuj");
            var done=new TaskCompletionSource<RunRecord>();engine.Finished+=r=>done.TrySetResult(r);run.PerformClick();
            var result=await done.Task.WaitAsync(TimeSpan.FromSeconds(40));
            check(result.State==RunState.Success&&remote.Files.Keys.Any(n=>n.EndsWith(".snap")),"main-screen click publishes cloud snapshot");
            check(remote.Downloads>0&&profile.LastSuccess is not null,"main-screen success requires downloaded cloud data verification");
            check(All(window).Any(c=>c.Text.StartsWith("W Chomikuj · sprawdzona:")),"verified cloud status is visible after button operation");
            using var bmp=new Bitmap(window.Width,window.Height);window.DrawToBitmap(bmp,new Rectangle(0,0,bmp.Width,bmp.Height));bmp.Save(Path.Combine(root,"previews","Chomikuj-button-pass.png"));
            window.ClientSize=new(1000,720);await Task.Delay(40);using var small=new Bitmap(window.Width,window.Height);window.DrawToBitmap(small,new Rectangle(0,0,small.Width,small.Height));small.Save(Path.Combine(root,"previews","Chomikuj-small.png"));
            var smallButton=All(window).OfType<Button>().Single(c=>c.Name=="RunBackup_"+profile.Id);
            var full=smallButton.RectangleToScreen(smallButton.ClientRectangle);var clipped=full;
            for(Control? parent=smallButton.Parent;parent is not null;parent=parent.Parent)clipped=Rectangle.Intersect(clipped,parent.RectangleToScreen(parent.ClientRectangle));
            check(clipped==full,"upload button fully visible without scrolling at minimum window size");
        }
        Console.WriteLine("CHOMCIO_STUDIO_CHOMIKUJ_ENTRY_AND_GENERATED_KEY=PASS");
    }
    private sealed class Connection(MemoryCloud remote):IJobCloud
    {public Task<ICloudVault> ConnectAsync(BackupProfile profile,JobSecrets secrets,CancellationToken token)=>Task.FromResult<ICloudVault>(remote);public void Dispose(){}}
    private sealed class MemoryCloud:ICloudVault
    {
        internal readonly Dictionary<string,byte[]> Files=new();internal int Downloads;
        public Task<IReadOnlyList<CloudObject>> ListAsync(CancellationToken token)=>Task.FromResult<IReadOnlyList<CloudObject>>(Files.Select(p=>new CloudObject(p.Key,p.Key,p.Value.Length)).ToArray());
        public async Task<CloudObject> UploadAsync(string name,Stream input,long length,CancellationToken token){using var memory=new MemoryStream();await input.CopyToAsync(memory,token);Files.Add(name,memory.ToArray());return new(name,name,length);}
        public async Task DownloadAsync(CloudObject file,Stream output,long max,CancellationToken token){if(Files[file.Name].Length>max)throw new IOException();Downloads++;await output.WriteAsync(Files[file.Name],token);}
    }
}
