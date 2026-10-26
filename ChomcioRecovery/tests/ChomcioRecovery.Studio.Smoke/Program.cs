using ChomcioRecovery.Desktop;
using ChomcioRecovery.Core;
using System.Security.Cryptography;
using Microsoft.Win32;

internal static class StudioSmoke
{
    private static int checks;
    private static void Check(bool condition,string label){checks++;if(!condition)throw new Exception(label);}
    private static async Task Fails(Func<Task> action,string label){bool failed=false;try{await action();}catch(Exception e)when(e is IOException or InvalidDataException or ArgumentException or CryptographicException or System.Text.Json.JsonException){failed=true;}Check(failed,label);}
    [STAThread]private static int Main(string[] args)
    {
        if(args.Length==2&&args[0]=="--background-cloud")return BackgroundCloudProbe.Run(args[1]);
        if(args.Length==2&&args[0]=="--background-native")return InstalledBackgroundProbe.Run(args[1]);
        if(args.Length==3&&args[0]=="--background-lease")
        {try{BackgroundCopyScenarios.Hold(args[1],args[2]);return 0;}catch(Exception){return 1;}}
        if(args.Length==2&&args[0]=="--background-copies")
        {
            try{BackgroundCopyScenarios.Run(Path.GetFullPath(args[1]),Check);Console.WriteLine($"Checks: {checks}");return 0;}
            catch(Exception e){Console.Error.WriteLine(e);return 1;}
        }
        if(args.Length==2&&args[0]=="--recovery-guide")
        {
            try{Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);Application.EnableVisualStyles();RecoveryGuideScenarios.Run(Path.GetFullPath(args[1]),Check);Console.WriteLine($"Checks: {checks}");return 0;}
            catch(Exception e){Console.Error.WriteLine(e);return 1;}
        }
        if(args.Length==3&&args[0]=="--prepare-windows-recovery")
        {
            const string lab=@"D:\Codex\VMs\ChomcioRecovery-Windows-Test\";
            if(!Path.GetFullPath(args[1]).StartsWith(lab,StringComparison.OrdinalIgnoreCase)||
                !Path.GetFullPath(args[2]).StartsWith(lab,StringComparison.OrdinalIgnoreCase))return 2;
            try{string recoveryPath=SystemImageRecovery.PrepareAsync(args[1],args[2],null,default,false).GetAwaiter().GetResult();Console.WriteLine("WINDOWS_RECOVERY_PREPARATION=PASS "+recoveryPath);return 0;}
            catch(Exception e){Console.Error.WriteLine(e);return 1;}
        }
        if(args.Length==4&&args[0]=="--resume-daily-image-fix")
            return InstalledDailyImageResumeProbe.Run(args[1],args[2],args[3],true);
        if(args.Length==4&&args[0]=="--resume-daily-image")
            return InstalledDailyImageResumeProbe.Run(args[1],args[2],args[3]);
        if(args.Length==4&&args[0]=="--installed-daily-image")
            return InstalledDailyImageProbe.Run(args[1],args[2],args[3]);
        if(args.Length==3&&args[0]=="--installed-plan-discovery")
            return InstalledImageWizardProbe.Run(args[1],args[2]);
        if(args.Length==1&&args[0]=="--installed-plan-token")
            return InstalledImageWizardProbe.RunAuthenticated();
        if(args.Length==1&&args[0]=="--installed-image-client")
            return InstalledImageClientProbe.RunAsync().GetAwaiter().GetResult();
        if(args.Length==2&&args[0]=="--image-layout")
        {
            try
            {
                StudioStore.RejectLinks(args[1]);
                using var input=new FileStream(args[1],FileMode.Open,FileAccess.Read,FileShare.Read);
                SystemImageLease.CheckArchive(input,default);
                Console.WriteLine("SYSTEM_IMAGE_ARCHIVE_LAYOUT=PASS (read-only central directory check; no capture/upload/restore)");
                return 0;
            }
            catch(Exception){Console.Error.WriteLine("SYSTEM_IMAGE_ARCHIVE_LAYOUT=FAILED");return 1;}
        }
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);Application.EnableVisualStyles();
        using var host=new Form{Opacity=0,ShowInTaskbar=false};int result=1;
        host.Shown+=async(_,_)=>
        {
            try{if(args[0]=="--live")await LiveAcceptance.Run(args[1],args.Length>2?args[2]:"create");else if(args.Length==2&&args[0]=="--system-readiness")await SystemImageWizardScenarios.Run(Path.GetFullPath(args[1]),Check);else await Run(args[0]);result=0;}catch(Exception e){Console.Error.WriteLine(e);}finally{host.Close();}
        };
        Application.Run(host);return result;
    }
    private static async Task Run(string root)
    {
        root=Path.GetFullPath(root);if(Directory.Exists(root))throw new IOException("Test requires a new directory.");Directory.CreateDirectory(root);
        RecoveryGuideScenarios.Run(Path.Combine(root,"recovery-guide"),Check);
        Work12Scenarios.Run(Check);
        await LocalJobProgressScenarios.Run(root,Check);
        var secrets=new JobSecrets("synthetic-vault-secret","synthetic-login","synthetic-account-secret");
        string protectedValue=WindowsSecrets.Protect(secrets);
        Check(WindowsSecrets.Unprotect(protectedValue)==secrets,"DPAPI current-user roundtrip");
        Check(!System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(protectedValue)).Contains(secrets.VaultPassword),"plaintext absent from encrypted credential blob");
        byte[] broken=Convert.FromBase64String(protectedValue);broken[^1]^=1;
        await Fails(()=>{WindowsSecrets.Unprotect(Convert.ToBase64String(broken));return Task.CompletedTask;},"tampered DPAPI refused");
        string src=Path.Combine(root,"source");Directory.CreateDirectory(Path.Combine(src,"empty"));byte[] original=RandomNumberGenerator.GetBytes(65_537);File.WriteAllBytes(Path.Combine(src,"sample.bin"),original);
        var profile=new BackupProfile{Name="Próba automatu",Source=src,Repository=Path.Combine(root,"vault"),AtLogon=true,Daily=true,DailyMinute=600,ProtectedSecrets=protectedValue};
        var now=new DateTimeOffset(2026,10,18,11,0,0,TimeSpan.FromHours(2));
        Check(SchedulePolicy.Due(profile,now,"logon1",false),"logon or overdue daily due");
        SchedulePolicy.MarkAttempt(profile,now,"logon1");
        Check(!SchedulePolicy.Due(profile,now,"logon1",false),"same session/day not duplicated");
        Check(SchedulePolicy.Due(profile,now,"logon2",false),"new login eligible");
        Check(SchedulePolicy.Due(profile,now.AddDays(1),null,false),"next day eligible");
        Check(!SchedulePolicy.Due(profile,now.AddDays(1),"new",true),"pause blocks automation");
        profile.ProtectedSecrets=null;Check(!SchedulePolicy.Due(profile,now.AddDays(1),"new",false),"no stored secret means no unattended run");profile.ProtectedSecrets=protectedValue;
        var store=new StudioStore(Path.Combine(root,"store"));store.Data.Profiles.Add(profile);store.Save();
        string settings=File.ReadAllText(Path.Combine(store.Root,"settings.json"));Check(!settings.Contains(secrets.VaultPassword)&&!settings.Contains(secrets.CloudPassword),"settings never store plaintext passwords");
        Check(new StudioStore(store.Root).Data.Profiles.Single().Id==profile.Id,"profile persistence");
        var engine=new JobEngine(store);
        var first=await engine.RunAsync(profile,secrets,now);
        Check(first?.State==RunState.Success && profile.LastSuccess is not null,"actual automatic local backup verified");
        string restored=Path.Combine(root,"restored");using(var vault=LocalEncryptedVault.Open(profile.Repository,secrets.VaultPassword))vault.RestoreSnapshot(profile.LastSnapshot!,restored);
        Check(File.ReadAllBytes(Path.Combine(restored,"sample.bin")).SequenceEqual(original)&&Directory.Exists(Path.Combine(restored,"empty")),"job output restores exact synthetic bytes and empty directory");
        string oldSnapshot=profile.LastSnapshot!;File.AppendAllText(Path.Combine(src,"sample.bin"),"changed");
        var second=await engine.RunAsync(profile,secrets,now.AddMinutes(1));
        Check(second?.State==RunState.Success&&profile.LastSnapshot!=oldSnapshot,"later run creates a different point");
        using(var vault=LocalEncryptedVault.Open(profile.Repository,secrets.VaultPassword))Check(vault.ListSnapshotIds().Contains(oldSnapshot),"previous snapshot retained");
        var bad=new BackupProfile{Name="Bad",Source=src,Repository=Path.Combine(src,"nested")};
        await Fails(()=>{JobEngine.Validate(bad,secrets);return Task.CompletedTask;},"overlapping destination refused before initialization");Check(!Directory.Exists(bad.Repository),"validation did not create a folder inside source");
        var remote=new FakeCloud();var cloudProfile=new BackupProfile{Name="Próba chmury",Source=src,Repository=Path.Combine(root,"cloud-vault"),Destination=BackupDestination.Chomikuj,ProtectedSecrets=protectedValue};store.Data.Profiles.Add(cloudProfile);
        var cloudEngine=new JobEngine(store,()=>new Connection(remote));remote.Block=true;
        var running=cloudEngine.RunAsync(cloudProfile,secrets,now);
        await remote.Started.Task;
        Check(await cloudEngine.RunAsync(profile,secrets,now) is null,"concurrent jobs do not run");
        cloudEngine.Cancel();var cancelled=await running;
        Check(cancelled?.State==RunState.Cancelled&&cloudProfile.PendingSnapshot is not null,"cancel keeps pending immutable snapshot");
        Check(!remote.Files.Keys.Any(n=>n.EndsWith(".snap")),"cancelled cloud run did not publish manifest");
        string pending=cloudProfile.PendingSnapshot!;remote.Block=false;
        var reloadedStore=new StudioStore(store.Root);var reloadedProfile=reloadedStore.Data.Profiles.Single(p=>p.Id==cloudProfile.Id);
        var restarted=new JobEngine(reloadedStore,()=>new Connection(remote));
        var resumed=await restarted.RunAsync(reloadedProfile,secrets,now.AddMinutes(3));
        Check(resumed?.State==RunState.Success&&resumed.Snapshot==pending&&reloadedProfile.PendingSnapshot is null,"restart resumes saved point instead of creating another");
        Check(remote.Uploads==remote.Files.Count,"resume reused existing uploaded record");
        var transfer=new CloudVaultTransfer(remote);string downloaded=Path.Combine(root,"downloaded");await transfer.DownloadSnapshotAsync(pending,secrets.VaultPassword,downloaded,null,default);
        using(var vault=LocalEncryptedVault.Open(downloaded,secrets.VaultPassword))vault.VerifySnapshot(pending);
        Check(true,"job-created cloud copy independently authenticated");
        reloadedStore.Data.History.Add(new(){State=RunState.Running,Name="Synthetic interrupted"});reloadedStore.Save();
        Check(new StudioStore(reloadedStore.Root).Data.History.Last().State==RunState.Interrupted,"crashed running history never reported success");
        string badRoot=Path.Combine(root,"bad-settings");Directory.CreateDirectory(badRoot);File.WriteAllText(Path.Combine(badRoot,"settings.json"),"{");
        await Fails(()=>{_=new StudioStore(badRoot);return Task.CompletedTask;},"corrupted settings fail closed");Check(File.ReadAllText(Path.Combine(badRoot,"settings.json"))=="{","corrupt settings retained for repair");
        string key=@"Software\ChomcioRecovery.Test\"+Guid.NewGuid().ToString("N");
        try{StartupRegistration.SetEnabled(true,key);Check(StartupRegistration.IsEnabled(key),"startup command registered in isolated test key");StartupRegistration.SetEnabled(false,key);Check(!StartupRegistration.IsEnabled(key),"startup option reversible");}
        finally{Registry.CurrentUser.DeleteSubKeyTree(key,false);}
        Check(StartupRegistration.Command(@"C:\Program Files\Chomcio\ChomcioRecovery.exe")=="\"C:\\Program Files\\Chomcio\\ChomcioRecovery.exe\" --autostart","autostart quotes executable path");
        Check(SchedulePolicy.LogonId()==SchedulePolicy.LogonId(),"native Windows login identity stable");
        await Fails(()=>{SystemImagePlan.Arguments("C:","C:");return Task.CompletedTask;},"image cannot target system volume");
        await Fails(()=>{SystemImagePlan.Arguments("E: & arbitrary","C:");return Task.CompletedTask;},"image rejects command injection and arbitrary paths");
        var imageArgs=SystemImagePlan.Arguments("E:","C:");Check(imageArgs.Contains("-allCritical")&&imageArgs.Contains("-vssCopy")&&!imageArgs.Contains("-noVerify"),"image request includes boot-critical volumes and non-invasive VSS mode");
        string uxPreviews=Path.Combine(root,"ux-previews");Directory.CreateDirectory(uxPreviews);
        void Capture(Form form,string name){using var image=new Bitmap(form.Width,form.Height);form.DrawToBitmap(image,new Rectangle(0,0,image.Width,image.Height));image.Save(Path.Combine(uxPreviews,name+".png"));}
        // Real wizard validation and remembered credentials, no MessageBox input.
        TextBox Input(Form form,string field)=>(TextBox)form.GetType().GetField(field,System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic)!.GetValue(form)!;
        using(var editor=new ProfileEditor(store.Root,null,secrets))
        {
            editor.Opacity=0;editor.ShowInTaskbar=false;editor.Show();
            editor.Advance();Check(editor.Step==0&&editor.ValidationMessage.Contains("Wybierz"),"empty source is an inline message, wizard stays open");
            Input(editor,"source").Text=src;editor.Advance();Check(editor.Step==1,"selected existing source advances wizard");Capture(editor,"step2");
            Check(Input(editor,"cloudPassword").Text==secrets.CloudPassword,"saved account fills next copy without asking password");
            editor.Advance();Check(editor.Step==2,"remembered account advances without manual login");Capture(editor,"step3");
            ((RadioButton)typeof(ProfileEditor).GetField("ownKey",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic)!.GetValue(editor)!).Checked=true;
            Input(editor,"password").Text="short";Input(editor,"confirmation").Text="short";editor.Advance();Check(editor.ResultProfile is null&&editor.ValidationMessage.Contains("12"),"short vault password refused before backup, inline");
            Input(editor,"password").Text=Input(editor,"confirmation").Text=secrets.VaultPassword;editor.Advance();
            Check(editor.ResultProfile?.ProtectedSecrets is not null&&editor.StartAfterSave,"new copy remembers encrypted passwords by default and requests first backup");
            var remembered=WindowsSecrets.Unprotect(editor.ResultProfile!.ProtectedSecrets!);
            Check(remembered with{FolderPassword=null}==secrets,"wizard remembers exact account and vault credentials");
            Check(remembered.FolderPassword is {Length:64}&&remembered.FolderPassword!=remembered.VaultPassword&&editor.ResultProfile.ProtectCloudFolder,
                "wizard generates and protects a separate portal folder password");
        }
        var accountStore=new StudioStore(Path.Combine(root,"account-store"));
        accountStore.Data.Profiles.Add(new(){ProtectedSecrets=protectedValue,Daily=true,AtLogon=true});
        StudioCredentials.RememberAccount(accountStore,secrets);accountStore.Save();
        Check(StudioCredentials.Account(new StudioStore(accountStore.Root))==secrets with{VaultPassword=""},"shared account survives settings reload without sharing vault key");
        StudioCredentials.Forget(accountStore);var forgotten=new StudioStore(accountStore.Root);
        Check(forgotten.Data.ProtectedAccount is null&&forgotten.Data.Profiles.All(p=>p.ProtectedSecrets is null&&!p.Daily&&!p.AtLogon),"forget clears persistent credentials and disables unattended copies");
        using(var restoreSession=new RestoreSession(store,profile,secrets))
        {
            var points=await restoreSession.ListAsync(false,default);Check(points.Count>=2&&points.All(p=>p.Date is not null),"guided local restore lists real dated snapshots");
            string target=Path.Combine(root,"guided-single.bin");await restoreSession.RestoreAsync(oldSnapshot,false,target,"sample.bin",null,default);
            Check(File.ReadAllBytes(target).SequenceEqual(original),"guided restore recovers selected file from earlier version");
            await Fails(()=>restoreSession.RestoreAsync(oldSnapshot,false,target,"sample.bin",null,default),"guided restore refuses existing output");
            Check(File.ReadAllBytes(target).SequenceEqual(original),"existing output unchanged after refused restore");
        }
        using(var restoreWindow=new RestoreWindow(store,profile,secrets))
        {
            restoreWindow.Opacity=0;restoreWindow.ShowInTaskbar=false;restoreWindow.Show();
            var list=(ListBox)typeof(RestoreWindow).GetField("points",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic)!.GetValue(restoreWindow)!;
            for(int attempt=0;attempt<100&&list.Items.Count==0;attempt++)await Task.Delay(30);
            Check(list.Items.Count>=2,"real restore window loads dated local points automatically");Capture(restoreWindow,"restore");restoreWindow.Close();
        }
        // UI is rendered on a real Windows message loop with isolated settings.
        string previews=Path.Combine(root,"previews");Directory.CreateDirectory(previews);
        using(var window=new StudioWindow(store,engine,true))
        {
            window.Opacity=0;window.ShowInTaskbar=false;window.Show();await Task.Delay(100);
            foreach(string page in new[]{"Pulpit","Zadania kopii","Historia","Przywracanie","Chomikuj","Obraz Windows","Ustawienia"})
            {window.ShowPage(page);await Task.Delay(60);using var bitmap=new Bitmap(window.Width,window.Height);window.DrawToBitmap(bitmap,new Rectangle(0,0,bitmap.Width,bitmap.Height));bitmap.Save(Path.Combine(previews,page+".png"));Check(!window.IsDisposed,"render page: "+page);}
            window.ShowPage("Pulpit");window.ClientSize=new(1000,720);await Task.Delay(60);using var small=new Bitmap(window.Width,window.Height);window.DrawToBitmap(small,new Rectangle(0,0,small.Width,small.Height));small.Save(Path.Combine(previews,"small.png"));
        }
        using(var editor=new ProfileEditor(store.Root)){editor.Opacity=0;editor.ShowInTaskbar=false;editor.Show();await Task.Delay(80);using var bmp=new Bitmap(editor.Width,editor.Height);editor.DrawToBitmap(bmp,new Rectangle(0,0,bmp.Width,bmp.Height));bmp.Save(Path.Combine(previews,"editor.png"));}
        using(var trayApp=new StudioApplication(false,Path.Combine(root,"tray-store")))
        {
            trayApp.Window.Opacity=0;trayApp.Window.ShowInTaskbar=false;trayApp.Store.Data.Notifications=false;
            Check(trayApp.Tray.Visible,"real Windows notification icon exists");trayApp.Window.Close();Check(!trayApp.Window.IsDisposed&&!trayApp.Window.Visible,"close hides window while application lives");trayApp.Show();Check(trayApp.Window.Visible,"tray can restore window");await trayApp.ExitAsync(false);Check(!trayApp.Tray.Visible,"explicit exit removes tray icon");
        }
        string automationRoot=Path.Combine(root,"automatic-app-store");var automationStore=new StudioStore(automationRoot);
        automationStore.Data.Notifications=false;
        automationStore.Data.Profiles.Add(new(){Name="Automatic integration",Source=src,Repository=Path.Combine(root,"automatic-vault"),AtLogon=true,ProtectedSecrets=protectedValue});automationStore.Save();
        using(var automatic=new StudioApplication(true,automationRoot))
        {
            automatic.Window.Enabled=false;await Task.Delay(80);await automatic.CheckScheduleAsync();
            Check(automatic.Store.Data.History.Count==0,"modal editing blocks automatic backup start");automatic.Window.Enabled=true;
            await automatic.CheckScheduleAsync();await automatic.Engine.Completion;
            Check(automatic.Store.Data.History.Count==1&&automatic.Store.Data.History[0].State==RunState.Success,"autostart application really executes saved opted-in backup");
            Check(!automatic.Window.Visible&&automatic.Tray.Visible,"autostart works in tray without opening dashboard");await automatic.ExitAsync(false);
        }
        using(var again=new StudioApplication(true,automationRoot))
        {await again.CheckScheduleAsync();Check(again.Store.Data.History.Count==1,"relaunch in same login does not duplicate startup copy");await again.ExitAsync(false);}
        await Work9Scenarios.Run(root,Check);
        await Work10Scenarios.Run(Check);
        await Work11Scenarios.Run(root,Check);
        await SystemImageJobScenarios.Run(root,Check);
        await SystemImageWizardScenarios.Run(root,Check);
        Console.WriteLine($"CHOMCIO_STUDIO_SMOKE=PASS assertions={checks}");Console.WriteLine("SYSTEM_IMAGE_CREATE_RESTORE=NOT_RUN (no system/user disks backed up)");Console.WriteLine("REAL_LOGOFF_REBOOT=NOT_RUN; scheduler policy and native registration tested separately");
    }
    private sealed class Connection(FakeCloud remote):IJobCloud
    {public Task<ICloudVault> ConnectAsync(BackupProfile profile,JobSecrets secrets,CancellationToken token)=>Task.FromResult<ICloudVault>(remote);public void Dispose(){}}
    private sealed class FakeCloud:ICloudVault
    {
        internal readonly Dictionary<string,byte[]> Files=new();internal int Uploads;internal bool Block;
        internal readonly TaskCompletionSource Started=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<IReadOnlyList<CloudObject>> ListAsync(CancellationToken ct)=>Task.FromResult<IReadOnlyList<CloudObject>>(Files.Select(p=>new CloudObject(p.Key,p.Key,p.Value.Length)).ToArray());
        public async Task<CloudObject> UploadAsync(string name,Stream stream,long length,CancellationToken ct)
        {using var memory=new MemoryStream();await stream.CopyToAsync(memory,ct);Files.Add(name,memory.ToArray());Uploads++;Started.TrySetResult();if(Block)await Task.Delay(Timeout.Infinite,ct);return new(name,name,length);}
        public async Task DownloadAsync(CloudObject file,Stream output,long limit,CancellationToken ct){if(Files[file.Name].Length>limit)throw new InvalidDataException();await output.WriteAsync(Files[file.Name],ct);}
    }
}
