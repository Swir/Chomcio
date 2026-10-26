using ChomcioRecovery.Core;
using ChomcioRecovery.Desktop;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

internal static class BackgroundCopyScenarios
{
    internal static void Hold(string root,string ready)
    {
        using var mutex=StudioProcessScope.Create(root);
        if(!StudioProcessScope.Acquire(mutex))throw new IOException("Test lease unavailable.");
        try{File.WriteAllText(ready,"ready");Console.ReadLine();}finally{mutex.ReleaseMutex();}
    }
    internal static void Run(string root,Action<bool,string> check)
    {
        if(Directory.Exists(root))throw new IOException("Fresh test directory required.");
        Directory.CreateDirectory(root);
        string source=Path.Combine(root,"source");Directory.CreateDirectory(source);
        byte[] expected=RandomNumberGenerator.GetBytes(2049);File.WriteAllBytes(Path.Combine(source,"test.bin"),expected);
        var secret=new JobSecrets(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),"","");
        string storeRoot=Path.Combine(root,"settings");var store=new StudioStore(storeRoot);
        var profile=new BackupProfile{Name="Synthetic background check",Source=source,Repository=Path.Combine(root,"vault"),AtBoot=true,ProtectedSecrets=WindowsSecrets.Protect(secret)};
        store.Data.Profiles.Add(profile);store.Save();
        string before=File.ReadAllText(Path.Combine(storeRoot,"settings.json"));
        string ready=Path.Combine(root,"lease-ready");
        var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true};
        start.ArgumentList.Add("--background-lease");start.ArgumentList.Add(storeRoot);start.ArgumentList.Add(ready);
        using(var child=Process.Start(start)!)
        {
            try
            {
                var clock=Stopwatch.StartNew();while(!File.Exists(ready)&&!child.HasExited&&clock.Elapsed<TimeSpan.FromSeconds(15))Thread.Sleep(50);
                check(File.Exists(ready),"independent process holds shared lease");
                check(BackgroundCopies.RunOnce(storeRoot,bootForTest:"boot1")==0,"background runner skips occupied GUI settings");
                check(before==File.ReadAllText(Path.Combine(storeRoot,"settings.json")),"occupied profile/history remains byte-identical");
                check(!Directory.Exists(profile.Repository),"occupied runner does not start a backup");
            }
            finally{child.StandardInput.WriteLine();child.StandardInput.Close();if(!child.WaitForExit(15000))throw new IOException("Test lease child did not exit.");}
        }
        check(BackgroundCopies.RunOnce(storeRoot,bootForTest:"boot1")==0,"headless scheduled backup completes");
        store=new StudioStore(storeRoot);var saved=store.Data.Profiles.Single();
        check(store.Data.History.Count==1&&store.Data.History[0].State==RunState.Success&&saved.LastBoot=="boot1","successful job and boot identity persisted");
        check(!File.ReadAllText(Path.Combine(storeRoot,"settings.json")).Contains(secret.VaultPassword),"headless settings preserve DPAPI protection");
        using(var vault=LocalEncryptedVault.Open(saved.Repository,secret.VaultPassword))
        {string restored=Path.Combine(root,"restored");vault.RestoreSnapshot(saved.LastSnapshot!,restored);check(File.ReadAllBytes(Path.Combine(restored,"test.bin")).SequenceEqual(expected),"headless backup restores exact bytes");}
        check(BackgroundCopies.RunOnce(storeRoot,bootForTest:"boot1")==0&&new StudioStore(storeRoot).Data.History.Count==1,"repeat task does not duplicate same boot");
        check(BackgroundCopies.RunOnce(storeRoot,bootForTest:"boot2")==0&&new StudioStore(storeRoot).Data.History.Count==2,"next boot executes opted-in profile");
        store=new StudioStore(storeRoot);store.Data.Paused=true;store.Save();
        check(BackgroundCopies.RunOnce(storeRoot,bootForTest:"boot3")==0&&new StudioStore(storeRoot).Data.History.Count==2,"pause suppresses boot copy");
        check(BackgroundCopies.ReadState(storeRoot)?.State=="Paused","paused status is reported honestly");
        store=new StudioStore(storeRoot);store.Data.Paused=false;store.Data.Profiles[0].ProtectedSecrets="corrupted";store.Save();
        check(BackgroundCopies.RunOnce(storeRoot,bootForTest:"boot3")==1,"unavailable DPAPI secrets fail without prompting");
        check(new StudioStore(storeRoot).Data.History.Last().State==RunState.Failed&&BackgroundCopies.ReadState(storeRoot)?.State=="Failed","credential failure is not reported as success");
        check(BackgroundCopies.RunOnce(storeRoot,bootForTest:"boot3")==0&&new StudioStore(storeRoot).Data.History.Count==3,"credential error does not repeat on every polling tick");
        check(BootIdentity.Read()==BootIdentity.Read(),"native boot identifier stable across independent queries");
        string command=ScheduledCopies.Arguments(Path.Combine(root,"with space"));
        check(command==BackgroundCopies.Switch+" \""+Path.Combine(root,"with space")+"\"","task quotes settings path");
        bool rejected=false;try{ScheduledCopies.Arguments(@"\\server\settings");}catch(IOException){rejected=true;}
        check(rejected,"unattended settings cannot be a network path");
        using var settings=new ScheduledCopiesWindow(storeRoot);
        check(Work9Scenarios.All(settings).OfType<TextBox>().Single(c=>c.Name=="BackgroundWindowsPassword").UseSystemPasswordChar,"Windows account password is masked in setup");
        using var overview=new StudioWindow(store,new JobEngine(store),true);
        overview.ShowPage("Pulpit");
        check(Work9Scenarios.All(overview).OfType<Label>().Any(c=>c.Text.Contains("Po uruchomieniu komputera")),"boot-only profile is shown as automatic on the real overview");
        Console.WriteLine("BACKGROUND_COPIES=PASS (cross-process exclusion, real encrypted local backup/restore, boot deduplication, pause and credential failure; no task registered on host)");
    }
}
