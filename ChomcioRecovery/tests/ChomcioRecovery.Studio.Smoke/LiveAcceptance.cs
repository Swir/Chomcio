using ChomcioRecovery.Desktop;
using ChomcioRecovery.Core;
using System.Security.Cryptography;
using System.Text.Json;

internal static class LiveAcceptance
{
    private static int checks;
    private static void Check(bool value,string name){if(!value)throw new Exception("LIVE FAILED: "+name);checks++;Console.WriteLine("PASS "+name);}
    private static string ReadSecretLine()
    {
        if(Console.IsInputRedirected)return Console.ReadLine()??"";
        var text=new System.Text.StringBuilder();
        while(true){var key=Console.ReadKey(intercept:true);if(key.Key==ConsoleKey.Enter)return text.ToString();if(key.Key==ConsoleKey.Backspace){if(text.Length>0)text.Length--;}else if(!char.IsControl(key.KeyChar))text.Append(key.KeyChar);}
    }
    internal static async Task Run(string root,string mode)
    {
        root=Path.GetFullPath(root);
        if(mode=="create"&&Directory.Exists(root))throw new IOException("Live test needs a new directory.");
        Directory.CreateDirectory(root);
        if(mode=="inspect-folder-web"){await Work12CloudInspect.Run();return;}
        if(mode is "dated-upload" or "dated-restore"){await Work12Scenarios.Live(root,mode=="dated-restore");return;}
        if(mode is "protected-upload" or "protected-restore"){await Work12Scenarios.Live(root,mode=="protected-restore",true);return;}
        if(mode=="privacy-check"){await Work12Scenarios.Privacy(root);return;}
        if(mode=="new-pc-restore"){await Work12Scenarios.NewPc(root);return;}
        if(mode=="catalog-ui"){await Work12Scenarios.CatalogUi(root);return;}
        if(mode is "own-upload" or "own-restore"){await Work11Scenarios.Live(root,mode=="own-restore");return;}
        if(mode=="diagnose-user"){await Work10Diagnostics.Run(root);return;}
        if(mode=="diagnose-user-local"){await Work10Diagnostics.Run(root,true);return;}
        if(mode=="diagnose-fresh"){await Work10Diagnostics.Fresh(root);return;}
        if(mode=="diagnose-folder"){await Work10Diagnostics.FolderSchema();return;}
        if(mode=="resume-user-test"){await Work10Diagnostics.ResumeUserTest();return;}
        if(mode=="verify-user-test"){await Work10Diagnostics.VerifyUserTest(root);return;}
        var store=new StudioStore(Path.Combine(root,"store"));store.Data.Notifications=false;
        if(mode=="preflight-user")
        {
            var destination=new StudioStore(StudioStore.DefaultRoot);
            var method=typeof(LocalEncryptedVault).GetMethod("CaptureSourceInventory",System.Reflection.BindingFlags.Static|System.Reflection.BindingFlags.NonPublic)!;
            foreach(var profile in destination.Data.Profiles.Where(p=>p.Destination==BackupDestination.Chomikuj))
            {
                try
                {
                    var inventory=(System.Collections.IDictionary)method.Invoke(null,new object?[]{profile.Source,CancellationToken.None,null,true,true})!;
                    Console.WriteLine("USER_SOURCE_PREFLIGHT=PASS entries="+inventory.Count);
                }
                catch(System.Reflection.TargetInvocationException e)
                {
                    string message=e.InnerException?.Message??"";
                    string category=message.Contains("stream",StringComparison.OrdinalIgnoreCase)?"unsupported NTFS stream":message.Contains("metadata",StringComparison.OrdinalIgnoreCase)?"unsupported metadata":message.Contains("reparse",StringComparison.OrdinalIgnoreCase)?"unsupported link":e.InnerException?.GetType().Name??"unknown";
                    Console.WriteLine("USER_SOURCE_PREFLIGHT=FAIL category="+category);throw new IOException("Source preflight failed: "+category);
                }
            }
            return;
        }
        if(mode=="prepare-user-key")
        {
            var destination=new StudioStore(StudioStore.DefaultRoot);
            foreach(var profile in destination.Data.Profiles)
            {
                if(profile.ProtectedSecrets is null)continue;
                var saved=WindowsSecrets.Unprotect(profile.ProtectedSecrets);
                if(saved.VaultPassword.Length>=12||!VaultKeys.CanInitialize(profile))continue;
                var prepared=VaultKeys.Prepare(destination,profile,saved);
                Check(prepared.VaultPassword.Length==64,"never-created profile now has a protected generated recovery key; no files uploaded");
            }
            return;
        }
        if(mode=="ui")
        {
            if(store.Data.Profiles.Count!=0)throw new IOException("UI live test requires a new isolated store.");
            var account=StudioCredentials.Account(new StudioStore(StudioStore.DefaultRoot))??throw new IOException("Missing saved test account.");
            StudioCredentials.RememberAccount(store,account);
            string source=Path.Combine(root,"source");Directory.CreateDirectory(Path.Combine(source,"Zażółć gęślą","pusty folder"));
            File.WriteAllBytes(Path.Combine(source,"duży.bin"),RandomNumberGenerator.GetBytes(LocalEncryptedVault.ChunkBytes+137));
            File.WriteAllText(Path.Combine(source,"Zażółć gęślą","notatka.txt"),"Sztuczne dane — pierwsza wersja.");File.WriteAllBytes(Path.Combine(source,"pusty.txt"),Array.Empty<byte>());
            File.WriteAllText(Path.Combine(source,"Zażółć gęślą","notatka.txt")+":Zone.Identifier","[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.test/\r\n");
            var p=new BackupProfile{Name="WORK11 — rzeczywisty przycisk Chomikuj",Source=source,Repository=Path.Combine(root,"vault"),Destination=BackupDestination.Chomikuj,ProtectedSecrets=WindowsSecrets.Protect(account with{VaultPassword="old-key"})};
            store.Data.Profiles.Add(p);store.Save();
            var engine=new JobEngine(store);string last="";
            engine.Changed+=()=>{if(last!=engine.Phase){last=engine.Phase;Console.WriteLine("STAGE "+last);}};
            using var window=new StudioWindow(store,engine,true);window.Opacity=0;window.ShowInTaskbar=false;window.Show();
            async Task<RunRecord> ClickUpload()
            {
                var done=new TaskCompletionSource<RunRecord>();
                void Finished(RunRecord record)=>done.TrySetResult(record);
                engine.Finished+=Finished;
                try
                {
                    var button=Work9Scenarios.All(window).OfType<Button>().Single(c=>c.Name=="RunBackup_"+p.Id);
                    Check(button.Visible&&button.Text=="Wyślij na Chomikuj","real Chomikuj upload button is visible on startup page");
                    button.PerformClick();return await done.Task.WaitAsync(TimeSpan.FromMinutes(5));
                }
                finally{engine.Finished-=Finished;}
            }
            var first=await ClickUpload();Check(first.State==RunState.Success,"main-screen button uploaded and read back first real cloud copy");
            File.WriteAllText(Path.Combine(source,"Zażółć gęślą","notatka.txt"),"Sztuczne dane — druga wersja.");
            // FileMode.Create replaces the stream set on Windows. Recreate the
            // synthetic download mark so BOTH versions exercise v3 restore.
            File.WriteAllText(Path.Combine(source,"Zażółć gęślą","notatka.txt")+":Zone.Identifier","[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.test/\r\n");
            var second=await ClickUpload();Check(second.State==RunState.Success&&second.Snapshot!=first.Snapshot,"same visible button created second real cloud version");
            Check(WindowsSecrets.Unprotect(p.ProtectedSecrets!).VaultPassword.Length==64,"legacy short key was replaced only before first vault creation");
            using(var verified=LocalEncryptedVault.Open(p.Repository,WindowsSecrets.Unprotect(p.ProtectedSecrets!).VaultPassword))
                Check(verified.ReadSnapshot(second.Snapshot!).Version==3,"real upload includes authenticated Windows Zone.Identifier metadata");
            using var image=new Bitmap(window.Width,window.Height);window.DrawToBitmap(image,new Rectangle(0,0,image.Width,image.Height));image.Save(Path.Combine(root,"LIVE_UI_CLOUD_PASS.png"));
            File.WriteAllText(Path.Combine(root,"LIVE_UI_UPLOAD_PASS.json"),JsonSerializer.Serialize(new{pass=true,checks,timeUtc=DateTimeOffset.UtcNow,profileId=p.Id,remoteFolder=p.RemoteFolderName,bytes=second.Bytes,files=second.Files}));
            Console.WriteLine("CHOMCIO_LIVE_UI_UPLOAD=PASS assertions="+checks);return;
        }
        if(mode=="remember")
        {
            var account=StudioCredentials.Account(store)??throw new IOException("Missing tested account.");
            var destination=new StudioStore(StudioStore.DefaultRoot);
            StudioCredentials.RememberAccount(destination,account);destination.Save();
            Check(StudioCredentials.Account(new StudioStore(destination.Root))==account,"tested account saved with DPAPI in application settings");return;
        }
        if(mode=="create")
        {
            Console.WriteLine("CREDENTIAL_INPUT_READY");
            string login=ReadSecretLine(),accountPassword=ReadSecretLine();
            if(login.Length==0||accountPassword.Length==0)throw new IOException("Missing interactive test credentials.");
            var secrets=new JobSecrets(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),login,accountPassword);
            StudioCredentials.RememberAccount(store,secrets);
            string source=Path.Combine(root,"source");Directory.CreateDirectory(Path.Combine(source,"Zażółć gęślą","pusty folder"));
            File.WriteAllBytes(Path.Combine(source,"duży.bin"),RandomNumberGenerator.GetBytes(LocalEncryptedVault.ChunkBytes+137));
            File.WriteAllText(Path.Combine(source,"Zażółć gęślą","notatka.txt"),"Sztuczne dane — pierwsza wersja.");File.WriteAllBytes(Path.Combine(source,"pusty.txt"),Array.Empty<byte>());
            var p=new BackupProfile{Name="WORK11 — test rzeczywistej chmury",Source=source,Repository=Path.Combine(root,"vault"),Destination=BackupDestination.Chomikuj,ProtectedSecrets=WindowsSecrets.Protect(secrets)};
            store.Data.Profiles.Add(p);store.Save();
            var engine=new JobEngine(store);string last="";engine.Changed+=()=>{if(engine.Phase!=last){last=engine.Phase;Console.WriteLine("STAGE "+last);}};
            var first=await engine.RunAsync(p,secrets,DateTimeOffset.Now);Check(first?.State==RunState.Success,"first encrypted live upload and downloaded byte comparison");
            File.WriteAllText(Path.Combine(source,"Zażółć gęślą","notatka.txt"),"Sztuczne dane — druga wersja.");
            var second=await engine.RunAsync(p,secrets,DateTimeOffset.Now);Check(second?.State==RunState.Success&&second.Snapshot!=first!.Snapshot,"second version preserves previous point");
            Console.WriteLine("LIVE_CREATE_PASS — restart required for independent restore");
        }
        else if(mode=="restore")
        {
            var p=store.Data.Profiles.First();var secrets=WindowsSecrets.Unprotect(p.ProtectedSecrets!);
            Check(StudioCredentials.Account(store)?.CloudLogin==secrets.CloudLogin,"account and vault passwords recovered after real process restart");
            string raw=File.ReadAllText(Path.Combine(store.Root,"settings.json"));Check(!raw.Contains(secrets.VaultPassword)&&!raw.Contains(secrets.CloudPassword),"no plaintext passwords in saved settings");
            using var session=new RestoreSession(store,p,secrets);var list=await session.ListAsync(true,default);Check(list.Count>=2,"cloud contains both committed points");
            var success=store.Data.History.Where(h=>h.State==RunState.Success&&h.ProfileId==p.Id).ToArray();
            var progress=new Progress<CloudProgress>(p=>Console.WriteLine("RESTORE "+p.Phase+" "+p.Completed+"/"+p.Total));
            string restored=Path.Combine(root,"restored-second");await session.RestoreAsync(success[^1].Snapshot!,true,restored,null,progress,default);
            foreach(string file in Directory.GetFiles(p.Source,"*",SearchOption.AllDirectories))
            {
                string relative=Path.GetRelativePath(p.Source,file);Check(SHA256.HashData(File.ReadAllBytes(file)).SequenceEqual(SHA256.HashData(File.ReadAllBytes(Path.Combine(restored,relative)))),"restored bytes: "+relative);
            }
            Check(Directory.Exists(Path.Combine(restored,"Zażółć gęślą","pusty folder")),"empty Unicode directory restored");
            var restoredMetadata=await session.PrepareAsync(success[^1].Snapshot!,true,null,default);
            if(p.Name.Contains("przycisk",StringComparison.Ordinal))
                Check(restoredMetadata.Version==3&&restoredMetadata.Files.Any(f=>f.ZoneIdentifierBase64 is not null),"cloud download retains v3 metadata schema");
            foreach(var file in restoredMetadata.Files.Where(f=>f.ZoneIdentifierBase64 is not null))
                Check(File.ReadAllBytes(Path.Combine(restored,file.Path.Replace('/',Path.DirectorySeparatorChar))+":Zone.Identifier").SequenceEqual(Convert.FromBase64String(file.ZoneIdentifierBase64!)),"download-origin mark restored byte for byte");
            string single=Path.Combine(root,"old-note.txt");await session.RestoreAsync(success[0].Snapshot!,true,single,"Zażółć gęślą/notatka.txt",progress,default);Check(File.ReadAllText(single)=="Sztuczne dane — pierwsza wersja.","single file from previous cloud version");
            if(p.Name.Contains("przycisk",StringComparison.Ordinal))
                Check(File.ReadAllBytes(single+":Zone.Identifier").SequenceEqual(File.ReadAllBytes(Path.Combine(p.Source,"Zażółć gęślą","notatka.txt")+":Zone.Identifier")),"older single cloud file retains download-origin mark");
            bool refused=false;try{await session.RestoreAsync(success[0].Snapshot!,true,single,"Zażółć gęślą/notatka.txt",null,default);}catch(IOException){refused=true;}
            Check(refused&&File.ReadAllText(single)=="Sztuczne dane — pierwsza wersja.","existing restored file never overwritten");
            File.WriteAllText(Path.Combine(root,"LIVE_RESTORE_PASS.json"),JsonSerializer.Serialize(new{pass=true,checks,timeUtc=DateTimeOffset.UtcNow,points=list.Count,files=Directory.GetFiles(restored,"*",SearchOption.AllDirectories).Length,bytes=Directory.GetFiles(restored,"*",SearchOption.AllDirectories).Sum(f=>new FileInfo(f).Length)},new JsonSerializerOptions{WriteIndented=true}));
            Console.WriteLine("CHOMCIO_LIVE_RESTART_RESTORE=PASS assertions="+checks);
        }
        else if(mode=="cancel")
        {
            var first=store.Data.Profiles.First();var secrets=WindowsSecrets.Unprotect(first.ProtectedSecrets!);
            var p=new BackupProfile{Name="WORK11 — przerwanie i wznowienie",Source=first.Source,Repository=Path.Combine(root,"cancel-vault"),Destination=BackupDestination.Chomikuj,ProtectedSecrets=WindowsSecrets.Protect(secrets)};store.Data.Profiles.Add(p);store.Save();
            var engine=new JobEngine(store);bool requested=false;
            engine.Changed+=()=>{if(engine.CompletedRecords>=1&&!requested&&engine.IsBusy){requested=true;engine.Cancel();}};
            var result=await engine.RunAsync(p,secrets,DateTimeOffset.Now);Check(requested&&result?.State==RunState.Cancelled&&p.PendingSnapshot is not null,"real upload cancelled after a verified cloud record, pending point saved");
            Console.WriteLine("LIVE_CANCEL_PASS — restart required for resume");
        }
        else if(mode=="resume")
        {
            var p=store.Data.Profiles.Last();var secrets=WindowsSecrets.Unprotect(p.ProtectedSecrets!);string? pending=p.PendingSnapshot;Check(pending is not null,"pending point survived process restart");
            var engine=new JobEngine(store);var result=await engine.RunAsync(p,secrets,DateTimeOffset.Now);Check(result?.State==RunState.Success&&result.Snapshot==pending&&p.PendingSnapshot is null,"same live upload resumed and verified after restart");
            using var session=new RestoreSession(store,p,secrets);await session.ListAsync(true,default);string target=Path.Combine(root,"resumed-restored");await session.RestoreAsync(p.LastSnapshot!,true,target,null,null,default);
            foreach(var f in Directory.GetFiles(p.Source,"*",SearchOption.AllDirectories))Check(SHA256.HashData(File.ReadAllBytes(f)).SequenceEqual(SHA256.HashData(File.ReadAllBytes(Path.Combine(target,Path.GetRelativePath(p.Source,f))))),"resumed copy exact bytes");
            var resumedMetadata=await session.PrepareAsync(p.LastSnapshot!,true,null,default);
            foreach(var file in resumedMetadata.Files.Where(f=>f.ZoneIdentifierBase64 is not null))
                Check(File.ReadAllBytes(Path.Combine(target,file.Path.Replace('/',Path.DirectorySeparatorChar))+":Zone.Identifier").SequenceEqual(Convert.FromBase64String(file.ZoneIdentifierBase64!)),"resumed copy retains download-origin mark");
            File.WriteAllText(Path.Combine(root,"LIVE_CANCEL_RESUME_PASS.json"),JsonSerializer.Serialize(new{pass=true,checks,timeUtc=DateTimeOffset.UtcNow}));Console.WriteLine("CHOMCIO_LIVE_CANCEL_RESTART_RESUME=PASS assertions="+checks);
        }
        else throw new ArgumentException("Unknown live test mode.");
    }
}
