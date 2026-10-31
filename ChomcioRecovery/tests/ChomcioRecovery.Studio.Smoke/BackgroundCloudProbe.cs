using ChomcioRecovery.Desktop;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

// Explicit, small live qualification. Never part of Test-Standard and never shipped.
// The expected test account is supplied on stdin, not embedded in sources/reports.
internal static class BackgroundCloudProbe
{
    internal static int Run(string root)
    {
        try
        {
            root=Path.GetFullPath(root);
            if(!Console.IsInputRedirected||Directory.Exists(root))return 2;
            string expectedAccount=Console.ReadLine()??"";
            var account=StudioCredentials.Account(new StudioStore(StudioStore.DefaultRoot));
            if(expectedAccount.Length is 0 or >256||account is null||!account.CloudLogin.Equals(expectedAccount,StringComparison.OrdinalIgnoreCase))return 2;
            Directory.CreateDirectory(root);
            string source=Path.Combine(root,"source");Directory.CreateDirectory(source);
            File.WriteAllText(Path.Combine(source,"note.txt"),"Synthetic unattended Chomikuj qualification");
            File.WriteAllBytes(Path.Combine(source,"bytes.bin"),RandomNumberGenerator.GetBytes(2049));
            var secrets=account with{VaultPassword=VaultKeys.Generate(),FolderPassword=VaultKeys.Generate()};
            string settings=Path.Combine(root,"settings");var store=new StudioStore(settings);
            store.Data.Profiles.Add(new(){Name="Synthetic background cloud check",Source=source,Repository=Path.Combine(root,"vault"),Destination=BackupDestination.Chomikuj,AtBoot=true,Daily=true,DailyMinute=0,CloudDateFolders=true,ProtectCloudFolder=true,ProtectedSecrets=WindowsSecrets.Protect(secrets)});store.Save();
            void Execute()
            {
                var info=new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory,"ChomcioRecovery.exe")){UseShellExecute=false,CreateNoWindow=true};
                info.ArgumentList.Add(BackgroundCopies.Switch);info.ArgumentList.Add(settings);
                using var child=Process.Start(info)??throw new IOException("Runner did not start.");
                if(!child.WaitForExit(180000))throw new IOException("Runner remains active; inspect before retry. Do not terminate writing.");
                if(child.ExitCode!=0)throw new IOException("Cloud runner did not succeed; preserve history and pending copy.");
            }
            Console.WriteLine("BACKGROUND_LIVE_UPLOAD_STARTED (synthetic files only)");
            Execute();
            store=new StudioStore(settings);var profile=store.Data.Profiles.Single();
            if(store.Data.History.Count!=1||store.Data.History[0].State!=RunState.Success||!profile.RemoteFolderHasConfirmedCopy)throw new IOException("Cloud copy not confirmed.");
            Execute();
            if(new StudioStore(settings).Data.History.Count!=1)throw new IOException("Polling duplicated copy.");
            using var restore=new RestoreSession(new StudioStore(Path.Combine(root,"independent")),profile,WindowsSecrets.Unprotect(profile.ProtectedSecrets!));
            var points=restore.ListAsync(true,default).GetAwaiter().GetResult();
            if(!points.Any(p=>p.Id==profile.LastSnapshot))throw new IOException("Cloud point absent.");
            string target=Path.Combine(root,"restored");
            restore.RestoreAsync(profile.LastSnapshot!,true,target,null,null,default).GetAwaiter().GetResult();
            foreach(string name in new[]{"note.txt","bytes.bin"})
                if(!File.ReadAllBytes(Path.Combine(source,name)).SequenceEqual(File.ReadAllBytes(Path.Combine(target,name))))throw new IOException("Independent cloud restore differs.");
            File.WriteAllText(Path.Combine(root,"result.json"),JsonSerializer.Serialize(new{pass=true,timeUtc=DateTimeOffset.UtcNow,files=2,bytes=Directory.GetFiles(source).Sum(f=>new FileInfo(f).Length),actualPublishedExe=true,headless=true,independentCloudDownload=true,bytesEqual=true,sameBootDuplicates=0,dateNamedProtectedFolder=true,windowsImage=false,beforeLogon=false,hostTaskRegistered=false}));
            Console.WriteLine("BACKGROUND_LIVE_CHOMIKUJ=PASS (published EXE, encrypted upload, protected dated folder, independent cloud restore; no Windows image and no before-logon cloud claim)");return 0;
        }
        catch(Exception e){Console.Error.WriteLine("BACKGROUND_LIVE_FAILED "+e.GetType().Name+" "+e.HResult);return 1;}
    }
}
