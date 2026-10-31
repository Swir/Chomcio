using ChomcioRecovery.Core;
using ChomcioRecovery.Desktop;
using ChomcioRecovery.SystemImages;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text;
using System.Runtime.InteropServices;

internal static class InstalledBackgroundProbe
{
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeNameForVolumeMountPoint(string root,StringBuilder volume,int length);
    private sealed record Input(string Operation,string PlanId,string ProbeId,string WindowsPassword);
    internal static int Run(string pipeName)
    {
        try
        {
            using var identity=WindowsIdentity.GetCurrent();
            if(Environment.MachineName!="CHOMCIOTEST"||!identity.Name.EndsWith("\\ChomcioImageTest",StringComparison.OrdinalIgnoreCase)||
                new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)||!pipeName.StartsWith("ChomcioLab_",StringComparison.Ordinal)||
                !Guid.TryParseExact(pipeName[11..],"N",out _))return 2;
            using var pipe=new NamedPipeClientStream(".",pipeName,PipeDirection.InOut,PipeOptions.None,TokenImpersonationLevel.Impersonation);
            pipe.Connect(30000);
            using var reader=new StreamReader(pipe,leaveOpen:true);using var writer=new StreamWriter(pipe,leaveOpen:true){AutoFlush=true};
            // Windows exposes the client's pipe identity only after its first write.
            // The server authenticates this greeting before sending credentials.
            writer.WriteLine("READY");
            string line=reader.ReadLine()??"";
            if(line.Length is 0 or >16384)return 2;
            var input=JsonSerializer.Deserialize<Input>(line)??throw new InvalidDataException();line="";
            if(!BrokerFiles.IsId(input.PlanId)||!BrokerFiles.IsId(input.ProbeId))return 2;
            var plan=BrokerFiles.Read<ImagePlan>(Path.Combine(BrokerFiles.PlanDirectory(input.PlanId),"plan.json"));
            BrokerFiles.RequireProtected(Path.Combine(BrokerFiles.PlanDirectory(input.PlanId),"plan.json"));BrokerFiles.Validate(plan);
            if(plan.OwnerSid!=identity.User!.Value)return 2;
            var target=new StringBuilder(64);
            if(!GetVolumeNameForVolumeMountPoint(@"T:\",target,target.Capacity)||!target.ToString().Equals(plan.TargetVolume,StringComparison.OrdinalIgnoreCase))return 2;
            string root=Path.Combine(@"T:\ChomcioRecoveryCache",plan.PlanId,"qualification","background-"+input.ProbeId);
            string settings=Path.Combine(root,"settings");
            BrokerFiles.RejectLinks(root);
            if(input.Operation=="Provision")
            {
                if(Directory.Exists(root))throw new IOException("Fresh qualification required.");
                Directory.CreateDirectory(root);string source=Path.Combine(root,"source");Directory.CreateDirectory(source);
                File.WriteAllText(Path.Combine(source,"note.txt"),"Chomcio synthetic unattended qualification");
                File.WriteAllBytes(Path.Combine(source,"bytes.bin"),RandomNumberGenerator.GetBytes(2049));
                var secret=new JobSecrets(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),"","");
                var store=new StudioStore(settings);
                store.Data.Profiles.Add(new(){Name="Synthetic before-logon check",Source=source,Repository=Path.Combine(root,"vault"),AtBoot=true,Daily=true,DailyMinute=0,ProtectedSecrets=WindowsSecrets.Protect(secret)});store.Save();
                ScheduledCopies.Register(settings,Path.Combine(AppContext.BaseDirectory,"ChomcioRecovery.exe"),input.WindowsPassword);
                input=input with{WindowsPassword=""};
                File.WriteAllText(Path.Combine(root,"provision.json"),JsonSerializer.Serialize(new{pass=true,standardUser=true,sessionId=Process.GetCurrentProcess().SessionId,taskName=ScheduledCopies.Name(settings),taskEnabled=ScheduledCopies.IsEnabled(settings),nativeCaptureRequested=false,timeUtc=DateTimeOffset.UtcNow}));
            }
            else if(input.Operation is "Verify" or "VerifyAndRemove")
            {
                using var mutex=StudioProcessScope.Create(settings);
                if(!StudioProcessScope.Acquire(mutex))throw new IOException("Background copy is still running.");
                try
                {
                    var store=new StudioStore(settings);var profile=store.Data.Profiles.Single();
                    var success=store.Data.History.Where(h=>h.State==RunState.Success).ToArray();
                    if(success.Length==0||store.Data.History.Any(h=>h.State!=RunState.Success))throw new IOException("Native background result is not success.");
                    var secrets=WindowsSecrets.Unprotect(profile.ProtectedSecrets!);
                    using var vault=LocalEncryptedVault.Open(profile.Repository,secrets.VaultPassword);
                    string restored=Path.Combine(root,"restore-"+success.Length);vault.RestoreSnapshot(profile.LastSnapshot!,restored);
                    foreach(string name in new[]{"note.txt","bytes.bin"})
                        if(!File.ReadAllBytes(Path.Combine(profile.Source,name)).SequenceEqual(File.ReadAllBytes(Path.Combine(restored,name))))throw new IOException("Native restored bytes mismatch.");
                    bool removed=false;if(input.Operation=="VerifyAndRemove"){ScheduledCopies.Remove(settings);removed=!ScheduledCopies.IsEnabled(settings);}
                    File.WriteAllText(Path.Combine(root,"verify-"+success.Length+".json"),JsonSerializer.Serialize(new{pass=true,standardUser=true,sessionId=Process.GetCurrentProcess().SessionId,successes=success.Length,profile.LastBoot,allSnapshots=success.Select(h=>h.Snapshot).ToArray(),restoredFiles=2,bytesEqual=true,taskRemoved=removed,nativeCaptureRequested=false,timeUtc=DateTimeOffset.UtcNow}));
                }
                finally{mutex.ReleaseMutex();}
            }
            else return 2;
            writer.WriteLine("PASS");return 0;
        }
        catch(Exception e){Console.Error.WriteLine("BACKGROUND_NATIVE_PROBE_FAILED "+e.GetType().Name+" "+e.HResult);return 1;}
    }
}
