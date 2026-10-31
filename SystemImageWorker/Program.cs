using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Principal;

namespace ChomcioRecovery.SystemImages;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        try
        {
            if(args.Length==4&&args[0]=="--install")return PackageInstaller.Install(args[1],args[2],args[3]);
            if(args.Length==1&&args[0]=="--check-package"){using var package=WorkerPackage.Open(AppContext.BaseDirectory);Console.WriteLine("IMAGE_WORKER_PACKAGE=PASS");return 0;}
            if(args.Length!=1||args[0] is not ("--serve" or "--probe"))return 2;
            if(!WindowsIdentity.GetCurrent().User!.IsWellKnown(WellKnownSidType.LocalSystemSid))return 3;
            if(!Path.GetDirectoryName(Environment.ProcessPath)!.Equals(BrokerFiles.InstallRoot,StringComparison.OrdinalIgnoreCase))return 4;
            BrokerFiles.RequireProtected(BrokerFiles.InstallRoot);
            foreach(string file in Directory.GetFiles(BrokerFiles.InstallRoot))BrokerFiles.RequireProtected(file);
            BrokerFiles.RequireProtected(BrokerFiles.Root);
            using var exclusive=new FileStream(Path.Combine(BrokerFiles.Root,"worker.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
            var healthGate=new object();
            using var heartbeat=new Timer(_=>
            {
                lock(healthGate)
                {
                    try{BrokerFiles.Save(Path.Combine(BrokerFiles.Root,"health.json"),new BrokerHealth(1,DateTimeOffset.UtcNow,Environment.ProcessId),true);}
                    catch(IOException){}catch(UnauthorizedAccessException){}
                }
            },null,TimeSpan.Zero,TimeSpan.FromSeconds(30));
            do
            {
                foreach(string directory in Directory.GetDirectories(Path.Combine(BrokerFiles.Root,"plans")))
                {
                    BrokerFiles.RequireProtected(directory);
                    string planPath=Path.Combine(directory,"plan.json");BrokerFiles.RequireProtected(planPath);
                    var plan=BrokerFiles.Read<ImagePlan>(planPath);BrokerFiles.Validate(plan);
                    if(Path.GetFileName(directory)!=plan.PlanId)throw new InvalidDataException("Plan identity mismatch.");
                    if(args[0]=="--probe")
                    {
                        NativeVolumes.Check(plan);
                        BrokerFiles.Save(Path.Combine(directory,"probe.json"),new{pass=true,systemIdentity=true,protectedInstall=true,protectedPlan=true,
                            approvedVolumeValidated=true,nativeBackupStarted=false,timeUtc=DateTimeOffset.UtcNow},true);
                        continue;
                    }
                    await Scan(plan,directory);
                }
                if(args[0]=="--probe")return 0;
                await Task.Delay(TimeSpan.FromSeconds(15));
            }while(true);
        }
        catch(InstallerFailure ex){return ex.Code;}
        catch(Exception ex)
        {
            // No paths, request data, native command output or secrets in console.
            Console.Error.WriteLine("IMAGE_WORKER_STOPPED "+ex.GetType().Name);return 1;
        }
    }

    private static async Task Scan(ImagePlan plan,string directory)
    {
        string inbox=Path.Combine(directory,"requests");BrokerFiles.RejectLinks(inbox);
        string states=Path.Combine(directory,"states");BrokerFiles.RequireProtected(states);
        foreach(string path in Directory.GetFiles(inbox,"*.json").Order(StringComparer.Ordinal))
        {
            string id=Path.GetFileNameWithoutExtension(path);
            if(!BrokerFiles.IsId(id))continue;
            CaptureRequest request;
            try{request=BrokerFiles.Read<CaptureRequest>(path);}
            catch(Exception e)when(e is IOException or System.Text.Json.JsonException or UnauthorizedAccessException){continue;}
            if(request.Version!=1||request.CaptureId!=id||request.RequestedUtc==default||request.RequestedUtc>DateTimeOffset.UtcNow.AddMinutes(5))continue;
            string statePath=Path.Combine(states,id+".json");
            CaptureState state;
            if(File.Exists(statePath))
            {
                BrokerFiles.RequireProtected(statePath);state=BrokerFiles.Read<CaptureState>(statePath);
                if(state.CaptureId!=id||state.RequestedUtc!=request.RequestedUtc)continue;
                if(state.Stage is "Complete" or "Failed" or "Interrupted")continue;
            }
            else
            {
                state=new(1,id,request.RequestedUtc,"Accepted");
                BrokerFiles.Save(statePath,state); // Durable acceptance precedes ALL native work.
            }
            try{await Execute(plan,directory,statePath,state);}
            catch(Exception e)
            {
                // Preserve native logs and partial data. Never reset a request to
                // Accepted after an uncertain launch and never kill a backup writer.
                var latest=BrokerFiles.Read<CaptureState>(statePath);
                // Protected diagnostics contain no credentials or encryption key;
                // retain the exact native I/O site without weakening the guard.
                try{BrokerFiles.Save(Path.Combine(directory,"failure-"+id+".txt"),new{errorType=e.GetType().Name,e.HResult,e.Message,
                    methods=new StackTrace(e,false).GetFrames()?.Select(f=>f.GetMethod()?.DeclaringType?.FullName+"."+f.GetMethod()?.Name).ToArray(),
                    stage=latest.Stage,timeUtc=DateTimeOffset.UtcNow},true);}catch(IOException){}catch(UnauthorizedAccessException){}
                // Logging/state I/O can fail after Process.Start. A disposed
                // Process object does not stop wbadmin: keep its uncertain writer
                // fenced off so the next request cannot start a second capture.
                BrokerFiles.Save(statePath,BrokerFiles.RecordFailure(latest,e.GetType().Name+": "+e.Message),true);
            }
        }
    }

    private static async Task Execute(ImagePlan plan,string directory,string statePath,CaptureState state)
    {
        string captureRoot=BrokerFiles.CaptureDirectory(plan,state.CaptureId);
        string image=Path.Combine(plan.TargetVolume,"WindowsImageBackup");
        string currentPath=Path.Combine(directory,"current-native.json");
        if(state.Stage=="Accepted")
        {
            NativeVolumes.Check(plan);
            foreach(string otherPlan in Directory.GetDirectories(Path.Combine(BrokerFiles.Root,"plans")))
            foreach(string otherState in Directory.GetFiles(Path.Combine(otherPlan,"states"),"*.json"))
            {
                BrokerFiles.RequireProtected(otherState);
                if(BrokerFiles.Read<CaptureState>(otherState).Stage is "Launching" or "NativeRunning" or "Interrupted")
                    throw new IOException("An earlier native writer has not been reconciled.");
            }
            if(Process.GetProcessesByName("wbadmin").Length!=0)throw new IOException("Another native backup tool is running.");
            if(Directory.Exists(image))
            {
                // Only a completed image created by this protected plan can be
                // moved. An unknown WindowsImageBackup directory is never touched.
                BrokerFiles.RequireProtected(currentPath);
                var previous=BrokerFiles.Read<CaptureState>(currentPath);
                if(previous.Stage!="NativeComplete"||previous.NativeExitCode!=0||previous.CaptureId==state.CaptureId)
                    throw new IOException("Previous native image is not confirmed.");
                string oldStatePath=Path.Combine(directory,"states",previous.CaptureId+".json");
                BrokerFiles.RequireProtected(oldStatePath);
                if(BrokerFiles.Read<CaptureState>(oldStatePath).Stage!="Complete")throw new IOException("Previous image export is unfinished.");
                string preserved=Path.Combine(BrokerFiles.CaptureDirectory(plan,previous.CaptureId),"native");
                BrokerFiles.RequireProtected(Path.GetDirectoryName(preserved)!);
                if(Directory.Exists(preserved)||File.Exists(preserved))throw new IOException("Preserved image location already exists.");
                BrokerFiles.RejectLinks(image);
                Directory.Move(image,preserved); // Both paths derive from pinned approved volume and IDs.
            }
            if(Directory.Exists(captureRoot))throw new IOException("Capture output already exists without an accepted native job.");
            BrokerFiles.ProtectDirectory(Path.Combine(plan.TargetVolume,"ChomcioRecoveryImages"),plan.OwnerSid);
            BrokerFiles.ProtectDirectory(Path.GetDirectoryName(captureRoot)!,plan.OwnerSid);
            BrokerFiles.ProtectDirectory(captureRoot,plan.OwnerSid);
            state=state with{Stage="Launching"};BrokerFiles.Save(statePath,state,true);
            var info=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"wbadmin.exe"))
            {UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
            foreach(string arg in new[]{"start","backup","-backupTarget:"+plan.TargetVolume.TrimEnd('\\'),
                "-include:"+plan.SourceVolume,"-allCritical","-vssCopy","-quiet"})info.ArgumentList.Add(arg);
            using var process=Process.Start(info)??throw new IOException("Native backup did not start.");
            state=state with{Stage="NativeRunning",NativePid=process.Id,NativeStartUtc=process.StartTime.ToUniversalTime()};
            BrokerFiles.Save(statePath,state,true);
            // Concurrent bounded streaming avoids redirect deadlocks and unbounded
            // memory. Request cancellation never terminates this native process.
            using var output=new FileStream(Path.Combine(captureRoot,"wbadmin-output.log"),FileMode.CreateNew);
            using var error=new FileStream(Path.Combine(captureRoot,"wbadmin-error.log"),FileMode.CreateNew);
            await Task.WhenAll(process.StandardOutput.BaseStream.CopyToAsync(output),process.StandardError.BaseStream.CopyToAsync(error),process.WaitForExitAsync());
            output.Flush(true);error.Flush(true);
            state=state with{NativeExitCode=process.ExitCode,Stage=process.ExitCode==0?"NativeComplete":"Failed"};
            BrokerFiles.Save(statePath,state,true);
            if(process.ExitCode!=0)return;
            BrokerFiles.Save(currentPath,state,true);
        }
        else if(state.Stage is "Launching" or "NativeRunning")
        {
            // A service/process restart lost the exit receipt. Do not guess success,
            // launch a duplicate or force-stop a possibly still-writing wbengine.
            state=state with{Stage="Interrupted",Failure="NativeExitNotConfirmed"};
            BrokerFiles.Save(statePath,state,true);return;
        }
        if(state.Stage=="NativeComplete")
        {
            if(state.NativeExitCode!=0||!Directory.Exists(image))throw new IOException("Native image missing.");
            BrokerFiles.RequireProtected(captureRoot);
            await Pack(plan,state,captureRoot,image);
            BrokerFiles.Save(statePath,state with{Stage="Complete",CompletedUtc=DateTimeOffset.UtcNow},true);
        }
    }

    private static async Task Pack(ImagePlan plan,CaptureState state,string root,string image)
    {
        string bundle=Path.Combine(root,"bundle");
        if(Directory.Exists(bundle))
        {
            BrokerFiles.RequireProtected(bundle);
            var receipt=BrokerFiles.Read<CaptureReceipt>(Path.Combine(bundle,"system-image.json"));
            if(receipt.CaptureId!=state.CaptureId||receipt.PlanId!=plan.PlanId||receipt.RequestedUtc!=state.RequestedUtc)
                throw new InvalidDataException("Existing export belongs to a different job.");
            using var input=OpenArchiveForHash(Path.Combine(bundle,"WindowsImageBackup.zip"));
            if(input.Length!=receipt.ArchiveBytes||Convert.ToHexString(await SHA256.HashDataAsync(input))!=receipt.ArchiveSha256)
                throw new InvalidDataException("Existing export changed.");
            return;
        }
        // Preserve an incomplete previous packing attempt; use a new stage without
        // touching native images or rerunning wbadmin.
        string stage=Path.Combine(root,"packing-"+Guid.NewGuid().ToString("N"));BrokerFiles.ProtectDirectory(stage,plan.OwnerSid);
        string archivePath=Path.Combine(stage,"WindowsImageBackup.zip");
        using var native=NativeImageFiles.OpenForPacking(plan,image);
        var files=native.Files;
        if(!files.Any(f=>f.EndsWith(".vhdx",StringComparison.OrdinalIgnoreCase)||f.EndsWith(".vhd",StringComparison.OrdinalIgnoreCase))||
            !files.Any(f=>f.Contains("\\Catalog\\",StringComparison.OrdinalIgnoreCase)))throw new IOException("Incomplete native image layout.");
        using(var output=new FileStream(archivePath,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None,1024*1024,FileOptions.SequentialScan))
        {
            using(var zip=new ZipArchive(output,ZipArchiveMode.Create,true))
                foreach(string file in files.Order(StringComparer.Ordinal))
                {
                    string name="WindowsImageBackup/"+Path.GetRelativePath(image,file).Replace('\\','/');
                    var input=native.StreamFor(file);
                    using var target=zip.CreateEntry(name,CompressionLevel.Optimal).Open();await input.CopyToAsync(target,1024*1024);
                }
            output.Flush(true);
        }
        string hash;long size;
        using(var input=OpenArchiveForHash(archivePath))
        {size=input.Length;hash=Convert.ToHexString(await SHA256.HashDataAsync(input));}
        BrokerFiles.Save(Path.Combine(stage,"system-image.json"),new CaptureReceipt(1,plan.PlanId,state.CaptureId,state.RequestedUtc,
            DateTimeOffset.UtcNow,0,true,true,size,hash));
        Directory.Move(stage,bundle);
    }

    // HashDataAsync reads in small blocks. A larger sequential stream buffer
    // prevents millions of 4 KiB guest-disk operations for a full Windows image.
    // Keep the same read-only/no-delete lease and full SHA256 verification.
    private static FileStream OpenArchiveForHash(string path)=>new(path,FileMode.Open,FileAccess.Read,FileShare.Read,
        1024*1024,FileOptions.Asynchronous|FileOptions.SequentialScan);
}
