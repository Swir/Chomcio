using System.Security.Principal;
using ChomcioRecovery.SystemImages;

namespace ChomcioRecovery.Desktop;

internal sealed class InstalledSystemImageCapture : ISystemImageCapture
{
    private static ImagePlan ReadPlan(string planId)
    {
        string directory=BrokerFiles.PlanDirectory(planId),planPath=Path.Combine(directory,"plan.json");
        if(!File.Exists(planPath))throw new SystemImageCaptureUnavailableException();
        BrokerFiles.RequireProtected(planPath);
        var plan=BrokerFiles.Read<ImagePlan>(planPath);BrokerFiles.Validate(plan);
        if(plan.PlanId!=planId||plan.OwnerSid!=WindowsIdentity.GetCurrent().User!.Value)
            throw new UnauthorizedAccessException("Ten plan Windows należy do innego użytkownika.");
        return plan;
    }
    private static void CheckCache(ImagePlan plan)
    {
        string cache=BrokerFiles.ClientDirectory(plan);
        BrokerFiles.RequireProtected(plan.TargetVolume);
        BrokerFiles.RequireProtected(Path.GetDirectoryName(cache)!);
        BrokerFiles.RejectLinks(cache);
        if(!Directory.Exists(cache))throw new IOException("Miejsce robocze obrazu jest niedostępne. Podłącz zatwierdzony dysk kopii.");
    }
    public void ValidateStorage(BackupProfile profile)
    {
        var plan=ReadPlan(profile.SystemImagePlanId!);
        SystemImageStorage.ValidateApproved(profile,plan);
        CheckCache(plan);
    }
    public async Task CaptureAsync(SystemImageCaptureRequest request,CancellationToken token)
    {
        var plan=ReadPlan(request.PlanId);
        string directory=BrokerFiles.PlanDirectory(request.PlanId);
        if(!BrokerFiles.IsId(request.CaptureId)||request.RequestedUtc==default)
            throw new InvalidDataException("Niepoprawne żądanie obrazu Windows.");
        CheckCache(plan);
        if(!Path.IsPathFullyQualified(request.OutputDirectory))throw new InvalidDataException("Niepoprawne miejsce obrazu Windows.");
        string output=Path.GetFullPath(request.OutputDirectory);
        string? profileDirectory=Path.GetDirectoryName(output),images=profileDirectory is null?null:Path.GetDirectoryName(profileDirectory);
        if(Path.GetFileName(output)!=request.CaptureId||!BrokerFiles.IsId(Path.GetFileName(profileDirectory))||images is null||
            !SystemImageStorage.SamePath(images,Path.Combine(BrokerFiles.ClientDirectory(plan),"images")))
            throw new InvalidDataException("Obraz musi pozostać w zatwierdzonym miejscu poza dyskiem Windows.");
        BrokerFiles.RejectLinks(output);
        CheckHealth();
        // The privileged process never receives OutputDirectory, credentials,
        // encryption keys, executable names, command lines or scripts.
        string requestPath=Path.Combine(directory,"requests",request.CaptureId+".json");
        var job=new CaptureRequest(1,request.CaptureId,request.RequestedUtc);
        token.ThrowIfCancellationRequested();
        if(File.Exists(requestPath))
        {
            if(BrokerFiles.Read<CaptureRequest>(requestPath)!=job)throw new InvalidDataException("Zmieniono zapisane żądanie obrazu.");
        }
        else BrokerFiles.Save(requestPath,job);
        string statePath=Path.Combine(directory,"states",request.CaptureId+".json");
        while(true)
        {
            token.ThrowIfCancellationRequested();
            if(File.Exists(statePath))
            {
                var state=BrokerFiles.ReadProtected<CaptureState>(statePath);
                if(state.Version!=1||state.CaptureId!=job.CaptureId||state.RequestedUtc!=job.RequestedUtc)
                    throw new InvalidDataException("Potwierdzenie modułu systemowego nie pasuje do zadania.");
                if(state.Stage is "Failed" or "Interrupted")
                    throw new SystemImageCaptureFailedException(state.Stage=="Interrupted",state.NativeExitCode);
                if(state.Stage=="Complete")
                {
                    if(state.NativeExitCode!=0||state.CompletedUtc is null)throw new InvalidDataException("Niepełne potwierdzenie Windows.");
                    await ExportAsync(plan,request,token);return;
                }
            }
            CheckHealth();
            await Task.Delay(TimeSpan.FromSeconds(2),token);
        }
    }
    private static void CheckHealth()
    {
        string path=Path.Combine(BrokerFiles.Root,"health.json");
        BrokerHealth health;
        try{health=BrokerFiles.ReadProtected<BrokerHealth>(path);}
        catch(FileNotFoundException){throw new SystemImageCaptureUnavailableException();}
        if(health.Version!=1||health.TimeUtc<DateTimeOffset.UtcNow.AddMinutes(-2)||health.TimeUtc>DateTimeOffset.UtcNow.AddMinutes(1))
            throw new SystemImageCaptureUnavailableException();
    }
    private static async Task ExportAsync(ImagePlan plan,SystemImageCaptureRequest request,CancellationToken token)
    {
        string source=Path.Combine(BrokerFiles.CaptureDirectory(plan,request.CaptureId),"bundle");
        BrokerFiles.RequireProtected(source);
        var pending=new PendingSystemImage(request.PlanId,request.CaptureId,request.RequestedUtc);
        using var proof=await SystemImageLease.OpenAsync(source,pending,token);
        pending.Proof=proof.Proof;
        if(Directory.Exists(request.OutputDirectory))
        {
            using var existing=await SystemImageLease.OpenAsync(request.OutputDirectory,pending,token);return;
        }
        StudioStore.RejectLinks(request.OutputDirectory);
        string parent=Path.GetDirectoryName(request.OutputDirectory)!;Directory.CreateDirectory(parent);
        string stage=Path.Combine(parent,"export-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(stage);
        foreach(string name in new[]{SystemImageLease.ArchiveName,SystemImageLease.ReceiptName})
        {
            string file=Path.Combine(source,name);BrokerFiles.RequireProtected(file);
            using var input=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.Read,1024*1024,FileOptions.Asynchronous);
            using var output=new FileStream(Path.Combine(stage,name),FileMode.CreateNew,FileAccess.Write,FileShare.None,1024*1024,FileOptions.Asynchronous);
            await input.CopyToAsync(output,token);output.Flush(true);
        }
        using(var exported=await SystemImageLease.OpenAsync(stage,pending,token)){}
        token.ThrowIfCancellationRequested();
        Directory.Move(stage,request.OutputDirectory);
    }
}
