using ChomcioRecovery.Desktop;
using ChomcioRecovery.SystemImages;
using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Security.Principal;

// Disposable offline lab only. Reopens the existing ordinary-user store/key and
// resumes its persisted capture. Never submits a fresh capture or resets state.
internal static class InstalledDailyImageResumeProbe
{
    [ThreadStatic] private static bool diagnosing;
    internal static int Run(string planId,string probeId,string captureId,bool recordRetryQualification=false)
    {
        if(Environment.MachineName!="CHOMCIOTEST"||!BrokerFiles.IsId(planId)||!BrokerFiles.IsId(probeId)||!BrokerFiles.IsId(captureId))return 2;
        using var identity=WindowsIdentity.GetCurrent();using var impersonation=WindowsIdentity.GetCurrent(true);
        if(impersonation is not null||new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))return 3;
        string planDirectory=BrokerFiles.PlanDirectory(planId),planPath=Path.Combine(planDirectory,"plan.json");
        BrokerFiles.RequireProtected(planPath);var plan=BrokerFiles.Read<ImagePlan>(planPath);BrokerFiles.Validate(plan);
        if(plan.OwnerSid!=identity.User!.Value)return 4;
        string qualification=Path.Combine(BrokerFiles.ClientDirectory(plan),"qualification",probeId);
        var store=new StudioStore(Path.Combine(qualification,"settings"));
        var profile=store.Data.Profiles.Single();
        if(profile.Content!=BackupContent.WindowsSystem||profile.Destination!=BackupDestination.Local||
            profile.PendingSystemImage?.CaptureId!=captureId||profile.PendingSystemImage.PlanId!=planId||
            Directory.GetFiles(Path.Combine(planDirectory,"requests"),"*.json").Length!=2)return 5;
        var prior=store.Data.History.ToArray();
        int expectedPrior=recordRetryQualification?3:2;
        if(prior.Length!=expectedPrior||prior[0].State!=RunState.Cancelled||prior.Skip(1).Any(p=>p.State!=RunState.Failed))return 6;
        string output=Path.Combine(qualification,recordRetryQualification?"resume-record-retry":"resume-diagnostic");
        if(Directory.Exists(output))return 7;
        Directory.CreateDirectory(output);
        int diagnosticCount=0;
        void Diagnose(object? sender,FirstChanceExceptionEventArgs args)
        {
            if(diagnosing||args.Exception is not IOException||Interlocked.Increment(ref diagnosticCount)>32)return;
            diagnosing=true;
            try
            {
                // Method names + numeric HRESULT only: never exception messages,
                // paths, account settings, passwords, keys or argument values.
                BrokerFiles.Save(Path.Combine(output,"io-"+Guid.NewGuid().ToString("N")+".json"),new{
                    errorType=args.Exception.GetType().Name,args.Exception.HResult,
                    methods=new StackTrace(1,false).GetFrames().Take(20).Select(f=>f.GetMethod()?.DeclaringType?.FullName+"."+f.GetMethod()?.Name).ToArray(),
                    timeUtc=DateTimeOffset.UtcNow});
            }
            catch(IOException){}catch(UnauthorizedAccessException){}
            finally{diagnosing=false;}
        }
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);Application.EnableVisualStyles();
        using var host=new Form{Opacity=0,ShowInTaskbar=false};
        var engine=new JobEngine(store);int result=1;
        using var monitor=new System.Windows.Forms.Timer{Interval=5000};
        var deadline=DateTimeOffset.UtcNow.AddHours(4);
        monitor.Tick+=(_,_)=>
        {
            if(DateTimeOffset.UtcNow>deadline)engine.Cancel();
            try{BrokerFiles.Save(Path.Combine(output,"progress.json"),new{phase=engine.Phase,captureId,
                bytes=engine.LocalProgress?.ProcessedBytes,total=engine.LocalProgress?.TotalBytes,timeUtc=DateTimeOffset.UtcNow},true);}
            catch(IOException){}catch(UnauthorizedAccessException){} // Observability cannot fail a backup.
        };
        host.Shown+=async(_,_)=>
        {
            AppDomain.CurrentDomain.FirstChanceException+=Diagnose;monitor.Start();
            try
            {
                var record=await engine.RunAsync(profile,WindowsSecrets.Unprotect(profile.ProtectedSecrets!),DateTimeOffset.Now);
                int requests=Directory.GetFiles(Path.Combine(planDirectory,"requests"),"*.json").Length;
                bool pass=record?.State==RunState.Success&&record.ImageCaptureId==captureId&&profile.PendingSystemImage is null&&
                    requests==2&&store.Data.History.Count==expectedPrior+1&&!SchedulePolicy.Due(profile,DateTimeOffset.Now,null,false);
                BrokerFiles.Save(Path.Combine(output,"result.json"),new{pass,captureId,nativeRequestCount=requests,
                    recordState=record?.State.ToString(),record?.FailureCode,record?.FailureStage,snapshot=record?.Snapshot,
                    sameDayDuplicateSuppressed=!SchedulePolicy.Due(profile,DateTimeOffset.Now,null,false),
                    priorCancelledAndFailedPreserved=store.Data.History.Take(expectedPrior).SequenceEqual(prior),recordRetryQualification,cloudUploaded=false,timeUtc=DateTimeOffset.UtcNow});
                result=pass?0:1;
            }
            catch(Exception e){BrokerFiles.Save(Path.Combine(output,"result.json"),new{pass=false,errorType=e.GetType().Name,e.HResult,timeUtc=DateTimeOffset.UtcNow});}
            finally{monitor.Stop();AppDomain.CurrentDomain.FirstChanceException-=Diagnose;host.Close();}
        };
        Application.Run(host);return result;
    }
}
