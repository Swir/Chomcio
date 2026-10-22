using ChomcioRecovery.Desktop;
using ChomcioRecovery.SystemImages;
using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;

// Explicit lab-only entry, never invoked by the normal smoke suite or shipped UI.
// Drives the real application timer, real DPAPI account and installed capture
// provider. The isolated guest has no network; this qualifies local scheduling,
// capture/cancel/resume/encryption, not cloud transport or an interactive logon.
internal static class InstalledDailyImageProbe
{
    internal static int Run(string planId,string probeId,string previousCaptureId)
    {
        string? output=null;
        try
        {
            if(Environment.MachineName!="CHOMCIOTEST"||!BrokerFiles.IsId(planId)||!BrokerFiles.IsId(probeId)||!BrokerFiles.IsId(previousCaptureId))
                throw new InvalidOperationException("Disposable lab only.");
            using var identity=WindowsIdentity.GetCurrent();
            using var impersonation=WindowsIdentity.GetCurrent(true);
            if(impersonation is not null||new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new UnauthorizedAccessException("Real ordinary-user process required.");
            string directory=BrokerFiles.PlanDirectory(planId),planPath=Path.Combine(directory,"plan.json");
            BrokerFiles.RequireProtected(planPath);var plan=BrokerFiles.Read<ImagePlan>(planPath);BrokerFiles.Validate(plan);
            if(plan.OwnerSid!=identity.User!.Value)throw new UnauthorizedAccessException("Wrong owner.");
            string states=Path.Combine(directory,"states"),requests=Path.Combine(directory,"requests");
            var oldState=BrokerFiles.Read<CaptureState>(Path.Combine(states,previousCaptureId+".json"));
            if(oldState.Stage!="Complete"||oldState.NativeExitCode!=0||Directory.GetFiles(requests,"*.json").Length!=1||
                Process.GetProcessesByName("wbadmin").Length!=0)throw new IOException("Previous capture must be complete and idle.");
            var now=DateTimeOffset.Now;
            if(now.Hour==23&&now.Minute>=57)throw new InvalidOperationException("Do not start across a calendar boundary.");
            string cache=BrokerFiles.ClientDirectory(plan);
            output=Path.Combine(cache,"qualification",probeId);BrokerFiles.RejectLinks(output);
            if(Directory.Exists(output))throw new IOException("Fresh qualification directory required.");
            Directory.CreateDirectory(output);
            var store=new StudioStore(Path.Combine(output,"settings"));
            var secrets=new JobSecrets(VaultKeys.Generate(),"","");
            var profile=new BackupProfile{Name="Dzienna kopia Windows - laboratorium",Content=BackupContent.WindowsSystem,
                Destination=BackupDestination.Local,Daily=true,AtLogon=false,DailyMinute=now.Hour*60+now.Minute+1,
                SystemImagePlanId=planId,SystemImageCacheRoot=cache,ProtectedSecrets=WindowsSecrets.Protect(secrets)};
            profile.Repository=SystemImageStorage.Repository(cache,profile.Id);
            new InstalledSystemImageCapture().ValidateStorage(profile);
            if(WindowsSecrets.Unprotect(profile.ProtectedSecrets)!=secrets)throw new IOException("DPAPI roundtrip failed.");
            store.Data.Notifications=false;store.Data.Profiles.Add(profile);store.Save();
            string folder=output;
            Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);Application.EnableVisualStyles();
            using var app=new StudioApplication(false,store.Root);
            app.Window.Hide();
            var live=app.Store.Data.Profiles.Single();
            bool cancelled=false,resumed=false,finishing=false;string? captureId=null;
            int result=1;DateTimeOffset lastProgress=DateTimeOffset.MinValue;
            object progressGate=new();
            void Progress(string stage)
            {
                lock(progressGate)
                {
                    BrokerFiles.Save(Path.Combine(folder,"progress.json"),new{stage,profileId=live.Id,captureId=live.PendingSystemImage?.CaptureId??captureId,
                        localPhase=app.Engine.Phase,bytes=app.Engine.LocalProgress?.ProcessedBytes,totalBytes=app.Engine.LocalProgress?.TotalBytes,
                        cancelled,resumed,historyCount=app.Store.Data.History.Count,timeUtc=DateTimeOffset.UtcNow},true);
                }
            }
            app.Engine.Changed+=()=>
            {
                if(DateTimeOffset.UtcNow-lastProgress<TimeSpan.FromSeconds(2))return;
                lastProgress=DateTimeOffset.UtcNow;Progress("APPLICATION_JOB_RUNNING");
            };
            using var monitor=new System.Windows.Forms.Timer{Interval=1000};
            var deadline=DateTimeOffset.UtcNow.AddHours(4);
            monitor.Tick+=async(_,_)=>
            {
                if(finishing)return;
                try
                {
                    if(DateTimeOffset.UtcNow>deadline)throw new TimeoutException("Bounded test ended; native writer must be reconciled, never killed.");
                    if(cancelled||live.PendingSystemImage is null)return;
                    string path=Path.Combine(states,live.PendingSystemImage.CaptureId+".json");
                    if(!File.Exists(path))return;
                    var current=BrokerFiles.Read<CaptureState>(path);
                    if(current.Stage!="NativeRunning")return;
                    captureId=current.CaptureId;
                    if(captureId==previousCaptureId||Directory.GetFiles(requests,"*.json").Length!=2)
                        throw new InvalidDataException("Expected exactly one new native request.");
                    cancelled=true;
                    Progress("CANCELLING_CLIENT_WHILE_NATIVE_IMAGE_IS_RUNNING");
                    app.Engine.Cancel();
                }
                catch(Exception e)
                {
                    finishing=true;monitor.Stop();app.Engine.Cancel();
                    BrokerFiles.Save(Path.Combine(folder,"result.json"),new{pass=false,errorType=e.GetType().Name,phase="monitor",timeUtc=DateTimeOffset.UtcNow},true);
                    await app.ExitAsync(false);
                }
            };
            app.Engine.Finished+=record=>
            {
                app.Window.BeginInvoke(async()=>
                {
                    if(finishing)return;
                    try
                    {
                        if(record.State==RunState.Cancelled&&cancelled&&!resumed)
                        {
                            if(live.PendingSystemImage?.CaptureId!=captureId||Directory.GetFiles(requests,"*.json").Length!=2)
                                throw new InvalidDataException("Cancellation lost the pending capture.");
                            if(Process.GetProcessesByName("wbadmin").Length!=1)
                                throw new InvalidDataException("Cancellation did not preserve the native writer.");
                            resumed=true;Progress("RESUMING_THE_SAME_NATIVE_CAPTURE");
                            await app.Engine.RunAsync(live,WindowsSecrets.Unprotect(live.ProtectedSecrets!),DateTimeOffset.Now);
                            return;
                        }
                        if(record.State!=RunState.Success||!cancelled||!resumed||record.ImageCaptureId!=captureId||live.PendingSystemImage is not null)
                            throw new InvalidDataException("Scheduled image did not complete with its original pending identity.");
                        int count=app.Store.Data.History.Count;
                        await app.CheckScheduleAsync();
                        if(count!=2||app.Store.Data.History.Count!=count||Directory.GetFiles(requests,"*.json").Length!=2||
                            SchedulePolicy.Due(live,DateTimeOffset.Now,null,false))throw new IOException("Same-day schedule duplicated work.");
                        if(BrokerFiles.Read<CaptureState>(Path.Combine(states,previousCaptureId+".json"))!=oldState||
                            BrokerFiles.Read<CaptureState>(Path.Combine(states,captureId+".json")).Stage!="Complete")
                            throw new InvalidDataException("Native capture receipts changed unexpectedly.");
                        finishing=true;monitor.Stop();
                        BrokerFiles.Save(Path.Combine(folder,"result.json"),new{pass=true,profileId=live.Id,captureId,previousCaptureId,
                            standardUserProcess=true,dailyApplicationTimer=true,currentUserDpapi=true,cancelDuringNativePreservedWriter=true,
                            resumedSameCapture=true,nativeRequestCount=2,sameDayDuplicateSuppressed=true,encryptedLocalSnapshot=record.Snapshot,
                            bytes=record.Bytes,files=record.Files,cloudUploaded=false,interactiveLoginTested=false,timeUtc=DateTimeOffset.UtcNow},true);
                        result=0;await app.ExitAsync(false);
                    }
                    catch(Exception e)
                    {
                        finishing=true;monitor.Stop();
                        BrokerFiles.Save(Path.Combine(folder,"result.json"),new{pass=false,errorType=e.GetType().Name,recordState=record.State.ToString(),
                            record.FailureCode,phase="completion",captureId,timeUtc=DateTimeOffset.UtcNow},true);
                        await app.ExitAsync(false);
                    }
                });
            };
            Progress("WAITING_FOR_REAL_APPLICATION_DAILY_TIMER");monitor.Start();Application.Run(app);return result;
        }
        catch(Exception e)
        {
            if(output is not null&&Directory.Exists(output))BrokerFiles.Save(Path.Combine(output,"result.json"),new{pass=false,errorType=e.GetType().Name,phase="setup",timeUtc=DateTimeOffset.UtcNow},true);
            return 1;
        }
    }
}
