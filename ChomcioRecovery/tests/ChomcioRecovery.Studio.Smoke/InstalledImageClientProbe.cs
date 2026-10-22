using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using ChomcioRecovery.Desktop;
using ChomcioRecovery.SystemImages;
using Microsoft.Win32.SafeHandles;

// Lab-only entry point: exercise the production adapter under an authenticated
// standard-account token. It consumes ONLY an already-completed native capture.
// Password arrives over stdin and is never included in output or command args.
internal static class InstalledImageClientProbe
{
    private sealed record Input(string User,string Password,string PlanId,string CaptureId,string ProfileId);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool LogonUser(string user,string domain,string password,int type,int provider,out SafeAccessTokenHandle token);

    internal static async Task<int> RunAsync()
    {
        try
        {
            if(Environment.MachineName!="CHOMCIOTEST")throw new InvalidOperationException("Isolated guest required.");
            string line=Console.ReadLine()??throw new InvalidDataException("Missing lab input.");
            if(line.Length>16_384)throw new InvalidDataException("Invalid lab input.");
            var input=JsonSerializer.Deserialize<Input>(line,BrokerFiles.Json)??throw new InvalidDataException();
            if(input.User!="ChomcioImageTest"||!BrokerFiles.IsId(input.PlanId)||!BrokerFiles.IsId(input.CaptureId)||!BrokerFiles.IsId(input.ProfileId))
                throw new InvalidDataException("Unexpected lab identity.");
            if(!LogonUser(input.User,Environment.MachineName,input.Password,3,0,out var token))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            using(token)
            {
                input=input with{Password=""};line="";
                var result=await WindowsIdentity.RunImpersonatedAsync(token,async()=>
                {
                    using(var identity=WindowsIdentity.GetCurrent())
                        if(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                            throw new UnauthorizedAccessException("Test must use a standard token.");
                    string directory=BrokerFiles.PlanDirectory(input.PlanId);
                    var plan=BrokerFiles.Read<ImagePlan>(Path.Combine(directory,"plan.json"));
                    var state=BrokerFiles.Read<CaptureState>(Path.Combine(directory,"states",input.CaptureId+".json"));
                    if(state.Stage!="Complete"||state.NativeExitCode!=0||state.CaptureId!=input.CaptureId)
                        throw new InvalidDataException("A completed native capture is required; no new image will be requested.");
                    int requestsBefore=Directory.GetFiles(Path.Combine(directory,"requests"),"*.json").Length;
                    int statesBefore=Directory.GetFiles(Path.Combine(directory,"states"),"*.json").Length;
                    var profile=new BackupProfile{Id=input.ProfileId,Name="Isolated image client",Content=BackupContent.WindowsSystem,
                        SystemImagePlanId=plan.PlanId,SystemImageCacheRoot=BrokerFiles.ClientDirectory(plan)};
                    profile.Repository=SystemImageStorage.Repository(profile.SystemImageCacheRoot,profile.Id);
                    var adapter=new InstalledSystemImageCapture();adapter.ValidateStorage(profile);
                    var pending=new PendingSystemImage(plan.PlanId,state.CaptureId,state.RequestedUtc);
                    string output=SystemImageLease.DirectoryFor(profile,pending);
                    if(Directory.Exists(output))throw new IOException("This probe requires a fresh export directory.");
                    var request=new SystemImageCaptureRequest(plan.PlanId,state.CaptureId,state.RequestedUtc,output);
                    bool cancelled=false;
                    using(var cancel=new CancellationTokenSource())
                    {
                        cancel.Cancel();
                        try{await adapter.CaptureAsync(request,cancel.Token);}catch(OperationCanceledException){cancelled=true;}
                    }
                    if(!cancelled||Directory.Exists(output))throw new IOException("Cancelled client created an export.");
                    bool outsideDenied=false;
                    try{await adapter.CaptureAsync(request with{OutputDirectory=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"ChomcioForbiddenExport",state.CaptureId)},default);}
                    catch(InvalidDataException){outsideDenied=true;}
                    if(!outsideDenied)throw new IOException("Off-target export was not rejected.");
                    await adapter.CaptureAsync(request,default);
                    SystemImageProof proof;
                    using(var lease=await SystemImageLease.OpenAsync(output,pending,default))proof=lease.Proof;
                    DateTime writeTime=File.GetLastWriteTimeUtc(Path.Combine(output,SystemImageLease.ArchiveName));
                    // Reconcile the same completed identity after a client restart.
                    await new InstalledSystemImageCapture().CaptureAsync(request,default);
                    using(var identity=WindowsIdentity.GetCurrent())
                        if(identity.User!.Value!=plan.OwnerSid||new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                            throw new UnauthorizedAccessException("Identity changed across await.");
                    if(writeTime!=File.GetLastWriteTimeUtc(Path.Combine(output,SystemImageLease.ArchiveName))||
                        requestsBefore!=Directory.GetFiles(Path.Combine(directory,"requests"),"*.json").Length||
                        statesBefore!=Directory.GetFiles(Path.Combine(directory,"states"),"*.json").Length)
                        throw new IOException("Client retry changed the export or duplicated a native request.");
                    return new{pass=true,method="production-adapter-under-standard-token",captureId=state.CaptureId,profileId=profile.Id,
                        cancelledBeforeWork=cancelled,outsideExportDenied=outsideDenied,independentExportVerified=true,
                        unchangedOnRetry=true,noDuplicateNativeRequest=true,archiveBytes=proof.ArchiveBytes,archiveSha256=proof.ArchiveSha256,
                        timeUtc=DateTimeOffset.UtcNow};
                });
                Console.WriteLine(JsonSerializer.Serialize(result));return 0;
            }
        }
        catch(Exception error)
        {
            // No arbitrary exception messages/paths/input in machine-visible output.
            Console.WriteLine(JsonSerializer.Serialize(new{pass=false,errorType=error.GetType().Name,
                nativeCode=error is Win32Exception native?(int?)native.NativeErrorCode:null,timeUtc=DateTimeOffset.UtcNow}));
            return 1;
        }
    }
}
