using ChomcioRecovery.Desktop;
using ChomcioRecovery.SystemImages;
using System.Security.Principal;
using System.Text.Json;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

internal static class InstalledImageWizardProbe
{
    private sealed record Input(string User,string Password,string PlanId,string ProbeId);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool LogonUser(string user,string domain,string password,int type,int provider,out SafeAccessTokenHandle token);
    internal static int RunAuthenticated()
    {
        try
        {
            if(Environment.MachineName!="CHOMCIOTEST")return 1;
            string text=Console.ReadLine()??"";
            if(text.Length is 0 or >16384)return 1;
            var input=JsonSerializer.Deserialize<Input>(text,BrokerFiles.Json)??throw new InvalidDataException();
            if(input.User!="ChomcioImageTest"||!BrokerFiles.IsId(input.PlanId)||!BrokerFiles.IsId(input.ProbeId))return 1;
            if(!LogonUser(input.User,Environment.MachineName,input.Password,3,0,out var token))return 1;
            using(token)
            {
                input=input with{Password=""};text="";
                // Same ACL token as an ordinary account. This is not proof of
                // an interactive login or of Task Scheduler launching the GUI.
                return WindowsIdentity.RunImpersonated(token,()=>Run(input.PlanId,input.ProbeId));
            }
        }
        catch(Exception){return 1;}
    }
    // Only the disposable, enrolled VM. This test does not request a capture,
    // change an account password, save secrets, or connect to the cloud.
    internal static int Run(string planId,string probeId)
    {
        string? resultPath=null;
        try
        {
            if(Environment.MachineName!="CHOMCIOTEST"||!BrokerFiles.IsId(planId)||!BrokerFiles.IsId(probeId))
                throw new InvalidOperationException("Disposable lab only.");
            using var identity=WindowsIdentity.GetCurrent();
            if(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new UnauthorizedAccessException("Standard user required.");
            string directory=BrokerFiles.PlanDirectory(planId),path=Path.Combine(directory,"plan.json");
            BrokerFiles.RequireProtected(path);var plan=BrokerFiles.Read<ImagePlan>(path);BrokerFiles.Validate(plan);
            if(plan.OwnerSid!=identity.User!.Value)throw new UnauthorizedAccessException("Wrong test owner.");
            string cache=BrokerFiles.ClientDirectory(plan);
            string output=Path.Combine(cache,"qualification",probeId);BrokerFiles.RejectLinks(output);
            if(Directory.Exists(output))throw new IOException("Fresh probe directory required.");
            Directory.CreateDirectory(output);resultPath=Path.Combine(output,"result.json");
            var before=Directory.GetFiles(Path.Combine(directory,"requests"),"*.json").Order().ToArray();
            var plans=new InstalledSystemImagePlans().List();
            if(plans.Count!=1||plans[0].Id!=planId||!SystemImageStorage.SamePath(plans[0].CacheRoot,cache))
                throw new InvalidDataException("Plan discovery mismatch.");
            using var wizard=new ProfileEditor(Path.Combine(output,"settings"),newContent:BackupContent.WindowsSystem);
            wizard.Advance();
            if(wizard.Step!=1||wizard.ResultProfile is not null||wizard.ValidationMessage.Length!=0)
                throw new InvalidOperationException("Enrolled wizard did not advance.");
            if(!before.SequenceEqual(Directory.GetFiles(Path.Combine(directory,"requests"),"*.json").Order()))
                throw new InvalidOperationException("Wizard unexpectedly requested a native capture.");
            File.WriteAllText(resultPath,JsonSerializer.Serialize(new{pass=true,standardUser=true,protectedPlanDiscovered=true,
                approvedStorageValidated=true,wizardAdvanced=true,nativeRequestsUnchanged=true,requestCount=before.Length,
                nativeCaptureRequested=false,passwordsChanged=false,timeUtc=DateTimeOffset.UtcNow}));
            return 0;
        }
        catch(Exception e)
        {
            if(resultPath is not null)File.WriteAllText(resultPath,JsonSerializer.Serialize(new{pass=false,errorType=e.GetType().Name,timeUtc=DateTimeOffset.UtcNow}));
            return 1;
        }
    }
}
