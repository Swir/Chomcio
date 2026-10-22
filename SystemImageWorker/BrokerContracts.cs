using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ChomcioRecovery.SystemImages;

internal sealed record ImagePlan(int Version,string PlanId,string OwnerSid,string TargetVolume,
    string SourceVolume,string MachineName);
internal sealed record CaptureRequest(int Version,string CaptureId,DateTimeOffset RequestedUtc);
internal sealed record BrokerHealth(int Version,DateTimeOffset TimeUtc,int Pid);
internal sealed record CaptureState(int Version,string CaptureId,DateTimeOffset RequestedUtc,
    string Stage,int? NativePid=null,DateTimeOffset? NativeStartUtc=null,int? NativeExitCode=null,
    string? Failure=null,DateTimeOffset? CompletedUtc=null);
internal sealed record CaptureReceipt(int Version,string PlanId,string CaptureId,DateTimeOffset RequestedUtc,
    DateTimeOffset CompletedUtc,int NativeBackupExitCode,bool AllCritical,bool VssCopy,long ArchiveBytes,string ArchiveSha256);

internal static class BrokerFiles
{
    internal static string Root => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"ChomcioRecovery","ImageBroker");
    internal static string InstallRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"ChomcioRecovery","ImageWorker");
    internal static readonly JsonSerializerOptions Json=new(){WriteIndented=true,UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow};
    internal static bool IsId(string? id)=>Guid.TryParseExact(id,"N",out _);
    internal static bool IsVolume(string volume)=>volume.Length==49&&volume.StartsWith(@"\\?\Volume{",StringComparison.Ordinal)&&
        volume.EndsWith(@"}\",StringComparison.Ordinal)&&Guid.TryParseExact(volume.Substring(11,36),"D",out _);
    internal static string PlanDirectory(string id)=>IsId(id)?Path.Combine(Root,"plans",id):throw new InvalidDataException("Invalid plan ID.");
    internal static string ClientDirectory(ImagePlan plan)
    {
        Validate(plan);
        return Path.Combine(plan.TargetVolume,"ChomcioRecoveryCache",plan.PlanId);
    }
    internal static string CaptureDirectory(ImagePlan plan,string captureId)=>IsId(captureId)&&IsVolume(plan.TargetVolume)
        ?Path.Combine(plan.TargetVolume,"ChomcioRecoveryImages",plan.PlanId,captureId):throw new InvalidDataException("Invalid capture path.");
    internal static void Validate(ImagePlan plan)
    {
        if(plan.Version!=1||!IsId(plan.PlanId)||!IsVolume(plan.TargetVolume)||!IsVolume(plan.SourceVolume)||
            plan.TargetVolume.Equals(plan.SourceVolume,StringComparison.OrdinalIgnoreCase)||
            plan.MachineName!=Environment.MachineName||!new SecurityIdentifier(plan.OwnerSid).IsAccountSid())
            throw new InvalidDataException("Invalid or foreign image plan.");
    }
    internal static T Read<T>(string path)=>RetryRecordAccess(()=>ReadOnce<T>(path));
    internal static T ReadProtected<T>(string path)=>RetryRecordAccess(()=>
    {
        // Revalidate the complete protected path on EVERY attempt. Retry only
        // transient Windows name/sharing errors, never ACL or content failures.
        RequireProtected(path);
        return ReadOnce<T>(path);
    });
    private static T ReadOnce<T>(string path)
    {
        using var input=OpenRecordReadOnce(path);
        if(input.Length is <=0 or >16_384)throw new InvalidDataException("Invalid broker record size.");
        return JsonSerializer.Deserialize<T>(input,Json)??throw new InvalidDataException("Empty broker record.");
    }
    internal static FileStream OpenRecordRead(string path)=>RetryRecordAccess(()=>OpenRecordReadOnce(path));
    private static FileStream OpenRecordReadOnce(string path)
    {
        RejectLinks(path);
        // Records are replaced atomically. An existing reader keeps its complete
        // old record without preventing the worker from committing the next one.
        // Image/archive leases deliberately continue to deny deletion and writes.
        return new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read|FileShare.Delete);
    }
    private static T RetryRecordAccess<T>(Func<T> read)
    {
        // ReplaceFile can momentarily expose ERROR_FILE_NOT_FOUND or
        // ERROR_SHARING_VIOLATION to a new reader despite DELETE sharing.
        // Keep retries bounded (<0.5s of delay); a missing/locked record still
        // fails, and no cached status can substitute for an actual valid read.
        for(int attempt=0;;attempt++)
        {
            try{return read();}
            catch(IOException e)when(attempt<19&&e.HResult is unchecked((int)0x80070002) or unchecked((int)0x80070020))
            {Thread.Sleep(25);}
        }
    }
    internal static CaptureState RecordFailure(CaptureState state,string failure)=>state with
    {
        Stage=state.Stage is "Launching" or "NativeRunning" or "Interrupted"?"Interrupted":"Failed",
        Failure=failure
    };
    internal static void Save<T>(string path,T record,bool replace=false)
    {
        RejectLinks(path);string temp=Path.Combine(Path.GetDirectoryName(path)!,"stage-"+Guid.NewGuid().ToString("N")+".tmp");
        using(var output=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough))
        {JsonSerializer.Serialize(output,record,Json);output.Flush(true);}
        // ReplaceFile preserves the destination ACL and supports readers sharing
        // DELETE on Windows; MoveFileEx overwrite can reject those same readers.
        if(replace&&File.Exists(path))File.Replace(temp,path,null);
        else File.Move(temp,path);
    }
    internal static void RejectLinks(string path)
    {
        for(string? current=Path.GetFullPath(path);current is not null;current=Path.GetDirectoryName(current))
            if((Directory.Exists(current)||File.Exists(current))&&(File.GetAttributes(current)&FileAttributes.ReparsePoint)!=0)
                throw new IOException("Broker paths must not contain links.");
    }
    private static bool Trusted(IdentityReference sid)=>sid.Value is "S-1-5-18" or "S-1-5-32-544" or
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    internal static void RequireProtected(string path)
    {
        RejectLinks(path);
        bool directory=Directory.Exists(path);
        FileSystemSecurity security=directory?new DirectoryInfo(path).GetAccessControl():new FileInfo(path).GetAccessControl();
        if(!Trusted(security.GetOwner(typeof(SecurityIdentifier))!))throw new UnauthorizedAccessException("Untrusted broker owner.");
        const FileSystemRights mutations=FileSystemRights.Write|FileSystemRights.Delete|FileSystemRights.DeleteSubdirectoriesAndFiles|
            FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership;
        foreach(FileSystemAccessRule rule in security.GetAccessRules(true,true,typeof(SecurityIdentifier)))
            if(rule.AccessControlType==AccessControlType.Allow&&(rule.PropagationFlags&PropagationFlags.InheritOnly)==0&&
                !Trusted(rule.IdentityReference)&&(rule.FileSystemRights&mutations)!=0)
                throw new UnauthorizedAccessException("Broker data permits unprivileged modification.");
        // A writable parent's DELETE_CHILD right can bypass the child's DACL.
        for(string? parent=Path.GetDirectoryName(Path.GetFullPath(path));parent is not null;parent=Path.GetDirectoryName(parent))
        {
            var acl=new DirectoryInfo(parent).GetAccessControl();
            if(!Trusted(acl.GetOwner(typeof(SecurityIdentifier))!))throw new UnauthorizedAccessException("Untrusted broker ancestor.");
            foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))
                if(rule.AccessControlType==AccessControlType.Allow&&(rule.PropagationFlags&PropagationFlags.InheritOnly)==0&&!Trusted(rule.IdentityReference)&&
                    (rule.FileSystemRights&(FileSystemRights.DeleteSubdirectoriesAndFiles|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership))!=0)
                    throw new UnauthorizedAccessException("Broker ancestor permits replacement.");
        }
    }
    internal static void ProtectDirectory(string path,string? readerSid=null)
    {
        RejectLinks(path);Directory.CreateDirectory(path);
        var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);
        var admin=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);acl.SetOwner(admin);
        foreach(var sid in new[]{admin,new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null)})
            acl.AddAccessRule(new(sid,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        if(readerSid is not null)acl.AddAccessRule(new(new SecurityIdentifier(readerSid),FileSystemRights.ReadAndExecute,
            InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(acl);RequireProtected(path);
    }
}
