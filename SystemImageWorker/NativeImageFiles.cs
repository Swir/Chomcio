using System.Security.AccessControl;
using System.Security.Principal;

namespace ChomcioRecovery.SystemImages;

internal sealed class NativeImageFiles : IDisposable
{
    private readonly Dictionary<string,FileStream> streams=new(StringComparer.OrdinalIgnoreCase);
    internal IEnumerable<string> Files=>streams.Keys;
    internal FileStream StreamFor(string path)=>streams[path];
    private static bool PrivilegedOwner(string sid)=>sid is "S-1-5-18" or "S-1-5-32-544" or
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    internal static void ValidateNativeAcl(FileSystemSecurity security)
    {
        if(!PrivilegedOwner(security.GetOwner(typeof(SecurityIdentifier))!.Value))
            throw new UnauthorizedAccessException("Untrusted native image owner.");
        const FileSystemRights mutation=FileSystemRights.Write|FileSystemRights.Delete|FileSystemRights.DeleteSubdirectoriesAndFiles|
            FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership;
        foreach(FileSystemAccessRule rule in security.GetAccessRules(true,true,typeof(SecurityIdentifier)))
        {
            if(rule.AccessControlType!=AccessControlType.Allow||(rule.PropagationFlags&PropagationFlags.InheritOnly)!=0||
                (rule.FileSystemRights&mutation)==0)continue;
            // wbadmin's actual default output includes Backup Operators and the
            // CREATOR OWNER placeholder with a SYSTEM owner. Recognize these only
            // on native data, before narrowing the ACL. Never trust them for code,
            // protected plans, state, receipts or exported bundles.
            if(!PrivilegedOwner(rule.IdentityReference.Value)&&rule.IdentityReference.Value is not ("S-1-5-32-551" or "S-1-3-0"))
                throw new UnauthorizedAccessException("Native image permits ordinary-account modification.");
        }
    }

    internal static NativeImageFiles OpenForPacking(ImagePlan plan,string image)
    {
        if(!WindowsIdentity.GetCurrent().User!.IsWellKnown(WellKnownSidType.LocalSystemSid))
            throw new UnauthorizedAccessException("Only the installed SYSTEM worker can seal its native output.");
        BrokerFiles.Validate(plan);BrokerFiles.RequireProtected(plan.TargetVolume);
        if(!Path.GetFullPath(image).Equals(Path.Combine(plan.TargetVolume,"WindowsImageBackup"),StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Unexpected native image root.");
        var directories=new List<string>();var files=new List<string>();
        void Visit(string directory)
        {
            BrokerFiles.RejectLinks(directory);ValidateNativeAcl(new DirectoryInfo(directory).GetAccessControl());directories.Add(directory);
            foreach(string entry in Directory.GetFileSystemEntries(directory))
            {
                BrokerFiles.RejectLinks(entry);
                if(Directory.Exists(entry))Visit(entry);
                else{ValidateNativeAcl(new FileInfo(entry).GetAccessControl());files.Add(entry);}
                if(files.Count+directories.Count>32_000)throw new IOException("Unexpected native image file count.");
            }
        }
        Visit(image);
        var result=new NativeImageFiles();
        try
        {
            // Hold every source member against writers/deletion until the entire
            // archive and receipt are committed, not only while copying one file.
            foreach(string file in files)
                result.streams.Add(file,new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.Read,4096,FileOptions.Asynchronous|FileOptions.SequentialScan));
            foreach(string directory in directories)BrokerFiles.ProtectDirectory(directory);
            foreach(string file in files)
            {
                var acl=new FileSecurity();acl.SetAccessRuleProtection(true,false);
                var admin=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);acl.SetOwner(admin);
                foreach(var sid in new[]{admin,new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null)})
                    acl.AddAccessRule(new(sid,FileSystemRights.FullControl,AccessControlType.Allow));
                new FileInfo(file).SetAccessControl(acl);BrokerFiles.RequireProtected(file);
            }
            return result;
        }
        catch{result.Dispose();throw;}
    }
    public void Dispose(){foreach(var input in streams.Values)input.Dispose();}
}
