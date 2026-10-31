using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ChomcioRecovery.SystemImages;

internal sealed class InstallerFailure(int code) : Exception
{
    internal int Code { get; }=code;
}

// Invoked only from the unpacked EXE after Windows grants elevation. No
// PowerShell policy changes, source-disk writes, formatting or capture requests.
internal static class PackageInstaller
{
    private const string TaskName="ChomcioRecovery Image Broker";
    internal static int Install(string sid,string target,string planId)
    {
        if(!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))return 47;
        if(!BrokerFiles.IsId(planId)||!new SecurityIdentifier(sid).IsAccountSid())return 40;
        if(!Regex.IsMatch(target,@"\A[A-Za-z]:\\\z"))return 45;
        var drive=new DriveInfo(target);
        if(!drive.IsReady||drive.DriveType!=DriveType.Fixed||drive.DriveFormat!="NTFS")return 45;
        BrokerFiles.RejectLinks(target);
        string volume=NativeVolumes.VolumeFor(target),source=NativeVolumes.SystemVolume();
        if(volume.Equals(source,StringComparison.OrdinalIgnoreCase))return 45;
        if(Directory.EnumerateFileSystemEntries(target).Any(p=>Path.GetFileName(p) is not ("System Volume Information" or "$RECYCLE.BIN")))return 45;
        var system=new DriveInfo(Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))!);
        if(drive.AvailableFreeSpace<checked((system.TotalSize-system.AvailableFreeSpace)*4+(2L<<30)))return 46;
        string install=BrokerFiles.InstallRoot,broker=BrokerFiles.Root;
        foreach(string path in new[]{install,broker,Path.GetDirectoryName(install)!,Path.GetDirectoryName(broker)!})
        {BrokerFiles.RejectLinks(path);if(Directory.Exists(path)||File.Exists(path))return 41;}
        using var package=WorkerPackage.Open(AppContext.BaseDirectory);
        dynamic service=Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service")!)!;
        dynamic? folder=null;dynamic? task=null;dynamic? registered=null;
        try
        {
            service.Connect();folder=service.GetFolder("\\");
            try{dynamic existing=folder.GetTask(TaskName);Marshal.FinalReleaseComObject(existing);return 41;}
            catch(FileNotFoundException){}
            catch(COMException e)when(e.HResult==unchecked((int)0x80070002)){}
            // Both parents are absent; unrelated application directories are
            // never adopted or assigned different permissions.
            BrokerFiles.ProtectDirectory(Path.GetDirectoryName(install)!,"S-1-5-11");
            BrokerFiles.ProtectDirectory(Path.GetDirectoryName(broker)!,"S-1-5-11");
            BrokerFiles.ProtectDirectory(install,"S-1-5-11");BrokerFiles.ProtectDirectory(broker,"S-1-5-11");
            BrokerFiles.ProtectDirectory(Path.Combine(broker,"plans"),"S-1-5-11");
            string planDirectory=BrokerFiles.PlanDirectory(planId);
            BrokerFiles.ProtectDirectory(planDirectory,sid);
            string requests=Path.Combine(planDirectory,"requests");BrokerFiles.ProtectDirectory(requests,sid);
            AddOwnerRights(requests,sid,FileSystemRights.Modify,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None);
            BrokerFiles.ProtectDirectory(Path.Combine(planDirectory,"states"),sid);
            BrokerFiles.ProtectDirectory(volume,sid);
            string cacheParent=Path.Combine(volume,"ChomcioRecoveryCache"),cache=Path.Combine(cacheParent,planId);
            BrokerFiles.ProtectDirectory(cacheParent,sid);BrokerFiles.ProtectDirectory(cache,sid);
            AddOwnerRights(cache,sid,FileSystemRights.ReadAndExecute|FileSystemRights.Write|FileSystemRights.DeleteSubdirectoriesAndFiles,InheritanceFlags.None,PropagationFlags.None);
            AddOwnerRights(cache,sid,FileSystemRights.Modify,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.InheritOnly);
            package.CopyTo(install);
            var plan=new ImagePlan(1,planId,sid,volume,source,Environment.MachineName);
            BrokerFiles.Validate(plan);BrokerFiles.Save(Path.Combine(planDirectory,"plan.json"),plan);
            task=service.NewTask(0);task.RegistrationInfo.Description="ChomcioRecovery: chroniony moduł tworzenia obrazów Windows.";
            task.Principal.UserId="SYSTEM";task.Principal.LogonType=5;task.Principal.RunLevel=1;
            task.Settings.Enabled=true;task.Settings.Hidden=true;task.Settings.ExecutionTimeLimit="PT0S";
            task.Settings.MultipleInstances=2;task.Settings.DisallowStartIfOnBatteries=false;task.Settings.StopIfGoingOnBatteries=false;
            dynamic trigger=task.Triggers.Create(8);trigger.Enabled=true;Marshal.FinalReleaseComObject(trigger);
            dynamic action=task.Actions.Create(0);action.Path=Path.Combine(install,"ChomcioRecovery.ImageWorker.exe");action.Arguments="--serve";action.WorkingDirectory=install;Marshal.FinalReleaseComObject(action);
            registered=folder.RegisterTaskDefinition(TaskName,task,2,"SYSTEM",null,5,"D:P(A;;FA;;;SY)(A;;FA;;;BA)");
            dynamic running=registered.Run(null);Marshal.FinalReleaseComObject(running);
            return 0;
        }
        finally
        {
            if(registered is not null)Marshal.FinalReleaseComObject(registered);
            if(task is not null)Marshal.FinalReleaseComObject(task);
            if(folder is not null)Marshal.FinalReleaseComObject(folder);
            Marshal.FinalReleaseComObject(service);
        }
    }
    private static void AddOwnerRights(string path,string sid,FileSystemRights rights,InheritanceFlags inheritance,PropagationFlags propagation)
    {
        var directory=new DirectoryInfo(path);var acl=directory.GetAccessControl();
        acl.AddAccessRule(new(new SecurityIdentifier(sid),rights,inheritance,propagation,AccessControlType.Allow));directory.SetAccessControl(acl);
    }
}

internal sealed class WorkerPackage : IDisposable
{
    private sealed record Entry(string name,string sha256);
    private readonly List<(Entry Entry,FileStream Input)> files=new();
    private FileStream? manifest;
    internal static WorkerPackage Open(string root)
    {
        var package=new WorkerPackage();
        try
        {
            BrokerFiles.RejectLinks(root);
            string manifestPath=Path.Combine(root,"package-hashes.json");BrokerFiles.RejectLinks(manifestPath);
            package.manifest=new(manifestPath,FileMode.Open,FileAccess.Read,FileShare.Read);
            if(package.manifest.Length is <2 or >1_048_576)throw new InstallerFailure(43);
            var entries=JsonSerializer.Deserialize<Entry[]>(package.manifest)??throw new InstallerFailure(43);
            if(entries.Length is <4 or >1024)throw new InstallerFailure(43);
            var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach(var entry in entries)
            {
                if(entry is null||entry.name is null||entry.sha256 is null||
                    !Regex.IsMatch(entry.name,@"\A[A-Za-z0-9._-]+\z")||entry.name.EndsWith('.')||
                    Regex.IsMatch(entry.name.Split('.')[0],@"\A(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])\z",RegexOptions.IgnoreCase)||!names.Add(entry.name)||
                    !Regex.IsMatch(entry.sha256,@"\A[A-Fa-f0-9]{64}\z"))throw new InstallerFailure(43);
                string path=Path.Combine(root,entry.name);BrokerFiles.RejectLinks(path);
                var input=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
                package.files.Add((entry,input));
                if(!Convert.ToHexString(SHA256.HashData(input)).Equals(entry.sha256,StringComparison.OrdinalIgnoreCase))throw new InstallerFailure(43);
            }
            foreach(string required in new[]{"ChomcioRecovery.ImageWorker.exe","ChomcioRecovery.ImageWorker.dll","ChomcioRecovery.ImageWorker.deps.json","ChomcioRecovery.ImageWorker.runtimeconfig.json"})
                if(!names.Contains(required))throw new InstallerFailure(43);
            return package;
        }
        catch{package.Dispose();throw;}
    }
    internal void CopyTo(string root)
    {
        foreach(var file in files)
        {
            string path=Path.Combine(root,file.Entry.name);file.Input.Position=0;
            using(var output=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)){file.Input.CopyTo(output);output.Flush(true);}
            using var actual=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
            if(!Convert.ToHexString(SHA256.HashData(actual)).Equals(file.Entry.sha256,StringComparison.OrdinalIgnoreCase))throw new InstallerFailure(43);
            BrokerFiles.RequireProtected(path);
        }
    }
    public void Dispose(){foreach(var file in files)file.Input.Dispose();manifest?.Dispose();}
}
