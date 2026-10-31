using ChomcioRecovery.Desktop;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;

internal static class SystemImageReadinessScenarios
{
    private sealed class CancelOnWrite(CancellationTokenSource cts):IProgress<string>
    {public void Report(string message){if(message.StartsWith("Przygotowanie obrazu:"))cts.Cancel();}}
    internal static async Task Run(string area,string bundle,BackupProfile profile,JobSecrets secrets,string snapshot,StudioStore store,Action<bool,string> check)
    {
        async Task Refuse(Func<Task> action,string label){bool refused=false;try{await action();}catch(Exception e)when(e is IOException or InvalidDataException or ArgumentException or OperationCanceledException){refused=true;}check(refused,label);}
        string output=Path.Combine(area,"recovery-prepared");Directory.CreateDirectory(output);
        string target=await SystemImageRecovery.PrepareAsync(bundle,output,null,default,requireVolumeRoot:false);
        check(Path.GetFileName(target)=="WindowsImageBackup","recovery produces the Windows native directory name");
        using(var zip=ZipFile.OpenRead(Path.Combine(bundle,SystemImageLease.ArchiveName)))
            foreach(var entry in zip.Entries.Where(e=>!e.FullName.EndsWith('/')))
            {
                using var input=entry.Open();using var actual=File.OpenRead(Path.Combine(output,entry.FullName.Replace('/',Path.DirectorySeparatorChar)));
                check(SHA256.HashData(input).SequenceEqual(SHA256.HashData(actual)),"recovery disk bytes match authenticated archive entry");
            }
        string original=Path.Combine(target,"KEEP.txt");File.WriteAllText(original,"original backup stays");
        await Refuse(()=>SystemImageRecovery.PrepareAsync(bundle,output,null,default,false),"existing WindowsImageBackup refused");
        check(File.ReadAllText(original)=="original backup stays","existing backup untouched after refusal");
        await Refuse(()=>Task.Run(()=>SystemImageRecovery.Destination(Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))!)),"host system root refused for recovery output");
        await Refuse(()=>Task.Run(()=>SystemImageRecovery.Destination(output)),"GUI recovery requires volume root");
        string stopped=Path.Combine(area,"recovery-cancelled");Directory.CreateDirectory(stopped);
        using(var cts=new CancellationTokenSource())
            await Refuse(()=>SystemImageRecovery.PrepareAsync(bundle,stopped,new CancelOnWrite(cts),cts.Token,false),"cancellation during extraction does not report success");
        check(!Directory.Exists(Path.Combine(stopped,"WindowsImageBackup")),"cancelled archive never published as complete");
        string broken=Path.Combine(area,"recovery-broken");Directory.CreateDirectory(broken);
        foreach(string name in new[]{SystemImageLease.ArchiveName,SystemImageLease.ReceiptName})File.Copy(Path.Combine(bundle,name),Path.Combine(broken,name));
        using(var file=new FileStream(Path.Combine(broken,SystemImageLease.ArchiveName),FileMode.Open,FileAccess.Write)){file.Position=4;file.WriteByte(99);}
        string brokenOutput=Path.Combine(area,"broken-output");Directory.CreateDirectory(brokenOutput);
        await Refuse(()=>SystemImageRecovery.PrepareAsync(broken,brokenOutput,null,default,false),"corrupt archive refused before extraction");
        check(!Directory.EnumerateFileSystemEntries(brokenOutput).Any(),"corrupt archive writes no plaintext");
        string traversal=Path.Combine(area,"traversal-bundle");Directory.CreateDirectory(traversal);
        string evilArchive=Path.Combine(traversal,SystemImageLease.ArchiveName);
        using(var zip=ZipFile.Open(evilArchive,ZipArchiveMode.Create))
            foreach(var name in new[]{"WindowsImageBackup/Test/Catalog/data","WindowsImageBackup/Test/Backup/disk.vhdx","WindowsImageBackup/../escape.txt"})
            {using var writer=new StreamWriter(zip.CreateEntry(name).Open());writer.Write("synthetic");}
        var receipt=JsonSerializer.Deserialize<SystemImageReceipt>(File.ReadAllText(Path.Combine(bundle,SystemImageLease.ReceiptName)))!;
        receipt=receipt with{ArchiveBytes=new FileInfo(evilArchive).Length,ArchiveSha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(evilArchive)))};
        File.WriteAllText(Path.Combine(traversal,SystemImageLease.ReceiptName),JsonSerializer.Serialize(receipt));
        await Refuse(()=>SystemImageRecovery.PrepareAsync(traversal,brokenOutput,null,default,false),"authenticated archive still rejects path traversal");
        check(!Directory.EnumerateFileSystemEntries(brokenOutput).Any(),"unsafe ZIP writes no plaintext");
        // A catalog opened on a different PC has no local capture plan or profile.
        var discovered=new BackupProfile{Repository=profile.Repository};
        using(var session=new RestoreSession(store,discovered,secrets))
        {
            string fresh=Path.Combine(area,"fresh-pc-image");
            await session.RestoreAsync(snapshot,false,fresh,null,null,default);
            check(session.PreparedSystemImage,"image identified from encrypted contents without old machine profile");
            await Refuse(()=>session.RestoreAsync(snapshot,false,Path.Combine(area,"partial-fresh-image"),SystemImageLease.ArchiveName,null,default),"discovered Windows image cannot restore only the ZIP");
        }
        string download=SystemImageStorage.RecoveryRepository(output,Guid.NewGuid().ToString("N"));
        check(download.StartsWith(output+Path.DirectorySeparatorChar)&&download.EndsWith("encrypted"),"independent cloud download uses chosen recovery disk");
        string package=Path.Combine(area,"synthetic-package");Directory.CreateDirectory(Path.Combine(package,"image-worker","payload"));
        File.WriteAllText(Path.Combine(package,"image-worker","payload","ChomcioRecovery.ImageWorker.exe"),"Synthetic; never executed");
        File.WriteAllText(Path.Combine(package,"image-worker","payload","package-hashes.json"),"[]");
        string sid=WindowsIdentity.GetCurrent().User!.Value;
        var command=ImageWorkerSetup.Command(package,sid,"Z:\\",Guid.NewGuid().ToString("N"));
        check(command.UseShellExecute&&command.Verb=="runas"&&command.ArgumentList.Contains(sid)&&command.ArgumentList[0]=="--install"&&Path.GetFileName(command.FileName)=="ChomcioRecovery.ImageWorker.exe","setup uses elevated EXE and structured arguments without changing script policy");
        await Refuse(()=>Task.Run(()=>ImageWorkerSetup.Command(package,sid,"Z:\\;whoami",Guid.NewGuid().ToString("N"))),"installer rejects target command injection");
        await Refuse(()=>Task.Run(()=>ImageWorkerSetup.Command(package,sid,"Z:\\","../plan")),"installer rejects unsafe plan ID");
        using(var window=new SystemImageRecoveryWindow(bundle))check(Work9Scenarios.All(window).Any(c=>c.Name=="PrepareWindowsRecovery"),"recovery preparation available in GUI");
        Console.WriteLine("SYSTEM_IMAGE_READINESS=PASS (synthetic recovery extraction, cancellation, fresh-PC discovery and installer arguments; no native capture)");
    }
}
