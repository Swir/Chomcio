using ChomcioRecovery.Core;

internal static class SystemLinkScenarios
{
    internal static void Run(string sandbox,Action<bool,string> check)
    {
        if(!OperatingSystem.IsWindows())return;
        string root=Path.Combine(sandbox,"system-links");Directory.CreateDirectory(root);
        string source=Path.Combine(root,"source"),outside=Path.Combine(root,"outside");
        Directory.CreateDirectory(source);Directory.CreateDirectory(outside);
        File.WriteAllText(Path.Combine(source,"document.txt"),"included synthetic bytes");
        File.WriteAllText(Path.Combine(outside,"foreign.txt"),"must never be read or restored");
        string link=Path.Combine(source,"System media");
        Directory.CreateSymbolicLink(link,outside);
        File.SetAttributes(link,File.GetAttributes(link)|FileAttributes.Hidden|FileAttributes.System);
        check((File.GetAttributes(link)&FileAttributes.ReparsePoint)!=0,"system test entry is a real directory link");
        string repo=Path.Combine(root,"vault");LocalEncryptedVault.Initialize(repo,"synthetic-system-links-only");
        using var vault=LocalEncryptedVault.Open(repo,"synthetic-system-links-only");
        bool refused=false;try{vault.BackupDirectory(source);}catch(IOException){refused=true;}
        check(refused&&!vault.ListSnapshotIds().Any(),"default Core still refuses directory links");
        var result=vault.BackupDirectory(source,skipSystemDirectoryLinks:true);
        var snapshot=vault.ReadSnapshot(result.SnapshotId);
        check(snapshot.Files.Count==1&&snapshot.Files[0].Path=="document.txt","opted-in backup never follows system directory link");
        check(snapshot.SkippedSystemDirectoryLinks?.SequenceEqual(new[]{"System media"})==true,"omitted system link is recorded inside encrypted manifest");
        string output=Path.Combine(root,"restored");vault.RestoreSnapshot(result.SnapshotId,output);
        check(File.ReadAllText(Path.Combine(output,"document.txt"))=="included synthetic bytes"&&!Directory.Exists(Path.Combine(output,"System media")),"restore includes selected bytes without recreating links");
        string portable=Path.Combine(root,"portable");vault.ExportEncryptedSnapshot(result.SnapshotId,portable);
        using(var readback=LocalEncryptedVault.Open(portable,"synthetic-system-links-only"))
            check(readback.ReadSnapshot(result.SnapshotId).SkippedSystemDirectoryLinks?.Count==1,"portable copy preserves omission report");
        var inventory=LocalEncryptedVault.CaptureSourceInventory(source,skipSystemDirectoryLinks:true);
        File.SetAttributes(link,File.GetAttributes(link)&~(FileAttributes.Hidden|FileAttributes.System));
        bool changeRefused=false;try{LocalEncryptedVault.ThrowIfSourceInventoryChanged(source,inventory,skipSystemDirectoryLinks:true);}catch(IOException){changeRefused=true;}
        check(changeRefused,"link policy change during backup fails closed");
        bool ordinaryRefused=false;try{vault.BackupDirectory(source,skipSystemDirectoryLinks:true);}catch(IOException){ordinaryRefused=true;}
        check(ordinaryRefused,"ordinary directory symlink is still refused when system-link omission enabled");
        File.SetAttributes(link,File.GetAttributes(link)|FileAttributes.Hidden|FileAttributes.System);
        bool conflictRefused=false;
        try{vault.PublishVerifiedSnapshot(Guid.NewGuid().ToString("N"),snapshot with{SkippedSystemDirectoryLinks=new(){"document.txt"}},()=>{});}
        catch(System.IO.InvalidDataException){conflictRefused=true;}
        check(conflictRefused,"manifest cannot claim a stored file was omitted");
        using(var stop=new CancellationTokenSource())
        {
            stop.Cancel();bool cancelled=false;try{vault.BackupDirectory(source,stop.Token,true);}catch(OperationCanceledException){cancelled=true;}
            check(cancelled,"system-link policy retains cancellation");
        }
        Console.WriteLine("CHOMCIO_NATIVE_SYSTEM_LINK_OMISSION=PASS");
    }
}
