using ChomcioRecovery.Core;
using System.Text;

internal static class ZoneIdentifierScenarios
{
    internal static void Run(string sandbox,Action<bool,string> check)
    {
        if(!OperatingSystem.IsWindows())return;
        string root=Path.Combine(sandbox,"zone-identifier");Directory.CreateDirectory(root);
        string source=Path.Combine(root,"source");Directory.CreateDirectory(source);
        string file=Path.Combine(source,"downloaded.txt");
        File.WriteAllText(file,"Synthetic downloaded document");
        byte[] zone=Encoding.UTF8.GetBytes("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.test/document\r\n");
        File.WriteAllBytes(file+WindowsZoneIdentifier.StreamName,zone);
        string repo=Path.Combine(root,"vault");LocalEncryptedVault.Initialize(repo,"synthetic-zone-secret-only");
        using var vault=LocalEncryptedVault.Open(repo,"synthetic-zone-secret-only");
        void Fails(Action action,string message)
        {bool failed=false;try{action();}catch(Exception e)when(e is IOException or InvalidDataException or ArgumentException){failed=true;}check(failed,message);}
        Fails(()=>vault.BackupDirectory(source),"strict default still refuses named streams");
        var result=vault.BackupDirectory(source,preserveZoneIdentifiers:true);
        var snapshot=vault.ReadSnapshot(result.SnapshotId);
        check(snapshot.Version==3&&snapshot.Files.Single().ZoneIdentifierBase64==Convert.ToBase64String(zone),"v3 authenticates exact Zone.Identifier bytes");
        string target=Path.Combine(root,"restored");vault.RestoreSnapshot(result.SnapshotId,target);
        check(File.ReadAllBytes(Path.Combine(target,"downloaded.txt")+WindowsZoneIdentifier.StreamName).SequenceEqual(zone),"whole-tree restore preserves Windows download-origin mark");
        check(File.ReadAllText(Path.Combine(target,"downloaded.txt"))==File.ReadAllText(file),"default file data remains exact");
        string single=Path.Combine(root,"single.txt");vault.RestoreFile(result.SnapshotId,"downloaded.txt",single);
        check(File.ReadAllBytes(single+WindowsZoneIdentifier.StreamName).SequenceEqual(zone),"single-file restore preserves exact Zone.Identifier");
        string portable=Path.Combine(root,"portable");vault.ExportEncryptedSnapshot(result.SnapshotId,portable);
        using(var exported=LocalEncryptedVault.Open(portable,"synthetic-zone-secret-only"))
        {
            exported.VerifySnapshot(result.SnapshotId);
            check(exported.ReadSnapshot(result.SnapshotId).Files.Single().ZoneIdentifierBase64==Convert.ToBase64String(zone),"encrypted portable export keeps authenticated zone metadata");
        }
        Fails(()=>vault.PublishVerifiedSnapshot(Guid.NewGuid().ToString("N"),snapshot with{Version=2},()=>{}),"down-level schema cannot silently discard Zone.Identifier");
        var malformed=snapshot with{Files=new(){snapshot.Files.Single() with{ZoneIdentifierBase64="not base64!"}}};
        Fails(()=>vault.PublishVerifiedSnapshot(Guid.NewGuid().ToString("N"),malformed,()=>{}),"malformed zone metadata refused before publication");
        var large=snapshot with{Files=new(){snapshot.Files.Single() with{ZoneIdentifierBase64=Convert.ToBase64String(new byte[WindowsZoneIdentifier.MaximumBytes+1])}}};
        Fails(()=>vault.PublishVerifiedSnapshot(Guid.NewGuid().ToString("N"),large,()=>{}),"zone metadata size bound enforced before publication");

        var inventory=LocalEncryptedVault.CaptureSourceInventory(source,preserveZoneIdentifiers:true);
        DateTime time=File.GetLastWriteTimeUtc(file);
        byte[] changed=Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(zone).Replace("ZoneId=3","ZoneId=0"));
        File.WriteAllBytes(file+WindowsZoneIdentifier.StreamName,changed);File.SetLastWriteTimeUtc(file,time);
        Fails(()=>LocalEncryptedVault.ThrowIfSourceInventoryChanged(source,inventory,preserveZoneIdentifiers:true),"same-length zone mutation detected even with restored file timestamp");
        File.WriteAllBytes(file+WindowsZoneIdentifier.StreamName,zone);
        string refused=Path.Combine(root,"refused");
        Fails(()=>vault.RestoreSnapshotCore(result.SnapshotId,refused,
            beforeStageReadback:stage=>File.WriteAllBytes(Path.Combine(stage,"downloaded.txt")+WindowsZoneIdentifier.StreamName,changed)),
            "changed restored zone refuses publication");
        check(!Directory.Exists(refused),"wrong zone metadata leaves no visible restore");
        string unknownTarget=Path.Combine(root,"unknown-refused");
        Fails(()=>vault.RestoreSnapshotCore(result.SnapshotId,unknownTarget,
            beforeStageReadback:stage=>File.WriteAllText(Path.Combine(stage,"downloaded.txt")+":untracked","unexpected")),
            "other ADS still refused during v3 restore");
        check(!Directory.Exists(unknownTarget),"unknown named stream not published");
        File.WriteAllText(file+":untracked","unexpected");
        Fails(()=>vault.BackupDirectory(source,preserveZoneIdentifiers:true),"preserving Zone.Identifier never permits unrelated streams");
        File.Delete(file+":untracked");
        File.WriteAllBytes(file+WindowsZoneIdentifier.StreamName,new byte[WindowsZoneIdentifier.MaximumBytes+1]);
        Fails(()=>vault.BackupDirectory(source,preserveZoneIdentifiers:true),"oversized source Zone.Identifier fails closed");
        File.WriteAllBytes(file+WindowsZoneIdentifier.StreamName,Array.Empty<byte>());
        var empty=vault.BackupDirectory(source,preserveZoneIdentifiers:true);
        string emptyTarget=Path.Combine(root,"empty-zone");vault.RestoreSnapshot(empty.SnapshotId,emptyTarget);
        check(File.ReadAllBytes(Path.Combine(emptyTarget,"downloaded.txt")+WindowsZoneIdentifier.StreamName).Length==0,"empty Zone.Identifier is retained as a stream");
        using(var stop=new CancellationTokenSource())
        {
            stop.Cancel();bool cancelled=false;try{vault.BackupDirectory(source,stop.Token,preserveZoneIdentifiers:true);}catch(OperationCanceledException){cancelled=true;}
            check(cancelled,"zone preservation remains cancellable");
        }
        Console.WriteLine("CHOMCIO_NATIVE_ZONE_IDENTIFIER=PASS");
    }
}
