using ChomcioRecovery.Core;
using System.Security.Cryptography;

internal static class VaultProgressScenarios
{
    internal static void Run(string root,Action<bool,string> check)
    {
        string area=Path.Combine(root,"vault-progress"),source=Path.Combine(area,"source"),repo=Path.Combine(area,"vault");
        Directory.CreateDirectory(source);Directory.CreateDirectory(Path.Combine(source,"empty"));
        byte[] original=RandomNumberGenerator.GetBytes(3*LocalEncryptedVault.ChunkBytes+157);
        File.WriteAllBytes(Path.Combine(source,"data.bin"),original);
        File.WriteAllBytes(Path.Combine(source,"empty.bin"),Array.Empty<byte>());
        const string secret="synthetic-progress-vault-key";
        LocalEncryptedVault.Initialize(repo,secret);
        using var vault=LocalEncryptedVault.Open(repo,secret);
        var events=new List<VaultProgress>();
        var observer=new Inline(events.Add);
        var first=vault.BackupDirectory(source,default,false,false,observer);
        var stages=new[]{VaultProgressStage.Encrypting,VaultProgressStage.CheckingStoredData,VaultProgressStage.CheckingSource,
            VaultProgressStage.CheckingPublishedData,VaultProgressStage.CheckingSourceAfterPublish};
        check(events.Select(x=>x.Stage).Distinct().SequenceEqual(stages),"local progress separates preparation from every verification pass");
        foreach(var stage in stages)
        {
            var pass=events.Where(x=>x.Stage==stage).ToArray();
            check(pass[0].ProcessedBytes==0&&pass[^1].ProcessedBytes==original.Length&&pass.All(x=>x.TotalBytes==original.Length),"each pass has its own actual source-byte total: "+stage);
            check(pass.Zip(pass.Skip(1)).All(p=>p.First.ProcessedBytes<=p.Second.ProcessedBytes),"progress never moves backwards within a pass: "+stage);
            check(pass.Any(x=>x.ProcessedBytes>0&&x.ProcessedBytes<x.TotalBytes),"large file reports progress before it is finished: "+stage);
        }
        events.Clear();vault.VerifySnapshot(first.SnapshotId,default,observer);
        check(events.All(x=>x.Stage==VaultProgressStage.VerifyingSnapshot)&&events[^1].ProcessedBytes==original.Length,"independent verifier reports its own completed byte walk");
        string restored=Path.Combine(area,"restored");vault.RestoreSnapshot(first.SnapshotId,restored);
        check(File.ReadAllBytes(Path.Combine(restored,"data.bin")).AsSpan().SequenceEqual(original),"progress-enabled backup restores exact bytes");
        events.Clear();var reused=vault.BackupDirectory(source,default,false,false,observer);
        check(reused.NewChunks==0&&reused.ReusedChunks>0&&events.Where(x=>x.Stage==VaultProgressStage.Encrypting).Last().ProcessedBytes==original.Length,
            "reused chunks count processed bytes without pretending they are newly stored bytes");

        using(var cancel=new CancellationTokenSource())
        {
            int before=vault.ListSnapshotIds().Count;bool stopped=false;
            var stop=new Inline(p=>{if(p.Stage==VaultProgressStage.Encrypting&&p.ProcessedBytes>0)cancel.Cancel();});
            try{vault.BackupDirectory(source,cancel.Token,false,false,stop);}catch(OperationCanceledException){stopped=true;}
            check(stopped&&vault.ListSnapshotIds().Count==before,"cancelling from live preparation progress creates no new recovery point");
        }
        using(var cancel=new CancellationTokenSource())
        {
            bool stopped=false;
            var stop=new Inline(p=>{if(p.ProcessedBytes>0)cancel.Cancel();});
            try{vault.VerifySnapshot(first.SnapshotId,cancel.Token,stop);}catch(OperationCanceledException){stopped=true;}
            check(stopped,"live verification progress supports mid-file cancellation");
        }
        using(var cancel=new CancellationTokenSource())
        {
            int before=vault.ListSnapshotIds().Count;bool stopped=false;
            var stop=new Inline(p=>{if(p.Stage==VaultProgressStage.CheckingPublishedData&&p.ProcessedBytes>0)cancel.Cancel();});
            try{vault.BackupDirectory(source,cancel.Token,false,false,stop);}catch(OperationCanceledException){stopped=true;}
            check(stopped&&vault.ListSnapshotIds().Count==before+1,"cancellation after publication preserves the committed point for inspection");
        }
        foreach(string id in vault.ListSnapshotIds())vault.VerifySnapshot(id);
        check(true,"all earlier and post-publication points remain independently valid after cancellation");
        string empty=Path.Combine(area,"empty-source");Directory.CreateDirectory(empty);events.Clear();
        var emptyResult=vault.BackupDirectory(empty,default,false,false,observer);vault.VerifySnapshot(emptyResult.SnapshotId);
        check(events.Count==stages.Length&&events.All(x=>x.TotalBytes==0&&x.ProcessedBytes==0),"empty source has zero-byte phases without invented percentages");
        File.WriteAllBytes(Path.Combine(source,"duplicate.bin"),original);
        string shared=vault.BackupDirectory(source).SnapshotId;
        events.Clear();string exported=Path.Combine(area,"exported");
        vault.ExportEncryptedSnapshot(shared,exported,default,observer);
        var exportStages=new List<VaultProgressStage>{VaultProgressStage.CheckingExportSource,VaultProgressStage.CopyingEncryptedExport,
            VaultProgressStage.CheckingExportData,VaultProgressStage.CheckingExportBeforePublish};
        if(OperatingSystem.IsWindows())exportStages.Add(VaultProgressStage.CheckingExportWithLeases);
        exportStages.Add(VaultProgressStage.CheckingPublishedExport);
        check(events.Select(x=>x.Stage).Distinct().SequenceEqual(exportStages),"export reports each authenticated pass separately");
        long encryptedBytes=Directory.EnumerateFiles(Path.Combine(exported,"objects"),"*.obj",SearchOption.AllDirectories).Sum(p=>new FileInfo(p).Length);
        foreach(var stage in exportStages)
        {
            var pass=events.Where(x=>x.Stage==stage).ToArray();
            long total=stage==VaultProgressStage.CopyingEncryptedExport?encryptedBytes:2L*original.Length;
            check(pass[0].ProcessedBytes==0&&pass[^1].ProcessedBytes==total&&pass.All(x=>x.TotalBytes==total),"export pass has actual logical or unique encrypted-byte total: "+stage);
            check(pass.Zip(pass.Skip(1)).All(p=>p.First.ProcessedBytes<=p.Second.ProcessedBytes)&&pass.Any(x=>x.ProcessedBytes>0&&x.ProcessedBytes<total),"export progress advances within a pass: "+stage);
        }
        using(var portable=LocalEncryptedVault.Open(exported,secret))
        {
            string target=Path.Combine(area,"export-restored");portable.RestoreSnapshot(shared,target);
            check(File.ReadAllBytes(Path.Combine(target,"duplicate.bin")).AsSpan().SequenceEqual(original),"progress-enabled deduplicated export restores exact bytes");
        }
        foreach(var phase in new[]{VaultProgressStage.CopyingEncryptedExport,VaultProgressStage.CheckingPublishedExport})
        {
            using var cancel=new CancellationTokenSource();bool stopped=false;string target=Path.Combine(area,"cancel-export-"+phase);
            var stop=new Inline(p=>{if(p.Stage==phase&&p.ProcessedBytes>0)cancel.Cancel();});
            try{vault.ExportEncryptedSnapshot(shared,target,cancel.Token,stop);}catch(OperationCanceledException){stopped=true;}
            bool published=phase==VaultProgressStage.CheckingPublishedExport;
            check(stopped&&Directory.Exists(target)==published,"export cancellation respects publication boundary: "+phase);
            if(published){using var portable=LocalEncryptedVault.Open(target,secret);portable.VerifySnapshot(shared);}
            vault.VerifySnapshot(shared);
        }
        events.Clear();vault.ExportEncryptedSnapshot(emptyResult.SnapshotId,Path.Combine(area,"empty-export"),default,observer);
        check(events.Count==exportStages.Count&&events.All(x=>x.ProcessedBytes==0&&x.TotalBytes==0),"empty export reports zero-byte passes without inventing work");
    }

    private sealed class Inline(Action<VaultProgress> report):IProgress<VaultProgress>
    {public void Report(VaultProgress value)=>report(value);}
}
