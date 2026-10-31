using ChomcioRecovery.Core;
using System.Security.Cryptography;

internal static class LongPathScenarios
{
    internal static void Run(string sandbox, Action<bool,string> check)
    {
        if (!OperatingSystem.IsWindows()) return;
        string root = Path.Combine(sandbox,"long-paths");
        while(root.Length < 340) root = Path.Combine(root,"długi-katalog-" + new string('a',35));
        Directory.CreateDirectory(root);
        check(!root.StartsWith(@"\\?\") && root.Length > 300,"test uses an ordinary DOS path beyond MAX_PATH");
        byte[] bytes = RandomNumberGenerator.GetBytes(8197);
        string source = Path.Combine(root,"source"), repository = Path.Combine(root,"repository");
        Directory.CreateDirectory(Path.Combine(source,"pusty"));
        File.WriteAllBytes(Path.Combine(source,"zażółć.bin"),bytes);
        string key = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        LocalEncryptedVault.Initialize(repository,key);
        using var vault = LocalEncryptedVault.Open(repository,key);
        var backup = vault.BackupDirectory(source);
        vault.VerifySnapshot(backup.SnapshotId);
        check(vault.ReadSnapshot(backup.SnapshotId).Files.Count == 1,"long path encrypted record publication and verification");
        string export = Path.Combine(root,"independent-export");
        vault.ExportEncryptedSnapshot(backup.SnapshotId,export);
        using var independent = LocalEncryptedVault.Open(export,key);
        independent.VerifySnapshot(backup.SnapshotId);
        check(true,"long path independent directory publication");
        string restored = Path.Combine(root,"restored");
        independent.RestoreSnapshot(backup.SnapshotId,restored);
        check(File.ReadAllBytes(Path.Combine(restored,"zażółć.bin")).SequenceEqual(bytes) && Directory.Exists(Path.Combine(restored,"pusty")),"long path full restore preserves bytes and empty directory");
        string single = Path.Combine(root,"single-file.bin");
        independent.RestoreFile(backup.SnapshotId,"zażółć.bin",single);
        check(File.ReadAllBytes(single).SequenceEqual(bytes),"long path single-file handle publication");
        PrivateRestoreStage.AssertWindowsProtectedDacl(restored);
        check(true,"long path restore retains private ACL");
        foreach (var attempt in new Action[]{()=>independent.RestoreFile(backup.SnapshotId,"zażółć.bin",single),
            ()=>independent.RestoreSnapshot(backup.SnapshotId,restored),()=>vault.ExportEncryptedSnapshot(backup.SnapshotId,export)})
        {
            bool refused=false;try{attempt();}catch(IOException){refused=true;}
            check(refused,"long destination still refuses overwrite");
        }
        check(File.ReadAllBytes(single).SequenceEqual(bytes) && File.ReadAllBytes(Path.Combine(restored,"zażółć.bin")).SequenceEqual(bytes),"refused long-path writes preserve previous data");
        independent.VerifySnapshot(backup.SnapshotId);
        Console.WriteLine("CHOMCIO_LONG_PATHS=PASS (ordinary path >340 characters, record/directory/file publication and no overwrite)");
    }
}
