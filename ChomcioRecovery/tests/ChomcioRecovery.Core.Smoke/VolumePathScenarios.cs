using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using ChomcioRecovery.Core;

internal static class VolumePathScenarios
{
    [DllImport("kernel32.dll", EntryPoint="GetVolumeNameForVolumeMountPointW", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeName(string root, StringBuilder name, uint length);

    internal static void Run(string sandbox, Action<bool,string> check)
    {
        if (!OperatingSystem.IsWindows()) return;
        string root=Path.GetPathRoot(Path.GetFullPath(sandbox))!;
        var name=new StringBuilder(261);
        if (!GetVolumeName(root,name,(uint)name.Capacity))
            throw new IOException("Cannot obtain synthetic fixture volume name.",new Win32Exception(Marshal.GetLastWin32Error()));
        string fixture=Path.Combine(sandbox,"volume-paths");Directory.CreateDirectory(fixture);
        string volumeFixture=Path.Combine(name.ToString(),Path.GetRelativePath(root,fixture));
        string extendedFixture=@"\\?\"+fixture;
        byte[] content=RandomNumberGenerator.GetBytes(8197);
        string source=Path.Combine(volumeFixture,"source");Directory.CreateDirectory(source);
        File.WriteAllBytes(Path.Combine(source,"payload.bin"),content);
        Directory.CreateDirectory(Path.Combine(source,"empty"));
        string repository=Path.Combine(volumeFixture,"repo");
        string key=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        LocalEncryptedVault.Initialize(repository,key);
        using var vault=LocalEncryptedVault.Open(repository,key);
        var backup=vault.BackupDirectory(source);
        foreach (var (parent,label) in new[]{(fixture,"dos"),(volumeFixture,"guid"),(extendedFixture,"extended")})
        {
            string export=Path.Combine(parent,"export-"+label);
            vault.ExportEncryptedSnapshot(backup.SnapshotId,export);
            using var independent=LocalEncryptedVault.Open(export,key);
            independent.VerifySnapshot(backup.SnapshotId);
            check(independent.ReadSnapshot(backup.SnapshotId).Files.Count==1,label+" independent encrypted export");
            string restored=Path.Combine(parent,"restored-"+label);
            independent.RestoreSnapshot(backup.SnapshotId,restored);
            check(File.ReadAllBytes(Path.Combine(restored,"payload.bin")).SequenceEqual(content),label+" restored exact bytes");
            check(Directory.Exists(Path.Combine(restored,"empty")),label+" empty directory preserved");
            PrivateRestoreStage.AssertWindowsProtectedDacl(restored);
            check(true,label+" protected ACL retained");
            string single=Path.Combine(parent,"single-"+label);
            independent.RestoreFile(backup.SnapshotId,"payload.bin",single);
            check(File.ReadAllBytes(single).SequenceEqual(content),label+" single-file exact bytes");
            bool refused=false;
            try { independent.RestoreSnapshot(backup.SnapshotId,restored); } catch(IOException) { refused=true; }
            check(refused&&File.ReadAllBytes(Path.Combine(restored,"payload.bin")).SequenceEqual(content),label+" existing restore preserved");
        }
        Console.WriteLine("CHOMCIO_VOLUME_PATHS=PASS");
    }
}
