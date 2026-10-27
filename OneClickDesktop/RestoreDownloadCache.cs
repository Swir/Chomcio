using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ChomcioRecovery.Desktop;

// This file is only a locator, never proof that a copy is complete. Core
// authenticates every reused byte against freshly fetched cloud metadata.
// Separate from settings.json so recovery cannot overwrite scheduler state.
internal sealed class RestoreDownloadCache(StudioStore store,string profileId,string snapshotId,string account)
{
    private sealed record Hint(int Version,string Repository);
    private string RecordPath => Path.Combine(store.Root,"download-resume",
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(profileId+"\n"+snapshotId+"\n"+account.ToUpperInvariant())))+".json");

    internal string? Find()
    {
        try
        {
            string path=RecordPath;StudioStore.RejectLinks(path);
            if(!File.Exists(path)||new FileInfo(path).Length>128*1024)return null;
            var hint=JsonSerializer.Deserialize<Hint>(File.ReadAllText(path));
            if(hint is not {Version:1}||!Allowed(hint.Repository)||!Directory.Exists(hint.Repository))return null;
            return hint.Repository;
        }
        catch(Exception e) when(e is IOException or UnauthorizedAccessException or JsonException or ArgumentException){return null;}
    }

    internal bool Remember(string repository)
    {
        try
        {
            if(!Allowed(repository))return false;
            int count=Objects(repository);
            if(count==0)return false;
            string? previous=Find();
            if(previous is not null&&Objects(previous)>count)return true;
            string path=RecordPath;StudioStore.RejectLinks(path);Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            string stage=path+"."+Guid.NewGuid().ToString("N")+".tmp";
            using(var file=new FileStream(stage,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough))
            {JsonSerializer.Serialize(file,new Hint(1,Path.GetFullPath(repository)));file.Flush(true);}
            StudioStore.RejectLinks(path);File.Move(stage,path,true);return true;
        }
        catch(Exception e) when(e is IOException or UnauthorizedAccessException or ArgumentException){return false;}
    }

    private bool Allowed(string path)
    {
        if(string.IsNullOrWhiteSpace(path)||!Path.IsPathFullyQualified(path))return false;
        StudioStore.RejectLinks(path);
        string full=Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if(Path.GetFileName(full)!="encrypted")return false;
        string? parent=Path.GetDirectoryName(full);
        if(parent is null)return false;
        string name=Path.GetFileName(parent);
        if(name.StartsWith("ChomcioPobieranie_",StringComparison.Ordinal)&&Guid.TryParseExact(name[18..],"N",out _))return true;
        return Guid.TryParseExact(name,"N",out _)&&SystemImageStorage.SamePath(Path.GetDirectoryName(parent!)!,Path.Combine(store.Root,"restores"));
    }

    private static int Objects(string repository)
    {
        string objects=Path.Combine(repository,"objects");StudioStore.RejectLinks(objects);
        if(!Directory.Exists(objects))return 0;
        int count=0;
        foreach(string bucket in Directory.EnumerateDirectories(objects))
        {
            string prefix=Path.GetFileName(bucket);
            if(prefix.Length!=2||!prefix.All(Hex))continue;
            StudioStore.RejectLinks(bucket);
            foreach(string file in Directory.EnumerateFiles(bucket,"*.obj"))
            {
                string name=Path.GetFileName(file);
                if(name.Length==68&&name.StartsWith(prefix,StringComparison.Ordinal)&&name[..64].All(Hex))
                {StudioStore.RejectLinks(file);count=checked(count+1);}
            }
        }
        return count;
    }
    private static bool Hex(char c)=>c is >= '0' and <= '9' or >= 'a' and <= 'f';
}
