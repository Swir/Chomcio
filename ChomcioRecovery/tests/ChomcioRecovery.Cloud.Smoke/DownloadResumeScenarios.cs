using ChomcioRecovery.Core;
using System.Security.Cryptography;

internal static class DownloadResumeScenarios
{
    internal static async Task Run(string repository,string password,string snapshot,Func<string,string> fresh,Action<bool,string> check)
    {
        var cloud=new SeedCloud();var transfer=new CloudVaultTransfer(cloud);
        await transfer.UploadSnapshotAsync(repository,password,snapshot,fresh("resume-export"),null,default);
        string partial=fresh("partial");
        cloud.Reset();cloud.FailObject=2;
        bool failed=false;try{await transfer.DownloadSnapshotAsync(snapshot,password,partial,null,default);}catch(IOException){failed=true;}
        string[] chunks=Directory.GetFiles(Path.Combine(partial,"objects"),"*.obj",SearchOption.AllDirectories);
        check(failed&&chunks.Length==1,"interrupted download leaves one completed encrypted chunk");
        byte[] original=File.ReadAllBytes(chunks.Single());string reusedName=Path.GetFileName(chunks.Single());
        cloud.Reset();string resumed=fresh("resumed");
        await transfer.DownloadSnapshotAsync(snapshot,password,resumed,null,default,partial);
        check(cloud.Reads.Count==3&&!cloud.Reads.Contains(reusedName),"resume fetches fresh config/manifest and only missing chunk");
        check(File.ReadAllBytes(chunks.Single()).SequenceEqual(original),"resume leaves previous encrypted bytes untouched");
        using(var source=LocalEncryptedVault.Open(repository,password))
        using(var result=LocalEncryptedVault.Open(resumed,password))
        {
            string before=fresh("before"),after=fresh("after");source.RestoreSnapshot(snapshot,before);result.RestoreSnapshot(snapshot,after);
            check(File.ReadAllBytes(Path.Combine(before,"data.bin")).SequenceEqual(File.ReadAllBytes(Path.Combine(after,"data.bin"))),"resumed independent restore matches original bytes");
        }
        // Untrusted metadata in the old attempt must never replace cloud metadata.
        File.WriteAllText(Path.Combine(partial,"repo.json"),"invalid old configuration");
        File.WriteAllText(Path.Combine(partial,"snapshots",snapshot+".snap"),"invalid old manifest");
        cloud.Reset();await transfer.DownloadSnapshotAsync(snapshot,password,fresh("fresh-metadata"),null,default,partial);
        check(cloud.Reads.Count==3,"old metadata ignored; authenticated local object still reused");
        original[^1]^=1;File.WriteAllBytes(chunks.Single(),original);
        cloud.Reset();await transfer.DownloadSnapshotAsync(snapshot,password,fresh("repair"),null,default,partial);
        check(cloud.Reads.Count==4&&cloud.Reads.Contains(reusedName),"corrupt local ciphertext fetched again");
        check(File.ReadAllBytes(chunks.Single()).SequenceEqual(original),"corrupt old attempt preserved for inspection");
        string otherName=cloud.Files.Keys.Single(n=>n.EndsWith(".obj",StringComparison.Ordinal)&&n!=reusedName);
        File.WriteAllBytes(chunks.Single(),cloud.Files[otherName]);
        cloud.Reset();await transfer.DownloadSnapshotAsync(snapshot,password,fresh("wrong-object"),null,default,partial);
        check(cloud.Reads.Contains(reusedName),"valid ciphertext under a different object ID cannot be reused");
        cloud.Reset();string cancelled=fresh("cancelled");using(var cancel=new CancellationTokenSource())
        {
            cancel.Cancel();bool stopped=false;try{await transfer.DownloadSnapshotAsync(snapshot,password,cancelled,null,cancel.Token,resumed);}catch(OperationCanceledException){stopped=true;}
            check(stopped&&!Directory.Exists(cancelled)&&cloud.Reads.Count==0,"cancel before resume has no output/network");
        }
        cloud.Reset();using(var cancel=new CancellationTokenSource())
        {
            bool stopped=false;string output=fresh("cancel-mid-reuse");
            try{await transfer.DownloadSnapshotAsync(snapshot,password,output,new Immediate(p=>{if(p.Completed==1)cancel.Cancel();}),cancel.Token,resumed);}catch(OperationCanceledException){stopped=true;}
            check(stopped&&Directory.GetFiles(Path.Combine(output,"objects"),"*.obj",SearchOption.AllDirectories).Length==1,"cancel during reuse stops before another object");
        }
        bool overlap=false;try{await transfer.DownloadSnapshotAsync(snapshot,password,Path.Combine(resumed,"nested"),null,default,resumed);}catch(IOException){overlap=true;}
        check(overlap&&!Directory.Exists(Path.Combine(resumed,"nested")),"overlap with old download refused before writes");
        cloud.Reset();cloud.Files.Remove(otherName);bool incomplete=false;
        try{await transfer.DownloadSnapshotAsync(snapshot,password,fresh("missing-remote"),null,default,resumed);}catch(InvalidDataException){incomplete=true;}
        check(incomplete,"local cache cannot hide an incomplete cloud listing");
    }
    private sealed class Immediate(Action<CloudProgress> action):IProgress<CloudProgress>{public void Report(CloudProgress value)=>action(value);}
    private sealed class SeedCloud:ICloudVault
    {
        internal Dictionary<string,byte[]> Files=new();internal List<string> Reads=new();internal int FailObject;private int objects;
        internal void Reset(){Reads.Clear();objects=0;FailObject=0;}
        public Task<IReadOnlyList<CloudObject>> ListAsync(CancellationToken token)=>Task.FromResult<IReadOnlyList<CloudObject>>(Files.Select(f=>new CloudObject(f.Key,f.Key,f.Value.Length)).ToArray());
        public async Task<CloudObject> UploadAsync(string name,Stream source,long length,CancellationToken token)
        {using var bytes=new MemoryStream();await source.CopyToAsync(bytes,token);Files.Add(name,bytes.ToArray());return new(name,name,length);}
        public async Task DownloadAsync(CloudObject file,Stream target,long maximumBytes,CancellationToken token)
        {token.ThrowIfCancellationRequested();Reads.Add(file.Name);if(file.Name.EndsWith(".obj",StringComparison.Ordinal)&&++objects==FailObject)throw new IOException("synthetic read interruption");await target.WriteAsync(Files[file.Name],token);}
    }
}
