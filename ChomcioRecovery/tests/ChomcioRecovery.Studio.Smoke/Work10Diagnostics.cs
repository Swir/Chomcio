using ChomcioRecovery.Desktop;
using ChomcioRecovery.Core;
using System.Diagnostics;
using ChomcioRecovery.Chomikuj;
using System.Reflection;
using System.Xml.Linq;
using System.Security.Cryptography;
using System.Text.Json;

internal static class Work10Diagnostics
{
    internal static async Task Run(string root,bool productionLocation=false)
    {
        var store=new StudioStore(StudioStore.DefaultRoot);
        int index=0;
        foreach(var profile in store.Data.Profiles.Where(p=>p.PendingSnapshot is not null))
        {
            string stage="open";index++;
            try
            {
                var secrets=WindowsSecrets.Unprotect(profile.ProtectedSecrets!);
                using var vault=LocalEncryptedVault.Open(profile.Repository,secrets.VaultPassword);
                stage="verify";vault.VerifySnapshot(profile.PendingSnapshot!);
                var manifest=vault.ReadSnapshot(profile.PendingSnapshot!);
                Console.WriteLine($"PROFILE {index} verified files={manifest.Files.Count} version={manifest.Version}");
                stage="export";
                string export=productionLocation
                    ?Path.Combine(store.Root,"transfers",profile.Id,Guid.NewGuid().ToString("N"))
                    :Path.Combine(root,"encrypted-export-"+index);
                Directory.CreateDirectory(Path.GetDirectoryName(export)!);
                vault.ExportEncryptedSnapshot(profile.PendingSnapshot!,export);
                Console.WriteLine($"PROFILE {index} encrypted export PASS");
                if(profile.RemoteFolderId is null)continue; // Diagnostic never creates a remote folder.
                stage="cloud-connect";
                using var client=new ChomikujClient();
                await client.LoginAsync(secrets.CloudLogin,secrets.CloudPassword,default);
                var folders=await client.ListFoldersAsync(default);
                var folder=folders.Single(f=>f.Id==profile.RemoteFolderId&&f.Name==profile.RemoteFolderName);
                var cloud=client.OpenFolder(folder);
                stage="cloud-list";
                var files=await cloud.ListAsync(default);
                Console.WriteLine($"PROFILE {index} cloud list PASS records={files.Count}");
            }
            catch(Exception error)
            {
                Console.WriteLine($"PROFILE {index} FAIL stage={stage} type={error.GetType().Name} hresult={error.HResult:X8}");
                Describe(error);
                foreach(var frame in new StackTrace(error,true).GetFrames().Take(10))
                    Console.WriteLine($"  {frame.GetMethod()?.DeclaringType?.Name}.{frame.GetMethod()?.Name} line={frame.GetFileLineNumber()}");
                // Deliberately omit exception text: it can contain private paths
                // or signed URLs. No credentials, names or plaintext are logged.
            }
        }
    }
    private static void Describe(Exception error)
    {
        if(error.Data.Contains("ExtendedFileId"))Console.WriteLine("EXTENDED_FILE_ID="+error.Data["ExtendedFileId"]);
        for(Exception? item=error;item is not null;item=item.InnerException)
            if(item is System.ComponentModel.Win32Exception native)Console.WriteLine("WIN32 "+native.NativeErrorCode);
        if(error is ChomikujServiceException service)Console.WriteLine($"SERVICE {service.Operation}/{service.Failure}");
        foreach(string code in new[]{"WebSession","WebUploadUrl","WebUploadResult","WebJson","SecureConnectionError","HTTP","niepotwierdzone","tożsamości"})
            if(error.Message.Contains(code,StringComparison.OrdinalIgnoreCase))Console.WriteLine("CATEGORY "+code);
    }
    internal static async Task Fresh(string root)
    {
        var store=new StudioStore(StudioStore.DefaultRoot);
        var account=StudioCredentials.Account(store)!;
        string repo=Path.Combine(root,"vault"),source=Path.Combine(root,"source");
        Directory.CreateDirectory(source);File.WriteAllText(Path.Combine(source,"synthetic.txt"),"Synthetic WORK11 cloud diagnosis only");
        string key=VaultKeys.Generate();LocalEncryptedVault.Initialize(repo,key);
        string snapshot;using(var vault=LocalEncryptedVault.Open(repo,key))snapshot=vault.BackupDirectory(source).SnapshotId;
        using var client=new ChomikujClient();
        client.Diagnostics=new SyncProgress<string>(line=>Console.WriteLine(line));
        try
        {
            await client.LoginAsync(account.CloudLogin,account.CloudPassword,default);
            var folder=await client.CreateFolderAsync("ChomcioRecovery_Test_WORK11_"+Guid.NewGuid().ToString("N"),default);
            await new CloudVaultTransfer(client.OpenFolder(folder)).UploadSnapshotAsync(repo,key,snapshot,Path.Combine(root,"export"),null,default);
            Console.WriteLine("FRESH_UPLOAD=PASS");
        }
        catch(Exception error)
        {
            Console.WriteLine($"FRESH_UPLOAD=FAIL {error.GetType().Name}");Describe(error);
            foreach(var frame in new StackTrace(error,true).GetFrames().Take(8))
                Console.WriteLine($"  {frame.GetMethod()?.DeclaringType?.Name}.{frame.GetMethod()?.Name} line={frame.GetFileLineNumber()}");
        }
    }
    private sealed class SyncProgress<T>(Action<T> report):IProgress<T>
    { public void Report(T value)=>report(value); }
    internal static async Task FolderSchema()
    {
        var store=new StudioStore(StudioStore.DefaultRoot);
        foreach(var profile in store.Data.Profiles.Where(p=>p.RemoteFolderId is not null))
        {
            var account=WindowsSecrets.Unprotect(profile.ProtectedSecrets!);
            using var client=new ChomikujClient();
            await client.LoginAsync(account.CloudLogin,account.CloudPassword,default);
            XNamespace ns="http://chomikuj.pl/";
            string Field(string name)=>(string)typeof(ChomikujClient).GetField(name,BindingFlags.NonPublic|BindingFlags.Instance)!.GetValue(client)!;
            var values=new[]{new XElement(ns+"token",Field("token")),new XElement(ns+"hamsterId",Field("accountId")),
                new XElement(ns+"folderId",profile.RemoteFolderId),new XElement(ns+"depth","1")};
            var call=typeof(ChomikujClient).GetMethod("CallAsync",BindingFlags.Instance|BindingFlags.NonPublic)!;
            var result=await (Task<XElement>)call.Invoke(client,new object[]{"Folders",CancellationToken.None,values})!;
            Console.WriteLine("SCHEMA "+string.Join(",",result.Descendants().Select(e=>e.Name.LocalName).Distinct()));
            foreach(var element in result.Descendants().Where(e=>e.Name.LocalName.Contains("count",StringComparison.OrdinalIgnoreCase)))
                if(long.TryParse(element.Value,out long count))Console.WriteLine("COUNT "+element.Name.LocalName+"="+count);
        }
    }
    private static string UserTestProfile=>Environment.GetEnvironmentVariable("CHOMCIO_ACCEPTANCE_PROFILE_ID")
        ??throw new IOException("Select the explicitly authorized interrupted test profile.");
    internal static async Task ResumeUserTest()
    {
        var store=new StudioStore(StudioStore.DefaultRoot);
        var profile=store.Data.Profiles.Single(p=>p.Id==UserTestProfile);
        if(profile.PendingSnapshot is null||profile.Destination!=BackupDestination.Chomikuj)
            throw new IOException("Expected interrupted test profile is unavailable.");
        string pending=profile.PendingSnapshot;
        var secrets=WindowsSecrets.Unprotect(profile.ProtectedSecrets!);
        var engine=new JobEngine(store);
        int completed=-1;
        engine.Changed+=()=>{if(engine.CompletedRecords!=completed){completed=engine.CompletedRecords;Console.WriteLine($"UPLOAD_RECORDS {completed}/{engine.TotalRecords}");}};
        var result=await engine.RunAsync(profile,secrets,DateTimeOffset.Now);
        if(result?.State!=RunState.Success||result.Snapshot!=pending)
            throw new IOException("User test resume failed: "+result?.FailureCode+" / "+result?.FailureStage);
        Console.WriteLine($"USER_SELECTED_TEST_RESUME=PASS files={result.Files} bytes={result.Bytes} preserved_old_folders={profile.PreviousUnconfirmedCloudFolders.Count}");
    }
    internal static async Task VerifyUserTest(string root)
    {
        var store=new StudioStore(StudioStore.DefaultRoot);
        var profile=store.Data.Profiles.Single(p=>p.Id==UserTestProfile);
        var secrets=WindowsSecrets.Unprotect(profile.ProtectedSecrets!);
        if(profile.LastSnapshot is null||profile.LastSuccess is null)throw new IOException("No successful test point.");
        using var restore=new RestoreSession(store,profile,secrets);
        var points=await restore.ListAsync(true,default);
        if(!points.Any(p=>p.Id==profile.LastSnapshot))throw new IOException("Cloud point missing.");
        string target=Path.Combine(root,"verified-restore");
        await restore.RestoreAsync(profile.LastSnapshot,true,target,null,
            new SyncProgress<CloudProgress>(p=>Console.WriteLine($"RESTORE_RECORDS {p.Completed}/{p.Total}")),default);
        var snapshot=await restore.PrepareAsync(profile.LastSnapshot,true,null,default);
        foreach(var file in snapshot.Files)
        {
            string path=Path.Combine(target,file.Path.Replace('/',Path.DirectorySeparatorChar));
            if(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant()!=file.Sha256)
                throw new IOException("Independent restore hash mismatch.");
            if(file.ZoneIdentifierBase64 is not null&&!File.ReadAllBytes(path+":Zone.Identifier").SequenceEqual(Convert.FromBase64String(file.ZoneIdentifierBase64)))
                throw new IOException("Independent restore metadata mismatch.");
        }
        var proof=new{pass=true,files=snapshot.Files.Count,bytes=snapshot.Files.Sum(f=>f.Size),metadataVersion=snapshot.Version,timeUtc=DateTimeOffset.UtcNow,sourceFilesChanged=false};
        File.WriteAllText(Path.Combine(root,"USER_TEST_RESTORE_PASS.json"),JsonSerializer.Serialize(proof));
        Console.WriteLine("USER_SELECTED_TEST_INDEPENDENT_RESTORE=PASS files="+snapshot.Files.Count);
    }
}
