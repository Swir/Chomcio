using ChomcioRecovery.Core;
using ChomcioRecovery.Chomikuj;
using System.Security.Cryptography;

namespace ChomcioRecovery.Desktop;

internal interface IJobCloud : IDisposable
{
    Task<ICloudVault> ConnectAsync(BackupProfile profile,JobSecrets secrets,CancellationToken token);
}
internal sealed class AccountJobCloud : IJobCloud
{
    private readonly ChomikujClient client;
    internal AccountJobCloud(ChomikujClient? client=null){this.client=client??new();}
    public async Task<ICloudVault> ConnectAsync(BackupProfile profile,JobSecrets secrets,CancellationToken token)
    {
        await client.LoginAsync(secrets.CloudLogin,secrets.CloudPassword,token);
        var folders=await client.ListFoldersAsync(token);
        if(profile.CloudDateFolders&&profile.PendingSnapshot is not null)
        {
            string day=profile.PendingCloudDate??throw new IOException("Brak zapamiętanej daty wysyłanej kopii.");
            if(profile.RemoteFolderId is null||profile.RemoteFolderDate!=day)
            {
                // Each day is an independent, complete encrypted export.
                // A same-named folder is never adopted, overwritten or removed.
                var next=await client.CreateFolderAsync(CloudFolderPlan.Name(day,profile.Id,folders),token);
                if(profile.RemoteFolderId is not null&&profile.RemoteFolderName is not null)
                    profile.ArchivedCloudFolders.Add(new(profile.RemoteFolderId,profile.RemoteFolderName));
                profile.RemoteFolderId=next.Id;profile.RemoteFolderName=next.Name;profile.RemoteFolderDate=day;
                profile.RemoteFolderHasConfirmedCopy=false;
                folders=folders.Append(next).ToArray();
            }
        }
        ChomikujFolder folder;
        if(profile.RemoteFolderId is not null)
            folder=folders.SingleOrDefault(f=>f.Id==profile.RemoteFolderId && f.Name==profile.RemoteFolderName)
                ??throw new IOException("Nie znaleziono folderu tego zadania na koncie Chomikuj.");
        else
        {
            string name="ChomcioRecovery_"+profile.Id;
            var matches=folders.Where(f=>f.Name==name).ToArray();
            if(matches.Length>1) throw new IOException("Niejednoznaczny folder kopii na koncie.");
            folder=matches.SingleOrDefault()??await client.CreateFolderAsync(name,token);
            profile.RemoteFolderId=folder.Id; profile.RemoteFolderName=folder.Name;
        }
        var remote=client.OpenFolder(folder);
        if(CloudFolderPlan.CanReplaceUnconfirmed(profile))
        {
            // This preflight only distinguishes an accessible folder from the
            // service's explicit unavailable response. Resolving every HTTP
            // length here duplicates the transfer's authenticated verification.
            // Name discovery proves neither completeness nor byte integrity.
            try{await remote.ListNamesAsync(token);}
            catch(ChomikujServiceException error) when(error.Failure==ChomikujFailure.RequestedFilesUnavailable)
            {
                // This folder has NEVER held a confirmed point in this profile.
                // Do not declare it empty or write into ambiguous contents.
                // Preserve its association and use a separately created folder.
                if(profile.PreviousUnconfirmedCloudFolders.Count>=3)
                    throw new IOException("Chomikuj nie potwierdza początkowego wysyłania po trzech próbach. Zachowano wszystkie poprzednie foldery. Sprawdź konto przed ponowieniem.");
                string replacementName=profile.CloudDateFolders
                    ?CloudFolderPlan.Name(profile.PendingCloudDate!,profile.Id,await client.ListFoldersAsync(token))
                    :"ChomcioRecovery_"+profile.Id+"_"+Guid.NewGuid().ToString("N")[..8];
                var replacement=await client.CreateFolderAsync(replacementName,token);
                profile.PreviousUnconfirmedCloudFolders.Add(new(folder.Id,folder.Name));
                profile.RemoteFolderId=replacement.Id;profile.RemoteFolderName=replacement.Name;
                remote=client.OpenFolder(replacement);
            }
        }
        if(profile.ProtectCloudFolder)
            await client.EnsureFolderPasswordAsync(new(profile.RemoteFolderId!,profile.RemoteFolderName!),
                secrets.FolderPassword??throw new IOException("Brak zapamiętanego hasła folderu Chomikuj."),token);
        return remote;
    }
    public void Dispose()=>client.Dispose();
}

internal sealed class JobEngine
{
    private readonly StudioStore store;
    private readonly Func<IJobCloud> cloudFactory;
    private readonly ISystemImageCapture systemImages;
    private readonly SemaphoreSlim gate=new(1,1);
    private CancellationTokenSource? active;
    private TaskCompletionSource completion=new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal bool IsBusy=>active is not null;
    internal string Phase { get; private set; }="Gotowy do pracy";
    internal string ActiveName { get; private set; }="";
    internal int CompletedRecords { get; private set; }
    internal int TotalRecords { get; private set; }
    internal VaultProgress? LocalProgress { get; private set; }
    internal event Action? Changed;
    internal event Action<RunRecord>? Finished;
    internal Task Completion=>IsBusy?completion.Task:Task.CompletedTask;
    internal JobEngine(StudioStore store,Func<IJobCloud>? cloudFactory=null,ISystemImageCapture? systemImages=null)
    { this.store=store; this.cloudFactory=cloudFactory??(()=>new AccountJobCloud()); this.systemImages=systemImages??new InstalledSystemImageCapture(); }
    internal void Cancel(){ if(active is not null){ Phase="Kończenie operacji…"; active.Cancel(); Changed?.Invoke(); } }
    internal static void Validate(BackupProfile profile,JobSecrets secrets)
    {
        if(string.IsNullOrWhiteSpace(profile.Name)||profile.Name.Length>80) throw new ArgumentException("Podaj nazwę zadania (do 80 znaków).");
        if(!Path.IsPathFullyQualified(profile.Repository))throw new ArgumentException("Wybierz pełną ścieżkę sejfu.");
        if(!Enum.IsDefined(profile.Destination))throw new ArgumentException("Niepoprawne miejsce docelowe kopii.");
        if(!Enum.IsDefined(profile.Content))throw new ArgumentException("Niepoprawny rodzaj kopii.");
        if(profile.Content==BackupContent.Files)
        {
            if(profile.SystemImagePlanId is not null||profile.PendingSystemImage is not null||profile.SystemImageCacheRoot is not null)
                throw new InvalidDataException("Zadanie plików zawiera stan obrazu Windows.");
            if(!Path.IsPathFullyQualified(profile.Source))throw new ArgumentException("Wybierz pełną ścieżkę źródła.");
            if(!Directory.Exists(profile.Source)) throw new DirectoryNotFoundException("Wybierz istniejący folder z plikami.");
            string source=Path.GetFullPath(profile.Source).TrimEnd(Path.DirectorySeparatorChar);
            string repo=Path.GetFullPath(profile.Repository).TrimEnd(Path.DirectorySeparatorChar);
            bool Nested(string a,string b)=>a.Equals(b,StringComparison.OrdinalIgnoreCase)||a.StartsWith(b+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase);
            if(Nested(source,repo)||Nested(repo,source)) throw new ArgumentException("Kopia musi być zapisana poza folderem z oryginalnymi plikami.");
            if(Path.GetPathRoot(profile.Source)!.TrimEnd(Path.DirectorySeparatorChar).Equals(source,StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Dla całego dysku użyj modułu obrazu Windows. W tym zadaniu wybierz folder z plikami.");
            StudioStore.RejectLinks(profile.Source);
        }
        else if(!Guid.TryParseExact(profile.SystemImagePlanId,"N",out _)||profile.Source.Length!=0)
            throw new ArgumentException("Obraz Windows wymaga zatwierdzonego planu systemowego, a nie folderu źródłowego.");
        StudioStore.RejectLinks(profile.Repository);
        if(string.IsNullOrWhiteSpace(secrets.VaultPassword)) throw new ArgumentException("Podaj hasło szyfrowania kopii.");
        if(secrets.VaultPassword.Length<12&&!File.Exists(Path.Combine(profile.Repository,"repo.json")))
            throw new ArgumentException("Klucz kopii jest za krótki. W ustawieniach kopii włącz generowanie klucza przez program.");
        if(profile.Destination==BackupDestination.Chomikuj && (string.IsNullOrWhiteSpace(secrets.CloudLogin)||string.IsNullOrEmpty(secrets.CloudPassword)))
            throw new ArgumentException("Podaj login i hasło Chomikuj.");
        if(profile.ProtectCloudFolder&&(secrets.FolderPassword is not {Length:>=16 and <=64}||
            !secrets.FolderPassword.All(char.IsAsciiLetterOrDigit)))
            throw new ArgumentException("Podaj osobne hasło folderu z pliku klucza odzyskiwania.");
        if(profile.ProtectCloudFolder&&secrets.FolderPassword==secrets.VaultPassword)
            throw new ArgumentException("Hasło folderu Chomikuj musi być inne niż klucz szyfrowania.");
        if(profile.DailyMinute is <0 or >=1440) throw new ArgumentException("Niepoprawna godzina harmonogramu.");
    }
    internal async Task<RunRecord?> RunAsync(BackupProfile profile,JobSecrets secrets,DateTimeOffset now,string? logon=null,string? boot=null)
    {
        if(!await gate.WaitAsync(0)) return null;
        using var cancellation=new CancellationTokenSource();
        active=cancellation; completion=new(TaskCreationOptions.RunContinuationsAsynchronously);
        ActiveName=profile.Name; CompletedRecords=TotalRecords=0;LocalProgress=null;
        var record=new RunRecord{ProfileId=profile.Id,Name=profile.Name,Started=now,State=RunState.Running,Content=profile.Content};
        try
        {
            SchedulePolicy.MarkAttempt(profile,now,logon,boot);
            store.Data.History.Add(record); store.Save();
            secrets=VaultKeys.Prepare(store,profile,secrets);
            Validate(profile,secrets);
            SetPhase("Przygotowanie zaszyfrowanej kopii");
            var token=cancellation.Token;
            string snapshot=await PrepareSnapshotAsync(profile,secrets,now,token);
            record.ImageCaptureId=profile.PendingSystemImage?.CaptureId;
            record.Snapshot=snapshot;
            using(var vault=LocalEncryptedVault.Open(profile.Repository,secrets.VaultPassword))
            { var info=vault.ReadSnapshot(snapshot); record.Files=info.Files.Count; record.Bytes=info.Files.Sum(f=>f.Size);record.SkippedSystemDirectoryLinks=info.SkippedSystemDirectoryLinks??new(); }
            if(profile.Destination==BackupDestination.Chomikuj)
            {
                // Persist this point before network I/O. A restart resumes the
                // same immutable export, not a new unrelated snapshot.
                if(profile.PendingCloudDate is null||profile.Content==BackupContent.Files&&profile.PendingSnapshot is null)
                    profile.PendingCloudDate=CloudFolderPlan.Day(now);
                profile.PendingSnapshot=snapshot; store.Save();
                string? prepared=SystemImageStorage.FindPreparedTransfer(store,profile,snapshot,token);
                SetPhase("Łączenie z Chomikuj");
                int previousFolders=profile.PreviousUnconfirmedCloudFolders.Count;
                using var connection=cloudFactory();
                var remote=await connection.ConnectAsync(profile,secrets,token); store.Save();
                if(profile.PreviousUnconfirmedCloudFolders.Count>previousFolders)
                    SetPhase("Wysyłanie do nowego folderu; poprzedni folder zachowano");
                SetPhase("Przygotowanie plików do wysłania");
                var progress=new InlineCloudProgress(p=>
                {
                    if(!ReferenceEquals(active,cancellation)) return;
                    LocalProgress=null;Phase=p.Phase; CompletedRecords=p.Completed; TotalRecords=p.Total; Changed?.Invoke();
                });
                var reportedRemote=new ListingProgressVault(remote,()=>SetPhase("Sprawdzanie listy i rozmiarów plików w chmurze"));
                var transfer=new CloudVaultTransfer(reportedRemote);
                if(prepared is not null)
                    await transfer.UploadPreparedSnapshotAsync(profile.Repository,secrets.VaultPassword,snapshot,prepared,progress,token,LocalObserver(token));
                else
                {
                    string staging=SystemImageStorage.TransferDirectory(store,profile,Guid.NewGuid().ToString("N"));
                    Directory.CreateDirectory(Path.GetDirectoryName(staging)!);
                    await transfer.UploadSnapshotAsync(profile.Repository,secrets.VaultPassword,snapshot,staging,progress,token,LocalObserver(token));
                }
            }
            profile.LastSuccess=DateTimeOffset.UtcNow; profile.LastSnapshot=snapshot; profile.PendingSnapshot=null;profile.PendingCloudDate=null;
            profile.PendingSystemImage=null;
            if(profile.Destination==BackupDestination.Chomikuj)profile.RemoteFolderHasConfirmedCopy=true;
            record.State=RunState.Success; record.Detail=profile.Destination==BackupDestination.Chomikuj?
                "Zaszyfrowano, wysłano i porównano dane pobrane z Chomikuj.":"Zaszyfrowano i zweryfikowano zapisane dane.";
            if(profile.Content==BackupContent.WindowsSystem)
                record.Detail+=" Zapisano obraz Windows/VSS. Uruchomienie po odtworzeniu tej konkretnej kopii nie było testowane.";
            if(record.SkippedSystemDirectoryLinks.Count>0)record.Detail+=$" Pominięte systemowe odsyłacze: {record.SkippedSystemDirectoryLinks.Count}. Lista w historii.";
        }
        catch(OperationCanceledException) when(cancellation.IsCancellationRequested)
        { record.State=RunState.Cancelled; record.Detail=profile.Content==BackupContent.WindowsSystem?
            "Wstrzymano oczekiwanie i wysyłanie. Windows może nadal bezpiecznie kończyć rozpoczęty obraz; wznowienie sprawdzi jego stan. Starsze kopie pozostają.":
            "Zatrzymano zadanie. Wcześniejsze kopie pozostały; lokalny punkt i ukończone fragmenty mogą zostać wznowione."; }
        catch(Exception error)
        {
            record.State=RunState.Failed;record.FailureStage=Phase;
            record.FailureCode=FailureId(error);
            if(error is ChomikujClient.CloudHttpException http)
            {
                record.HttpStatus=(int)http.StatusCode;
                record.RetryAfterSeconds=http.RetryAfter?.TotalSeconds;
                record.HttpOperation=http.Operation==ChomikujClient.HttpOperation.Unknown?null:http.Operation.ToString();
            }
            if(ChomikujClient.GetTransportFailure(error) is {} transport)
            {
                record.TransportError=transport.Error.ToString();
                record.HttpOperation=transport.Operation==ChomikujClient.HttpOperation.Unknown?null:transport.Operation.ToString();
                record.NativeErrorCode=transport.NativeErrorCode;
                record.CauseHResult=transport.CauseHResult;
                record.CauseKind=transport.CauseKind;
            }
            record.Detail=SafeError(error)+" Etap: "+record.FailureStage+" ["+record.FailureCode+"].";
        }
        finally
        {
            record.Finished=DateTimeOffset.UtcNow;
            if(!store.Data.History.Contains(record)) store.Data.History.Add(record);
            try { store.Save(); }
            catch(Exception) { record.State=RunState.Failed; record.Detail="Nie zapisano historii zadania. Sprawdź dostęp i wolne miejsce w folderze ustawień."; }
            active=null; Phase="Gotowy do pracy"; ActiveName="";LocalProgress=null;CompletedRecords=TotalRecords=0; gate.Release(); completion.TrySetResult();
            Changed?.Invoke(); Finished?.Invoke(record);
        }
        return record;
    }
    private async Task<string> PrepareSnapshotAsync(BackupProfile profile,JobSecrets secrets,DateTimeOffset now,CancellationToken token)
    {
        SystemImageLease? image=null;
        string source=profile.Source;
        try
        {
            if(profile.Content==BackupContent.WindowsSystem)
            {
                if(profile.PendingSystemImage is null)
                {
                    if(profile.PendingSnapshot is not null)throw new InvalidDataException("Brak tożsamości wznawianego obrazu.");
                    profile.PendingSystemImage=new(profile.SystemImagePlanId!,Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow);
                    profile.PendingCloudDate=CloudFolderPlan.Day(now);
                    store.Save(); // Persist identity BEFORE asking the capture broker to do work.
                }
                var pending=profile.PendingSystemImage;
                // Enforce the approved off-system volume on fresh captures AND
                // resumed uploads, before opening a vault or contacting a cloud.
                systemImages.ValidateStorage(profile);
                source=SystemImageLease.DirectoryFor(profile,pending);
                string repo=Path.GetFullPath(profile.Repository).TrimEnd(Path.DirectorySeparatorChar);
                if(source.Equals(repo,StringComparison.OrdinalIgnoreCase)||source.StartsWith(repo+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)||
                    repo.StartsWith(source+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Sejf i przygotowywany obraz nie mogą się zawierać.");
                if(profile.PendingSnapshot is null)
                {
                    // The provider reconciles its protected native-job state even
                    // if user staging contains a receipt from an earlier attempt.
                    // File.Exists is not proof of a successful privileged capture.
                    SetPhase("Przygotowanie obrazu Windows/VSS dla tego zadania");
                    await systemImages.CaptureAsync(new(pending.PlanId,pending.CaptureId,pending.RequestedUtc,source),token);
                    token.ThrowIfCancellationRequested();
                    SetPhase("Sprawdzanie ukończonego obrazu Windows");
                    image=await SystemImageLease.OpenAsync(source,pending,token);
                    pending.Proof=image.Proof;
                    store.Save();
                }
            }
            SetPhase("Szyfrowanie i sprawdzanie kopii");
            var localProgress=LocalObserver(token);
            return await Task.Run(()=>
            {
                token.ThrowIfCancellationRequested();
                if(!Directory.Exists(profile.Repository))
                {
                    if(profile.PendingSnapshot is not null)throw new InvalidDataException("Brak sejfu wznawianego zadania.");
                    LocalEncryptedVault.Initialize(profile.Repository,secrets.VaultPassword);
                }
                using var vault=LocalEncryptedVault.Open(profile.Repository,secrets.VaultPassword);
                string id=profile.PendingSnapshot??vault.BackupDirectory(source,token,
                    profile.Content==BackupContent.Files&&profile.SkipSystemDirectoryLinks,preserveZoneIdentifiers:true,progress:localProgress).SnapshotId;
                vault.VerifySnapshot(id,token,localProgress);
                if(profile.Content==BackupContent.WindowsSystem)
                    SystemImageLease.VerifySnapshot(vault.ReadSnapshot(id,token),profile.PendingSystemImage!);
                return id;
            });
        }
        finally{image?.Dispose();}
    }
    private IProgress<VaultProgress> LocalObserver(CancellationToken token)=>new InlineVaultProgress(p=>
    {
        if(token.IsCancellationRequested)return;
        LocalProgress=p;CompletedRecords=TotalRecords=0;
        Phase=p.Stage switch
        {
            VaultProgressStage.Encrypting=>"Przygotowanie zaszyfrowanych danych",
            VaultProgressStage.CheckingStoredData=>"Kontrola zapisanych danych",
            VaultProgressStage.CheckingSource=>"Porównanie z oryginałem",
            VaultProgressStage.CheckingPublishedData=>"Kontrola zapisanego punktu kopii",
            VaultProgressStage.CheckingSourceAfterPublish=>"Końcowe porównanie z oryginałem",
            VaultProgressStage.CheckingExportSource=>"Sprawdzanie kopii przed przygotowaniem wysyłania",
            VaultProgressStage.CopyingEncryptedExport=>"Przygotowanie zaszyfrowanych plików do wysłania",
            VaultProgressStage.CheckingExportData=>"Sprawdzanie przygotowanych plików",
            VaultProgressStage.CheckingExportBeforePublish=>"Kontrola kompletności przed wysyłaniem",
            VaultProgressStage.CheckingExportWithLeases=>"Kontrola zabezpieczonych plików przed wysyłaniem",
            VaultProgressStage.CheckingPublishedExport=>"Końcowa kontrola plików do wysłania",
            _=>"Sprawdzanie kompletności lokalnej kopii"
        };
        Changed?.Invoke();
    });
    private sealed class InlineVaultProgress(Action<VaultProgress> report):IProgress<VaultProgress>
    {public void Report(VaultProgress value)=>report(value);}
    // FailureStage must be set before a synchronous/fast remote failure, not
    // later by a queued progress callback. UI listeners already marshal updates.
    private sealed class InlineCloudProgress(Action<CloudProgress> report):IProgress<CloudProgress>
    {public void Report(CloudProgress value)=>report(value);}
    private sealed class ListingProgressVault(ICloudVault inner,Action report):ICloudVault
    {
        public Task<IReadOnlyList<CloudObject>> ListAsync(CancellationToken token)
        {report();return inner.ListAsync(token);}
        public Task<IReadOnlyList<string>> ListNamesAsync(CancellationToken token)=>inner.ListNamesAsync(token);
        public Task<CloudObject> UploadAsync(string name,Stream input,long length,CancellationToken token)
            =>inner.UploadAsync(name,input,length,token);
        public Task DownloadAsync(CloudObject file,Stream output,long maximumBytes,CancellationToken token)
            =>inner.DownloadAsync(file,output,maximumBytes,token);
    }
    private void SetPhase(string phase){ LocalProgress=null;CompletedRecords=TotalRecords=0;Phase=phase; Changed?.Invoke(); }
    internal static string FailureId(Exception error)=>error switch
    {
        SystemImageCaptureUnavailableException=>"SYSTEM-CAPTURE-NOT-INSTALLED",
        SystemImageCaptureFailedException e=>e.Interrupted?"SYSTEM-CAPTURE-INTERRUPTED":"SYSTEM-CAPTURE-FAILED",
        ChomikujServiceException e=>"CLOUD-"+e.Operation+"-"+e.Failure,
        ChomikujReadException e=>"CLOUD-READ-"+e.Failure,
        ChomikujFolderProtectionException e=>e.DifferentPassword?"CLOUD-FOLDER-PASSWORD":"CLOUD-FOLDER-PROTECTION",
        IOException {InnerException:System.ComponentModel.Win32Exception native}=>"WINDOWS-"+native.NativeErrorCode,
        InvalidDataException=>"INTEGRITY",
        CryptographicException=>"KEY-OR-DATA",
        UnauthorizedAccessException=>"ACCESS",
        OperationCanceledException=>"TIMEOUT",
        _=>"FAILED-"+error.GetType().Name
    };
    internal static string SafeError(Exception error)=>error switch
    {
        SystemImageCaptureUnavailableException e=>e.Message,
        SystemImageCaptureFailedException e=>e.Interrupted?
            "Po przerwaniu modułu Windows nie potwierdzono końca obrazu. Zablokowano ponowne tworzenie i wysyłanie do czasu sprawdzenia; dane zachowano.":
            "Moduł Windows nie potwierdził obrazu"+(e.NativeExitCode is null?"":" (kod "+e.NativeExitCode+")")+". Nie rozpoczęto wysyłania; dane zachowano.",
        CryptographicException=>"Nie odblokowano kopii lub wykryto uszkodzenie szyfrowanych danych. Sprawdź hasło i kopię.",
        UnauthorizedAccessException=>"Brak dostępu do folderu. Sprawdź uprawnienia i podłączenie dysku.",
        DirectoryNotFoundException=>"Folder źródłowy lub dysk kopii jest niedostępny.",
        ChomikujServiceException e=>e.Message,
        ChomikujClient.CloudHttpException e=>"Chomikuj: błąd HTTP "+(int)e.StatusCode+". Kopia pozostaje do wznowienia."+
            (e.RetryAfter is {TotalSeconds:>0} delay?" Serwer zaleca odczekać co najmniej "+Math.Ceiling(delay.TotalSeconds)+" s.":""),
        ChomikujReadException e=>e.Message,
        IOException e when ChomikujClient.GetTransportFailure(e) is not null=>
            "Przerwano połączenie z Chomikuj. Nie potwierdzono operacji; kopia pozostaje do wznowienia.",
        ChomikujFolderProtectionException e=>e.Message,
        OperationCanceledException=>"Serwer nie odpowiedział w wyznaczonym czasie. Ponów zadanie.",
        IOException {InnerException:System.ComponentModel.Win32Exception native}=>
            "Windows nie pozwolił przygotować bezpiecznego zapisu (kod "+native.NativeErrorCode+"). Zachowano wcześniejsze kopie.",
        InvalidDataException=>"Kontrola danych lub odpowiedzi serwera nie powiodła się. Nie oznaczono kopii jako gotowej.",
        IOException e when e.Message.Contains("(WebSession)",StringComparison.Ordinal)=>
            "Chomikuj nie udostępnił sesji wysyłania. Połącz konto ponownie i ponów zadanie.",
        IOException e when e.Message.Contains("(WebUploadUrl)",StringComparison.Ordinal)=>
            "Chomikuj nie udostępnił adresu wysyłania. Sprawdź konto i ponów zadanie.",
        IOException e when e.Message.Contains("(WebUploadResult)",StringComparison.Ordinal)=>
            "Chomikuj nie potwierdził wysłania pliku. Kopia pozostaje do wznowienia.",
        IOException e when e.Message.StartsWith("Chomikuj nie potwierdza początkowego wysyłania po trzech próbach.",StringComparison.Ordinal)=>e.Message,
        ArgumentException e when e.Message.StartsWith("Klucz kopii jest za krótki",StringComparison.Ordinal)=>e.Message,
        IOException e when e.Message.StartsWith("Source contains an unsupported reparse point:",StringComparison.Ordinal)||
            e.Message.StartsWith("Symlinks/junctions are not supported:",StringComparison.Ordinal)=>
            "Folder zawiera odsyłacz do innych danych. Standardowe łącza systemowe pomijamy, pozostałe wymagają wyboru rzeczywistego folderu źródłowego.",
        // Raw paths and exceptions may contain signed URLs or other secrets.
        _=>"Operacja nie została potwierdzona. Sprawdź foldery, miejsce na dysku i połączenie; poprzednich kopii nie usunięto."
    };
}
