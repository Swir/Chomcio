using ChomcioRecovery.Core;
using ChomcioRecovery.Chomikuj;

namespace ChomcioRecovery.Desktop;

internal sealed record RestorePoint(string Id,DateTimeOffset? Date)
{
    public override string ToString()=>Date is null?"Kopia "+Id[..12]:Date.Value.ToLocalTime().ToString("dd.MM.yyyy  HH:mm:ss");
}

internal sealed class RestoreSession : IDisposable
{
    private readonly StudioStore store;
    private readonly BackupProfile profile;
    private readonly JobSecrets secrets;
    private ChomikujClient? client;
    private readonly Dictionary<string,CloudVaultTransfer> remotePoints=new();
    private readonly Dictionary<string,string> downloaded=new();
    internal int SkippedSystemLinksCount{get;private set;}
    internal bool PreparedSystemImage{get;private set;}
    internal RestoreSession(StudioStore store,BackupProfile profile,JobSecrets secrets){this.store=store;this.profile=profile;this.secrets=secrets;}
    internal async Task<IReadOnlyList<RestorePoint>> ListAsync(bool cloud,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if(!cloud)return await Task.Run(()=>{using var vault=LocalEncryptedVault.Open(profile.Repository,secrets.VaultPassword);return (IReadOnlyList<RestorePoint>)vault.ListSnapshotIds().Select(id=>new RestorePoint(id,vault.ReadSnapshot(id,token).CreatedUtc)).OrderByDescending(p=>p.Date).ToArray();},token);
        var locations=CloudFolderPlan.All(profile).ToArray();
        if(locations.Length==0)return Array.Empty<RestorePoint>();
        client?.Dispose();client=new ChomikujClient();await client.LoginAsync(secrets.CloudLogin,secrets.CloudPassword,token);
        var folders=await client.ListFoldersAsync(token);
        remotePoints.Clear();
        foreach(var location in locations)
        {
            var folder=folders.SingleOrDefault(f=>f.Id==location.Id&&f.Name==location.Name)??throw new IOException("Brak jednego z folderów kopii na koncie.");
            var remote=new CloudVaultTransfer(client.OpenFolder(folder));
            foreach(string id in await remote.ListSnapshotsAsync(token))remotePoints.TryAdd(id,remote);
        }
        return remotePoints.Keys.Select(id=>new RestorePoint(id,store.Data.History.LastOrDefault(h=>h.ProfileId==profile.Id&&h.Snapshot==id&&h.State==RunState.Success)?.Started)).OrderByDescending(p=>p.Date).ToArray();
    }
    internal async Task<LocalEncryptedVault.Snapshot> PrepareAsync(string id,bool cloud,IProgress<CloudProgress>? progress,CancellationToken token,string? recoveryParent=null)
    {
        string repo=profile.Repository;
        if(cloud)
        {
            if(!remotePoints.TryGetValue(id,out var remote))throw new InvalidOperationException("Najpierw odczytaj listę kopii.");
            if(!downloaded.TryGetValue(id,out repo!))
            {
                if(profile.Content==BackupContent.WindowsSystem&&recoveryParent is null)
                    throw new ArgumentException("Wybierz dysk lub folder do pobrania obrazu Windows.");
                repo=recoveryParent is not null?SystemImageStorage.RecoveryRepository(recoveryParent,Guid.NewGuid().ToString("N")):
                    Path.Combine(store.Root,"restores",Guid.NewGuid().ToString("N"),"encrypted");
                Directory.CreateDirectory(Path.GetDirectoryName(repo)!);
                var cache=new RestoreDownloadCache(store,profile.Id,id,secrets.CloudLogin);
                string? previous=cache.Find();
                // Local authentication can involve many GB. Keep it off the UI
                // thread, even when the transport completes synchronously.
                try{await Task.Run(()=>remote.DownloadSnapshotAsync(id,secrets.VaultPassword,repo,progress,token,previous),token);}
                finally{await Task.Run(()=>cache.Remember(repo));}
                downloaded.Add(id,repo);
            }
        }
        var snapshot=await Task.Run(()=>{using var vault=LocalEncryptedVault.Open(repo,secrets.VaultPassword);vault.VerifySnapshot(id,token);return vault.ReadSnapshot(id,token);},token);
        PreparedSystemImage=profile.Content==BackupContent.WindowsSystem||
            snapshot.Files.Any(f=>f.Path==SystemImageLease.ArchiveName)&&snapshot.Files.Any(f=>f.Path==SystemImageLease.ReceiptName);
        SkippedSystemLinksCount=snapshot.SkippedSystemDirectoryLinks?.Count??0;return snapshot;
    }
    internal async Task RestoreAsync(string id,bool cloud,string target,string? relativeFile,IProgress<CloudProgress>? progress,CancellationToken token)
    {
        if(profile.Content==BackupContent.WindowsSystem&&relativeFile is not null)
            throw new ArgumentException("Pobierz cały zestaw obrazu Windows razem z jego opisem.");
        // Refuse an existing destination before network or plaintext writes.
        if(File.Exists(target)||Directory.Exists(target))throw new IOException("Folder lub plik docelowy już istnieje. Wybierz nową nazwę.");
        await PrepareAsync(id,cloud,progress,token,Path.GetDirectoryName(target));
        if(PreparedSystemImage&&relativeFile is not null)
            throw new ArgumentException("To kopia Windows. Pobierz cały obraz razem z jego opisem.");
        string repo=cloud?downloaded[id]:profile.Repository;
        await Task.Run(()=>{using var vault=LocalEncryptedVault.Open(repo,secrets.VaultPassword);if(relativeFile is null)vault.RestoreSnapshot(id,target,token);else vault.RestoreFile(id,relativeFile,target,token);},token);
        if(PreparedSystemImage)
        {
            var receipt=ChomcioRecovery.SystemImages.BrokerFiles.Read<SystemImageReceipt>(Path.Combine(target,SystemImageLease.ReceiptName));
            if(profile.SystemImagePlanId is not null&&receipt.PlanId!=profile.SystemImagePlanId)throw new InvalidDataException("Pobrany obraz pochodzi z innego planu Windows.");
            using var verified=await SystemImageLease.OpenAsync(target,new(receipt.PlanId,receipt.CaptureId,receipt.RequestedUtc),token);
        }
    }
    public void Dispose()=>client?.Dispose();
}

internal sealed class RestoreWindow : Form,IInlineFeedback
{
    private readonly RestoreSession session;
    private readonly ComboBox origin=new(){DropDownStyle=ComboBoxStyle.DropDownList,BackColor=StudioTheme.Raised,ForeColor=StudioTheme.Ink};
    private readonly ListBox points=new(){BackColor=StudioTheme.Raised,ForeColor=StudioTheme.Ink,BorderStyle=BorderStyle.None};
    private readonly ComboBox files=new(){DropDownStyle=ComboBoxStyle.DropDownList,BackColor=StudioTheme.Raised,ForeColor=StudioTheme.Ink};
    private readonly Label status=StudioTheme.Label("Wczytywanie kopii…",10,StudioTheme.Muted);
    private readonly TextBox parent=StudioTheme.Input();
    private readonly StudioButton restore,loadFiles,stop,prepareImage;
    private string? imageBundle;
    private CancellationTokenSource? active;
    private bool closing;
    private string? prepared;
    private readonly bool systemImage;
    internal RestoreWindow(StudioStore store,BackupProfile profile,JobSecrets secrets)
    {
        systemImage=profile.Content==BackupContent.WindowsSystem;
        session=new(store,profile,secrets);StudioTheme.Form(this);Text=(systemImage?"Pobierz obraz Windows • ":"Przywróć pliki • ")+profile.Name;ClientSize=new(720,690);MinimumSize=new(650,650);StartPosition=FormStartPosition.CenterParent;
        var body=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,Padding=new(28)};Controls.Add(body);
        void Add(Control control,int height){int row=body.RowCount++;body.RowStyles.Add(new(SizeType.Absolute,height));control.Dock=DockStyle.Fill;body.Controls.Add(control,0,row);}
        Add(StudioTheme.Label(systemImage?"Pobierz obraz Windows.":"Wybierz kopię. Odzyskaj pliki.",24,null,true),49);
        Add(StudioTheme.Label(systemImage?"Pobieramy pliki obrazu. Odtworzenie systemu wymaga WinRE.":"Hasła są uzupełnione. Odtwarzamy do nowego folderu.",10,StudioTheme.Muted),33);
        origin.Items.Add("Z kopii na dysku");if(profile.Destination==BackupDestination.Chomikuj)origin.Items.Add("Bezpośrednio z Chomikuj");origin.SelectedIndex=profile.Destination==BackupDestination.Chomikuj?1:0;Add(origin,40);
        Add(points,150);files.Items.Add("Wszystkie pliki i foldery");files.SelectedIndex=0;Add(files,38);
        loadFiles=StudioTheme.AsyncButton("Wybierz pojedynczy plik",LoadFilesAsync);Add(loadFiles,46);loadFiles.Visible=!systemImage;
        Add(StudioTheme.Label("Gdzie przywrócić? Wskaż folder nadrzędny:",10,StudioTheme.Muted),28);
        var line=new TableLayoutPanel{ColumnCount=2};line.ColumnStyles.Add(new(SizeType.Percent,100));line.ColumnStyles.Add(new(SizeType.Absolute,105));line.Controls.Add(parent,0,0);
        var browse=StudioTheme.Button("Wybierz",()=>{using var picker=new FolderBrowserDialog{Description="Odtworzone dane trafią do nowego podfolderu."};if(picker.ShowDialog(this)==DialogResult.OK)parent.Text=picker.SelectedPath;});browse.Dock=DockStyle.Fill;line.Controls.Add(browse,1,0);Add(line,44);
        var actions=new FlowLayoutPanel();restore=StudioTheme.AsyncButton(systemImage?"Pobierz i sprawdź":"Przywróć teraz",RestoreAsync,true);stop=StudioTheme.Button("Zatrzymaj",()=>active?.Cancel());stop.Visible=false;actions.Controls.Add(restore);actions.Controls.Add(stop);Add(actions,52);
        prepareImage=StudioTheme.Button("Przygotuj odzyskiwanie",()=>{if(active is not null||imageBundle is null)return;using var window=new SystemImageRecoveryWindow(imageBundle);window.ShowDialog(this);});prepareImage.Name="PrepareRestoredWindowsImage";prepareImage.Width=230;prepareImage.Visible=false;actions.Controls.Add(prepareImage);
        status.AutoSize=false;Add(status,83);
        origin.SelectedIndexChanged+=async(_,_)=>await LoadAsync();points.SelectedIndexChanged+=(_,_)=>{prepared=null;files.Items.Clear();files.Items.Add("Wszystkie pliki i foldery");files.SelectedIndex=0;};
        Shown+=async(_,_)=>await LoadAsync();FormClosing+=(_,e)=>{if(active is not null){e.Cancel=true;closing=true;active.Cancel();ShowFeedback("Kończenie operacji…");}};FormClosed+=(_,_)=>session.Dispose();
    }
    private bool Cloud=>origin.SelectedIndex==1;
    private IProgress<CloudProgress> Progress()=>new Progress<CloudProgress>(p=>ShowFeedback(p.Phase+"  "+p.Completed+"/"+p.Total));
    private async Task RunAsync(Func<CancellationToken,Task> action)
    {
        if(active is not null)return;
        using var cts=new CancellationTokenSource();active=cts;restore.Enabled=loadFiles.Enabled=origin.Enabled=points.Enabled=files.Enabled=parent.Enabled=false;stop.Visible=true;
        try{await action(cts.Token);}
        catch(OperationCanceledException){ShowFeedback("Zatrzymano. Jeśli wynik już powstał, wymaga ponownego sprawdzenia. Wcześniejsze kopie pozostają.");}
        catch(Exception e){ShowFeedback(e is ArgumentException?e.Message:JobEngine.SafeError(e));}
        finally{active=null;restore.Enabled=loadFiles.Enabled=origin.Enabled=points.Enabled=files.Enabled=parent.Enabled=true;stop.Visible=false;if(closing)Close();}
    }
    private Task LoadAsync()=>RunAsync(async token=>{ShowFeedback("Odczytywanie dostępnych kopii…");var list=await session.ListAsync(Cloud,token);points.Items.Clear();foreach(var point in list)points.Items.Add(point);if(points.Items.Count>0)points.SelectedIndex=0;ShowFeedback(list.Count>0?"Wybierz datę kopii i miejsce przywrócenia.":"Brak ukończonych kopii w tym miejscu.");});
    private Task LoadFilesAsync()=>RunAsync(async token=>
    {
        if(points.SelectedItem is not RestorePoint point){ShowFeedback("Wybierz kopię z listy.");return;}
        if(Cloud&&(!Path.IsPathFullyQualified(parent.Text)||!Directory.Exists(parent.Text))){ShowFeedback("Najpierw wybierz miejsce pobrania kopii. Duży obraz Windows nie trafi na dysk z ustawieniami programu.");return;}
        ShowFeedback("Pobieranie i sprawdzanie kopii…");
        var snapshot=await session.PrepareAsync(point.Id,Cloud,Progress(),token,Cloud?parent.Text:null);
        prepared=point.Id;files.Items.Clear();files.Items.Add("Wszystkie pliki i foldery");
        if(!session.PreparedSystemImage)foreach(var file in snapshot.Files)files.Items.Add(file.Path);
        files.SelectedIndex=0;
        ShowFeedback(session.PreparedSystemImage?"To kopia całego Windows. Pobierz cały zestaw, następnie przygotuj go do odzyskiwania.":"Wybierz pojedynczy plik albo przywróć całość.");
    });
    private Task RestoreAsync()=>RunAsync(async token=>
    {
        if(points.SelectedItem is not RestorePoint point){ShowFeedback("Wybierz kopię z listy.");return;}
        if(!Path.IsPathFullyQualified(parent.Text)||!Directory.Exists(parent.Text)){ShowFeedback("Wybierz istniejący folder przyciskiem „Wybierz”.");return;}
        string? file=files.SelectedIndex>0&&prepared==point.Id?files.SelectedItem as string:null;
        string target=Path.Combine(parent.Text,"Przywrocone_"+DateTime.Now.ToString("yyyyMMdd_HHmmss")+"_"+Guid.NewGuid().ToString("N")[..6]+(file is null?"":Path.GetExtension(file)));
        ShowFeedback("Odtwarzanie i sprawdzanie plików…");await session.RestoreAsync(point.Id,Cloud,target,file,Progress(),token);
        imageBundle=session.PreparedSystemImage?target:null;prepareImage.Visible=imageBundle is not null;
        ShowFeedback((session.PreparedSystemImage?"Pobrano i sprawdzono obraz. Windows nie został jeszcze odtworzony.\n":"Przywrócono i sprawdzono. Pliki są tutaj:\n")+target+
            (session.SkippedSystemLinksCount>0?$"\nKopia pomija systemowe odsyłacze do innych folderów: {session.SkippedSystemLinksCount}.":""));
    });
    public void ShowFeedback(string text){if(!IsDisposed)status.Text=text;}
}

