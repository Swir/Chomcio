using ChomcioRecovery.Chomikuj;

namespace ChomcioRecovery.Desktop;

internal sealed class CloudCatalogWindow : Form,IInlineFeedback
{
    private readonly StudioStore store;
    private readonly JobSecrets account;
    private readonly ListBox folders=new(){Dock=DockStyle.Fill,BackColor=StudioTheme.Raised,ForeColor=StudioTheme.Ink,BorderStyle=BorderStyle.None};
    private readonly TextBox key=StudioTheme.Input(true);
    private readonly Label status=StudioTheme.Label("Odczytywanie folderów z Twojego konta…",10,StudioTheme.Muted);
    private readonly StudioButton open,refresh;
    private readonly CancellationTokenSource lifetime=new();
    private bool loading;
    internal CloudCatalogWindow(StudioStore store,JobSecrets account)
    {
        this.store=store;this.account=account;
        StudioTheme.Form(this);Text="Kopie na moim koncie • ChomcioRecovery";ClientSize=new(760,570);MinimumSize=new(680,540);StartPosition=FormStartPosition.CenterParent;
        var body=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,Padding=new(28)};Controls.Add(body);
        void Add(Control control,int height){int row=body.RowCount++;body.RowStyles.Add(new(SizeType.Absolute,height));control.Dock=DockStyle.Fill;body.Controls.Add(control,0,row);}
        Add(StudioTheme.Label("Twoje kopie, także na innym PC",23,null,true),49);
        Add(StudioTheme.Label("Lista pochodzi z Chomikuj. Wybierz folder z datą kopii.\nKompletność i zawartość sprawdzimy przed przywróceniem.",10,StudioTheme.Muted),57);
        Add(folders,210);
        Add(StudioTheme.Label("Klucz odzyskiwania tej kopii",10,StudioTheme.Muted),27);key.Name="CloudRecoveryKey";Add(key,38);
        var actions=new FlowLayoutPanel();open=StudioTheme.Button("Otwórz i przywróć",Open,true);open.Name="OpenCloudCatalogCopy";
        refresh=StudioTheme.AsyncButton("Odśwież listę",LoadAsync);actions.Controls.Add(open);actions.Controls.Add(refresh);Add(actions,50);
        open.Enabled=refresh.Enabled=false;
        status.AutoSize=false;Add(status,60);
        folders.SelectedIndexChanged+=(_,_)=>PrefillKey();
        Shown+=async(_,_)=>await LoadAsync();
        FormClosing+=(_,_)=>lifetime.Cancel();FormClosed+=(_,_)=>lifetime.Dispose();
    }
    internal static async Task<IReadOnlyList<ChomikujFolder>> DiscoverAsync(JobSecrets account,CancellationToken token)
    {
        using var client=new ChomikujClient();await client.LoginAsync(account.CloudLogin,account.CloudPassword,token);
        return (await client.ListFoldersAsync(token)).Where(f=>f.Name.StartsWith("Chomciore_",StringComparison.Ordinal)||
            f.Name.StartsWith("ChomcioRecovery_",StringComparison.Ordinal)).OrderByDescending(f=>CloudFolderPlan.FolderDate(f.Name)??DateOnly.MinValue)
            .ThenBy(f=>f.Name,StringComparer.Ordinal).ToArray();
    }
    private async Task LoadAsync()
    {
        if(loading)return;loading=true;open.Enabled=refresh.Enabled=false;
        try
        {
            var list=await DiscoverAsync(account,lifetime.Token);
            if(IsDisposed)return;
            folders.Items.Clear();foreach(var folder in list)folders.Items.Add(new Choice(folder));
            if(folders.Items.Count>0)folders.SelectedIndex=0;
            ShowFeedback(list.Count==0?"Na koncie nie znaleziono folderów Chomcio.":"Wybierz kopię. Na nowym PC potrzebujesz jej oryginalnego klucza.");
        }
        catch(OperationCanceledException){if(!IsDisposed)ShowFeedback("Zatrzymano odczyt listy.");}
        catch(Exception e){if(!IsDisposed)ShowFeedback(JobEngine.SafeError(e));}
        finally{loading=false;if(!IsDisposed)open.Enabled=refresh.Enabled=true;}
    }
    private void PrefillKey()
    {
        key.Text="";
        if(folders.SelectedItem is not Choice choice)return;
        foreach(var profile in store.Data.Profiles.Where(p=>p.ProtectedSecrets is not null&&
            CloudFolderPlan.All(p).Any(f=>f.Id==choice.Folder.Id&&f.Name==choice.Folder.Name)))
        {
            try{
                var secrets=WindowsSecrets.Unprotect(profile.ProtectedSecrets!);
                if(secrets.CloudLogin.Equals(account.CloudLogin,StringComparison.OrdinalIgnoreCase)){key.Text=secrets.VaultPassword;break;}
            }catch(System.Security.Cryptography.CryptographicException){}
        }
    }
    private void Open()
    {
        if(folders.SelectedItem is not Choice choice){ShowFeedback("Najpierw wybierz folder kopii.");return;}
        if(string.IsNullOrWhiteSpace(key.Text)){ShowFeedback("Wpisz oryginalny klucz odzyskiwania. Samo hasło konta nie odszyfruje kopii.");return;}
        var profile=new BackupProfile{Name=choice.Folder.Name,Destination=BackupDestination.Chomikuj,
            RemoteFolderId=choice.Folder.Id,RemoteFolderName=choice.Folder.Name,Repository=Path.Combine(store.Root,"remote-only",Guid.NewGuid().ToString("N"))};
        using var restore=new RestoreWindow(store,profile,account with{VaultPassword=key.Text});
        restore.ShowDialog(this);
    }
    public void ShowFeedback(string text){if(!IsDisposed)status.Text=text;}
    private sealed record Choice(ChomikujFolder Folder){public override string ToString()=>Folder.Name;}
}
