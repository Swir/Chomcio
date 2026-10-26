using ChomcioRecovery.Core;
using System.Security.Cryptography;

namespace ChomcioRecovery.Desktop;

internal sealed class ProfileEditor : Form
{
    private readonly TextBox name=StudioTheme.Input(), source=StudioTheme.Input(), repository=StudioTheme.Input(), password=StudioTheme.Input(true), confirmation=StudioTheme.Input(true), login=StudioTheme.Input(), cloudPassword=StudioTheme.Input(true);
    private readonly ComboBox destination=new(){DropDownStyle=ComboBoxStyle.DropDownList,BackColor=StudioTheme.Raised,ForeColor=StudioTheme.Ink,FlatStyle=FlatStyle.Flat};
    private readonly CheckBox remember=new(){Text="Zapamiętaj hasła na tym komputerze",AutoSize=true,Checked=true};
    private readonly CheckBox enabled=new(){Text="Kopia aktywna",AutoSize=true,Checked=true};
    private readonly CheckBox atLogon=new(){Text="Rób kopię po zalogowaniu do Windows",AutoSize=true};
    private readonly CheckBox atBoot=new(){Name="BackupAtBoot",Text="Rób kopię po uruchomieniu komputera",AutoSize=true};
    private readonly CheckBox daily=new(){Text="Rób kopię codziennie o",AutoSize=true};
    private readonly CheckBox dated=new(){Name="CloudDateFolders",Text="Foldery w Chomikuj nazwane datą kopii",AutoSize=true};
    private readonly CheckBox protectFolder=new(){Name="ProtectCloudFolder",Text="Dodatkowo chroń folder w Chomikuj hasłem",AutoSize=true};
    private readonly RadioButton automaticKey=new(){Name="GeneratedKeyChoice",Text="Program tworzy losowy klucz",Checked=true,AutoSize=true};
    private readonly RadioButton ownKey=new(){Name="OwnKeyChoice",Text="Używam własnego hasła lub klucza",AutoSize=true};
    private readonly DateTimePicker time=new(){Format=DateTimePickerFormat.Custom,CustomFormat="HH:mm",ShowUpDown=true,Width=95};
    private readonly Label error=StudioTheme.Label("",10,StudioTheme.Amber), title=StudioTheme.Label("",25,null,true), stepLabel=StudioTheme.Label("",9,StudioTheme.Accent,true);
    private readonly Panel body=new(){Dock=DockStyle.Fill,AutoScroll=true};
    private readonly StudioButton next,back;
    private readonly BackupProfile draft;
    private readonly BackupProfile? original;
    private readonly JobSecrets? previous;
    private int step;
    private bool editAccount;
    private readonly BackupDestination? preset;
    private readonly ISystemImagePlanCatalog imagePlans;
    private readonly ComboBox imagePlan=new(){Name="WindowsImagePlan",DropDownStyle=ComboBoxStyle.DropDownList,BackColor=StudioTheme.Raised,ForeColor=StudioTheme.Ink,FlatStyle=FlatStyle.Flat};
    private string? imagePlanError;
    private bool IsWindows=>draft.Content==BackupContent.WindowsSystem;
    private bool KnownKey=>previous is not null&&(previous.VaultPassword.Length>=12||!VaultKeys.CanInitialize(draft));
    internal BackupProfile? ResultProfile {get;private set;}
    internal JobSecrets? ResultSecrets {get;private set;}
    internal bool StartAfterSave{get;private set;}
    internal string ValidationMessage=>error.Text;
    internal int Step=>step;

    internal ProfileEditor(string storeRoot,BackupProfile? profile=null,JobSecrets? account=null,JobSecrets? session=null,BackupDestination? newDestination=null,bool useOwnKey=false,
        BackupContent newContent=BackupContent.Files,ISystemImagePlanCatalog? imagePlans=null)
    {
        original=profile;preset=profile is null?newDestination:null;
        draft=profile is null?new BackupProfile{Destination=newDestination??BackupDestination.Chomikuj,CloudDateFolders=true,ProtectCloudFolder=true}:
            System.Text.Json.JsonSerializer.Deserialize<BackupProfile>(System.Text.Json.JsonSerializer.Serialize(profile))!;
        this.imagePlans=imagePlans??new InstalledSystemImagePlans();
        if(profile is null){draft.Content=newContent;if(IsWindows)draft.Name="Mój Windows";}
        if(IsWindows)
        {
            if(profile is not null)
            {
                if(profile.SystemImagePlanId is not null&&profile.SystemImageCacheRoot is not null)
                    imagePlan.Items.Add(new SystemImagePlanChoice(profile.SystemImagePlanId,profile.SystemImageCacheRoot));
                imagePlan.Enabled=false;
            }
            else try{foreach(var plan in this.imagePlans.List())imagePlan.Items.Add(plan);}
                catch(Exception e)when(e is IOException or UnauthorizedAccessException or ArgumentException or System.Text.Json.JsonException)
                {imagePlanError="Nie można odczytać zatwierdzonych planów Windows. Sprawdź instalację modułu systemowego.";}
            if(imagePlan.Items.Count==1)imagePlan.SelectedIndex=0;
        }
        if(profile?.ProtectedSecrets is not null){try{previous=WindowsSecrets.Unprotect(profile.ProtectedSecrets);}catch(CryptographicException){}}
        previous??=session;
        StudioTheme.Form(this);Text=profile is null?"Nowa kopia • ChomcioRecovery":"Ustawienia kopii • ChomcioRecovery";
        ClientSize=new(680,690);MinimumSize=new(630,640);StartPosition=FormStartPosition.CenterParent;
        var root=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=4,Padding=new(28)};
        root.RowStyles.Add(new(SizeType.Absolute,90));root.RowStyles.Add(new(SizeType.Percent,100));root.RowStyles.Add(new(SizeType.Absolute,65));root.RowStyles.Add(new(SizeType.Absolute,54));Controls.Add(root);
        var header=new Panel{Dock=DockStyle.Fill};stepLabel.Location=new(0,0);title.Location=new(0,28);header.Controls.Add(stepLabel);header.Controls.Add(title);root.Controls.Add(header,0,0);root.Controls.Add(body,0,1);
        error.Dock=DockStyle.Fill;error.AutoSize=false;root.Controls.Add(error,0,2);
        var footer=new FlowLayoutPanel{Dock=DockStyle.Fill,FlowDirection=FlowDirection.RightToLeft};
        next=StudioTheme.Button("Dalej",Advance,true);back=StudioTheme.Button("Wstecz",()=>{step--;Render();});
        var close=StudioTheme.Button("Anuluj",()=>{DialogResult=DialogResult.Cancel;Close();});close.Width=95;back.Width=100;next.Width=220;
        footer.Controls.Add(next);footer.Controls.Add(back);footer.Controls.Add(close);root.Controls.Add(footer,0,3);AcceptButton=next;CancelButton=close;
        name.Text=draft.Name;source.Text=draft.Source;repository.Text=string.IsNullOrWhiteSpace(draft.Repository)?Path.Combine(storeRoot,"vaults",draft.Id):draft.Repository;
        destination.Items.AddRange(new object[]{"Na dysku — lokalnym lub zewnętrznym","Na moim koncie Chomikuj"});destination.SelectedIndex=(int)draft.Destination;
        login.Text=previous?.CloudLogin??account?.CloudLogin??"";
        cloudPassword.Text=previous?.CloudPassword??account?.CloudPassword??"";
        enabled.Checked=draft.Enabled;atLogon.Checked=draft.AtLogon;atBoot.Checked=draft.AtBoot;daily.Checked=draft.Daily;time.Value=DateTime.Today.AddMinutes(Math.Clamp(draft.DailyMinute,0,1439));
        dated.Checked=draft.CloudDateFolders;
        protectFolder.Checked=draft.ProtectCloudFolder;
        // Existing profiles retain their key. A global preference only chooses
        // the initial option when setting up a new copy.
        automaticKey.Checked=!useOwnKey;ownKey.Checked=useOwnKey;
        if(!KnownKey&&original is not null&&!VaultKeys.CanInitialize(draft))
        {automaticKey.Checked=false;ownKey.Checked=true;automaticKey.Enabled=false;}
        if(original is not null){source.ReadOnly=repository.ReadOnly=true;destination.Enabled=false;login.ReadOnly=true;}
        destination.SelectedIndexChanged+=(_,_)=>{if(step==1)Render();};
        automaticKey.CheckedChanged+=(_,_)=>{if(automaticKey.Checked){remember.Checked=true;if(step==2)Render();}};
        ownKey.CheckedChanged+=(_,_)=>{if(ownKey.Checked&&step==2)Render();};
        atLogon.CheckedChanged+=(_,_)=>{if(atLogon.Checked)remember.Checked=true;};daily.CheckedChanged+=(_,_)=>{if(daily.Checked)remember.Checked=true;};
        atBoot.CheckedChanged+=(_,_)=>{if(atBoot.Checked)remember.Checked=true;};
        Render();
    }
    private void Render()
    {
        // Keep field instances so moving back never discards what was entered.
        foreach(var input in new Control[]{name,source,repository,password,confirmation,login,cloudPassword,destination,remember,enabled,atLogon,atBoot,daily,time,automaticKey,ownKey,dated,protectFolder,imagePlan})input.Parent?.Controls.Remove(input);
        foreach(Control old in body.Controls.Cast<Control>().ToArray()){body.Controls.Remove(old);old.Dispose();}
        error.Text="";back.Visible=step>0;next.Text=step==2?(original is null?(destination.SelectedIndex==1?"Wyślij kopię na Chomikuj":"Wykonaj kopię na dysku"):"Zapisz ustawienia"):"Dalej";
        stepLabel.Text=$"{step+1} Z 3  •  {(step==0?(IsWindows?"TWÓJ WINDOWS":"TWOJE PLIKI"):step==1?"MIEJSCE KOPII":"HASŁO I AUTOMAT")}";
        title.Text=step==0?"Co chcesz chronić?":step==1?"Gdzie zapisać kopię?":"Gotowe. Ustaw ochronę.";
        var fields=new TableLayoutPanel{Dock=DockStyle.Top,AutoSize=true,ColumnCount=1,Padding=new(0,0,12,12)};fields.ColumnStyles.Add(new(SizeType.Percent,100));body.Controls.Add(fields);
        void Field(string label,Control control,int height=40){if(label.Length>0){int r=fields.RowCount++;fields.RowStyles.Add(new(SizeType.Absolute,24));fields.Controls.Add(StudioTheme.Label(label,10,StudioTheme.Muted),0,r);}int row=fields.RowCount++;fields.RowStyles.Add(new(SizeType.Absolute,height+10));control.Dock=DockStyle.Fill;fields.Controls.Add(control,0,row);}
        void Note(string text,int height=60)=>Field("",StudioTheme.Label(text,10,StudioTheme.Muted),height);
        if(step==0)
        {
            if(IsWindows)
            {
                Note("Kopia obejmie Windows, programy, ustawienia oraz partycje\npotrzebne do uruchomienia systemu. Korzystamy z VSS.",60);
                Field("Zatwierdzona konfiguracja systemowa",imagePlan);
                Field("Nazwa kopii",name);
                Note("Obraz powstaje na osobnym dysku roboczym. Następnie\nprogram szyfruje go, wysyła i sprawdza w wybranym miejscu.\nPotrzebujesz wolnego miejsca także podczas wysyłania.",75);
                if(imagePlan.Items.Count==0)
                {
                    Note(imagePlanError??"Przygotuj moduł systemowy. Wymaga osobnego, pustego\ndysku NTFS i zatwierdzenia administratora.",55);
                    if(original is null)Field("",StudioTheme.Button("Przygotuj moduł Windows",()=>
                    {
                        using var setup=new ImageWorkerSetupWindow();
                        if(setup.ShowDialog(this)!=DialogResult.OK)return;
                        imagePlan.Items.Clear();imagePlanError=null;
                        foreach(var plan in imagePlans.List())imagePlan.Items.Add(plan);
                        if(imagePlan.Items.Count==1)imagePlan.SelectedIndex=0;
                        Render();
                    }),40);
                }
            }
            else
            {
            Note("Wybierz folder. Program zachowa jego kolejne wersje,\nżeby można było wrócić do wcześniejszych plików.");
            Field("Folder do skopiowania",BrowseLine(source,()=>PickFolder(source,false),original is null));
            Field("Nazwa kopii",name);
            Note("Dokumenty, zdjęcia, projekty — zacznij od jednego folderu.\nSystemowe odsyłacze do innych folderów pomijamy;\nlista pominięć będzie widoczna w wyniku kopii.",75);
            }
        }
        else if(step==1)
        {
            if(preset is null)Field("Miejsce kopii",destination);
            else Field("Miejsce kopii",StudioTheme.Label(preset==BackupDestination.Chomikuj?"Twoje konto Chomikuj":"Wybrany dysk",18,null,true));
            if(destination.SelectedIndex==1)
            {
                Note(cloudPassword.Text.Length>0?"Konto jest zapamiętane. Możesz od razu przejść dalej.":"Zaloguj się raz. Przy następnych kopiach program użyje\nzapamiętanego konta.",42);
                if(cloudPassword.Text.Length==0||editAccount)
                { Field("Login Chomikuj",login);Field("Hasło Chomikuj",cloudPassword); }
                else
                {
                    Field("Zapamiętane konto",StudioTheme.Label(login.Text,17,null,true),34);
                    Field("",StudioTheme.Button("Zmień dane konta",()=>{editAccount=true;Render();}),34);
                }
                Field("",dated,28);
                Field("",protectFolder,28);
                Note("Przykład: Chomciore_20_10_2026. Starsze dni pozostają.\nDane zostaną zaszyfrowane przed wysłaniem.",45);
                Note("Hasło folderu tworzymy i zapamiętujemy osobno od klucza.\nKlucz szyfrowania nigdy nie trafia do Chomikuj.",42);

            }
            else
            {
                if(IsWindows)
                    Note("Zaszyfrowany obraz pozostanie na dysku roboczym\nzatwierdzonym podczas przygotowania modułu systemowego.",70);
                else
                {
                Field("Folder na zaszyfrowaną kopię",BrowseLine(repository,()=>PickFolder(repository,true),original is null));
                Note("Najlepiej wybrać inny dysk niż ten z oryginalnymi plikami.\nProgram zapisze kopię w osobnym podfolderze.",70);
                }
            }
        }
        else
        {
            bool known=KnownKey;
            if(known)Note("Hasło lub klucz tej kopii jest już zapamiętany.\nZachowujemy go także dla wcześniejszych wersji.\nAby użyć innego, utwórz nową kopię.",72);
            else
            {
                Field("Jak chronić tę kopię?",automaticKey,26);
                Field("",ownKey,26);
                if(!automaticKey.Checked)
                {
                    if(!automaticKey.Enabled)Note("Wpisz dotychczasowe hasło lub klucz tego sejfu.\nWygenerowanie nowego nie odblokuje istniejącej kopii.",50);
                    Field("Twoje hasło lub klucz — minimum 12 znaków",password,34);
                    Field("Powtórz dokładnie to samo hasło lub klucz",confirmation,34);
                }
                else Note("Nie musisz wymyślać ani wpisywać kolejnego hasła.\nWygenerujemy losowy klucz i zabezpieczymy go na tym PC.",55);
            }
            Field("",remember,28);
            Note("Przycisk „Klucz odzyskiwania” pozwoli zapisać klucz poza PC.\nBędzie potrzebny po awarii lub ponownej instalacji Windows.",54);
            Field("Automatyczne wykonywanie — opcjonalne",atLogon,28);
            Field("",atBoot,28);
            Note("Aby kopie ruszały przed zalogowaniem, w ustawieniach włącz\n„Kopie przy zamkniętym programie”.",46);
            var line=new TableLayoutPanel{ColumnCount=2};line.ColumnStyles.Add(new(SizeType.Percent,100));line.ColumnStyles.Add(new(SizeType.Absolute,110));line.Controls.Add(daily,0,0);line.Controls.Add(time,1,0);Field("",line,32);
            if(original is not null)Field("",enabled,28);
            Note("Automat uruchamia program z Windowsem. Bez niego klikasz „Wykonaj kopię”.",33);
        }
    }
    private static Control BrowseLine(TextBox input,Action browse,bool editable)
    {
        var panel=new TableLayoutPanel{ColumnCount=2,RowCount=1};panel.ColumnStyles.Add(new(SizeType.Percent,100));panel.ColumnStyles.Add(new(SizeType.Absolute,100));panel.Controls.Add(input,0,0);
        var button=StudioTheme.Button("Wybierz",browse);button.Enabled=editable;button.Dock=DockStyle.Fill;button.Margin=new(8,0,0,5);panel.Controls.Add(button,1,0);return panel;
    }
    private void PickFolder(TextBox input,bool vault)
    {
        using var dialog=new FolderBrowserDialog{Description=vault?"Wybierz miejsce na zaszyfrowaną kopię.":"Wybierz folder, który chcesz chronić.",UseDescriptionForTitle=true,ShowNewFolderButton=vault};
        if(dialog.ShowDialog(this)!=DialogResult.OK)return;
        input.Text=vault&&!File.Exists(Path.Combine(dialog.SelectedPath,"repo.json"))?Path.Combine(dialog.SelectedPath,"ChomcioVault_"+draft.Id[..8]):dialog.SelectedPath;
        if(!vault&&(name.Text=="Moje dokumenty"||name.Text.Length==0))name.Text=Path.GetFileName(dialog.SelectedPath.TrimEnd(Path.DirectorySeparatorChar));
    }
    internal void Advance()
    {
        try
        {
            if(step==0)
            {
                if(IsWindows)
                {
                    if(original is null)SelectImagePlan();
                }
                else if(!Path.IsPathFullyQualified(source.Text)||!Directory.Exists(source.Text))throw new ArgumentException("Wybierz istniejący folder z plikami przyciskiem „Wybierz”.");
                if(string.IsNullOrWhiteSpace(name.Text)||name.Text.Length>80)throw new ArgumentException("Wpisz krótką nazwę kopii (do 80 znaków).");
            }
            if(step==1&&destination.SelectedIndex==1&&(string.IsNullOrWhiteSpace(login.Text)||cloudPassword.Text.Length==0))throw new ArgumentException("Wpisz login i hasło konta Chomikuj. Program je zapamięta.");
            if(step<2){step++;Render();return;}
            Save();
        }
        catch(Exception e){error.Text=e is ArgumentException?e.Message:JobEngine.SafeError(e);}
    }
    private void Save()
    {
        if(IsWindows&&original is null)SelectImagePlan(); // Revalidate after time spent on the other pages.
        string vaultPassword=KnownKey?previous!.VaultPassword:automaticKey.Checked?VaultKeys.Generate():password.Text;
        if(!KnownKey&&!automaticKey.Checked&&(password.Text.Length<12||string.IsNullOrWhiteSpace(password.Text)||password.Text!=confirmation.Text))throw new ArgumentException(password.Text.Length<12||string.IsNullOrWhiteSpace(password.Text)?"Wpisz hasło lub klucz: minimum 12 znaków, nie same spacje.":"Wpisane hasła lub klucze różnią się. Sprawdź oba pola.");
        if(!KnownKey&&automaticKey.Checked&&!remember.Checked)throw new ArgumentException("Włącz zapamiętanie wygenerowanego klucza albo wybierz własne hasło.");
        var secrets=new JobSecrets(vaultPassword,login.Text.Trim(),cloudPassword.Text,previous?.FolderPassword??
            (destination.SelectedIndex==1&&protectFolder.Checked?VaultKeys.Generate():null));
        draft.Name=name.Text.Trim();
        if(!IsWindows){draft.Source=source.Text.Trim();draft.Repository=repository.Text.Trim();}
        draft.Destination=(BackupDestination)destination.SelectedIndex;
        draft.Enabled=enabled.Checked;draft.AtLogon=atLogon.Checked;draft.AtBoot=atBoot.Checked;draft.Daily=daily.Checked;draft.DailyMinute=time.Value.Hour*60+time.Value.Minute;
        if(draft.PendingSnapshot is not null&&draft.CloudDateFolders!=dated.Checked)
            throw new ArgumentException("Najpierw dokończ przerwane wysyłanie. Potem możesz zmienić sposób nazywania folderów.");
        draft.CloudDateFolders=dated.Checked;
        draft.ProtectCloudFolder=destination.SelectedIndex==1&&protectFolder.Checked;
        if(draft.ProtectCloudFolder&&!remember.Checked)
            throw new ArgumentException("Zaznacz zapamiętanie haseł, aby zachować także losowe hasło folderu Chomikuj.");
        JobEngine.Validate(draft,secrets);
        if((draft.AtLogon||draft.AtBoot||draft.Daily)&&!remember.Checked)throw new ArgumentException("Zaznacz zapamiętanie haseł albo wyłącz automatyczne wykonywanie.");
        if(Directory.Exists(draft.Repository)){using var vault=LocalEncryptedVault.Open(draft.Repository,secrets.VaultPassword);}
        if(original is not null&&(draft.Source!=original.Source||draft.Repository!=original.Repository||draft.Destination!=original.Destination||secrets.CloudLogin!=(previous?.CloudLogin??secrets.CloudLogin)))throw new ArgumentException("Dla innego folderu lub konta dodaj nową kopię w głównym oknie.");
        draft.ProtectedSecrets=remember.Checked?WindowsSecrets.Protect(secrets):null;
        ResultSecrets=secrets;ResultProfile=draft;StartAfterSave=original is null;DialogResult=DialogResult.OK;Close();
    }
    private void SelectImagePlan()
    {
        if(imagePlan.SelectedItem is not SystemImagePlanChoice plan)
            throw new ArgumentException(imagePlanError??(imagePlan.Items.Count==0?
                "Najpierw przygotuj moduł systemowy i osobny dysk roboczy. Kopia nie została rozpoczęta.":"Wybierz zatwierdzony plan Windows."));
        SystemImageProfiles.SelectNewPlan(draft,plan);
        imagePlans.Validate(draft);
    }
}

internal sealed class UnlockDialog : Form
{
    internal JobSecrets? Secrets{get;private set;}
    internal bool Remember{get;private set;}
    internal UnlockDialog(BackupProfile profile,JobSecrets? account=null)
    {
        StudioTheme.Form(this);Text="Odblokuj kopię";ClientSize=new(480,profile.ProtectCloudFolder?520:440);StartPosition=FormStartPosition.CenterParent;FormBorderStyle=FormBorderStyle.FixedDialog;MaximizeBox=false;MinimizeBox=false;
        var content=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new(24),ColumnCount=1};Controls.Add(content);
        var vault=StudioTheme.Input(true);var login=StudioTheme.Input();var pass=StudioTheme.Input(true);var remember=new CheckBox{Text="Zapamiętaj na tym komputerze",Checked=true,AutoSize=true};
        var folderPass=StudioTheme.Input(true);
        content.Controls.Add(StudioTheme.Label(profile.Name,18,null,true));content.Controls.Add(StudioTheme.Label("Hasło szyfrowania kopii",9,StudioTheme.Muted));content.Controls.Add(vault);
        login.Text=account?.CloudLogin??"";pass.Text=account?.CloudPassword??"";
        if(profile.Destination==BackupDestination.Chomikuj){content.Controls.Add(StudioTheme.Label("Login Chomikuj",9,StudioTheme.Muted));content.Controls.Add(login);content.Controls.Add(StudioTheme.Label("Hasło Chomikuj",9,StudioTheme.Muted));content.Controls.Add(pass);}
        if(profile.ProtectCloudFolder){content.Controls.Add(StudioTheme.Label("Osobne hasło folderu — z pliku klucza odzyskiwania",9,StudioTheme.Muted));content.Controls.Add(folderPass);}
        content.Controls.Add(remember);
        var go=StudioTheme.Button("Odblokuj",()=>{Secrets=new(vault.Text,login.Text.Trim(),pass.Text,profile.ProtectCloudFolder?folderPass.Text:null);Remember=remember.Checked;DialogResult=DialogResult.OK;Close();},true);content.Controls.Add(go);AcceptButton=go;
    }
}
