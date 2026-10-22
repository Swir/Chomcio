namespace ChomcioRecovery.Desktop;

internal sealed class StudioWindow : Form, IInlineFeedback
{
    private readonly StudioStore store;
    private readonly JobEngine engine;
    private readonly Dictionary<string,JobSecrets> sessionSecrets=new();
    private readonly Panel page=new(){Dock=DockStyle.Fill,Padding=new(30,8,30,12)};
    private readonly Label breadcrumb=StudioTheme.Label("Przegląd ochrony",12);
    private readonly Label operation=StudioTheme.Label("Gotowy do pracy",9,StudioTheme.Muted);
    private readonly ProgressBar progress=new(){Width=180,Height=9,Style=ProgressBarStyle.Marquee};
    private readonly StudioButton cancel;
    private readonly Dictionary<string,StudioButton> navigation=new();
    private string currentPage="Chomikuj";
    internal bool ManualWindowOpen{get;private set;}
    internal event Action? ExitRequested;
    internal bool Preview{get;}

    internal StudioWindow(StudioStore store,JobEngine engine,bool preview=false)
    {
        this.store=store;this.engine=engine;Preview=preview;
        StudioTheme.Form(this);Text="ChomcioRecovery by Swir • 1.0.0";ClientSize=new(1200,820);MinimumSize=new(1000,720);StartPosition=FormStartPosition.CenterScreen;
        var root=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=2,RowCount=1,Margin=Padding.Empty};root.ColumnStyles.Add(new(SizeType.Absolute,224));root.ColumnStyles.Add(new(SizeType.Percent,100));Controls.Add(root);
        var side=new Panel{Dock=DockStyle.Fill,BackColor=StudioTheme.Sidebar,Padding=new(20),Margin=Padding.Empty};root.Controls.Add(side,0,0);
        var sideGrid=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=3,Margin=Padding.Empty};sideGrid.RowStyles.Add(new(SizeType.Absolute,112));sideGrid.RowStyles.Add(new(SizeType.Percent,100));sideGrid.RowStyles.Add(new(SizeType.Absolute,95));side.Controls.Add(sideGrid);
        var brand=new Panel{Dock=DockStyle.Fill,Margin=Padding.Empty};sideGrid.Controls.Add(brand,0,0);
        var logo=new PictureBox{Image=Icon?.ToBitmap(),SizeMode=PictureBoxSizeMode.Zoom,Location=new(1,7),Size=new(43,43)};brand.Controls.Add(logo);
        var word=StudioTheme.Label("Chomcio",19,null,true);word.Location=new(53,1);brand.Controls.Add(word);
        var sub=StudioTheme.Label("RECOVERY  /  by Swir",8,StudioTheme.Muted,true);sub.Location=new(55,36);brand.Controls.Add(sub);
        var menu=new FlowLayoutPanel{Dock=DockStyle.Fill,FlowDirection=FlowDirection.TopDown,WrapContents=false,Padding=new(0,5,0,0),Margin=Padding.Empty,AutoScroll=true};sideGrid.Controls.Add(menu,0,1);
        foreach(string name in new[]{"Chomikuj","Obraz Windows","Moje kopie","Przywróć pliki","Historia","Ustawienia"})
        {
            var item=StudioTheme.Button(name,()=>ShowPage(name));item.Width=182;item.Height=46;item.Margin=new(0,0,0,7);navigation.Add(name,item);menu.Controls.Add(item);
        }
        var sideFooter=new Panel{Dock=DockStyle.Fill,Margin=Padding.Empty};sideGrid.Controls.Add(sideFooter,0,2);
        var version=StudioTheme.Label("v1.0.0  •  kopie plików",8,StudioTheme.Muted);version.Location=new(2,9);sideFooter.Controls.Add(version);
        var trayNote=StudioTheme.Label("Ochrona działa w tle,\ngdy program jest przy zegarze.",8,StudioTheme.Muted);trayNote.Location=new(2,36);sideFooter.Controls.Add(trayNote);
        var main=new TableLayoutPanel{Dock=DockStyle.Fill,RowCount=3,ColumnCount=1,Margin=Padding.Empty};main.RowStyles.Add(new(SizeType.Absolute,88));main.RowStyles.Add(new(SizeType.Percent,100));main.RowStyles.Add(new(SizeType.Absolute,58));root.Controls.Add(main,1,0);
        var top=new Panel{Dock=DockStyle.Fill,Padding=new(30,24,30,12)};breadcrumb.Location=new(30,31);top.Controls.Add(breadcrumb);
        var add=StudioTheme.Button("+  Kopia na Chomikuj",()=>EditProfile(null,BackupDestination.Chomikuj),true);add.Name="NewChomikujBackup";add.Width=218;add.Anchor=AnchorStyles.Top|AnchorStyles.Right;add.Location=new(690,23);top.Controls.Add(add);top.Resize+=(_,_)=>add.Left=top.ClientSize.Width-add.Width-30;main.Controls.Add(top,0,0);main.Controls.Add(page,0,1);
        var bottom=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=3,RowCount=1,Padding=new(30,9,30,9)};bottom.ColumnStyles.Add(new(SizeType.Percent,100));bottom.ColumnStyles.Add(new(SizeType.Absolute,190));bottom.ColumnStyles.Add(new(SizeType.Absolute,118));
        operation.Dock=DockStyle.Fill;operation.AutoSize=false;operation.TextAlign=ContentAlignment.MiddleLeft;bottom.Controls.Add(operation,0,0);progress.Anchor=AnchorStyles.Left;bottom.Controls.Add(progress,1,0);
        cancel=StudioTheme.Button("Zatrzymaj",()=>engine.Cancel());cancel.Width=110;cancel.Height=33;bottom.Controls.Add(cancel,2,0);main.Controls.Add(bottom,0,2);
        engine.Changed+=EngineChanged;engine.Finished+=EngineFinished;FormClosed+=(_,_)=>{engine.Changed-=EngineChanged;engine.Finished-=EngineFinished;};
        ShowPage("Chomikuj");EngineChanged();
    }
    private void EngineChanged()
    {
        if(IsDisposed)return;
        if(InvokeRequired){BeginInvoke(EngineChanged);return;}
        operation.ForeColor=StudioTheme.Muted;
        operation.Text=engine.IsBusy?engine.ActiveName+"  ·  "+engine.Phase:store.Data.Paused?"Automatyczne zadania są wstrzymane":"Gotowy  ·  kopie w Chomikuj są sprawdzane po wysłaniu";
        var local=engine.LocalProgress;
        if(engine.IsBusy&&local is {TotalBytes:>0})
            operation.Text+=$"  ·  {StudioTheme.Bytes(local.ProcessedBytes)} / {StudioTheme.Bytes(local.TotalBytes)} w tym etapie";
        progress.Visible=cancel.Visible=engine.IsBusy;cancel.Enabled=engine.IsBusy;
        if(local is {TotalBytes:>0}){progress.Style=ProgressBarStyle.Continuous;progress.Value=(int)Math.Clamp(100d*local.ProcessedBytes/local.TotalBytes,0,100);}
        else if(engine.TotalRecords>0){progress.Style=ProgressBarStyle.Continuous;progress.Value=(int)Math.Clamp(100d*engine.CompletedRecords/engine.TotalRecords,0,100);}else progress.Style=ProgressBarStyle.Marquee;
    }
    private void EngineFinished(RunRecord record){if(!IsDisposed){EngineChanged();ShowPage(currentPage);}}
    internal void ShowPage(string name)
    {
        name=name switch {"Pulpit" or "Zadania kopii"=>"Moje kopie","Przywracanie"=>"Przywróć pliki",_=>name};
        currentPage=name;breadcrumb.Text=name;
        foreach(var item in navigation){item.Value.Primary=item.Key==name;item.Value.Invalidate();}
        foreach(Control control in page.Controls.Cast<Control>().ToArray()){page.Controls.Remove(control);control.Dispose();}
        switch(name)
        {
            case "Moje kopie":Dashboard();break;
            case "Zadania kopii":Jobs();break;
            case "Historia":History();break;
            case "Ustawienia":Settings();break;
            case "Obraz Windows":SystemImage();break;
            case "Chomikuj":Cloud();break;
            case "Przywróć pliki":Restore();break;
        }
    }
    private FlowLayoutPanel Stack()
    {
        var scroll=new Panel{Dock=DockStyle.Fill,AutoScroll=true};page.Controls.Add(scroll);
        var flow=new FlowLayoutPanel{Dock=DockStyle.Top,FlowDirection=FlowDirection.TopDown,WrapContents=false,AutoSize=true,Padding=new(0,0,0,16)};scroll.Controls.Add(flow);
        void ResizeItems(){foreach(Control c in flow.Controls)c.Width=Math.Max(450,scroll.ClientSize.Width-20);}
        flow.ControlAdded+=(_,_)=>ResizeItems();scroll.Resize+=(_,_)=>ResizeItems();return flow;
    }
    private static void Place(Control parent,Control child,int x,int y){child.Location=new(x,y);parent.Controls.Add(child);}
    private void Dashboard()
    {
        var flow=Stack();var hero=new StudioCard{Height=184,Highlight=true};flow.Controls.Add(hero);
        Place(hero,StudioTheme.Label("TWOJE PLIKI. TWOJA SPOKOJNA GŁOWA.",9,StudioTheme.Accent,true),26,22);
        Place(hero,StudioTheme.Label("Bezpieczna kopia,\nbez zbędnych kroków.",26,null,true),24,48);
        Place(hero,StudioTheme.Label("Wybierz folder raz. Kolejne kopie wykonasz jednym kliknięciem.",10,StudioTheme.Muted),26,137);
        var art=new ProtectionArt{Size=new(172,153)};hero.Controls.Add(art);hero.Resize+=(_,_)=>{art.Location=new(hero.Width-197,13);art.Visible=hero.Width>710;};
        var last=store.Data.History.LastOrDefault();
        if(last is not null)
        {
            var result=new StudioCard{Height=96};flow.Controls.Add(result);
            Place(result,StudioTheme.Label(last.Name+"  ·  "+StudioTheme.State(last.State),12,last.State==RunState.Success?StudioTheme.Accent:StudioTheme.Amber,true),22,17);
            var detail=StudioTheme.Label(last.Detail,10,StudioTheme.Muted);detail.MaximumSize=new(710,48);Place(result,detail,22,43);
        }
        flow.Controls.Add(StudioTheme.Label("Moje kopie",17,null,true));
        if(store.Data.Profiles.Count==0)
        {
            var empty=new StudioCard{Height=170};flow.Controls.Add(empty);
            Place(empty,StudioTheme.Label("Zacznij od jednego folderu",18,null,true),24,21);
            Place(empty,StudioTheme.Label("Dokumenty, zdjęcia albo projekt. Hasła zapamiętamy na tym komputerze.",10,StudioTheme.Muted),24,62);
            Place(empty,StudioTheme.Button("Utwórz pierwszą kopię",()=>EditProfile(null),true),24,108);
        }
        else foreach(var profile in store.Data.Profiles)flow.Controls.Add(JobCard(profile));
        flow.Controls.Add(StudioTheme.Button("Dodaj kopię na dysku",()=>EditProfile(null,BackupDestination.Local)));
        flow.Controls.Add(StudioTheme.Label(store.Data.Paused?"Automatyczne kopie są wstrzymane — zmień to w Ustawieniach.":"Program może pracować w tle przy zegarze. Automat włączysz w ustawieniach kopii.",9,StudioTheme.Muted));
    }
    private static void Metric(TableLayoutPanel table,int column,string title,string value,string note)
    {
        var card=new StudioCard{Dock=DockStyle.Fill,Margin=new(column==0?0:7,0,column==2?0:7,0),Padding=new(17)};table.Controls.Add(card,column,0);
        Place(card,StudioTheme.Label(title,7.7f,StudioTheme.Muted,true),17,16);Place(card,StudioTheme.Label(value,20,null,true),17,37);
        var sub=StudioTheme.Label(note,8,StudioTheme.Muted);sub.AutoSize=false;sub.Height=24;sub.AutoEllipsis=true;Place(card,sub,17,80);card.Resize+=(_,_)=>sub.Width=card.Width-30;
    }
    private void EmptyJobs(FlowLayoutPanel flow)
    {
        var card=new StudioCard{Height=144};flow.Controls.Add(card);
        Place(card,StudioTheme.Label("Pierwsza kopia w trzech krokach",15,null,true),24,20);
        Place(card,StudioTheme.Label("01   Wybierz folder       02   Wskaż miejsce kopii       03   Ustaw automat",10,StudioTheme.Muted),24,59);
        Place(card,StudioTheme.Label("Hasło szyfrowania należy do Ciebie. Kopia otrzyma status „Sprawdzona”\ndopiero po kontroli zapisanych danych.",9,StudioTheme.Muted),24,89);
    }
    private StudioCard JobCard(BackupProfile profile)
    {
        bool cloud=profile.Destination==BackupDestination.Chomikuj;
        var card=new StudioCard{Height=268};
        Place(card,StudioTheme.Label(profile.Name,17,null,true),22,17);
        Place(card,StudioTheme.Label(profile.Destination==BackupDestination.Chomikuj?"CHOMIKUJ  ·  SZYFROWANA KOPIA":"NA DYSKU  ·  SZYFROWANA KOPIA",8,StudioTheme.Accent,true),23,50);
        var path=StudioTheme.Label(profile.Content==BackupContent.WindowsSystem?"Windows, programy, ustawienia i partycje startowe":profile.Source,9,StudioTheme.Muted);path.AutoSize=false;path.AutoEllipsis=true;path.Height=23;Place(card,path,23,74);
        string schedule=(profile.AtLogon?"Po zalogowaniu do Windows  ":"")+(profile.Daily?$"Codziennie {profile.DailyMinute/60:00}:{profile.DailyMinute%60:00}":profile.AtLogon?"":"Uruchamiasz przyciskiem poniżej");
        Place(card,StudioTheme.Label(profile.Enabled?schedule:"Automatyczne wykonywanie wyłączone",9,StudioTheme.Muted),23,103);
        string state=profile.LastSuccess is null?(cloud?"Kopia nie została jeszcze wysłana do Chomikuj.":"Brak ukończonej kopii."):
            (cloud?"W Chomikuj · sprawdzona: ":"Na dysku · sprawdzona: ")+profile.LastSuccess.Value.ToLocalTime().ToString("dd.MM.yyyy HH:mm");
        Place(card,StudioTheme.Label(state,9,profile.LastSuccess is null?StudioTheme.Amber:StudioTheme.Accent,true),23,130);
        var actions=new FlowLayoutPanel{Location=new(19,163),Height=96,WrapContents=true};card.Controls.Add(actions);
        var run=StudioTheme.AsyncButton(profile.PendingSnapshot is not null?"Dokończ wysyłanie":profile.PendingSystemImage is not null?"Dokończ kopię Windows":cloud?"Wyślij na Chomikuj":"Wykonaj kopię na dysku",()=>RunProfileAsync(profile),true);run.Name="RunBackup_"+profile.Id;run.Width=190;run.Enabled=!engine.IsBusy;actions.Controls.Add(run);
        var restore=StudioTheme.AsyncButton(profile.Content==BackupContent.WindowsSystem?"Pobierz obraz":"Przywróć pliki",()=>OpenRestoreAsync(profile));restore.Width=145;restore.Enabled=!engine.IsBusy;actions.Controls.Add(restore);
        var edit=StudioTheme.Button("Ustawienia kopii",()=>EditProfile(profile));edit.Width=145;edit.Enabled=!engine.IsBusy;actions.Controls.Add(edit);
        var key=StudioTheme.Button("Klucz odzyskiwania",()=>ShowRecoveryKey(profile));key.Width=170;key.Enabled=!engine.IsBusy;actions.Controls.Add(key);
        card.Resize+=(_,_)=>{path.Width=card.Width-48;actions.Width=card.Width-40;};return card;
    }
    private void Jobs()
    {
        var flow=Stack();flow.Controls.Add(StudioTheme.Label("Kopie, które pracują dla Ciebie",23,null,true));flow.Controls.Add(StudioTheme.Label("Każde zadanie ma własny sejf, miejsce docelowe i harmonogram.",10,StudioTheme.Muted));
        if(store.Data.Profiles.Count==0)EmptyJobs(flow);else foreach(var profile in store.Data.Profiles)flow.Controls.Add(JobCard(profile));
    }
    private void History()
    {
        var flow=Stack();flow.Controls.Add(StudioTheme.Label("Historia ochrony",23,null,true));flow.Controls.Add(StudioTheme.Label("Rzeczywiste wyniki zadań. Przerwane operacje są odróżnione od sprawdzonych kopii.",10,StudioTheme.Muted));
        if(store.Data.History.Count==0){var empty=new StudioCard{Height=130};flow.Controls.Add(empty);Place(empty,StudioTheme.Label("Historia jest jeszcze pusta",17,null,true),24,22);Place(empty,StudioTheme.Label("Uruchom pierwsze zadanie, a jego wynik pojawi się tutaj.",10,StudioTheme.Muted),24,65);}
        foreach(var entry in store.Data.History.AsEnumerable().Reverse().Take(100))
        {
            var card=new StudioCard{Height=145};flow.Controls.Add(card);Place(card,StudioTheme.Label(entry.Name,14,null,true),22,17);
            Place(card,StudioTheme.Label(entry.Started.ToLocalTime().ToString("dd.MM.yyyy  HH:mm")+"  ·  "+StudioTheme.State(entry.State),9,entry.State==RunState.Success?StudioTheme.Accent:StudioTheme.Amber,true),23,47);
            var detail=StudioTheme.Label(entry.Detail,9,StudioTheme.Muted);detail.MaximumSize=new(720,43);Place(card,detail,23,73);
            if(entry.SkippedSystemDirectoryLinks.Count>0)
            {
                card.Height=210;var skipped=StudioTheme.Label("Pominięte systemowe odsyłacze: "+string.Join(", ",entry.SkippedSystemDirectoryLinks),9,StudioTheme.Amber);
                skipped.MaximumSize=new(710,64);Place(card,skipped,23,142);
            }
            if(entry.State==RunState.Success)Place(card,StudioTheme.Label($"{entry.Files} plików  /  {StudioTheme.Bytes(entry.Bytes)}",8,StudioTheme.Muted),23,116);
        }
    }
    private void Settings()
    {
        var flow=Stack();flow.Controls.Add(StudioTheme.Label("Program na Twoich zasadach",23,null,true));
        var card=new StudioCard{Height=390};flow.Controls.Add(card);
        var startup=new CheckBox{Text="Uruchamiaj przy logowaniu do Windows",AutoSize=true,Checked=!Preview&&StartupRegistration.IsEnabled()};Place(card,startup,24,25);
        var tray=new CheckBox{Text="Zamknięcie okna chowa program przy zegarze",AutoSize=true,Checked=store.Data.CloseToTray};Place(card,tray,24,65);
        var notifications=new CheckBox{Text="Powiadamiaj o wyniku zadań",AutoSize=true,Checked=store.Data.Notifications};Place(card,notifications,24,105);
        var paused=new CheckBox{Text="Wstrzymaj automatyczne kopie",AutoSize=true,Checked=store.Data.Paused};Place(card,paused,24,145);
        Place(card,StudioTheme.Label("Domyślna ochrona nowych kopii",11,null,true),24,184);
        var keyChoice=new ComboBox{Name="DefaultKeyChoice",DropDownStyle=ComboBoxStyle.DropDownList,FlatStyle=FlatStyle.Flat,BackColor=StudioTheme.Raised,ForeColor=StudioTheme.Ink,Width=380};
        keyChoice.Items.AddRange(new object[]{"Program tworzy losowy klucz","Używam własnego hasła lub klucza"});
        keyChoice.SelectedIndex=store.Data.UseOwnKeyForNewCopies?1:0;Place(card,keyChoice,24,218);
        Place(card,StudioTheme.Label("To ustawienie nie zmienia kluczy istniejących kopii.\nWłasne hasło lub klucz wpiszesz podczas tworzenia nowej kopii.",9,StudioTheme.Muted),24,258);
        Place(card,StudioTheme.Button("Zapisz ustawienia",()=>
        {
            try{if(!Preview)StartupRegistration.SetEnabled(startup.Checked);store.Data.CloseToTray=tray.Checked;store.Data.Notifications=notifications.Checked;store.Data.Paused=paused.Checked;store.Data.UseOwnKeyForNewCopies=keyChoice.SelectedIndex==1;store.Save();EngineChanged();ShowFeedback("Ustawienia zapisane.");}
            catch(Exception e){ShowFeedback(JobEngine.SafeError(e));}
        },true),24,321);
        var info=new StudioCard{Height=176};flow.Controls.Add(info);Place(info,StudioTheme.Label("Kontrola pozostaje u Ciebie",15,null,true),24,20);
        Place(info,StudioTheme.Label("Autostart działa po zalogowaniu użytkownika, także przy schowanym oknie.\nTa wersja nie jest usługą działającą przed logowaniem. Wyjście z programu\nwstrzymuje harmonogram. Windows może opóźnić uruchomienie autostartu.\nHasła automatycznych zadań chroni konto Windows (DPAPI).",10,StudioTheme.Muted),24,60);
        var account=StudioTheme.Button("Konto i zapisane hasła",()=>{using var window=new AccountWindow(store);window.ShowDialog(this);if(window.Forgotten)sessionSecrets.Clear();});account.Width=240;flow.Controls.Add(account);
        var image=StudioTheme.Button("Kopia Windows na Chomikuj",()=>ShowPage("Obraz Windows"));image.Width=240;flow.Controls.Add(image);
        var tools=StudioTheme.Button("Narzędzia zaawansowane",()=>OpenManual(true));tools.Width=240;flow.Controls.Add(tools);
        var exit=StudioTheme.Button("Zakończ program",()=>ExitRequested?.Invoke());flow.Controls.Add(exit);
    }
    private void Cloud()
    {
        var flow=Stack();var hero=new StudioCard{Height=140,Highlight=true};flow.Controls.Add(hero);
        Place(hero,StudioTheme.Label("TWOJE PLIKI · TWOJE KONTO CHOMIKUJ",9,StudioTheme.Accent,true),25,20);
        Place(hero,StudioTheme.Label("Kopia na Chomikuj.",26,null,true),23,40);
        Place(hero,StudioTheme.Label("Wybierz folder. Program zaszyfruje, wyśle i sprawdzi Twoje pliki.\nKlucz szyfrowania wygeneruje i zapamięta na tym komputerze.",10,StudioTheme.Muted),25,88);
        var accountCard=new StudioCard{Height=80};flow.Controls.Add(accountCard);
        JobSecrets? account=null;try{account=StudioCredentials.Account(store);}catch(System.Security.Cryptography.CryptographicException){}
        var accountLabel=StudioTheme.Label(account is null?"Połącz konto Chomikuj":"Zapamiętane konto: "+account.CloudLogin,13,null,true);accountLabel.AutoSize=false;accountLabel.AutoEllipsis=true;accountLabel.Height=25;Place(accountCard,accountLabel,23,13);
        Place(accountCard,StudioTheme.Label(account is null?"Zalogujesz się przy tworzeniu pierwszej kopii.":"Konto zostanie sprawdzone przed wysłaniem.",9,StudioTheme.Muted),24,45);
        var manage=StudioTheme.Button("Konto Chomikuj",()=>{using var window=new AccountWindow(store);window.ShowDialog(this);if(window.Forgotten)sessionSecrets.Clear();ShowPage("Chomikuj");});manage.Size=new(185,32);accountCard.Controls.Add(manage);accountCard.Resize+=(_,_)=>{manage.Location=new(accountCard.Width-208,5);accountLabel.Width=accountCard.Width-245;};
        var profiles=store.Data.Profiles.Where(p=>p.Destination==BackupDestination.Chomikuj).ToArray();
        var discover=StudioTheme.Button("Pokaż kopie z konta",()=>
        {
            try
            {
                var saved=StudioCredentials.Account(store);
                if(saved is null){using var loginWindow=new AccountWindow(store);loginWindow.ShowDialog(this);saved=StudioCredentials.Account(store);}
                if(saved is null){ShowFeedback("Połącz konto, aby odczytać zapisane w nim kopie.");return;}
                using var catalog=new CloudCatalogWindow(store,saved);catalog.ShowDialog(this);
            }
            catch(Exception e){ShowFeedback(JobEngine.SafeError(e));}
        });discover.Name="DiscoverCloudCopies";discover.Size=new(185,32);discover.Enabled=!engine.IsBusy;accountCard.Controls.Add(discover);accountCard.Resize+=(_,_)=>discover.Location=new(accountCard.Width-208,42);
        flow.Controls.Add(StudioTheme.Label("Moje kopie w Chomikuj",18,null,true));
        if(profiles.Length==0)
        {
            var first=new StudioCard{Height=155};flow.Controls.Add(first);
            Place(first,StudioTheme.Label("Wyślij pierwszą kopię",18,null,true),24,18);
            Place(first,StudioTheme.Label("Kopie na dysku nie są automatycznie kopiami w chmurze.",10,StudioTheme.Muted),24,58);
            var create=StudioTheme.Button("Wybierz folder i wyślij",()=>EditProfile(null,BackupDestination.Chomikuj),true);create.Width=240;Place(first,create,24,94);
        }
        foreach(var profile in profiles)flow.Controls.Add(JobCard(profile));
        var last=store.Data.History.LastOrDefault(r=>profiles.Any(p=>p.Id==r.ProfileId));
        if(last is not null)
        {
            var result=new StudioCard{Height=102};flow.Controls.Add(result);
            Place(result,StudioTheme.Label("Ostatnia próba · "+StudioTheme.State(last.State),12,last.State==RunState.Success?StudioTheme.Accent:StudioTheme.Amber,true),23,17);
            var detail=StudioTheme.Label(last.Detail,10,StudioTheme.Muted);detail.MaximumSize=new(720,55);Place(result,detail,23,43);
        }
        flow.Controls.Add(StudioTheme.Label("Po pierwszej kopii zapisz „Klucz odzyskiwania” poza PC. Będzie potrzebny po awarii Windows.",9,StudioTheme.Muted));
    }
    private void Restore()
    {
        var flow=Stack();flow.Controls.Add(StudioTheme.Label("Wróć do dobrego momentu",23,null,true));flow.Controls.Add(StudioTheme.Label("Przywracamy do nowego folderu — istniejące pliki pozostają na miejscu.",10,StudioTheme.Muted));
        foreach(var profile in store.Data.Profiles)
        {
            var card=new StudioCard{Height=128};flow.Controls.Add(card);Place(card,StudioTheme.Label(profile.Name,15,null,true),24,20);
            Place(card,StudioTheme.Label(profile.LastSuccess is null?"Brak potwierdzonej kopii tego zadania":"Ostatnia kopia: "+profile.LastSuccess.Value.ToLocalTime().ToString("dd.MM.yyyy HH:mm"),10,StudioTheme.Muted),24,54);
            Place(card,StudioTheme.AsyncButton(profile.Content==BackupContent.WindowsSystem?"Wybierz i pobierz obraz":"Wybierz kopię i przywróć",()=>OpenRestoreAsync(profile),true),24,80);
        }
        if(store.Data.Profiles.Count==0){var card=new StudioCard{Height=160};flow.Controls.Add(card);Place(card,StudioTheme.Label("Masz już wcześniejszy sejf?",17,null,true),24,23);Place(card,StudioTheme.Label("Możesz otworzyć kopie z dysku albo zalogować się do Chomikuj.",10,StudioTheme.Muted),24,65);Place(card,StudioTheme.Button("Otwórz lokalny sejf",()=>OpenManual(false)),24,100);Place(card,StudioTheme.Button("Otwórz Chomikuj",()=>OpenManual(true)),225,100);}
    }
    private void SystemImage()
    {
        var flow=Stack();flow.Controls.Add(StudioTheme.Label("Obraz Windows — eksperymentalny",23,null,true));
        var card=new StudioCard{Height=280,Highlight=true};flow.Controls.Add(card);Place(card,StudioTheme.Label("Cały Windows. Kopia na Chomikuj.",22,null,true),24,23);
        Place(card,StudioTheme.Label("Program przygotuje obraz Windows przez VSS, zaszyfruje go,\nwyśle na Twoje konto i sprawdzi zapisane dane. W kreatorze\nwybierzesz klucz oraz kopię codzienną lub po zalogowaniu.",11,StudioTheme.Muted),24,76);
        Place(card,StudioTheme.Label("Funkcja dla zaawansowanych, poza stabilnym zakresem v1.\nWymaga modułu systemowego i osobnego dysku roboczego.",9,StudioTheme.Muted),24,160);
        var create=StudioTheme.Button("Ustaw kopię Windows na Chomikuj",()=>EditProfile(null,BackupDestination.Chomikuj,BackupContent.WindowsSystem),true);
        create.Name="NewWindowsCloudBackup";create.Width=320;create.Enabled=!engine.IsBusy;Place(card,create,24,218);
        foreach(var profile in store.Data.Profiles.Where(p=>p.Content==BackupContent.WindowsSystem))flow.Controls.Add(JobCard(profile));
        var local=StudioTheme.Button("Kopia Windows na dysku",()=>EditProfile(null,BackupDestination.Local,BackupContent.WindowsSystem));local.Enabled=!engine.IsBusy;flow.Controls.Add(local);
        var restore=new StudioCard{Height=176};flow.Controls.Add(restore);Place(restore,StudioTheme.Label("Przygotuj się na awarię",15,null,true),24,20);Place(restore,StudioTheme.Label("Zapisz klucz odzyskiwania poza komputerem. Przycisk „Pobierz obraz”\npobiera i sprawdza pliki obrazu. Przywrócenie całego Windows wymaga\nuruchomienia środowiska ratunkowego (WinRE). Kreator własnego\nnośnika ratunkowego jest jeszcze w przygotowaniu.",10,StudioTheme.Muted),24,61);
    }
    internal void EditProfile(BackupProfile? profile,BackupDestination? newDestination=null,BackupContent newContent=BackupContent.Files)
    {
        if(engine.IsBusy){ShowFeedback("Trwa wykonywanie kopii. Możesz ją zatrzymać przyciskiem na dole.");return;}
        JobSecrets? account=null;try{account=StudioCredentials.Account(store);}catch(System.Security.Cryptography.CryptographicException){}
        sessionSecrets.TryGetValue(profile?.Id??"",out var session);
        using var editor=new ProfileEditor(store.Root,profile,account,session,newDestination,store.Data.UseOwnKeyForNewCopies,newContent);
        if(editor.ShowDialog(this)!=DialogResult.OK||editor.ResultProfile is null)return;
        var changed=editor.ResultProfile;
        try
        {
            if((changed.AtLogon||changed.Daily)&&!Preview)StartupRegistration.SetEnabled(true);
            int index=store.Data.Profiles.FindIndex(p=>p.Id==changed.Id);if(index<0)store.Data.Profiles.Add(changed);else store.Data.Profiles[index]=changed;
            if(changed.ProtectedSecrets is not null&&changed.Destination==BackupDestination.Chomikuj)StudioCredentials.RememberAccount(store,editor.ResultSecrets!);
            store.Save();sessionSecrets[changed.Id]=editor.ResultSecrets!;ShowPage(changed.Destination==BackupDestination.Chomikuj?"Chomikuj":"Moje kopie");
            if(editor.StartAfterSave)_=RunProfileAsync(changed);else ShowFeedback("Ustawienia kopii zapisane.");
        }
        catch(Exception e){ShowFeedback(JobEngine.SafeError(e));}
    }
    internal async Task RunProfileAsync(BackupProfile profile)
    {
        if(engine.IsBusy)return;
        try
        {
            var secrets=Unlock(profile);if(secrets is null)return;
            secrets=VaultKeys.Prepare(store,profile,secrets);sessionSecrets[profile.Id]=secrets;
            JobEngine.Validate(profile,secrets);await engine.RunAsync(profile,secrets,DateTimeOffset.Now);
        }
        catch(Exception e){ShowFeedback(e is ArgumentException?e.Message:JobEngine.SafeError(e));}
    }
    private void ShowRecoveryKey(BackupProfile profile)
    {
        if(engine.IsBusy)return;
        ManualWindowOpen=true;
        try
        {
            var secrets=Unlock(profile);if(secrets is null)return;
            secrets=VaultKeys.Prepare(store,profile,secrets);
            using var dialog=new RecoveryKeyWindow(profile,secrets);dialog.ShowDialog(this);
        }
        catch(Exception error){ShowFeedback(JobEngine.SafeError(error));}
        finally{ManualWindowOpen=false;}
    }
    private JobSecrets? Unlock(BackupProfile profile)
    {
        if(profile.ProtectedSecrets is not null)
        {
            try{return WindowsSecrets.Unprotect(profile.ProtectedSecrets);}catch(System.Security.Cryptography.CryptographicException){}
        }
        if(sessionSecrets.TryGetValue(profile.Id,out var saved))return saved;
        JobSecrets? account=null;try{account=StudioCredentials.Account(store);}catch(System.Security.Cryptography.CryptographicException){}
        using var unlock=new UnlockDialog(profile,account);if(unlock.ShowDialog(this)!=DialogResult.OK)return null;
        var secrets=unlock.Secrets!;
        // Validate the vault key before remembering a mistyped unlock password.
        if(Directory.Exists(profile.Repository)){using var vault=ChomcioRecovery.Core.LocalEncryptedVault.Open(profile.Repository,secrets.VaultPassword);}
        if(unlock.Remember){profile.ProtectedSecrets=WindowsSecrets.Protect(secrets);StudioCredentials.RememberAccount(store,secrets);store.Save();}
        sessionSecrets[profile.Id]=secrets;return secrets;
    }
    private Task OpenRestoreAsync(BackupProfile profile)
    {
        if(engine.IsBusy)return Task.CompletedTask;
        ManualWindowOpen=true;
        try
        {
            var secrets=Unlock(profile);if(secrets is null)return Task.CompletedTask;
            using var window=new RestoreWindow(store,profile,secrets);window.ShowDialog(this);
        }
        catch(Exception e){ShowFeedback(JobEngine.SafeError(e));}
        finally{ManualWindowOpen=false;}
        return Task.CompletedTask;
    }
    public void ShowFeedback(string text){operation.Text=text;operation.ForeColor=StudioTheme.Amber;}
    private void OpenManual(bool cloud,BackupProfile? profile=null)
    {
        if(engine.IsBusy){ShowFeedback("Trwa wykonywanie kopii. Możesz ją zatrzymać przyciskiem na dole.");return;}
        ManualWindowOpen=true;
        try
        {
            string repo=profile?.Repository??Path.Combine(store.Root,"manual-vault");string source=profile?.Source??"";
            if(cloud){using var window=new CloudWindow(repo,source);window.UseSavedCredentials(store,profile);window.ShowDialog(this);}
            else{using var window=new RecoveryWindow();window.SetProfile(repo,source);window.ShowDialog(this);}
        }
        finally{ManualWindowOpen=false;}
    }
}
