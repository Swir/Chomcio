using System.Security.Cryptography;
using System.Text;

namespace ChomcioRecovery.Desktop;

internal sealed class StudioApplication : ApplicationContext
{
    internal readonly StudioStore Store;
    internal readonly JobEngine Engine;
    internal readonly StudioWindow Window;
    internal readonly NotifyIcon Tray;
    private readonly System.Windows.Forms.Timer timer=new(){Interval=30_000};
    private readonly string? logon;
    private string? boot;
    private bool closing,checking;
    private bool notifiedHidden;
    internal StudioApplication(bool autoStart,string? root=null)
    {
        Store=new StudioStore(root??StudioStore.DefaultRoot);Engine=new(Store);Window=new(Store,Engine);
        logon=autoStart?SchedulePolicy.LogonId():null;
        Tray=new NotifyIcon{Icon=Window.Icon,Text="ChomcioRecovery by Swir",Visible=true};
        var menu=new ContextMenuStrip{BackColor=StudioTheme.Surface,ForeColor=StudioTheme.Ink};
        menu.Items.Add("Otwórz ChomcioRecovery",null,(_,_)=>Show());
        menu.Items.Add("Moje zadania",null,(_,_)=>{Show();Window.ShowPage("Zadania kopii");});
        var pause=new ToolStripMenuItem("Wstrzymaj automatyczne kopie"){Checked=Store.Data.Paused,CheckOnClick=true};
        pause.Click+=(_,_)=>{Store.Data.Paused=pause.Checked;try{Store.Save();}catch(Exception){ShowNotice("Nie zapisano ustawień",true);}Window.ShowPage("Pulpit");};menu.Items.Add(pause);
        menu.Opening+=(_,_)=>pause.Checked=Store.Data.Paused;
        menu.Items.Add("Zatrzymaj bieżącą kopię",null,(_,_)=>Engine.Cancel());menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Zakończ program",null,async(_,_)=>await ExitAsync());Tray.ContextMenuStrip=menu;Tray.DoubleClick+=(_,_)=>Show();
        Window.ExitRequested+=async()=>await ExitAsync();
        Window.FormClosing+=(_,e)=>
        {
            if(closing)return;
            if(e.CloseReason is CloseReason.WindowsShutDown or CloseReason.TaskManagerClosing){Engine.Cancel();closing=true;ExitThread();return;}
            e.Cancel=true;
            if(Store.Data.CloseToTray)
            { Window.Hide();if(!notifiedHidden){notifiedHidden=true;ShowNotice("Program działa przy zegarze. Zadania pozostają aktywne.",false);} }
            else _=ExitAsync();
        };
        Window.FormClosed+=(_,_)=>ExitThread();
        Engine.Finished+=record=>ShowNotice(record.Name+": "+StudioTheme.State(record.State),record.State is RunState.Failed or RunState.Interrupted);
        timer.Tick+=async(_,_)=>await CheckScheduleAsync();
        Window.Show();if(autoStart)Window.Hide();
        timer.Start();Window.BeginInvoke(async()=>await CheckScheduleAsync());
    }
    internal void Show(){if(Window.IsDisposed)return;Window.Show();Window.WindowState=FormWindowState.Normal;Window.BringToFront();Window.Activate();}
    private void ShowNotice(string text,bool error)
    {if(Store.Data.Notifications&&!closing&&!Window.Visible){Tray.BalloonTipTitle="ChomcioRecovery by Swir";Tray.BalloonTipText=text;Tray.BalloonTipIcon=error?ToolTipIcon.Warning:ToolTipIcon.Info;Tray.ShowBalloonTip(4000);}}
    internal async Task CheckScheduleAsync()
    {
        if(checking||closing||Engine.IsBusy||Window.ManualWindowOpen||!Window.Enabled)return;
        checking=true;
        try
        {
            if(boot is null&&Store.Data.Profiles.Any(p=>p.Enabled&&p.AtBoot))boot=await Task.Run(BootIdentity.Read);
            foreach(var profile in Store.Data.Profiles.ToArray())
            {
                if(closing||Store.Data.Paused||Window.ManualWindowOpen||!Window.Enabled)break;
                var now=DateTimeOffset.Now;
                if(!SchedulePolicy.Due(profile,now,logon,Store.Data.Paused,boot))continue;
                JobSecrets secrets;
                try{secrets=WindowsSecrets.Unprotect(profile.ProtectedSecrets!);}
                catch(System.Security.Cryptography.CryptographicException)
                {
                    SchedulePolicy.MarkAttempt(profile,now,logon,boot);
                    Store.Data.History.Add(new(){Name=profile.Name,ProfileId=profile.Id,State=RunState.Failed,Finished=now,Detail="Windows nie odblokował zapamiętanych haseł. Otwórz ustawienia zadania."});Store.Save();ShowNotice("Zadanie wymaga ponownego wpisania haseł.",true);continue;
                }
                await Engine.RunAsync(profile,secrets,now,logon,boot);
            }
        }
        catch(Exception){ShowNotice("Automatyczne zadanie wymaga uwagi. Sprawdź historię i ustawienia.",true);}
        finally{checking=false;}
    }
    internal async Task ExitAsync(bool confirm=true)
    {
        if(closing)return;
        if(Engine.IsBusy&&confirm&&MessageBox.Show(Window,"Zatrzymać bieżące zadanie i zakończyć program po bezpiecznym zamknięciu zapisu?","Kończenie pracy",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes)return;
        closing=true;timer.Stop();Engine.Cancel();await Engine.Completion;
        Tray.Visible=false;Window.Close();ExitThread();
    }
    protected override void Dispose(bool disposing)
    {if(disposing){timer.Dispose();Tray.Dispose();Window.Dispose();}base.Dispose(disposing);}
    internal static void Run(bool autoStart)
    {
        string scope=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(StudioStore.DefaultRoot.ToUpperInvariant()+Environment.UserName)))[..24];
        using var mutex=StudioProcessScope.Create(StudioStore.DefaultRoot);
        bool owns=StudioProcessScope.Acquire(mutex);
        if(!owns)
        {
            try{using var signal=EventWaitHandle.OpenExisting("Local\\ChomcioRecovery.Show."+scope);signal.Set();return;}
            catch(WaitHandleCannotBeOpenedException){}
            if(autoStart)return;
            using var waiting=new BackgroundWaitWindow(StudioStore.DefaultRoot,mutex);
            Application.Run(waiting);if(!waiting.Acquired)return;
        }
        using var wake=new EventWaitHandle(false,EventResetMode.AutoReset,"Local\\ChomcioRecovery.Show."+scope);
        try
        {
            using var app=new StudioApplication(autoStart);
            using var registration=new WaitRegistration(wake,()=>{if(!app.Window.IsDisposed)app.Window.BeginInvoke(app.Show);});
            Application.Run(app);
        }
        finally{mutex.ReleaseMutex();}
    }
    private sealed class WaitRegistration : IDisposable
    {
        private readonly RegisteredWaitHandle handle;
        internal WaitRegistration(WaitHandle wait,Action action){handle=ThreadPool.RegisterWaitForSingleObject(wait,(_,_)=>{try{action();}catch(InvalidOperationException){}},null,Timeout.Infinite,false);}
        public void Dispose()=>handle.Unregister(null);
    }
}
