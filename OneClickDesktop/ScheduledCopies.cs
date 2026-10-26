using System.Runtime.InteropServices;
using System.Security.Principal;

namespace ChomcioRecovery.Desktop;

internal static class ScheduledCopies
{
    internal static string Name(string root)=>"ChomcioRecovery Backup "+StudioProcessScope.Id(root);
    internal static string Arguments(string root)
    {
        string path=Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        if(path.StartsWith(@"\\")||path.IndexOfAny(new[]{'"','\r','\n'})>=0||path.Length<4)
            throw new IOException("Wybierz lokalny folder ustawień Chomcio.");
        StudioStore.RejectLinks(path);
        return BackgroundCopies.Switch+" \""+path+"\"";
    }
    private static string Sid=>WindowsIdentity.GetCurrent().User!.Value;
    private static bool Missing(Exception e)=>e is FileNotFoundException||e is COMException c&&c.HResult==unchecked((int)0x80070002);
    private static void Release(object? value){if(value is not null&&Marshal.IsComObject(value))Marshal.FinalReleaseComObject(value);}
    private static void RequireOwned(dynamic task,string root)
    {
        dynamic definition=task.Definition,principal=definition.Principal,actions=definition.Actions;
        dynamic? action=null;
        try
        {
            string account=(string)principal.UserId;
            string sid=account.StartsWith("S-1-",StringComparison.Ordinal)?account:((SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier))).Value;
            if((string)definition.Data!="ChomcioRecovery.Background.v1:"+StudioProcessScope.Id(root)||sid!=Sid||
                (int)principal.LogonType!=1||(int)principal.RunLevel!=0||(int)actions.Count!=1)
                throw new IOException("Istniejące zadanie Windows ma inną konfigurację. Zachowano je.");
            action=actions.Item(1);
            if((int)action.Type!=0||(string)action.Arguments!=Arguments(root)||!Path.IsPathFullyQualified((string)action.Path))
                throw new IOException("Nie rozpoznano istniejącego zadania Windows. Zachowano je.");
        }
        finally{Release(action);Release(actions);Release(principal);Release(definition);}
    }
    internal static bool IsEnabled(string root)
    {
        dynamic service=Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service")!)!;
        dynamic? folder=null,task=null;
        try
        {
            service.Connect();folder=service.GetFolder("\\");
            try{task=folder.GetTask(Name(root));}catch(Exception e)when(Missing(e)){return false;}
            RequireOwned(task,root);return (bool)task.Enabled;
        }
        finally{Release(task);Release(folder);Release(service);}
    }
    internal static void Register(string root,string executable,string windowsPassword)
    {
        if(string.IsNullOrEmpty(windowsPassword))throw new ArgumentException("Podaj hasło konta Windows, nie kod PIN.");
        string args=Arguments(root),exe=Path.GetFullPath(executable);
        StudioStore.RejectLinks(exe);
        if(exe.StartsWith(@"\\")||!File.Exists(exe)||!Path.GetFileName(exe).Equals("ChomcioRecovery.exe",StringComparison.OrdinalIgnoreCase))
            throw new IOException("Przenieś kompletny program na stały dysk tego komputera.");
        dynamic service=Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service")!)!;
        dynamic? folder=null,existing=null,task=null,trigger=null,action=null,registered=null;
        try
        {
            service.Connect();folder=service.GetFolder("\\");
            try{existing=folder.GetTask(Name(root));RequireOwned(existing,root);}catch(Exception e)when(Missing(e)){}
            task=service.NewTask(0);
            task.Data="ChomcioRecovery.Background.v1:"+StudioProcessScope.Id(root);
            task.RegistrationInfo.Description="ChomcioRecovery: kopie według zapisanych ustawień, także bez zalogowania. Uprawnienia zwykłego użytkownika.";
            task.Principal.UserId=Sid;task.Principal.LogonType=1;task.Principal.RunLevel=0;
            task.Settings.Enabled=true;task.Settings.Hidden=false;task.Settings.StartWhenAvailable=true;
            task.Settings.MultipleInstances=2;task.Settings.ExecutionTimeLimit="PT0S";task.Settings.AllowHardTerminate=false;
            task.Settings.DisallowStartIfOnBatteries=false;task.Settings.StopIfGoingOnBatteries=false;task.Settings.WakeToRun=false;task.Settings.Priority=7;
            // A repeating time trigger works for ordinary accounts. A BootTrigger
            // would require administrative registration. The process exits when
            // no profile is due; credentials are held by Windows Task Scheduler.
            trigger=task.Triggers.Create(1);trigger.StartBoundary=DateTimeOffset.Now.AddMinutes(1).ToString("yyyy-MM-dd'T'HH:mm:sszzz");
            trigger.Enabled=true;trigger.Repetition.Interval="PT2M";trigger.Repetition.StopAtDurationEnd=false;
            action=task.Actions.Create(0);action.Path=exe;action.Arguments=args;action.WorkingDirectory=Path.GetDirectoryName(exe);
            registered=folder.RegisterTaskDefinition(Name(root),task,existing is null?2:4,Sid,windowsPassword,1,null);
            RequireOwned(registered,root);
        }
        finally{Release(registered);Release(action);Release(trigger);Release(task);Release(existing);Release(folder);Release(service);}
    }
    internal static void Remove(string root)
    {
        dynamic service=Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service")!)!;
        dynamic? folder=null,task=null;
        try
        {
            service.Connect();folder=service.GetFolder("\\");
            try{task=folder.GetTask(Name(root));}catch(Exception e)when(Missing(e)){return;}
            RequireOwned(task,root);
            if((int)task.State==4)throw new IOException("Najpierw zatrzymaj bieżącą kopię i poczekaj na zakończenie zapisu.");
            folder.DeleteTask(Name(root),0);
        }
        finally{Release(task);Release(folder);Release(service);}
    }
}

internal sealed class ScheduledCopiesWindow : Form,IInlineFeedback
{
    private readonly string root;
    private readonly TextBox password=StudioTheme.Input(true);
    private readonly Label status=StudioTheme.Label("",10,StudioTheme.Muted);
    internal ScheduledCopiesWindow(string root)
    {
        this.root=root;StudioTheme.Form(this);Text="Automatyczne kopie w tle • ChomcioRecovery";ClientSize=new(640,460);MinimumSize=new(640,460);StartPosition=FormStartPosition.CenterParent;
        var body=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new(24),ColumnCount=1,AutoScroll=true};Controls.Add(body);
        void Add(Control c,int height){int row=body.RowCount++;body.RowStyles.Add(new(SizeType.Absolute,height));c.Dock=DockStyle.Fill;body.Controls.Add(c,0,row);}
        Add(StudioTheme.Label("Kopie przy zamkniętym programie",21,null,true),50);
        Add(StudioTheme.Label("Windows wykona zapisane zadania także po wylogowaniu.\nKomputer musi być włączony; nie wybudzamy go ze snu.\nDziała harmonogram oraz opcja kopii po uruchomieniu komputera.",10,StudioTheme.Muted),80);
        Add(StudioTheme.Label("Konto Windows: "+WindowsIdentity.GetCurrent().Name,10,null,true),28);
        Add(StudioTheme.Label("Hasło tego konta Windows — nie kod PIN ani hasło Chomikuj",10,StudioTheme.Muted),28);
        password.Name="BackgroundWindowsPassword";Add(password,38);
        Add(StudioTheme.Label("Hasło przekazujemy tylko Harmonogramowi Windows. Nie zapisujemy go\nw ustawieniach Chomcio. Po zmianie hasła Windows włącz tę opcję ponownie.",9,StudioTheme.Muted),52);
        var actions=new FlowLayoutPanel();
        var enable=StudioTheme.Button("Włącz pracę w tle",()=>
        {
            try{ScheduledCopies.Register(root,Application.ExecutablePath,password.Text);ShowFeedback("Włączono. Windows będzie wykonywać zapisane zadania. Zachowaj program w tej lokalizacji.");}
            catch(Exception e){ShowFeedback(e is ArgumentException or IOException?e.Message:"Windows nie zapisał zadania. Sprawdź hasło konta i prawo do uruchamiania zadań w tle.");}
            finally{password.Clear();}
        },true);enable.Name="EnableBackgroundCopies";enable.Width=210;actions.Controls.Add(enable);
        var disable=StudioTheme.Button("Wyłącz pracę w tle",()=>{try{ScheduledCopies.Remove(root);ShowFeedback("Wyłączono pracę przy zamkniętym programie. Kopie i klucze zachowano.");}catch(Exception e){ShowFeedback(e is IOException?e.Message:"Nie wyłączono zadania Windows. Sprawdź jego uprawnienia.");}});disable.Width=210;actions.Controls.Add(disable);Add(actions,50);
        status.AutoSize=false;Add(status,70);
        try{ShowFeedback(ScheduledCopies.IsEnabled(root)?"Praca w tle jest włączona.":"Praca w tle jest wyłączona.");}catch(Exception){ShowFeedback("Nie można odczytać zadania Windows.");}
    }
    public void ShowFeedback(string text){if(!IsDisposed)status.Text=text;}
}
