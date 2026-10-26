using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace ChomcioRecovery.Desktop;

// Both the visible application and the scheduled process hold this same lease
// for their entire lifetime. They never load/edit two independent settings copies.
internal static class StudioProcessScope
{
    internal static string Id(string root)
    {
        string sid=WindowsIdentity.GetCurrent().User!.Value;
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            sid+"|"+Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)).ToUpperInvariant())))[..32];
    }
    internal static Mutex Create(string root)=>new(false,"Global\\ChomcioRecovery.Studio."+Id(root));
    internal static string CancelName(string root)=>"Global\\ChomcioRecovery.Cancel."+Id(root);
    internal static bool Acquire(Mutex mutex)
    {try{return mutex.WaitOne(0);}catch(AbandonedMutexException){return true;}}
    internal static bool Cancel(string root)
    {
        try{using var signal=EventWaitHandle.OpenExisting(CancelName(root));signal.Set();return true;}
        catch(WaitHandleCannotBeOpenedException){return false;}
    }
}

internal sealed record BackgroundCopyState(string State,string Detail,DateTimeOffset Updated,int Completed=0,int Total=0);

internal static class BackgroundCopies
{
    internal const string Switch="--scheduled-run";
    internal static BackgroundCopyState? ReadState(string root)
    {
        string path=Path.Combine(root,"background-status.json");StudioStore.RejectLinks(path);
        if(!File.Exists(path))return null;
        if(new FileInfo(path).Length>65536)throw new IOException("Nieprawidłowy stan pracy w tle.");
        using var input=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete);
        return JsonSerializer.Deserialize<BackgroundCopyState>(input);
    }
    private static void WriteState(string root,BackgroundCopyState value)
    {
        StudioStore.RejectLinks(root);Directory.CreateDirectory(root);
        string target=Path.Combine(root,"background-status.json"),stage=Path.Combine(root,"background-"+Guid.NewGuid().ToString("N")+".tmp");
        StudioStore.RejectLinks(target);
        try
        {
            using(var stream=new FileStream(stage,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough))
            {JsonSerializer.Serialize(stream,value);stream.Flush(true);}
            File.Move(stage,target,true);
        }
        finally{if(File.Exists(stage))File.Delete(stage);}
    }
    // Synchronous outer lifetime preserves mutex ownership on the entry thread.
    // No forms, message boxes or interactive credential prompts in Session 0.
    internal static int RunOnce(string root,Func<StudioStore,JobEngine>? factory=null,string? bootForTest=null)
    {
        using var mutex=StudioProcessScope.Create(root);
        if(!StudioProcessScope.Acquire(mutex))return 0;
        try{return ExecuteAsync(root,factory,bootForTest).GetAwaiter().GetResult();}
        catch(Exception)
        {
            try{WriteState(root,new("Failed","Nie uruchomiono kopii w tle. Otwórz Chomcio i sprawdź ustawienia.",DateTimeOffset.UtcNow));}catch(Exception){}
            return 1;
        }
        finally{mutex.ReleaseMutex();}
    }
    private static async Task<int> ExecuteAsync(string root,Func<StudioStore,JobEngine>? factory,string? bootForTest)
    {
        var store=new StudioStore(root);
        if(store.Data.Paused){WriteState(root,new("Paused","Automatyczne kopie są wstrzymane.",DateTimeOffset.UtcNow));return 0;}
        var engine=factory?.Invoke(store)??new JobEngine(store);
        using var cancel=new EventWaitHandle(false,EventResetMode.ManualReset,StudioProcessScope.CancelName(root));
        var registration=ThreadPool.RegisterWaitForSingleObject(cancel,(_,_)=>engine.Cancel(),null,Timeout.Infinite,true);
        object progressLock=new();bool reporting=true;DateTimeOffset last=DateTimeOffset.MinValue;
        engine.Changed+=()=>
        {
            lock(progressLock)
            {
                if(!reporting||DateTimeOffset.UtcNow-last<TimeSpan.FromSeconds(1))return;
                last=DateTimeOffset.UtcNow;
                try{WriteState(root,new("Running",engine.Phase,last,engine.CompletedRecords,engine.TotalRecords));}catch(IOException){}
            }
        };
        bool failed=false,ran=false;
        try
        {
            string? boot=store.Data.Profiles.Any(p=>p.Enabled&&p.AtBoot)?bootForTest??BootIdentity.Read():null;
            foreach(var profile in store.Data.Profiles.ToArray())
            {
                if(cancel.WaitOne(0))break;
                var now=DateTimeOffset.Now;
                if(!SchedulePolicy.Due(profile,now,null,store.Data.Paused,boot))continue;
                ran=true;
                JobSecrets secrets;
                try{secrets=WindowsSecrets.Unprotect(profile.ProtectedSecrets!);}
                catch(CryptographicException)
                {
                    failed=true;SchedulePolicy.MarkAttempt(profile,now,null,boot);
                    store.Data.History.Add(new(){ProfileId=profile.Id,Name=profile.Name,State=RunState.Failed,Finished=now,Detail="Windows nie odblokował zapamiętanych kluczy. Otwórz ustawienia kopii."});store.Save();continue;
                }
                var result=await engine.RunAsync(profile,secrets,now,boot:boot).ConfigureAwait(false);
                failed|=result?.State==RunState.Failed;
            }
            lock(progressLock)
            {
                reporting=false;
                WriteState(root,new(cancel.WaitOne(0)?"Cancelled":failed?"Failed":"Ready",
                    cancel.WaitOne(0)?"Zatrzymano oczekiwanie i wysyłanie; sprawdź historię.":failed?"Kopia wymaga uwagi. Sprawdź historię w Chomcio.":ran?"Zakończono zaplanowane kopie. Wyniki zapisano w historii.":"Brak kopii oczekujących na wykonanie.",DateTimeOffset.UtcNow));
            }
            return failed?1:0;
        }
        finally{lock(progressLock){reporting=false;}registration.Unregister(null);}
    }
}

internal static class BootIdentity
{
    internal static string Read()
    {
        dynamic locator=Activator.CreateInstance(Type.GetTypeFromProgID("WbemScripting.SWbemLocator")!)!;
        dynamic? service=null,rows=null;
        try
        {
            service=locator.ConnectServer(".","root\\cimv2");
            rows=service.ExecQuery("SELECT LastBootUpTime FROM Win32_OperatingSystem");
            foreach(dynamic row in rows)
            {
                dynamic? properties=null,property=null;
                try{properties=row.Properties_;property=properties.Item("LastBootUpTime");string value=(string)property.Value;if(value.Length is >=14 and <=32)return value;}
                finally{if(property is not null)Marshal.FinalReleaseComObject(property);if(properties is not null)Marshal.FinalReleaseComObject(properties);Marshal.FinalReleaseComObject(row);}
            }
            throw new IOException("Nie odczytano uruchomienia Windows.");
        }
        finally{if(rows is not null)Marshal.FinalReleaseComObject(rows);if(service is not null)Marshal.FinalReleaseComObject(service);Marshal.FinalReleaseComObject(locator);}
    }
}

internal sealed class BackgroundWaitWindow : Form
{
    private readonly System.Windows.Forms.Timer timer=new(){Interval=1000};
    private readonly Label status=StudioTheme.Label("Trwa praca Chomcio w tle.",11,StudioTheme.Muted);
    internal bool Acquired {get;private set;}
    internal BackgroundWaitWindow(string root,Mutex mutex)
    {
        StudioTheme.Form(this);Text="Trwa automatyczna kopia • ChomcioRecovery";ClientSize=new(570,260);StartPosition=FormStartPosition.CenterScreen;
        var body=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new(24),ColumnCount=1};Controls.Add(body);
        body.Controls.Add(StudioTheme.Label("Twoja kopia jest wykonywana",20,null,true));
        status.AutoSize=false;status.Size=new(510,95);body.Controls.Add(status);
        body.Controls.Add(StudioTheme.Button("Zatrzymaj kopię i otwórz program",()=>
        {status.Text=StudioProcessScope.Cancel(root)?"Kończenie zapisu. Poczekaj na potwierdzenie.":"Program działa w innej sesji Windows. Otwórz go w tej sesji lub poczekaj na zakończenie.";}));
        timer.Tick+=(_,_)=>
        {
            if(StudioProcessScope.Acquire(mutex)){Acquired=true;timer.Stop();Close();return;}
            try{var state=BackgroundCopies.ReadState(root);if(state is not null)status.Text=state.Detail+"\nProgram otworzy się po bezpiecznym zakończeniu zadania.";}catch(Exception){}
        };
        timer.Start();
    }
    protected override void Dispose(bool disposing){if(disposing)timer.Dispose();base.Dispose(disposing);}
}
