using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace ChomcioRecovery.Desktop;

internal enum BackupDestination { Local, Chomikuj }
internal enum BackupContent { Files, WindowsSystem }
internal enum RunState { Running, Success, Failed, Cancelled, Interrupted }
internal sealed class BackupProfile
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "Moje dokumenty";
    public string Source { get; set; } = "";
    public string Repository { get; set; } = "";
    public BackupDestination Destination { get; set; }
    public BackupContent Content { get; set; }
    // Identifies an administrator-approved, immutable capture plan. Never a command,
    // executable or path supplied to an elevated process by this settings file.
    public string? SystemImagePlanId { get; set; }
    public string? SystemImageCacheRoot { get; set; }
    public PendingSystemImage? PendingSystemImage { get; set; }
    public bool Enabled { get; set; } = true;
    public bool AtLogon { get; set; }
    public bool AtBoot { get; set; }
    public string? LastBoot { get; set; }
    public bool Daily { get; set; }
    public int DailyMinute { get; set; } = 20 * 60;
    public string? ProtectedSecrets { get; set; }
    public string? RemoteFolderId { get; set; }
    public string? RemoteFolderName { get; set; }
    public bool CloudDateFolders { get; set; }
    public bool ProtectCloudFolder { get; set; }
    public string? RemoteFolderDate { get; set; }
    public bool RemoteFolderHasConfirmedCopy { get; set; }
    public string? PendingCloudDate { get; set; }
    public List<UnconfirmedCloudFolder> ArchivedCloudFolders { get; set; } = new();
    public List<UnconfirmedCloudFolder> PreviousUnconfirmedCloudFolders { get; set; } = new();
    public string? PendingSnapshot { get; set; }
    public string? LastSnapshot { get; set; }
    public string? LastLogon { get; set; }
    public DateTimeOffset? LastAttempt { get; set; }
    public DateTimeOffset? LastSuccess { get; set; }
    public string? LastDailyDate { get; set; }
    public bool SkipSystemDirectoryLinks { get; set; } = true;
    public override string ToString() => Name;
}
internal sealed record UnconfirmedCloudFolder(string Id,string Name);
internal sealed record JobSecrets(string VaultPassword, string CloudLogin, string CloudPassword,string? FolderPassword=null);
internal sealed class RunRecord
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string ProfileId { get; set; } = "";
    public string Name { get; set; } = "";
    public DateTimeOffset Started { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? Finished { get; set; }
    public RunState State { get; set; }
    public string Detail { get; set; } = "";
    public string? FailureCode { get; set; }
    public string? FailureStage { get; set; }
    public int? HttpStatus { get; set; }
    public double? RetryAfterSeconds { get; set; }
    public string? HttpOperation { get; set; }
    public string? Snapshot { get; set; }
    public BackupContent Content { get; set; }
    public string? ImageCaptureId { get; set; }
    public int Files { get; set; }
    public long Bytes { get; set; }
    public List<string> SkippedSystemDirectoryLinks { get; set; } = new();
}
internal sealed class StudioSettings
{
    public int Version { get; set; } = 1;
    public bool Paused { get; set; }
    public bool CloseToTray { get; set; } = true;
    public bool Notifications { get; set; } = true;
    public bool UseOwnKeyForNewCopies { get; set; }
    public string? ProtectedAccount { get; set; }
    public List<BackupProfile> Profiles { get; set; } = new();
    public List<RunRecord> History { get; set; } = new();
}

internal static class StudioCredentials
{
    internal static JobSecrets? Account(StudioStore store)
    {
        if(store.Data.ProtectedAccount is not null)
            return WindowsSecrets.Unprotect(store.Data.ProtectedAccount) with{VaultPassword="",FolderPassword=null};
        foreach(var p in store.Data.Profiles.Where(p=>p.Destination==BackupDestination.Chomikuj && p.ProtectedSecrets is not null))
        {
            try { var s=WindowsSecrets.Unprotect(p.ProtectedSecrets!); return s with { VaultPassword="",FolderPassword=null }; }
            catch(CryptographicException) { }
        }
        return null;
    }
    internal static void RememberAccount(StudioStore store,JobSecrets secrets)
    {
        if(string.IsNullOrWhiteSpace(secrets.CloudLogin)||string.IsNullOrEmpty(secrets.CloudPassword))return;
        store.Data.ProtectedAccount=WindowsSecrets.Protect(secrets with { VaultPassword="",FolderPassword=null });
        // Refresh remembered passwords for this account without changing vault keys.
        foreach(var p in store.Data.Profiles.Where(p=>p.ProtectedSecrets is not null))
        {
            try
            {
                var s=WindowsSecrets.Unprotect(p.ProtectedSecrets!);
                if(s.CloudLogin.Equals(secrets.CloudLogin,StringComparison.OrdinalIgnoreCase))
                    p.ProtectedSecrets=WindowsSecrets.Protect(s with {CloudPassword=secrets.CloudPassword});
            }
            catch(CryptographicException) { }
        }
    }
    internal static void Forget(StudioStore store)
    {
        store.Data.ProtectedAccount=null;
        foreach(var p in store.Data.Profiles) { p.ProtectedSecrets=null; p.AtLogon=p.AtBoot=p.Daily=false; }
        store.Save();
    }
}

internal sealed class StudioStore
{
    internal string Root { get; }
    internal StudioSettings Data { get; private set; }
    internal static string DefaultRoot => Environment.GetEnvironmentVariable("CHOMCIO_STUDIO_HOME")
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ChomcioRecovery", "Studio");
    internal StudioStore(string root)
    {
        Root = Path.GetFullPath(root);
        RejectLinks(Root);
        string file = Path.Combine(Root, "settings.json");
        if (File.Exists(file))
        {
            RejectLinks(file);
            if (new FileInfo(file).Length > 8 * 1024 * 1024) throw new InvalidDataException("Ustawienia są zbyt duże.");
            try { Data = JsonSerializer.Deserialize<StudioSettings>(File.ReadAllText(file)) ?? throw new JsonException(); }
            catch (JsonException) { throw new InvalidDataException("Nie można odczytać ustawień. Zachowano plik; nie utworzono pustej konfiguracji."); }
            if (Data.Version != 1 || Data.Profiles is null || Data.History is null ||
                Data.Profiles.Any(p => p is null || !Guid.TryParseExact(p.Id,"N",out _)) ||
                Data.Profiles.Select(p=>p.Id).Distinct().Count()!=Data.Profiles.Count)
                throw new InvalidDataException("Nieobsługiwana lub niepełna konfiguracja.");
            foreach (var item in Data.History.Where(h=>h.State==RunState.Running))
            { item.State=RunState.Interrupted; item.Detail="Program został zamknięty podczas operacji. Można ponowić zadanie."; }
        }
        else Data = new();
    }
    internal void Save()
    {
        RejectLinks(Root); Directory.CreateDirectory(Root);
        string target=Path.Combine(Root,"settings.json"); RejectLinks(target);
        Data.History = Data.History.TakeLast(500).ToList();
        byte[] bytes=JsonSerializer.SerializeToUtf8Bytes(Data,new JsonSerializerOptions{WriteIndented=true});
        string stage=Path.Combine(Root,"settings-"+Guid.NewGuid().ToString("N")+".tmp");
        using(var file=new FileStream(stage,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough))
        { file.Write(bytes); file.Flush(true); }
        File.Move(stage,target,true);
    }
    internal static void RejectLinks(string path)
    {
        for(string? p=Path.GetFullPath(path);p is not null;p=Path.GetDirectoryName(p))
            if ((File.Exists(p)||Directory.Exists(p)) && (File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)
                throw new IOException("Ścieżka ustawień lub danych zawiera niedozwolone przekierowanie.");
    }
}

// DPAPI CurrentUser: no machine-wide flag, no plaintext passwords in JSON.
internal static class WindowsSecrets
{
    [StructLayout(LayoutKind.Sequential)] private struct Blob { internal int Length; internal IntPtr Data; }
    [DllImport("crypt32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CryptProtectData(ref Blob input,string? description,IntPtr entropy,IntPtr reserved,IntPtr prompt,uint flags,out Blob output);
    [DllImport("crypt32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CryptUnprotectData(ref Blob input,IntPtr description,IntPtr entropy,IntPtr reserved,IntPtr prompt,uint flags,out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    internal static string Protect(JobSecrets secrets)
    {
        byte[] plain=JsonSerializer.SerializeToUtf8Bytes(secrets);
        try { return Convert.ToBase64String(Transform(plain,true)); }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }
    internal static JobSecrets Unprotect(string protectedValue)
    {
        byte[]? plain=null;
        try { plain=Transform(Convert.FromBase64String(protectedValue),false); return JsonSerializer.Deserialize<JobSecrets>(plain)??throw new CryptographicException(); }
        catch(Exception ex) when(ex is FormatException or JsonException or CryptographicException)
        { throw new CryptographicException("Windows nie odblokował zapamiętanych haseł. Wpisz je ponownie w ustawieniach zadania."); }
        finally { if(plain is not null) CryptographicOperations.ZeroMemory(plain); }
    }
    private static byte[] Transform(byte[] input,bool protect)
    {
        var source=new Blob{Length=input.Length,Data=Marshal.AllocHGlobal(input.Length)};
        Blob output=default;
        try
        {
            Marshal.Copy(input,0,source.Data,input.Length);
            bool ok=protect?CryptProtectData(ref source,null,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,1,out output):CryptUnprotectData(ref source,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,1,out output);
            if(!ok) throw new CryptographicException("Windows nie zabezpieczył danych konta.");
            var result=new byte[output.Length]; Marshal.Copy(output.Data,result,0,result.Length); return result;
        }
        finally
        {
            if(source.Data!=IntPtr.Zero) { Marshal.Copy(new byte[source.Length],0,source.Data,source.Length); Marshal.FreeHGlobal(source.Data); }
            if(output.Data!=IntPtr.Zero) { Marshal.Copy(new byte[output.Length],0,output.Data,output.Length); LocalFree(output.Data); }
        }
    }
}

internal static class StartupRegistration
{
    internal const string ValueName="ChomcioRecovery by Swir";
    internal const string RunKey=@"Software\Microsoft\Windows\CurrentVersion\Run";
    internal static string Command(string executable)
    {
        string path=Path.GetFullPath(executable);
        if(path.Contains('"')||path.Contains('\n')||path.Contains('\r')) throw new ArgumentException("Niepoprawna ścieżka programu.");
        string command="\""+path+"\" --autostart";
        if(command.Length>260) throw new IOException("Ścieżka programu jest za długa dla autostartu. Przenieś cały folder App do krótszej lokalizacji.");
        return command;
    }
    internal static bool IsEnabled(string? keyPath=null)
    { using var key=Registry.CurrentUser.OpenSubKey(keyPath??RunKey); return key?.GetValue(ValueName) is string s && s==Command(Application.ExecutablePath); }
    internal static void SetEnabled(bool enabled,string? keyPath=null)
    {
        using var key=Registry.CurrentUser.CreateSubKey(keyPath??RunKey,true);
        if(enabled) key.SetValue(ValueName,Command(Application.ExecutablePath),RegistryValueKind.String);
        else key.DeleteValue(ValueName,false);
    }
}

internal static class SchedulePolicy
{
    internal static bool Due(BackupProfile profile,DateTimeOffset now,string? logon,bool paused,string? boot=null)
    {
        if(paused||!profile.Enabled||profile.ProtectedSecrets is null) return false;
        if(profile.AtBoot && boot is not null && profile.LastBoot!=boot) return true;
        if(profile.AtLogon && logon is not null && profile.LastLogon!=logon) return true;
        return profile.Daily && profile.DailyMinute is >=0 and <1440 &&
            now.Hour*60+now.Minute>=profile.DailyMinute && profile.LastDailyDate!=now.ToString("yyyy-MM-dd");
    }
    internal static void MarkAttempt(BackupProfile profile,DateTimeOffset now,string? logon,string? boot=null)
    {
        profile.LastAttempt=now;
        if(profile.AtBoot && boot is not null) profile.LastBoot=boot;
        if(profile.AtLogon && logon is not null) profile.LastLogon=logon;
        if(profile.Daily && now.Hour*60+now.Minute>=profile.DailyMinute) profile.LastDailyDate=now.ToString("yyyy-MM-dd");
    }
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(IntPtr token,int info,IntPtr data,int length,out int needed);
    internal static string LogonId()
    {
        using var identity=System.Security.Principal.WindowsIdentity.GetCurrent();
        IntPtr data=Marshal.AllocHGlobal(128);
        try { if(!GetTokenInformation(identity.AccessToken.DangerousGetHandle(),10,data,128,out _)) throw new IOException("Nie można ustalić sesji Windows."); return Marshal.ReadInt64(data,8).ToString("X16"); }
        finally { Marshal.FreeHGlobal(data); }
    }
}
