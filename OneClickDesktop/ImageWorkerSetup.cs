using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using ChomcioRecovery.SystemImages;

namespace ChomcioRecovery.Desktop;

internal static class ImageWorkerSetup
{
    internal static ProcessStartInfo Command(string applicationDirectory,string ownerSid,string target,string planId)
    {
        if(!Path.IsPathFullyQualified(applicationDirectory)||!BrokerFiles.IsId(planId))
            throw new ArgumentException("Niepoprawna paczka lub konfiguracja modułu.");
        var sid=new SecurityIdentifier(ownerSid);
        if(!sid.IsAccountSid())throw new ArgumentException("Wybierz indywidualne konto Windows.");
        if(target.Length!=3||!char.IsAsciiLetter(target[0])||target[1]!=':'||target[2]!='\\')
            throw new ArgumentException("Wybierz lokalny dysk roboczy.");
        if(target.Equals(Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)),StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Dysk Windows nie może być miejscem obrazu.");
        string package=Path.Combine(applicationDirectory,"image-worker","payload"),executable=Path.Combine(package,"ChomcioRecovery.ImageWorker.exe");
        StudioStore.RejectLinks(package);StudioStore.RejectLinks(executable);
        if(!File.Exists(executable)||!File.Exists(Path.Combine(package,"package-hashes.json")))
            throw new IOException("Brakuje modułu systemowego w paczce. Rozpakuj cały komplet programu.");
        var info=new ProcessStartInfo(executable)
        {UseShellExecute=true,Verb="runas",WindowStyle=ProcessWindowStyle.Hidden};
        foreach(string arg in new[]{"--install",sid.Value,target,planId})info.ArgumentList.Add(arg);
        return info;
    }
    internal static void CheckTarget(string target)
    {
        var drive=new DriveInfo(target);
        if(!drive.IsReady||drive.DriveType!=DriveType.Fixed||drive.DriveFormat!="NTFS")
            throw new ArgumentException("Potrzebny jest osobny, pusty lokalny dysk NTFS.");
        StudioStore.RejectLinks(drive.RootDirectory.FullName);
        if(Directory.EnumerateFileSystemEntries(target).Any(p=>Path.GetFileName(p) is not ("System Volume Information" or "$RECYCLE.BIN")))
            throw new ArgumentException("Wybrany dysk zawiera pliki. Wybierz pusty dysk; program niczego nie usuwa ani nie formatuje.");
        var source=new DriveInfo(SystemImagePlan.SystemDrive+"\\");
        long used=source.TotalSize-source.AvailableFreeSpace;
        if(drive.AvailableFreeSpace<checked(used*4+(2L<<30)))
            throw new ArgumentException("Za mało miejsca. Zarezerwuj około cztery razy zajętość Windows na obraz, archiwum i szyfrowaną kopię.");
    }
}

internal sealed class ImageWorkerSetupWindow : Form,IInlineFeedback
{
    private readonly ComboBox targets=new(){Name="ImageSetupTarget",DropDownStyle=ComboBoxStyle.DropDownList};
    private readonly CheckBox consent=new(){Name="ImageSetupConsent",Text="Przeznaczam wybrany pusty dysk na kopie Windows.",AutoSize=true};
    private readonly Label status=StudioTheme.Label("Instalacja nie uruchamia tworzenia obrazu.",10,StudioTheme.Muted);
    private readonly StudioButton install;
    private bool running;
    internal ImageWorkerSetupWindow()
    {
        StudioTheme.Form(this);Text="Przygotuj kopie Windows • ChomcioRecovery";ClientSize=new(700,420);StartPosition=FormStartPosition.CenterParent;
        var body=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,Padding=new(25)};Controls.Add(body);
        void Add(Control c,int height){int row=body.RowCount++;body.RowStyles.Add(new(SizeType.Absolute,height));c.Dock=DockStyle.Fill;body.Controls.Add(c,0,row);}
        Add(StudioTheme.Label("Przygotuj moduł Windows",23,null,true),58);
        Add(StudioTheme.Label("Wybierz pusty dysk NTFS, inny niż Windows. Program zainstaluje\nmoduł z uprawnieniami administratora i ograniczy dostęp do dysku.\nNie formatuje nośników i nie usuwa istniejących danych.\nObraz i jego szyfrowana kopia wymagają miejsca roboczego.",10,StudioTheme.Muted),100);
        foreach(var drive in DriveInfo.GetDrives())
            try{if(drive.IsReady&&drive.DriveType==DriveType.Fixed&&drive.DriveFormat=="NTFS"&&drive.Name[..2]!=SystemImagePlan.SystemDrive)targets.Items.Add(drive.Name);}catch(IOException){}
        Add(targets,40);Add(consent,42);
        install=StudioTheme.AsyncButton("Zainstaluj moduł Windows",InstallAsync,true);install.Name="InstallImageWorker";Add(install,48);
        status.AutoSize=false;Add(status,70);
        FormClosing+=(_,e)=>{if(running){e.Cancel=true;ShowFeedback("Trwa instalacja modułu. Poczekaj na jej wynik.");}};
    }
    private async Task InstallAsync()
    {
        if(!consent.Checked||targets.SelectedItem is not string target){ShowFeedback("Wybierz dysk i potwierdź jego przeznaczenie.");return;}
        string plan=Guid.NewGuid().ToString("N");
        running=true;install.Enabled=targets.Enabled=consent.Enabled=false;
        try
        {
            ImageWorkerSetup.CheckTarget(target);
            var command=ImageWorkerSetup.Command(AppContext.BaseDirectory,WindowsIdentity.GetCurrent().User!.Value,target,plan);
            ShowFeedback("Potwierdź instalację w oknie administratora Windows.");
            using var process=Process.Start(command)??throw new IOException("Nie uruchomiono instalacji.");
            await process.WaitForExitAsync();
            if(process.ExitCode!=0){ShowFeedback(process.ExitCode switch{
                41=>"Moduł lub jego konfiguracja już istnieje. Zachowano poprzednią instalację.",
                43=>"Paczka modułu jest niekompletna albo zmieniona. Pobierz ponownie cały komplet programu.",
                45=>"Wybierz osobny, pusty lokalny dysk NTFS. Niczego nie sformatowano.",
                46=>"Na dysku roboczym brakuje miejsca na obraz i jego szyfrowaną kopię.",
                47=>"Windows nie przyznał uprawnień administratora. Nie rozpoczęto kopii.",
                _=>"Instalacja nie została potwierdzona (kod "+process.ExitCode+"). Zachowano pliki; sprawdź uprawnienia i konfigurację."});return;}
            if(!new InstalledSystemImagePlans().List().Any(p=>p.Id==plan))throw new IOException("Nie potwierdzono zainstalowanej konfiguracji.");
            DialogResult=DialogResult.OK;
        }
        catch(Win32Exception e)when(e.NativeErrorCode==1223){ShowFeedback("Anulowano zgodę administratora. Nie rozpoczęto kopii.");}
        catch(ArgumentException e){ShowFeedback(e.Message);}
        finally{running=false;install.Enabled=targets.Enabled=consent.Enabled=true;}
    }
    public void ShowFeedback(string text){if(!IsDisposed)status.Text=text;}
}
