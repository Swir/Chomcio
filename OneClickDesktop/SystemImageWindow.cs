using System.Diagnostics;
using System.Security.Principal;

namespace ChomcioRecovery.Desktop;

internal static class SystemImagePlan
{
    internal static string Drive(string value)
    {
        if(value.Length!=2||!char.IsAsciiLetter(value[0])||value[1]!=':')throw new ArgumentException("Wybierz lokalny dysk docelowy.");
        return value.ToUpperInvariant();
    }
    internal static string[] Arguments(string destination,string system)
    {
        string target=Drive(destination),source=Drive(system);
        if(target==source)throw new ArgumentException("Obraz systemu wymaga innego dysku niż Windows.");
        return new[]{"start","backup","-backupTarget:"+target,"-include:"+source,"-allCritical","-vssCopy","-quiet"};
    }
    internal static string SystemDrive=>Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))![..2];
    internal static string Tool=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"wbadmin.exe");
    internal static void Preflight(string target)
    {
        _=Arguments(target,SystemDrive);
        if(!File.Exists(Tool))throw new IOException("Ta instalacja Windows nie udostępnia narzędzia tworzenia obrazu.");
        var disk=new DriveInfo(Drive(target)+"\\");
        if(!disk.IsReady||disk.DriveType is not (DriveType.Fixed or DriveType.Removable)||disk.DriveFormat!="NTFS")
            throw new IOException("Wybierz dostępny lokalny dysk NTFS.");
        if(Directory.Exists(Path.Combine(disk.RootDirectory.FullName,"WindowsImageBackup")))
            throw new IOException("Na tym dysku są już obrazy Windows. Ta wersja ich nie zmienia; wybierz inny dysk przeznaczony na nowy obraz.");
        var source=new DriveInfo(SystemDrive+"\\");
        long minimum=source.TotalSize-source.AvailableFreeSpace;
        if(disk.AvailableFreeSpace<minimum+Math.Max(2L<<30,minimum/10))
            throw new IOException("Dysk ma za mało wolnego miejsca dla konserwatywnego oszacowania obrazu systemu.");
    }
}

internal sealed class SystemImageWindow : Form
{
    private readonly ComboBox targets=new(){DropDownStyle=ComboBoxStyle.DropDownList,Width=500,BackColor=StudioTheme.Raised,ForeColor=StudioTheme.Ink};
    private readonly RichTextBox log=new(){ReadOnly=true,Dock=DockStyle.Fill,BackColor=StudioTheme.Sidebar,ForeColor=StudioTheme.Muted,BorderStyle=BorderStyle.None};
    private readonly StudioButton start;
    private bool running;
    internal SystemImageWindow(string? target=null)
    {
        StudioTheme.Form(this);Text="Obraz Windows • ChomcioRecovery";ClientSize=new(760,620);MinimumSize=new(700,580);StartPosition=FormStartPosition.CenterParent;
        var root=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new(28),ColumnCount=1,RowCount=6};Controls.Add(root);
        root.RowStyles.Add(new(SizeType.Absolute,62));root.RowStyles.Add(new(SizeType.Absolute,115));root.RowStyles.Add(new(SizeType.Absolute,50));root.RowStyles.Add(new(SizeType.Absolute,70));root.RowStyles.Add(new(SizeType.Percent,100));root.RowStyles.Add(new(SizeType.Absolute,35));
        root.Controls.Add(StudioTheme.Label("Obraz Windows i partycji startowych",23,null,true),0,0);
        var note=StudioTheme.Label("Windows wykona obraz systemu przez VSS. Programy i ustawienia na dysku\nsystemowym zostaną objęte kopią. Użyj osobnego, zewnętrznego dysku NTFS.\nObraz nie jest szyfrowany przez Chomcio. W tej wersji nie wysyłamy go do chmury.\nTworzenie obrazu wymaga uprawnień administratora i może potrwać długo.",10,StudioTheme.Muted);root.Controls.Add(note,0,1);
        foreach(var drive in DriveInfo.GetDrives())
        {try{if(drive.IsReady&&drive.Name[..2]!=SystemImagePlan.SystemDrive&&drive.DriveType is DriveType.Fixed or DriveType.Removable)targets.Items.Add(new DriveChoice(drive.Name[..2],drive.VolumeLabel,drive.AvailableFreeSpace));}catch(IOException){}}
        if(target is not null){SystemImagePlan.Drive(target);targets.SelectedItem=targets.Items.Cast<DriveChoice>().FirstOrDefault(d=>d.Drive==target.ToUpperInvariant());}
        root.Controls.Add(targets,0,2);
        start=StudioTheme.AsyncButton("Utwórz obraz Windows",StartAsync,true);start.Width=230;root.Controls.Add(start,0,3);root.Controls.Add(log,0,4);
        root.Controls.Add(StudioTheme.Label("Eksperymentalny moduł. Odtworzenie obrazu wymaga osobnego testu w WinRE.",8,StudioTheme.Amber),0,5);
        FormClosing+=(_,e)=>{if(running){e.Cancel=true;MessageBox.Show(this,"Windows nadal wykonuje obraz. Poczekaj na zakończenie; zamknięcie okna nie przerywa zapisu.","Trwa obraz systemu");}};
        Write("Wybierz dysk przeznaczony na nowy obraz. Istniejące obrazy Windows blokują rozpoczęcie.");
    }
    private async Task StartAsync()
    {
        if(targets.SelectedItem is not DriveChoice choice)throw new ArgumentException("Najpierw wybierz dysk docelowy.");
        SystemImagePlan.Preflight(choice.Drive);
        if(MessageBox.Show(this,$"Utworzyć lokalny obraz Windows na {choice.Drive}?\n\nObraz zawiera dane systemu. Nie będzie szyfrowany przez Chomcio.\nUpewnij się, że jest to dysk przeznaczony na tę kopię.\nIstniejące pliki nie będą formatowane.","Rozpocznij obraz systemu",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes)return;
        using var identity=WindowsIdentity.GetCurrent();
        if(!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            // Elevation happens only after a deliberate click. No credentials,
            // script text, arbitrary command or user-provided path is elevated.
            var info=new ProcessStartInfo(Application.ExecutablePath){UseShellExecute=true,Verb="runas"};
            info.ArgumentList.Add("--image-backup");info.ArgumentList.Add(choice.Drive);
            try{using var elevated=Process.Start(info);Write("Otwarto okno administratora. Potwierdź wybrany dysk w tym oknie.");}
            catch(System.ComponentModel.Win32Exception){Write("Nie uruchomiono modułu administratora.");}
            return;
        }
        running=true;start.Enabled=targets.Enabled=false;
        try
        {
            SystemImagePlan.Preflight(choice.Drive);
            Write("Windows rozpoczyna tworzenie obrazu. W tym module nie przerywamy procesu przez wymuszone zamknięcie.");
            var info=new ProcessStartInfo(SystemImagePlan.Tool){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
            foreach(string arg in SystemImagePlan.Arguments(choice.Drive,SystemImagePlan.SystemDrive))info.ArgumentList.Add(arg);
            using var worker=new Process{StartInfo=info};
            worker.OutputDataReceived+=(_,e)=>{if(e.Data is not null&&!IsDisposed)BeginInvoke(()=>Write(e.Data));};
            worker.ErrorDataReceived+=(_,e)=>{if(e.Data is not null&&!IsDisposed)BeginInvoke(()=>Write(e.Data));};
            worker.Start();worker.BeginOutputReadLine();worker.BeginErrorReadLine();await worker.WaitForExitAsync();
            Write(worker.ExitCode==0?"Windows zgłosił zakończenie obrazu. To nie potwierdza testu odtworzenia; sprawdź obraz w środowisku WinRE.":"Windows nie potwierdził obrazu. Kod zakończenia: "+worker.ExitCode+". Nie oznaczono go jako sprawdzonej kopii.");
        }
        finally{running=false;start.Enabled=targets.Enabled=true;}
    }
    private void Write(string value){log.AppendText(value+Environment.NewLine);log.ScrollToCaret();}
    private sealed record DriveChoice(string Drive,string Label,long Free){public override string ToString()=>$"{Drive}   {Label}   /   wolne {StudioTheme.Bytes(Free)}";}
}
