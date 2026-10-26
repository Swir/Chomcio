using System.IO.Compression;
using System.Security.Cryptography;
using ChomcioRecovery.Core;
using ChomcioRecovery.SystemImages;

namespace ChomcioRecovery.Desktop;

internal sealed class RecoveryTargetExistsException : IOException
{
    internal RecoveryTargetExistsException() : base("Na wybranym dysku jest już WindowsImageBackup. Zachowaj tę kopię i wybierz inny dysk.") { }
}

internal static class SystemImageRecovery
{
    internal static string Destination(string existingParent,bool requireVolumeRoot=true)
    {
        if(!Path.IsPathFullyQualified(existingParent)||!Directory.Exists(existingParent))
            throw new ArgumentException("Wybierz dostępny dysk do przygotowania obrazu.");
        string parent=Path.GetFullPath(existingParent);
        StudioStore.RejectLinks(parent);
        if(requireVolumeRoot)
        {
            if(!SystemImageStorage.SamePath(parent,Path.GetPathRoot(parent)!))
                throw new ArgumentException("Wybierz główny katalog dysku, np. E:\\, aby WinRE znalazło obraz.");
            if(SystemImageStorage.SamePath(parent,Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))!))
                throw new ArgumentException("Obrazu do odzyskania nie umieszczamy na dysku działającego Windows.");
            var drive=new DriveInfo(parent);
            if(!drive.IsReady||drive.DriveFormat!="NTFS"||drive.DriveType is not (DriveType.Fixed or DriveType.Removable))
                throw new ArgumentException("Wybierz dostępny lokalny dysk NTFS.");
        }
        string target=Path.Combine(parent,"WindowsImageBackup");
        if(File.Exists(target)||Directory.Exists(target))
            throw new RecoveryTargetExistsException();
        return target;
    }

    // Test-only parent relaxation never bypasses path, ACL, identity or content
    // checks. The GUI always requires a separate volume root. No disk is formatted.
    internal static async Task<string> PrepareAsync(string bundle,string parent,IProgress<string>? progress,
        CancellationToken token,bool requireVolumeRoot=true)
    {
        string target=Destination(parent,requireVolumeRoot);
        using var pinnedParent=WindowsRestoreParentPin.Acquire(parent);
        using var pinnedBundle=WindowsRestoreParentPin.Acquire(bundle);
        var receipt=BrokerFiles.Read<SystemImageReceipt>(Path.Combine(bundle,SystemImageLease.ReceiptName));
        progress?.Report("Sprawdzanie integralności pobranego obrazu…");
        using var lease=await SystemImageLease.OpenAsync(bundle,new(receipt.PlanId,receipt.CaptureId,receipt.RequestedUtc),token);
        using var input=new FileStream(Path.Combine(bundle,SystemImageLease.ArchiveName),FileMode.Open,FileAccess.Read,FileShare.Read);
        using var zip=new ZipArchive(input,ZipArchiveMode.Read);
        RestoreSpaceGuard.RequireAvailable(parent,zip.Entries.Select(e=>e.Length));
        token.ThrowIfCancellationRequested();
        var created=PrivateRestoreStage.CreateOwned(parent,".chomcio-windows-");
        string stage=created.Stage;
        using var guard=created.Guard;
        using var owned=new WindowsOwnedRestoreTreeCleanup(stage);
        var hashes=new Dictionary<string,(long Size,byte[] Hash)>(StringComparer.OrdinalIgnoreCase);
        bool published=false;
        try
        {
            int completed=0;
            foreach(var entry in zip.Entries)
            {
                token.ThrowIfCancellationRequested();
                string relative=entry.FullName["WindowsImageBackup/".Length..].TrimEnd('/');
                if(relative.Length==0)continue;
                string path=Path.GetFullPath(Path.Combine(stage,relative.Replace('/',Path.DirectorySeparatorChar)));
                if(!path.StartsWith(stage+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Plik wychodzi poza katalog odzyskiwania.");
                bool directory=entry.FullName.EndsWith('/');
                PrivateRestoreStage.CreatePrivateSubdirectory(stage,directory?path:Path.GetDirectoryName(path)!,
                    (p,h)=>owned.TrackNewDirectory(p,h),pinKnownParent:p=>owned.PinOwnedParentForWrite(p,guard));
                if(directory)continue;
                using var writeParent=owned.PinOwnedParentForWrite(Path.GetDirectoryName(path)!,guard);
                using var output=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None,1024*1024,FileOptions.Asynchronous);
                owned.TrackCreatedFile(path,output.SafeFileHandle);
                using var source=entry.Open();using var sha=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var buffer=new byte[1024*1024];long size=0;
                long nextReport=Environment.TickCount64+1000;
                while(true)
                {
                    int count=await source.ReadAsync(buffer,token);if(count==0)break;
                    size=checked(size+count);if(size>entry.Length)throw new InvalidDataException("Rozmiar obrazu przekracza opis archiwum.");
                    sha.AppendData(buffer,0,count);await output.WriteAsync(buffer.AsMemory(0,count),token);
                    if(Environment.TickCount64>=nextReport)
                    {
                        progress?.Report($"Zapisywanie pliku obrazu: {size/(1024*1024):N0} / {entry.Length/(1024*1024):N0} MB.");
                        nextReport=Environment.TickCount64+1000;
                    }
                }
                output.Flush(true);writeParent.RequireMatches();
                if(size!=entry.Length)throw new InvalidDataException("Niepełny plik obrazu.");
                hashes.Add(relative,(size,sha.GetHashAndReset()));
                progress?.Report($"Przygotowanie obrazu: {++completed} plików.");
            }
            owned.RequireOriginalInventoryForPublication(guard);
            using(var locked=owned.AcquireImmutableContentLeases(guard))
            {
                progress?.Report("Porównywanie zapisanych danych obrazu z archiwum…");
                await VerifyAsync(stage,hashes,token);
                owned.RequireOriginalInventoryForPublication(guard);pinnedParent.RequireMatches();guard.RequireMatches(stage);
                WindowsOwnedDirectoryPublisher.Publish(stage,target,guard,token);published=true;
            }
            owned.RequireOriginalPublishedInventory(target,guard,token);
            progress?.Report("Końcowa kontrola opublikowanego obrazu…");
            await VerifyAsync(target,hashes,token);
            owned.RequireOriginalPublishedInventory(target,guard,token);pinnedParent.RequireMatches();
            return target;
        }
        finally
        {
            // Never delete a published tree or recursively clean foreign paths.
            if(!published&&Directory.Exists(stage)){guard.RequireMatches(stage);owned.TryCleanup(guard);}
        }
    }
    private static async Task VerifyAsync(string root,Dictionary<string,(long Size,byte[] Hash)> expected,CancellationToken token)
    {
        foreach(var item in expected)
        {
            string path=Path.Combine(root,item.Key.Replace('/',Path.DirectorySeparatorChar));StudioStore.RejectLinks(path);
            using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read|FileShare.Delete,1024*1024,FileOptions.Asynchronous);
            if(file.Length!=item.Value.Size||!CryptographicOperations.FixedTimeEquals(await SHA256.HashDataAsync(file,token),item.Value.Hash))
                throw new InvalidDataException("Kontrola zapisanych plików obrazu nie powiodła się.");
        }
    }
}

internal sealed class SystemImageRecoveryWindow : Form,IInlineFeedback
{
    private readonly TextBox bundle=StudioTheme.Input(),destination=StudioTheme.Input();
    private readonly Label status=StudioTheme.Label("Przygotowanie nie zmienia działającego systemu ani partycji.",10,StudioTheme.Muted);
    private readonly StudioButton prepare,cancel;
    private CancellationTokenSource? active;
    internal SystemImageRecoveryWindow(string? source=null)
    {
        StudioTheme.Form(this);Text="Przygotuj odzyskiwanie Windows • ChomcioRecovery";ClientSize=new(760,620);MinimumSize=new(700,650);StartPosition=FormStartPosition.CenterParent;
        var body=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,Padding=new(24),AutoScroll=true};Controls.Add(body);
        void Add(Control c,int h){int r=body.RowCount++;body.RowStyles.Add(new(SizeType.Absolute,h));c.Dock=DockStyle.Fill;body.Controls.Add(c,0,r);}
        void Pick(TextBox field,string label){Add(StudioTheme.Label(label,10,StudioTheme.Muted),28);var row=new TableLayoutPanel{ColumnCount=2};row.ColumnStyles.Add(new(SizeType.Percent,100));row.ColumnStyles.Add(new(SizeType.Absolute,110));field.Dock=DockStyle.Fill;row.Controls.Add(field);var button=StudioTheme.Button("Wybierz",()=>{if(active is not null)return;using var dialog=new FolderBrowserDialog();if(dialog.ShowDialog(this)==DialogResult.OK)field.Text=dialog.SelectedPath;});button.Dock=DockStyle.Fill;row.Controls.Add(button,1,0);Add(row,45);}
        Add(StudioTheme.Label("Przygotuj pobrany obraz Windows",22,null,true),52);
        Add(StudioTheme.Label("Program sprawdzi archiwum i rozpakowane pliki. Utworzy katalog\nWindowsImageBackup na wybranym dysku NTFS, bez nadpisywania kopii.\nTen dysk z obrazem podłączysz podczas odzyskiwania w WinRE.",10,StudioTheme.Muted),80);
        Pick(bundle,"Folder z pobranym WindowsImageBackup.zip i system-image.json");
        Pick(destination,"Dysk zewnętrzny / roboczy — wybierz jego główny katalog");bundle.Text=source??"";
        var actions=new FlowLayoutPanel();prepare=StudioTheme.AsyncButton("Przygotuj i sprawdź obraz",PrepareAsync,true);prepare.Name="PrepareWindowsRecovery";prepare.Width=260;cancel=StudioTheme.Button("Zatrzymaj",()=>active?.Cancel());cancel.Visible=false;actions.Controls.Add(prepare);actions.Controls.Add(cancel);Add(actions,50);
        status.AutoSize=false;Add(status,115);
        FormClosing+=(_,e)=>{if(active is not null){e.Cancel=true;active.Cancel();ShowFeedback("Kończenie zapisu. Poczekaj na potwierdzenie.");}};
    }
    private async Task PrepareAsync()
    {
        using var cts=new CancellationTokenSource();active=cts;prepare.Enabled=bundle.Enabled=destination.Enabled=false;cancel.Visible=true;
        string input=bundle.Text,output=destination.Text;
        try
        {
            var progress=new Progress<string>(ShowFeedback);
            var path=await Task.Run(()=>SystemImageRecovery.PrepareAsync(input,output,progress,cts.Token));
            ShowFeedback("Obraz przygotowany i sprawdzony: "+path+"\nUruchom komputer z nośnika odzyskiwania Windows. Wybierz Rozwiąż problemy → Opcje zaawansowane → Odzyskiwanie obrazu systemu. Ten krok nie przywrócił jeszcze Windows.");
        }
        catch(OperationCanceledException){ShowFeedback("Zatrzymano. Istniejące kopie zachowano; nie potwierdzono gotowości nowego obrazu.");}
        catch(Exception e){ShowFeedback(e is ArgumentException or RecoveryTargetExistsException?e.Message:JobEngine.SafeError(e));}
        finally{active=null;prepare.Enabled=bundle.Enabled=destination.Enabled=true;cancel.Visible=false;}
    }
    public void ShowFeedback(string text){if(!IsDisposed)status.Text=text;}
}
