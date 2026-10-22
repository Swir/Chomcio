using System.Security.Cryptography;
using System.Text;
using ChomcioRecovery.Core;

namespace ChomcioRecovery.Desktop;

internal static class VaultKeys
{
    internal static string Generate()
    {
        byte[] bytes=RandomNumberGenerator.GetBytes(32);
        try{return Convert.ToHexString(bytes);}
        finally{CryptographicOperations.ZeroMemory(bytes);}
    }
    internal static bool CanInitialize(BackupProfile profile)
    {
        if(profile.LastSuccess is not null||profile.LastSnapshot is not null||
            profile.PendingSnapshot is not null||profile.RemoteFolderId is not null)return false;
        try{File.GetAttributes(profile.Repository);return false;}
        catch(FileNotFoundException){return true;}
        catch(DirectoryNotFoundException){return true;}
        // Access denied, invalid paths and other failures are not proof that
        // a vault does not exist. Do not replace a key in those cases.
    }

    // Repair only a never-created vault. Never replace the key of an existing
    // local/remote vault or an interrupted upload.
    internal static JobSecrets Prepare(StudioStore store,BackupProfile profile,JobSecrets secrets)
    {
        if(secrets.VaultPassword.Length>=12||!CanInitialize(profile))return secrets;
        var replacement=secrets with{VaultPassword=Generate()};
        string? previous=profile.ProtectedSecrets;
        profile.ProtectedSecrets=WindowsSecrets.Protect(replacement);
        try{store.Save();}
        catch{profile.ProtectedSecrets=previous;throw;}
        return replacement;
    }
    internal static string RecoveryText(BackupProfile profile,JobSecrets secrets)=>
        "CHOMCIORECOVERY by Swir — KLUCZ ODZYSKIWANIA\r\n\r\n"+
        "Kopia: "+profile.Name+"\r\n"+
        "Identyfikator: "+profile.Id+"\r\n"+
        (profile.Destination==BackupDestination.Chomikuj?"Folder Chomikuj: "+(profile.RemoteFolderName??"ChomcioRecovery_"+profile.Id):"Repozytorium lokalne: "+profile.Repository)+"\r\n\r\n"+
        secrets.VaultPassword+"\r\n\r\n"+
        (secrets.FolderPassword is null?"":"Osobne hasło folderu w serwisie Chomikuj:\r\n"+secrets.FolderPassword+"\r\n\r\n")+
        "Ten klucz odblokowuje zaszyfrowaną kopię. Nie jest hasłem konta Chomikuj.\r\n"+
        "Zachowaj go poza tym komputerem, np. na własnym pendrivie lub w menedżerze haseł.\r\n"+
        "Nie udostępniaj go innym osobom. Program nie odzyska go po utracie tego Windowsa.\r\n";
}

internal sealed class RecoveryKeyWindow : Form, IInlineFeedback
{
    private readonly Label status=StudioTheme.Label("",10,StudioTheme.Muted);
    internal RecoveryKeyWindow(BackupProfile profile,JobSecrets secrets)
    {
        StudioTheme.Form(this);Text="Klucz odzyskiwania • ChomcioRecovery";
        ClientSize=new(630,390);MinimumSize=new(620,420);StartPosition=FormStartPosition.CenterParent;
        var body=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,Padding=new(28)};Controls.Add(body);
        void Add(Control control,int height){int row=body.RowCount++;body.RowStyles.Add(new(SizeType.Absolute,height));control.Dock=DockStyle.Fill;body.Controls.Add(control,0,row);}
        Add(StudioTheme.Label("Zachowaj dostęp do swojej kopii",21,null,true),48);
        Add(StudioTheme.Label("Klucz jest zapamiętany na tym PC. Zapisz go także poza komputerem,\naby odtworzyć dane po awarii lub ponownej instalacji Windows.",10,StudioTheme.Muted),60);
        var key=StudioTheme.Input(true);key.ReadOnly=true;key.Text=secrets.VaultPassword;Add(key,40);
        var show=new CheckBox{Text="Pokaż klucz odzyskiwania",AutoSize=true};show.CheckedChanged+=(_,_)=>key.UseSystemPasswordChar=!show.Checked;Add(show,38);
        var save=StudioTheme.Button("Zapisz klucz do pliku…",()=>
        {
            try
            {
                using var picker=new SaveFileDialog{Title="Zapisz klucz poza komputerem",Filter="Klucz odzyskiwania (*.txt)|*.txt",FileName="ChomcioRecovery_Klucz_"+profile.Id[..8]+".txt",OverwritePrompt=true};
                if(picker.ShowDialog(this)!=DialogResult.OK)return;
                // Do not overwrite another file even after a dialog race.
                using var stream=new FileStream(picker.FileName,FileMode.CreateNew,FileAccess.Write,FileShare.None);
                byte[] text=Encoding.UTF8.GetBytes(VaultKeys.RecoveryText(profile,secrets));
                try{stream.Write(text);stream.Flush(true);}
                finally{CryptographicOperations.ZeroMemory(text);}
                ShowFeedback("Klucz zapisany. Przechowuj ten plik w bezpiecznym miejscu.");
            }
            catch(IOException){ShowFeedback("Nie zapisano klucza. Wybierz nową nazwę pliku i dostępny folder.");}
            catch(UnauthorizedAccessException){ShowFeedback("Brak dostępu do wybranego miejsca. Wybierz inny folder.");}
        },true);Add(save,48);status.AutoSize=false;Add(status,60);
    }
    public void ShowFeedback(string text)=>status.Text=text;
}
