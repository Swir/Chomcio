using ChomcioRecovery.Desktop;
using ChomcioRecovery.Core;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

internal static class SystemImageWizardScenarios
{
    private static T Field<T>(Form form,string name) where T:Control =>
        (T)form.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(form)!;
    private static void Show(Form form){form.Opacity=0;form.ShowInTaskbar=false;form.Show();}
    private static void Capture(Form form,string path)
    {using var bitmap=new Bitmap(form.Width,form.Height);form.DrawToBitmap(bitmap,new(0,0,bitmap.Width,bitmap.Height));bitmap.Save(path);}
    private sealed class Plans(params SystemImagePlanChoice[] choices):ISystemImagePlanCatalog
    {
        internal bool Reject;internal int Validations;
        public IReadOnlyList<SystemImagePlanChoice> List()=>choices;
        public void Validate(BackupProfile profile)
        {
            Validations++;
            if(Reject||!choices.Any(c=>c.Id==profile.SystemImagePlanId&&c.CacheRoot==profile.SystemImageCacheRoot))
                throw new IOException("Synthetic enrollment revoked.");
            SystemImageStorage.ValidateShape(profile);
        }
    }
    internal static async Task Run(string root,Action<bool,string> check)
    {
        string area=Path.Combine(root,"windows-wizard");Directory.CreateDirectory(area);
        var store=new StudioStore(Path.Combine(area,"settings"));
        var account=new JobSecrets("","synthetic-test-account","synthetic-test-password");
        using(var wizard=new ProfileEditor(store.Root,account:account,newContent:BackupContent.WindowsSystem,imagePlans:new Plans()))
        {
            Show(wizard);wizard.Advance();
            check(wizard.Step==0&&wizard.ResultProfile is null&&wizard.ValidationMessage.Contains("moduł"),
                "missing image module stays inline on first step; no file fallback");
            check(!Work9Scenarios.All(wizard).Contains(Field<TextBox>(wizard,"source")),"image wizard never offers C as a folder backup");
            Capture(wizard,Path.Combine(area,"module-needed.png"));
        }
        check(!Directory.Exists(Path.Combine(store.Root,"vaults")),"module gate does not create an AppData image vault");
        var plan=new SystemImagePlanChoice(Guid.NewGuid().ToString("N"),Path.Combine(area,"approved-cache"));
        var plans=new Plans(plan);
        BackupProfile profile;JobSecrets secrets;
        using(var wizard=new ProfileEditor(store.Root,account:account,newDestination:BackupDestination.Chomikuj,
            newContent:BackupContent.WindowsSystem,imagePlans:plans))
        {
            Show(wizard);Capture(wizard,Path.Combine(area,"windows-step1.png"));
            Field<TextBox>(wizard,"source").Text=@"C:\";
            Field<TextBox>(wizard,"repository").Text=Path.Combine(store.Root,"unapproved-image-repository");
            wizard.Advance();check(wizard.Step==1,"approved image plan advances without a source folder");
            Capture(wizard,Path.Combine(area,"windows-step2.png"));wizard.Advance();
            Field<CheckBox>(wizard,"daily").Checked=true;Field<CheckBox>(wizard,"atLogon").Checked=true;
            Field<DateTimePicker>(wizard,"time").Value=DateTime.Today.AddHours(21).AddMinutes(15);
            Capture(wizard,Path.Combine(area,"windows-step3.png"));wizard.Advance();
            profile=wizard.ResultProfile??throw new Exception(wizard.ValidationMessage);secrets=wizard.ResultSecrets!;
            check(wizard.StartAfterSave&&profile.Content==BackupContent.WindowsSystem&&profile.Source=="","image wizard returns a real image job, never a file scan");
            check(profile.SystemImagePlanId==plan.Id&&profile.SystemImageCacheRoot==plan.CacheRoot&&
                profile.Repository==SystemImageStorage.Repository(plan.CacheRoot,profile.Id),"image paths come only from the selected approved plan");
            check(plans.Validations==2,"enrollment revalidated at first step and immediately before saving");
            check(profile.Destination==BackupDestination.Chomikuj&&profile.CloudDateFolders&&profile.ProtectCloudFolder,
                "Windows profile defaults to encrypted dated password-protected Chomikuj folders");
            check(profile.Daily&&profile.AtLogon&&profile.DailyMinute==1275,"Windows daily and logon choices preserved");
            check(WindowsSecrets.Unprotect(profile.ProtectedSecrets!)==secrets&&secrets.VaultPassword.Length>=12&&
                secrets.VaultPassword!=secrets.FolderPassword,"generated key and distinct folder password remembered with DPAPI");
        }
        var pending=new PendingSystemImage(plan.Id,Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow);
        profile.PendingSystemImage=pending;
        using(var wizard=new ProfileEditor(store.Root,profile,imagePlans:new Plans()))
        {
            Show(wizard);check(!Field<ComboBox>(wizard,"imagePlan").Enabled,"existing image plan cannot be switched");
            Field<TextBox>(wizard,"source").Text=@"C:\Users";wizard.Advance();wizard.Advance();
            Field<CheckBox>(wizard,"daily").Checked=false;wizard.Advance();var edited=wizard.ResultProfile!;
            check(edited is not null&&edited.PendingSystemImage==pending&&edited.Repository==profile.Repository&&
                edited.SystemImageCacheRoot==profile.SystemImageCacheRoot&&edited.Source==""&&
                wizard.ResultSecrets==secrets&&!wizard.StartAfterSave&&!edited.Daily,
                "editing schedule keeps pending capture, cache, plan and exact old keys without starting a job");
        }
        profile.PendingSystemImage=null;
        using(var wizard=new ProfileEditor(store.Root,account:account,newContent:BackupContent.WindowsSystem,imagePlans:plans))
        {
            Show(wizard);wizard.Advance();wizard.Advance();plans.Reject=true;wizard.Advance();
            check(wizard.Step==2&&wizard.ResultProfile is null&&wizard.ValidationMessage.Length>0,"revoked enrollment is caught before save or start");
            plans.Reject=false;
        }
        var second=new SystemImagePlanChoice(Guid.NewGuid().ToString("N"),Path.Combine(area,"other-cache"));
        using(var wizard=new ProfileEditor(store.Root,account:account,newContent:BackupContent.WindowsSystem,imagePlans:new Plans(plan,second)))
        {
            Show(wizard);wizard.Advance();check(wizard.Step==0&&wizard.ResultProfile is null,"multiple plans require an explicit selection");
            Field<ComboBox>(wizard,"imagePlan").SelectedIndex=1;wizard.Advance();wizard.Advance();wizard.Advance();
            check(wizard.ResultProfile?.SystemImagePlanId==second.Id,"explicit plan selection survives all wizard pages");
        }
        bool refused=false;
        try{SystemImageProfiles.SelectNewPlan(new BackupProfile{PendingSystemImage=pending},plan);}catch(InvalidDataException){refused=true;}
        check(refused,"pending image cannot be repointed by new-plan helper");
        store.Data.Profiles.Add(profile);store.Save();
        using(var window=new StudioWindow(store,new JobEngine(store),true))
        {
            Show(window);window.ShowPage("Obraz Windows");Capture(window,Path.Combine(area,"windows-page.png"));
            check(Work9Scenarios.All(window).Any(c=>c.Name=="NewWindowsCloudBackup")&&
                Work9Scenarios.All(window).Any(c=>c.Text=="Pobierz obraz"),"Windows page exposes cloud backup and image download");
            check(!Work9Scenarios.All(window).Any(c=>c.Text.Contains("bez szyfrowania przez Chomcio")),"Windows page no longer points to old local-only capture");
        }
        // Synthetic archive only. No native capture, elevation, VM or network.
        string source=Path.Combine(area,"synthetic-image");Directory.CreateDirectory(source);
        string archive=Path.Combine(source,SystemImageLease.ArchiveName);
        using(var zip=ZipFile.Open(archive,ZipArchiveMode.Create))
            foreach(string name in new[]{"WindowsImageBackup/Test/Catalog/BackupGlobalCatalog","WindowsImageBackup/Test/Backup/volume.vhdx"})
            {using var writer=new StreamWriter(zip.CreateEntry(name).Open());writer.Write("SYNTHETIC ONLY");}
        var receipt=new SystemImageReceipt(1,plan.Id,pending.CaptureId,pending.RequestedUtc,DateTimeOffset.UtcNow,
            0,true,true,new FileInfo(archive).Length,Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(archive))));
        File.WriteAllText(Path.Combine(source,SystemImageLease.ReceiptName),JsonSerializer.Serialize(receipt));
        string snapshot;
        LocalEncryptedVault.Initialize(profile.Repository,secrets.VaultPassword);
        using(var vault=LocalEncryptedVault.Open(profile.Repository,secrets.VaultPassword))snapshot=vault.BackupDirectory(source).SnapshotId;
        using(var session=new RestoreSession(store,profile,secrets))
        {
            string target=Path.Combine(area,"downloaded-image");
            await session.RestoreAsync(snapshot,false,target,null,null,default);
            check(File.ReadAllBytes(Path.Combine(target,SystemImageLease.ArchiveName)).SequenceEqual(File.ReadAllBytes(archive)),
                "image download verifies complete archive and receipt before success");
            refused=false;try{await session.RestoreAsync(snapshot,false,Path.Combine(area,"incomplete-image"),SystemImageLease.ArchiveName,null,default);}
            catch(ArgumentException){refused=true;}
            check(refused&&!Directory.Exists(Path.Combine(area,"incomplete-image")),"single-file image export refused before writing");
        }
        using(var window=new RestoreWindow(store,profile,secrets))
        {
            check(window.Text.StartsWith("Pobierz obraz Windows")&&!Field<Button>(window,"loadFiles").Visible,
                "image download does not present itself as completed Windows recovery");
        }
        Console.WriteLine("CHOMCIO_WINDOWS_PROFILE_WIZARD=PASS (synthetic plans and bytes; no native capture or cloud)");
    }
}
