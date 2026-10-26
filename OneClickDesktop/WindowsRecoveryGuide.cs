using System.Diagnostics;
using System.Text;

namespace ChomcioRecovery.Desktop;

internal static class WindowsRecoveryGuide
{
    internal const string MicrosoftHelp = "https://support.microsoft.com/en-us/windows/experience/backup-recovery/recovery-drive";

    // Only the Windows tool, with its own drive selection and confirmation.
    // Never pass a disk, format command, script, or restart argument to it.
    internal static ProcessStartInfo MediaCommand()
    {
        string tool = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "RecoveryDrive.exe");
        StudioStore.RejectLinks(tool);
        if (!File.Exists(tool)) throw new FileNotFoundException("Windows nie udostępnia kreatora dysku odzyskiwania.");
        return new(tool) { UseShellExecute = true, Verb = "runas" };
    }

    internal static string Instructions(string? preparedImage = null) =>
        "CHOMCIORECOVERY BY SWIR — ODZYSKIWANIE WINDOWS\r\n\r\n" +
        "1. ZACHOWAJ DOSTĘP DO KOPII\r\n" +
        "Zapisz klucz szyfrowania Chomcio poza komputerem. Potrzebujesz także dostępu do konta Chomikuj. " +
        "Jeżeli używasz BitLocker, zachowaj jego klucz odzyskiwania osobno. Ten dokument nie zawiera haseł ani kluczy.\r\n\r\n" +
        "2. PRZYGOTUJ PENDRIVE RATUNKOWY\r\n" +
        "Na sprawnym komputerze otwórz w Chomcio kreator nośnika Windows. Użyj osobnego, pustego pendrive'a. " +
        "Windows usunie dane z wybranego pendrive'a. Nie wybieraj dysku z kopiami ani kluczami. " +
        "Przejdź przez wybór nośnika i potwierdzenie w kreatorze Windows. " +
        "Po utworzeniu sprawdź uruchomienie z USB na komputerze, który ma być chroniony, z włączonym Secure Boot. " +
        "Samo otwarcie kreatora nie potwierdza utworzenia ani sprawności nośnika.\r\n\r\n" +
        "3. POBIERZ I PRZYGOTUJ WYBRANĄ KOPIĘ\r\n" +
        "Na sprawnym PC zaloguj się w Chomcio do Chomikuj, wybierz sejf i datę kopii Windows. " +
        "Odblokuj kopię swoim kluczem i pobierz cały obraz. Następnie wybierz Przygotuj odzyskiwanie Windows. " +
        "Użyj osobnego dysku NTFS, który pomieści pobrane archiwum i rozpakowany obraz. " +
        "Poczekaj na kontrolę integralności. Na tym dysku powstanie katalog WindowsImageBackup.\r\n" +
        (string.IsNullOrWhiteSpace(preparedImage) ? "" : "Przygotowany katalog: " + preparedImage + "\r\n") +
        "Nie usuwaj wcześniejszych kopii. Dysk z obrazem musi pozostać osobnym nośnikiem podczas odzyskiwania.\r\n\r\n" +
        "4. PRZYWRÓĆ WINDOWS NA WYBRANYM KOMPUTERZE\r\n" +
        "Podłącz pendrive ratunkowy oraz dysk z WindowsImageBackup. Uruchom komputer z pendrive'a. " +
        "W środowisku odzyskiwania wybierz Rozwiąż problemy → Opcje zaawansowane → Odzyskiwanie obrazu systemu. " +
        "Wybierz właściwy komputer i datę obrazu. Przed zatwierdzeniem sprawdź dysk docelowy; odzyskiwanie zastąpi jego dane. " +
        "Odłącz zbędne dyski z ważnymi danymi. Opcja odzyskiwania obrazu ma korzystać z WindowsImageBackup; " +
        "przywracanie ustawień fabrycznych nie odtwarza kopii Chomcio. " +
        "Jeśli obrazu lub dysku nie widać, zatrzymaj się i sprawdź podłączenie oraz sterowniki kontrolera.\r\n\r\n" +
        "5. SPRAWDŹ WYNIK\r\n" +
        "Po zakończeniu uruchom odtworzony Windows i sprawdź swoje pliki, programy oraz ustawienia. " +
        "Zachowaj kopię i klucz do czasu potwierdzenia wyniku. Przygotowanie obrazu w Chomcio nie jest jeszcze odtworzeniem systemu.\r\n\r\n" +
        "Dokumentacja kreatora Microsoft: " + MicrosoftHelp + "\r\n";
}

internal sealed class WindowsRecoveryGuideWindow : Form, IInlineFeedback
{
    private readonly Label status = StudioTheme.Label("", 10, StudioTheme.Muted);
    private readonly CheckBox consent = new() { Name = "RecoveryMediaConsent", Text = "Użyję osobnego, pustego pendrive'a. Windows usunie z niego dane.", AutoSize = true };
    private readonly StudioButton media;
    private readonly string? preparedImage;
    private readonly Action launch;
    private bool launched;

    internal WindowsRecoveryGuideWindow(string? preparedImage = null, Action? launchForTest = null)
    {
        this.preparedImage = preparedImage;
        launch = launchForTest ?? (() => { using var process = Process.Start(WindowsRecoveryGuide.MediaCommand()); });
        StudioTheme.Form(this); Text = "Odzyskiwanie Windows krok po kroku • ChomcioRecovery";
        ClientSize = new(790, 730); MinimumSize = new(710, 690); StartPosition = FormStartPosition.CenterParent;
        var body = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new(24), AutoScroll = true };
        Controls.Add(body);
        void Add(Control control, int height)
        {
            int row = body.RowCount++; body.RowStyles.Add(new(SizeType.Absolute, height));
            control.Dock = DockStyle.Fill; body.Controls.Add(control, 0, row);
        }
        void Note(string title, string text, int height)
        { Add(StudioTheme.Label(title, 14, null, true), 35); Add(StudioTheme.Label(text, 10, StudioTheme.Muted), height); }
        Add(StudioTheme.Label("Przygotuj się do odzyskania Windows", 22, null, true), 53);
        Note("1. Zachowaj klucz poza komputerem", "Zapisz klucz szyfrowania Chomcio na innym nośniku. Dzięki niemu\nodblokujesz kopię z Chomikuj również na nowym komputerze.", 50);
        Note("2. Utwórz pendrive ratunkowy", "Kreator Windows pozwoli wybrać i przygotować USB. Pendrive musi być\nosobny od dysku z obrazem i kluczami. Sprawdź jego uruchomienie na swoim PC.", 55);
        consent.ForeColor = StudioTheme.Ink; Add(consent, 38);
        media = StudioTheme.Button("Otwórz kreator nośnika Windows", LaunchMedia, true);
        media.Name = "CreateWindowsRecoveryMedia"; media.Enabled = false; Add(media, 45);
        consent.CheckedChanged += (_, _) => media.Enabled = consent.Checked && !launched;
        Note("3. Pobierz i przygotuj kopię", "W Chomcio wybierz kopię Windows z Chomikuj i pobierz cały obraz.\nPrzygotuj go na osobnym dysku NTFS przyciskiem „Przygotuj odzyskiwanie”.", 55);
        Note("4. Uruchom komputer z USB", "Podłącz również dysk z obrazem. W WinRE wybierz Rozwiąż problemy →\nOpcje zaawansowane → Odzyskiwanie obrazu systemu. Sprawdź komputer,\ndatę i dysk docelowy: odtworzenie zastąpi dane tego dysku.", 70);
        var save = StudioTheme.Button("Zapisz instrukcję na później", SaveInstructions); save.Name = "SaveWindowsRecoveryInstructions"; Add(save, 44);
        status.AutoSize = false; Add(status, 85);
        if (preparedImage is not null) ShowFeedback("Obraz został przygotowany: " + preparedImage + "\nUruchomienie odtworzonego Windows pozostaje do sprawdzenia.");
    }

    private void LaunchMedia()
    {
        if (!consent.Checked || launched) return;
        try
        {
            launch(); launched = true; media.Enabled = false;
            ShowFeedback("Otwarto kreator Windows. Wybierz pusty pendrive i zakończ przygotowanie w jego oknie. Chomcio nie potwierdził jeszcze utworzenia ani uruchomienia nośnika.");
        }
        catch (System.ComponentModel.Win32Exception e) when (e.NativeErrorCode == 1223)
        { ShowFeedback("Nie udzielono zgody administratora. Możesz spróbować ponownie."); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        { ShowFeedback("Nie otwarto kreatora. Uruchom „Dysk odzyskiwania” z menu Start lub użyj nośnika odzyskiwania Microsoft odpowiedniego dla swojego komputera."); }
    }
    private void SaveInstructions()
    {
        using var dialog = new SaveFileDialog { FileName = "Chomcio-odzyskiwanie-Windows.txt", Filter = "Instrukcja tekstowa|*.txt", OverwritePrompt = true };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            StudioStore.RejectLinks(dialog.FileName);
            File.WriteAllText(dialog.FileName, WindowsRecoveryGuide.Instructions(preparedImage), new UTF8Encoding(true));
            ShowFeedback("Zapisano instrukcję. Dokument nie zawiera haseł ani kluczy.");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        { ShowFeedback("Nie zapisano instrukcji. Wybierz dostępne miejsce na innym nośniku."); }
    }
    public void ShowFeedback(string text) { if (!IsDisposed) status.Text = text; }
}
