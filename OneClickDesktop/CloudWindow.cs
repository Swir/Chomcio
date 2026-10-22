using ChomcioRecovery.Chomikuj;
using ChomcioRecovery.Core;
using System.Security.Cryptography;
using System.Text.Json;

namespace ChomcioRecovery.Desktop;

internal sealed class CloudWindow : Form
{
    private readonly ChomikujClient client = new();
    private readonly string repositoryPath;
    private readonly string sourcePath;
    private readonly TextBox username = new();
    private readonly TextBox accountPassword = new() { UseSystemPasswordChar = true };
    private readonly TextBox vaultPassword = new() { UseSystemPasswordChar = true };
    private readonly ComboBox folders = new() { DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly ListBox snapshots = new();
    private readonly RichTextBox log = new() { ReadOnly = true };
    private readonly Label status = new() { AutoSize = true };
    private readonly Button cancel = new() { Text = "ANULUJ", Enabled = false };
    private readonly List<Control> inputs = new();
    private CancellationTokenSource? active;
    private bool closeWhenDone;
    private string? pendingSnapshot;
    private bool connected;
    private string? lastFailure;
    private JobSecrets? savedSecrets;
    internal void UseSavedCredentials(StudioStore store,BackupProfile? profile)
    {
        try
        {
            savedSecrets=profile?.ProtectedSecrets is not null?WindowsSecrets.Unprotect(profile.ProtectedSecrets):StudioCredentials.Account(store);
            if(savedSecrets is null)return;
            username.Text=savedSecrets.CloudLogin;accountPassword.Text=savedSecrets.CloudPassword;vaultPassword.Text=savedSecrets.VaultPassword;
            Shown+=async(_,_)=>{try{await LoginAsync();if(profile?.RemoteFolderId is not null)folders.SelectedItem=folders.Items.Cast<ChomikujFolder>().SingleOrDefault(f=>f.Id==profile.RemoteFolderId);}catch(Exception e){Write(JobEngine.SafeError(e));}};
        }
        catch(System.Security.Cryptography.CryptographicException){Write("Wpisz dane konta ponownie — Windows nie odblokował zapisu.");}
    }

    public CloudWindow(string repository, string source)
    {
        repositoryPath = repository;
        sourcePath = source;
        Text = "ChomcioRecovery by Swir — Chomikuj — WORK12";
        StudioTheme.Form(this);
        ClientSize = new(960, 780);
        MinimumSize = new(780, 620);
        BackColor = StudioTheme.Background;
        ForeColor = Color.FromArgb(230, 240, 255);
        Font = new("Segoe UI", 10);
        StartPosition = FormStartPosition.CenterParent;
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Padding = new(18) };
        layout.RowStyles.Add(new(SizeType.Absolute, 52));
        layout.RowStyles.Add(new(SizeType.Absolute, 330));
        layout.RowStyles.Add(new(SizeType.Percent, 100));
        layout.RowStyles.Add(new(SizeType.Absolute, 40));
        Controls.Add(layout);
        layout.Controls.Add(new Label { Text = "CHOMIKUJ  /  BY SWIR  /  WORK12 TEST", Font = new("Segoe UI", 17, FontStyle.Bold), AutoSize = true }, 0, 0);
        var fields = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 6, AutoScroll = true };
        fields.ColumnStyles.Add(new(SizeType.Absolute, 190));
        fields.ColumnStyles.Add(new(SizeType.Percent, 100));
        layout.Controls.Add(fields, 0, 1);
        AddField(fields, 0, "Login Chomikuj", username);
        AddField(fields, 1, "Hasło Chomikuj", accountPassword);
        AddField(fields, 2, "Folder w chmurze", folders);
        AddField(fields, 3, "Hasło szyfrowania kopii", vaultPassword);
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true };
        fields.Controls.Add(buttons, 0, 4);
        fields.SetColumnSpan(buttons, 2);
        AddButton(buttons, "POŁĄCZ KONTO", LoginAsync);
        AddButton(buttons, "ODŚWIEŻ FOLDERY", RefreshFoldersAsync);
        AddButton(buttons, "NOWY FOLDER KOPII", CreateFolderAsync);
        AddButton(buttons, "TEST KONTA — MAŁA KOPIA", RoundTripTestAsync);
        AddButton(buttons, "WYKONAJ KOPIĘ DO CHMURY", BackupToCloudAsync);
        AddButton(buttons, "WZNÓW OSTATNIE WYSYŁANIE", ResumeAsync);
        AddButton(buttons, "ODŚWIEŻ KOPIE", RefreshAsync);
        AddButton(buttons, "PRZYWRÓĆ Z CHOMIKUJ", RestoreAsync);
        var notes = new Label { AutoSize = true, Text = "Logowanie pozostaje w pamięci tej sesji. Hasło szyfrowania jest osobne.\n" +
            "Przerwanie zachowuje wcześniejsze kopie i przesłane fragmenty. Program nie akceptuje opłat za transfer.", ForeColor = Color.Silver };
        fields.Controls.Add(notes, 0, 5);
        fields.SetColumnSpan(notes, 2);
        var body = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1 };
        body.ColumnStyles.Add(new(SizeType.Percent, 40));
        body.ColumnStyles.Add(new(SizeType.Percent, 60));
        snapshots.Dock = log.Dock = DockStyle.Fill;
        snapshots.BackColor = log.BackColor = Color.FromArgb(18, 32, 53);
        snapshots.ForeColor = log.ForeColor = ForeColor;
        snapshots.HorizontalScrollbar = true;
        body.Controls.Add(snapshots, 0, 0);
        body.Controls.Add(log, 1, 0);
        layout.Controls.Add(body, 0, 2);
        var footer = new FlowLayoutPanel { Dock = DockStyle.Fill };
        cancel.AutoSize = true;
        cancel.Click += (_, _) => active?.Cancel();
        footer.Controls.Add(cancel);
        footer.Controls.Add(status);
        layout.Controls.Add(footer, 0, 3);
        inputs.Add(snapshots);
        folders.SelectedIndexChanged += (_, _) => snapshots.Items.Clear();
        FormClosing += (_, e) =>
        {
            if (active is null) return;
            e.Cancel = true;
            closeWhenDone = true;
            active.Cancel();
            status.Text = "Kończenie operacji przed zamknięciem…";
        };
        FormClosed += (_, _) => client.Dispose();
        Write("Najpierw połącz konto testowe. Mały test sprawdza prawdziwe wysłanie i odtworzenie danych.");
    }

    private void AddField(TableLayoutPanel panel, int row, string name, Control control)
    {
        panel.RowStyles.Add(new(SizeType.Absolute, 38));
        panel.Controls.Add(new Label { Text = name, AutoSize = true, Anchor = AnchorStyles.Left }, 0, row);
        control.Dock = DockStyle.Fill;
        control.BackColor = Color.FromArgb(18, 32, 53);
        control.ForeColor = Color.FromArgb(230, 240, 255);
        panel.Controls.Add(control, 1, row);
        inputs.Add(control);
    }

    private void AddButton(FlowLayoutPanel panel, string title, Func<Task> action)
    {
        var button = new Button { Text = title, AutoSize = true, FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(28, 69, 105), ForeColor = Color.White, Margin = new(3, 3, 6, 6) };
        button.Click += async (_, _) =>
        {
            try { await action(); }
            catch (Exception ex) { Write("Nie rozpoczęto: " + SafeMessage(ex)); }
        };
        panel.Controls.Add(button);
        inputs.Add(button);
    }

    private async Task LoginAsync()
    {
        string login = username.Text.Trim(), password = accountPassword.Text;
        // The password field is cleared after login. A repeat click with an
        // empty field must not erase the working session or selected folder.
        if (connected && string.IsNullOrEmpty(password))
        {
            Write("Konto jest połączone. Użyj ODŚWIEŻ FOLDERY albo TEST KONTA — MAŁA KOPIA.");
            return;
        }
        if (string.IsNullOrWhiteSpace(login) || string.IsNullOrEmpty(password))
            throw new ArgumentException("Podaj login i hasło konta Chomikuj.");
        accountPassword.Clear();
        connected = false;
        folders.Items.Clear(); snapshots.Items.Clear();
        IReadOnlyList<ChomikujFolder>? found = null;
        bool ok = await RunAsync("Łączenie konta", async ct =>
        {
            await client.LoginAsync(login, password, ct);
            found = await client.ListFoldersAsync(ct);
        });
        WriteDiagnostic("connection-result.json", new { success = ok, detail = lastFailure, timeUtc = DateTimeOffset.UtcNow });
        if (!ok || closeWhenDone) return;
        connected = true;
        ShowFolders(found!);
        Write($"Połączono konto. Dostępne foldery: {folders.Items.Count}. Mały test sam tworzy własny folder.");
    }

    private async Task RefreshFoldersAsync()
    {
        RequireConnected();
        IReadOnlyList<ChomikujFolder>? found = null;
        if (await RunAsync("Odświeżanie folderów", async ct => found = await client.ListFoldersAsync(ct)))
        {
            ShowFolders(found!);
            Write($"Odświeżono foldery: {folders.Items.Count}.");
        }
    }

    private void ShowFolders(IReadOnlyList<ChomikujFolder> found)
    {
        string? selected = (folders.SelectedItem as ChomikujFolder)?.Id;
        folders.Items.Clear();
        foreach (var folder in found) folders.Items.Add(folder);
        var keep = found.FirstOrDefault(f => f.Id == selected);
        if (keep is not null) folders.SelectedItem = keep;
        else if (folders.Items.Count > 0) folders.SelectedIndex = 0;
        snapshots.Items.Clear();
    }

    private void SelectCreatedFolder(ChomikujFolder folder)
    {
        var existing = folders.Items.Cast<ChomikujFolder>().FirstOrDefault(f => f.Id == folder.Id);
        if (existing is null) folders.Items.Add(folder);
        folders.SelectedItem = existing ?? folder;
    }

    private async Task CreateFolderAsync()
    {
        RequireConnected();
        ChomikujFolder? created = null;
        if (await RunAsync("Tworzenie nowego folderu", async ct =>
            created = await client.CreateFolderAsync("ChomcioRecovery_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + "_" + Guid.NewGuid().ToString("N")[..8], ct)))
        {
            SelectCreatedFolder(created!);
        }
    }

    private async Task BackupToCloudAsync()
    {
        if (string.IsNullOrWhiteSpace(sourcePath) || !Directory.Exists(sourcePath))
            throw new InvalidOperationException("Najpierw wybierz istniejący folder źródłowy w głównym oknie. Mały test nie wymaga wyboru plików.");
        var transfer = Transfer();
        string password = TakeVaultPassword();
        string work = NewWorkRoot();
        var progress = Progress();
        await RunAsync("Kopia do Chomikuj", async ct =>
        {
            if (!Directory.Exists(repositoryPath)) LocalEncryptedVault.Initialize(repositoryPath, password);
            using (var vault = LocalEncryptedVault.Open(repositoryPath, password))
                pendingSnapshot = vault.BackupDirectory(sourcePath, ct).SnapshotId;
            await transfer.UploadSnapshotAsync(repositoryPath, password, pendingSnapshot,
                Path.Combine(work, "encrypted-upload"), progress, ct);
        });
    }

    private async Task ResumeAsync()
    {
        var transfer = Transfer();
        if (pendingSnapshot is null) throw new InvalidOperationException("W tej sesji nie ma przerwanego wysyłania.");
        string password = TakeVaultPassword(), snapshot = pendingSnapshot, work = NewWorkRoot();
        var progress = Progress();
        await RunAsync("Kontynuacja wysyłania", ct => transfer.UploadSnapshotAsync(repositoryPath, password,
            snapshot, Path.Combine(work, "encrypted-upload"), progress, ct));
    }

    private async Task RefreshAsync()
    {
        var transfer = Transfer();
        IReadOnlyList<string>? found = null;
        if (await RunAsync("Punkty kopii w Chomikuj", async ct => found = await transfer.ListSnapshotsAsync(ct)))
        {
            snapshots.Items.Clear();
            foreach (string id in found!) snapshots.Items.Add(id);
            Write("Lista zawiera identyfikatory punktów; integralność jest sprawdzana podczas pobierania.");
        }
    }

    private async Task RestoreAsync()
    {
        var transfer = Transfer();
        string id = snapshots.SelectedItem as string ?? throw new InvalidOperationException("Wybierz kopię z listy.");
        using var picker = new FolderBrowserDialog { Description = "Wybierz katalog nadrzędny. Dane trafią do nowego podfolderu." };
        if (picker.ShowDialog(this) != DialogResult.OK) return;
        string password = TakeVaultPassword(), work = NewWorkRoot();
        string target = Path.Combine(picker.SelectedPath, "ChomcioRestore_" + Guid.NewGuid().ToString("N"));
        var progress = Progress();
        bool ok = await RunAsync("Przywracanie z Chomikuj", async ct =>
        {
            string downloaded = Path.Combine(work, "encrypted-download");
            await transfer.DownloadSnapshotAsync(id, password, downloaded, progress, ct);
            using var vault = LocalEncryptedVault.Open(downloaded, password);
            vault.RestoreSnapshot(id, target, ct);
        });
        if (ok) Write("Sprawdzone dane odtworzono: " + target);
    }

    private async Task RoundTripTestAsync()
    {
        RequireConnected();
        string work = NewWorkRoot();
        var progress = Progress();
        ChomikujFolder? testFolder = null;
        string stage = "Przygotowanie danych testowych";
        IProgress<string> steps = new Progress<string>(Write);
        void Step(string value) { stage = value; steps.Report(value); }
        bool ok = await RunAsync("Test konta: wysłanie, pobranie i odtworzenie", async ct =>
        {
            Step("1/5: Przygotowanie sztucznej, zaszyfrowanej kopii");
            string src = Path.Combine(work, "source");
            Directory.CreateDirectory(Path.Combine(src, "pusty-folder"));
            byte[] expected = RandomNumberGenerator.GetBytes(65_537);
            File.WriteAllBytes(Path.Combine(src, "test.bin"), expected);
            string password = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            string repo = Path.Combine(work, "vault");
            LocalEncryptedVault.Initialize(repo, password);
            string id;
            using (var vault = LocalEncryptedVault.Open(repo, password)) id = vault.BackupDirectory(src, ct).SnapshotId;
            Step("2/5: Tworzenie osobnego folderu testowego w Chomikuj");
            testFolder = await client.CreateFolderAsync("ChomcioRecovery_Test_" + Guid.NewGuid().ToString("N"), ct);
            var transfer = new CloudVaultTransfer(client.OpenFolder(testFolder));
            Step("3/5: Lista folderu, wysyłanie i odczyt kontrolny zaszyfrowanych plików");
            await transfer.UploadSnapshotAsync(repo, password, id, Path.Combine(work, "export"), progress, ct);
            Step("4/5: Pobieranie kopii do niezależnego repozytorium");
            string downloaded = Path.Combine(work, "download");
            await transfer.DownloadSnapshotAsync(id, password, downloaded, progress, ct);
            string restored = Path.Combine(work, "restored");
            Step("5/5: Odtworzenie i porównanie plików bajt po bajcie");
            using (var vault = LocalEncryptedVault.Open(downloaded, password)) vault.RestoreSnapshot(id, restored, ct);
            if (!File.ReadAllBytes(Path.Combine(restored, "test.bin")).AsSpan().SequenceEqual(expected) ||
                !Directory.Exists(Path.Combine(restored, "pusty-folder"))) throw new InvalidDataException("Odtworzone dane nie zgadzają się.");
            File.WriteAllText(Path.Combine(work, "CHOMIKUJ_TEST_PASS.json"), JsonSerializer.Serialize(new
            {
                success = true, version = "1.0.0", testedAtUtc = DateTimeOffset.UtcNow, snapshot = id, folder = testFolder.Name,
                bytes = expected.Length, sha256 = Convert.ToHexString(SHA256.HashData(expected)),
                tested = "live HTTPS upload, readback, independent download and byte-exact restore"
            }, new JsonSerializerOptions { WriteIndented = true }));
        });
        Write("Pliki i wynik testu: " + work);
        File.WriteAllText(Path.Combine(work, "test-result.json"), JsonSerializer.Serialize(new
        { success = ok, version = "1.0.0", stage, detail = lastFailure, remoteFolder = testFolder?.Name, timeUtc = DateTimeOffset.UtcNow }));
        if (testFolder is not null)
        {
            SelectCreatedFolder(testFolder);
            Write("Folder testowy w Chomikuj: " + testFolder.Name);
        }
        if (ok) Write("TEST CHOMIKUJ PASS — prawdziwa kopia z chmury została odtworzona i porównana.");
    }

    private CloudVaultTransfer Transfer()
    {
        RequireConnected();
        return new(client.OpenFolder(folders.SelectedItem as ChomikujFolder ?? throw new InvalidOperationException("Wybierz folder kopii.")));
    }
    private void RequireConnected() { if (!connected) throw new InvalidOperationException("Najpierw połącz konto."); }
    private string TakeVaultPassword()
    {
        string password = vaultPassword.Text.Length>0?vaultPassword.Text:savedSecrets?.VaultPassword??"";
        vaultPassword.Clear();
        if (string.IsNullOrEmpty(password)) throw new ArgumentException("Podaj osobne hasło szyfrowania kopii.");
        return password;
    }
    private static string NewWorkRoot()
    {
        string parent = Environment.GetEnvironmentVariable("CHOMCIO_WORK_ROOT") ??
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ChomcioRecovery", "CloudWork");
        string path = Path.Combine(parent, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
    private IProgress<CloudProgress> Progress() => new Progress<CloudProgress>(p =>
        status.Text = $"{p.Phase}: {p.Completed}/{p.Total} ({p.Bytes:N0} B)");
    private async Task<bool> RunAsync(string title, Func<CancellationToken, Task> operation)
    {
        if (active is not null) throw new InvalidOperationException("Poczekaj na zakończenie poprzedniej operacji.");
        using var stop = new CancellationTokenSource();
        active = stop;
        client.Diagnostics = new Progress<string>(Write);
        lastFailure = null;
        foreach (Control c in inputs) c.Enabled = false;
        cancel.Enabled = true;
        status.Text = title;
        Write("Start: " + title);
        try
        {
            await Task.Run(() => operation(stop.Token));
            Write("OK: " + title);
            return true;
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested)
        { lastFailure = "Anulowano"; Write("ANULOWANO. Wcześniejsze kopie i już wysłane zaszyfrowane fragmenty pozostają."); return false; }
        catch (Exception ex) { lastFailure = SafeMessage(ex); Write("BŁĄD: " + lastFailure); return false; }
        finally
        {
            active = null;
            cancel.Enabled = false;
            foreach (Control c in inputs) c.Enabled = true;
            status.Text = "Gotowe";
            if (closeWhenDone) BeginInvoke(new Action(Close));
        }
    }
    private static string SafeMessage(Exception error) => error is HttpRequestException ?
        "Błąd połączenia HTTPS. Operacja nie została potwierdzona." : error.Message;
    private static void WriteDiagnostic(string name, object report)
    {
        // Optional local test output only, never stores username/password/token.
        string? parent = Environment.GetEnvironmentVariable("CHOMCIO_WORK_ROOT");
        if (string.IsNullOrEmpty(parent)) return;
        Directory.CreateDirectory(parent);
        File.WriteAllText(Path.Combine(parent, name), JsonSerializer.Serialize(report));
    }
    private void Write(string message) { log.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}"); log.ScrollToCaret(); }
}
