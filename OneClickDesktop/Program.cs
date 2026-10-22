using System.Drawing;
using System.IO;
using System.Windows.Forms;
using ChomcioRecovery.Core;

namespace ChomcioRecovery.Desktop;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        if (args.Length == 2 && args[0] == "--image-backup")
            Application.Run(new SystemImageWindow(SystemImagePlan.Drive(args[1])));
        else if (args.Contains("--chomikuj", StringComparer.Ordinal))
            Application.Run(new CloudWindow(Path.Combine(Environment.GetFolderPath(
                Environment.SpecialFolder.MyDocuments), "ChomcioVault"), ""));
        else if (args.Contains("--local-tools", StringComparer.Ordinal))
            Application.Run(new RecoveryWindow());
        else
        {
            try { StudioApplication.Run(args.Contains("--autostart", StringComparer.Ordinal)); }
            catch(Exception error) { MessageBox.Show(error.Message,"Nie można uruchomić ChomcioRecovery",MessageBoxButtons.OK,MessageBoxIcon.Error); }
        }
    }
}

internal sealed class RecoveryWindow : Form
{
    internal void SetProfile(string repo, string from) { repository.Text=repo;source.Text=from; }
    private static readonly Color Background = StudioTheme.Background;
    private static readonly Color Surface = StudioTheme.Surface;
    private static readonly Color Ink = Color.FromArgb(230, 240, 255);
    private static readonly Color Dim = Color.FromArgb(145, 165, 195);
    private static readonly Color Cyan = Color.FromArgb(35, 178, 240);
    private static readonly Font TextFont = new("Segoe UI", 10f);

    private readonly TextBox repository = new();
    private readonly TextBox source = new();
    private readonly TextBox secret = new();
    private readonly ListBox recoveryPoints = new();
    private readonly RichTextBox eventLog = new();
    private readonly Label state = new();
    private readonly List<Button> actions = new();
    private readonly Button cancelOperation = new();
    private CancellationTokenSource? activeOperation;
    private bool activeOperationCanCancel;
    private bool closeAfterOperation;

    public RecoveryWindow()
    {
        Text = "Kopie lokalne • ChomcioRecovery by Swir";
        StudioTheme.Form(this);
        BackColor = Background;
        ForeColor = Ink;
        Font = TextFont;
        MinimumSize = new Size(850, 630);
        ClientSize = new Size(1060, 740);
        StartPosition = FormStartPosition.CenterScreen;

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            BackColor = Background,
            Padding = new Padding(20),
        };
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
        Controls.Add(layout);

        var header = new Panel { Dock = DockStyle.Fill, BackColor = Background };
        layout.Controls.Add(header, 0, 0);
        var title = new Label
        {
            Text = "CHOMCIO  RECOVERY",
            Font = new Font("Segoe UI Semibold", 23f, FontStyle.Bold),
            ForeColor = Color.White,
            Location = new Point(5, 0),
            AutoSize = true,
        };
        header.Controls.Add(title);
        header.Controls.Add(new Label
        {
            Text = "BY SWIR    /    KOPIE PLIKÓW I CHOMIKUJ    /    v1.0.0",
            ForeColor = Cyan,
            Location = new Point(8, 52),
            AutoSize = true,
            Font = new Font("Segoe UI", 9f, FontStyle.Bold),
        });

        var columns = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = Background,
        };
        columns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 44));
        columns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 56));
        layout.Controls.Add(columns, 0, 1);

        var left = MakeSurface();
        var right = MakeSurface();
        left.Padding = new Padding(20);
        right.Padding = new Padding(20);
        columns.Controls.Add(left, 0, 0);
        columns.Controls.Add(right, 1, 0);
        columns.SetCellPosition(right, new TableLayoutPanelCellPosition(1, 0));
        columns.Margin = new Padding(0);
        left.Margin = new Padding(0, 0, 8, 0);
        right.Margin = new Padding(8, 0, 0, 0);

        // A scrollable form keeps every control reachable on smaller screens.
        var inputPanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            AutoScroll = true,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            BackColor = Surface,
            Padding = new Padding(0),
        };
        left.Controls.Add(inputPanel);
        inputPanel.Resize += (_, _) => ResizeInputControls(inputPanel);

        AddHeading(inputPanel, "TWÓJ SEJF", "Zaszyfrowane kopie na dysku lokalnym");
        AddField(inputPanel, "Folder sejfu", repository, true, () => BrowseRepository());
        repository.Text = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "ChomcioVault");
        AddField(inputPanel, "Folder do skopiowania", source, true, () => BrowseSource());
        AddField(inputPanel, "Hasło sejfu (nigdzie nie zapisywane)", secret, false, null);
        secret.UseSystemPasswordChar = true;
        inputPanel.Controls.Add(MakeAction("UTWÓRZ NOWY SEJF", async () =>
        {
            string path = repository.Text.Trim();
            string password = TakePassword();
            await PerformAsync("Tworzenie sejfu", _ =>
                LocalEncryptedVault.Initialize(path, password), canCancel: false);
        }));
        inputPanel.Controls.Add(MakeAction("WYKONAJ KOPIĘ", BackupAsync, true));
        inputPanel.Controls.Add(MakeAction("CHOMIKUJ — KOPIE W CHMURZE", () =>
        {
            using var cloud = new CloudWindow(repository.Text.Trim(), source.Text.Trim());
            cloud.ShowDialog(this);
            return Task.CompletedTask;
        }, true));
        inputPanel.Controls.Add(MakeAction("ODŚWIEŻ PUNKTY", RefreshSnapshotsAsync));
        inputPanel.Controls.Add(MakeAction("ZWERYFIKUJ KOPIĘ", VerifyAsync));
        inputPanel.Controls.Add(MakeAction("PRZYWRÓĆ DO NOWEGO FOLDERU", RestoreAsync));
        cancelOperation.Text = "ANULUJ OPERACJĘ";
        cancelOperation.BackColor = Background;
        cancelOperation.ForeColor = Cyan;
        cancelOperation.FlatStyle = FlatStyle.Flat;
        cancelOperation.Height = 42;
        cancelOperation.Width = 400;
        cancelOperation.Enabled = false;
        cancelOperation.Click += (_, _) => RequestCancellation();
        FormClosing += OnClosingDuringOperation;
        inputPanel.Controls.Add(new Label
        {
            Text = "Zaawansowane operacje na lokalnym sejfie. " +
                   "Automatyczne zadania i obraz Windows są dostępne w głównym pulpicie.",
            ForeColor = Dim,
            AutoSize = false,
            Height = 78,
            TextAlign = ContentAlignment.MiddleLeft,
            Margin = new Padding(0, 16, 0, 0),
        });

        var rightGrid = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            RowCount = 4,
            ColumnCount = 1,
            BackColor = Surface,
        };
        rightGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 45));
        rightGrid.RowStyles.Add(new RowStyle(SizeType.Percent, 48));
        rightGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
        rightGrid.RowStyles.Add(new RowStyle(SizeType.Percent, 52));
        right.Controls.Add(rightGrid);
        rightGrid.Controls.Add(MakeLabel("PUNKTY PRZYWRACANIA", Cyan, true), 0, 0);
        recoveryPoints.BackColor = Background;
        recoveryPoints.ForeColor = Ink;
        recoveryPoints.BorderStyle = BorderStyle.None;
        recoveryPoints.Font = TextFont;
        recoveryPoints.Dock = DockStyle.Fill;
        recoveryPoints.IntegralHeight = false;
        recoveryPoints.HorizontalScrollbar = true;
        rightGrid.Controls.Add(recoveryPoints, 0, 1);
        rightGrid.Controls.Add(MakeLabel("DZIENNIK OPERACJI", Cyan, true), 0, 2);
        eventLog.BackColor = Background;
        eventLog.ForeColor = Dim;
        eventLog.ReadOnly = true;
        eventLog.BorderStyle = BorderStyle.None;
        eventLog.Dock = DockStyle.Fill;
        rightGrid.Controls.Add(eventLog, 0, 3);
        WriteEvent("Gotowe. Ustaw folder sejfu i wybierz operację.");

        state.Dock = DockStyle.Fill;
        state.ForeColor = Color.FromArgb(108, 210, 174);
        state.Text = "●  TRYB LOKALNY  •  brak połączenia z Chomikuj";
        state.TextAlign = ContentAlignment.MiddleLeft;
        state.Font = new Font("Segoe UI", 9f);
        var footer = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1 };
        footer.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 190));
        footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        cancelOperation.Dock = DockStyle.Fill;
        footer.Controls.Add(cancelOperation, 0, 0);
        footer.Controls.Add(state, 1, 0);
        layout.Controls.Add(footer, 0, 2);
    }

    private static Panel MakeSurface() => new() { Dock = DockStyle.Fill, BackColor = Surface };

    private static Label MakeLabel(string text, Color color, bool bold = false) => new()
    {
        Text = text,
        ForeColor = color,
        Font = new Font("Segoe UI", bold ? 10f : 9f,
            bold ? FontStyle.Bold : FontStyle.Regular),
        AutoSize = false,
        Height = 35,
        Dock = DockStyle.Fill,
        TextAlign = ContentAlignment.MiddleLeft,
    };

    private static void AddHeading(FlowLayoutPanel parent, string heading, string subtitle)
    {
        parent.Controls.Add(new Label
        {
            Text = heading, ForeColor = Cyan,
            Font = new Font("Segoe UI", 15f, FontStyle.Bold),
            Height = 36, Width = 400,
        });
        parent.Controls.Add(new Label
        {
            Text = subtitle, ForeColor = Dim,
            Height = 30, Width = 400,
        });
    }

    private void AddField(FlowLayoutPanel parent, string title, TextBox input,
        bool showBrowse, Action? browse)
    {
        var wrapper = new Panel { Height = 83, Width = 400, Margin = new Padding(0, 0, 0, 6) };
        wrapper.Controls.Add(new Label
        {
            Text = title,
            ForeColor = Dim,
            Height = 25,
            Dock = DockStyle.Top,
        });
        var line = new Panel { Dock = DockStyle.Bottom, Height = 42, BackColor = Background };
        wrapper.Controls.Add(line);
        input.BackColor = Background;
        input.ForeColor = Ink;
        input.BorderStyle = BorderStyle.None;
        input.Font = TextFont;
        input.Location = new Point(9, 11);
        input.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        input.Width = showBrowse ? 305 : 380;
        line.Controls.Add(input);
        line.Resize += (_, _) => input.Width = Math.Max(120, line.Width - (showBrowse ? 88 : 20));
        if (showBrowse)
        {
            var browseButton = new Button
            {
                Text = "...",
                Width = 60,
                Height = 34,
                Dock = DockStyle.Right,
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(28, 69, 105),
                ForeColor = Color.White,
            };
            browseButton.FlatAppearance.BorderSize = 0;
            browseButton.Click += (_, _) => browse?.Invoke();
            line.Controls.Add(browseButton);
            actions.Add(browseButton);
        }
        parent.Controls.Add(wrapper);
    }

    private static void ResizeInputControls(FlowLayoutPanel panel)
    {
        int width = Math.Max(190, panel.ClientSize.Width - 28);
        foreach (Control control in panel.Controls)
            control.Width = width;
    }

    private Button MakeAction(string caption, Func<Task> action, bool prominent = false)
    {
        var button = new StudioButton
        {
            Primary = prominent,
            Text = caption,
            Width = 400,
            Height = 46,
            Margin = new Padding(0, 5, 0, 5),
            FlatStyle = FlatStyle.Flat,
            BackColor = prominent ? Color.FromArgb(10, 119, 183) : Color.FromArgb(28, 55, 84),
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 9f, FontStyle.Bold),
        };
        button.FlatAppearance.BorderSize = 0;
        button.Click += async (_, _) =>
        {
            try { await action(); }
            catch (Exception error)
            {
                WriteEvent("BŁĄD: " + error.GetType().Name + ": " + error.Message);
                state.Text="Sprawdź dane — szczegóły w dzienniku poniżej.";
            }
        };
        actions.Add(button);
        return button;
    }

    private void BrowseRepository()
    {
        using var pick = new FolderBrowserDialog
        {
            Description = "Wybierz istniejący sejf. Aby stworzyć nowy, wpisz nową ścieżkę ręcznie.",
            ShowNewFolderButton = true,
        };
        if (pick.ShowDialog(this) == DialogResult.OK)
            repository.Text = pick.SelectedPath;
    }

    private void BrowseSource()
    {
        using var pick = new FolderBrowserDialog
        {
            Description = "Wybierz folder z plikami do skopiowania",
            ShowNewFolderButton = false,
        };
        if (pick.ShowDialog(this) == DialogResult.OK)
            source.Text = pick.SelectedPath;
    }

    private string TakePassword()
    {
        string password = secret.Text;
        secret.Clear();
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Podaj hasło sejfu.");
        return password;
    }

    private string GetSnapshotId()
    {
        if (recoveryPoints.SelectedItem is not PointItem item)
            throw new ArgumentException("Najpierw zaznacz punkt przywracania.");
        return item.Id;
    }

    private async Task BackupAsync()
    {
        string path = repository.Text.Trim();
        string from = source.Text.Trim();
        string password = TakePassword();
        BackupResultHolder? result = null;
        bool ok = await PerformAsync("Tworzenie zaszyfrowanej kopii", token =>
        {
            using var vault = LocalEncryptedVault.Open(path, password);
            var backup = vault.BackupDirectory(from, token);
            result = new BackupResultHolder(backup.SnapshotId, backup.Files, backup.TotalBytes);
        });
        if (ok && result is not null && !closeAfterOperation)
        {
            WriteEvent($"Kopia {result.Id}: {result.Files} plików, {result.Bytes:N0} B");
            await ReloadWithPasswordAsync(path, password);
        }
    }

    private async Task RefreshSnapshotsAsync()
    {
        string path = repository.Text.Trim();
        string password = TakePassword();
        await ReloadWithPasswordAsync(path, password);
    }

    private async Task ReloadWithPasswordAsync(string path, string password)
    {
        List<PointItem>? points = null;
        bool ok = await PerformAsync("Wczytywanie punktów", token =>
        {
            using var vault = LocalEncryptedVault.Open(path, password);
            points = vault.ListSnapshotIds().Select(id =>
            {
                token.ThrowIfCancellationRequested();
                var snap = vault.ReadSnapshot(id);
                return new PointItem(id, snap.CreatedUtc.LocalDateTime);
            }).OrderByDescending(p => p.When).ToList();
        });
        if (!ok || points is null) return;
        recoveryPoints.Items.Clear();
        foreach (var item in points) recoveryPoints.Items.Add(item);
        WriteEvent($"Wczytano {points.Count} punktów przywracania.");
    }

    private async Task VerifyAsync()
    {
        string id = GetSnapshotId();
        string path = repository.Text.Trim();
        string password = TakePassword();
        await PerformAsync("Weryfikacja szyfrowanej kopii", token =>
        {
            using var vault = LocalEncryptedVault.Open(path, password);
            vault.VerifySnapshot(id, token);
        });
    }

    private async Task RestoreAsync()
    {
        string id = GetSnapshotId();
        string path = repository.Text.Trim();
        using var pick = new FolderBrowserDialog
        {
            Description = "Wybierz FOLDER NADRZĘDNY. Przywrócenie nastąpi do nowego podfolderu.",
            ShowNewFolderButton = true,
        };
        if (pick.ShowDialog(this) != DialogResult.OK) return;
        string target = Path.Combine(pick.SelectedPath,
            $"ChomcioRestore_{DateTime.Now:yyyyMMdd_HHmmss}_{Guid.NewGuid():N}");
        if (MessageBox.Show(this,
            $"Odtworzyć kopię {id} do NOWEGO folderu?\n\n{target}\n\n" +
            "Żaden istniejący plik nie powinien zostać nadpisany.",
            "Potwierdź przywracanie", MessageBoxButtons.YesNo,
            MessageBoxIcon.Question) != DialogResult.Yes) return;
        string password = TakePassword();
        bool ok = await PerformAsync("Przywracanie kopii", token =>
        {
            using var vault = LocalEncryptedVault.Open(path, password);
            vault.VerifySnapshot(id, token);
            vault.RestoreSnapshot(id, target, token);
        });
        if (ok) WriteEvent($"Odtworzono do: {target}");
    }

    private void RequestCancellation()
    {
        if (activeOperation is null) return;
        if (!activeOperationCanCancel)
        {
            state.Text = "●  CZEKAM NA ZAKOŃCZENIE KRÓTKIEJ OPERACJI";
            return;
        }
        cancelOperation.Enabled = false;
        activeOperation.Cancel(); // Requests cooperative cancellation; never kills the worker.
        state.Text = "●  ANULOWANIE — CZEKAM NA ZAKOŃCZENIE ZAPISU I SPRZĄTANIE";
        WriteEvent("Zlecono anulowanie. Jeśli zatwierdzenie już nastąpiło, kopia pozostanie poprawna.");
    }

    private void OnClosingDuringOperation(object? sender, FormClosingEventArgs e)
    {
        if (activeOperation is null) return;
        // The window must remain alive until the worker exits its cleanup/finally.
        // This cannot protect against power loss or a forced OS process kill.
        e.Cancel = true;
        if (closeAfterOperation) return;
        if (MessageBox.Show(this,
            "Operacja trwa. Zatrzymać ją i zamknąć program po jej bezpiecznym zakończeniu?",
            "Trwa praca z kopią", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
            return;
        closeAfterOperation = true;
        RequestCancellation();
    }

    private async Task<bool> PerformAsync(string operation, Action<CancellationToken> work,
        bool canCancel = true)
    {
        if (activeOperation is not null)
            throw new InvalidOperationException("Inna operacja jeszcze trwa.");
        using var cancellation = new CancellationTokenSource();
        activeOperation = cancellation;
        activeOperationCanCancel = canCancel;
        foreach (Button control in actions) control.Enabled = false;
        repository.Enabled = source.Enabled = secret.Enabled = recoveryPoints.Enabled = false;
        cancelOperation.Enabled = canCancel;
        state.Text = "●  TRWA: " + operation;
        WriteEvent("Start: " + operation);
        try
        {
            await Task.Run(() =>
            {
                cancellation.Token.ThrowIfCancellationRequested();
                work(cancellation.Token);
            });
            // Do NOT inspect IsCancellationRequested after work returns: a late
            // click may follow the final atomic commit. That operation succeeded.
            WriteEvent("OK: " + operation);
            return true;
        }
        catch (OperationCanceledException canceled) when (canceled.CancellationToken == cancellation.Token)
        {
            WriteEvent("ANULOWANO: " + operation + ". Wynik może już istnieć; przed użyciem wymaga ponownego sprawdzenia.");
            return false;
        }
        catch (Exception error)
        {
            // Cleanup/I/O errors are failures, NOT a falsely successful cancellation.
            WriteEvent("BŁĄD: " + error.GetType().Name + ": " + error.Message);
            state.Text="Operacja wymaga uwagi — szczegóły w dzienniku poniżej.";
            return false;
        }
        finally
        {
            activeOperation = null;
            activeOperationCanCancel = false;
            cancelOperation.Enabled = false;
            state.Text = "●  TRYB LOKALNY  •  brak połączenia z Chomikuj";
            foreach (Button control in actions) control.Enabled = true;
            repository.Enabled = source.Enabled = secret.Enabled = recoveryPoints.Enabled = true;
            if (closeAfterOperation) BeginInvoke(new Action(Close));
        }
    }

    private void WriteEvent(string message)
    {
        eventLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
        eventLog.ScrollToCaret();
    }

    private sealed record BackupResultHolder(string Id, int Files, long Bytes);
    private sealed record PointItem(string Id, DateTime When)
    {
        public override string ToString() => $"{When:yyyy-MM-dd HH:mm}    {Id}";
    }
}
