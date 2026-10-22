using System.Reflection;
using ChomcioRecovery.Chomikuj;

internal static class DesktopSmoke
{
    private static int assertions;
    private static void Check(bool condition, string message) { assertions++; if (!condition) throw new Exception(message); }
    private static object Field(object target, string name) => target.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(target)!;
    private static object? Call(object target, string name, params object[] args) => target.GetType().GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(target, args);
    private static Form Create(string name, params object[] args) => (Form)Activator.CreateInstance(Assembly.Load("ChomcioRecovery").GetType("ChomcioRecovery.Desktop." + name)!, args)!;

    [STAThread]
    private static int Main(string[] args)
    {
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        int exit = 1;
        using var host = new Form { Opacity = 0, ShowInTaskbar = false };
        host.Shown += async (_, _) =>
        {
            try
            {
                string pictures = args.Length > 0 ? args[0] : Path.GetTempPath();
                Directory.CreateDirectory(pictures);
                using var window = Create("RecoveryWindow");
                window.Opacity = 0; window.ShowInTaskbar = false; window.Show();
                await Task.Delay(100);
                using (var bmp = new Bitmap(window.Width, window.Height))
                { window.DrawToBitmap(bmp, new Rectangle(0, 0, bmp.Width, bmp.Height)); bmp.Save(Path.Combine(pictures, "desktop.png")); }
                var repository = (TextBox)Field(window, "repository");
                using var cleanup = new ManualResetEventSlim();
                bool cleaned = false;
                var work = new Action<CancellationToken>(ct =>
                {
                    try { ct.WaitHandle.WaitOne(); ct.ThrowIfCancellationRequested(); }
                    finally { cleanup.Wait(TimeSpan.FromSeconds(5)); cleaned = true; }
                });
                var task = (Task<bool>)Call(window, "PerformAsync", "synthetic cancellation", work, true)!;
                Check(!repository.Enabled, "editing disabled during operation");
                Call(window, "RequestCancellation");
                window.GetType().GetField("closeAfterOperation", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(window, true);
                window.Close();
                Check(!window.IsDisposed && !cleaned, "window remains alive until cleanup");
                cleanup.Set();
                Check(!await task, "cancel distinct from success");
                Check(cleaned, "worker cleanup completed before GUI closure");
                await Task.Delay(100);
                Check(window.IsDisposed, "window closes after worker cleanup");
                using var late = Create("RecoveryWindow");
                late.Opacity = 0; late.ShowInTaskbar = false; late.Show();
                var committed = new Action<CancellationToken>(_ => ((CancellationTokenSource)Field(late, "activeOperation")).Cancel());
                Check(await (Task<bool>)Call(late, "PerformAsync", "commit raced with late cancel", committed, true)!, "late cancellation does not undo committed success");
                Check(((TextBox)Field(late, "repository")).Enabled, "fields enabled after completion");
                using var cloud = Create("CloudWindow", "synthetic-vault", "synthetic-source");
                cloud.Opacity = 0; cloud.ShowInTaskbar = false; cloud.Show();
                await Task.Delay(100);
                using (var bmp = new Bitmap(cloud.Width, cloud.Height))
                { cloud.DrawToBitmap(bmp, new Rectangle(0, 0, bmp.Width, bmp.Height)); bmp.Save(Path.Combine(pictures, "cloud.png")); }
                Check(((TextBox)Field(cloud, "accountPassword")).UseSystemPasswordChar, "account password masked");
                Check(((TextBox)Field(cloud, "vaultPassword")).UseSystemPasswordChar, "vault password masked separately");
                var folderList = (ComboBox)Field(cloud, "folders");
                var cloudType = cloud.GetType();
                cloudType.GetField("connected", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(cloud, true);
                var selectedFolder = new ChomikujFolder("17", "ChomcioRecovery_Test");
                Call(cloud, "SelectCreatedFolder", selectedFolder);
                Check(Equals(folderList.SelectedItem, selectedFolder), "test folder selected even after interrupted roundtrip");
                await (Task)Call(cloud, "LoginAsync")!;
                Check((bool)Field(cloud, "connected") && Equals(folderList.SelectedItem, selectedFolder),
                    "repeat connect with cleared password preserves connection and folder");
                IReadOnlyList<ChomikujFolder> reordered = new[] { new ChomikujFolder("18", "ChomcioRecovery_Other"), selectedFolder };
                Call(cloud, "ShowFolders", reordered);
                Check(Equals(folderList.SelectedItem, selectedFolder), "folder refresh preserves selection by ID");
                var snapshotList = (ListBox)Field(cloud, "snapshots");
                snapshotList.Items.Add("synthetic-snapshot");
                folderList.SelectedIndex = 0;
                Check(snapshotList.Items.Count == 0, "changing cloud folder clears old snapshot selection");
                using var release = new ManualResetEventSlim();
                bool cloudCleaned = false;
                var cloudWork = new Func<CancellationToken, Task>(ct => Task.Run(() =>
                {
                    try { ct.WaitHandle.WaitOne(); ct.ThrowIfCancellationRequested(); }
                    finally { release.Wait(TimeSpan.FromSeconds(5)); cloudCleaned = true; }
                }));
                var cloudTask = (Task<bool>)Call(cloud, "RunAsync", "synthetic cloud cancellation", cloudWork)!;
                cloud.Close();
                Check(!cloud.IsDisposed && !cloudCleaned, "cloud window waits for cancellation cleanup");
                release.Set();
                Check(!await cloudTask && cloudCleaned, "cloud cancel completes before closing");
                await Task.Delay(100);
                Check(cloud.IsDisposed, "cloud closes after cleanup");
                Console.WriteLine($"CHOMCIO_DESKTOP_SMOKE=PASS assertions={assertions}");
                exit = 0;
            }
            catch (Exception ex) { Console.Error.WriteLine(ex); }
            finally { host.Close(); }
        };
        Application.Run(host);
        return exit;
    }
}
