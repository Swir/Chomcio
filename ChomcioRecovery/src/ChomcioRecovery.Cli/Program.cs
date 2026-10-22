using ChomcioRecovery.Core;
using System.Text;
using System.Security.Cryptography;

static string ReadPassword(CancellationToken cancellationToken)
{
    cancellationToken.ThrowIfCancellationRequested();
    string? fromEnvironment = Environment.GetEnvironmentVariable("CHOMCIO_PASSWORD");
    if (!string.IsNullOrEmpty(fromEnvironment)) return fromEnvironment;
    if (Console.IsInputRedirected)
        throw new InvalidOperationException("Set CHOMCIO_PASSWORD or use an interactive terminal.");
    Console.Error.Write("Password (not echoed): ");
    var sb = new StringBuilder();
    while (true)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // ReadKey alone blocks after Ctrl+C has been handled cooperatively.
        // Poll while waiting so a canceled password prompt can exit as well.
        if (!Console.KeyAvailable)
        {
            Thread.Sleep(25);
            continue;
        }
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter) break;
        if (key.Key == ConsoleKey.Backspace && sb.Length > 0) sb.Length--;
        else if (!char.IsControl(key.KeyChar)) sb.Append(key.KeyChar);
    }
    Console.Error.WriteLine();
    return sb.ToString();
}

// Ctrl+C requests cooperative cancellation only for token-aware operations.
// A canceled backup/import may already have published immutable records.
using var cancellation = new CancellationTokenSource();
bool canCancel = args.Length > 0 && args[0] is "backup" or "verify" or "restore" or "restore-file" or "import" or "export";
ConsoleCancelEventHandler cancelHandler = (_, e) =>
{
    if (!canCancel) return;
    e.Cancel = true; // Repeated Ctrl+C still must not kill a worker mid-cleanup.
    cancellation.Cancel();
};
Console.CancelKeyPress += cancelHandler;

try
{
    if (args.Length < 2) throw new ArgumentException("Usage: init REPO | backup REPO SOURCE | list REPO | verify REPO SNAPSHOT | restore REPO SNAPSHOT NEW_DESTINATION | files REPO SNAPSHOT | folders REPO SNAPSHOT | restore-file REPO SNAPSHOT RELATIVE_PATH NEW_FILE | export REPO SNAPSHOT NEW_ENCRYPTED_REPO | import REPO SNAPSHOT PORTABLE_ENCRYPTED_REPO");
    string password = ReadPassword(cancellation.Token);
    if (args[0] == "init" && args.Length == 2)
    {
        LocalEncryptedVault.Initialize(args[1], password);
        Console.WriteLine("New encrypted repository initialized.");
    }
    else
    {
        using var vault = LocalEncryptedVault.Open(args[1], password);
        switch (args[0])
        {
            case "backup" when args.Length == 3:
                var result = vault.BackupDirectory(args[2], cancellation.Token);
                Console.WriteLine($"SNAPSHOT={result.SnapshotId} FILES={result.Files} BYTES={result.TotalBytes} NEW_CHUNKS={result.NewChunks} REUSED_CHUNKS={result.ReusedChunks}");
                break;
            case "list" when args.Length == 2:
                foreach (string id in vault.ListSnapshotIds())
                    Console.WriteLine($"{id} {vault.ReadSnapshot(id).CreatedUtc:O}");
                break;
            case "files" when args.Length == 3:
                foreach (var file in vault.ReadSnapshot(args[2]).Files)
                    Console.WriteLine($"{file.Size,12}  {file.Path}");
                break;
            case "folders" when args.Length == 3:
                foreach (string directory in vault.ReadSnapshot(args[2]).Directories ?? Enumerable.Empty<string>())
                    Console.WriteLine(directory);
                break;
            case "restore-file" when args.Length == 5:
                vault.RestoreFile(args[2], args[3], args[4], cancellation.Token);
                Console.WriteLine("Verified single file restored to a NEW filename; nothing overwritten.");
                break;
            case "export" when args.Length == 4:
                vault.ExportEncryptedSnapshot(args[2], args[3], cancellation.Token);
                Console.WriteLine("Exported one verified encrypted recovery point into a NEW local vault.");
                break;
            case "import" when args.Length == 4:
                vault.ImportEncryptedSnapshot(args[2], args[3], cancellation.Token);
                Console.WriteLine("Imported and verified encrypted recovery point; no existing snapshot overwritten.");
                break;
            case "verify" when args.Length == 3:
                vault.VerifySnapshot(args[2], cancellation.Token);
                Console.WriteLine("Verified: encrypted snapshot and all file chunks.");
                break;
            case "restore" when args.Length == 4:
                vault.RestoreSnapshot(args[2], args[3], cancellation.Token);
                Console.WriteLine("Restored to a NEW destination; existing files were not overwritten.");
                break;
            default: throw new ArgumentException("Unknown command or incorrect arguments.");
        }
    }
    return 0;
}
catch (OperationCanceledException canceled) when (canceled.CancellationToken == cancellation.Token)
{
    Console.Error.WriteLine("ChomcioRecovery: operation canceled. Immutable chunks or a committed result may remain; verify/list before retrying. Nothing was rolled back by pathname.");
    return 130;
}
catch (Exception error) when (error is IOException or ArgumentException or CryptographicException or UnauthorizedAccessException or InvalidDataException or InvalidOperationException)
{
    Console.Error.WriteLine($"ChomcioRecovery: {error.GetType().Name}: {error.Message}");
    return 2;
}

finally
{
    Console.CancelKeyPress -= cancelHandler;
}
