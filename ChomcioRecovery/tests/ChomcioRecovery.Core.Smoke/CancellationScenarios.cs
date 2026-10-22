using ChomcioRecovery.Core;
using System.Security.Cryptography;

// Real filesystem/crypto tests, not a mocked vault. Must be compiled and RUN
// by the smoke project before any CHOMCIO_NATIVE_CANCELLATION result is credited.
internal static class CancellationScenarios
{
    internal static void Run(string sandbox, Action<bool, string> check)
    {
        string root = Path.Combine(sandbox, "cancellation");
        Directory.CreateDirectory(root);
        string source = Path.Combine(root, "source");
        Directory.CreateDirectory(Path.Combine(source, "empty"));
        byte[] content = RandomNumberGenerator.GetBytes(LocalEncryptedVault.ChunkBytes + 17);
        string inputFile = Path.Combine(source, "synthetic.bin");
        File.WriteAllBytes(inputFile, content);
        string repo = Path.Combine(root, "vault");
        LocalEncryptedVault.Initialize(repo, "synthetic-cancellation-test-only-2026");
        using var vault = LocalEncryptedVault.Open(repo, "synthetic-cancellation-test-only-2026");
        var baseline = vault.BackupDirectory(source);
        var snapshot = vault.ReadSnapshot(baseline.SnapshotId);
        byte[] oldManifest = File.ReadAllBytes(Path.Combine(repo, "snapshots", baseline.SnapshotId + ".snap"));

        void MustCancel(Action work, CancellationToken token, string label)
        {
            bool caught = false;
            try { work(); }
            catch (OperationCanceledException error)
            {
                caught = true;
                check(error.CancellationToken == token, label + ": original token preserved");
            }
            check(caught, label + ": canceled rather than returning success");
        }

        using (var earlyWrite = new CancellationTokenSource())
        {
            string record = Path.Combine(root, "early-cancel.obj");
            MustCancel(() => LocalEncryptedVault.WriteAtomic(record, content,
                cancellationToken: earlyWrite.Token, afterTempCreated: () => earlyWrite.Cancel()),
                earlyWrite.Token, "cancel after creating temp before first write");
            check(!File.Exists(record) && !Directory.EnumerateFiles(root, "early-cancel.obj.tmp-*").Any(),
                "early canceled write cleans own identified temp without masking cancellation");
        }

        using (var stop = new CancellationTokenSource())
        {
            stop.Cancel();
            MustCancel(() => vault.BackupDirectory(source, stop.Token), stop.Token, "pre-canceled backup");
            MustCancel(() => vault.VerifySnapshot(baseline.SnapshotId, stop.Token), stop.Token, "pre-canceled verify");
            string target = Path.Combine(root, "pre-canceled-restore");
            MustCancel(() => vault.RestoreSnapshot(baseline.SnapshotId, target, stop.Token), stop.Token,
                "pre-canceled directory restore");
            check(!Directory.Exists(target), "pre-canceled directory output absent");
            target = Path.Combine(root, "pre-canceled-file");
            MustCancel(() => vault.RestoreFile(baseline.SnapshotId, "synthetic.bin", target, stop.Token), stop.Token,
                "pre-canceled single file restore");
            check(!File.Exists(target), "pre-canceled single-file output absent");
            MustCancel(() => { using var pin = WindowsSourceTreePin.Acquire(source, stop.Token); },
                stop.Token, "pre-canceled source handle inventory");
        }

        // The production read loop must notice cancellation requested while a
        // synchronous OS read was in flight, before the bytes reach encryption.
        using (var stop = new CancellationTokenSource())
        using (var input = new CancelDuringReadStream(content, () => stop.Cancel()))
        {
            byte[] buffer = new byte[LocalEncryptedVault.ChunkBytes];
            try
            {
                MustCancel(() => LocalEncryptedVault.ReadChunk(input, buffer, stop.Token), stop.Token,
                    "cancellation inside a source read");
                check(input.ReadCalls == 1, "no second source read after cancellation");
                check(input.LargestRequest == 65_536, "source read cancellation has 64-KiB polling bound");
            }
            finally { CryptographicOperations.ZeroMemory(buffer); }
        }

        // Inject cancellation after encrypted chunks have been verified, at the
        // final source-check boundary used by the real backup publication path.
        using (var stop = new CancellationTokenSource())
        {
            string id = Guid.NewGuid().ToString("N");
            bool reached = false;
            MustCancel(() => vault.PublishVerifiedSnapshot(id, snapshot,
                () => { reached = true; stop.Cancel(); }, cancellationToken: stop.Token), stop.Token, "manifest pre-commit");
            check(reached, "manifest pre-commit callback really executed");
            check(!File.Exists(Path.Combine(repo, "snapshots", id + ".snap")), "canceled manifest not published");
        }

        // Real encrypted temp file exists when cancellation is requested. Neither
        // its target nor a partial manifest may be left visible by WriteAtomic.
        using (var stop = new CancellationTokenSource())
        {
            string record = Path.Combine(root, "cancel-record.obj");
            bool reached = false;
            MustCancel(() => LocalEncryptedVault.WriteAtomic(record, content,
                beforeReadback: temp =>
                {
                    check(File.Exists(temp), "atomic cancellation happened after actual temp write");
                    reached = true;
                    stop.Cancel();
                }, cancellationToken: stop.Token), stop.Token, "atomic record before publication");
            check(reached && !File.Exists(record), "atomic cancellation no committed record");
            check(!Directory.EnumerateFiles(root, "cancel-record.obj.tmp-*").Any(), "atomic cancellation cleans own temp");
        }

        using (var stop = new CancellationTokenSource())
        {
            string target = Path.Combine(root, "cancel-tree");
            bool reached = false;
            MustCancel(() => vault.RestoreSnapshotCore(baseline.SnapshotId, target,
                beforeStageReadback: stage =>
                {
                    check(File.Exists(Path.Combine(stage, "synthetic.bin")), "restore cancellation after real write");
                    reached = true;
                    stop.Cancel();
                }, cancellationToken: stop.Token), stop.Token, "directory restore before readback");
            check(reached && !Directory.Exists(target), "canceled restore never published");
            check(!Directory.EnumerateDirectories(root, ".chomcio-restore-*").Any(), "canceled restore own stage cleaned");
        }

        using (var stop = new CancellationTokenSource())
        {
            string target = Path.Combine(root, "cancel-file.bin");
            MustCancel(() => vault.RestoreFileCore(baseline.SnapshotId, "synthetic.bin", target,
                beforeStageReadback: _ => stop.Cancel(), cancellationToken: stop.Token), stop.Token,
                "single file before readback");
            check(!File.Exists(target), "canceled single file never published");
            check(!Directory.EnumerateDirectories(root, ".chomcio-file-restore-*").Any(),
                "canceled single-file own stage cleaned");
        }

        using (var stop = new CancellationTokenSource())
        {
            MustCancel(() => LocalEncryptedVault.VerifyStagedFileOnDisk(inputFile, snapshot.Files.Single(),
                beforeReadbackHandleOpen: () => stop.Cancel(), cancellationToken: stop.Token), stop.Token,
                "cancellation during opened-file readback");
        }

        // Publication racing with late cancellation must not replace existing data.
        string existing = Path.Combine(root, "existing.bin");
        byte[] sentinel = "original must survive"u8.ToArray();
        File.WriteAllBytes(existing, sentinel);
        using (var stop = new CancellationTokenSource())
        {
            stop.Cancel();
            MustCancel(() => vault.RestoreFile(baseline.SnapshotId, "synthetic.bin", existing, stop.Token),
                stop.Token, "pre-canceled existing target");
        }
        check(File.ReadAllBytes(existing).SequenceEqual(sentinel), "existing user file unchanged");
        check(File.ReadAllBytes(inputFile).SequenceEqual(content), "original source bytes unchanged");
        check(File.ReadAllBytes(Path.Combine(repo, "snapshots", baseline.SnapshotId + ".snap"))
            .SequenceEqual(oldManifest), "previous recovery point byte-identical after cancellation");
        check(vault.ListSnapshotIds().Count == 1, "all canceled operations left snapshot count unchanged");

        // The same vault remains usable and the previous recovery point restores.
        var after = vault.BackupDirectory(source, CancellationToken.None);
        vault.VerifySnapshot(after.SnapshotId, CancellationToken.None);
        string restored = Path.Combine(root, "restored-after-cancel");
        vault.RestoreSnapshot(baseline.SnapshotId, restored, CancellationToken.None);
        check(File.ReadAllBytes(Path.Combine(restored, "synthetic.bin")).SequenceEqual(content),
            "byte-exact restore still works after cancellation");
        check(Directory.Exists(Path.Combine(restored, "empty")), "empty directory still restores");
        check(vault.ListSnapshotIds().Count == 2, "new normal backup commits after canceled operations");
        Console.WriteLine("CHOMCIO_NATIVE_CANCELLATION=PASS");
    }

    private sealed class CancelDuringReadStream : MemoryStream
    {
        private readonly Action afterRead;
        internal int ReadCalls { get; private set; }
        internal int LargestRequest { get; private set; }
        internal CancelDuringReadStream(byte[] content, Action afterRead) : base(content, writable: false)
        {
            this.afterRead = afterRead;
        }
        public override int Read(byte[] buffer, int offset, int count)
        {
            ReadCalls++;
            LargestRequest = Math.Max(LargestRequest, count);
            int result = base.Read(buffer, offset, count);
            afterRead();
            return result;
        }
    }
}
