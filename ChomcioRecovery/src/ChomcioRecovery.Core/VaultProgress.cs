using System.Diagnostics;

namespace ChomcioRecovery.Core;

public enum VaultProgressStage
{
    Encrypting,
    CheckingStoredData,
    CheckingSource,
    CheckingPublishedData,
    CheckingSourceAfterPublish,
    VerifyingSnapshot,
    CheckingExportSource,
    CopyingEncryptedExport,
    CheckingExportData,
    CheckingExportBeforePublish,
    CheckingExportWithLeases,
    CheckingPublishedExport
}

// Counts describe the CURRENT pass, never overall completion or backup success.
// They deliberately carry no source paths, account data or encryption material.
public sealed record VaultProgress(VaultProgressStage Stage, long ProcessedBytes, long TotalBytes);

internal sealed class VaultProgressReporter
{
    private readonly IProgress<VaultProgress>? observer;
    private readonly VaultProgressStage stage;
    private readonly long total;
    private readonly Stopwatch clock = Stopwatch.StartNew();
    private long processed, lastReported = -1;
    private bool reportedAdvance;

    internal VaultProgressReporter(IProgress<VaultProgress>? observer, VaultProgressStage stage, long total)
    {
        this.observer = observer; this.stage = stage; this.total = total;
        Report();
    }

    internal void Advance(long bytes)
    {
        if (observer is null) return;
        processed = checked(processed + bytes);
        // Source changes are still refused by the existing identity/content
        // checks. Do not make an invalid total look like a completed pass.
        if (processed > total) throw new IOException("Source size changed during the current backup pass.");
        if (!reportedAdvance || clock.ElapsedMilliseconds >= 200 || processed == total)
        {
            reportedAdvance = true;
            Report();
        }
    }

    private void Report()
    {
        if (observer is null || processed == lastReported) return;
        observer.Report(new(stage, processed, total));
        lastReported = processed; clock.Restart();
    }
}
