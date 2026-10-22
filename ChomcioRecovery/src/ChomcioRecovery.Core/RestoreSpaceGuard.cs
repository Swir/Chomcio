namespace ChomcioRecovery.Core;

/// <summary>
/// Conservative restore-volume free-space preflight. No plaintext staging is
/// created if the volume cannot hold the manifest's total logical file size
/// plus a reserve. This is NOT a disk allocation or quota guarantee: free
/// space may change during restore and metadata itself consumes disk space.
/// </summary>
internal static class RestoreSpaceGuard
{
    internal const long SafetyReserveBytes = 64L * 1024 * 1024;

    /// <param name="freeSpaceQuery">Native smoke-only injection for deterministic
    /// low-space tests; normal restore always reads the real volume.</param>
    internal static void RequireAvailable(string existingParent, IEnumerable<long> fileSizes,
        Func<string, long>? freeSpaceQuery = null)
    {
        ArgumentNullException.ThrowIfNull(existingParent);
        ArgumentNullException.ThrowIfNull(fileSizes);
        long required = 0;
        foreach (long length in fileSizes)
        {
            if (length < 0)
                throw new InvalidDataException("Invalid negative restore file size.");
            try { required = checked(required + length); }
            catch (OverflowException error)
            {
                throw new InvalidDataException("Restore logical size exceeds supported range.", error);
            }
        }
        string parent = Path.GetFullPath(existingParent);
        // If volume information is unavailable, do not claim it is safe to
        // start writing decrypted content. UNC/quotas require real Windows tests.
        long free = freeSpaceQuery is not null
            ? freeSpaceQuery(parent)
            : OperatingSystem.IsWindows() ? WindowsVolumeSpace.AvailableBytes(parent)
            : new DriveInfo(Path.GetPathRoot(parent)
                ?? throw new IOException("Restore volume root unavailable.")).AvailableFreeSpace;
        // Subtract only AFTER comparing so required+reserve never overflows.
        if (free < 0 || free < required || free - required < SafetyReserveBytes)
            throw new IOException("Insufficient free space for verified restore and safety reserve.");
    }
}
