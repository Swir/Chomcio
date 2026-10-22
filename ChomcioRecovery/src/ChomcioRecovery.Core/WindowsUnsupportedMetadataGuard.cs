namespace ChomcioRecovery.Core;

/// <summary>
/// The current snapshot encodes regular file bytes and directory names only.
/// Reject Windows filesystem features whose confidentiality, storage allocation,
/// or content availability cannot be reproduced by this format. This is a
/// preflight check, not a race-free guarantee: Windows VSS + pinned handles and
/// preservation of ACLs and attributes remain mandatory before production use.
/// </summary>
internal static class WindowsUnsupportedMetadataGuard
{
    internal const FileAttributes Unsupported =
        FileAttributes.Encrypted | FileAttributes.SparseFile | FileAttributes.Offline | FileAttributes.Compressed;

    internal static void RejectUnsupported(FileAttributes attributes, string path)
    {
        // FileAttributes has platform-dependent meaning. The Windows guard is
        // invoked in both source inventory scans and immediately before reads.
        if (!OperatingSystem.IsWindows()) return;
        RejectFlags(attributes, path);
    }

    // Pure predicate for native .NET tests, independent of EFS provisioning.
    internal static void RejectFlags(FileAttributes attributes, string path)
    {
        FileAttributes unsupported = attributes & Unsupported;
        if (unsupported != 0)
            throw new IOException(
                $"Cannot make a complete restorable backup of '{path}': " +
                $"unsupported NTFS attribute(s): {unsupported}. " +
                "EFS, sparse allocation, NTFS compression and offline files are not preserved.");
    }
}
