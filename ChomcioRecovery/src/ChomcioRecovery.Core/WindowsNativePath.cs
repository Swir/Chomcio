namespace ChomcioRecovery.Core;

// Win32 P/Invokes do not inherit System.IO's extended-path conversion.
// Convert only at the native boundary, after public path validation.
internal static class WindowsNativePath
{
    internal static string FromPath(string path)
    {
        string full = Path.GetFullPath(path);
        if (full.StartsWith(@"\\?\", StringComparison.Ordinal)) return full;
        return full.StartsWith(@"\\", StringComparison.Ordinal)
            ? @"\\?\UNC\" + full[2..]
            : @"\\?\" + full;
    }
}
