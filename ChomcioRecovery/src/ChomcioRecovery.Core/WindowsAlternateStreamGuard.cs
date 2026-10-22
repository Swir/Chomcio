using System.Runtime.InteropServices;

namespace ChomcioRecovery.Core;

/// <summary>
/// Strict default rejects every additional stream. Explicit v3 callers may
/// capture/verify bounded Zone.Identifier bytes; all other streams still fail.
/// This is a PRE-FLIGHT check, not a race-free Win32 handle pinning guarantee.
/// </summary>
internal static class WindowsAlternateStreamGuard
{
    private const int FindStreamInfoStandard = 0;
    private const int ErrorNoMoreFiles = 18;
    private const int ErrorHandleEof = 38;
    private static readonly IntPtr InvalidFindHandle = new(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Win32FindStreamData
    {
        public long StreamSize;

        // MAX_PATH + 36 UTF-16 characters, as specified by Win32.
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
        public string StreamName;
    }

    [DllImport("kernel32.dll", EntryPoint = "FindFirstStreamW", CharSet = CharSet.Unicode,
        SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr FindFirstStream(string fileName, int infoLevel,
        out Win32FindStreamData findStreamData, int flags);

    [DllImport("kernel32.dll", EntryPoint = "FindNextStreamW", CharSet = CharSet.Unicode,
        SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindNextStream(IntPtr findHandle,
        out Win32FindStreamData findStreamData);

    [DllImport("kernel32.dll", EntryPoint = "FindClose", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindClose(IntPtr findHandle);

    internal static void RejectUnsupportedStreams(string filePath, bool isDirectory = false)
        =>Inspect(filePath,isDirectory);

    internal static long? Inspect(string filePath,bool isDirectory=false,bool allowZoneIdentifier=false)
    {
        if (!OperatingSystem.IsWindows()) return null;
        long? zoneLength=null;

        IntPtr handle = FindFirstStream(WindowsNativePath.FromPath(filePath), FindStreamInfoStandard,
            out Win32FindStreamData data, 0);
        if (handle == InvalidFindHandle)
        {
            int code = Marshal.GetLastWin32Error();
            // Unlike a file, a directory has no unnamed stream by default.
            // Win32 reports EOF when a directory has no named data streams.
            if (isDirectory && code == ErrorHandleEof) return null;
            throw new IOException("Cannot enumerate file streams; refusing an incomplete backup " +
                $"of '{filePath}' (Win32 error {code}).");
        }

        try
        {
            while (true)
            {
                // The default unnamed stream is part of the file's normal data.
                // Every other named or non-$DATA stream is unsupported by v2.
                if(allowZoneIdentifier&&!isDirectory&&string.Equals(data.StreamName,WindowsZoneIdentifier.StreamName,StringComparison.OrdinalIgnoreCase))
                {
                    if(zoneLength is not null)throw new IOException("Duplicate Zone.Identifier stream.");
                    zoneLength=data.StreamSize;
                }
                else if (!string.Equals(data.StreamName, "::$DATA", StringComparison.Ordinal))
                    throw new IOException("Backup refuses a file with an unsupported NTFS " +
                        $"alternate stream: '{filePath}'. Stream={data.StreamName}");

                if (FindNextStream(handle, out data)) continue;
                int error = Marshal.GetLastWin32Error();
                if (error is ErrorHandleEof or ErrorNoMoreFiles) return zoneLength;
                throw new IOException("NTFS stream enumeration failed; refusing an " +
                    $"incomplete backup of '{filePath}' (Win32 error {error}).");
            }
        }
        finally
        {
            FindClose(handle);
        }
    }
}
