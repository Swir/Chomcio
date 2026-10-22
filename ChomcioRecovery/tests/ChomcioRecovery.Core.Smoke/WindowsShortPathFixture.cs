using System.Runtime.InteropServices;
using System.Text;

internal static class WindowsShortPathFixture
{
    [DllImport("kernel32.dll", EntryPoint = "GetShortPathNameW", CharSet = CharSet.Unicode,
        ExactSpelling = true, SetLastError = true)]
    private static extern uint GetShortPathName(string full, StringBuilder output, uint outputCapacity);

    internal static string? TryGetShortPath(string path)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var output = new StringBuilder(32_768);
        uint written = GetShortPathName(Path.GetFullPath(path), output, (uint)output.Capacity);
        if (written == 0 || written >= (uint)output.Capacity) return null;
        string shortPath = output.ToString();
        if (!Directory.Exists(shortPath) ||
            string.Equals(Path.GetFullPath(shortPath), Path.GetFullPath(path),
                StringComparison.OrdinalIgnoreCase))
            return null; // 8.3 aliases disabled on this volume: do not claim PASS.
        return shortPath;
    }
}
