using System.ComponentModel;
using System.Runtime.InteropServices;

internal static class WindowsHardLinkFixture
{
    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode,
        SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string newName, string existingName, nint reserved);

    internal static void Create(string newName, string existingName)
    {
        if (!CreateHardLink(newName, existingName, 0))
            throw new IOException("NTFS hard-link test fixture could not be created.",
                new Win32Exception(Marshal.GetLastWin32Error()));
    }
}
