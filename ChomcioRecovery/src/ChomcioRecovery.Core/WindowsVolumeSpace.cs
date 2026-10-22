using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace ChomcioRecovery.Core;

// DriveInfo rejects volume-GUID and extended paths used by approved image plans.
// Query the actual existing destination with Win32, without mapping a drive
// letter, changing ACLs, or substituting the current/boot volume on failure.
[SupportedOSPlatform("windows")]
internal static class WindowsVolumeSpace
{
    [DllImport("kernel32.dll", EntryPoint="GetVolumePathNameW", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumePathName(string path, StringBuilder root, uint capacity);

    [DllImport("kernel32.dll", EntryPoint="GetVolumeInformationW", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformation(string root, IntPtr volumeName, uint volumeCapacity,
        IntPtr serial, IntPtr componentLength, IntPtr flags, StringBuilder fileSystem, uint capacity);

    [DllImport("kernel32.dll", EntryPoint="GetDiskFreeSpaceExW", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetDiskFreeSpaceEx(string directory, out ulong available, out ulong total, out ulong free);

    private static string ExistingDirectory(string path)
    {
        string full=Path.GetFullPath(path);
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException("Destination volume directory unavailable.");
        return Path.TrimEndingDirectorySeparator(full)+Path.DirectorySeparatorChar;
    }

    internal static string FileSystem(string existingDirectory)
    {
        string directory=ExistingDirectory(existingDirectory);
        // An extra terminator/backslash avoids GetVolumePathName's truncated-root
        // behavior. See Microsoft fileapi GetVolumePathNameW documentation.
        var root=new StringBuilder(Math.Max(261,checked(directory.Length+2)));
        if (!GetVolumePathName(directory,root,(uint)root.Capacity))
            throw Error("Cannot determine destination volume.");
        if (root.Length==0 || root[^1]!='\\') throw new IOException("Destination volume root is incomplete.");
        var fileSystem=new StringBuilder(261);
        if (!GetVolumeInformation(root.ToString(),IntPtr.Zero,0,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,fileSystem,(uint)fileSystem.Capacity))
            throw Error("Cannot determine destination filesystem.");
        return fileSystem.ToString();
    }

    internal static long AvailableBytes(string existingDirectory)
    {
        // Available-to-caller respects quotas. Never substitute total free space.
        if (!GetDiskFreeSpaceEx(ExistingDirectory(existingDirectory),out ulong available,out _,out _))
            throw Error("Cannot determine available destination space.");
        return available>long.MaxValue ? long.MaxValue : (long)available;
    }

    private static IOException Error(string message) => new(message,new Win32Exception(Marshal.GetLastWin32Error()));
}
