using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace ChomcioRecovery.SystemImages;

internal static class NativeVolumes
{
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetVolumeNameForVolumeMountPoint(string mount,StringBuilder name,int length);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetVolumeInformation(string root,StringBuilder label,int labelLength,
        out uint serial,out uint maximumComponent,out uint flags,StringBuilder filesystem,int filesystemLength);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetDiskFreeSpaceEx(string root,out ulong available,out ulong total,out ulong free);
    internal static string SystemVolume()
    {
        var name=new StringBuilder(128);
        if(!GetVolumeNameForVolumeMountPoint(Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))!,name,name.Capacity))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return name.ToString();
    }
    internal static void Check(ImagePlan plan)
    {
        BrokerFiles.Validate(plan);
        if(!plan.SourceVolume.Equals(SystemVolume(),StringComparison.OrdinalIgnoreCase))throw new IOException("System volume changed.");
        var label=new StringBuilder(261);var fs=new StringBuilder(261);
        if(!GetVolumeInformation(plan.TargetVolume,label,label.Capacity,out _,out _,out _,fs,fs.Capacity)||fs.ToString()!="NTFS")
            throw new IOException("Approved NTFS target is unavailable.");
        BrokerFiles.RequireProtected(plan.TargetVolume);
        if(!GetDiskFreeSpaceEx(plan.SourceVolume,out _,out var sourceTotal,out var sourceFree)||
            !GetDiskFreeSpaceEx(plan.TargetVolume,out var targetFree,out _,out _))throw new IOException("Cannot check volume capacity.");
        ulong used=sourceTotal-sourceFree;
        // Native image plus compressed export; retain all older captures.
        if(targetFree<checked(used*2+4UL*1024*1024*1024))throw new IOException("Insufficient space; older images were retained.");
    }
}
