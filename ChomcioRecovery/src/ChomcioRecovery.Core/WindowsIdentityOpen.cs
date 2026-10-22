using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Text;

namespace ChomcioRecovery.Core;

// NTFS refuses parent-directory renames while descendant handles were opened
// by name, even with SHARE_DELETE. ID opens retain the same physical object
// without that name dependency. Never truncate a nonzero high 64-bit ID.
internal static class WindowsIdentityOpen
{
    [StructLayout(LayoutKind.Sequential)] private struct Descriptor
    { internal uint Size; internal int Type; internal ulong Low; internal ulong High; }
    [DllImport("kernel32.dll",SetLastError=true)]
    private static extern SafeFileHandle OpenFileById(SafeFileHandle hint,ref Descriptor descriptor,uint access,uint share,IntPtr security,uint flags);
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,StringBuilder path,uint length,uint flags);
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
    internal static SafeFileHandle Open(SafeFileHandle hint,uint access,uint share,uint flags)
    {
        var expected=WindowsSourceFileIdentity.Capture(hint);
        var descriptor=new Descriptor{Size=24,Type=expected.FileIdHigh==0?0:2,Low=expected.FileIdLow,High=expected.FileIdHigh};
        var result=OpenFileById(hint,ref descriptor,access,share,IntPtr.Zero,flags);
        if(result.IsInvalid&&Marshal.GetLastWin32Error()==50)
        {
            // Retry using an actual volume-root directory as the documented
            // volume hint. Keep the full ID and exact access/share restrictions.
            result.Dispose();
            var path=new StringBuilder(32768);
            uint count=GetFinalPathNameByHandle(hint,path,(uint)path.Capacity,1);
            string physical=count is >0 and <32768?path.ToString():"";
            int end=physical.IndexOf("}\\",StringComparison.Ordinal);
            if(!physical.StartsWith(@"\\?\Volume{",StringComparison.Ordinal)||end<0)
                throw new IOException("Cannot establish identity-bound volume root.");
            using var volume=CreateFile(physical[..(end+2)],0x80,7,IntPtr.Zero,3,0x02000000,IntPtr.Zero);
            if(volume.IsInvalid)throw new IOException("Cannot open identity-bound volume root.",new Win32Exception(Marshal.GetLastWin32Error()));
            result=OpenFileById(volume,ref descriptor,access,share,IntPtr.Zero,flags);
        }
        if(result.IsInvalid){int code=Marshal.GetLastWin32Error();result.Dispose();throw new IOException("Cannot retain physical file identity (Win32 "+code+").",new Win32Exception(code));}
        try { if(WindowsSourceFileIdentity.Capture(result)!=expected)throw new IOException("Physical file identity changed while opening by ID.");return result; }
        catch {result.Dispose();throw;}
    }
}
