using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace ChomcioRecovery.Core;

// Only the Windows download-origin stream is supported. All other named
// streams still fail closed. Bytes are authenticated inside a v3 manifest.
internal static class WindowsZoneIdentifier
{
    internal const string StreamName=":Zone.Identifier:$DATA";
    internal const int MaximumBytes=65_536;
    internal static int Validate(string? encoded)
    {
        if(encoded is null)return 0;
        if(encoded.Length>((MaximumBytes+2)/3)*4)throw new InvalidDataException("Zone.Identifier exceeds limit.");
        byte[] bytes;
        try{bytes=Convert.FromBase64String(encoded);}
        catch(FormatException e){throw new InvalidDataException("Invalid Zone.Identifier metadata.",e);}
        try
        {
            if(bytes.Length>MaximumBytes||Convert.ToBase64String(bytes)!=encoded)
                throw new InvalidDataException("Invalid Zone.Identifier metadata.");
            return bytes.Length;
        }
        finally{CryptographicOperations.ZeroMemory(bytes);}
    }
    internal static string? Read(string path,CancellationToken token=default)
    {
        token.ThrowIfCancellationRequested();
        long? length=WindowsAlternateStreamGuard.Inspect(path,allowZoneIdentifier:true);
        if(length is null)return null;
        if(length.Value is <0 or >MaximumBytes)throw new InvalidDataException("Zone.Identifier exceeds limit.");
        using var owner=WindowsNoFollowSourceReader.Open(path,allowDeleteSharing:true);
        var identity=WindowsSourceFileIdentity.Capture(owner);
        using var input=WindowsNoFollowSourceReader.Open(path+StreamName,allowDeleteSharing:true);
        WindowsSourceFileIdentity.RequireMatches(input,identity,path);
        if(input.Length!=length.Value)throw new IOException("Zone.Identifier changed during read.");
        byte[] bytes=new byte[checked((int)length.Value)];
        try
        {
            for(int offset=0;offset<bytes.Length;)
            {
                token.ThrowIfCancellationRequested();int read=input.Read(bytes,offset,Math.Min(8192,bytes.Length-offset));
                if(read==0)throw new IOException("Zone.Identifier changed during read.");offset+=read;
            }
            token.ThrowIfCancellationRequested();
            if(input.ReadByte()!=-1||input.Length!=bytes.Length)throw new IOException("Zone.Identifier changed during read.");
            WindowsSourceFileIdentity.RequireMatches(input,identity,path);
            return Convert.ToBase64String(bytes);
        }
        finally{CryptographicOperations.ZeroMemory(bytes);}
    }
    internal static string? Fingerprint(string? encoded)
    {
        if(encoded is null)return null;
        byte[] bytes=Convert.FromBase64String(encoded);
        try{return Convert.ToHexString(SHA256.HashData(bytes));}
        finally{CryptographicOperations.ZeroMemory(bytes);}
    }
    internal static void Verify(string path,string? expected,CancellationToken token=default)
    {
        if(expected is null){WindowsAlternateStreamGuard.RejectUnsupportedStreams(path);return;}
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException("Restoring Zone.Identifier requires Windows and NTFS.");
        Validate(expected);
        if(Read(path,token)!=expected)throw new InvalidDataException("Restored Zone.Identifier differs from authenticated metadata.");
    }
    internal static void WriteOwned(string path,SafeFileHandle originalWriter,string? encoded,CancellationToken token)
    {
        if(encoded is null)return;
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException("Restoring Zone.Identifier requires Windows and NTFS.");
        Validate(encoded);token.ThrowIfCancellationRequested();
        var expectedId=WindowsSourceFileIdentity.Capture(originalWriter);
        // Original exclusive default-stream writer and pinned parent remain
        // open. A stream must belong to that same FILE_ID before bytes land.
        using var output=new FileStream(path+StreamName,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough);
        if(WindowsSourceFileIdentity.Capture(output)!=expectedId)throw new IOException("Zone.Identifier writer changed file identity.");
        byte[] bytes=Convert.FromBase64String(encoded);
        try
        {
            for(int offset=0;offset<bytes.Length;offset+=8192)
            {token.ThrowIfCancellationRequested();output.Write(bytes.AsSpan(offset,Math.Min(8192,bytes.Length-offset)));}
            output.Flush(true);token.ThrowIfCancellationRequested();
            if(WindowsSourceFileIdentity.Capture(output)!=expectedId)throw new IOException("Zone.Identifier writer changed file identity.");
        }
        finally{CryptographicOperations.ZeroMemory(bytes);}
    }
}
