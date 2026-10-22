using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using System.Security.Principal;

namespace ChomcioRecovery.Core;

/// <summary>
/// Plaintext restore staging must NOT inherit a public destination parent's ACL.
/// The Windows path is created in ONE native operation with a protected DACL:
/// current account, SYSTEM and Administrators only (inheritable by children).
/// NTFS/ReFS only; filesystem without enforceable ACLs is rejected, not silently
/// downgraded. This is not a defense against a malicious same-user process that
/// can change the DACL or replace filesystem entries while restore is running.
/// </summary>
internal static class PrivateRestoreStage
{
    private const uint SddlRevision1 = 1;
    private const uint DaclSecurityInformation = 0x00000004;
    private const ushort SeDaclPresent = 0x0004;
    private const ushort SeDaclProtected = 0x1000;

    [DllImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string sddl, uint revision, out IntPtr descriptor, IntPtr descriptorSize);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr LocalFree(IntPtr address);

    [DllImport("advapi32.dll", EntryPoint = "GetKernelObjectSecurity", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetKernelObjectSecurity(SafeFileHandle handle,
        uint requestedInformation, byte[]? descriptor, uint descriptorSize,
        out uint requiredLength);

    [DllImport("advapi32.dll", EntryPoint = "GetFileSecurityW", CharSet = CharSet.Unicode,
        ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileSecurity(string name, uint information, byte[]? buffer,
        uint length, out uint needed);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorControl(
        byte[] descriptor, out ushort control, out uint revision);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorDacl(byte[] descriptor,
        [MarshalAs(UnmanagedType.Bool)] out bool present, out IntPtr acl,
        [MarshalAs(UnmanagedType.Bool)] out bool defaulted);

    // Legacy helper for isolated fixtures only. Production must use CreateOwned
    // and carry the creation-pinned stage guard through restore/export.
    internal static string Create(string existingParent, string prefix,
        Action<string>? afterWindowsCreateBeforeValidation = null)
    {
        var owned = CreateOwned(existingParent, prefix, afterWindowsCreateBeforeValidation);
        owned.Guard.Dispose();
        return owned.Stage;
    }

    internal static (string Stage, WindowsPrivateRestoreStageGuard Guard) CreateOwned(
        string existingParent, string prefix,
        Action<string>? afterWindowsCreateBeforeValidation = null)
    {
        string parent = Path.GetFullPath(existingParent);
        if (!Directory.Exists(parent))
            throw new DirectoryNotFoundException("Private restore stage requires an existing parent.");
        if (!prefix.StartsWith(".chomcio-", StringComparison.Ordinal) || prefix.Contains('/') || prefix.Contains('\\'))
            throw new ArgumentException("Invalid private stage prefix.", nameof(prefix));

        string stage = Path.Combine(parent, prefix + Guid.NewGuid().ToString("N"));
        WindowsPrivateRestoreStageGuard? originalGuard = null;
        if (OperatingSystem.IsWindows())
        {
            string filesystem = WindowsVolumeSpace.FileSystem(parent);
            if (!filesystem.Equals("NTFS", StringComparison.OrdinalIgnoreCase) &&
                !filesystem.Equals("ReFS", StringComparison.OrdinalIgnoreCase))
                throw new IOException("Private restore staging requires NTFS/ReFS ACLs; volume is " + filesystem);
            // Root FILE_CREATE returns an ORIGINAL retained handle. The source
            // identity is pinned before its handle is released, so the first
            // managed guard cannot adopt a swapped same-user directory.
            originalGuard = CreateWindowsProtectedDirectory(stage,
                afterWindowsCreateBeforeValidation);
        }
        else
        {
            Directory.CreateDirectory(stage,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            UnixFileMode actual = File.GetUnixFileMode(stage);
            UnixFileMode other = UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                UnixFileMode.GroupExecute | UnixFileMode.OtherRead |
                UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
            if ((actual & other) != 0)
            {
                Directory.Delete(stage); // Nothing has been written yet.
                throw new IOException("Restore staging directory was not created with private permissions.");
            }
        }
        return (stage, originalGuard ?? WindowsPrivateRestoreStageGuard.Acquire(stage));
    }

    /// <summary>
    /// Create staged child directories one component at a time. A default
    /// CreateDirectory(path) uses the process umask on Unix: with umask 000,
    /// every nested folder becomes 0777 and RETAINS that mode after publish.
    /// The restore stage root itself is private, but nested content and folder
    /// names must remain private after publication as well. On Windows the
    /// protected inheritable DACL from Create() applies to new children.
    /// Refuse unexpected pre-existing permissive directories rather than
    /// silently changing their permissions or writing plaintext into them.
    /// Not intended as protection from a hostile same-user process racing
    /// filesystem operations; true handle-based isolation remains pending.
    /// </summary>
    internal static void CreatePrivateSubdirectory(string stageRoot, string requiredDirectory,
        Action<string, SafeFileHandle>? onCreatedOwned = null,
        Func<string, IDisposable>? pinKnownParent = null)
    {
        string root = Path.GetFullPath(stageRoot);
        string target = Path.GetFullPath(requiredDirectory);
        string relative = Path.GetRelativePath(root, target);
        if (Path.IsPathRooted(relative) || relative == ".." ||
            relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new InvalidDataException("Private restore directory escapes staging root.");
        const UnixFileMode privateMode = UnixFileMode.UserRead |
            UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        const UnixFileMode sharedMode = UnixFileMode.GroupRead |
            UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
            UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

        static void CheckPrivateDirectory(string path, UnixFileMode publicBits)
        {
            FileAttributes attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.Directory) == 0 ||
                (attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Non-directory or reparse point inside private restore stage: " + path);
            if (!OperatingSystem.IsWindows() && (File.GetUnixFileMode(path) & publicBits) != 0)
                throw new IOException("Insecure permissions inside private restore stage: " + path);
        }

        // Optional native owned-tree contract: trust the ORIGINAL FileIds,
        // not just a private-looking directory reopened by pathname.
        using var rootLease = pinKnownParent?.Invoke(root);
        CheckPrivateDirectory(root, sharedMode);
        if (relative == ".") return;
        string cursor = root;
        foreach (string component in relative.Split(Path.DirectorySeparatorChar))
        {
            cursor = Path.Combine(cursor, component);
            // Retain the original, FileId-checked parent until creation (or
            // validation of an existing child) has finished. Missing tracked
            // ownership fails closed rather than disclosing staged file names.
            using var parentLease = pinKnownParent?.Invoke(Path.GetDirectoryName(cursor)!);
            if (!Directory.Exists(cursor))
            {
                if (File.Exists(cursor))
                    throw new IOException("File blocks staged directory: " + cursor);
                if (OperatingSystem.IsWindows())
                {
                    // Hold the original parent and its ancestors while creating
                    // and recording a child. Only newly created directories are
                    // eligible for owned failure cleanup; pre-existing, foreign
                    // or substituted entries are NEVER adopted for deletion.
                    using var parentPin = WindowsRestoreParentPin.Acquire(Path.GetDirectoryName(cursor)!);
                    parentPin.RequireMatches();
                    // NtCreateFile(FILE_CREATE|FILE_DIRECTORY_FILE) returns the
                    // ORIGINAL directory handle; callback captures its FileId
                    // while deletion/rename sharing is still denied. Never
                    // adopt a different pathname entry after creation.
                    WindowsAtomicStageChildCreator.Create(
                        Path.GetDirectoryName(cursor)!, Path.GetFileName(cursor),
                        (created, creator) =>
                        {
                            CheckPrivateDirectory(created, sharedMode);
                            onCreatedOwned?.Invoke(created, creator);
                        });
                    parentPin.RequireMatches();
                }
                else
                    Directory.CreateDirectory(cursor, privateMode);
            }
            // Even a pre-existing real directory with a private ACL might be
            // a substituted or untracked object. Require original FileId now,
            // while the pinned parent prevents a concurrent rename.
            using var ownedChildLease = pinKnownParent?.Invoke(cursor);
            CheckPrivateDirectory(cursor, sharedMode);
        }
    }

    internal static void RestrictRestoredFileOnUnix(string path)
    {
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    [SupportedOSPlatform("windows")]
    private static WindowsPrivateRestoreStageGuard CreateWindowsProtectedDirectory(
        string path, Action<string>? afterWindowsCreateBeforeValidation)
    {
        string sid = WindowsIdentity.GetCurrent().User?.Value
            ?? throw new IOException("Cannot establish Windows account for restore ACL.");
        if (!sid.StartsWith("S-1-", StringComparison.Ordinal))
            throw new IOException("Invalid Windows account SID.");

        // Protected DACL is applied during NT FILE_CREATE, not after publication.
        // OICI applies the same private ACL to staged descendants.
        string sddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + sid + ")";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                sddl, SddlRevision1, out IntPtr descriptor, IntPtr.Zero))
            throw WindowsError("Cannot construct private restore ACL");
        try
        {
            WindowsPrivateRestoreStageGuard? pinned = null;
            try
            {
                string parent = Path.GetDirectoryName(path)
                    ?? throw new IOException("Protected restore stage lacks a parent.");
                string leaf = Path.GetFileName(path);
                using var ancestorPins = WindowsRestoreParentPin.Acquire(parent);
                ancestorPins.RequireMatches();
                WindowsAtomicStageChildCreator.CreateProtectedRoot(
                    parent, leaf, descriptor, (created, creator) =>
                    {
                        // Query security from the exact ORIGINAL NT-created
                        // FILE_OBJECT, never from a replaceable pathname.
                        AssertWindowsProtectedDacl(creator);
                        pinned = WindowsPrivateRestoreStageGuard.AcquireFromOriginalCreation(
                            created, creator);
                        // Only native smoke callers supply this hostile callback.
                        // It must run while creator denies DELETE sharing.
                        afterWindowsCreateBeforeValidation?.Invoke(created);
                        pinned.RequireMatches(created);
                        ancestorPins.RequireMatches();
                    });
                return pinned ?? throw new IOException("Original root stage ownership was not captured.");
            }
            catch
            {
                pinned?.Dispose();
                // The stage may be empty and private, but its pathname is not
                // proof of ownership after failure: NO path-based deletion.
                throw;
            }
        }
        finally { LocalFree(descriptor); }
    }

    [SupportedOSPlatform("windows")]
    private static void AssertWindowsProtectedDacl(SafeFileHandle created)
    {
        // Must have READ_CONTROL on the original creation handle.
        GetKernelObjectSecurity(created, DaclSecurityInformation, null, 0,
            out uint needed);
        if (needed == 0 || needed > 65_536)
            throw WindowsError("Cannot inspect original stage security descriptor");
        byte[] descriptor = new byte[needed];
        if (!GetKernelObjectSecurity(created, DaclSecurityInformation, descriptor,
                (uint)descriptor.Length, out _))
            throw WindowsError("Cannot read original stage security descriptor");
        if (!GetSecurityDescriptorControl(descriptor, out ushort control, out _) ||
            (control & (SeDaclProtected | SeDaclPresent)) != (SeDaclProtected | SeDaclPresent) ||
            !GetSecurityDescriptorDacl(descriptor, out bool present, out IntPtr acl, out _) ||
            !present || acl == IntPtr.Zero)
            throw new IOException("Original stage DACL is absent or not protected.");
    }

    [SupportedOSPlatform("windows")]
    internal static void AssertWindowsProtectedDacl(string directory)
    {
        GetFileSecurity(WindowsNativePath.FromPath(directory), DaclSecurityInformation, null, 0, out uint needed);
        if (needed == 0 || needed > 65_536)
            throw WindowsError("Cannot inspect new restore-stage ACL");
        byte[] descriptor = new byte[needed];
        if (!GetFileSecurity(WindowsNativePath.FromPath(directory), DaclSecurityInformation, descriptor,
                (uint)descriptor.Length, out _))
            throw WindowsError("Cannot read new restore-stage ACL");
        if (!GetSecurityDescriptorControl(descriptor, out ushort control, out _) ||
            (control & (SeDaclProtected | SeDaclPresent)) != (SeDaclProtected | SeDaclPresent) ||
            !GetSecurityDescriptorDacl(descriptor, out bool present, out IntPtr acl, out _) ||
            !present || acl == IntPtr.Zero)
            throw new IOException("Restore-stage ACL is missing, unprotected or allows all users.");
    }

    private static IOException WindowsError(string message)
    {
        int code = Marshal.GetLastWin32Error();
        return new IOException(message + " (Win32 " + code + ").", new Win32Exception(code));
    }
}
