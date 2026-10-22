using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using ChomcioRecovery.SystemImages;

namespace ChomcioRecovery.Desktop;

internal sealed record SystemImagePlanChoice(string Id, string CacheRoot, string Description="Windows i partycje startowe")
{
    public override string ToString() => Description;
}

internal interface ISystemImagePlanCatalog
{
    IReadOnlyList<SystemImagePlanChoice> List();
    void Validate(BackupProfile profile);
}

// Discovery is read-only. A profile can select an enrolled plan, but cannot
// enroll a disk, provide an elevated command, or change its approved volumes.
internal sealed class InstalledSystemImagePlans : ISystemImagePlanCatalog
{
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeNameForVolumeMountPoint(string root,StringBuilder volume,int length);
    private static string Describe(ImagePlan plan)
    {
        foreach(var drive in DriveInfo.GetDrives())
        {
            try
            {
                if(drive.DriveType!=DriveType.Fixed||!drive.IsReady)continue;
                var volume=new StringBuilder(64);
                if(GetVolumeNameForVolumeMountPoint(drive.Name,volume,volume.Capacity)&&
                    volume.ToString().Equals(plan.TargetVolume,StringComparison.OrdinalIgnoreCase))
                    return "Windows · dysk roboczy "+drive.Name.TrimEnd('\\')+" "+drive.VolumeLabel;
            }
            catch(Exception e)when(e is IOException or UnauthorizedAccessException){ }
        }
        return "Windows · podłącz zatwierdzony dysk roboczy";
    }
    public IReadOnlyList<SystemImagePlanChoice> List()
    {
        string root = Path.Combine(BrokerFiles.Root, "plans");
        if (!Directory.Exists(root)) return Array.Empty<SystemImagePlanChoice>();
        BrokerFiles.RequireProtected(root);
        string owner = WindowsIdentity.GetCurrent().User!.Value;
        var result = new List<SystemImagePlanChoice>();
        int count=0;
        foreach (string directory in Directory.EnumerateDirectories(root).Take(129))
        {
            if(++count>128)throw new InvalidDataException("Zbyt wiele planów Windows.");
            if (!BrokerFiles.IsId(Path.GetFileName(directory)))
                throw new InvalidDataException("Niepoprawna konfiguracja modułu systemowego.");
            ImagePlan plan;
            try
            {
                string path = Path.Combine(directory, "plan.json");
                BrokerFiles.RequireProtected(path);
                plan = BrokerFiles.Read<ImagePlan>(path);
            }
            catch (UnauthorizedAccessException) { continue; } // Other users' plans are private.
            BrokerFiles.Validate(plan);
            if (plan.PlanId != Path.GetFileName(directory))
                throw new InvalidDataException("Niepoprawna tożsamość planu Windows.");
            if (plan.OwnerSid == owner) result.Add(new(plan.PlanId, BrokerFiles.ClientDirectory(plan),Describe(plan)));
        }
        return result.OrderBy(p => p.Id, StringComparer.Ordinal).ToArray();
    }

    public void Validate(BackupProfile profile) => new InstalledSystemImageCapture().ValidateStorage(profile);
}

internal static class SystemImageProfiles
{
    internal static void SelectNewPlan(BackupProfile profile, SystemImagePlanChoice plan)
    {
        if (!BrokerFiles.IsId(plan.Id) || !Path.IsPathFullyQualified(plan.CacheRoot) ||
            profile.PendingSystemImage is not null || profile.PendingSnapshot is not null ||
            profile.LastSnapshot is not null || profile.LastSuccess is not null)
            throw new InvalidDataException("Nie można zmienić planu istniejącej kopii Windows.");
        profile.Content = BackupContent.WindowsSystem;
        profile.Source = "";
        profile.SystemImagePlanId = plan.Id;
        profile.SystemImageCacheRoot = plan.CacheRoot;
        profile.Repository = SystemImageStorage.Repository(plan.CacheRoot, profile.Id);
        SystemImageStorage.ValidateShape(profile);
    }
}
