using ChomcioRecovery.SystemImages;

namespace ChomcioRecovery.Desktop;

// Large native exports, encrypted vaults and upload stages must remain outside
// the captured system volume. Settings and DPAPI secrets may remain in AppData.
internal static class SystemImageStorage
{
    internal static string Repository(string cacheRoot,string profileId)
    {
        if(!BrokerFiles.IsId(profileId))throw new InvalidDataException("Niepoprawny identyfikator kopii.");
        return Path.Combine(Path.GetFullPath(cacheRoot),"vaults",profileId);
    }
    internal static bool SamePath(string a,string b)=>Path.TrimEndingDirectorySeparator(Path.GetFullPath(a))
        .Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(b)),StringComparison.OrdinalIgnoreCase);
    internal static void ValidateShape(BackupProfile profile)
    {
        if(profile.Content!=BackupContent.WindowsSystem||!BrokerFiles.IsId(profile.Id)||
            profile.SystemImageCacheRoot is not {Length:>0} cache||!Path.IsPathFullyQualified(cache)||
            !Path.IsPathFullyQualified(profile.Repository)||!SamePath(profile.Repository,Repository(cache,profile.Id)))
            throw new InvalidDataException("Kopia Windows wymaga osobnego miejsca roboczego zatwierdzonego w konfiguracji modułu.");
        StudioStore.RejectLinks(cache);StudioStore.RejectLinks(profile.Repository);
    }
    internal static void ValidateApproved(BackupProfile profile,ImagePlan plan)
    {
        ValidateShape(profile);BrokerFiles.Validate(plan);
        if(profile.SystemImagePlanId!=plan.PlanId||!SamePath(profile.SystemImageCacheRoot!,BrokerFiles.ClientDirectory(plan)))
            throw new InvalidDataException("Miejsce robocze kopii Windows nie należy do zatwierdzonego dysku. Nie rozpoczęto kopii.");
    }
    internal static string TransferDirectory(StudioStore store,BackupProfile profile,string operationId)
    {
        if(!BrokerFiles.IsId(operationId)||!BrokerFiles.IsId(profile.Id))throw new InvalidDataException("Niepoprawna tożsamość wysyłania.");
        if(profile.Content==BackupContent.WindowsSystem)ValidateShape(profile);
        string root=profile.Content==BackupContent.WindowsSystem?profile.SystemImageCacheRoot!:store.Root;
        string path=Path.Combine(root,"transfers",profile.Id,operationId);
        StudioStore.RejectLinks(path);return path;
    }
}
