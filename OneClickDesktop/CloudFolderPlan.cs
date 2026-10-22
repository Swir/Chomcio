using System.Globalization;
using ChomcioRecovery.Chomikuj;

namespace ChomcioRecovery.Desktop;

internal static class CloudFolderPlan
{
    internal static string Day(DateTimeOffset now)=>now.ToString("yyyy-MM-dd",CultureInfo.InvariantCulture);
    internal static DateOnly? FolderDate(string name)=>name.StartsWith("Chomciore_",StringComparison.Ordinal)&&name.Length>=20&&
        DateOnly.TryParseExact(name.Substring(10,10),"dd_MM_yyyy",CultureInfo.InvariantCulture,DateTimeStyles.None,out var day)?day:null;
    internal static bool CanReplaceUnconfirmed(BackupProfile profile)=>profile.PendingSnapshot is not null&&
        (profile.CloudDateFolders?!profile.RemoteFolderHasConfirmedCopy:profile.LastSuccess is null&&profile.LastSnapshot is null);
    internal static string Name(string day,string profileId,IEnumerable<ChomikujFolder> existing)
    {
        if(!DateOnly.TryParseExact(day,"yyyy-MM-dd",CultureInfo.InvariantCulture,DateTimeStyles.None,out var date)||
            !Guid.TryParseExact(profileId,"N",out _))throw new ArgumentException("Niepoprawna data lub zadanie kopii.");
        string stem="Chomciore_"+date.ToString("dd_MM_yyyy",CultureInfo.InvariantCulture);
        var names=existing.Select(f=>f.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if(!names.Contains(stem))return stem;
        string suffix=stem+"_"+profileId[..8];
        if(!names.Contains(suffix))return suffix;
        for(int attempt=2;attempt<=1000;attempt++)
            if(!names.Contains(suffix+"_"+attempt))return suffix+"_"+attempt;
        throw new IOException("Zbyt wiele folderów z tą samą datą. Zachowano wszystkie kopie.");
    }
    internal static IEnumerable<UnconfirmedCloudFolder> All(BackupProfile profile)
    {
        var folders=profile.ArchivedCloudFolders.AsEnumerable();
        if(profile.RemoteFolderId is not null&&profile.RemoteFolderName is not null)
            folders=folders.Append(new(profile.RemoteFolderId,profile.RemoteFolderName));
        return folders.DistinctBy(f=>f.Id);
    }
}
