using ChomcioRecovery.Chomikuj;
using ChomcioRecovery.Core;
using System.Net;
using System.Text;
using System.Xml.Linq;
using System.Text.Json;

internal static class FolderProtocolRegressions
{
    internal static async Task Run(Action<bool, string> check, Func<Func<Task>, string, Task> fails,
        string repository, string password, string snapshot, Func<string, string> newPath)
    {
        using var handler = new FolderServer { InexactSoapSize = true, StaleListUrls = true, RejectHead = true };
        using var client = new ChomikujClient(handler);
        await client.LoginAsync("synthetic-user", "test-password", default);
        var folder = await client.CreateFolderAsync("ChomcioRecovery_TestFresh", default);
        var cloud = client.OpenFolder(folder);
        check((await client.ListFoldersAsync(default)).Single().Id == folder.Id, "depth 2 returns child folders");
        check((await cloud.ListAsync(default)).Count == 0, "known new empty folder tolerates exact unavailable response");
        check(handler.FolderRequests.All(p => p == "/synthetic-user/ChomcioRecovery_TestFresh/"), "folder lookup uses canonical trailing slash");

        handler.Error = "Unknown";
        try { await cloud.ListAsync(default); throw new Exception("unknown failure incorrectly accepted"); }
        catch (ChomikujServiceException error)
        {
            check(error.Failure == ChomikujFailure.Rejected, "unknown errors stay failures in fresh folders");
            check(!error.ToString().Contains("sensitive-server-echo", StringComparison.Ordinal), "raw server text never enters diagnostics");
        }
        handler.Error = "SessionExpired";
        try { await cloud.ListAsync(default); throw new Exception("expired session incorrectly accepted"); }
        catch (ChomikujServiceException error) { check(error.Failure == ChomikujFailure.SessionRejected, "expired session classified separately"); }
        handler.Error = "MissingList";
        await fails(() => cloud.ListAsync(default), "missing list is not a valid empty response");
        handler.Error = "MalformedList";
        await fails(() => cloud.ListAsync(default), "unknown list structure is not a valid empty response");
        handler.Error = "";
        handler.HideFolder = true;
        await fails(() => cloud.ListAsync(default), "deleted or renamed new folder cannot be treated as empty");
        handler.HideFolder = false;
        await fails(() => cloud.DownloadAsync(new("42", "repo.json", 1), new MemoryStream(), 1, default),
            "missing individual file never treated as empty folder");

        // Run the encrypted engine through the actual SOAP/multipart adapter.
        // The fake service independently enforces folder depth and slash and
        // returns the legacy error for empty folders (not an invented OK list).
        var transfer = new CloudVaultTransfer(cloud);
        await transfer.UploadSnapshotAsync(repository, password, snapshot, newPath("soap-export"), null, default);
        check(handler.Stored.Count >= 4, "all encrypted records uploaded through real adapter");
        string downloaded = newPath("soap-download");
        await transfer.DownloadSnapshotAsync(snapshot, password, downloaded, null, default);
        using (var vault = LocalEncryptedVault.Open(downloaded, password)) vault.VerifySnapshot(snapshot);
        check(handler.Downloads >= handler.Stored.Count * 2, "uploaded records read back and independently downloaded");
        int uploads = handler.Uploads;
        handler.LegacyDownloadUrls = true;
        await transfer.UploadSnapshotAsync(repository, password, snapshot, newPath("soap-resume"), null, default);
        check(handler.Uploads == uploads, "SOAP listing supports resume without duplicate uploads");
        check(handler.AllRequestsHttps, "legacy download URLs upgraded before any request, never HTTP");
        var exactFiles = await cloud.ListAsync(default);
        check(exactFiles.All(f => f.Length == handler.Stored[f.Id].Bytes.Length), "HTTP byte lengths replace inexact SOAP metadata");
        check(handler.Heads == 0 && handler.StaleUrlRequests == 0,
            "fresh per-file GET works when directory URLs are stale and server rejects HEAD");
        var exactFile = exactFiles.First();
        handler.LengthAdjustment = 1;
        await fails(() => cloud.DownloadAsync(exactFile, new MemoryStream(), exactFile.Length, default), "HTTP length mismatch still rejected");
        handler.LengthAdjustment = 0;
        handler.BodyAdjustment = -1;
        await fails(() => cloud.DownloadAsync(exactFile, new MemoryStream(), exactFile.Length, default), "truncated body with correct declared length rejected");
        handler.BodyAdjustment = 1;
        await fails(() => cloud.DownloadAsync(exactFile, new MemoryStream(), exactFile.Length, default), "oversized body with correct declared length rejected");
        handler.BodyAdjustment = 0;
        handler.WrongFileName = true;
        await fails(() => cloud.DownloadAsync(exactFile, new MemoryStream(), exactFile.Length, default), "SOAP ID cannot select a different record name");
        handler.WrongFileName = false;
        handler.CorruptBody = true;
        await fails(() => transfer.UploadSnapshotAsync(repository, password, snapshot, newPath("soap-corrupt"), null, default),
            "inexact metadata never bypasses byte comparison during resume");
        handler.CorruptBody = false;
        check(handler.Uploads == uploads, "failed readback does not upload replacements");
        handler.Error = "Unavailable";
        await fails(() => cloud.ListAsync(default), "listing failure after upload cannot masquerade as empty folder");
        await fails(() => cloud.UploadAsync("other.obj", new MemoryStream(new byte[1]), 1, default), "ambiguous listing blocks another upload");
        check(handler.Uploads == uploads, "listing failure sends no extra file");
        handler.Error = "";

        int downloadsBefore=handler.Downloads;
        for(int n=0;n<50;n++)
        {
            byte[] data=Encoding.UTF8.GetBytes("synthetic performance "+n);
            await cloud.UploadAsync("performance"+n+".obj",new MemoryStream(data),data.Length,default);
        }
        check(handler.Downloads==downloadsBefore,"50-file conflict checks do not repeatedly download all earlier files");

        using var uncertainServer = new FolderServer { LoseUploadReply = true };
        using var uncertainClient = new ChomikujClient(uncertainServer);
        await uncertainClient.LoginAsync("synthetic-user", "test-password", default);
        var uncertainFolder = await uncertainClient.CreateFolderAsync("ChomcioRecovery_TestUncertain", default);
        var uncertainCloud = uncertainClient.OpenFolder(uncertainFolder);
        await fails(() => uncertainCloud.UploadAsync("repo.json", new MemoryStream(new byte[1]), 1, default), "lost upload response propagated");
        await fails(() => uncertainCloud.ListAsync(default), "lost reply revokes new-empty exception before send");

        using var reloginServer = new FolderServer();
        using var reloginClient = new ChomikujClient(reloginServer);
        await reloginClient.LoginAsync("synthetic-user", "test-password", default);
        var oldFolder = await reloginClient.CreateFolderAsync("ChomcioRecovery_TestOld", default);
        await reloginClient.LoginAsync("synthetic-user", "test-password", default);
        await fails(() => reloginClient.OpenFolder(oldFolder).ListAsync(default), "new-session listing ambiguity not assumed empty");
        check(handler.Agreements.All(a => a == "own") && !handler.SawCost, "no paid transfer agreement introduced");
        using var tlsServer = new FolderServer { SimulateTlsFailure = true };
        using var tlsClient = new ChomikujClient(tlsServer);
        var diagnostics = new SafeDiagnostics();
        tlsClient.Diagnostics = diagnostics;
        await tlsClient.LoginAsync("synthetic-user", "test-password", default);
        var tlsFolder = await tlsClient.CreateFolderAsync("ChomcioRecovery_TestTLS", default);
        try
        {
            await tlsClient.OpenFolder(tlsFolder).UploadAsync("repo.json", new MemoryStream(new byte[1]), 1, default);
            throw new Exception("TLS failure not reported");
        }
        catch (IOException error)
        {
            check(error.Message.Contains("SecureConnectionError", StringComparison.Ordinal), "TLS error category preserved");
            check(!error.ToString().Contains("sensitive-token", StringComparison.Ordinal), "transport exceptions never expose raw secret-bearing messages");
            check(diagnostics.Messages.Last() == "Wysyłanie HTTPS: https://upload.chomikuj.pl" &&
                diagnostics.Messages.All(line => !line.Contains("sensitive-token", StringComparison.Ordinal)), "diagnostic contains authority only");
        }
        foreach (string unsafeUrl in new[] { "http://upload.chomikuj.pl/web-upload", "https://attacker.invalid/web-upload" })
        {
            using var unsafeServer = new FolderServer { WebUploadUrl = unsafeUrl };
            using var unsafeClient = new ChomikujClient(unsafeServer);
            await unsafeClient.LoginAsync("synthetic-user", "test-password", default);
            var unsafeFolder = await unsafeClient.CreateFolderAsync("ChomcioRecovery_TestUnsafe", default);
            await fails(() => unsafeClient.OpenFolder(unsafeFolder).UploadAsync("repo.json", new MemoryStream(new byte[1]), 1, default),
                "website URL cannot downgrade TLS or send credentials/data outside Chomikuj");
            check(unsafeServer.Uploads == 0, "unsafe upload address receives no file");
        }
    }

    private sealed class SafeDiagnostics : IProgress<string>
    {
        internal List<string> Messages { get; } = new();
        public void Report(string value) => Messages.Add(value);
    }
}

internal sealed class FolderServer : HttpMessageHandler
{
    private const string Ns = "http://chomikuj.pl/";
    internal string Error = "";
    internal bool HideFolder, LoseUploadReply, SawCost, SimulateTlsFailure;
    internal bool LegacyDownloadUrls;
    internal bool InexactSoapSize, WrongFileName, CorruptBody;
    internal int LengthAdjustment, BodyAdjustment, Heads;
    internal bool StaleListUrls, RejectHead;
    internal int StaleUrlRequests;
    internal bool AllRequestsHttps = true;
    internal int Uploads, Downloads;
    internal string WebUploadUrl = "https://upload.chomikuj.pl/web-upload?key=sensitive-token";
    internal string? FolderName;
    internal List<string> FolderRequests { get; } = new();
    internal List<string> Agreements { get; } = new();
    internal Dictionary<string, (string Name, byte[] Bytes)> Stored { get; } = new();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        AllRequestsHttps &= request.RequestUri!.Scheme == "https";
        if (request.RequestUri!.Host == "chomikuj.pl")
        {
            if (request.Method == HttpMethod.Get)
                return new(HttpStatusCode.OK) { Content = new StringContent("<input value='synthetic&amp;csrf' name='__RequestVerificationToken'/>") };
            string form = await request.Content!.ReadAsStringAsync(ct);
            if (!form.Contains("accountname=synthetic-user", StringComparison.Ordinal) ||
                !form.Contains("folderid=17", StringComparison.Ordinal) ||
                !form.Contains("__RequestVerificationToken=synthetic%26csrf", StringComparison.Ordinal))
                throw new Exception("Incorrect web upload authorization fields.");
            return Json(new { Url = WebUploadUrl });
        }
        if (request.Method == HttpMethod.Get || request.Method == HttpMethod.Head)
        {
            if (request.Method == HttpMethod.Head) Heads++; else Downloads++;
            if (RejectHead && request.Method == HttpMethod.Head) return new(HttpStatusCode.NotFound);
            if (request.RequestUri!.AbsolutePath.Contains("/stale/", StringComparison.Ordinal))
            { StaleUrlRequests++; return new(HttpStatusCode.NotFound); }
            var stored = Stored[request.RequestUri!.Segments[^1]].Bytes;
            byte[] body = new byte[stored.Length + BodyAdjustment];
            stored.AsSpan(0, Math.Min(body.Length, stored.Length)).CopyTo(body);
            if (CorruptBody) body[^1] ^= 1;
            var content = new ByteArrayContent(body);
            content.Headers.ContentLength = stored.Length + LengthAdjustment;
            return new(HttpStatusCode.OK) { Content = content };
        }
        if (request.RequestUri!.AbsolutePath == "/web-upload")
        {
            Uploads++;
            if (SimulateTlsFailure) throw new HttpRequestException(HttpRequestError.SecureConnectionError, "sensitive-token-in-signed-URL");
            if (LoseUploadReply) throw new IOException("synthetic connection lost after upload request");
            var parts = (MultipartFormDataContent)request.Content!;
            var file = parts.Single(p => p.Headers.ContentDisposition?.Name?.Trim('"') == "files[]");
            string id = (40 + Stored.Count).ToString();
            Stored.Add(id, (file.Headers.ContentDisposition!.FileName!.Trim('"'), await file.ReadAsByteArrayAsync(ct)));
            return Json(new { files = new[] { new { fileId = id, name = Stored[id].Name, size = Stored[id].Bytes.Length } } });
        }
        var xml = XDocument.Parse(await request.Content!.ReadAsStringAsync(ct));
        string action = request.Headers.GetValues("SOAPAction").Single().Split('/')[^1];
        string Value(string name) => xml.Descendants().Single(e => e.Name.LocalName == name).Value;
        string payload;
        switch (action)
        {
            case "Auth": payload = "<token>synthetic-token</token><hamsterId>123</hamsterId><hamsterName>synthetic-user</hamsterName>"; break;
            case "Folders":
                payload = "<folder><id>0</id><folders>" +
                    (Value("depth") == "2" && !HideFolder && FolderName is not null ?
                        $"<FolderInfo><id>17</id><name>{FolderName}</name></FolderInfo>" : "") + "</folders></folder>";
                break;
            case "AddFolder": FolderName = Value("name"); payload = "<folderId>17</folderId>"; break;
            case "UploadToken": payload = "<key>synthetic-key</key><stamp>1</stamp><server>upload.chomikuj.pl</server>"; break;
            case "Download":
                SawCost |= xml.Descendants().Any(e => e.Name.LocalName == "cost");
                Agreements.AddRange(xml.Descendants().Where(e => e.Name.LocalName == "AgreementInfo")
                    .Select(e => e.Elements().Single(n => n.Name.LocalName == "name").Value));
                if (Error == "Unknown") return Reply(action, "Failed", "<errorMessage>sensitive-server-echo</errorMessage>");
                if (Error == "SessionExpired") return Reply(action, "SessionExpired", "");
                if (Error == "MissingList") return Reply(action, "Ok", "");
                if (Error == "MalformedList") return Reply(action, "Ok", "<list><Unexpected/></list>");
                string requested = Value("id");
                if (requested.StartsWith('/')) FolderRequests.Add(requested);
                if (Error == "Unavailable" || Stored.Count == 0) return Unavailable(action);
                IEnumerable<KeyValuePair<string, (string Name, byte[] Bytes)>> records;
                if (requested == "/synthetic-user/" + FolderName + "/") records = Stored;
                else if (Stored.ContainsKey(requested)) records = Stored.Where(pair => pair.Key == requested);
                else return Unavailable(action);
                payload = "<list><DownloadFolder><id>17</id><files>" + string.Concat(records.Select(pair =>
                    $"<FileEntry><id>{pair.Key}</id><name>{(WrongFileName ? "different.obj" : pair.Value.Name)}</name><size>{(InexactSoapSize ? 1 : pair.Value.Bytes.Length)}</size>" +
                    $"<url>{(LegacyDownloadUrls ? "http" : "https")}://download.chomikuj.pl/{(StaleListUrls && requested.StartsWith('/') ? "stale" : "file")}/{pair.Key}</url></FileEntry>")) + "</files></DownloadFolder></list>";
                break;
            default: throw new Exception("Unexpected SOAP request: " + action);
        }
        return Reply(action, "Ok", payload);
    }
    private static HttpResponseMessage Unavailable(string action) => Reply(action, "Failed", "<errorMessage>failed : requested file(s) not available</errorMessage>");
    private static HttpResponseMessage Reply(string action, string status, string payload) => Xml(
        $"<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'><s:Body><{action}Response xmlns='{Ns}'><{action}Result xmlns:a='urn:test-result'><a:status>{status}</a:status>{payload}</{action}Result></{action}Response></s:Body></s:Envelope>");
    private static HttpResponseMessage Xml(string value) => new(HttpStatusCode.OK) { Content = new StringContent(value, Encoding.UTF8, "text/xml") };
    private static HttpResponseMessage Json(object value) => new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json") };
}
