using ChomcioRecovery.Core;
using ChomcioRecovery.Chomikuj;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

int checks = 0;
void Check(bool condition, string label) { checks++; if (!condition) throw new Exception(label); }
async Task Fails(Func<Task> action, string label)
{
    bool failed = false;
    try { await action(); } catch (Exception ex) when (ex is IOException or InvalidDataException or OperationCanceledException or CryptographicException) { failed = true; }
    Check(failed, label);
}
string root = Path.Combine(Path.GetTempPath(), "chomcio-cloud-tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
string New(string name) => Path.Combine(root, name + Guid.NewGuid().ToString("N"));
try
{
    string source = New("source"), repo = New("vault");
    Directory.CreateDirectory(Path.Combine(source, "empty"));
    byte[] bytes = RandomNumberGenerator.GetBytes(LocalEncryptedVault.ChunkBytes + 123);
    File.WriteAllBytes(Path.Combine(source, "data.bin"), bytes);
    const string password = "synthetic-cloud-tests-only";
    LocalEncryptedVault.Initialize(repo, password);
    string id;
    using (var vault = LocalEncryptedVault.Open(repo, password)) id = vault.BackupDirectory(source).SnapshotId;
    var remote = new MemoryVault();
    var transfer = new CloudVaultTransfer(remote);
    await transfer.UploadSnapshotAsync(repo, password, id, New("export"), null, default);
    Check(remote.UploadOrder[0] == "repo.json", "config checked before objects");
    Check(remote.UploadOrder[^1] == id + ".snap", "snapshot published last");
    Check(remote.Downloads == remote.Files.Count, "every uploaded byte read back from remote");
    Check(!remote.Files.Values.Any(b => b.AsSpan().IndexOf(bytes.AsSpan(0, 64)) >= 0), "remote stores ciphertext only");
    int originalUploads = remote.UploadOrder.Count;
    await transfer.UploadSnapshotAsync(repo, password, id, New("resume"), null, default);
    Check(remote.UploadOrder.Count == originalUploads, "resume reuses verified identical remote objects");
    Check((await transfer.ListSnapshotsAsync(default)).SequenceEqual(new[] { id }), "snapshot listing");
    string downloaded = New("download");
    await transfer.DownloadSnapshotAsync(id, password, downloaded, null, default);
    string restored = New("restored");
    using (var vault = LocalEncryptedVault.Open(downloaded, password)) vault.RestoreSnapshot(id, restored);
    Check(File.ReadAllBytes(Path.Combine(restored, "data.bin")).SequenceEqual(bytes), "independent cloud restore exact");
    Check(Directory.Exists(Path.Combine(restored, "empty")), "cloud restores empty directories");
    using (var stop = new CancellationTokenSource())
    {
        var partial = new MemoryVault();
        partial.AfterUpload = name => { if (name.EndsWith(".obj", StringComparison.Ordinal)) stop.Cancel(); };
        var resumed = new CloudVaultTransfer(partial);
        await Fails(() => resumed.UploadSnapshotAsync(repo, password, id, New("cancel"), null, stop.Token), "cancel during transfer");
        Check(!partial.Files.ContainsKey(id + ".snap"), "cancel never publishes incomplete snapshot");
        partial.AfterUpload = null;
        await resumed.UploadSnapshotAsync(repo, password, id, New("continued"), null, default);
        Check(partial.UploadOrder.Count == partial.Files.Count, "continuation does not re-upload completed objects");
    }
    var corrupt = new MemoryVault { CorruptReadback = true };
    await Fails(() => new CloudVaultTransfer(corrupt).UploadSnapshotAsync(repo, password, id, New("corrupt"), null, default), "bad remote readback rejected");
    Check(!corrupt.Files.ContainsKey(id + ".snap"), "corrupt readback prevents publication");
    var foreign = new MemoryVault(); foreign.Files.Add("repo.json", new byte[1]);
    await Fails(() => new CloudVaultTransfer(foreign).UploadSnapshotAsync(repo, password, id, New("foreign"), null, default), "wrong repository refused");
    Check(foreign.UploadOrder.Count == 0, "wrong repository refused before uploading data");
    string objectName = remote.Files.Keys.First(n => n.EndsWith(".obj", StringComparison.Ordinal));
    remote.Files[objectName][^1] ^= 1;
    await Fails(() => transfer.DownloadSnapshotAsync(id, password, New("bad-download"), null, default), "tampered ciphertext rejected by independent core");
    remote.Files[objectName][^1] ^= 1;
    await Fails(() => transfer.DownloadSnapshotAsync(id, "wrong", New("wrong-password"), null, default), "wrong password rejected");
    foreach (string uri in new[] { "http://box.chomikuj.pl/", "https://chomikuj.pl.attacker.invalid/", "https://attacker.invalid/", "https://user:password@box.chomikuj.pl/" })
        await Fails(() => { ChomikujClient.RequireServiceUri(new Uri(uri)); return Task.CompletedTask; }, "unsafe endpoint refused");
    ChomikujClient.RequireServiceUri(new Uri("https://box.chomikuj.pl/"));
    Check(true, "HTTPS service allowed");
    using (var handler = new ProtocolHandler())
    using (var client = new ChomikujClient(handler))
    {
        await client.LoginAsync("synthetic-user", "not-a-real-password", default);
        Check(!handler.Requests[0].Contains("not-a-real-password", StringComparison.Ordinal), "plaintext account password absent from wire request");
        var folders = await client.ListFoldersAsync(default);
        Check(folders.Single().Name == "ChomcioRecovery_Test", "folder response parsed");
        var cloud = client.OpenFolder(folders.Single());
        Check((await cloud.ListAsync(default)).Count == 0, "empty cloud folder parsed");
        using var input = new MemoryStream(new byte[] { 1, 2, 3 });
        CloudObject file = await cloud.UploadAsync("repo.json", input, 3, default);
        using var output = new MemoryStream();
        await cloud.DownloadAsync(file, output, 3, default);
        Check(output.ToArray().SequenceEqual(new byte[] { 1, 2, 3 }), "SOAP and multipart + download path executed");
        Check(handler.UploadSeen, "multipart file transfer executed");
        Check(handler.Requests.All(s => !s.Contains("<cost>", StringComparison.Ordinal)), "no paid transfer acceptance");
    }
    await FolderProtocolRegressions.Run(Check, Fails, repo, password, id, New);
    await FolderProtectionTests.Run(Check,Fails);
    await ReadRetryTests.Run(Check, Fails);
    await TransferProgressScenarios.Run(repo,password,id,New,Check);
    await DownloadResumeScenarios.Run(repo,password,id,New,Check);
    Console.WriteLine($"CHOMCIO_CLOUD_ENGINE_PROTOCOL_SMOKE=PASS assertions={checks}");
    Console.WriteLine("LIVE_CHOMIKUJ_ACCOUNT=NOT_TESTED (local deterministic transport)");
}
finally
{
    string prefix = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
    if (!Path.GetFullPath(root).StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) throw new IOException("Unsafe test cleanup");
    Directory.Delete(root, recursive: true);
}

sealed class MemoryVault : ICloudVault
{
    internal Dictionary<string, byte[]> Files { get; } = new(StringComparer.Ordinal);
    internal List<string> UploadOrder { get; } = new();
    internal int Downloads;
    internal Action<string>? AfterUpload;
    internal bool CorruptReadback;
    public Task<IReadOnlyList<CloudObject>> ListAsync(CancellationToken ct)
    { ct.ThrowIfCancellationRequested(); return Task.FromResult<IReadOnlyList<CloudObject>>(Files.Select(kv => new CloudObject(kv.Key, kv.Key, kv.Value.Length)).ToArray()); }
    public async Task<CloudObject> UploadAsync(string name, Stream input, long length, CancellationToken ct)
    {
        using var memory = new MemoryStream(); await input.CopyToAsync(memory, ct);
        Files.Add(name, memory.ToArray()); UploadOrder.Add(name); AfterUpload?.Invoke(name);
        return new(name, name, length);
    }
    public async Task DownloadAsync(CloudObject file, Stream output, long maximumBytes, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); Downloads++;
        byte[] data = Files[file.Name].ToArray(); if (CorruptReadback) data[^1] ^= 1;
        if (data.Length > maximumBytes) throw new InvalidDataException();
        await output.WriteAsync(data, ct);
    }
}

sealed class ProtocolHandler : HttpMessageHandler
{
    internal List<string> Requests { get; } = new();
    internal bool UploadSeen;
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        if (request.RequestUri!.Host == "chomikuj.pl")
        {
            if (request.Method == HttpMethod.Get)
                return new(HttpStatusCode.OK) { Content = new StringContent("<input name='__RequestVerificationToken' value='synthetic-csrf'/>") };
            string form = await request.Content!.ReadAsStringAsync(ct);
            if (!form.Contains("folderid=7", StringComparison.Ordinal) || !form.Contains("__RequestVerificationToken=synthetic-csrf", StringComparison.Ordinal))
                throw new InvalidDataException("Web upload must target selected folder and provide CSRF token.");
            return new(HttpStatusCode.OK) { Content = new StringContent("{\"Url\":\"https://upload.chomikuj.pl/web-upload?key=synthetic-key\"}") };
        }
        if (request.Method == HttpMethod.Get)
            return new(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[] { 1, 2, 3 }) };
        if (request.RequestUri!.AbsolutePath == "/web-upload")
        {
            string body = await request.Content!.ReadAsStringAsync(ct);
            UploadSeen = body.Contains("repo.json", StringComparison.Ordinal) && body.Contains("files[]", StringComparison.Ordinal);
            return new(HttpStatusCode.OK) { Content = new StringContent("{\"files\":[{\"fileId\":42,\"name\":\"repo.json\",\"size\":3}]}") };
        }
        string xml = await request.Content!.ReadAsStringAsync(ct); Requests.Add(xml);
        string action = request.Headers.GetValues("SOAPAction").Single().Split('/')[^1];
        var requestXml = XDocument.Parse(xml);
        if (action == "Folders" && requestXml.Descendants().Single(e => e.Name.LocalName == "depth").Value != "2")
            throw new InvalidDataException("Regression: listing immediate child folders requires depth 2.");
        if (action == "Download")
        {
            string id = requestXml.Descendants().Single(e => e.Name.LocalName == "id").Value;
            if (id.StartsWith('/') && !id.EndsWith('/'))
                throw new InvalidDataException("Regression: a directory request must end with a slash.");
        }
        string payload = action switch
        {
            "Auth" => "<token>synthetic-token</token><hamsterId>123</hamsterId><hamsterName>synthetic-user</hamsterName>",
            "Folders" => "<folder><folders><FolderInfo><id>7</id><name>ChomcioRecovery_Test</name></FolderInfo></folders></folder>",
            "UploadToken" => "<key>upload-key</key><stamp>1</stamp><server>upload.chomikuj.pl</server>",
            "Download" when XDocument.Parse(xml).Descendants().Any(e => e.Name.LocalName == "id" && e.Value == "42") =>
                "<list><DownloadFolder><files><FileEntry><id>42</id><name>repo.json</name><size>3</size><url>https://download.chomikuj.pl/test.bin</url></FileEntry></files></DownloadFolder></list>",
            "Download" => "<list><DownloadFolder><files/></DownloadFolder></list>",
            _ => throw new InvalidOperationException("Unexpected request")
        };
        return Xml($"<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'><s:Body><{action}Response><{action}Result><status>Ok</status>{payload}</{action}Result></{action}Response></s:Body></s:Envelope>");
    }
    private static HttpResponseMessage Xml(string value) => new(HttpStatusCode.OK) { Content = new StringContent(value, Encoding.UTF8, "text/xml") };
}
