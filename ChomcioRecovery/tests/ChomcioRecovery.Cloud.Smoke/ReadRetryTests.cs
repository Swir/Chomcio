using ChomcioRecovery.Chomikuj;
using ChomcioRecovery.Core;
using System.Net;
using System.Net.Http.Headers;
using System.Xml.Linq;

internal static class ReadRetryTests
{
    private static readonly ChomikujFolder Folder = new("7", "ChomcioRecovery_Test");
    private static readonly CloudObject File = new("42", "repo.json", 3);

    internal static async Task Run(Action<bool, string> check, Func<Func<Task>, string, Task> fails)
    {
        using (var server = new FaultServer())
        using (var client = await Connect(server))
        {
            var broken = new InterruptedBody();
            server.GetFault = (n, _) => n == 1 ? Body(broken) : null;
            using var output = new MemoryStream();
            output.WriteByte(99);
            await client.OpenFolder(Folder).DownloadAsync(File, output, 3, default);
            check(output.ToArray().SequenceEqual(new byte[] { 99, 1, 2, 3 }), "interrupted body retry never leaks or duplicates partial output");
            check(server.Gets == 2 && server.FileMetadata == 2, "body retry fetches a fresh own-file URL");
            check(broken.WasDisposed, "failed response body disposed before retry");
        }
        using (var server = new FaultServer { ListOneFile = true })
        using (var client = await Connect(server))
        {
            server.GetFault = (n, _) => n == 1 ? throw new TaskCanceledException("synthetic internal timeout") : null;
            var listed = await client.OpenFolder(Folder).ListAsync(default);
            check(listed.Single().Length == 3 && server.Gets == 2 && server.FileMetadata == 2,
                "listing retries a timed-out exact-length probe with fresh metadata");
        }
        using (var server = new FaultServer())
        using (var client = await Connect(server))
        {
            var broken = new InterruptedBody(Schannel(unchecked((int)0x80090330u)));
            server.GetFault = (n, _) => n == 1 ? Body(broken) : null;
            using var output = new MemoryStream();
            output.WriteByte(99);
            await client.OpenFolder(Folder).DownloadAsync(File, output, 3, default);
            check(output.ToArray().SequenceEqual(new byte[] { 99, 1, 2, 3 }), "Schannel record failure discards partial response before a complete new read");
            check(server.Gets == 2 && server.FileMetadata == 2 && broken.WasDisposed,
                "Schannel record retry disposes response and fetches fresh authenticated metadata");
        }
        using (var server = new FaultServer())
        using (var client = await Connect(server))
        {
            server.GetFault = (_, _) => Body(new InterruptedBody(Schannel(unchecked((int)0x80090330u))));
            using var output = new MemoryStream();
            output.WriteByte(99);
            try { await client.OpenFolder(Folder).DownloadAsync(File, output, 3, default); throw new Exception("Expected TLS read failure"); }
            catch (ChomikujReadException error)
            {
                check(error.Failure == ChomikujReadFailure.TlsRecord && error.InnerException is null &&
                    !error.ToString().Contains("synthetic-private-url"), "exhausted TLS body failure retains only safe transport classification");
            }
            check(server.Gets == 3 && server.FileMetadata == 3 && output.ToArray().SequenceEqual(new byte[] { 99 }),
                "persistent TLS body failure is bounded and never delivers partial output");
        }
        foreach (uint code in new uint[] { 0x80090325, 0x80090328, 0x80092010, 0x8009030f, 0x80090326 })
        {
            using var server = new FaultServer();
            using var client = await Connect(server);
            server.GetFault = (_, _) => Body(new InterruptedBody(Schannel(unchecked((int)code))));
            using var output = new MemoryStream();
            try { await client.OpenFolder(Folder).DownloadAsync(File, output, 3, default); throw new Exception("Expected TLS security failure"); }
            catch (ChomikujReadException error)
            {
                check(error.Failure == ChomikujReadFailure.TlsSecurity && error.InnerException is null,
                    "TLS trust/protocol failure remains a safe security failure " + code.ToString("X8"));
            }
            check(server.Gets == 1 && output.Length == 0, "TLS trust/protocol failure is not retried " + code.ToString("X8"));
        }
        using (var server = new FaultServer())
        using (var client = await Connect(server))
        {
            server.GetFault = (n, _) => n == 1 ? Body(new InterruptedBody(Schannel(unchecked((int)0x80090330u))))
                : new(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[] { 1, 2 }) };
            using var output = new MemoryStream();
            await fails(() => client.OpenFolder(Folder).DownloadAsync(File, output, 3, default), "retry must still reject incorrect response length");
            check(server.Gets == 2 && output.Length == 0, "TLS retry does not weaken length validation or restart after integrity failure");
        }
        using (var server = new FaultServer())
        using (var client = await Connect(server))
        {
            server.SoapFault = (action, n) => action == "Folders" && n == 1 ? new(HttpStatusCode.ServiceUnavailable) : null;
            check((await client.ListFoldersAsync(default)).Single() == Folder && server.ActionCounts["Folders"] == 2,
                "authenticated folder read retries temporary HTTP failure");
        }
        using (var server = new FaultServer())
        using (var client = await Connect(server))
        {
            server.GetFault = (n, _) => n == 1 ? new(HttpStatusCode.NotFound) : null;
            using var output = new MemoryStream();
            await client.OpenFolder(Folder).DownloadAsync(File, output, 3, default);
            check(server.Gets == 2 && output.ToArray().SequenceEqual(new byte[] { 1, 2, 3 }),
                "temporary own-file 404 gets a bounded fresh URL retry");
        }
        using (var server = new FaultServer())
        using (var client = await Connect(server))
        {
            server.GetFault = (_, _) => throw new HttpRequestException(HttpRequestError.ConnectionError, "synthetic-private-url");
            using var output = new MemoryStream();
            output.WriteByte(99);
            try { await client.OpenFolder(Folder).DownloadAsync(File, output, 3, default); throw new Exception("Expected exhaustion"); }
            catch (IOException error) { check(!error.ToString().Contains("synthetic-private-url"), "transport diagnostics do not retain raw inner exception text"); }
            check(server.Gets == 3 && server.FileMetadata == 3, "read retries bounded at three total attempts without nested retry amplification");
            check(output.ToArray().SequenceEqual(new byte[] { 99 }), "exhausted retries leave destination unchanged");
        }
        foreach (var failure in new[] { "denied", "tls", "length", "cooldown", "unsafe-redirect" })
        {
            using var server = new FaultServer();
            using var client = await Connect(server);
            server.GetFault = (_, _) => failure switch
            {
                "denied" => new(HttpStatusCode.Forbidden),
                "tls" => throw new HttpRequestException(HttpRequestError.SecureConnectionError, "synthetic-secret"),
                "length" => new(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[] { 1, 2 }) },
                "cooldown" => Cooldown(),
                _ => new(HttpStatusCode.Redirect) { Headers = { Location = new Uri("https://attacker.invalid/") } }
            };
            using var output = new MemoryStream();
            await fails(() => client.OpenFolder(Folder).DownloadAsync(File, output, 3, default), failure + " remains a failure");
            check(server.Gets == 1 && output.Length == 0, failure + " is not retried or accepted as data");
        }
        using (var server = new FaultServer())
        using (var client = await Connect(server))
        using (var stop = new CancellationTokenSource())
        {
            server.GetFault = (_, _) =>
            {
                stop.CancelAfter(100);
                return new(HttpStatusCode.ServiceUnavailable);
            };
            using var output = new MemoryStream();
            bool canceled = false;
            try { await client.OpenFolder(Folder).DownloadAsync(File, output, 3, stop.Token); }
            catch (OperationCanceledException) { canceled = true; }
            check(canceled && server.Gets == 1 && output.Length == 0, "user cancellation interrupts backoff without another request");
        }
        using (var server = new FaultServer())
        using (var client = await Connect(server))
        {
            server.UploadFault = () => throw new HttpRequestException(HttpRequestError.ConnectionError, "synthetic lost upload acknowledgement");
            await fails(() => client.OpenFolder(Folder).UploadAsync("repo.json", new MemoryStream(new byte[] { 1, 2, 3 }), 3, default),
                "ambiguous upload remains unconfirmed");
            check(server.Uploads == 1, "ambiguous file POST is never automatically repeated");
        }
        using (var server = new FaultServer())
        using (var client = await Connect(server))
        {
            server.SoapFault = (action, _) => action == "AddFolder" ? new(HttpStatusCode.ServiceUnavailable) : null;
            await fails(() => client.CreateFolderAsync("ChomcioRecovery_New", default), "failed folder creation stays unconfirmed");
            check(server.ActionCounts["AddFolder"] == 1, "folder creation is never automatically repeated");
        }
        using (var server = new FaultServer())
        using (var client = await Connect(server))
        {
            server.SoapFault = (action, _) => action == "AddFolder"
                ? Body(new InterruptedBody(Schannel(unchecked((int)0x80090330u)))) : null;
            await fails(() => client.CreateFolderAsync("ChomcioRecovery_New", default), "TLS failure in folder acknowledgement stays unconfirmed");
            check(server.ActionCounts["AddFolder"] == 1, "TLS record recovery never repeats a mutation");
        }
    }

    private static async Task<ChomikujClient> Connect(FaultServer server)
    {
        var client = new ChomikujClient(server);
        await client.LoginAsync("synthetic-user", "synthetic-password", default);
        return client;
    }

    private static HttpResponseMessage Body(Stream stream)
    {
        var content = new StreamContent(stream);
        content.Headers.ContentLength = 3;
        return new(HttpStatusCode.OK) { Content = content };
    }

    private static HttpResponseMessage Cooldown()
    {
        var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromMinutes(10));
        return response;
    }

    private static IOException Schannel(int code) => new("synthetic-private-url",
        new System.ComponentModel.Win32Exception(code, "synthetic-private-url"));

    private sealed class InterruptedBody(Exception? failure = null) : MemoryStream(new byte[] { 1, 2, 3 })
    {
        internal bool WasDisposed;
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            if (Position != 0) throw failure ?? new HttpIOException(HttpRequestError.ResponseEnded, "synthetic interrupted body");
            return new ValueTask<int>(Read(buffer.Span[..1]));
        }
        protected override void Dispose(bool disposing) { WasDisposed = true; base.Dispose(disposing); }
    }

    private sealed class FaultServer() : DelegatingHandler(new ProtocolHandler())
    {
        internal Func<int, CancellationToken, HttpResponseMessage?>? GetFault;
        internal Func<string, int, HttpResponseMessage?>? SoapFault;
        internal Func<HttpResponseMessage?>? UploadFault;
        internal bool ListOneFile;
        internal int Gets, FileMetadata, Uploads;
        internal Dictionary<string, int> ActionCounts = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.RequestUri!.Host == "download.chomikuj.pl")
            {
                var fault = GetFault?.Invoke(++Gets, ct);
                if (fault is not null) return fault;
            }
            if (request.RequestUri!.AbsolutePath == "/web-upload")
            {
                Uploads++;
                var fault = UploadFault?.Invoke();
                if (fault is not null) return fault;
            }
            if (request.Headers.TryGetValues("SOAPAction", out var values))
            {
                string action = values.Single().Split('/')[^1];
                int count = ActionCounts[action] = ActionCounts.GetValueOrDefault(action) + 1;
                var fault = SoapFault?.Invoke(action, count);
                if (fault is not null) return fault;
                if (action == "Download")
                {
                    var xml = XDocument.Parse(await request.Content!.ReadAsStringAsync(ct));
                    string id = xml.Descendants().Single(e => e.Name.LocalName == "id").Value;
                    if (id == "42") FileMetadata++;
                    else if (ListOneFile)
                        return new(HttpStatusCode.OK) { Content = new StringContent(
                            "<Envelope><Body><DownloadResult><status>Ok</status><list><DownloadFolder><files><FileEntry>" +
                            "<id>42</id><name>repo.json</name><size>512</size>" +
                            "</FileEntry></files></DownloadFolder></list></DownloadResult></Body></Envelope>") };
                }
            }
            return await base.SendAsync(request, ct);
        }
    }
}
