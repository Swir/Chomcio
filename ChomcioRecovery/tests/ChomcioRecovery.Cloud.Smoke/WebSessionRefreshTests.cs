using ChomcioRecovery.Chomikuj;
using ChomcioRecovery.Core;
using System.Net;
using System.Text.Json;

internal static class WebSessionRefreshTests
{
    private const string FolderPassword = "IndependentFolderPassword123456";
    private static readonly ChomikujFolder Folder = new("17", "ChomcioRecovery_Session");

    internal static async Task Run(Action<bool, string> check, Func<Func<Task>, string, Task> fails)
    {
        using (var handler = new SessionServer())
        using (var client = new ChomikujClient(handler))
        {
            await Prepare(client);
            check(handler.Sessions == 1 && handler.ProtectionReads == 1, "folder protection establishes the initial portal session");
            var cloud = client.OpenFolder(Folder);
            handler.Expired = true;
            check((await cloud.ListNamesAsync(default)).Contains("repo.json"), "SOAP reads still work after portal session expiry");
            using var first = new MemoryStream(new byte[] { 3, 5, 7 });
            var uploaded = await cloud.UploadAsync(Name('a'), first, 3, default);
            check(handler.Sessions == 2 && handler.Addresses == 1 && handler.Uploads == 1,
                "upload establishes a fresh portal session after lengthy preparation, with one address and one send");
            using var readback = new MemoryStream();
            await cloud.DownloadAsync(uploaded, readback, 3, default);
            check(readback.ToArray().SequenceEqual(new byte[] { 3, 5, 7 }), "uploaded bytes remain independently readable");

            handler.Expired = true;
            using var second = new MemoryStream(new byte[] { 11 });
            await cloud.UploadAsync(Name('b'), second, 1, default);
            check(handler.Sessions == 3 && handler.Addresses == 2 && handler.Uploads == 2,
                "another object establishes a new portal session after intervening reads");
            check(handler.ProtectionReads == 1 && handler.AllHttps, "refresh preserves folder protection and HTTPS");
        }

        foreach (string fault in new[] { "session", "address", "missing-url", "unsafe-url", "send" })
        {
            using var handler = new SessionServer();
            using var client = new ChomikujClient(handler);
            await Prepare(client);
            handler.Expired = true;
            handler.Fault = fault;
            using var content = new MemoryStream(new byte[] { 13 });
            await fails(async () => { await client.OpenFolder(Folder).UploadAsync(Name('c'), content, 1, default); },
                "failure is preserved at " + fault);
            check(handler.Sessions == 2, "only one new session attempt at " + fault);
            check(handler.Addresses == (fault == "session" ? 0 : 1), "no address retry or address after failed authentication at " + fault);
            check(handler.Uploads == (fault == "send" ? 1 : 0), "no ambiguous send retry or send after invalid address at " + fault);
            check(handler.AllHttps && handler.ProtectionReads == 1, "HTTPS and existing folder password unchanged at " + fault);
        }

        using (var handler = new SessionServer())
        using (var client = new ChomikujClient(handler))
        {
            await Prepare(client);
            using var stop = new CancellationTokenSource();
            stop.Cancel();
            using var content = new MemoryStream(new byte[] { 17 });
            await fails(async () => { await client.OpenFolder(Folder).UploadAsync(Name('d'), content, 1, stop.Token); },
                "cancellation before transfer remains effective");
            check(handler.Sessions == 1 && handler.Addresses == 0 && handler.Uploads == 0,
                "cancelled upload does not refresh, request an address or send");
        }
    }

    private static string Name(char c) => new string(c, 64) + ".obj";
    private static async Task Prepare(ChomikujClient client)
    {
        await client.LoginAsync("synthetic-user", "synthetic-account-password", default);
        await client.EnsureFolderPasswordAsync(Folder, FolderPassword, default);
    }

    // Session expiry is injected without wall-clock waits. This models the
    // protocol boundary; it does not assert the cause of any live failure.
    private sealed class SessionServer : HttpMessageHandler
    {
        private readonly FolderServer files = new() { FolderName = Folder.Name };
        private readonly HttpMessageInvoker inner;
        internal bool Expired, AllHttps = true;
        internal string Fault = "";
        internal int Sessions, Addresses, ProtectionReads;
        internal int Uploads => files.Uploads;
        internal SessionServer()
        {
            files.Stored.Add("40", ("repo.json", new byte[] { 1 }));
            inner = new HttpMessageInvoker(files);
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            var uri = request.RequestUri!;
            AllHttps &= uri.Scheme == "https";
            if (uri.Host != "chomikuj.pl")
            {
                files.LoseUploadReply = Fault == "send";
                return await inner.SendAsync(request, ct);
            }
            if (request.Method == HttpMethod.Get && uri.AbsolutePath == "/chomik/chomikbox/LoginFromBox")
            {
                Sessions++;
                if (Fault == "session") return new(HttpStatusCode.Unauthorized);
                Expired = false;
                return Text($"<input name='__RequestVerificationToken' value='session-{Sessions}'/>");
            }
            var fields = (await request.Content!.ReadAsStringAsync(ct)).Split('&').Select(s => s.Split('=', 2))
                .ToDictionary(a => WebUtility.UrlDecode(a[0]), a => WebUtility.UrlDecode(a.Length > 1 ? a[1] : ""));
            if (fields.GetValueOrDefault("__RequestVerificationToken") != "session-" + Sessions)
                throw new Exception("Missing or stale synthetic CSRF token.");
            if (uri.AbsolutePath == "/action/FolderOptions/ChangePassword")
            {
                ProtectionReads++;
                if (fields.GetValueOrDefault("FolderId") != Folder.Id || fields.GetValueOrDefault("ChomikName") != "synthetic-user")
                    throw new Exception("Wrong protected folder.");
                return Json(new { Content = $"<form action='/action/FolderOptions/ChangePasswordAction'><input name='FolderId' value='{Folder.Id}'/><input name='ChomikName' value='synthetic-user'/><input name='Password' value='{FolderPassword}'/></form>" });
            }
            if (uri.AbsolutePath != "/action/Upload/GetUrl/" || request.Method != HttpMethod.Post)
                throw new Exception("Unexpected mutation or portal operation.");
            Addresses++;
            if (fields.GetValueOrDefault("folderid") != Folder.Id || fields.GetValueOrDefault("accountname") != "synthetic-user")
                throw new Exception("Wrong upload destination.");
            if (Fault == "address") return new(HttpStatusCode.InternalServerError);
            if (Expired || Fault == "missing-url") return Json(new { Success = false });
            if (Fault == "unsafe-url") return Json(new { Url = "http://upload.chomikuj.pl/web-upload" });
            return Json(new { Url = "https://upload.chomikuj.pl/web-upload" });
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) inner.Dispose();
            base.Dispose(disposing);
        }
        private static HttpResponseMessage Text(string text) => new(HttpStatusCode.OK) { Content = new StringContent(text) };
        private static HttpResponseMessage Json(object value) => Text(JsonSerializer.Serialize(value));
    }
}
