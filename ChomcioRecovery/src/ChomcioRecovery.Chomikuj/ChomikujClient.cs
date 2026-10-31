using ChomcioRecovery.Core;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace ChomcioRecovery.Chomikuj;

public sealed record ChomikujFolder(string Id, string Name)
{
    public override string ToString() => Name;
}

/// <summary>
/// Experimental adapter for the ChomikBox protocol. HTTPS only, authenticated
/// own-account folders only, no overwrite/delete, no paid-transfer consent.
/// Compatibility is qualified only by a live upload/download/restore test.
/// </summary>
public sealed partial class ChomikujClient : IDisposable
{
    private static readonly Uri Service = new("https://box.chomikuj.pl/services/ChomikBoxService.svc");
    private static readonly XNamespace Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace Ns = "http://chomikuj.pl/";
    private const int SmallSoapLimit = 2 * 1024 * 1024;
    // A folder contains thousands of encrypted chunk records. Its complete
    // metadata can exceed the small control-response quota. Keep a finite
    // byte/character quota and reject overflow instead of truncating the list.
    private const int FolderSoapLimit = 64 * 1024 * 1024;
    private readonly HttpClient http;
    private string token = "";
    private string accountId = "";
    private string accountName = "";
    // The legacy Download endpoint can report an empty directory as an error.
    // Accept that ambiguity only for a folder created by THIS session, before
    // any upload attempt. Never hide failures in an existing backup as "empty".
    private readonly HashSet<string> freshEmptyFolders = new(StringComparer.Ordinal);
    public IProgress<string>? Diagnostics { get; set; }

    public ChomikujClient() : this(new HttpClientHandler
    {
        AllowAutoRedirect = false,
        AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
        UseCookies = true
    }) { }

    // Injectable transport for protocol tests; production always validates HTTPS.
    public ChomikujClient(HttpMessageHandler handler)
    {
        webCookies = (handler as HttpClientHandler)?.CookieContainer;
        http = new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(15) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("ChomcioRecovery/0.1.56");
    }

    public async Task LoginAsync(string username, string password, CancellationToken cancellationToken)
    {
        token = accountId = accountName = "";
        freshEmptyFolders.Clear(); ResetWebSession();
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(password))
            throw new ArgumentException("Podaj login i hasło konta testowego Chomikuj.");
        // MD5 is required by this legacy authentication protocol, never used
        // for backup encryption or integrity. It is sent only inside TLS.
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        string passwordHash;
        try { passwordHash = Convert.ToHexString(MD5.HashData(passwordBytes)).ToLowerInvariant(); }
        finally { CryptographicOperations.ZeroMemory(passwordBytes); }
        var result = await CallAsync("Auth", cancellationToken,
            E("name", username), E("passHash", passwordHash),
            E("client", E("name", "chomikbox"), E("version", "2.0.8.2")), E("ver", "4"));
        string nextToken = Text(result, "token");
        string nextId = Text(result, "hamsterId");
        if (string.IsNullOrEmpty(nextToken) || !long.TryParse(nextId, out long id) || id <= 0)
            throw new InvalidDataException("Serwer nie potwierdził konta.");
        accountName = Text(result, "hamsterName");
        if (string.IsNullOrEmpty(accountName)) accountName = username;
        accountId = nextId;
        token = nextToken;
    }

    public async Task<IReadOnlyList<ChomikujFolder>> ListFoldersAsync(CancellationToken ct)
    {
        RequireLogin();
        var result = await RetryReadAsync(() => CallAsync("Folders", ct, E("token", token), E("hamsterId", accountId),
            E("folderId", "0"), E("depth", "2")), ct);
        var root = result.Elements().FirstOrDefault(e => e.Name.LocalName == "folder");
        if (root is null) throw new InvalidDataException("Chomikuj nie zwrócił drzewa folderów konta.");
        var children = root?.Elements().FirstOrDefault(e => e.Name.LocalName == "folders");
        if (children is null) return Array.Empty<ChomikujFolder>();
        return children.Elements().Where(e => e.Name.LocalName == "FolderInfo")
            .Select(e => new ChomikujFolder(Text(e, "id"), Text(e, "name")))
            .Where(f => long.TryParse(f.Id, out long id) && id > 0).ToArray();
    }

    public async Task<ChomikujFolder> CreateFolderAsync(string name, CancellationToken ct)
    {
        RequireLogin();
        if (!(name.StartsWith("ChomcioRecovery_", StringComparison.Ordinal)||name.StartsWith("Chomciore_", StringComparison.Ordinal)) ||
            name.Length > 100 || !name.All(c => char.IsAsciiLetterOrDigit(c) || c == '_'))
            throw new ArgumentException("Nowy folder musi mieć prefiks ChomcioRecovery_ lub Chomciore_ i litery lub cyfry.");
        if ((await ListFoldersAsync(ct)).Any(f => f.Name == name))
            throw new IOException("Folder już istnieje. Wybierz go z listy, aby kontynuować.");
        var result = await CallAsync("AddFolder", ct, E("token", token), E("newFolderId", "0"), E("name", name));
        string id = Text(result, "folderId");
        if (!long.TryParse(id, out long number) || number <= 0)
            throw new InvalidDataException("Niepotwierdzony wynik tworzenia folderu; odśwież listę.");
        freshEmptyFolders.Add(id);
        return new(id, name);
    }

    public ICloudVault OpenFolder(ChomikujFolder folder)
    {
        RequireLogin();
        if (!long.TryParse(folder.Id, out long id) || id <= 0 || string.IsNullOrEmpty(folder.Name))
            throw new ArgumentException("Wybierz folder kopii na swoim koncie.");
        return new FolderVault(this, folder);
    }

    private sealed class FolderVault(ChomikujClient client, ChomikujFolder folder) : ICloudVault
    {
        public Task<IReadOnlyList<CloudObject>> ListAsync(CancellationToken cancellationToken) => client.ListFilesAsync(folder, cancellationToken);
        public async Task<IReadOnlyList<string>> ListNamesAsync(CancellationToken cancellationToken) =>
            (await client.ListFilesAsync(folder,cancellationToken,resolveLengths:false)).Select(file=>file.Name).ToArray();
        public Task<CloudObject> UploadAsync(string name, Stream encryptedContent, long length, CancellationToken cancellationToken) =>
            client.UploadAsync(folder, name, encryptedContent, length, cancellationToken);
        public Task DownloadAsync(CloudObject file, Stream destination, long maximumBytes, CancellationToken cancellationToken) =>
            client.DownloadAsync(file, destination, maximumBytes, cancellationToken);
    }

    private async Task<IReadOnlyList<CloudObject>> ListFilesAsync(ChomikujFolder folder, CancellationToken ct,bool resolveLengths=true)
    {
        // A trailing slash distinguishes a folder from a file in ChomikBox.
        string path = "/" + EscapePathPart(accountName) + "/" + EscapePathPart(folder.Name) + "/";
        XElement result;
        try { result = await RequestFolderDownloadAsync(path, ct); }
        catch (ChomikujServiceException error) when (
            error.Failure == ChomikujFailure.RequestedFilesUnavailable && freshEmptyFolders.Contains(folder.Id))
        {
            // Confirm its identity in the authenticated account tree. A deleted
            // or renamed folder, failed login or unknown response stays a failure.
            if (!(await ListFoldersAsync(ct)).Any(f => f.Id == folder.Id && f.Name == folder.Name)) throw;
            return Array.Empty<CloudObject>();
        }
        var list = result.Elements().FirstOrDefault(e => e.Name.LocalName == "list")
            ?? throw InvalidResponse("Chomikuj nie zwrócił listy plików; nie uznano folderu za pusty.", ResponseFailureKind.FileListMissing, HttpOperation.SoapRequest);
        var downloadedFolders = list.Elements().ToArray();
        if (downloadedFolders.Any(e => e.Name.LocalName != "DownloadFolder" ||
                !e.Elements().Any(child => child.Name.LocalName == "files")))
            throw InvalidResponse("Chomikuj zwrócił nierozpoznaną strukturę listy plików.", ResponseFailureKind.FileListStructure, HttpOperation.SoapRequest);
        var fileEntries = downloadedFolders.SelectMany(e => e.Elements().Where(child => child.Name.LocalName == "files"))
            .SelectMany(e => e.Elements()).ToArray();
        if (fileEntries.Any(e => e.Name.LocalName != "FileEntry"))
            throw InvalidResponse("Chomikuj zwrócił nierozpoznany rekord pliku.", ResponseFailureKind.FileRecordStructure, HttpOperation.SoapRequest);
        var records = fileEntries
            .Select(e => new CloudObject(Text(e, "id"), Text(e, "name"), ParseLength(Text(e, "size"))))
            .ToArray();
        if (records.Any(f => string.IsNullOrEmpty(f.Id) || string.IsNullOrEmpty(f.Name)))
            throw InvalidResponse("Chomikuj zwrócił niepełny rekord pliku.", ResponseFailureKind.FileRecordIncomplete, HttpOperation.SoapRequest);
        if (records.Length > 0) freshEmptyFolders.Remove(folder.Id);
        // SOAP's size field is not the authority for byte-accurate transfer.
        // Resolve the actual HTTP representation length before exposing records
        // to the core, which requires exact lengths for resume and restore.
        for (int i = 0; resolveLengths&&i < records.Length; i++)
        {
            // Directory entries can carry a different/stale download URL. Obtain
            // an own-file URL exactly as for readback. Some servers reject HEAD;
            // GET with ResponseHeadersRead confirms the representation without
            // buffering its body. Dispose it immediately after checking length.
            var record = records[i];
            long length = await RetryReadAsync(async () =>
            {
                var entry = await RequestFileAsync(record, ct);
                using var response = await OpenDownloadAsync(DownloadUri(entry), HttpMethod.Get, ct);
                return response.Content.Headers.ContentLength
                    ?? throw new InvalidDataException("Serwer pobierania nie potwierdził rozmiaru pliku w bajtach.");
            }, ct, allowTemporaryNotFound: true);
            if (length < 0 || length > 64L * 1024 * 1024 + 36)
                throw new InvalidDataException("Przekroczony rozmiar rekordu kopii w chmurze.");
            ReportLengths(records[i].Length, length);
            records[i] = records[i] with { Length = length };
        }
        return records;
    }

    private async Task<CloudObject> UploadAsync(ChomikujFolder folder, string name, Stream input, long length, CancellationToken ct)
    {
        RequireLogin();
        if (length < 0 || length > 64 * 1024 * 1024 + 36 || string.IsNullOrEmpty(name) ||
            name.Any(c => !(char.IsAsciiLetterOrDigit(c) || c == '.')))
            throw new ArgumentException("Niepoprawny zaszyfrowany rekord.");
        // The conflict check needs names only. Resolving every existing file's
        // download length before EACH upload made a folder with N objects
        // perform O(N²) HTTP downloads. Core listing and readback still resolve
        // exact lengths and compare every encrypted byte.
        if ((await ListFilesAsync(folder, ct,resolveLengths:false)).Any(f => f.Name == name))
            throw new IOException("Rekord już istnieje w chmurze. Wznów zadanie, aby sprawdzić jego zgodność.");
        return await UploadViaWebAsync(folder, name, input, length, ct);
    }

    private async Task DownloadAsync(CloudObject file, Stream output, long maxBytes, CancellationToken ct)
    {
        if (file.Length < 0 || file.Length > maxBytes || file.Length > 64L * 1024 * 1024 + 36)
            throw new InvalidDataException("Przekroczony rozmiar fragmentu.");
        // Each attempt owns a fresh bounded buffer. A broken response must
        // never append partial bytes into the caller's stream before retry.
        byte[] verifiedLength = await RetryReadAsync(() => ReadDownloadedBytesAsync(file, maxBytes, ct),
            ct, allowTemporaryNotFound: true);
        try { await output.WriteAsync(verifiedLength, ct); }
        finally { CryptographicOperations.ZeroMemory(verifiedLength); }
    }

    private async Task<byte[]> ReadDownloadedBytesAsync(CloudObject file, long maxBytes, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromMinutes(15));
        var readToken = deadline.Token;
        var entry = await RequestFileAsync(file, readToken);
        long metadataLength = ParseLength(Text(entry, "size"));
        ReportLengths(metadataLength, file.Length);
        using var response = await OpenDownloadAsync(DownloadUri(entry), HttpMethod.Get, readToken);
        if (response.Content.Headers.ContentLength is long declared && declared != file.Length)
            throw new InvalidDataException($"Niezgodny rozmiar pobieranego fragmentu: oczekiwano {file.Length} B, serwer HTTPS podał {declared} B.");
        await using var stream = await response.Content.ReadAsStreamAsync(readToken);
        using var output = new MemoryStream();
        byte[] buffer = new byte[65_536];
        long count = 0;
        while (true)
        {
            int read = await ReadBodyAsync(stream, buffer, readToken);
            if (read == 0) break;
            count = checked(count + read);
            if (count > maxBytes || count > file.Length) throw new InvalidDataException("Serwer przesłał zbyt dużo danych.");
            await output.WriteAsync(buffer.AsMemory(0, read), readToken);
        }
        if (count != file.Length) throw new InvalidDataException("Połączenie zakończyło się przed pobraniem całości.");
        return output.ToArray();
    }

    private void ReportLengths(long metadata, long bytes)
    {
        if (metadata != bytes)
            Diagnostics?.Report($"Kontrola rozmiaru: metadane ChomikBox={metadata}, wymagany rozmiar pliku={bytes} B. Obowiązuje kontrola pobranych bajtów.");
    }

    private async Task<XElement> RequestFileAsync(CloudObject file, CancellationToken ct)
    {
        // Retry belongs to the complete file read/length probe. Keeping this
        // call single-attempt avoids multiplying retry budgets.
        var result = await RequestDownloadOnceAsync(file.Id, ct);
        var entry = result.Descendants().FirstOrDefault(e => e.Name.LocalName == "FileEntry" && Text(e, "id") == file.Id)
            ?? throw new IOException("Brak dostępu do fragmentu na Chomikuj.");
        if (Text(entry, "name") != file.Name)
            throw new InvalidDataException("Chomikuj zwrócił inny plik niż żądany fragment kopii.");
        return entry;
    }

    private static Uri DownloadUri(XElement entry)
    {
        string url = Text(entry, "url");
        if (string.IsNullOrEmpty(url))
            throw new IOException("Chomikuj nie udostępnił pobrania własnego pliku. Sprawdź konto i limit transferu; program nie akceptuje opłat automatycznie.");
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            throw new InvalidDataException("Chomikuj zwrócił niepoprawny adres pobierania.");
        return SecureDownloadUri(uri);
    }

    private async Task<HttpResponseMessage> OpenDownloadAsync(Uri uri, HttpMethod method, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(45));
        for (int redirect = 0; redirect < 4; redirect++)
        {
            RequireServiceUri(uri);
            using var request = new HttpRequestMessage(method, uri);
            var response = await SendTransferAsync(request, method == HttpMethod.Head ? "Rozmiar pliku" : "Pobieranie", deadline.Token,HttpOperation.DownloadContent);
            if ((int)response.StatusCode is >= 300 and < 400 && response.Headers.Location is { } location)
            {
                response.Dispose();
                uri = SecureDownloadUri(location.IsAbsoluteUri ? location : new Uri(uri, location));
                continue;
            }
            if (response.StatusCode != HttpStatusCode.OK)
            {
                var error = SafeHttpError(response,HttpOperation.DownloadContent);
                response.Dispose();
                throw error;
            }
            return response;
        }
        throw new IOException("Zbyt wiele przekierowań pobierania.");
    }

    private Task<XElement> RequestFolderDownloadAsync(string id, CancellationToken ct)
        => RetryReadAsync(() => RequestDownloadOnceAsync(id, ct, folderListing: true), ct);

    private Task<XElement> RequestDownloadOnceAsync(string id, CancellationToken ct, bool folderListing = false)
    {
        RequireLogin();
        // The trusted caller selects the scope, never a server-supplied file ID.
        return CallAsync("Download", ct, folderListing ? FolderSoapLimit : SmallSoapLimit, E("token", token),
            E("sequence", E("stamp", "0"), E("part", "0"), E("count", "1")),
            E("disposition", "download"), E("list", E("DownloadReqEntry", E("id", id),
                E("agreementInfo", E("AgreementInfo", E("name", "own"))))));
    }

    private async Task<HttpResponseMessage> SendTransferAsync(HttpRequestMessage request, string operation, CancellationToken ct,HttpOperation transportOperation)
    {
        var uri = request.RequestUri!;
        RequireServiceUri(uri);
        // Only a service authority is logged: never path, query, body, token,
        // cookies or the raw exception text (which can contain a signed URL).
        string endpoint = uri.GetLeftPart(UriPartial.Authority);
        Diagnostics?.Report(operation + " HTTPS: " + endpoint);
        try { return await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct); }
        catch (OperationCanceledException error)
        {
            // Retain cancellation semantics and the request boundary, without
            // retaining an exception that may contain a signed URL.
            throw new CloudTransferCanceledException(error,transportOperation);
        }
        catch (HttpRequestException error)
        {
            string reason = error.HttpRequestError.ToString();
            for (Exception? inner = error.InnerException; inner is not null; inner = inner.InnerException)
                if (inner is SocketException socket) { reason += "/" + socket.SocketErrorCode; break; }
            throw new CloudTransportException(operation + " HTTPS: " + endpoint + " — " + reason +
                ". Operacja nie została potwierdzona.", error.HttpRequestError,error,transportOperation);
        }
    }

    private Task<XElement> CallAsync(string action, CancellationToken ct, params XElement[] values)
        => CallAsync(action, ct, SmallSoapLimit, values);

    private async Task<XElement> CallAsync(string action, CancellationToken ct, int responseLimit, params XElement[] values)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(45));
        var envelope = new XElement(Soap + "Envelope", new XAttribute(XNamespace.Xmlns + "s", Soap),
            new XElement(Soap + "Body", new XElement(Ns + action, values)));
        using var request = new HttpRequestMessage(HttpMethod.Post, Service);
        request.Headers.TryAddWithoutValidation("SOAPAction", "http://chomikuj.pl/IChomikBoxService/" + action);
        request.Content = new StringContent(envelope.ToString(SaveOptions.DisableFormatting), Encoding.UTF8, "text/xml");
        try
        {
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            if (!response.IsSuccessStatusCode) throw SafeHttpError(response,HttpOperation.SoapRequest);
            XElement doc = await ReadXmlAsync(response, deadline.Token, responseLimit);
            var result = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == action + "Result")
                ?? throw InvalidResponse("Niezgodna odpowiedź interfejsu Chomikuj.", ResponseFailureKind.SoapResultMissing, HttpOperation.SoapRequest);
            if (!Text(result, "status").Equals("Ok", StringComparison.OrdinalIgnoreCase))
            {
                // Classify only exact known responses; never surface raw server
                // messages, which may echo account names, URLs or session tokens.
                string message = Text(result, "errorMessage").Trim();
                string status = Text(result, "status");
                var failure = message.Equals("failed : requested file(s) not available", StringComparison.OrdinalIgnoreCase)
                    ? ChomikujFailure.RequestedFilesUnavailable
                    : status is "InvalidToken" or "NotLoggedIn" or "SessionExpired"
                        ? ChomikujFailure.SessionRejected : ChomikujFailure.Rejected;
                throw new ChomikujServiceException(action, failure);
            }
            return result;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw new OperationCanceledException(ct); }
        catch (OperationCanceledException) { throw new CloudReadTimeoutException(); }
        catch (HttpRequestException error) { throw new CloudTransportException("Nie udało się połączyć z Chomikuj przez HTTPS.", error.HttpRequestError,error,HttpOperation.SoapRequest); }
    }

    private static async Task<XElement> ReadXmlAsync(HttpResponseMessage response, CancellationToken ct, int limit)
    {
        await using var input = await response.Content.ReadAsStreamAsync(ct);
        using var bytes = new MemoryStream();
        byte[] buffer = new byte[16_384];
        int count;
        while ((count = await ReadBodyAsync(input, buffer, ct)) > 0)
        {
            if (bytes.Length + count > limit) throw InvalidResponse("Zbyt duża odpowiedź Chomikuj.", ResponseFailureKind.SoapBodyTooLarge, HttpOperation.SoapRequest);
            bytes.Write(buffer, 0, count);
        }
        bytes.Position = 0;
        using var reader = XmlReader.Create(bytes, new XmlReaderSettings
        { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = limit });
        return XElement.Load(reader);
    }

    public static void RequireServiceUri(Uri uri)
    {
        if (!uri.IsAbsoluteUri || uri.Scheme != "https" || !string.IsNullOrEmpty(uri.UserInfo) ||
            !(uri.IdnHost.Equals("chomikuj.pl", StringComparison.OrdinalIgnoreCase) ||
              uri.IdnHost.EndsWith(".chomikuj.pl", StringComparison.OrdinalIgnoreCase)))
            throw new IOException("Odmowa przesłania danych poza bezpieczny serwer Chomikuj HTTPS.");
    }

    // Older SOAP responses may spell a standard-port download URL as HTTP.
    // Try only its HTTPS equivalent on the SAME service host, preserving the
    // signed path/query. Never send a GET or token to the plaintext URL.
    internal static Uri SecureDownloadUri(Uri uri)
    {
        if (uri.IsAbsoluteUri && uri.Scheme == "http" && uri.Port == 80)
            uri = new UriBuilder(uri) { Scheme = "https", Port = 443 }.Uri;
        RequireServiceUri(uri);
        return uri;
    }

    private void RequireLogin() { if (string.IsNullOrEmpty(token)) throw new InvalidOperationException("Najpierw połącz konto Chomikuj."); }
    private static XElement E(string name, params object[] value) => new(Ns + name, value);
    private static string Text(XElement parent, string name) => parent.Elements().FirstOrDefault(e => e.Name.LocalName == name)?.Value ?? "";
    private static string RequiredText(XElement parent, string name) => Text(parent, name) is { Length: > 0 } text ? text : throw new InvalidDataException("Niepełna odpowiedź Chomikuj.");
    private static long ParseLength(string text) => long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out long n) && n >= 0 ? n : throw InvalidResponse("Niepoprawny rozmiar pliku Chomikuj.", ResponseFailureKind.FileLengthInvalid, HttpOperation.SoapRequest);
    private static string EscapePathPart(string part) => Uri.EscapeDataString(part).Replace("%20", "+").Replace('%', '*');
    private static IOException SafeHttpError(HttpResponseMessage response,HttpOperation operation=HttpOperation.Unknown)
    {
        TimeSpan? retryAfter = response.Headers.RetryAfter?.Delta;
        if (retryAfter is null && response.Headers.RetryAfter?.Date is { } date)
            retryAfter = date - DateTimeOffset.UtcNow;
        return new CloudHttpException(response.StatusCode, retryAfter,operation);
    }
    public void Dispose() { token = accountId = accountName = ""; freshEmptyFolders.Clear(); ResetWebSession(); http.Dispose(); }
}
