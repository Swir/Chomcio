using ChomcioRecovery.Core;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ChomcioRecovery.Chomikuj;

public sealed partial class ChomikujClient
{
    private readonly CookieContainer? webCookies;
    private string webVerificationToken = "";

    private void ResetWebSession()
    {
        webVerificationToken = "";
        if (webCookies is not null)
            foreach (Cookie cookie in webCookies.GetAllCookies()) cookie.Expired = true;
    }

    // The legacy SOAP UploadToken advertises an HTTP listener (e.g. :8084).
    // Do not guess its TLS port or send the upload key over HTTP. Request the
    // HTTPS upload URL through the flow used by Chomikuj's own web uploader.
    private async Task<CloudObject> UploadViaWebAsync(ChomikujFolder folder, string name,
        Stream input, long length, CancellationToken ct)
    {
        // Folder protection or a previous object may have opened the portal
        // session before lengthy local preparation/read-back. SOAP activity
        // does not establish that its cookies and cached form are still valid.
        // Establish one fresh portal session BEFORE requesting an address;
        // neither an address request nor an ambiguous send is retried.
        ResetWebSession();
        await EnsureWebSessionAsync(ct);
        Uri uploadUri;
        using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            deadline.CancelAfter(TimeSpan.FromSeconds(45));
            using var request = new HttpRequestMessage(HttpMethod.Post, "https://chomikuj.pl/action/Upload/GetUrl/");
            request.Headers.TryAddWithoutValidation("X-Requested-With", "XMLHttpRequest");
            request.Headers.Referrer = new Uri("https://chomikuj.pl/");
            request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["accountname"] = accountName, ["folderid"] = folder.Id,
                ["__RequestVerificationToken"] = webVerificationToken
            });
            using var response = await SendTransferAsync(request, "Adres wysyłania ze strony", deadline.Token,HttpOperation.UploadAddress);
            if (!response.IsSuccessStatusCode) throw SafeHttpError(response,HttpOperation.UploadAddress);
            using var json = await ReadWebJsonAsync(response, deadline.Token, HttpOperation.UploadAddress);
            if (!json.RootElement.TryGetProperty("Url", out var value) || value.ValueKind != JsonValueKind.String ||
                !Uri.TryCreate(value.GetString(), UriKind.Absolute, out var address))
                throw new IOException("Chomikuj nie potwierdził adresu wysyłania na własne konto (WebUploadUrl).");
            RequireServiceUri(address);
            uploadUri = address;
        }

        using var multipart = new MultipartFormDataContent("Chomcio" + Guid.NewGuid().ToString("N"));
        using var file = new StreamContent(input, 65_536);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        file.Headers.ContentLength = length;
        multipart.Add(file, "files[]", name);
        using var upload = new HttpRequestMessage(HttpMethod.Post, uploadUri) { Content = multipart };
        upload.Headers.Referrer = new Uri("https://chomikuj.pl/");
        // Do not retry an ambiguous send or treat its folder as new and empty.
        freshEmptyFolders.Remove(folder.Id);
        using var uploaded = await SendTransferAsync(upload, "Wysyłanie", ct,HttpOperation.UploadContent);
        if (!uploaded.IsSuccessStatusCode) throw SafeHttpError(uploaded,HttpOperation.UploadContent);
        using var result = await ReadWebJsonAsync(uploaded, ct, HttpOperation.UploadContent);
        if (!result.RootElement.TryGetProperty("files", out var files) || files.ValueKind != JsonValueKind.Array || files.GetArrayLength() != 1)
            throw new IOException("Chomikuj nie potwierdził pojedynczego wysłanego pliku (WebUploadResult).");
        var record = files[0];
        if (record.TryGetProperty("error", out var error) && error.ValueKind is not JsonValueKind.Null &&
            !(error.ValueKind == JsonValueKind.String && string.IsNullOrEmpty(error.GetString())))
            throw new IOException("Chomikuj zgłosił błąd wysyłania pliku (WebUploadResult).");
        string id = JsonScalar(record, "fileId");
        string returnedName = JsonScalar(record, "name");
        string returnedSize = JsonScalar(record, "size");
        if (string.IsNullOrEmpty(id) || (returnedName.Length > 0 && returnedName != name) ||
            (returnedSize.Length > 0 && (!long.TryParse(returnedSize, out long size) || size != length)))
            throw new IOException("Niezgodne potwierdzenie pliku ze strony Chomikuj.");
        // The caller independently re-downloads and compares every byte before
        // any snapshot can be reported successful; this response alone is not proof.
        return new(id, name, length);
    }

    private async Task EnsureWebSessionAsync(CancellationToken ct)
    {
        if (webVerificationToken.Length > 0) return;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(45));
        Uri uri = new("https://chomikuj.pl/chomik/chomikbox/LoginFromBox?t=" +
            Uri.EscapeDataString(token) + "&returnUrl=" + Uri.EscapeDataString(accountName));
        for (int hop = 0; hop < 6; hop++)
        {
            RequireServiceUri(uri);
            // SSO credentials and cookies stay on the site's own origin.
            if (uri.IdnHost is not ("chomikuj.pl" or "www.chomikuj.pl"))
                throw new IOException("Odmowa przekazania sesji strony poza domenę logowania Chomikuj.");
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            using var response = await SendTransferAsync(request, "Sesja strony", deadline.Token,HttpOperation.WebSession);
            if ((int)response.StatusCode is >= 300 and < 400 && response.Headers.Location is { } location)
            {
                uri = SecureDownloadUri(location.IsAbsoluteUri ? location : new Uri(uri, location));
                continue;
            }
            if (!response.IsSuccessStatusCode) throw SafeHttpError(response,HttpOperation.WebSession);
            string html = await ReadWebTextAsync(response, deadline.Token, HttpOperation.WebSession);
            foreach (Match tag in Regex.Matches(html, "<input\\b[^>]*>", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1)))
            {
                var attributes = Regex.Matches(tag.Value, "([\\w-]+)\\s*=\\s*([\"'])(.*?)\\2", RegexOptions.Singleline, TimeSpan.FromSeconds(1));
                string name = "", value = "";
                foreach (Match attribute in attributes)
                {
                    if (attribute.Groups[1].Value.Equals("name", StringComparison.OrdinalIgnoreCase)) name = WebUtility.HtmlDecode(attribute.Groups[3].Value);
                    if (attribute.Groups[1].Value.Equals("value", StringComparison.OrdinalIgnoreCase)) value = WebUtility.HtmlDecode(attribute.Groups[3].Value);
                }
                if (name == "__RequestVerificationToken" && value.Length is > 0 and < 8192)
                { webVerificationToken = value; return; }
            }
            throw new IOException("Strona Chomikuj nie udostępniła formularza dla sesji (WebSession). Połączenie SOAP nadal może działać.");
        }
        throw new IOException("Zbyt wiele przekierowań podczas łączenia sesji strony Chomikuj.");
    }

    private static string JsonScalar(JsonElement value, string key) => value.TryGetProperty(key, out var field) ?
        field.ValueKind == JsonValueKind.String ? field.GetString() ?? "" :
        field.ValueKind == JsonValueKind.Number ? field.GetRawText() : "" : "";

    private static async Task<JsonDocument> ReadWebJsonAsync(HttpResponseMessage response, CancellationToken ct, HttpOperation operation)
    {
        string text = await ReadWebTextAsync(response, ct, operation);
        try { return JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 32 }); }
        catch (JsonException) { throw InvalidResponse("Chomikuj zwrócił nierozpoznaną odpowiedź strony (WebJson).", ResponseFailureKind.WebJsonMalformed, operation); }
    }

    private static async Task<string> ReadWebTextAsync(HttpResponseMessage response, CancellationToken ct, HttpOperation operation)
    {
        await using var input = await response.Content.ReadAsStreamAsync(ct);
        using var bytes = new MemoryStream();
        byte[] buffer = new byte[16_384];
        int count;
        while ((count = await input.ReadAsync(buffer, ct)) > 0)
        {
            if (bytes.Length + count > 2 * 1024 * 1024) throw InvalidResponse("Zbyt duża odpowiedź strony Chomikuj.", ResponseFailureKind.WebBodyTooLarge, operation);
            bytes.Write(buffer, 0, count);
        }
        return Encoding.UTF8.GetString(bytes.GetBuffer(), 0, checked((int)bytes.Length));
    }
}
