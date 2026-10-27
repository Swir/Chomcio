using System.Net;
using System.Net.Http;

namespace ChomcioRecovery.Chomikuj;

public sealed partial class ChomikujClient
{
    // Only authenticated reads use this policy. Creating a folder, requesting
    // an upload URL and sending a file are never automatically repeated.
    private async Task<T> RetryReadAsync<T>(Func<Task<T>> read, CancellationToken ct,
        bool allowTemporaryNotFound = false)
    {
        for (int attempt = 0; ; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            try { return await read(); }
            catch (Exception error) when (attempt < 2 && IsTransientRead(error, ct, allowTemporaryNotFound))
            {
                TimeSpan delay = TimeSpan.FromSeconds(2 << attempt);
                if (error is CloudHttpException { RetryAfter: { } requested } && requested > delay)
                    delay = requested;
                Diagnostics?.Report($"Przerwa w odczycie z Chomikuj. Ponowna próba {attempt + 2}/3.");
                await Task.Delay(delay, ct);
            }
        }
    }

    private static bool IsTransientRead(Exception error, CancellationToken ct, bool allowNotFound)
    {
        if (ct.IsCancellationRequested) return false;
        // A Schannel record-decryption alert after HTTP headers invalidates
        // that response. Retry only this complete read with fresh metadata
        // and a fresh buffer; never accept its partial bytes. Certificate,
        // handshake and all other TLS failures remain non-retryable.
        if (error is ChomikujReadException body)
            return body.Failure == ChomikujReadFailure.TlsRecord;
        if (error is CloudHttpException status)
        {
            // A long server-requested cooldown is reported to the caller;
            // never cap it and retry earlier than the server permitted.
            if (status.RetryAfter > TimeSpan.FromMinutes(2)) return false;
            return status.StatusCode is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests
                or HttpStatusCode.InternalServerError or HttpStatusCode.BadGateway
                or HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout
                || (allowNotFound && status.StatusCode == HttpStatusCode.NotFound);
        }
        if (error is CloudReadTimeoutException or OperationCanceledException) return true;
        if (error is CloudTransportException wrapped)
            return IsTransientTransport(wrapped.HttpRequestError);
        return error switch
        {
            HttpRequestException e => IsTransientTransport(e.HttpRequestError),
            HttpIOException e => IsTransientTransport(e.HttpRequestError),
            _ => false
        };
    }

    private static bool IsTransientTransport(HttpRequestError error) => error is HttpRequestError.ConnectionError
        or HttpRequestError.NameResolutionError or HttpRequestError.ResponseEnded;

    private static async ValueTask<int> ReadBodyAsync(Stream stream, Memory<byte> buffer, CancellationToken ct)
    {
        try { return await stream.ReadAsync(buffer, ct); }
        catch (IOException error) when (error.InnerException is System.ComponentModel.Win32Exception native &&
            (unchecked((uint)native.NativeErrorCode) & 0xffff0000u) == 0x80090000u)
        {
            int code = ((System.ComponentModel.Win32Exception)error.InnerException!).NativeErrorCode;
            // SEC_E_DECRYPT_FAILURE is a transport alert, not a backup-key
            // failure or local filesystem permission problem. No TLS settings
            // or certificate validation callbacks are changed here.
            throw new ChomikujReadException(code == unchecked((int)0x80090330u)
                ? ChomikujReadFailure.TlsRecord : ChomikujReadFailure.TlsSecurity);
        }
    }

    private sealed class CloudReadTimeoutException() : IOException("Chomikuj nie odpowiedział w wyznaczonym czasie.");

    // Preserve classification without retaining a raw inner exception that
    // could expose a signed URL through Exception.ToString().
    private sealed class CloudTransportException : IOException
    {
        public HttpRequestError HttpRequestError { get; }
        public int? NativeErrorCode { get; }
        public int? CauseHResult { get; }
        public string? CauseKind { get; }
        internal CloudTransportException(string message,HttpRequestError error):this(message,error,null){}
        internal CloudTransportException(string message,HttpRequestError error,Exception? cause):base(message)
        {
            HttpRequestError=error;
            // Keep only bounded numeric diagnostics and fixed categories. Never
            // retain the raw exception, its message, data, URL or stack text.
            for(int depth=0;cause is not null&&depth<8;depth++,cause=cause.InnerException)
            {
                CauseHResult=cause.HResult;
                CauseKind=cause switch
                {
                    System.Net.Sockets.SocketException=>"Socket",
                    System.ComponentModel.Win32Exception=>"Windows",
                    System.Security.Authentication.AuthenticationException=>"Authentication",
                    HttpRequestException=>"Http",
                    IOException=>"IO",
                    _=>"Other"
                };
                if(cause is System.ComponentModel.Win32Exception native)NativeErrorCode=native.NativeErrorCode;
            }
        }
    }

    private sealed class CloudHttpException(HttpStatusCode code, TimeSpan? retryAfter)
        : IOException("Chomikuj: błąd HTTP " + (int)code + ". Operacja niepotwierdzona.")
    {
        internal HttpStatusCode StatusCode { get; } = code;
        internal TimeSpan? RetryAfter { get; } = retryAfter;
    }
}
