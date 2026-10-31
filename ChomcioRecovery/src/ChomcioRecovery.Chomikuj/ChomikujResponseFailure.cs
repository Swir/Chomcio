namespace ChomcioRecovery.Chomikuj;

public sealed partial class ChomikujClient
{
    // Preserve InvalidDataException and its non-retryable semantics. The
    // private key distinguishes adapter observations from arbitrary messages.
    private static readonly object ResponseFailureKey = new();
    public enum ResponseFailureKind
    {
        WebJsonMalformed, WebBodyTooLarge, SoapBodyTooLarge, SoapResultMissing,
        FileListMissing, FileListStructure, FileRecordStructure, FileRecordIncomplete,
        FileLengthInvalid
    }
    public sealed record ResponseFailure(ResponseFailureKind Reason, HttpOperation Operation);

    private static InvalidDataException InvalidResponse(string message,
        ResponseFailureKind reason, HttpOperation operation)
    {
        var error = new InvalidDataException(message);
        error.Data[ResponseFailureKey] = new ResponseFailure(reason, operation);
        return error;
    }

    public static ResponseFailure? GetResponseFailure(Exception error) =>
        error is InvalidDataException && error.Data[ResponseFailureKey] is ResponseFailure failure &&
        Enum.IsDefined(failure.Reason) && Enum.IsDefined(failure.Operation) &&
        failure.Operation != HttpOperation.Unknown ? failure : null;
}
