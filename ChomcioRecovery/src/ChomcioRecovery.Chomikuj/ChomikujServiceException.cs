namespace ChomcioRecovery.Chomikuj;

public enum ChomikujFailure
{
    RequestedFilesUnavailable,
    SessionRejected,
    Rejected
}

/// <summary>Only locally defined classifications, never raw server text or credentials.</summary>
public sealed class ChomikujServiceException : IOException
{
    public string Operation { get; }
    public ChomikujFailure Failure { get; }

    internal ChomikujServiceException(string operation, ChomikujFailure failure)
        : base(MessageFor(operation, failure))
    {
        Operation = operation;
        Failure = failure;
    }

    private static string MessageFor(string operation, ChomikujFailure failure) => failure switch
    {
        ChomikujFailure.RequestedFilesUnavailable => "Chomikuj: brak dostępnych plików w żądaniu " + operation +
            " (RequestedFilesUnavailable). Nie potwierdzono pustego folderu ani kompletności kopii.",
        ChomikujFailure.SessionRejected => "Chomikuj odrzucił sesję podczas " + operation + ". Połącz konto ponownie.",
        _ when operation == "Auth" => "Chomikuj odrzucił logowanie (Auth/Rejected). Sprawdź dane konta.",
        _ => "Chomikuj odrzucił operację " + operation + " (Rejected). Wynik nie został potwierdzony."
    };
}
