namespace ChomcioRecovery.Chomikuj;

public enum ChomikujReadFailure { TlsRecord, TlsSecurity }

/// <summary>A safe classification of an HTTPS body-read failure, without raw network exception text.</summary>
public sealed class ChomikujReadException : IOException
{
    public ChomikujReadFailure Failure { get; }

    public ChomikujReadException(ChomikujReadFailure failure) : base(failure switch
    {
        ChomikujReadFailure.TlsRecord => "Przerwano szyfrowany odczyt z Chomikuj. Niepełne dane odrzucono; kopia pozostaje niepotwierdzona.",
        ChomikujReadFailure.TlsSecurity => "Nie potwierdzono bezpieczeństwa połączenia HTTPS z Chomikuj. Pobieranie zatrzymano.",
        _ => throw new ArgumentOutOfRangeException(nameof(failure))
    }) => Failure = failure;
}
