# ChomcioRecovery by Swir

**v1.0.0 — szyfrowane kopie plików i folderów, przede wszystkim na Chomikuj.**

## Pobierz i uruchom

Z [Releases](https://github.com/Swir/Chomcio/releases/latest) pobierz
`ChomcioRecovery-v1.0.0-win-x64.zip`, rozpakuj **cały folder** i uruchom
`ChomcioRecovery.exe`. Paczka zawiera środowisko .NET; SDK nie jest potrzebne.
Wymagany Windows x64. Wydanie sprawdzono na Windows 11; nie deklaruje osobnej
kwalifikacji wszystkich starszych wersji Windows. Pliki nie mają podpisu
wydawcy Authenticode.

1. Połącz konto Chomikuj w programie i wybierz „Kopia na Chomikuj”.
2. Wskaż folder do ochrony. Program może utworzyć i zapamiętać klucz albo użyć
   własnego hasła/klucza ustawionego przez użytkownika.
3. **Zapisz klucz odzyskiwania poza tym komputerem.** Sam login Chomikuj nie
   wystarczy do odszyfrowania kopii po awarii lub na innym komputerze.
4. Uruchom kopię. Później wybierz ją w „Przywróć pliki” i wskaż nowe miejsce.

## Stabilny zakres v1

- Kopie i wersje plików oraz folderów na dysku i na Chomikuj.
- Szyfrowanie przed wysłaniem; sprawdzanie danych po wysłaniu i przy odtwarzaniu.
- Zapamiętywanie danych konta i klucza chronionych przez Windows dla danego
  użytkownika. Zapisane poświadczenia nie są przenośnym kluczem odzyskiwania.
- Lista kopii na koncie, pobieranie oraz odtwarzanie z zachowaniem kontroli
  integralności. Na drugim komputerze potrzebny jest również klucz kopii.
- Historia, postęp, zatrzymywanie zadań i działanie przy zegarze.
- Opcjonalne kopie codzienne i po zalogowaniu. Program musi działać w tle;
  **nie jest to usługa wykonująca kopie plików przed zalogowaniem**.
- Foldery z datą i opcjonalnym hasłem na Chomikuj. Ochrona folderu nie zastępuje
  szyfrowania danych ani zapasowego klucza.

Chomikuj jest usługą zewnętrzną. Zmiany po stronie usługi, limity konta i transfer
mogą wpływać na działanie programu. Nie zakładamy oficjalnego, gwarantowanego API
ani nielimitowanej przestrzeni. Program nie jest produktem Chomikuj.

## Obraz całego Windows: funkcja eksperymentalna

Kod obrazu Windows/VSS, kreator profilu i moduł systemowy pozostają dostępne
w źródłach, a ekran programu jest wyraźnie oznaczony jako eksperymentalny.
Moduł wymaga osobnej instalacji administratora i zatwierdzonego, dedykowanego
dysku roboczego. Obraz jest najpierw przygotowywany lokalnie; nie jest to
bezpośrednie tworzenie obrazu bez bufora na dysku.

W odizolowanych maszynach potwierdzono utworzenie obrazu, zaszyfrowany transport
przez Chomikuj, niezależne pobranie, odtworzenie na pustym dysku i uruchomienie
Windows. Test używał pomocniczego przekazania danych między maszyną a gospodarzem.
**Nie oznacza to gotowego, stabilnego procesu odzyskania dowolnego komputera
przez GUI.** Instalator dla zwykłego użytkownika, kreator nośnika ratunkowego,
interaktywne logowanie i pełny codzienny cykl systemowy wymagają dalszej pracy.
Modułu systemowego ani prywatnego nośnika Windows nie dołączamy do paczki stable.

## Budowanie i krótkie sprawdzenie

Wymagane Windows i .NET 10 SDK. W PowerShell:

```powershell
pwsh -File tools/Build-Release.ps1
pwsh -File tools/Test-Standard.ps1
```

Testy standardowe używają sztucznych danych i lokalnego transportu testowego.
Nie logują się do Chomikuj, nie tworzą obrazu systemu i nie uruchamiają VM.
Nie dodawaj do repozytorium ustawień kont, kluczy, kopii danych ani obrazów VM.

Opis zmian i granice wydania: [CHANGELOG.md](CHANGELOG.md).
