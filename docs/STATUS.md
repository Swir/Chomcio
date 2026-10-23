# Stan ChomcioRecovery

![Postęp pełnego produktu: N/A, IN PROGRESS](../assets/readme/progress-mini.svg)

**Zakres:** cały produkt — kopie plików i odzyskiwanie Windows.
**Postęp: N/A; ukończone/łącznie: N/A.** Brak zamkniętej, policzalnej listy
kryteriów całego produktu. Wydanie: **v1.0.0 Preview**.

Źródłem wartości dla obu grafik jest [project-status.json](project-status.json).
Generator nie wylicza procentu z liczby asercji, commitów ani numeru wydania.
Poniższe obszary opisują stan funkcji; nie są punktami przyjętego modelu procentowego.

## Potwierdzony zakres

- Kopie plików i folderów, szyfrowanie, kontrola integralności oraz przywracanie.
- Wcześniejsze rzeczywiste wysłanie, pobranie i odtworzenie plików z Chomikuj.
- Kompilacja GUI/CLI, testy standardowe i kontrola publikowanej paczki opisane w [VALIDATION.md](../VALIDATION.md).
- Wcześniejszy test obrazu w izolowanych VM: Windows/VSS, szyfrowany transport przez Chomikuj, pobranie, odtworzenie i start systemu. Test korzystał z pomocniczego przekazania danych między VM a gospodarzem; nie kwalifikuje pełnego procesu w produkcie.

## Co pozostaje do ukończenia

- Instalator modułu systemowego i obsługa jego uprawnień przez zwykłego użytkownika.
- Kompletny proces obrazu Windows, wysłania, niezależnego pobrania i odzyskania za pomocą dostarczonej aplikacji.
- Kreator nośnika ratunkowego USB/WinPE oraz sprawdzony proces odtworzenia na pustym dysku.
- Interaktywne logowanie w procesie systemowym i pełny codzienny cykl kopii systemu.
- Rzeczywiste testy wylogowania i restartu dla paczki; usługa kopii plików przed logowaniem nie jest ukończona.

Oznaczenie Stable wymaga ukończenia i udokumentowania tych przepływów.
Testy systemowe prowadzi się wyłącznie w izolowanych maszynach na ich własnych
dyskach. Aktualizacja README nie zmienia stanu wykonania powyższych prac.
