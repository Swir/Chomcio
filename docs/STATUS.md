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

- Kwalifikacja całego przejścia przez interaktywny kreator Windows na zwykłym koncie; instalator EXE i odczyt planu pod tokenem zwykłego użytkownika przeszły test VM.
- Kompletny proces obrazu Windows, wysłania, niezależnego pobrania i odzyskania za pomocą dostarczonej aplikacji.
- Kreator nośnika ratunkowego USB/WinPE oraz sprawdzony proces odtworzenia na pustym dysku.
- Interaktywne logowanie w procesie systemowym i pełny codzienny cykl kopii systemu.
- Rzeczywista kopia do chmury po wylogowaniu i restarcie; start samego modułu obrazu po restarcie przeszedł test VM. Usługa kopii plików przed logowaniem nie jest ukończona.

Oznaczenie Stable wymaga ukończenia i udokumentowania tych przepływów.
Testy systemowe prowadzi się wyłącznie w izolowanych maszynach na ich własnych
dyskach. Aktualizacja README nie zmienia stanu wykonania powyższych prac.

## Zmiany przygotowane 26 października 2026 — jeszcze niewydane

- Naprawiono obsługę długich ścieżek przy zapisie, eksporcie i odtwarzaniu.
  Po poprawce pełny test Core zakończył się 673 kontrolami PASS; sprawdzono
  także zachowanie odmowy nadpisania istniejących danych.
- Paczka zawiera moduł obrazowania. Kreator uruchamia instalację EXE ze zgodą
  administratora, bez zmiany zasad wykonywania skryptów PowerShell.
- Instalacja EXE w osobnej VM, odczyt planu pod tokenem zwykłego użytkownika,
  odmowa powtórnego nadpisania instalacji i start modułu po rzeczywistym
  restarcie VM przeszły kontrolę. Moduł jest zadaniem startowym SYSTEM
  w Harmonogramie zadań; ten test nie wykonał automatycznej kopii do chmury.
- Pobieranie obrazu na innym komputerze korzysta z wybranego miejsca roboczego
  i rozpoznaje kopię Windows bez konfiguracji dawnego modułu.
- Program sprawdza i przygotowuje `WindowsImageBackup` na dysku NTFS do WinRE,
  z kontrolą zapisanych bajtów, anulowaniem i odmową nadpisania starszego obrazu.
- Dodano przewodnik z przyciskiem systemowego kreatora nośnika i instrukcją
  offline. Krótki test interfejsu zastępował uruchomienie Windows atrapą.
  Utworzenie USB, start z USB i odzyskanie Windows przez ten przewodnik
  **pozostają nieprzetestowane**. Nie jest to własny generator WinPE.
- Przygotowanie zachowanego, niezależnie pobranego obrazu laboratoryjnego
  (14,69 GiB po rozpakowaniu) przeszło kontrolę. Nie oznacza to nowego testu
  uruchomienia odtworzonego Windows ani gotowości całego produktu.

Te zmiany nie zmieniają statusu publicznego wydania v1.0.0 Preview.
