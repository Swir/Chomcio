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
- Nowy tryb bez okna: mała kopia do Chomikuj, niezależne pobranie i porównanie
  odtworzonych plików z gotowego EXE. Osobno: lokalne kopie przed logowaniem
  i po rzeczywistym restarcie VM na zwykłym koncie Windows.
- Kompilacja GUI/CLI, testy standardowe i kontrola publikowanej paczki opisane w [VALIDATION.md](../VALIDATION.md).
- Wcześniejszy test obrazu w izolowanych VM: Windows/VSS, szyfrowany transport przez Chomikuj, pobranie, odtworzenie i start systemu. Test korzystał z pomocniczego przekazania danych między VM a gospodarzem; nie kwalifikuje pełnego procesu w produkcie.
- 27 października: drugi obraz przeszedł produkcyjne wysłanie, wznowienie niezależnego
  pobierania i przygotowanie odzyskiwania. Po odtworzeniu na pustym dysku Windows
  uruchomił się z odłączoną kopią i ISO; pliki, syntetyczne programy i ustawienia
  zgadzały się. VM wyłączono normalnie. Ta próba używała prywatnego WinRE
  i sterowania laboratoryjnego; nie zastępuje kwalifikacji przewodnika użytkownika.
- 30 października: gotowy EXE kandydata r64 wykonał lokalną kopię przed
  logowaniem po rzeczywistym restarcie z pozostawionym włączonym zadaniem.
  Jeden plik / 50 bajtów, historia sukcesu, kod zadania 0 i weryfikacja
  zaszyfrowanej kopii na zwykłym koncie przeszły. Nie powtarzano obrazu Windows;
  ustawienia i dane dużej kopii pozostały zachowane. Szczegóły w [VALIDATION.md](../VALIDATION.md).

## Co pozostaje do ukończenia

Aktualizacja 30 października: próba zachowanej dużej kopii po poprawce sesji
strony zakończyła się przekroczeniem czasu. Dokładna operacja i przyczyna
pozostają nieznane. Poprawiono wskazywanie fazy odczytu listy i bezpieczne
zapisywanie kategorii przerwanego żądania; 29 nowych krótkich kontroli oraz
66 kontroli historii błędów przeszło na runtime kandydata r99. Nie jest to
zaliczenie dużego transferu. Obraz, niedokończona kopia i historia są zachowane,
a VM normalnie wyłączona. Odczyt metadanych potwierdził pięć zachowanych
eksportów zajmujących łącznie około 76,85 GB według logicznych rozmiarów plików.
Poprawka `c69f062` pozwala bezpiecznie wznowić z istniejącego eksportu po
sprawdzeniu jego powiązania ze źródłem i pełnej integralności; każdy fragment
jest uwierzytelniany ponownie przed użyciem. R102 przeszedł 66 nowych kontroli
wznowienia, 29 kontroli diagnostyki i 11 prób CLI na sztucznych danych.
Nie kasowano wcześniejszych eksportów ani nie osłabiano porównania pobranych
bajtów. R102 wdrożono do VM, lecz następna próba zakończyła się `TIMEOUT`
podczas łączenia, z operacją `DownloadContent`. Przyczyna sieciowa pozostaje
nieznana; dane i sześć niepowodzeń zachowano, VM wyłączono normalnie.
Poprawka `46a406c` usuwa powtórne pobieranie nagłówków na etapie sprawdzania
dostępności folderu, wykorzystując tam listę nazw. Pełna kontrola rozmiarów,
integralności eksportu i pobranych bajtów w transferze pozostaje wymagana.
Przeszło 28 nowych kontroli syntetycznych na dokładnych końcowych bibliotekach.
Aktualizacja 31 października: r111 wdrożono; jedna próba zachowanego punktu
zakończyła się `INTEGRITY` podczas wysyłania. Dokładna kontrola i przyczyna
nie zostały zapisane; sam kod nie rozstrzyga między niezgodnością danych
a błędną odpowiedzią serwera. Dane i siedem niepowodzeń zachowano, VM
wyłączono normalnie po potwierdzeniu bezczynności. Poprawka `1e693f0` dodaje
bezpieczną kategorię wybranych odrzuconych odpowiedzi i operację; 76 nowych
kontroli syntetycznych przeszło na dokładnych końcowych bibliotekach.
Kandydat r115 nie został wdrożony. Nie ponawiano dużej kopii dla diagnostyki.
Następny odczyt samych nazw ujawnił konkretną bieżącą przeszkodę:
`SoapBodyTooLarge`, czyli pełną listę przekraczającą limit 2 MiB. Poprawka
`dea62b2` oddziela ograniczoną do 64 MiB listę folderu od małych odpowiedzi
SOAP; pozostałe limity i weryfikacja danych pozostają zachowane. Przeszło
27 nowych kontroli syntetycznych. Poprawiona biblioteka odczytała następnie
2892 unikalne nazwy bez pobierania treści i zapisów, nadal bez manifestu
oczekującej kopii. To potwierdza odczyt listy, nie ukończenie kopii.
Kandydat r117 został następnie wdrożony. 31 października o 07:10 UTC
kontynuacja tej samej kopii zakończyła się sukcesem: 2 pliki, 15 369 275 273 B,
potwierdzenie chmury, kod zadania 0, zgodny ostatni punkt i trzy wyczyszczone
pola oczekiwania. Zachowano siedem wcześniejszych porażek i ten sam zestaw
pięciu eksportów. Nie utworzono nowego obrazu ani kolejnego eksportu.
Niezależne pobranie zatrzymało się na jednym odrzuconym logowaniu
(`Auth` / `Rejected`), przed odczytem folderu lub pliku. Przyczyna odmowy
pozostaje nieznana; nie wykonywano ponowień w pętli.
Szczegóły i granice dowodów w [VALIDATION.md](../VALIDATION.md).

- Kwalifikacja całego przejścia przez interaktywny kreator Windows na zwykłym koncie; instalator EXE i odczyt planu pod tokenem zwykłego użytkownika przeszły test VM.
- Kompletny proces obrazu Windows, wysłania, niezależnego pobrania i odzyskania za pomocą dostarczonej aplikacji.
- Przewodnik nośnika ratunkowego USB/WinRE i odzyskanie przez dostarczoną ścieżkę użytkownika; odtworzenie na pustym dysku zostało już potwierdzone laboratoryjnie.
- Interaktywne logowanie w procesie systemowym i pełny codzienny cykl kopii systemu.
- Pełny cykl zadania chmurowego pozostawionego włączonego przez restart.
  Lokalny test takiego zadania jest zaliczony. Nowa kopia chmurowa ukończyła
  wznowienie przed logowaniem po uruchomieniu Windows; zakresów tych prób
  nie należy utożsamiać.
- Niezależne pobranie i odtworzenie nowej kopii systemowej. Wysyłanie jest
  ukończone i potwierdzone przez produkt; osobny odczyt nadal wymaga zaliczenia.

Próba naturalnego wznowienia 30 października zatrzymała się na braku poprawnego
adresu wysyłania. Krótka próba nowej sesji otrzymała adres, lecz nie wysyłała
pliku i nie wyjaśnia historycznej odmowy. Obraz zachowano, a późniejsze
ukończenie transferu nie ustala przyczyny tamtej awarii;
szczegóły oraz ograniczenia dowodów opisano w [VALIDATION.md](../VALIDATION.md).

Oznaczenie Stable wymaga ukończenia i udokumentowania tych przepływów.
Testy systemowe prowadzi się wyłącznie w izolowanych maszynach na ich własnych
dyskach. Aktualizacja README nie zmienia stanu wykonania powyższych prac.

## Zmiany przygotowane 26 października 2026 — jeszcze niewydane

- Dodano [kopie przy zamkniętym programie](BACKGROUND-COPIES.md) i opcję
  wykonania kopii po uruchomieniu komputera. Zadanie pracuje bez praw
  administratora; GUI i proces w tle współdzielą blokadę ustawień.
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
