# Historia wydań

## Niewydane — przygotowanie kopii Windows, 2026-10-26

- Dodano opcjonalną pracę przez Harmonogram Windows przy zamkniętym programie,
  także przed zalogowaniem. Zadanie działa na zwykłym koncie i odczytuje klucze
  chronione przez DPAPI. Hasła Windows nie zapisuje się w ustawieniach Chomcio.
- Dodano kopię po uruchomieniu komputera, wspólną blokadę GUI/procesu w tle
  i możliwość bezpiecznego zatrzymania kopii przed otwarciem programu.
  Potwierdzono dwie lokalne kopie przed logowaniem, rozdzielone restartem VM,
  oraz osobny mały test gotowego EXE z rzeczywistym Chomikuj.
- Naprawiono zapis i odtwarzanie w głęboko zagnieżdżonych katalogach Windows.
  Natywne operacje otrzymują pełną postać długiej ścieżki; zachowano kontrolę
  uprawnień, integralności i odmowę nadpisania istniejących danych.
- Dołączono moduł obrazowania do paczki i dodano instalację EXE z kreatora.
  Instalacja wymaga zgody administratora i pustego osobnego dysku NTFS;
  nie formatuje nośników ani nie zmienia zasad PowerShell.
- Dodano niezależne miejsce pobierania kopii Windows oraz rozpoznawanie obrazu
  na komputerze bez starego profilu i planu tworzenia kopii.
- Dodano przygotowanie sprawdzonego `WindowsImageBackup` do odzyskiwania w WinRE,
  bez nadpisywania istniejącej kopii, z anulowaniem i kontrolą integralności.
- Dodano przewodnik z wejściem do systemowego kreatora USB i zapisem instrukcji.
  Test jego interfejsu używał atrapy uruchomienia narzędzia Windows. Nie wykonano
  nim rzeczywistego utworzenia USB, startu z USB ani przywrócenia Windows.
- Wykonano testy syntetyczne nowych ścieżek i przygotowanie zachowanego obrazu
  pobranego z testowego Chomikuj. Kwalifikacja całego produktu nadal trwa.

## Korekta statusu — 2026-10-23

Wydanie 1.0.0 zmieniono na Preview. Oznaczenie całego produktu jako Stable było
przedwczesne: pełne przywracanie Windows wymagało narzędzi laboratoryjnych,
a opublikowana paczka nie zawiera modułu systemowego ani gotowego kreatora
odzyskiwania. Testy plików i folderów nie kwalifikują tych brakujących funkcji.
Dotychczasowe pliki wydania i wyniki zachowano bez zmian.

## 1.0.0 Preview — opublikowane 2026-10-23

Pierwsze wydanie dla kopii plików i folderów na dysku oraz Chomikuj.

- Ciemny interfejs, wygodny wybór folderu, konto zapamiętywane na komputerze,
  wygenerowany klucz lub własne hasło, lista kopii i historia.
- Wysyłanie zaszyfrowanych danych z odczytem kontrolnym, przywracanie bez
  cichego nadpisywania, wykrywanie brakujących i uszkodzonych elementów.
- Kopie codzienne i po zalogowaniu, działanie w zasobniku oraz zatrzymywanie zadań.
- Poprawki odczytu Chomikuj, rozmiaru plików i połączeń HTTPS, obsługi ścieżek
  Windows, publikowania plików i przerwania operacji.
- Obsługa GUID woluminu przy sprawdzaniu miejsca i tworzeniu bezpiecznych
  katalogów roboczych.

**Sprawdzony zakres paczki:** pliki i foldery. Kopia całego Windows jest eksperymentalna,
wyraźnie oznaczona w aplikacji; moduł wykonawczy pozostaje w źródłach.
Brak gotowego kreatora USB ratunkowego i usługi kopii plików przed logowaniem.
Interfejs używa WinForms; migracja do WinUI 3 nie jest częścią v1.

Wydanie korzysta z wcześniejszych rzeczywistych prób wysyłania, pobierania
i porównania odtworzonych plików na Chomikuj oraz testu obrazu Windows
w izolowanych VM. Krótkie kontrole końcowej paczki opisuje `VALIDATION.md`.
