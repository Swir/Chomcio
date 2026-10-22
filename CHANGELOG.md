# Historia wydań

## 1.0.0 — 2026-10-22

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

**Zakres stable:** pliki i foldery. Kopia całego Windows jest eksperymentalna,
wyraźnie oznaczona w aplikacji; moduł wykonawczy pozostaje w źródłach.
Brak gotowego kreatora USB ratunkowego i usługi kopii plików przed logowaniem.
Interfejs używa WinForms; migracja do WinUI 3 nie jest częścią v1.

Wydanie korzysta z wcześniejszych rzeczywistych prób wysyłania, pobierania
i porównania odtworzonych plików na Chomikuj oraz testu obrazu Windows
w izolowanych VM. Krótkie kontrole końcowej paczki opisuje `VALIDATION.md`.
