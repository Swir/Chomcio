# Sprawdzenie wydania 1.0.0

Data: 22 października 2026. Środowisko: Windows 11 x64, .NET SDK 10.0.402.

| Kontrola | Wynik |
| --- | --- |
| Samodzielna paczka Windows x64: GUI i CLI | PASS |
| Core — pliki, szyfrowanie, integralność, ścieżki i anulowanie | PASS, 662 asercje |
| Cloud — deterministyczny transport testowy, protokół i błędy | PASS, 126 asercji |
| Studio — profile, zapisane klucze, harmonogram i interfejs | PASS, 229 asercji |
| Uruchomienie faktycznie publikowanego CLI | PASS, 11 kontroli |

Sprawdzenie opublikowanego CLI wykonało kopię dwóch małych sztucznych plików
(w tym nazwy Unicode) i pustego katalogu, weryfikację, odtworzenie i porównanie
SHA-256, odmowę nadpisania celu, odmowę błędnego hasła oraz eksport i niezależne
otwarcie zaszyfrowanego sejfu. Numer wersji EXE: `1.0.0.0`.

Testy końcowe nie uruchamiały VM, nie tworzyły obrazu systemu, nie używały
konta Chomikuj ani danych użytkownika. Pełne logowanie, rzeczywiste wysłanie,
pobranie i porównanie odtworzonych plików były sprawdzone wcześniej w toku
prac nad tym samym rdzeniem i integracją. 89 plików źródłowych/projektów
pozostało bez zmian względem poprzednio sprawdzonego drzewa; zmiany wydania
dotyczą numeru wersji, oznaczeń GUI i dokumentacji.

W teście natywnym wykonano pięć kontroli dowiązań. Przypadek krótkiej nazwy
8.3 pominięto, ponieważ środowisko nie udostępniało takiego aliasu.

**Nie zaliczamy jako części stable:** odzyskiwania dowolnego całego komputera,
instalatora modułu systemowego dla zwykłego użytkownika, kreatora USB ratunkowego,
usługi przed zalogowaniem ani rzeczywistego cyklu wylogowania/restartu dla tej
paczki. Obraz Windows jest oznaczony jako eksperymentalny. Wcześniejszy test
obrazu w izolowanych VM nie zastępuje kwalifikacji tych przepływów.

Źródła zawierają jedynie mały, publiczny wzorzec testowy zgodności formatu;
jego `PasswordTestOnly` dotyczy wyłącznie sztucznych danych. Paczka programu
nie zawiera poświadczeń, ustawień kont, kluczy użytkownika, kopii jego plików,
dysków VM ani nośników instalacyjnych Windows.
