# Sprawdzenie wydania 1.0.0

## Kandydat roboczy r7 — 26 października 2026

Naprawiono błąd końcowego zapisu do zwykłej ścieżki DOS dłuższej niż 260 znaków
oraz natywnego odczytu wolnego miejsca dla takiej ścieżki. Konwersja do postaci
rozszerzonej następuje wyłącznie przy wywołaniu Windows; nie zmieniono kontroli
dowiązań, przypiętych uchwytów, uprawnień ani zakazu nadpisywania.

| Kontrola po poprawce | Wynik |
| --- | --- |
| Pełny Core na Windows, w tym 10 nowych kontroli ścieżek ponad 340 znaków | PASS: 673; natywne kontrole dowiązań 5/5 |
| Przygotowanie obrazu, anulowanie, rozpoznawanie na nowym PC i kreator profilu | PASS: testy syntetyczne zmienionych ścieżek |
| Nowy przewodnik odzyskiwania: zgoda na pusty USB, odmowa UAC, ponowne kliknięcie, instrukcja | PASS: 7 kontroli; uruchomienie narzędzia Windows zastąpione atrapą |
| Zbudowane EXE CLI r7: kopia, odtworzenie, porównanie bajtów, odmowy i niezależny eksport | PASS: 11 kontroli |

Pierwszy test przygotowania odzyskiwania ujawnił błąd Windows 206, a wąski test
długiej ścieżki wskazał dodatkowo błąd 3 w odczycie wolnego miejsca. Po poprawkach
obie ścieżki przeszły. Naprawiono też przygotowanie pustego strumienia ADS w teście:
przed sprawdzeniem jawnie obcina istniejący strumień i potwierdza długość zero.
Kod produkcyjny zachowywania Zone.Identifier nie został zmieniony.

R7 zawiera przebudowane GUI i CLI oraz niezmieniony moduł obrazowania z r5.
Nie powtarzano dużego transferu obrazu ani wcześniejszych testów transportu.
Przewodnik nie jest dowodem utworzenia USB ani odzyskania systemu: rzeczywiste
utworzenie nośnika, start z niego i pełne odzyskanie przez gotową paczkę pozostają
niepotwierdzone. Oznaczenie eksperymentalne i status Preview pozostają.

## Wcześniejsze kontrole kandydata r5 — 26 października 2026

Windows 11 x64, SDK 10.0.403, samodzielna paczka na runtime 10.0.14.
Nie opublikowano nowego Stable.

| Kontrola | Wynik |
| --- | --- |
| Core / Cloud / Studio, jeden pełny zestaw syntetyczny | PASS: 662 / 126 / 249 asercji |
| Zbudowane EXE CLI: kopia, weryfikacja, odtworzenie, odmowy | PASS: 11 kontroli |
| Zmieniony kreator i przygotowanie odzyskiwania po końcowych poprawkach | PASS |
| Natywna kontrola paczki worker EXE, również błędne manifesty i nazwy urządzeń Windows | PASS: 16 kontroli; bez instalacji na gospodarzu |
| Przygotowanie obrazu wcześniej niezależnie pobranego z Chomikuj | PASS: 14,69 GiB; kontrola zapisu przed i po publikacji |
| Instalacja worker EXE w osobnej VM, odczyt planu pod tokenem zwykłego konta, odmowa powtórnej instalacji | PASS; zasady PowerShell pozostały Restricted |
| Start zadania SYSTEM po rzeczywistym restarcie tej VM | PASS; świeży sygnał działania, bez uruchamiania kopii |

Duży test korzystał z wcześniej pobranego obrazu izolowanej VM. Nie wysyłano
go ponownie, nie tworzono obrazu dysku C gospodarza i nie wykonywano nowego
odtwarzania systemu. Późniejsze poprawki okna dotyczą postępu i czytelności
błędów; nie zmieniają sprawdzonego algorytmu przygotowania obrazu.
Nie powtarzano całych testów rdzenia i transportu po zmianie instalatora:
sprawdzono zmienione ścieżki oraz faktycznie zbudowany worker EXE.

Pierwsza próba w VM ujawniła `FileNotFoundException` podczas sprawdzania
nieistniejącego zadania Harmonogramu. Nie utworzyła katalogów instalacji ani
zadania. Po poprawieniu obsługi tego wyjątku instalacja oraz restart przeszły.
Pakiet r5 zachowuje niezmienione GUI/CLI z r4; przebudowano tylko worker.
Sprawdzenie planu używało uwierzytelnionego tokenu zwykłego użytkownika,
a nie interaktywnego zalogowania tego użytkownika. Nie zastępuje próby
całego kreatora, codziennego wysyłania obrazu i uruchomienia odzyskanego Windows.

## Historyczne wydanie Preview

Data: 22 października 2026. Środowisko: Windows 11 x64, .NET SDK 10.0.402.

Status skorygowany 23 października: **Preview**. Poniższe wyniki dotyczą
opisanego zakresu, a nie ukończenia pełnego produktu z odzyskiwaniem Windows.

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

**Nie potwierdzono gotowości:** odzyskiwania dowolnego całego komputera,
instalatora modułu systemowego dla zwykłego użytkownika, kreatora USB ratunkowego,
usługi przed zalogowaniem ani rzeczywistego cyklu wylogowania/restartu dla tej
paczki. Obraz Windows jest oznaczony jako eksperymentalny. Wcześniejszy test
obrazu w izolowanych VM nie zastępuje kwalifikacji tych przepływów.

Źródła zawierają jedynie mały, publiczny wzorzec testowy zgodności formatu;
jego `PasswordTestOnly` dotyczy wyłącznie sztucznych danych. Paczka programu
nie zawiera poświadczeń, ustawień kont, kluczy użytkownika, kopii jego plików,
dysków VM ani nośników instalacyjnych Windows.
