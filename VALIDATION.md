# Sprawdzenie wydania 1.0.0

## Obraz r10 z Chomikuj i uruchomienie Windows — 27 października 2026

Niezależne pobranie drugiego obrazu testowego Windows zakończyło się powodzeniem.
Archiwum ma 7 986 038 825 bajtów; jego SHA-256 oraz rozmiar i SHA-256 opisu obrazu
są identyczne z eksportem źródłowej VM i potwierdzeniem wysłania. Użyto nowego
połączenia i nowego repozytorium. Wznowienie wykorzystało 1484 fragmenty wyłącznie
z wcześniejszego niezależnego pobrania, po ich uwierzytelnieniu. Lokalny oryginał
kopii nie był źródłem tych fragmentów.

| Etap | Wynik |
| --- | --- |
| Produkcyjne wysłanie z odczytem kontrolnym | PASS; zachowany wynik r8, bez ponownego wysyłania |
| Produkcyjne wznowienie i niezależne odtworzenie archiwum | PASS; r10, kod zakończenia 0 |
| Przygotowanie obrazu przez `SystemImageRecovery.PrepareAsync` | PASS; 21 plików, 16 271 077 670 bajtów, kontrola przed i po publikacji |
| Przygotowanie osobnego dysku wejściowego i prywatnego WinRE | PASS; obraz ponownie sprawdzony po kopiowaniu |
| Odtworzenie na pustym dysku | PASS; WinRE zakończył odzyskiwanie kodem 0, dysk z kopią wykluczony z odtwarzania |
| Uruchomienie odzyskanego Windows | PASS; Windows 11, kompilacja 26200, wyłącznie odzyskany dysk systemowy, odłączony dysk z kopią i ISO |
| Zgodność plików, programów i ustawień | PASS; dwa wcześniejsze pliki oraz dwa elementy nowej dziennej próby, dwa syntetyczne programy CMD i ustawienia rejestru |

Próba używała odizolowanej VM z 3 GiB RAM, włączonym Secure Boot i TPM, bez karty
sieciowej. Szyfrowanie i transport używały produkcyjnego kodu; uruchomienie WinRE
oraz porównania były sterowane narzędziami laboratoryjnymi. Sprawdzono wcześniej
utworzony obraz testowego Windows, nie nową kopię systemu gospodarza.

To dowody dotyczące konkretnej kopii syntetycznej VM. Do kwalifikacji pełnego
produktu nadal potrzebne są dostarczona ścieżka nośnika/WinRE oraz pełny codzienny
cykl systemowy do chmury przed logowaniem.
Publiczne wydanie pozostaje Preview. Poniższe sekcje zachowują historię napraw
i wcześniejszych prób; nie trzeba powtarzać ich zaliczonych zestawów bez zmiany kodu.

## Lista dużych kopii i diagnostyka — 27 października 2026

Próba r9 zatrzymała się w odczycie dokładnych rozmiarów plików, przed pobraniem
fragmentów. Raport wskazuje `CloudTransportException / Unknown`, bez HTTP ani
Retry-After; pierwotny kod Windows nie był zachowany. Nie ustalono jeszcze
konkretnej przyczyny błędu transportu. Stare 1484 fragmenty pozostają dostępne.

Wykryto zbędny pełny odczyt rozmiarów przy samym wyświetlaniu listy kopii.
Nowa ścieżka odkrywania używa wyłącznie nazw i nie potwierdza kompletności kopii.
Dokładne listowanie, kontrola długości i kryptografia podczas pobierania oraz
wysyłania pozostały bez zmian. Nieznany błąd połączenia nadal zatrzymuje próbę;
diagnostyka zachowuje teraz tylko bezpieczne kody i stałą kategorię przyczyny.

- Cloud: PASS, 150 kontroli, w tym 12 nowych dotyczących szybkiej listy,
  duplikatów, anulowania, dokładnych rozmiarów i bezpiecznej diagnostyki.
- Studio: PASS, 14 kontroli wznowienia na końcowej kompilacji Release.
- Nieznane błędy i błędy certyfikatów pozostają bez automatycznych ponowień.
  Testy sprawdzają też brak surowych wyjątków i sekretów w diagnostyce.

Same testy syntetyczne nie potwierdzały rzeczywistego pobrania dużego obrazu.
Późniejszy wynik r10 opisano powyżej. Publiczne wydanie pozostaje Preview.

## Poprawka wznowienia pobierania — 27 października 2026

Rzeczywiste wysłanie drugiego obrazu testowego Windows (7 986 038 825 bajtów)
zakończyło się z odczytem kontrolnym. Niezależne pobieranie przerwał błąd
połączenia po zachowaniu 1484 zaszyfrowanych fragmentów. Na tym etapie nie było
jeszcze potwierdzenia kompletności pobrania ani uruchomienia Windows z tej kopii.

Naprawiono brak wykorzystania częściowego pobrania: przy ponowieniu aplikacja
tworzy nowy katalog i odczytuje świeżą konfigurację oraz opis kopii z chmury.
Wcześniejsze fragmenty można wykorzystać dopiero po uwierzytelnieniu AES-GCM,
sprawdzeniu identyfikatora HMAC i długości. Brakujący lub uszkodzony fragment
jest pobierany ponownie; wcześniejsze dane pozostają niezmienione. Osobny plik
wskazujący pobranie nie przechowuje haseł i nie nadpisuje ustawień harmonogramu.

- Cloud: PASS, 138 kontroli, w tym 12 nowych kontroli wznowienia, uszkodzeń,
  nieprawidłowego fragmentu, świeżych metadanych, anulowania i braku pliku w chmurze.
- Aplikacja: PASS, 14 kontroli automatycznego wznowienia po nowej sesji,
  zgodności odtworzonych plików, zachowania starych fragmentów i ustawień,
  rozdzielenia kont/profili/kopii oraz uszkodzonego pliku wskazującego pobranie.
- Kompilacja zmienionych projektów: bez błędów i ostrzeżeń.

Były to krótkie testy syntetyczne bez konta sieciowego. Późniejsze rzeczywiste
wznowienie r10 opisano powyżej. Nie zmieniono oznaczenia publicznego wydania na Stable.

## Kandydat roboczy r8 — automatyka, 26 października 2026

Dodano osobny tryb EXE wykonywany przez Harmonogram Windows na zwykłym koncie
użytkownika, także bez interaktywnego logowania. Używa tego samego silnika kopii,
zapisanych kluczy DPAPI i historii. Wspólna blokada między sesjami chroni ustawienia
przed jednoczesnym zapisem przez GUI i proces w tle. Zadanie ma ograniczone
uprawnienia; hasło konta Windows przekazywane jest Harmonogramowi, nie do JSON.

| Kontrola | Wynik i zakres |
| --- | --- |
| Studio po dodaniu procesu w tle | PASS: 256 kontroli syntetycznych |
| Końcowy mały zestaw automatyki | PASS: 20; rzeczywista lokalna kopia/odtworzenie, blokada drugiego procesu, pauza, błąd DPAPI, brak powtórzenia w tym samym starcie, opis w GUI |
| Rejestracja przez zwykłe konto i kopia przed logowaniem w VM | PASS: zadanie Password / Limited, sesja 0, brak zalogowanego użytkownika, dwa odtworzone pliki identyczne |
| Rzeczywisty restart tej samej VM | PASS: druga kopia bez logowania, poprzednia zachowana, ponowne odtworzenie dwóch plików; zadanie testowe usunięte, VM normalnie wyłączona |
| Gotowe EXE bez okna → rzeczywisty Chomikuj → niezależne pobranie i odtworzenie | PASS: dwa sztuczne pliki, 2092 bajty, szyfrowanie, folder z datą i hasłem, zgodność bajtów, brak nowej kopii przy ponownym wywołaniu |

Próba Chomikuj działała w sesji gospodarza; **nie jest dowodem wysyłania do chmury
przed logowaniem**. Próby VM dotyczyły plików na dysku testowym i nie tworzyły
obrazu Windows. VM miała 3 GiB RAM, Secure Boot i TPM oraz brak karty sieciowej.
Nie rejestrowano zadań na gospodarzu i nie odczytywano jego dysku C jako źródła kopii.

Pierwsza próba natywna zatrzymała się przed przekazaniem hasła: narzędzie testowe
sprawdzało tożsamość klienta potoku przed odczytem jego pierwszej wiadomości.
Poprawiono protokół próby: najpierw komunikat gotowości, potem kontrola SID,
dopiero potem dane dla Harmonogramu. Hasła nie trafiły do plików, argumentów ani logów.

Po teście natywnym poprawiono wyłącznie opis opcji startowej w GUI i włączenie
zwykłego autostartu przy wybraniu tej opcji. Końcowy zestaw 20 kontroli oraz
rzeczywisty test Chomikuj używały końcowej kompilacji. CLI, worker oraz algorytmy
Core/Cloud pozostały niezmienione; zachowano ich wcześniejsze wyniki zamiast
ponawiać duży transfer i cały zestaw testów. R8 zawiera GUI, CLI i worker,
bez narzędzi laboratoryjnych, danych konta ani kopii testowych.

Publiczne wydanie nadal ma status **Preview**. Do pełnego Stable pozostają
kwalifikacja całego procesu Windows przez gotowy produkt, nośnik ratunkowy
i pełny codzienny cykl systemowy do chmury. Mały test plików ich nie zastępuje.
Obsługę nowej funkcji opisuje [automatyka w tle](docs/BACKGROUND-COPIES.md).

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
