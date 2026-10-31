# Sprawdzenie wydania 1.0.0

## Ukończona nowa kopia i zatrzymany niezależny odczyt — 31 października 2026

Kandydat r117 został wdrożony. O 07:10 UTC jedna kontynuacja zachowanego
punktu zakończyła się sukcesem: ósmy rekord historii ma stan `Success`,
zadanie zakończyło się kodem 0, program potwierdził zapis w chmurze i zgodny
ostatni punkt. Wszystkie trzy pola oczekującej kopii zostały wyczyszczone.
Siedem wcześniejszych niepowodzeń pozostało zachowanych w tej samej kolejności.

Zakres obejmuje 2 pliki o łącznym rozmiarze 15 369 275 273 B. Produkt użył
istniejącego zaszyfrowanego eksportu, z pełną kontrolą źródła, eksportu i
pobranych bajtów oraz publikacją manifestu na końcu. Zestaw pięciu katalogów
eksportu pozostał niezmieniony; nie tworzono kolejnego obrazu ani eksportu.
Stan natywnego obrazu nadal potwierdza ukończenie z kodem 0.

Harmonogram podjął punkt przed logowaniem, po naturalnej należności na nowym
uruchomieniu Windows. Nie zmieniano ręcznie dat ani historii. Jest to
wznowienie po uruchomieniu systemu; nie zastępuje osobnego testu zadania
chmurowego pozostawionego włączonego przez restart. Wcześniejszy taki test
lokalny pozostaje ważny w swoim zakresie.

Następnie rozpoczęto niezależny odczyt na tym samym końcowym zestawie bibliotek,
do nowego katalogu, bez zasiewania plikami źródłowymi. Jedno żądanie logowania
zostało odrzucone: `ChomikujServiceException`, operacja `Auth`, wynik `Rejected`.
Nie wykonano odczytu folderu, pobrania treści ani zapisu w chmurze. Dokładna
przyczyna odmowy pozostaje nieznana. Nie ponawiano logowania w pętli.

Ukończenie wysyłania nowej kopii jest potwierdzone. Jej niezależne pobranie
i odtworzenie pozostają niezaliczone. Nadal wymagane są pełna dostarczona
ścieżka GUI/nośnika/WinRE oraz zgodność końcowej paczki i dokumentacji.
**Stable nie zostało wydane.**

## Pełna lista folderu ponad 2 MiB — 31 października 2026

Jeden rzeczywisty odczyt samych nazw na r115 zakończył się
`SoapBodyTooLarge` / `SoapRequest`. Nie pobierano treści plików i nie
wykonywano zapisów. Ujawnił konkretną bieżącą przeszkodę: pełna lista
fragmentów przekraczała wspólny limit 2 MiB dla odpowiedzi sterujących.
Oryginalna odpowiedź wcześniejszej awarii nie została zachowana, dlatego
ten wynik nie przypisuje jej automatycznie tej samej przyczyny.

Poprawka `dea62b2` daje odpowiedzi z pełną listą folderu osobny limit
64 MiB, kontrolowany zarówno w bajtach, jak i znakach XML. Pozostałe
odpowiedzi SOAP, w tym logowanie, drzewo folderów i metadane pojedynczego
pliku, nadal mają limit 2 MiB. Zakres wybiera miejsce wywołania w programie,
nie identyfikator otrzymany z serwera. Przekroczenie limitu nadal kończy
operację błędem; lista nie jest obcinana. Nie zmieniono limitów czasu,
retry, TLS, kryptografii ani sprawdzania dokładnych pobranych bajtów.

Na poprzednim runtime syntetyczna poprawna lista 3000 rekordów odtworzyła
odmowę. Na dokładnym końcowym zestawie bibliotek przeszło 27 nowych kontroli:
pełna lista z końcowymi rekordami, późniejsze dokładne długości i odczyt,
błędny rekord lub duplikat na końcu, blokada DTD, granice 64/2 MiB także
przy fałszywym nagłówku długości oraz anulowanie bez ponowienia.

Jeden rzeczywisty odczyt na poprawionej bibliotece zwrócił 2892 unikalne
nazwy: repo.json i 2891 obiektów, bez manifestu oczekującego punktu.
Wykonano po jednym żądaniu logowania, folderów i listy; zero pobierania
treści i zero zapisów. Potwierdza to usunięcie obecnej przeszkody odczytu
listy, a nie integralność ani ukończenie dużej kopii. VM pozostała wyłączona.

Kandydat r117 zachowuje Core i aplikację z r115, zmienia adapter.
Na tym etapie wdrożenie i pełna próba transferu pozostawały do potwierdzenia;
późniejszy wynik opisano w pierwszej sekcji.
Nadal nie wydano Stable; niezależne pobranie nowej kopii i pełna dostarczona
ścieżka GUI/nośnika/WinRE pozostają wymagane.

## Odrzucenie danych lub odpowiedzi podczas wznowienia — 31 października 2026

R111 wdrożono i wykonano jedną próbę tego samego oczekującego punktu z
zachowanego eksportu. Próba zakończyła się `INTEGRITY` w fazie wysyłania.
Historia nie zachowała dokładnej kontroli ani odpowiedzi, która wywołała
błąd; nie ustalono, czy dotyczył danych kopii, czy odpowiedzi serwera.
Nie potwierdzono ukończenia kopii. Siedem niepowodzeń, oczekujący punkt,
obraz i pięć eksportów zachowano. Po świeżym potwierdzeniu braku procesów
kopii i wyłączonych zadań odłączono testową sieć i normalnie wyłączono VM.

Poprawka `1e693f0` zachowuje zamkniętą kategorię `ResponseFailure` oraz
`HttpOperation` dla wybranych kontroli odpowiedzi SOAP i strony: błędnego
JSON, przekroczenia rozmiaru odpowiedzi, braku wyniku lub listy, niepoprawnej
struktury rekordów i rozmiaru pliku. Nie zapisuje treści odpowiedzi, adresów,
sekretów ani surowego wyjątku parsera. Zachowuje `InvalidDataException`,
kod `INTEGRITY` i dotychczasową odmowę ponawiania takiej operacji. Stare lub
nieoznaczone błędy pozostają bez przypisanej kategorii.

Regresja na poprzednim runtime odtworzyła utratę kategorii błędnej odpowiedzi.
Na dokładnych końcowych bibliotekach przeszło 76 nowych małych kontroli:
odrzucenie odpowiedzi, właściwa operacja, brak ponowień i ujawnienia treści,
zapis historii, zachowanie oczekującego punktu, zgodność starych rekordów
oraz poprawne pojedyncze wysłanie do syntetycznego serwera. Nie wykonano
rzeczywistych wywołań chmury ani nowej dużej próby. Core, moduł obrazowania,
kryptografia, TLS, retry i limity czasu pozostają bez zmian.

Kandydat r115 nie jest wdrożony do VM. Poprawka diagnostyki nie ustala
historycznej przyczyny i nie kwalifikuje dużej kopii. Nadal wymagane są jej
ukończenie i niezależne pobranie oraz pełna dostarczona ścieżka GUI, nośnika
i WinRE. **Stable pozostaje niewydane.**

## Wstępna lista nazw bez powtórnego pobierania — 30 października 2026

R102 wdrożono do testowej VM. Harmonogram podjął zachowany punkt przed
logowaniem, bez zmiany dat, nowego obrazu lub nowego katalogu eksportu.
Próba zatrzymała się podczas łączenia z chmurą: `TIMEOUT`, operacja
`DownloadContent`, rodzaj wyjątku `Cancellation`. Status HTTP i dokładna
przyczyna przekroczenia czasu pozostają nieznane. Sześć niepowodzeń,
oczekujący punkt i wszystkie eksporty zachowano; po świeżej kontroli
bezczynności VM wyłączono normalnie.

Analiza kodu wskazała nadmiarowy odczyt: sprawdzanie dostępności folderu
przed transferem pobierało nagłówki każdego istniejącego pliku, choć na tym
etapie potrzebna jest tylko poprawna lista nazw. Poprawka `46a406c` używa
istniejącego API listy nazw. Nie zmienia rozpoznawania odpowiedzi usługi,
ochrony folderu, ograniczenia zastępowania niedostępnego folderu ani
uwierzytelniania eksportu. Późniejszy transfer nadal odczytuje dokładne
rozmiary i porównuje pełne pobrane bajty; manifest wysyła na końcu.

Regresja na poprzednim kodzie wykazała niepotrzebny odczyt danych już podczas
łączenia. Na dokładnym zestawie końcowych bibliotek przeszło 28 nowych
kontroli: lista 128 rekordów bez pobierania, późniejsze rzeczywiste długości
zamiast wskazówek SOAP, pełne bajty i odmowa uciętej odpowiedzi, ochrona
folderu, błędy usługi, zachowanie profilu oraz anulowanie. Wszystkie odpowiedzi
były syntetyczne; nie wykonywano żądań do konta chmurowego.

Zmienia się wyłącznie biblioteka aplikacji; Core, adapter, moduł obrazowania,
TLS, limity czasu i ponawianie pozostają bez zmian. Usunięcie powtórnego
odczytu nie wyjaśnia przyczyny awarii sieci i nie kwalifikuje dużego transferu.
Kandydat r111 nie został jeszcze wdrożony. Nadal wymagane są ukończenie nowej
dużej kopii, niezależne pobranie i pełna dostarczona ścieżka GUI/nośnika/WinRE.
Stable nie zostało wydane.

## Wznowienie z zachowanego eksportu — 30 października 2026

Ograniczony odczyt metadanych dysku testowego potwierdził pięć zachowanych
eksportów tego samego punktu: łącznie około 76,85 GB logicznych rozmiarów
plików. Wolne miejsce wynosiło około 11,34 GB. Nie usuwano danych, nie
czytano treści dużej kopii i nie wykonywano następnego eksportu. Same nazwy
i rozmiary nie potwierdzają integralności tych pięciu katalogów.

Poprawka `c69f062` pozwala zadaniu użyć istniejącego opublikowanego eksportu.
Nowa ścieżka Core wiąże jego konfigurację z kluczem źródłowego sejfu oraz
porównuje dokładny zaszyfrowany manifest wybranego punktu. Przed odczytem
listy w chmurze weryfikuje pełną zawartość źródła i eksportu. Każdy fragment
jest ponownie uwierzytelniany z dokładnie tego bufora, który trafi do transportu.
Przekierowane ścieżki są odrzucane; katalogi na Windows pozostają przypięte
na czas operacji. Nie wysyła się dodatkowych, niepowiązanych rekordów.
Porównanie pobranych bajtów i publikacja manifestu na końcu są zachowane.
Uszkodzony wybrany eksport zatrzymuje zadanie bez tworzenia zastępczego
eksportu ani kasowania plików. Dotychczasowe API nowego eksportu nadal
odmawia użycia istniejącego katalogu docelowego.

Na dokładnej kombinacji bibliotek kandydata r102 przeszło 66 nowych kontroli:
wznowienie po ponownym otwarciu ustawień, zachowanie historii i daty punktu,
brak kolejnego eksportu, niezależne pobranie i odtworzenie, obcy sejf, uszkodzone
lub brakujące rekordy, zmiana po weryfikacji i po pobraniu do bufora, dodatkowe
rekordy, odmowa dowiązań i podmiany katalogu, anulowanie oraz zły odczyt z chmury.
Przeszło też 29 kontroli faz i diagnostyki przerwania oraz 11 prób gotowego CLI
z nową biblioteką Core. Użyto sztucznych danych na D: i transportu w pamięci,
bez rzeczywistego konta chmurowego i bez uruchamiania VM.

R102 zmienia aplikację i Core (także kopię Core używaną przez CLI).
Adapter chmurowy, moduł obrazowania, kryptografia, limity czasu i zasady
ponawiania żądań pozostały bez zmian. Nie powtarzano Cloud150/Studio14 ani
wcześniejszych prób systemowych. Po tych kontrolach R102 wdrożono do VM;
wynik późniejszej próby opisano powyżej. Duża kopia pozostaje niedokończona,
a historyczna przyczyna poprzedniego przekroczenia czasu nie jest
ustalona. Testy syntetyczne nie kwalifikują dużego transferu ani pełnej ścieżki
GUI/nośnika/WinRE. Stable nadal nie zostało wydane.

## Faza odczytu listy i diagnostyka przekroczenia czasu — 30 października 2026

Kandydat r90 został wdrożony w testowej VM. Harmonogram przed logowaniem
podjął ten sam zachowany punkt kopii na podstawie nowego uruchomienia Windows,
bez ręcznej zmiany dat i bez nowego obrazu. Próba zakończyła się `TIMEOUT`;
w historii zachowano pięć niepowodzeń. Zapisana faza lokalnej kontroli nie
rozstrzyga, która operacja zawiodła: kod pozostawiał ją widoczną podczas
późniejszego odczytu listy i rozmiarów plików z chmury. Historyczne HTTP,
operacja i przyczyna pozostają nieznane. Nie stwierdzono sukcesu uploadu.

Poprawka `b1f6778` ustawia fazę odczytu listy przed wywołaniem sieci i zapisuje
postęp transferu bez opóźnionego callbacku. Przerwanie oczekiwania we wspólnej
funkcji wysyłania żądania zachowuje zamkniętą kategorię operacji oraz liczbowy
kod wyjątku, bez surowej treści, adresu i wewnętrznego wyjątku. Kategoria
`Cancellation` opisuje rodzaj wyjątku, nie ustaloną przyczynę awarii sieci.
Nie klasyfikuje to wstecz historycznych błędów ani wszystkich możliwych
przerw po otrzymaniu nagłówków. Anulowanie przez użytkownika nadal oznacza
anulowanie; polityka ponawiania odczytów i odmowa ponawiania zapisów są zachowane.

Nowy test odtworzył mylącą fazę na bibliotekach r90. Na dokładnym runtime
r99 przeszło 29 krótkich kontroli faz, metadanych, anulowania i zachowania
jednego niedokończonego punktu oraz 66 kontroli historii błędów. Użyto
wyłącznie sztucznych danych i odpowiedzi HTTP. Nie powtarzano pełnych zestawów.
Paczka r99 zawiera 676 sprawdzonych plików: zmieniono cztery DLL/PDB aplikacji
i adaptera oraz dwa dokumenty, pozostałe 670 plików są identyczne z r90.
Core i moduł obrazowania pozostają identyczne. R99 nie wdrożono jeszcze do VM.

Świeży odczyt po niepowodzeniu potwierdził brak procesów kopii, wyłączone
zadania, ukończony obraz i zachowany punkt. Na dysku roboczym pozostało około
11,34 GB, mniej niż rozmiar kolejnego pełnego eksportu. Po kontroli bezczynności
odłączono tylko testowy adapter i normalnie wyłączono VM. Nie usuwano kopii,
eksportów ani kluczy. Poprawa diagnostyki nie kończy nowej dużej kopii;
jej ukończenie, niezależny odczyt i pełna ścieżka użytkownika nadal blokują Stable.

## Sesja strony przed wysłaniem fragmentu — 30 października 2026

Ograniczona próba aktywnej sesji przeszła 19 odczytów folderu przez trzy godziny.
Następnie zarówno ta sesja, jak i nowe logowanie otrzymały poprawny adres HTTPS
przy HTTP 200. Wysyłanie zawartości było zablokowane. Osobna sesja pozostawiona
bez odczytów została wcześniej odrzucona przy odczycie folderu; jej raport nie
zachował dokładnej kategorii odmowy. Wyniki nie ustalają historycznej przyczyny
WebUploadUrl i nie potwierdzają ukończenia dużej kopii.

Przegląd rzeczywistej ścieżki wykazał istotną różnicę: ochrona folderu otwiera
sesję strony przed lokalnym przygotowaniem i kontrolą istniejących fragmentów.
Próba aktywnej sesji otwierała ją dopiero na końcu. Produkt ustanawia teraz
świeżą sesję strony przed każdym nowym żądaniem adresu wysyłania. Nie ponawia
żądania adresu ani niejednoznacznego wysłania zawartości.

Krótki test protokołu odtworzył WebUploadUrl na poprzednim kodzie po
syntetycznym wygaśnięciu sesji strony przy nadal działającym SOAP.
Po poprawce przeszły 33 kontrole: wznowienie po ochronie folderu i odczytach,
niezależny odczyt wysłanych bajtów, odmowa sesji/adresu, brak lub niebezpieczny
adres, niejednoznaczne wysłanie oraz anulowanie. HTTPS i ochrona folderu
pozostają wymagane. To lokalny test mechanizmu, nie dowód przyczyny wcześniejszej
awarii ani rzeczywistego ukończenia dużego uploadu po poprawce.

Na dokładnej kombinacji bibliotek kandydata r90 ponownie przeszły te
33 kontrole oraz 66 krótkich kontroli historii błędów i granic ponawiania.
Nie powtarzano pełnych zestawów Cloud150/Studio14. ZIP r90 ma 676 sprawdzonych
plików: zmieniły się tylko DLL/PDB adaptera Chomikuj, pozostałe 674 pliki,
w tym główna aplikacja, Core i moduł obrazu, są identyczne z r64.
Kod adaptera: e5e3f31. W chwili tej kwalifikacji paczka nie była jeszcze
wdrożona do VM. Późniejsze wdrożenie i nieudana próba zachowanej dużej kopii
są opisane w sekcji powyżej; transfer nadal wymaga kwalifikacji.

## Naturalne wznowienie dużej kopii — 30 października 2026

Zadanie gotowego EXE r64 przed logowaniem podjęło zachowany punkt kopii w nowym
dniu, bez ręcznej zmiany daty i bez ponownego tworzenia obrazu Windows.
Transfer zakończył się niepowodzeniem. Zapisana bezpieczna kategoria wskazuje
brak poprawnego adresu wysyłania (WebUploadUrl); dokładna odpowiedź i przyczyna
tej odmowy nie zostały zachowane. Nie oznacza to potwierdzonej awarii dysku ani
ustalonego problemu z czasem życia sesji.

Osobna, krótka diagnostyka z nową sesją otrzymała adres HTTPS przy HTTP 200.
Zablokowano wysyłanie zawartości i nie utworzono pliku. Odczyt folderu nadal
wykazał 2382 fragmenty i konfigurację bez końcowego manifestu. To nie jest
dowód pełnego wysłania ani niezależnej integralności kopii. Obraz, klucze,
częściowy transfer i cztery wpisy niepowodzeń zostały zachowane.

Po sprawdzeniu braku zapisów odłączono wyłącznie testowy adapter i normalnie
wyłączono VM. Wcześniejsze zaliczone próby pozostają ważne w swoim zakresie;
nowa duża kopia oraz pełna ścieżka użytkownika nadal blokują Stable.

## Lokalny harmonogram pozostawiony przez restart — 30 października 2026

Gotowy EXE kandydata r64, kod `ca16b7b`, wykonał automatyczną kopię jednego
sztucznego pliku (50 bajtów) na zwykłym koncie Windows, bez logowania użytkownika.
Zadanie zarejestrowano produkcyjnym mechanizmem i pozostawiono włączone przez
normalne wyłączenie i ponowne uruchomienie VM. Nie uruchamiano EXE ręcznie.

| Kontrola | Wynik |
| --- | --- |
| Nowy start Windows i brak zalogowanego użytkownika | PASS |
| Jeden wpis sukcesu w historii, kod zadania 0, jeden plik / 50 bajtów | PASS |
| Aktualizacja zapisanego identyfikatora uruchomienia Windows | PASS |
| Weryfikacja zaszyfrowanej kopii na zwykłym koncie, w sesji 0 | PASS |
| Zachowanie ustawień i ukończonego obrazu wcześniejszej kopii systemowej | PASS |
| Normalne wyłączenie VM po weryfikacji | PASS |

Próba używała dokładnego runtime kandydata: 227 plików głównego programu
zweryfikowano przy przygotowaniu; moduł obrazowania pozostał niezmieniony.
Sieć była odłączona. Pomocnik testowy przygotował osobny profil i sprawdził
wynik; właściwą kopię wykonało zadanie dostarczonego EXE. Nie był to test
interaktywnego ustawiania profilu przez GUI.

Osobna duża kopia Windows nadal ma zachowany ukończony obraz i częściowy
transfer, lecz nie ma potwierdzonego końcowego manifestu w chmurze.
Powyższy wynik nie potwierdza jej ukończenia ani pełnej ścieżki USB/WinRE.
Publiczne wydanie pozostaje Preview.

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
