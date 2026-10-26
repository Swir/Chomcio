# Automatyczne kopie przy zamkniętym programie

Funkcja znajduje się w kandydacie r8; publiczny ZIP v1.0.0 Preview jej nie zawiera.

1. Rozpakuj cały program do stałego folderu na lokalnym dysku.
2. W ustawieniach swojej kopii zaznacz kopię codzienną lub po uruchomieniu
   komputera. Pozostaw zapamiętanie klucza i konta włączone.
3. Otwórz **Ustawienia → Kopie przy zamkniętym programie**.
4. Podaj hasło bieżącego konta Windows i wybierz **Włącz pracę w tle**.
   To hasło Windows, nie PIN ani hasło Chomikuj. Pole jest czyszczone po próbie.

Windows przechowuje poświadczenie zadania. Chomcio nie zapisuje tego hasła
w ustawieniach ani logach. Po zmianie hasła Windows ponownie włącz pracę w tle.
Konto musi pozwalać na logowanie zadania przy użyciu hasła; ograniczenia konta
lub zasady organizacji mogą uniemożliwić rejestrację.

Komputer musi być włączony. Zadanie sprawdza zapisany harmonogram co dwie minuty;
nie wybudza komputera ze snu. Kopia po starcie uruchamia się, gdy Windows
udostępni Harmonogram i konto, więc nie musi ruszyć natychmiast. Kopia
„po zalogowaniu” pozostaje obsługiwana przez zwykły autostart aplikacji.

Wyniki pojawiają się w historii po otwarciu Chomcio. Przy trwającej kopii
zobaczysz postęp i możliwość jej zatrzymania. Program poczeka na bezpieczne
zakończenie zapisu. GUI i proces w tle nie edytują równocześnie ustawień.
Przed aktualizacją zakończ starszą wersję programu; zachowaj cały nowy folder
w lokalizacji wskazanej podczas włączania zadania.

**Wstrzymaj automatyczne kopie** blokuje również pracę w tle.
**Wyłącz pracę w tle** usuwa tylko własne zadanie Harmonogramu; zachowuje
kopie, profile i klucze. Trwającą kopię najpierw bezpiecznie zatrzymaj.

Potwierdzone testy i ograniczenia opisuje [VALIDATION.md](../VALIDATION.md).
Kopia plików w tle nie jest kwalifikacją pełnego odzyskiwania Windows.
