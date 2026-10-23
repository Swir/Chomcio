# Utrzymanie README

Wzór: [SWIR README PRO v2](https://github.com/Swir/Swir/blob/main/SWIR-README-STANDARD.md)
oraz [SWIR Progress SVG PRO](https://github.com/Swir/Swir/blob/main/SWIR-PROGRESS-STANDARD.md).
Publikacja spójnego pakietu zmian zgodnie z [SWIR Development Cadence](https://github.com/Swir/Swir/blob/main/SWIR-DEVELOPMENT-CADENCE.md).

- Baner adaptuje `Swir/Swir/templates/readme/hero-template.svg`, zachowując rodzinę kolorów i własną ikonę aplikacji.
- `screenshots/ustawienia.png` to rzeczywisty ekran z odizolowanego testu GUI paczki 1.0.0. Nie zawiera danych konta. Zastępuj go wyłącznie aktualnym, sprawdzonym zrzutem, nigdy makietą.
- `project-status.json` jest jedynym źródłem zakresu, licznika i statusu dla grafik postępu. Nieznany mianownik oznacza **N/A**. Zmiana dokumentacji nie zwiększa postępu produktu.
- `progress-template.svg` to wzorzec oznaczony **TEMPLATE / NOT PROJECT DATA**; nie osadzaj go jako rzeczywistego wyniku.

Deterministyczne generowanie i kontrola (Python 3, tylko biblioteka standardowa):

```powershell
python tools/Generate-ReadmeAssets.py
python tools/Generate-ReadmeAssets.py --check
```

Generator używa istniejącej ikony projektu, tworzy samodzielne SVG i nie łączy się
z siecią. Po zmianie danych sprawdź także zwykły opis w README i STATUS.md oraz
wygląd grafik. Kontrola dokumentacji nie uruchamia testów aplikacji ani chmury.
