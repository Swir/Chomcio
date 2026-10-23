"""SWIR README assets: Python 3 standard library; no network or app tests.

Progress source: docs/project-status.json. An unweighted, verified counter is
completed / total; unknown or empty scope stays N/A. Never derive from tests.
"""
import argparse
import base64
import json
import textwrap
from decimal import Decimal, ROUND_HALF_UP
from html import escape
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets/readme"
FONT = 'font-family="Segoe UI, Arial, sans-serif"'


def metric(data):
    done, total = data["completed"], data["total"]
    if done is None and total is None:
        return None, "N/A", "N/A — " + data["unit"]
    if type(done) is not int or type(total) is not int or not 0 <= done <= total:
        raise ValueError("completed/total must both be null or valid nonnegative integers")
    if total == 0:
        return None, "N/A", "0 / 0 — " + data["unit"]
    fraction = Decimal(done) / Decimal(total)
    percent = (fraction * 100).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
    label = "<100%" if done < total and percent == 100 else f"{percent}%"
    return fraction, label, f'{done} / {total} — {data["unit"]}'


def text(x, y, value, size=18, color="#8DA8B8", extra=""):
    return f'<text x="{x}" y="{y}" {FONT} font-size="{size}" fill="{color}" {extra}>{escape(value)}</text>'


def svg(width, height, title, desc, body):
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">
<title id="title">{escape(title)}</title><desc id="desc">{escape(desc)}</desc>
<defs>
<linearGradient id="bg" x2="1" y2="1"><stop stop-color="#02050A"/><stop offset="1" stop-color="#07111C"/></linearGradient>
<linearGradient id="cyan"><stop stop-color="#0088FF"/><stop offset="1" stop-color="#62E5FF"/></linearGradient>
<pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse"><path d="M40 0H0V40" fill="none" stroke="#62E5FF" stroke-opacity=".045"/></pattern>
</defs>
<rect width="{width}" height="{height}" rx="22" fill="url(#bg)"/>
<rect width="{width}" height="{height}" rx="22" fill="url(#grid)"/>
<rect x="1" y="1" width="{width-2}" height="{height-2}" rx="21" fill="none" stroke="#62E5FF" stroke-opacity=".25"/>
{body}
</svg>
'''


def progress(data, mini=False):
    fraction, label, counter = metric(data)
    scope_label = data["project"] + " · " + data["scope"] if mini else data["scope"]
    scope = textwrap.wrap(scope_label, width=85 if mini else 95)
    title = textwrap.wrap(data["project"], width=65)
    reason = textwrap.wrap(data["reason"], width=105)
    width = 900 if mini else 1200
    height = (72 + 18 * (len(scope)-1)) if mini else 180 + 25 * (len(title)-1) + 22 * (len(scope)-1) + 18 * (len(reason)-1)
    body = []
    if mini:
        body += [text(24, 26, "POSTĘP PRODUKTU", 12, "#62E5FF"), text(24, 53, label, 25, "#F4FAFF", 'font-weight="700"')]
        for i, line in enumerate(scope):
            body.append(text(170, 23 + i*18, line, 14, "#F4FAFF"))
        body.append(text(170, height-30, f'{data["stage"]} · {counter}', 11))
        x, y, track, bar_height = 170, height-19, 700, 7
    else:
        for i, line in enumerate(title):
            body.append(text(50, 39 + i*25, line, 25, "#F4FAFF", 'font-weight="700"'))
        offset = 25 * (len(title)-1)
        for i, line in enumerate(scope):
            body.append(text(50, 67 + offset + i*22, line, 18))
        offset += 22 * (len(scope)-1)
        body.append(text(1150, 48, label, 34, "#62E5FF", 'text-anchor="end" font-weight="700"'))
        body.append(text(50, 94+offset, f'{data["stage"]} · {data["release"]}', 15, "#62E5FF"))
        body.append(text(1150, 94+offset, counter, 15, "#8DA8B8", 'text-anchor="end"'))
        x, y, track, bar_height = 50, 112+offset, 1100, 10
        for i, line in enumerate(reason):
            body.append(text(50, 151+offset+i*18, line, 16))
    dash = ' stroke-dasharray="6 6"' if fraction is None else ""
    body.append(f'<rect x="{x}" y="{y}" width="{track}" height="{bar_height}" rx="3" fill="#07111C" stroke="#245266"{dash}/>')
    if fraction:
        fill = format(fraction * track, ".6f")
        body.append(f'<clipPath id="track"><rect x="{x}" y="{y}" width="{track}" height="{bar_height}" rx="3"/></clipPath>')
        body.append(f'<rect x="{x}" y="{y}" width="{fill}" height="{bar_height}" fill="url(#cyan)" clip-path="url(#track)"/>')
    desc = f'{data["project"]}. {data["scope"]}. {label}; {counter}. {data["stage"]}. {data["reason"]}'
    return svg(width, height, data["project"] + " — " + label, desc, "\n".join(body))


def hero():
    icon = base64.b64encode((ROOT / "ChomcioRecovery/assets/ChomcioRecovery.png").read_bytes()).decode("ascii")
    body = f'''<path d="M0 260C180 220 250 300 430 258S720 214 885 248S1070 282 1200 232" fill="none" stroke="url(#cyan)" stroke-opacity=".22" stroke-width="2"/>
<path d="M860 45H1150M1010 67H1150" stroke="#62E5FF" stroke-opacity=".15"/>
<image x="56" y="56" width="208" height="208" href="data:image/png;base64,{icon}"/>
{text(300, 70, 'SWIR PROJECT', 16, '#62E5FF', 'letter-spacing="4" font-weight="700"')}
{text(296, 145, 'ChomcioRecovery', 62, '#F4FAFF', 'font-weight="700"')}
{text(300, 188, 'Szyfrowane kopie. Twoje pliki pod kontrolą.', 25, '#B8D2E0')}
{text(300, 232, 'WINDOWS x64  •  PLIKI I FOLDERY  •  CHOMIKUJ', 16, '#62E5FF', 'letter-spacing="1"')}
{text(1147, 285, 'by Swir', 16, '#8DA8B8', 'text-anchor="end"')}
'''
    return svg(1200, 320, "ChomcioRecovery by Swir", "Szyfrowane kopie plików i folderów na dysku i na Chomikuj. Windows x64.", body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail on stale or missing assets without writing")
    args = parser.parse_args()
    data = json.loads((ROOT / "docs/project-status.json").read_text(encoding="utf-8"))
    template = dict(data, project="TEMPLATE / NOT PROJECT DATA", scope="Replace with the measured scope", stage="PLANNING", release="Template", completed=None, total=None, unit="verified criteria", reason="No project data. Edit the canonical source and regenerate; never embed this template as live progress.")
    assets = {"hero.svg": hero(), "progress-card.svg": progress(data), "progress-mini.svg": progress(data, True), "progress-template.svg": progress(template)}
    if not args.check:
        OUT.mkdir(parents=True, exist_ok=True)
    for name, content in assets.items():
        ET.fromstring(content)
        expected = content.encode("utf-8")
        target = OUT / name
        if args.check:
            if not target.exists() or target.read_bytes() != expected:
                raise SystemExit("STALE: " + str(target.relative_to(ROOT)))
        elif not target.exists() or target.read_bytes() != expected:
            target.write_bytes(expected)
    print("PASS: 4 deterministic README assets" + (" verified" if args.check else " generated"))


if __name__ == "__main__":
    main()
