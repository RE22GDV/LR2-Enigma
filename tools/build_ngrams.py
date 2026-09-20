"""
Побудова статистичної моделі англійської мови для криптоаналізу.

Скрипт завантажує кілька текстів із суспільного надбання (Project Gutenberg),
очищає їх до послідовності літер A..Z і рахує частоти квадриграм.
У репозиторій потрапляє ЛИШЕ похідна статистика (частоти n-грам),
а не самі тексти.

Запуск (потрібен інтернет; результат уже закомічено в data/):

    python tools/build_ngrams.py
"""

from __future__ import annotations

import gzip
import re
import sys
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "english_quadgrams.txt.gz"

#: Тексти суспільного надбання (Project Gutenberg), ~10 МБ сумарно.
BOOKS = {
    "Pride and Prejudice": "https://www.gutenberg.org/cache/epub/1342/pg1342.txt",
    "The Adventures of Sherlock Holmes": "https://www.gutenberg.org/cache/epub/1661/pg1661.txt",
    "Moby Dick": "https://www.gutenberg.org/cache/epub/2701/pg2701.txt",
    "Frankenstein": "https://www.gutenberg.org/cache/epub/84/pg84.txt",
    "A Tale of Two Cities": "https://www.gutenberg.org/cache/epub/98/pg98.txt",
    "War and Peace": "https://www.gutenberg.org/cache/epub/2600/pg2600.txt",
    "Alice in Wonderland": "https://www.gutenberg.org/cache/epub/11/pg11.txt",
    "The Time Machine": "https://www.gutenberg.org/cache/epub/35/pg35.txt",
}

N = 4
MIN_COUNT = 3

_START = re.compile(r"\*\*\*\s*START OF TH[EI]S? PROJECT GUTENBERG.*?\*\*\*", re.S)
_END = re.compile(r"\*\*\*\s*END OF TH[EI]S? PROJECT GUTENBERG.*?\*\*\*", re.S)


def strip_boilerplate(raw: str) -> str:
    """Відкидає юридичну «обгортку» Project Gutenberg, лишаючи тіло книги."""
    m = _START.search(raw)
    if m:
        raw = raw[m.end():]
    m = _END.search(raw)
    if m:
        raw = raw[: m.start()]
    return raw


def letters_only(text: str) -> str:
    return "".join(ch for ch in text.upper() if "A" <= ch <= "Z")


def main() -> int:
    counter: Counter[str] = Counter()
    total_chars = 0

    for title, url in BOOKS.items():
        try:
            raw = urllib.request.urlopen(url, timeout=60).read().decode(
                "utf-8", errors="ignore"
            )
        except Exception as exc:  # мережа може бути недоступна
            print("  ! пропущено %-36s (%s)" % (title, exc), file=sys.stderr)
            continue
        body = letters_only(strip_boilerplate(raw))
        total_chars += len(body)
        for i in range(len(body) - N + 1):
            counter[body[i:i + N]] += 1
        print("  + %-36s %9d літер" % (title, len(body)))

    if not counter:
        print("не вдалося зібрати корпус", file=sys.stderr)
        return 1

    kept = {g: c for g, c in counter.items() if c >= MIN_COUNT}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(OUT, "wt", encoding="ascii", compresslevel=9) as fh:
        fh.write("# english quadgram counts, corpus=%d letters, min_count=%d\n"
                 % (total_chars, MIN_COUNT))
        for gram, cnt in sorted(kept.items(), key=lambda kv: -kv[1]):
            fh.write("%s %d\n" % (gram, cnt))

    print("\nкорпус:        %d літер" % total_chars)
    print("унікальних 4-грам: %d (збережено %d з count >= %d)"
          % (len(counter), len(kept), MIN_COUNT))
    print("записано:      %s (%.1f КБ)" % (OUT, OUT.stat().st_size / 1024))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
