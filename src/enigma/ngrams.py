"""
Статистична модель англійської мови на основі квадриграм.

Фітнес-функція для атак: логарифмічна правдоподібність тексту

    score(t) = sum_i  log10 P( t[i..i+3] )

Модель натренована на ~5.6 млн літер текстів із суспільного надбання
(див. ``tools/build_ngrams.py``). У репозиторії зберігається лише
похідна статистика частот, не самі тексти.

Для швидкості квадриграма адресується цілим числом у системі числення
за основою 26, а таблиця логімовірностей — це плоский список довжиною
26^4 = 456 976. Це дозволяє оцінювати кандидата без роботи з рядками,
що критично для сходження за схилом (десятки тисяч оцінок за запуск).
"""

from __future__ import annotations

import gzip
import math
from pathlib import Path
from typing import Sequence

from .analysis import ENGLISH_FREQ
from .core import ALPHABET, M

_A = ord("A")

DEFAULT_MODEL = Path(__file__).resolve().parents[2] / "data" / "english_quadgrams.txt.gz"


class NgramScorer:
    """
    Оцінювач «англійськості» тексту за квадриграмами.

    >>> s = NgramScorer()
    >>> s.score("THEQUICKBROWNFOX") > s.score("XQZJVWKPFMBGHYTR")
    True
    """

    __slots__ = ("n", "table", "floor", "corpus_size", "source")

    def __init__(self, path: Path | str | None = None, n: int = 4) -> None:
        self.n = n
        self.source = "quadgram-model"
        path = Path(path) if path is not None else DEFAULT_MODEL

        counts: dict[str, int] = {}
        header = ""
        if path.exists():
            opener = gzip.open if str(path).endswith(".gz") else open
            with opener(path, "rt", encoding="ascii") as fh:  # type: ignore[operator]
                for line in fh:
                    if line.startswith("#"):
                        header = line.strip()
                        continue
                    gram, _, cnt = line.partition(" ")
                    if len(gram) == n:
                        counts[gram] = int(cnt)

        if counts:
            self._build_from_counts(counts)
            self.corpus_size = sum(counts.values())
            self.source = "%s (%s)" % (path.name, header.lstrip("# "))
        else:
            # Запасний варіант: модель на одиночних літерах.
            self._build_monogram_fallback()
            self.corpus_size = 0
            self.source = "monogram-fallback (файл моделі не знайдено)"

    # ------------------------------------------------------------------ #

    def _build_from_counts(self, counts: dict[str, int]) -> None:
        total = sum(counts.values())
        size = M ** self.n
        # Згладжування: неспостережувані n-грами отримують «штрафну» ймовірність.
        self.floor = math.log10(0.01 / total)
        table = [self.floor] * size
        for gram, cnt in counts.items():
            idx = 0
            for ch in gram:
                idx = idx * M + (ord(ch) - _A)
            table[idx] = math.log10(cnt / total)
        self.table = table

    def _build_monogram_fallback(self) -> None:
        self.n = 1
        self.floor = math.log10(1e-6)
        self.table = [
            math.log10(max(ENGLISH_FREQ[ch], 1e-4) / 100.0) for ch in ALPHABET
        ]

    # ------------------------------------------------------------------ #

    def score_indices(self, seq: Sequence[int]) -> float:
        """Швидкий шлях: оцінка послідовності індексів 0..25."""
        n, table = self.n, self.table
        length = len(seq)
        if length < n:
            return self.floor * max(length, 1)
        if n == 1:
            return sum(table[v] for v in seq)

        stride = M ** (n - 1)
        idx = 0
        for k in range(n):
            idx = idx * M + seq[k]
        total = table[idx]
        for k in range(n, length):
            idx = (idx % stride) * M + seq[k]
            total += table[idx]
        return total

    def score(self, text: str) -> float:
        """Сумарна логправдоподібність тексту (більше — «англійськіше»)."""
        return self.score_indices([ord(ch) - _A for ch in text])

    def score_per_char(self, text: str) -> float:
        """Нормована оцінка — придатна для порівняння текстів різної довжини."""
        if not text:
            return self.floor
        return self.score(text) / len(text)

    def __repr__(self) -> str:
        return "NgramScorer(n=%d, source=%r)" % (self.n, self.source)


_DEFAULT: NgramScorer | None = None


def default_scorer() -> NgramScorer:
    """Лінива глобальна модель — щоб не перечитувати файл на кожну атаку."""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = NgramScorer()
    return _DEFAULT
