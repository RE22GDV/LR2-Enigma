"""
Статистичний інструментарій криптоаналітика.

Містить класичні метрики, якими оцінюють «схожість тексту на природну мову»
та відрізняють моноалфавітний шифр від поліалфавітного:

  * частотний аналіз                 :func:`letter_frequencies`
  * індекс відповідності (Friedman)  :func:`index_of_coincidence`
  * критерій хі-квадрат              :func:`chi_squared`
  * ентропія Шеннона                 :func:`shannon_entropy`
  * профіль IoC за періодом          :func:`ioc_by_period`
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Sequence

from .core import ALPHABET, M

_A = ord("A")

#: Еталонні частоти літер англійської мови, % (Beker & Piper, 1982).
ENGLISH_FREQ: dict[str, float] = {
    "A": 8.167, "B": 1.492, "C": 2.782, "D": 4.253, "E": 12.702, "F": 2.228,
    "G": 2.015, "H": 6.094, "I": 6.966, "J": 0.153, "K": 0.772, "L": 4.025,
    "M": 2.406, "N": 6.749, "O": 7.507, "P": 1.929, "Q": 0.095, "R": 5.987,
    "S": 6.327, "T": 9.056, "U": 2.758, "V": 0.978, "W": 2.360, "X": 0.150,
    "Y": 1.974, "Z": 0.074,
}

#: Очікуваний IoC для осмисленого англійського тексту.
IOC_ENGLISH = 0.0667

#: Очікуваний IoC для рівномірно випадкової послідовності над 26 літерами.
IOC_RANDOM = 1.0 / M  # = 0.03846...


# --------------------------------------------------------------------------- #

def letter_counts(text: str) -> list[int]:
    """Абсолютні частоти 26 літер."""
    counts = [0] * M
    for ch in text:
        if "A" <= ch <= "Z":
            counts[ord(ch) - _A] += 1
    return counts


def letter_frequencies(text: str, *, percent: bool = True) -> list[float]:
    """Відносні частоти 26 літер (у відсотках або частках одиниці)."""
    counts = letter_counts(text)
    total = sum(counts)
    if total == 0:
        return [0.0] * M
    scale = 100.0 / total if percent else 1.0 / total
    return [c * scale for c in counts]


def index_of_coincidence(text: str) -> float:
    """
    Індекс відповідності — ймовірність того, що дві навмання обрані
    літери тексту збігаються.

    Для англійської мови ~0.0667, для випадкового тексту ~0.0385.
    Метрика інваріантна щодо моноалфавітної заміни, тому саме вона
    відрізняє «просту заміну» від «поліалфавітного шифру».
    """
    counts = letter_counts(text)
    n = sum(counts)
    if n < 2:
        return 0.0
    return sum(c * (c - 1) for c in counts) / (n * (n - 1))


def chi_squared(text: str, reference: dict[str, float] | None = None) -> float:
    """
    Критерій хі-квадрат між спостережуваними частотами та еталонними
    англійськими. Менше значення — текст більше схожий на англійську.
    """
    ref = reference or ENGLISH_FREQ
    counts = letter_counts(text)
    n = sum(counts)
    if n == 0:
        return float("inf")
    total = 0.0
    for i, letter in enumerate(ALPHABET):
        expected = n * ref[letter] / 100.0
        if expected <= 0:
            expected = 1e-9
        total += (counts[i] - expected) ** 2 / expected
    return total


def shannon_entropy(text: str) -> float:
    """Ентропія Шеннона в бітах на символ (максимум log2(26) = 4.70)."""
    counts = letter_counts(text)
    n = sum(counts)
    if n == 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def columns(text: str, period: int) -> list[str]:
    """Розбиття тексту на ``period`` стовпців за індексом ``i mod period``."""
    if period < 1:
        raise ValueError("період має бути >= 1")
    buckets: list[list[str]] = [[] for _ in range(period)]
    for i, ch in enumerate(text):
        buckets[i % period].append(ch)
    return ["".join(b) for b in buckets]


def average_column_ioc(text: str, period: int) -> float:
    """Середній IoC по стовпцях для заданого припущеного періоду."""
    cols = [c for c in columns(text, period) if len(c) >= 2]
    if not cols:
        return 0.0
    return sum(index_of_coincidence(c) for c in cols) / len(cols)


def ioc_by_period(text: str, max_period: int = 40) -> list[tuple[int, float]]:
    """
    Профіль «період -> середній IoC стовпців».

    Для шифру з нашої задачі профіль дає виразний сплеск на періоді 26:
    це і є експериментальне підтвердження того, що шифр — поліалфавітний
    з періодом рівно 26.
    """
    return [(p, average_column_ioc(text, p)) for p in range(1, max_period + 1)]


def friedman_period_estimate(text: str) -> float:
    """
    Оцінка довжини ключа за формулою Фрідмана.
    Для дуже коротких текстів оцінка нестабільна — це нормально.
    """
    n = len([c for c in text if "A" <= c <= "Z"])
    ic = index_of_coincidence(text)
    denom = (n - 1) * ic - IOC_RANDOM * n + IOC_ENGLISH
    if abs(denom) < 1e-12:
        return float("inf")
    return (IOC_ENGLISH - IOC_RANDOM) * n / denom


def unicity_distance(key_bits: float, entropy_per_char: float = 1.5) -> float:
    """
    Відстань єдиності за Шенноном:  U = H(K) / D,
    де D = log2(26) - H_мови — надлишковість мови на символ.

    Це теоретична межа: шифротекст, коротший за U, у принципі має
    кілька осмислених розшифрувань, тому однозначно зламати його
    неможливо ЖОДНИМ алгоритмом. Довші тексти зламні в принципі —
    але скільки саме треба на практиці, показує експеримент (рис. 4).

    >>> round(unicity_distance(math.log2(math.factorial(26))))
    28
    """
    redundancy = math.log2(M) - entropy_per_char
    if redundancy <= 0:
        return float("inf")
    return key_bits / redundancy


def bigram_counts(text: str) -> Counter:
    """Лічильник біграм (для додаткової діагностики)."""
    return Counter(text[i:i + 2] for i in range(len(text) - 1))


def summary(text: str) -> dict[str, float]:
    """Зведений «паспорт» тексту — зручно друкувати в звіті."""
    return {
        "length": float(len(text)),
        "ioc": index_of_coincidence(text),
        "chi2": chi_squared(text),
        "entropy_bits_per_char": shannon_entropy(text),
        "distinct_letters": float(len({c for c in text if "A" <= c <= "Z"})),
    }


def describe_distance_to_english(text: str) -> str:
    """Людиночитна інтерпретація IoC."""
    ioc = index_of_coincidence(text)
    if ioc >= 0.060:
        return "моноалфавітний або відкритий текст (IoC близький до англійського)"
    if ioc >= 0.048:
        return "проміжний випадок (короткий текст або малий період)"
    return "поліалфавітний / випадковий (IoC близький до рівномірного)"
