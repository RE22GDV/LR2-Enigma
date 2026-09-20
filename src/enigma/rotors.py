"""
Каталог роторних проводок.

Цікавий історичний факт, помічений під час виконання роботи:
набір роторів із умови CodinGame — це справжні проводки роторів
Enigma I (Wehrmacht/Luftwaffe, 1930), але перелічені у ЗВОРОТНОМУ порядку:

    CodinGame "ROTOR I"   == історичний Rotor III
    CodinGame "ROTOR II"  == історичний Rotor II
    CodinGame "ROTOR III" == історичний Rotor I

Джерело проводок: Enigma rotor details, en.wikipedia.org/wiki/Enigma_rotor_details
"""

from __future__ import annotations

import random
from typing import Sequence

from .core import ALPHABET, M, Rotor, perm_to_str

#: Історичні ротори Enigma I / M3 / M4 (відображення A..Z -> проводка).
HISTORICAL_ROTORS: dict[str, str] = {
    "I": "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
    "II": "AJDKSIRUXBLHWTMCQGZNPYFVOE",
    "III": "BDFHJLCPRTXVZNYEIWGAKMUSQO",
    "IV": "ESOVPZJAYQUIRHXLNFTGKDCMWB",
    "V": "VZBRGITYUPSDNHLXAWMJQOFECK",
    "VI": "JPGVOUMFYQBENHZRDKASXLICTW",
    "VII": "NZJHGRCXMYSWBOUFAIVLPEKQDT",
    "VIII": "FKQHTLXOCBJSPDZRAMEWNIUYGV",
}

#: Історичні рефлектори (у спрощеній задачі НЕ використовуються — див. README).
HISTORICAL_REFLECTORS: dict[str, str] = {
    "A": "EJMZALYXVBWFCRQUONTSPIKHGD",
    "B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "C": "FVPJIAOYEDRZXWGCTKUQSBNMHL",
}

#: Набір роторів рівно в тому порядку, в якому їх подає CodinGame.
CODINGAME_ROTORS: tuple[str, str, str] = (
    HISTORICAL_ROTORS["III"],  # "ROTOR I"   в умові задачі
    HISTORICAL_ROTORS["II"],   # "ROTOR II"  в умові задачі
    HISTORICAL_ROTORS["I"],    # "ROTOR III" в умові задачі
)


def random_rotor(rng: random.Random | int | None = None) -> Rotor:
    """Випадковий ротор — рівномірно з усіх 26! підстановок."""
    if not isinstance(rng, random.Random):
        rng = random.Random(rng)
    perm = list(range(M))
    rng.shuffle(perm)
    return Rotor(perm_to_str(perm))


def random_rotor_set(
    count: int = 3, rng: random.Random | int | None = None
) -> tuple[Rotor, ...]:
    """Набір з ``count`` незалежних випадкових роторів."""
    if not isinstance(rng, random.Random):
        rng = random.Random(rng)
    return tuple(random_rotor(rng) for _ in range(count))


def describe(wiring: str | Rotor) -> dict[str, object]:
    """Короткий структурний паспорт ротора (для звіту)."""
    rotor = wiring if isinstance(wiring, Rotor) else Rotor(wiring)
    name = next(
        (n for n, w in HISTORICAL_ROTORS.items() if w == rotor.wiring), None
    )
    return {
        "wiring": rotor.wiring,
        "historical_name": name,
        "fixed_points": [ALPHABET[i] for i in rotor.fixed_points],
        "cycle_type": list(rotor.cycle_type),
        "is_involution": rotor.forward == rotor.backward,
    }
