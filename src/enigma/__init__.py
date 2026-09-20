"""
Пакет `enigma` — навчальна реалізація спрощеної машини Енігми
(варіант задачі CodinGame "Encryption/Decryption of Enigma Machine")
та набір криптоаналітичних атак на неї.

Лабораторна робота №2 з дисципліни «Захист даних».
"""

from .core import (
    ALPHABET,
    M,
    EnigmaMachine,
    Rotor,
    RotorError,
    MessageError,
    decrypt_with_effective_key,
    encrypt_with_effective_key,
    invert,
    normalize,
    perm_to_str,
    str_to_perm,
)
from .rotors import (
    CODINGAME_ROTORS,
    HISTORICAL_ROTORS,
    HISTORICAL_REFLECTORS,
    random_rotor,
    random_rotor_set,
)

__all__ = [
    "ALPHABET",
    "M",
    "EnigmaMachine",
    "Rotor",
    "RotorError",
    "MessageError",
    "decrypt_with_effective_key",
    "encrypt_with_effective_key",
    "invert",
    "normalize",
    "perm_to_str",
    "str_to_perm",
    "CODINGAME_ROTORS",
    "HISTORICAL_ROTORS",
    "HISTORICAL_REFLECTORS",
    "random_rotor",
    "random_rotor_set",
]

__version__ = "1.0.0"
