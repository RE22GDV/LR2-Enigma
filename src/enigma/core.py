"""
Ядро шифру: два класичні криптографічні примітиви в чистому вигляді.

    1. ЗСУВ (перестановка алфавіту) — шифр Цезаря з інкрементним ключем:
       i-й символ зсувається на (N + i) mod 26.

    2. ЗАМІНА — три ротори, кожен з яких є довільною підстановкою
       (бієкцією) алфавіту A..Z.

Формально, для відкритого тексту m[0..L-1] і початкового зсуву N:

    c[i] = S[ (m[i] + N + i) mod 26 ],     S = R3 . R2 . R1

де S — композиція трьох роторів. Зворотне перетворення:

    m[i] = ( S^-1[c[i]] - N - i ) mod 26

КЛЮЧОВЕ СПОСТЕРЕЖЕННЯ (див. README, розділ «Криптоаналіз»):
композиція трьох бієкцій — це знову одна бієкція, тому три ротори
не додають стійкості порівняно з одним. Більше того, константу N
можна «втопити» в цю бієкцію, отримавши ЄДИНИЙ ефективний ключ

    D[x] = ( S^-1[x] - N ) mod 26,        m[i] = ( D[c[i]] - i ) mod 26

Саме D і відновлюють усі реалізовані атаки.
"""

from __future__ import annotations

from typing import Iterable, Sequence

#: Робочий алфавіт задачі — лише великі латинські літери.
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

#: Потужність алфавіту (модуль кільця Z_26).
M = 26

_A = ord("A")


class RotorError(ValueError):
    """Ротор не є коректною підстановкою алфавіту A..Z."""


class MessageError(ValueError):
    """Повідомлення містить символи поза алфавітом A..Z."""


# --------------------------------------------------------------------------- #
#  Допоміжні функції над підстановками Z_26 -> Z_26
# --------------------------------------------------------------------------- #

def invert(perm: Sequence[int]) -> tuple[int, ...]:
    """Обернена підстановка: ``invert(p)[p[i]] == i``."""
    out = [0] * len(perm)
    for i, v in enumerate(perm):
        out[v] = i
    return tuple(out)


def perm_to_str(perm: Sequence[int]) -> str:
    """Підстановка у вигляді 26-літерного рядка (як записують ротори)."""
    return "".join(chr(_A + v) for v in perm)


def str_to_perm(text: str) -> tuple[int, ...]:
    """Рядок роторної проводки -> кортеж індексів."""
    return tuple(ord(ch) - _A for ch in text)


def normalize(text: str) -> str:
    """Прибирає все, крім латинських літер, і переводить у верхній регістр."""
    return "".join(ch for ch in text.upper() if "A" <= ch <= "Z")


def _check_message(message: str) -> None:
    bad = sorted({ch for ch in message if not ("A" <= ch <= "Z")})
    if bad:
        raise MessageError(
            "повідомлення має складатися лише з великих літер A..Z; "
            "знайдено сторонні символи: " + repr(bad)
        )


# --------------------------------------------------------------------------- #
#  Ротор
# --------------------------------------------------------------------------- #

class Rotor:
    """
    Один ротор = одна таблиця заміни.

    Проводка задається рядком з 26 літер: літера на позиції ``i``
    визначає, у що переходить ``i``-та літера алфавіту.

    >>> Rotor("BDFHJLCPRTXVZNYEIWGAKMUSQO").encode_char("A")
    'B'
    """

    __slots__ = ("wiring", "forward", "backward")

    def __init__(self, wiring: str | Sequence[int]) -> None:
        if not isinstance(wiring, str):
            wiring = perm_to_str(wiring)
        w = wiring.strip().upper()
        if len(w) != M:
            raise RotorError(
                "ротор має містити рівно %d літер, отримано %d: %r" % (M, len(w), w)
            )
        if set(w) != set(ALPHABET):
            missing = sorted(set(ALPHABET) - set(w))
            dup = sorted({c for c in w if w.count(c) > 1})
            raise RotorError(
                "ротор %r не є підстановкою алфавіту "
                "(відсутні: %s, дублікати: %s)" % (w, missing, dup)
            )
        self.wiring = w
        self.forward = str_to_perm(w)
        self.backward = invert(self.forward)

    # -- пряме / зворотне відображення ------------------------------------- #

    def encode_char(self, ch: str) -> str:
        return chr(_A + self.forward[ord(ch) - _A])

    def decode_char(self, ch: str) -> str:
        return chr(_A + self.backward[ord(ch) - _A])

    def encode(self, text: str) -> str:
        f = self.forward
        return "".join(chr(_A + f[ord(c) - _A]) for c in text)

    def decode(self, text: str) -> str:
        b = self.backward
        return "".join(chr(_A + b[ord(c) - _A]) for c in text)

    # -- сервіс ------------------------------------------------------------ #

    def inverse(self) -> "Rotor":
        """Ротор, що реалізує обернену підстановку."""
        return Rotor(perm_to_str(self.backward))

    @property
    def fixed_points(self) -> tuple[int, ...]:
        """Літери, які ротор залишає на місці (``S[x] == x``)."""
        return tuple(i for i, v in enumerate(self.forward) if i == v)

    @property
    def cycle_type(self) -> tuple[int, ...]:
        """Циклова структура підстановки — довжини циклів за спаданням."""
        seen = [False] * M
        cycles: list[int] = []
        for start in range(M):
            if seen[start]:
                continue
            length, cur = 0, start
            while not seen[cur]:
                seen[cur] = True
                cur = self.forward[cur]
                length += 1
            cycles.append(length)
        return tuple(sorted(cycles, reverse=True))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Rotor) and other.wiring == self.wiring

    def __hash__(self) -> int:
        return hash(self.wiring)

    def __repr__(self) -> str:
        return "Rotor(%r)" % (self.wiring,)

    def __str__(self) -> str:
        return self.wiring


# --------------------------------------------------------------------------- #
#  Машина
# --------------------------------------------------------------------------- #

class EnigmaMachine:
    """
    Спрощена Енігма: інкрементний зсув Цезаря + каскад роторів.

    :param rotors: послідовність роторів (рядки або ``Rotor``); порядок —
                   у якому сигнал проходить крізь них.
    :param shift:  початкове значення зсуву ``N`` (0 <= N < 26).

    >>> m = EnigmaMachine(["BDFHJLCPRTXVZNYEIWGAKMUSQO",
    ...                    "AJDKSIRUXBLHWTMCQGZNPYFVOE",
    ...                    "EKMFLGDQVZNTOWYHXUSPAIBRCJ"], shift=4)
    >>> m.encode("AAA")
    'KQF'
    >>> m.decode("KQF")
    'AAA'
    """

    __slots__ = ("rotors", "shift", "substitution", "inverse_substitution",
                 "_enc_tables", "_dec_tables")

    def __init__(self, rotors: Iterable[str | Rotor], shift: int = 0) -> None:
        self.rotors: tuple[Rotor, ...] = tuple(
            r if isinstance(r, Rotor) else Rotor(r) for r in rotors
        )
        if not self.rotors:
            raise RotorError("потрібен щонайменше один ротор")
        self.shift = int(shift) % M

        # --- згортка каскаду роторів в одну підстановку S -------------------
        # Саме тут видно, що «три таблиці заміни» = «одна таблиця заміни».
        composed = list(range(M))
        for rotor in self.rotors:
            composed = [rotor.forward[x] for x in composed]
        self.substitution: tuple[int, ...] = tuple(composed)
        self.inverse_substitution: tuple[int, ...] = invert(self.substitution)

        # --- 26 готових алфавітів шифрування --------------------------------
        # Шифр є періодичним поліалфавітним з періодом 26: на позиції i
        # застосовується алфавіт номер (N + i) mod 26. Завдяки попередньому
        # обчисленню таблиць внутрішній цикл не містить жодної арифметики.
        s, inv = self.substitution, self.inverse_substitution
        self._enc_tables: tuple[bytes, ...] = tuple(
            bytes(_A + s[(m + p) % M] for m in range(M)) for p in range(M)
        )
        self._dec_tables: tuple[bytes, ...] = tuple(
            bytes(_A + (inv[c] - p) % M for c in range(M)) for p in range(M)
        )

    # -- основне API -------------------------------------------------------- #

    def encode(self, message: str, *, validate: bool = True) -> str:
        """Зашифрувати повідомлення (лише літери A..Z)."""
        if validate:
            _check_message(message)
        tables, n = self._enc_tables, self.shift
        return bytes(
            tables[(n + i) % M][ord(ch) - _A] for i, ch in enumerate(message)
        ).decode("ascii")

    def decode(self, ciphertext: str, *, validate: bool = True) -> str:
        """Розшифрувати повідомлення (лише літери A..Z)."""
        if validate:
            _check_message(ciphertext)
        tables, n = self._dec_tables, self.shift
        return bytes(
            tables[(n + i) % M][ord(ch) - _A] for i, ch in enumerate(ciphertext)
        ).decode("ascii")

    def process(self, mode: str, message: str) -> str:
        """Диспетчер за режимом ``ENCODE`` / ``DECODE`` (формат CodinGame)."""
        mode_u = mode.strip().upper()
        if mode_u == "ENCODE":
            return self.encode(message)
        if mode_u == "DECODE":
            return self.decode(message)
        raise ValueError(
            "невідомий режим %r: очікується ENCODE або DECODE" % (mode,)
        )

    # -- структурні властивості (використовуються в криптоаналізі) ---------- #

    @property
    def effective_key(self) -> tuple[int, ...]:
        """
        Ефективний ключ ``D``: єдина бієкція, що повністю задає шифр.

            m[i] = ( D[c[i]] - i ) mod 26

        Увесь номінальний ключ (3 ротори + зсув) стискається до цих 26 чисел.
        """
        n = self.shift
        return tuple((v - n) % M for v in self.inverse_substitution)

    @property
    def alphabets(self) -> tuple[str, ...]:
        """26 алфавітів заміни, які шифр циклічно застосовує до позицій."""
        return tuple(t.decode("ascii") for t in self._enc_tables)

    def equivalent_single_rotor(self) -> "EnigmaMachine":
        """
        Машина з ОДНИМ ротором і нульовим зсувом, еквівалентна цій.

        Доводить, що каскад «3 ротори + зсув N» не має жодної переваги
        над «1 ротор + зсув 0».
        """
        return EnigmaMachine([Rotor(perm_to_str(invert(self.effective_key)))], shift=0)

    def __repr__(self) -> str:
        rotors = ", ".join(r.wiring for r in self.rotors)
        return "EnigmaMachine(shift=%d, rotors=[%s])" % (self.shift, rotors)


# --------------------------------------------------------------------------- #
#  Робота напряму з ефективним ключем D (потрібна атакам)
# --------------------------------------------------------------------------- #

def decrypt_with_effective_key(ciphertext: str, key: Sequence[int]) -> str:
    """``m[i] = (D[c[i]] - i) mod 26``"""
    return bytes(
        _A + (key[ord(ch) - _A] - i) % M for i, ch in enumerate(ciphertext)
    ).decode("ascii")


def encrypt_with_effective_key(plaintext: str, key: Sequence[int]) -> str:
    """Обернена до :func:`decrypt_with_effective_key` операція."""
    inv = invert(key)
    return bytes(
        _A + inv[(ord(ch) - _A + i) % M] for i, ch in enumerate(plaintext)
    ).decode("ascii")
