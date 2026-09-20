"""
Криптоаналіз спрощеної Енігми.

Реалізовано чотири атаки, впорядковані за силою припущень про
можливості зловмисника (класична ієрархія моделей атак):

  1. :func:`brute_force_shift`      — відомі ротори, невідомий зсув.
                                      Простір ключів = 26. Секунди -> мілісекунди.
  2. :func:`known_plaintext_attack` — відома пара (текст, шифротекст).
                                      Лінійне відновлення ключа, без перебору.
  3. :func:`chosen_plaintext_attack`— доступ до шифрувального оракула.
                                      ОДИН запит із 26 символів -> повний ключ.
  4. :func:`ciphertext_only_attack` — відомий лише шифротекст. Сходження
                                      за схилом по квадриграмах + жадібна
                                      частотна ініціалізація.

Усі атаки відновлюють той самий об'єкт — ефективний ключ ``D`` (26 чисел),
див. :attr:`enigma.core.EnigmaMachine.effective_key`.

Модуль не має зовнішніх залежностей: лише стандартна бібліотека.
"""

from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass, field
from typing import Callable, Sequence

from .analysis import ENGLISH_FREQ
from .core import (
    ALPHABET,
    M,
    EnigmaMachine,
    Rotor,
    decrypt_with_effective_key,
    invert,
)
from .ngrams import NgramScorer, default_scorer

_A = ord("A")


# --------------------------------------------------------------------------- #
#  Результати
# --------------------------------------------------------------------------- #

@dataclass
class AttackResult:
    """Уніфікований результат будь-якої атаки."""

    name: str
    success: bool
    plaintext: str
    key: tuple[int, ...] | None
    score: float
    elapsed_s: float
    evaluations: int = 0
    notes: dict[str, object] = field(default_factory=dict)

    def key_letters(self) -> str | None:
        """Ефективний ключ у літерному вигляді (для друку)."""
        if self.key is None:
            return None
        return "".join(chr(_A + v) for v in self.key)

    def __str__(self) -> str:
        status = "УСПІХ" if self.success else "невдача"
        return "%-28s %-8s score=%9.1f  t=%6.3f с  %s" % (
            self.name, status, self.score, self.elapsed_s, self.plaintext[:48]
        )


# --------------------------------------------------------------------------- #
#  Оцінка простору ключів
# --------------------------------------------------------------------------- #

def keyspace_analysis(rotor_count: int = 3) -> dict[str, float]:
    """
    Номінальний і фактичний розмір простору ключів, у бітах.

    Номінально ключ — це ``rotor_count`` довільних підстановок плюс зсув:
    ``(26!)^k * 26``. Фактично ж усе згортається в одну підстановку ``D``,
    тому справжня стійкість дорівнює ``26!`` незалежно від k.
    """
    bits_perm = math.log2(math.factorial(M))
    nominal = rotor_count * bits_perm + math.log2(M)
    effective = bits_perm
    return {
        "bits_per_rotor": bits_perm,
        "nominal_bits": nominal,
        "effective_bits": effective,
        "reduction_bits": nominal - effective,
        "equivalent_keys_bits": nominal - effective,
        # Сценарій за принципом Керкгоффса: ротори опубліковані в умові
        # задачі й однакові в усіх тестах, тож секретом є тільки N.
        "kerckhoffs_bits": math.log2(M),
    }


def find_key_collision(
    rng: random.Random | int | None = None, tries: int = 200
) -> dict[str, object] | None:
    """
    Конструктивний доказ надлишковості ключа: знаходить ДВА різні набори
    (ротори + зсув), які шифрують будь-яке повідомлення однаково.

    Побудова не випадкова, а пряма: беремо довільні R1, R2, R3, N і
    замінюємо трійку на еквівалентний один ротор зі зсувом 0.
    """
    from .rotors import random_rotor_set

    if not isinstance(rng, random.Random):
        rng = random.Random(rng)

    for _ in range(tries):
        rotors = random_rotor_set(3, rng)
        shift = rng.randrange(M)
        a = EnigmaMachine(rotors, shift)
        b = a.equivalent_single_rotor()
        probe = "".join(rng.choice(ALPHABET) for _ in range(120))
        if a.encode(probe) == b.encode(probe) and a.rotors != b.rotors:
            return {
                "key_a": {"rotors": [r.wiring for r in a.rotors], "shift": a.shift},
                "key_b": {"rotors": [r.wiring for r in b.rotors], "shift": b.shift},
                "probe": probe,
                "ciphertext": a.encode(probe),
                "identical": True,
            }
    return None


# --------------------------------------------------------------------------- #
#  Атака 1: перебір зсуву (ротори відомі)
# --------------------------------------------------------------------------- #

def brute_force_shift(
    ciphertext: str,
    rotors: Sequence[str | Rotor],
    scorer: NgramScorer | None = None,
) -> AttackResult:
    """
    Повний перебір усіх 26 значень зсуву за відомих роторів.

    Це реалістичний сценарій саме для цієї задачі: ротори надруковані
    в умові й однакові в усіх шести офіційних тестах, тому секретом
    лишається тільки N — трохи менше ніж 5 біт ентропії.
    """
    scorer = scorer or default_scorer()
    t0 = time.perf_counter()
    candidates: list[tuple[float, int, str]] = []
    for n in range(M):
        pt = EnigmaMachine(rotors, n).decode(ciphertext)
        candidates.append((scorer.score(pt), n, pt))
    candidates.sort(reverse=True)
    best_score, best_n, best_pt = candidates[0]
    elapsed = time.perf_counter() - t0

    margin = best_score - candidates[1][0] if len(candidates) > 1 else 0.0
    key = EnigmaMachine(rotors, best_n).effective_key
    return AttackResult(
        name="Перебір зсуву (26 ключів)",
        success=True,
        plaintext=best_pt,
        key=key,
        score=best_score,
        elapsed_s=elapsed,
        evaluations=M,
        notes={
            "recovered_shift": best_n,
            "margin_over_runner_up": margin,
            "ranking": [(n, round(s, 2), p) for s, n, p in candidates[:5]],
        },
    )


# --------------------------------------------------------------------------- #
#  Атака 2: відомий відкритий текст
# --------------------------------------------------------------------------- #

def known_plaintext_attack(
    plaintext: str, ciphertext: str, *, full_ciphertext: str | None = None
) -> AttackResult:
    """
    Атака на основі відомого фрагмента («шпаргалки», crib).

    З кожної пари ``(m[i], c[i])`` одразу випливає один елемент ключа:

        D[c[i]] = (m[i] + i) mod 26

    Жодного перебору — чисте лінійне відновлення. Щоб покрити всі 26
    елементів, потрібно в середньому 26*H(26) ~ 100 символів (задача
    про збирання купонів); часткового ключа вже достатньо, щоб
    прочитати більшу частину повідомлення.
    """
    t0 = time.perf_counter()
    n_pairs = min(len(plaintext), len(ciphertext))
    partial: list[int | None] = [None] * M
    contradictions = 0

    for i in range(n_pairs):
        c = ord(ciphertext[i]) - _A
        value = (ord(plaintext[i]) - _A + i) % M
        if partial[c] is None:
            partial[c] = value
        elif partial[c] != value:
            contradictions += 1

    known = [v for v in partial if v is not None]
    coverage = len(known)

    # Доповнюємо невідомі позиції довільною бієкцією, щоб ключ був повним.
    unused = [v for v in range(M) if v not in set(known)]
    completed = []
    it = iter(unused)
    for v in partial:
        completed.append(v if v is not None else next(it))
    key = tuple(completed)

    target = full_ciphertext if full_ciphertext is not None else ciphertext
    recovered = decrypt_with_effective_key(target, key)
    elapsed = time.perf_counter() - t0

    return AttackResult(
        name="Відомий відкритий текст",
        success=contradictions == 0 and coverage == M,
        plaintext=recovered,
        key=key,
        score=float(coverage),
        elapsed_s=elapsed,
        evaluations=n_pairs,
        notes={
            "crib_length": n_pairs,
            "key_coverage": coverage,
            "coverage_percent": 100.0 * coverage / M,
            "contradictions": contradictions,
            "unknown_letters": [ALPHABET[i] for i, v in enumerate(partial) if v is None],
        },
    )


def expected_crib_coverage(crib_length: int) -> float:
    """
    Теоретичне очікуване покриття ключа за довжиною шпаргалки
    (модель рівномірних незалежних літер шифротексту):

        E[coverage] = 26 * (1 - (25/26)^L)
    """
    return M * (1.0 - ((M - 1) / M) ** crib_length)


# --------------------------------------------------------------------------- #
#  Атака 3: підібраний відкритий текст
# --------------------------------------------------------------------------- #

def chosen_plaintext_attack(
    oracle: Callable[[str], str], ciphertext: str | None = None
) -> AttackResult:
    """
    Найсильніша й найдешевша атака: маючи доступ до шифрувального
    оракула, повний ключ дістається за ОДИН запит із 26 літер.

    Надсилаємо ``"AAAA...A"`` (26 символів). Тоді
    ``c[i] = S[(0 + N + i) mod 26]``, а отже ``D[c[i]] = i``.
    Оскільки S — бієкція, усі 26 символів ``c[i]`` різні, і ключ
    відновлюється повністю.
    """
    t0 = time.perf_counter()
    probe = "A" * M
    response = oracle(probe)
    if len(response) < M or len(set(response)) != M:
        raise ValueError("оракул повернув некоректну відповідь на пробу")

    key_list = [0] * M
    for i, ch in enumerate(response[:M]):
        key_list[ord(ch) - _A] = i
    key = tuple(key_list)

    recovered = decrypt_with_effective_key(ciphertext, key) if ciphertext else ""
    elapsed = time.perf_counter() - t0
    return AttackResult(
        name="Підібраний відкритий текст",
        success=True,
        plaintext=recovered,
        key=key,
        score=float(M),
        elapsed_s=elapsed,
        evaluations=1,
        notes={"queries": 1, "query_length": M, "probe": probe, "response": response},
    )


# --------------------------------------------------------------------------- #
#  Атака 4: тільки шифротекст
# --------------------------------------------------------------------------- #

def frequency_initial_key(ciphertext: str) -> list[int]:
    """
    Жадібна частотна ініціалізація ключа.

    Для кожної літери шифротексту ``x`` і кожного кандидата ``v``
    рахуємо, наскільки «англійськими» за частотою літер вийдуть
    символи ``(v - i) mod 26`` на всіх позиціях, де стоїть ``x``.
    Потім жадібно розбираємо пари (x, v) за спаданням вигоди,
    зберігаючи бієктивність.
    """
    log_freq = [math.log(max(ENGLISH_FREQ[ch], 1e-3) / 100.0) for ch in ALPHABET]

    positions: list[list[int]] = [[] for _ in range(M)]
    for i, ch in enumerate(ciphertext):
        positions[ord(ch) - _A].append(i)

    gains: list[tuple[float, int, int]] = []
    for x in range(M):
        pos = positions[x]
        if not pos:
            continue
        for v in range(M):
            gains.append((sum(log_freq[(v - i) % M] for i in pos), x, v))
    gains.sort(reverse=True)

    key: list[int | None] = [None] * M
    used_v: set[int] = set()
    for _, x, v in gains:
        if key[x] is None and v not in used_v:
            key[x] = v
            used_v.add(v)

    leftovers = [v for v in range(M) if v not in used_v]
    it = iter(leftovers)
    return [v if v is not None else next(it) for v in key]


def ciphertext_only_attack(
    ciphertext: str,
    *,
    restarts: int = 24,
    patience: int = 1500,
    scorer: NgramScorer | None = None,
    rng: random.Random | int | None = None,
    init: str = "frequency",
    expected_plaintext: str | None = None,
) -> AttackResult:
    """
    Атака лише на шифротексті: сходження за схилом у просторі бієкцій ``D``
    з фітнес-функцією на квадриграмах англійської мови.

    Ключова ідея. Позиційний зсув ``-i`` є ПУБЛІЧНОЮ структурою, а не
    секретом, тому його не треба вгадувати: перебирається лише бієкція
    ``D`` (26! варіантів). Через це стійкість шифру дорівнює стійкості
    звичайної моноалфавітної заміни, попри «поліалфавітний» вигляд.

    :param restarts: кількість незалежних запусків із різних початкових точок
    :param patience: скільки невдалих випадкових обмінів поспіль терпіти
    :param init:     ``"frequency"`` (жадібна частотна) або ``"random"``
    """
    scorer = scorer or default_scorer()
    if not isinstance(rng, random.Random):
        rng = random.Random(rng)

    t0 = time.perf_counter()
    cipher_idx = [ord(ch) - _A for ch in ciphertext]
    length = len(cipher_idx)
    evaluations = 0

    def decrypt_idx(key: Sequence[int]) -> list[int]:
        return [(key[c] - i) % M for i, c in enumerate(cipher_idx)]

    best_key: list[int] = list(range(M))
    best_score = -float("inf")

    for attempt in range(restarts):
        if init == "frequency" and attempt == 0:
            key = frequency_initial_key(ciphertext)
        elif init == "frequency" and attempt < max(2, restarts // 4):
            # Кілька збурених копій частотного старту.
            key = frequency_initial_key(ciphertext)
            for _ in range(4):
                a, b = rng.randrange(M), rng.randrange(M)
                key[a], key[b] = key[b], key[a]
        else:
            key = list(range(M))
            rng.shuffle(key)

        score = scorer.score_indices(decrypt_idx(key))
        evaluations += 1
        stale = 0
        while stale < patience:
            a = rng.randrange(M)
            b = rng.randrange(M)
            if a == b:
                continue
            key[a], key[b] = key[b], key[a]
            trial = scorer.score_indices(decrypt_idx(key))
            evaluations += 1
            if trial > score:
                score = trial
                stale = 0
            else:
                key[a], key[b] = key[b], key[a]  # відкат
                stale += 1

        if score > best_score:
            best_score, best_key = score, list(key)

    plaintext = decrypt_with_effective_key(ciphertext, best_key)
    elapsed = time.perf_counter() - t0

    notes: dict[str, object] = {
        "restarts": restarts,
        "patience": patience,
        "init": init,
        "score_per_char": best_score / length if length else 0.0,
    }
    success = True
    if expected_plaintext is not None:
        matches = sum(1 for a, b in zip(plaintext, expected_plaintext) if a == b)
        accuracy = matches / max(len(expected_plaintext), 1)
        notes["accuracy"] = accuracy
        notes["exact"] = plaintext == expected_plaintext
        success = accuracy >= 0.95

    return AttackResult(
        name="Тільки шифротекст (hill climbing)",
        success=success,
        plaintext=plaintext,
        key=tuple(best_key),
        score=best_score,
        elapsed_s=elapsed,
        evaluations=evaluations,
        notes=notes,
    )


# --------------------------------------------------------------------------- #
#  Діагностика дифузії
# --------------------------------------------------------------------------- #

def avalanche_test(
    machine: EnigmaMachine,
    length: int = 200,
    trials: int = 300,
    rng: random.Random | int | None = None,
) -> dict[str, float]:
    """
    Лавинний ефект: яка частка символів шифротексту змінюється,
    якщо змінити ОДИН символ відкритого тексту.

    Для стійкого блокового шифру очікується ~50 %. Тут очікується
    рівно один змінений символ, тобто ``1/L`` — дифузія відсутня
    повністю, кожен символ шифрується незалежно від решти.
    """
    if not isinstance(rng, random.Random):
        rng = random.Random(rng)

    changed_total = 0
    for _ in range(trials):
        pt = [rng.choice(ALPHABET) for _ in range(length)]
        base = machine.encode("".join(pt))
        pos = rng.randrange(length)
        original = pt[pos]
        pt[pos] = rng.choice([c for c in ALPHABET if c != original])
        mutated = machine.encode("".join(pt))
        changed_total += sum(1 for a, b in zip(base, mutated) if a != b)

    avg_changed = changed_total / trials
    return {
        "message_length": float(length),
        "trials": float(trials),
        "avg_changed_chars": avg_changed,
        "avalanche_ratio": avg_changed / length,
        "ideal_ratio": 0.5,
    }


def run_all_attacks(
    machine: EnigmaMachine,
    plaintext: str,
    *,
    crib_length: int = 40,
    restarts: int = 24,
    rng: random.Random | int | None = None,
) -> list[AttackResult]:
    """Прогін усіх чотирьох атак на одному повідомленні — зручно для звіту."""
    ciphertext = machine.encode(plaintext)
    results = [
        brute_force_shift(ciphertext, machine.rotors),
        known_plaintext_attack(
            plaintext[:crib_length], ciphertext[:crib_length],
            full_ciphertext=ciphertext,
        ),
        chosen_plaintext_attack(machine.encode, ciphertext),
        ciphertext_only_attack(
            ciphertext, restarts=restarts, rng=rng, expected_plaintext=plaintext
        ),
    ]
    truth = machine.effective_key
    for r in results:
        r.notes["key_exact_match"] = r.key == truth
        if r.name.startswith("Відомий"):
            r.success = r.plaintext == plaintext
    return results
