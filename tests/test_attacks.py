"""Тести криптоаналітичних атак."""

from __future__ import annotations

import math
import random

import pytest

from enigma import ALPHABET, M, CODINGAME_ROTORS, EnigmaMachine, random_rotor_set
from enigma.attacks import (
    avalanche_test,
    brute_force_shift,
    chosen_plaintext_attack,
    ciphertext_only_attack,
    expected_crib_coverage,
    find_key_collision,
    frequency_initial_key,
    keyspace_analysis,
    known_plaintext_attack,
    run_all_attacks,
)

LONG_PLAINTEXT = (
    "THEENEMYFLEETWILLAPPROACHTHENORTHERNHARBOURSHORTLYAFTERDAWNAND"
    "WEMUSTSENDEVERYAVAILABLEREINFORCEMENTTOHOLDTHELINEUNTILMORNING"
    "BECAUSETHESUPPLYCONVOYCANNOTARRIVEBEFORETHEENDOFTHEWEEKUNDERANY"
    "CIRCUMSTANCESWHATSOEVERANDTHEGARRISONISALREADYSHORTOFAMMUNITION"
)

SHORT_PLAINTEXT = "ATTACKATDAWNTOMORROWMORNING"


# --------------------------------------------------------------------------- #
#  Атака 1 — перебір зсуву
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("shift", list(range(0, M, 5)))
def test_brute_force_recovers_shift(shift: int) -> None:
    machine = EnigmaMachine(CODINGAME_ROTORS, shift)
    result = brute_force_shift(machine.encode(LONG_PLAINTEXT), CODINGAME_ROTORS)
    assert result.notes["recovered_shift"] == shift
    assert result.plaintext == LONG_PLAINTEXT
    assert result.evaluations == M


def test_brute_force_works_on_short_message() -> None:
    machine = EnigmaMachine(CODINGAME_ROTORS, 19)
    result = brute_force_shift(machine.encode(SHORT_PLAINTEXT), CODINGAME_ROTORS)
    assert result.plaintext == SHORT_PLAINTEXT


def test_brute_force_is_fast() -> None:
    machine = EnigmaMachine(CODINGAME_ROTORS, 3)
    result = brute_force_shift(machine.encode(LONG_PLAINTEXT), CODINGAME_ROTORS)
    assert result.elapsed_s < 1.0


# --------------------------------------------------------------------------- #
#  Атака 2 — відомий відкритий текст
# --------------------------------------------------------------------------- #

def test_known_plaintext_recovers_full_key_with_long_crib() -> None:
    machine = EnigmaMachine(CODINGAME_ROTORS, 8)
    ct = machine.encode(LONG_PLAINTEXT)
    result = known_plaintext_attack(LONG_PLAINTEXT, ct)
    assert result.notes["contradictions"] == 0
    assert result.notes["key_coverage"] == M
    assert result.key == machine.effective_key
    assert result.plaintext == LONG_PLAINTEXT


def test_known_plaintext_partial_crib_is_consistent() -> None:
    """Короткий фрагмент дає частковий ключ — але без суперечностей."""
    machine = EnigmaMachine(CODINGAME_ROTORS, 8)
    ct = machine.encode(LONG_PLAINTEXT)
    result = known_plaintext_attack(LONG_PLAINTEXT[:20], ct[:20], full_ciphertext=ct)
    assert result.notes["contradictions"] == 0
    assert 0 < result.notes["key_coverage"] <= M
    # Ділянка, покрита шпаргалкою, розшифровується правильно.
    assert result.plaintext[:20] == LONG_PLAINTEXT[:20]


def test_known_plaintext_detects_mismatch() -> None:
    machine = EnigmaMachine(CODINGAME_ROTORS, 8)
    ct = machine.encode(LONG_PLAINTEXT)
    result = known_plaintext_attack("X" * 60, ct[:60])
    assert result.notes["contradictions"] > 0
    assert not result.success


def test_expected_crib_coverage_matches_simulation() -> None:
    """Теоретична крива покриття збігається з емпіричною."""
    rng = random.Random(5)
    length = 60
    trials = 400
    total = 0
    for _ in range(trials):
        machine = EnigmaMachine(random_rotor_set(3, rng), rng.randrange(M))
        pt = "".join(rng.choice(ALPHABET) for _ in range(length))
        res = known_plaintext_attack(pt, machine.encode(pt))
        total += res.notes["key_coverage"]
    empirical = total / trials
    assert abs(empirical - expected_crib_coverage(length)) < 1.0


# --------------------------------------------------------------------------- #
#  Атака 3 — підібраний відкритий текст
# --------------------------------------------------------------------------- #

def test_chosen_plaintext_needs_exactly_one_query() -> None:
    rng = random.Random(3)
    for _ in range(25):
        machine = EnigmaMachine(random_rotor_set(3, rng), rng.randrange(M))
        calls = []

        def oracle(text: str) -> str:
            calls.append(text)
            return machine.encode(text)

        pt = "".join(rng.choice(ALPHABET) for _ in range(90))
        result = chosen_plaintext_attack(oracle, machine.encode(pt))
        assert len(calls) == 1
        assert len(calls[0]) == M
        assert result.key == machine.effective_key
        assert result.plaintext == pt


# --------------------------------------------------------------------------- #
#  Атака 4 — тільки шифротекст
# --------------------------------------------------------------------------- #

def test_ciphertext_only_attack_recovers_long_message() -> None:
    machine = EnigmaMachine(CODINGAME_ROTORS, 11)
    ct = machine.encode(LONG_PLAINTEXT)
    result = ciphertext_only_attack(
        ct, restarts=20, rng=2024, expected_plaintext=LONG_PLAINTEXT
    )
    assert result.success
    assert result.plaintext == LONG_PLAINTEXT
    assert result.key == machine.effective_key


def test_ciphertext_only_attack_works_with_unknown_rotors() -> None:
    """Атака не знає ані роторів, ані зсуву — лише шифротекст."""
    rng = random.Random(99)
    machine = EnigmaMachine(random_rotor_set(3, rng), rng.randrange(M))
    ct = machine.encode(LONG_PLAINTEXT)
    result = ciphertext_only_attack(
        ct, restarts=20, rng=7, expected_plaintext=LONG_PLAINTEXT
    )
    assert result.notes["accuracy"] >= 0.95


def test_frequency_initial_key_is_bijection() -> None:
    machine = EnigmaMachine(CODINGAME_ROTORS, 4)
    key = frequency_initial_key(machine.encode(LONG_PLAINTEXT))
    assert sorted(key) == list(range(M))


# --------------------------------------------------------------------------- #
#  Структурні висновки
# --------------------------------------------------------------------------- #

def test_keyspace_numbers() -> None:
    ks = keyspace_analysis()
    assert math.isclose(ks["bits_per_rotor"], math.log2(math.factorial(26)), rel_tol=1e-12)
    assert ks["nominal_bits"] > 260
    assert 88 < ks["effective_bits"] < 89
    assert ks["reduction_bits"] > 175
    assert math.isclose(ks["kerckhoffs_bits"], math.log2(26), rel_tol=1e-12)


def test_key_collision_exists() -> None:
    collision = find_key_collision(rng=1)
    assert collision is not None
    assert collision["key_a"]["rotors"] != collision["key_b"]["rotors"]


def test_avalanche_effect_is_absent() -> None:
    """Зміна одного символу відкритого тексту змінює рівно один символ шифротексту."""
    av = avalanche_test(EnigmaMachine(CODINGAME_ROTORS, 7), length=100, trials=100, rng=1)
    assert math.isclose(av["avg_changed_chars"], 1.0, abs_tol=1e-9)
    assert av["avalanche_ratio"] < 0.02


def test_run_all_attacks_smoke() -> None:
    machine = EnigmaMachine(CODINGAME_ROTORS, 15)
    results = run_all_attacks(machine, LONG_PLAINTEXT, crib_length=40, restarts=12, rng=5)
    assert len(results) == 4
    by_name = {r.name: r for r in results}

    # Три атаки відновлюють текст повністю.
    for name in ("Перебір зсуву (26 ключів)",
                 "Підібраний відкритий текст",
                 "Тільки шифротекст (hill climbing)"):
        assert by_name[name].plaintext == LONG_PLAINTEXT, name
        assert by_name[name].key == machine.effective_key, name

    # Атака з короткою шпаргалкою — частковий ключ, але без суперечностей
    # і з коректною розшифровкою покритої ділянки.
    crib = by_name["Відомий відкритий текст"]
    assert crib.notes["contradictions"] == 0
    assert crib.notes["key_coverage"] < M
    assert crib.plaintext[:40] == LONG_PLAINTEXT[:40]


def test_run_all_attacks_full_crib_recovers_everything() -> None:
    machine = EnigmaMachine(CODINGAME_ROTORS, 15)
    results = run_all_attacks(machine, LONG_PLAINTEXT, crib_length=len(LONG_PLAINTEXT),
                              restarts=12, rng=5)
    assert all(r.plaintext == LONG_PLAINTEXT for r in results)
    assert all(r.key == machine.effective_key for r in results)
