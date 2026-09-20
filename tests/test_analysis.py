"""Тести статистичного модуля."""

from __future__ import annotations

import random

import pytest

from enigma import ALPHABET, M, CODINGAME_ROTORS, EnigmaMachine, Rotor
from enigma.analysis import (
    ENGLISH_FREQ,
    IOC_ENGLISH,
    IOC_RANDOM,
    average_column_ioc,
    chi_squared,
    columns,
    index_of_coincidence,
    ioc_by_period,
    letter_frequencies,
    shannon_entropy,
    summary,
)
from enigma.ngrams import NgramScorer, default_scorer

ENGLISH_SAMPLE = (
    "ITISATRUTHUNIVERSALLYACKNOWLEDGEDTHATASINGLEMANINPOSSESSIONOFA"
    "GOODFORTUNEMUSTBEINWANTOFAWIFEHOWEVERLITTLEKNOWNTHEFEELINGSOR"
    "VIEWSOFSUCHAMANMAYBEONHISFIRSTENTERINGANEIGHBOURHOODTHISTRUTH"
    "ISSOWELLFIXEDINTHEMINDSOFTHESURROUNDINGFAMILIESTHATHEISCONSIDERED"
) * 4


def test_english_frequencies_sum_to_100() -> None:
    assert abs(sum(ENGLISH_FREQ.values()) - 100.0) < 0.1


def test_ioc_of_english_text() -> None:
    ioc = index_of_coincidence(ENGLISH_SAMPLE)
    assert 0.055 < ioc < 0.085, ioc


def test_ioc_of_random_text() -> None:
    rng = random.Random(0)
    text = "".join(rng.choice(ALPHABET) for _ in range(20000))
    assert abs(index_of_coincidence(text) - IOC_RANDOM) < 0.003


def test_ioc_invariant_under_monoalphabetic_substitution() -> None:
    """Проста заміна не змінює IoC — саме тому метрика її викриває."""
    rotor = Rotor(CODINGAME_ROTORS[0])
    assert abs(index_of_coincidence(ENGLISH_SAMPLE)
               - index_of_coincidence(rotor.encode(ENGLISH_SAMPLE))) < 1e-12


def test_cipher_flattens_frequencies() -> None:
    """Інкрементний зсув «розмазує» частоти: IoC падає до випадкового."""
    ct = EnigmaMachine(CODINGAME_ROTORS, 4).encode(ENGLISH_SAMPLE)
    assert index_of_coincidence(ct) < 0.045
    assert chi_squared(ct) > chi_squared(ENGLISH_SAMPLE)


def test_period_26_is_detectable() -> None:
    """
    Головний розпізнавальний тест: розбиття шифротексту на 26 стовпців
    повертає IoC до англійського рівня, бо кожен стовпець —
    це моноалфавітна заміна.
    """
    ct = EnigmaMachine(CODINGAME_ROTORS, 4).encode(ENGLISH_SAMPLE)
    assert average_column_ioc(ct, M) > 0.055
    assert average_column_ioc(ct, 1) < 0.045
    best_period, best_ioc = max(ioc_by_period(ct, 40), key=lambda kv: kv[1])
    assert best_period % M == 0


def test_columns_partition_text() -> None:
    text = "ABCDEFGHIJ"
    cols = columns(text, 3)
    assert cols == ["ADGJ", "BEH", "CFI"]
    assert "".join(sorted("".join(cols))) == "".join(sorted(text))
    with pytest.raises(ValueError):
        columns(text, 0)


def test_entropy_bounds() -> None:
    rng = random.Random(1)
    uniform = "".join(rng.choice(ALPHABET) for _ in range(20000))
    assert 4.65 < shannon_entropy(uniform) <= 4.7005
    assert shannon_entropy("AAAAAAAA") == 0.0
    assert shannon_entropy(ENGLISH_SAMPLE) < shannon_entropy(uniform)


def test_chi_squared_prefers_english() -> None:
    rng = random.Random(2)
    noise = "".join(rng.choice(ALPHABET) for _ in range(len(ENGLISH_SAMPLE)))
    assert chi_squared(ENGLISH_SAMPLE) < chi_squared(noise)


def test_letter_frequencies_sum() -> None:
    freqs = letter_frequencies(ENGLISH_SAMPLE)
    assert abs(sum(freqs) - 100.0) < 1e-9
    assert len(freqs) == M


def test_summary_keys() -> None:
    s = summary(ENGLISH_SAMPLE)
    assert {"length", "ioc", "chi2", "entropy_bits_per_char", "distinct_letters"} <= s.keys()


# --------------------------------------------------------------------------- #
#  Мовна модель
# --------------------------------------------------------------------------- #

def test_scorer_prefers_english() -> None:
    scorer = default_scorer()
    rng = random.Random(3)
    noise = "".join(rng.choice(ALPHABET) for _ in range(200))
    assert scorer.score(ENGLISH_SAMPLE[:200]) > scorer.score(noise)


def test_scorer_handles_short_and_empty_input() -> None:
    scorer = default_scorer()
    assert scorer.score("") < 0
    assert scorer.score("AB") < 0


def test_scorer_string_and_index_paths_agree() -> None:
    scorer = default_scorer()
    text = ENGLISH_SAMPLE[:120]
    idx = [ord(c) - 65 for c in text]
    assert abs(scorer.score(text) - scorer.score_indices(idx)) < 1e-9


def test_fallback_scorer_when_model_missing(tmp_path) -> None:
    scorer = NgramScorer(tmp_path / "missing.txt.gz")
    assert scorer.n == 1
    assert "fallback" in scorer.source
    assert scorer.score("THEQUICKBROWNFOX") > scorer.score("ZZZZZZZZZZZZZZZZ")


def test_unicity_distance() -> None:
    """Теоретична межа однозначного зламу для ключа 26! ≈ 28 символів."""
    import math

    from enigma.analysis import unicity_distance

    u = unicity_distance(math.log2(math.factorial(26)))
    assert 25 < u < 30
    # Коли ротори відомі, ключ — лише зсув: межа падає до кількох символів.
    assert unicity_distance(math.log2(26)) < 2.0
