"""Модульні тести ядра шифру."""

from __future__ import annotations

import random
import string

import pytest

from enigma import (
    ALPHABET,
    M,
    CODINGAME_ROTORS,
    EnigmaMachine,
    MessageError,
    Rotor,
    RotorError,
    decrypt_with_effective_key,
    encrypt_with_effective_key,
    invert,
    random_rotor_set,
)

R1, R2, R3 = CODINGAME_ROTORS


# --------------------------------------------------------------------------- #
#  Ротор
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "bad",
    [
        "",                              # порожній
        "ABC",                           # закороткий
        "ABCDEFGHIJKLMNOPQRSTUVWXYZA",   # задовгий
        "AACDEFGHIJKLMNOPQRSTUVWXYZ",    # дублікат, пропущена B
        "ABCDEFGHIJKLMNOPQRSTUVWXY1",    # не літера
    ],
)
def test_rotor_rejects_invalid_wiring(bad: str) -> None:
    with pytest.raises(RotorError):
        Rotor(bad)


def test_rotor_accepts_identity_and_is_bijective() -> None:
    rotor = Rotor(ALPHABET)
    assert rotor.encode(ALPHABET) == ALPHABET
    assert sorted(rotor.forward) == list(range(M))


def test_rotor_inverse_roundtrip() -> None:
    rotor = Rotor(R1)
    assert rotor.decode(rotor.encode(ALPHABET)) == ALPHABET
    assert rotor.inverse().forward == rotor.backward


def test_invert_is_involution() -> None:
    rng = random.Random(1)
    perm = list(range(M))
    rng.shuffle(perm)
    assert invert(invert(perm)) == tuple(perm)


# --------------------------------------------------------------------------- #
#  Приклад із умови задачі, розібраний по кроках
# --------------------------------------------------------------------------- #

def test_statement_example_step_by_step() -> None:
    """AAA -(зсув 4)-> EFG -(R1)-> JLC -(R2)-> BHD -(R3)-> KQF"""
    shifted = "".join(
        chr(ord("A") + (0 + 4 + i) % M) for i in range(3)
    )
    assert shifted == "EFG"
    after_r1 = Rotor(R1).encode(shifted)
    assert after_r1 == "JLC"
    after_r2 = Rotor(R2).encode(after_r1)
    assert after_r2 == "BHD"
    after_r3 = Rotor(R3).encode(after_r2)
    assert after_r3 == "KQF"
    assert EnigmaMachine(CODINGAME_ROTORS, 4).encode("AAA") == "KQF"


# --------------------------------------------------------------------------- #
#  Машина
# --------------------------------------------------------------------------- #

def test_roundtrip_property_random() -> None:
    """Розшифрування — точна інверсія шифрування для будь-яких входів."""
    rng = random.Random(42)
    for _ in range(300):
        rotors = random_rotor_set(3, rng)
        shift = rng.randrange(M)
        length = rng.randrange(1, 60)
        msg = "".join(rng.choice(ALPHABET) for _ in range(length))
        machine = EnigmaMachine(rotors, shift)
        assert machine.decode(machine.encode(msg)) == msg


def test_shift_is_modular() -> None:
    msg = "HELLOWORLD"
    assert (EnigmaMachine(CODINGAME_ROTORS, 3).encode(msg)
            == EnigmaMachine(CODINGAME_ROTORS, 29).encode(msg))
    assert (EnigmaMachine(CODINGAME_ROTORS, 0).encode(msg)
            == EnigmaMachine(CODINGAME_ROTORS, 26).encode(msg))


def test_shift_increments_per_position() -> None:
    """Однакові літери відкритого тексту дають різні літери шифротексту."""
    out = EnigmaMachine(CODINGAME_ROTORS, 0).encode("A" * M)
    assert len(set(out)) == M, "усі 26 символів мають бути різними"


def test_period_is_exactly_26() -> None:
    """Алфавіт заміни повторюється рівно через 26 позицій."""
    machine = EnigmaMachine(CODINGAME_ROTORS, 5)
    out = machine.encode("A" * 52)
    assert out[:26] == out[26:]


def test_message_validation() -> None:
    machine = EnigmaMachine(CODINGAME_ROTORS, 1)
    for bad in ["hello", "AB C", "AB!", "ПРИВІТ"]:
        with pytest.raises(MessageError):
            machine.encode(bad)


def test_empty_message() -> None:
    assert EnigmaMachine(CODINGAME_ROTORS, 4).encode("") == ""
    assert EnigmaMachine(CODINGAME_ROTORS, 4).decode("") == ""


def test_process_dispatch() -> None:
    machine = EnigmaMachine(CODINGAME_ROTORS, 4)
    assert machine.process("ENCODE", "AAA") == "KQF"
    assert machine.process("decode", "KQF") == "AAA"
    with pytest.raises(ValueError):
        machine.process("ROTATE", "AAA")


# --------------------------------------------------------------------------- #
#  Структурні властивості — основа криптоаналізу
# --------------------------------------------------------------------------- #

def test_three_rotors_collapse_to_one() -> None:
    """Каскад із трьох роторів + зсув еквівалентний одному ротору без зсуву."""
    rng = random.Random(7)
    for _ in range(50):
        machine = EnigmaMachine(random_rotor_set(3, rng), rng.randrange(M))
        equivalent = machine.equivalent_single_rotor()
        assert len(equivalent.rotors) == 1
        assert equivalent.shift == 0
        msg = "".join(rng.choice(ALPHABET) for _ in range(80))
        assert equivalent.encode(msg) == machine.encode(msg)


def test_effective_key_is_a_bijection() -> None:
    rng = random.Random(11)
    for _ in range(50):
        key = EnigmaMachine(random_rotor_set(3, rng), rng.randrange(M)).effective_key
        assert sorted(key) == list(range(M))


def test_effective_key_reproduces_cipher() -> None:
    rng = random.Random(13)
    machine = EnigmaMachine(random_rotor_set(3, rng), 17)
    key = machine.effective_key
    msg = "".join(rng.choice(ALPHABET) for _ in range(120))
    ct = machine.encode(msg)
    assert decrypt_with_effective_key(ct, key) == msg
    assert encrypt_with_effective_key(msg, key) == ct


def test_rotor_order_matters() -> None:
    """Композиція підстановок некомутативна — порядок роторів значущий."""
    a = EnigmaMachine([R1, R2, R3], 4).encode("HELLOWORLD")
    b = EnigmaMachine([R3, R2, R1], 4).encode("HELLOWORLD")
    assert a != b


def test_alphabets_property() -> None:
    machine = EnigmaMachine(CODINGAME_ROTORS, 0)
    alphabets = machine.alphabets
    assert len(alphabets) == M
    assert all(sorted(a) == list(ALPHABET) for a in alphabets)
    # Алфавіт номер p — це S, застосована до алфавіту, зсунутого на p.
    assert alphabets[0] == "".join(chr(65 + v) for v in machine.substitution)


def test_no_rotors_rejected() -> None:
    with pytest.raises(RotorError):
        EnigmaMachine([], 0)


def test_single_rotor_machine_is_valid() -> None:
    machine = EnigmaMachine([R1], 3)
    assert machine.decode(machine.encode("TESTMESSAGE")) == "TESTMESSAGE"
