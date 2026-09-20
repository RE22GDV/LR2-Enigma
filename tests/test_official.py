"""
Прогін офіційних валідаційних тестів CodinGame.

Дані у ``tests/official_cases.json`` — це саме ті шість тестів, які
виконує валідатор платформи (входи та еталонні виходи).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from enigma import EnigmaMachine

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CASES = json.loads((HERE / "official_cases.json").read_text(encoding="utf-8"))["cases"]

IDS = [c["label"] for c in CASES]


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_official_case(case: dict) -> None:
    machine = EnigmaMachine(case["rotors"], case["shift"])
    assert machine.process(case["mode"], case["message"]) == case["expected"]


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_official_case_is_reversible(case: dict) -> None:
    """Зворотна операція повертає вихідне повідомлення."""
    machine = EnigmaMachine(case["rotors"], case["shift"])
    if case["mode"] == "ENCODE":
        assert machine.decode(case["expected"]) == case["message"]
    else:
        assert machine.encode(case["expected"]) == case["message"]


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_standalone_codingame_script(case: dict, tmp_path: Path) -> None:
    """Файл, який вставляється в редактор CodinGame, теж має проходити тести."""
    script = ROOT / "solution" / "codingame_solution.py"
    stdin = "%s\n%d\n%s\n%s\n" % (
        case["mode"], case["shift"], "\n".join(case["rotors"]), case["message"]
    )
    proc = subprocess.run(
        [sys.executable, str(script)],
        input=stdin, capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == case["expected"]


def test_all_cases_share_the_same_rotors() -> None:
    """
    Спостереження, важливе для криптоаналізу: у всіх офіційних тестах
    ротори однакові, тобто справжнім секретом є лише зсув N.
    """
    rotor_sets = {tuple(c["rotors"]) for c in CASES}
    assert len(rotor_sets) == 1


def test_cli_selftest_command() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "run.py"), "selftest"],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
