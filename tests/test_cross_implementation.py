"""
Перехресна перевірка двох незалежних реалізацій (Python і C#).

Тести автоматично пропускаються, якщо .NET SDK не встановлено.
"""

from __future__ import annotations

import json
import random
import shutil
import subprocess
from pathlib import Path

import pytest

from enigma import ALPHABET, M, CODINGAME_ROTORS, EnigmaMachine

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PROJECT = ROOT / "csharp" / "Enigma"
CASES = json.loads((HERE / "official_cases.json").read_text(encoding="utf-8"))["cases"]

dotnet_required = pytest.mark.skipif(
    shutil.which("dotnet") is None, reason=".NET SDK не встановлено"
)


def _run_csharp(args: list[str], stdin: str | None = None) -> str:
    # Явне UTF-8: програма на C# сама виставляє Console.OutputEncoding = UTF8,
    # тож покладатися на локаль консолі Windows не можна.
    proc = subprocess.run(
        ["dotnet", "run", "--project", str(PROJECT), "--"] + args,
        input=stdin, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout.strip()


@dotnet_required
def test_csharp_selftest_passes() -> None:
    out = _run_csharp(["selftest"])
    assert "пройдено 6 з 6" in out
    assert "2000 з 2000" in out
    assert "FAIL" not in out


@dotnet_required
@pytest.mark.parametrize("shift", [0, 4, 13, 25])
def test_python_and_csharp_agree(shift: int) -> None:
    """Обидві реалізації мають давати однаковий шифротекст."""
    rng = random.Random(shift)
    message = "".join(rng.choice(ALPHABET) for _ in range(45))
    expected = EnigmaMachine(CODINGAME_ROTORS, shift).encode(message)
    assert _run_csharp(["encode", str(shift), message]) == expected


@dotnet_required
def test_csharp_stdin_mode_matches_official_cases() -> None:
    for case in CASES:
        stdin = "%s\n%d\n%s\n%s\n" % (
            case["mode"], case["shift"], "\n".join(case["rotors"]), case["message"]
        )
        assert _run_csharp([], stdin=stdin) == case["expected"], case["label"]
