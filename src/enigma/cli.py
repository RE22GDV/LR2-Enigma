"""
Командний інтерфейс лабораторної роботи.

    python run.py encode  --shift 4 --message AAA
    python run.py decode  --shift 4 --message KQF
    python run.py solve   < tests/samples/case1.txt      # формат CodinGame
    python run.py analyze --text <шифротекст>
    python run.py attack  --message "<відкритий текст>" --shift 11
    python run.py keyspace
    python run.py selftest
"""

from __future__ import annotations

import argparse
import io
import json
import random
import sys
from pathlib import Path

from .analysis import (
    ENGLISH_FREQ,
    IOC_ENGLISH,
    IOC_RANDOM,
    chi_squared,
    describe_distance_to_english,
    index_of_coincidence,
    ioc_by_period,
    letter_frequencies,
    shannon_entropy,
)
from .attacks import (
    avalanche_test,
    find_key_collision,
    keyspace_analysis,
    run_all_attacks,
)
from .core import ALPHABET, EnigmaMachine, normalize
from .rotors import CODINGAME_ROTORS, describe

ROOT = Path(__file__).resolve().parents[2]


def _utf8_stdout() -> None:
    """Щоб кирилиця коректно друкувалася в консолі Windows."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")


def _machine(args: argparse.Namespace) -> EnigmaMachine:
    rotors = args.rotors if args.rotors else list(CODINGAME_ROTORS)
    if len(rotors) != 3:
        print("попередження: очікувалося 3 ротори, отримано %d" % len(rotors))
    return EnigmaMachine(rotors, args.shift)


def _bar(value: float, scale: float, width: int = 40) -> str:
    n = int(round(width * min(value / scale, 1.0))) if scale > 0 else 0
    return "#" * n


# --------------------------------------------------------------------------- #
#  Команди
# --------------------------------------------------------------------------- #

def cmd_encode(args: argparse.Namespace) -> int:
    msg = normalize(args.message)
    print(_machine(args).encode(msg))
    return 0


def cmd_decode(args: argparse.Namespace) -> int:
    msg = normalize(args.message)
    print(_machine(args).decode(msg))
    return 0


def cmd_solve(args: argparse.Namespace) -> int:
    """Режим CodinGame: читає 6 рядків зі stdin, друкує результат."""
    data = sys.stdin.read().split()
    if len(data) < 5:
        print("недостатньо вхідних даних", file=sys.stderr)
        return 2
    mode, shift, rotors = data[0], int(data[1]), data[2:5]
    message = data[5] if len(data) > 5 else ""
    print(EnigmaMachine(rotors, shift).process(mode, message))
    return 0


def cmd_rotors(args: argparse.Namespace) -> int:
    print("Ротори з умови задачі CodinGame\n" + "-" * 72)
    for i, wiring in enumerate(CODINGAME_ROTORS, 1):
        info = describe(wiring)
        print("ROTOR %-3s %s" % (("%d:" % i), info["wiring"]))
        print("          історична назва : Enigma I, Rotor %s" % info["historical_name"])
        print("          нерухомі точки   : %s" % (", ".join(info["fixed_points"]) or "—"))
        print("          циклова структура: %s" % (info["cycle_type"],))
    print("\nВисновок: CodinGame подає історичні ротори Enigma I "
          "у зворотному порядку (III, II, I).")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    text = normalize(args.text) if args.text else normalize(sys.stdin.read())
    if not text:
        print("порожній текст", file=sys.stderr)
        return 2

    print("Довжина            : %d" % len(text))
    print("Ентропія           : %.4f біт/символ (макс. 4.7004)" % shannon_entropy(text))
    print("Індекс відповідності: %.5f  (англ. %.4f, випадк. %.4f)"
          % (index_of_coincidence(text), IOC_ENGLISH, IOC_RANDOM))
    print("Хі-квадрат до англ. : %.1f" % chi_squared(text))
    print("Інтерпретація      : %s" % describe_distance_to_english(text))

    print("\nЧастотний аналіз (спостережувано проти англійської):")
    freqs = letter_frequencies(text)
    for i, letter in enumerate(ALPHABET):
        print("  %s %5.2f%% %-22s | еталон %5.2f%% %s"
              % (letter, freqs[i], _bar(freqs[i], 13.0, 22),
                 ENGLISH_FREQ[letter], _bar(ENGLISH_FREQ[letter], 13.0, 22)))

    if len(text) >= 60:
        print("\nПрофіль IoC за припущеним періодом (сплеск = справжній період):")
        profile = ioc_by_period(text, min(40, len(text) // 3))
        top = sorted(profile, key=lambda kv: -kv[1])[:5]
        for period, ioc in profile:
            mark = "  <== " if (period, ioc) in top else ""
            print("  період %2d : %.5f %s%s" % (period, ioc, _bar(ioc, 0.09, 30), mark))
    return 0


def cmd_attack(args: argparse.Namespace) -> int:
    plaintext = normalize(args.message)
    machine = _machine(args)
    ciphertext = machine.encode(plaintext)

    print("Відкритий текст : %s" % plaintext)
    print("Шифротекст      : %s" % ciphertext)
    print("Справжній ключ  : зсув N=%d, ефективний ключ D=%s"
          % (machine.shift, "".join(chr(65 + v) for v in machine.effective_key)))
    print("\n%-34s %-9s %-11s %-9s %s"
          % ("Атака", "Статус", "Оцінка", "Час, с", "Відновлений текст"))
    print("-" * 110)

    results = run_all_attacks(
        machine, plaintext, crib_length=args.crib, restarts=args.restarts, rng=args.seed
    )
    for r in results:
        print("%-34s %-9s %11.1f %9.3f  %s"
              % (r.name, "УСПІХ" if r.success else "частково",
                 r.score, r.elapsed_s, r.plaintext[:46]))
        print("     ключ відновлено точно: %s | обчислень: %d"
              % ("так" if r.notes.get("key_exact_match") else "ні", r.evaluations))
    return 0


def cmd_keyspace(args: argparse.Namespace) -> int:
    ks = keyspace_analysis()
    print("Оцінка простору ключів")
    print("-" * 60)
    print("Один ротор (26!)            : 2^%.2f" % ks["bits_per_rotor"])
    print("Номінальний ключ (3 ротори+N): 2^%.2f" % ks["nominal_bits"])
    print("Фактичний (ефективний) ключ : 2^%.2f" % ks["effective_bits"])
    print("Втрата стійкості            : 2^%.2f біт «зайвого» ключа"
          % ks["reduction_bits"])
    print("За Керкгоффсом (ротори відомі): 2^%.2f  <-- випадок цієї задачі"
          % ks["kerckhoffs_bits"])

    print("\nКонструктивний доказ надлишковості (колізія ключів):")
    collision = find_key_collision(rng=args.seed)
    if collision:
        a, b = collision["key_a"], collision["key_b"]
        print("  Ключ A: N=%d, ротори=%s" % (a["shift"], a["rotors"]))
        print("  Ключ B: N=%d, ротори=%s" % (b["shift"], b["rotors"]))
        print("  Обидва дають однаковий шифротекст на 120 випадкових символах: так")

    print("\nМіжсимвольна дифузія:")
    av = avalanche_test(EnigmaMachine(CODINGAME_ROTORS, 7), rng=args.seed)
    print("  Змінено символів шифротексту при зміні 1 символу: %.2f з %d"
          % (av["avg_changed_chars"], int(av["message_length"])))
    print("  Частка: %.4f   (змінюється рівно одна позиція з L)"
          % av["avalanche_ratio"])
    return 0


def cmd_selftest(args: argparse.Namespace) -> int:
    path = ROOT / "tests" / "official_cases.json"
    cases = json.loads(path.read_text(encoding="utf-8"))["cases"]
    passed = 0
    print("Офіційні тести CodinGame")
    print("-" * 72)
    for case in cases:
        got = EnigmaMachine(case["rotors"], case["shift"]).process(
            case["mode"], case["message"]
        )
        ok = got == case["expected"]
        passed += ok
        print("[%s] %-11s %s -> %s" % ("OK" if ok else "FAIL", case["label"],
                                       case["mode"], got))
    print("-" * 72)
    print("Пройдено %d з %d" % (passed, len(cases)))
    return 0 if passed == len(cases) else 1


# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="enigma",
        description="Лабораторна робота №2: шифр Енігми та його криптоаналіз.",
    )
    p.add_argument("--seed", type=int, default=2024, help="зерно генератора (для відтворюваності)")
    sub = p.add_subparsers(dest="command", required=True)

    def add_cipher_args(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--shift", type=int, default=0, help="початковий зсув N")
        sp.add_argument("--rotors", nargs="*", default=None,
                        help="три ротори по 26 літер (типово — з умови задачі)")

    sp = sub.add_parser("encode", help="зашифрувати повідомлення")
    add_cipher_args(sp)
    sp.add_argument("--message", required=True)
    sp.set_defaults(func=cmd_encode)

    sp = sub.add_parser("decode", help="розшифрувати повідомлення")
    add_cipher_args(sp)
    sp.add_argument("--message", required=True)
    sp.set_defaults(func=cmd_decode)

    sp = sub.add_parser("solve", help="режим CodinGame: 6 рядків зі stdin")
    sp.set_defaults(func=cmd_solve)

    sp = sub.add_parser("rotors", help="паспорт роторів з умови задачі")
    sp.set_defaults(func=cmd_rotors)

    sp = sub.add_parser("analyze", help="статистичний аналіз тексту")
    sp.add_argument("--text", default=None, help="текст (типово — зі stdin)")
    sp.set_defaults(func=cmd_analyze)

    sp = sub.add_parser("attack", help="прогін усіх чотирьох атак")
    add_cipher_args(sp)
    sp.add_argument("--message", required=True, help="відкритий текст для експерименту")
    sp.add_argument("--crib", type=int, default=40, help="довжина відомого фрагмента")
    sp.add_argument("--restarts", type=int, default=24, help="перезапуски сходження за схилом")
    sp.set_defaults(func=cmd_attack)

    sp = sub.add_parser("keyspace", help="оцінка простору ключів і дифузії")
    sp.set_defaults(func=cmd_keyspace)

    sp = sub.add_parser("selftest", help="прогін офіційних тестів CodinGame")
    sp.set_defaults(func=cmd_selftest)
    return p


def main(argv: list[str] | None = None) -> int:
    _utf8_stdout()
    args = build_parser().parse_args(argv)
    random.seed(args.seed)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
