"""
Обчислювальні експерименти лабораторної роботи.

Скрипт відтворює всі числа й графіки, наведені в README та у звіті:

    python experiments/run_experiments.py            # усі експерименти
    python experiments/run_experiments.py --quick    # скорочений прогін

Результати:
    docs/results/experiments.json   — усі виміряні величини
    docs/results/summary.md         — зведена таблиця для звіту
    docs/figures/*.png              — сім рисунків

Усі генератори випадкових чисел ініціалізуються фіксованим зерном,
тому результати відтворювані побітово.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import PercentFormatter  # noqa: E402

from enigma import ALPHABET, M, CODINGAME_ROTORS, EnigmaMachine, normalize  # noqa: E402
from enigma.analysis import (  # noqa: E402
    ENGLISH_FREQ,
    IOC_ENGLISH,
    IOC_RANDOM,
    average_column_ioc,
    chi_squared,
    index_of_coincidence,
    ioc_by_period,
    letter_frequencies,
    shannon_entropy,
)
from enigma.attacks import (  # noqa: E402
    avalanche_test,
    brute_force_shift,
    chosen_plaintext_attack,
    ciphertext_only_attack,
    expected_crib_coverage,
    find_key_collision,
    keyspace_analysis,
    known_plaintext_attack,
)
from enigma.ngrams import default_scorer  # noqa: E402

# --------------------------------------------------------------------------- #
#  Оформлення рисунків
#  Палітра — перші три категорійні слоти референсної системи (blue/orange/aqua):
#  саме ця трійка проходить перевірку all-pairs за колірним зором.
# --------------------------------------------------------------------------- #

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
GRID = "#e3e2de"
S1 = "#2a78d6"   # слот 1 — синій
S2 = "#eb6834"   # слот 2 — помаранчевий
S3 = "#1baf7a"   # слот 3 — бірюзовий

plt.rcParams.update({
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE,
    "axes.edgecolor": GRID,
    "axes.labelcolor": INK_2,
    "axes.titlecolor": INK,
    "axes.titlesize": 12,
    "axes.titleweight": "semibold",
    "axes.labelsize": 9.5,
    "axes.grid": True,
    "axes.axisbelow": True,
    "grid.color": GRID,
    "grid.linewidth": 0.8,
    "xtick.color": INK_2,
    "ytick.color": INK_2,
    "xtick.labelsize": 8.5,
    "ytick.labelsize": 8.5,
    "legend.frameon": False,
    "legend.fontsize": 9,
    "lines.linewidth": 2.0,
    "font.size": 10,
})

FIG = ROOT / "docs" / "figures"
RES = ROOT / "docs" / "results"


def _n(value: float, digits: int = 2) -> str:
    """Число з комою як десятковим роздільником (для підписів на рисунках)."""
    return ("%.*f" % (digits, value)).replace(".", ",")


def _finish(ax, note: str | None = None) -> None:
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    if note:
        ax.text(0.995, -0.16, note, transform=ax.transAxes, ha="right", va="top",
                fontsize=7.5, color=INK_2)


def save(fig, name: str) -> str:
    """
    Зберігає рисунок двічі:
      docs/figures/<name>      — із заголовком, для README на GitHub;
      docs/figures/pdf/<name>  — без заголовка, для PDF-звіту, де роль
                                 заголовка виконує підпис «Рисунок N.M – ...».
    """
    FIG.mkdir(parents=True, exist_ok=True)
    path = FIG / name
    fig.savefig(path, dpi=200, bbox_inches="tight")

    (FIG / "pdf").mkdir(parents=True, exist_ok=True)
    for ax in fig.axes:
        ax.set_title("")
    fig.savefig(FIG / "pdf" / name, dpi=200, bbox_inches="tight")

    plt.close(fig)
    print("    рисунок -> %s (+ pdf/)" % path.relative_to(ROOT))
    return str(path.relative_to(ROOT)).replace("\\", "/")


# --------------------------------------------------------------------------- #

def load_plaintext() -> str:
    return normalize((ROOT / "data" / "sample_plaintext.txt").read_text(encoding="utf-8"))


def sample_of(text: str, length: int, rng: random.Random) -> str:
    start = rng.randrange(len(text))
    doubled = text + text
    return doubled[start:start + length]


# --------------------------------------------------------------------------- #
#  Експеримент 1 — частотний аналіз
# --------------------------------------------------------------------------- #

def exp_frequency(plaintext: str) -> dict:
    print("[1] Частотний аналіз")
    machine = EnigmaMachine(CODINGAME_ROTORS, 7)
    ciphertext = machine.encode(plaintext)

    pt_freq = letter_frequencies(plaintext)
    ct_freq = letter_frequencies(ciphertext)
    ref = [ENGLISH_FREQ[c] for c in ALPHABET]

    fig, ax = plt.subplots(figsize=(10, 4.2))
    x = range(M)
    w = 0.38
    ax.bar([i - w / 2 for i in x], pt_freq, width=w - 0.04, color=S1,
           label="відкритий текст", zorder=3)
    ax.bar([i + w / 2 for i in x], ct_freq, width=w - 0.04, color=S2,
           label="шифротекст", zorder=3)
    ax.plot(list(x), ref, color=INK_2, linewidth=1.4, linestyle=(0, (4, 3)),
            marker="o", markersize=3.2, label="норма англійської мови", zorder=4)

    ax.set_xticks(list(x))
    ax.set_xticklabels(list(ALPHABET))
    ax.set_ylabel("частота, %")
    ax.set_title("Рис. 1. Інкрементний зсув вирівнює частоти літер")
    ax.legend(loc="upper right", ncols=3)
    _finish(ax, "IoC: відкритий %s -> шифротекст %s   |   хі-квадрат: %s -> %s"
            % (_n(index_of_coincidence(plaintext), 4), _n(index_of_coincidence(ciphertext), 4),
               _n(chi_squared(plaintext), 0), _n(chi_squared(ciphertext), 0)))
    path = save(fig, "fig1_frequency.png")

    return {
        "figure": path,
        "plaintext_ioc": index_of_coincidence(plaintext),
        "ciphertext_ioc": index_of_coincidence(ciphertext),
        "plaintext_chi2": chi_squared(plaintext),
        "ciphertext_chi2": chi_squared(ciphertext),
        "plaintext_entropy": shannon_entropy(plaintext),
        "ciphertext_entropy": shannon_entropy(ciphertext),
        "max_ct_freq_deviation_pp": max(abs(f - 100 / M) for f in ct_freq),
    }


# --------------------------------------------------------------------------- #
#  Експеримент 2 — визначення періоду
# --------------------------------------------------------------------------- #

def exp_period(plaintext: str) -> dict:
    print("[2] Визначення періоду за індексом відповідності")
    ciphertext = EnigmaMachine(CODINGAME_ROTORS, 7).encode(plaintext)
    profile = ioc_by_period(ciphertext, 52)
    periods = [p for p, _ in profile]
    values = [v for _, v in profile]
    best = max(profile, key=lambda kv: kv[1])

    fig, ax = plt.subplots(figsize=(9.5, 4.0))
    ax.plot(periods, values, color=S1, marker="o", markersize=4.0,
            markerfacecolor=SURFACE, markeredgewidth=1.6, zorder=3)
    ax.axhline(IOC_ENGLISH, color=INK_2, linewidth=1.2, linestyle=(0, (4, 3)), zorder=2)
    ax.axhline(IOC_RANDOM, color=INK_2, linewidth=1.2, linestyle=(0, (1, 3)), zorder=2)
    ax.set_xlim(-1, 70)
    ax.text(53.5, IOC_ENGLISH, "  англійська 0,0667", va="bottom", fontsize=8, color=INK_2)
    ax.text(53.5, IOC_RANDOM, "  випадкова 0,0385", va="bottom", fontsize=8, color=INK_2)

    peak = dict(profile)[26]
    ax.scatter([26], [peak], s=110, color=S2, zorder=5)
    ax.annotate("період 26\nIoC = %s" % _n(peak, 4),
                xy=(26, peak), xytext=(33, peak - 0.009),
                fontsize=9, color=INK, va="center",
                arrowprops=dict(arrowstyle="-", color=S2, linewidth=1.4))

    ax.set_xlabel("припущений період (кількість стовпців)")
    ax.set_ylabel("середній IoC стовпця")
    ax.set_title("Рис. 2. Профіль IoC викриває поліалфавітний період 26")
    _finish(ax, "довжина шифротексту %d символів" % len(ciphertext))
    path = save(fig, "fig2_ioc_period.png")

    return {
        "figure": path,
        "best_period": best[0],
        "best_ioc": best[1],
        "ioc_at_26": dict(profile)[26],
        "ioc_at_1": dict(profile)[1],
        "multiples_of_26_are_top": all(
            p % M == 0 for p, _ in sorted(profile, key=lambda kv: -kv[1])[:2]
        ),
    }


# --------------------------------------------------------------------------- #
#  Експеримент 3 — перебір зсуву
# --------------------------------------------------------------------------- #

def exp_bruteforce(plaintext: str) -> dict:
    print("[3] Перебір 26 значень зсуву")
    true_shift = 11
    machine = EnigmaMachine(CODINGAME_ROTORS, true_shift)
    ciphertext = machine.encode(plaintext[:200])
    scorer = default_scorer()
    scores = [
        scorer.score(EnigmaMachine(CODINGAME_ROTORS, n).decode(ciphertext))
        for n in range(M)
    ]
    result = brute_force_shift(ciphertext, CODINGAME_ROTORS)

    colors = [S2 if n == true_shift else S1 for n in range(M)]
    fig, ax = plt.subplots(figsize=(9.5, 4.0))
    ax.bar(range(M), scores, color=colors, width=0.68, zorder=3)
    ax.set_xticks(range(M))
    ax.set_xlabel("припущений зсув N")
    ax.set_ylabel("логправдоподібність за квадриграмами")
    ax.set_title("Рис. 3. За відомих роторів правильний ключ видно з першого погляду")
    ax.annotate("N = %d" % true_shift, xy=(true_shift, scores[true_shift]),
                xytext=(true_shift + 1.2, scores[true_shift] + 0.18 * abs(scores[true_shift])),
                fontsize=9.5, color=INK,
                arrowprops=dict(arrowstyle="-", color=S2, linewidth=1.4))
    handles = [plt.Rectangle((0, 0), 1, 1, color=S1),
               plt.Rectangle((0, 0), 1, 1, color=S2)]
    ax.legend(handles, ["хибні кандидати", "правильний зсув"], loc="lower right")
    _finish(ax, "відрив від найкращого хибного кандидата: %s одиниць оцінки; час атаки %s мс"
            % (_n(result.notes["margin_over_runner_up"], 0), _n(result.elapsed_s * 1000, 1)))
    path = save(fig, "fig3_bruteforce.png")

    return {
        "figure": path,
        "true_shift": true_shift,
        "recovered_shift": result.notes["recovered_shift"],
        "margin": result.notes["margin_over_runner_up"],
        "elapsed_ms": result.elapsed_s * 1000,
        "correct": result.notes["recovered_shift"] == true_shift,
    }


# --------------------------------------------------------------------------- #
#  Експеримент 4 — успішність атак залежно від довжини
# --------------------------------------------------------------------------- #

def exp_success_vs_length(plaintext: str, quick: bool) -> dict:
    print("[4] Успішність атак залежно від довжини повідомлення")
    lengths = [10, 20, 30, 40, 60, 80, 120, 160, 240] if not quick else [20, 60, 160]
    trials = 12 if not quick else 4
    restarts = 10 if not quick else 4

    rng = random.Random(20240501)
    co_rate, bf_rate, co_time = [], [], []

    for length in lengths:
        co_ok = bf_ok = 0
        times = []
        for _ in range(trials):
            pt = sample_of(plaintext, length, rng)
            shift = rng.randrange(M)
            machine = EnigmaMachine(CODINGAME_ROTORS, shift)
            ct = machine.encode(pt)

            bf = brute_force_shift(ct, CODINGAME_ROTORS)
            bf_ok += bf.plaintext == pt

            co = ciphertext_only_attack(
                ct, restarts=restarts, patience=1200,
                rng=rng.randrange(10 ** 6), expected_plaintext=pt,
            )
            co_ok += co.notes["accuracy"] >= 0.95
            times.append(co.elapsed_s)

        co_rate.append(100.0 * co_ok / trials)
        bf_rate.append(100.0 * bf_ok / trials)
        co_time.append(statistics.mean(times))
        print("    L=%3d  перебір %5.1f%%   тільки шифротекст %5.1f%%  (%.2f с)"
              % (length, bf_rate[-1], co_rate[-1], co_time[-1]))

    fig, ax = plt.subplots(figsize=(9.0, 4.2))
    ax.plot(lengths, bf_rate, color=S1, marker="o", markersize=7,
            markerfacecolor=SURFACE, markeredgewidth=2,
            label="перебір зсуву (ротори відомі)", zorder=4)
    ax.plot(lengths, co_rate, color=S2, marker="s", markersize=7,
            markerfacecolor=SURFACE, markeredgewidth=2,
            label="тільки шифротекст (ротори невідомі)", zorder=3)
    ax.axvspan(1, 49, color=S3, alpha=0.10, zorder=1)
    ax.text(25, 6, "діапазон CodinGame\n(L < 50)", ha="center", fontsize=8, color=INK_2)

    # Зсуваємо підписи по вертикалі, щоб вони не наклалися, коли обидві
    # криві сходяться в одну точку.
    collided = abs(bf_rate[-1] - co_rate[-1]) < 5
    for ys, col, dy in ((bf_rate, S1, 9 if collided else 0),
                        (co_rate, S2, -9 if collided else 0)):
        ax.annotate("%.0f%%" % ys[-1], xy=(lengths[-1], ys[-1]), xytext=(8, dy),
                    textcoords="offset points", va="center", fontsize=9, color=col)

    ax.set_xlim(0, lengths[-1] * 1.10)
    ax.set_xlabel("довжина повідомлення, символів")
    ax.set_ylabel("частка повних зламів")
    ax.yaxis.set_major_formatter(PercentFormatter())
    ax.set_ylim(-4, 108)
    ax.set_title("Рис. 4. Обидві атаки надійно ламають шифр; питання лише в обсязі даних")
    ax.legend(loc="lower right")
    _finish(ax, "по %d випробувань на точку, %d перезапусків сходження за схилом" % (trials, restarts))
    path = save(fig, "fig4_success_vs_length.png")

    return {
        "figure": path,
        "lengths": lengths,
        "trials_per_point": trials,
        "bruteforce_success_percent": bf_rate,
        "ciphertext_only_success_percent": co_rate,
        "ciphertext_only_mean_time_s": co_time,
    }


# --------------------------------------------------------------------------- #
#  Експеримент 5 — відомий відкритий текст
# --------------------------------------------------------------------------- #

def exp_crib(plaintext: str, quick: bool) -> dict:
    print("[5] Покриття ключа за довжиною відомого фрагмента")
    lengths = list(range(5, 131, 5))
    trials = 200 if not quick else 40
    rng = random.Random(777)

    empirical, theoretical = [], []
    for length in lengths:
        total = 0
        for _ in range(trials):
            pt = sample_of(plaintext, length, rng)
            machine = EnigmaMachine(CODINGAME_ROTORS, rng.randrange(M))
            res = known_plaintext_attack(pt, machine.encode(pt))
            total += res.notes["key_coverage"]
        empirical.append(total / trials)
        theoretical.append(expected_crib_coverage(length))

    full_at = next((l for l, e in zip(lengths, empirical) if e >= 25.5), None)

    fig, ax = plt.subplots(figsize=(9.0, 4.2))
    ax.plot(lengths, theoretical, color=S1, linewidth=2.0,
            label="теорія:  26·(1 − (25/26)^L)", zorder=3)
    ax.plot(lengths, empirical, color=S2, linestyle="none", marker="o",
            markersize=6.5, markerfacecolor=SURFACE, markeredgewidth=1.8,
            label="експеримент (%d прогонів на точку)" % trials, zorder=4)
    ax.axhline(M, color=INK_2, linewidth=1.2, linestyle=(0, (4, 3)), zorder=2)
    ax.text(130, M, " повний ключ (26)", va="center", fontsize=8, color=INK_2)

    ax.set_xlabel("довжина відомого фрагмента, символів")
    ax.set_ylabel("відновлено елементів ключа")
    ax.set_ylim(0, 28.5)
    ax.set_title("Рис. 5. Відомий відкритий текст: ключ збирається як купони")
    ax.legend(loc="lower right")
    _finish(ax, "середнє відхилення експерименту від теорії: %s елемента"
            % _n(sum(abs(a - b) for a, b in zip(empirical, theoretical)) / len(lengths), 3))
    path = save(fig, "fig5_crib_coverage.png")

    return {
        "figure": path,
        "lengths": lengths,
        "empirical_coverage": empirical,
        "theoretical_coverage": theoretical,
        "trials_per_point": trials,
        "length_for_full_key": full_at,
        "mean_abs_error": sum(abs(a - b) for a, b in zip(empirical, theoretical)) / len(lengths),
    }


# --------------------------------------------------------------------------- #
#  Експеримент 6 — простір ключів
# --------------------------------------------------------------------------- #

def exp_keyspace() -> dict:
    print("[6] Простір ключів")
    ks = keyspace_analysis()
    collision = find_key_collision(rng=2024)

    labels = [
        "Номінальний ключ\n3 ротори + зсув:  (26!)³·26",
        "Фактичний ключ\nодна підстановка:  26!",
        "За Керкгоффсом\nротори опубліковані:  26",
    ]
    values = [ks["nominal_bits"], ks["effective_bits"], ks["kerckhoffs_bits"]]

    fig, ax = plt.subplots(figsize=(9.0, 3.6))
    bars = ax.barh(labels[::-1], values[::-1], color=S1, height=0.52, zorder=3)
    for bar, v in zip(bars, values[::-1]):
        ax.text(v + 4, bar.get_y() + bar.get_height() / 2,
                "2^" + _n(v, 1), va="center", fontsize=10, color=INK, fontweight="semibold")
    ax.set_xlabel("ентропія ключа, біт")
    ax.set_xlim(0, ks["nominal_bits"] * 1.18)
    ax.set_title("Рис. 6. Заявлена складність ключа майже вся є фіктивною")
    _finish(ax, "надлишок: 2^%s біт ключів, що дають тотожні шифри" % _n(ks["reduction_bits"], 1))
    path = save(fig, "fig6_keyspace.png")

    return {
        "figure": path,
        **{k: float(v) for k, v in ks.items()},
        "collision_found": collision is not None,
        "collision_example": {
            "key_a": collision["key_a"], "key_b": collision["key_b"]
        } if collision else None,
    }


# --------------------------------------------------------------------------- #
#  Експеримент 7 — лавинний ефект
# --------------------------------------------------------------------------- #

def exp_avalanche() -> dict:
    print("[7] Лавинний ефект")
    machine = EnigmaMachine(CODINGAME_ROTORS, 7)
    lengths = [25, 50, 100, 200, 400]
    ratios = []
    for length in lengths:
        av = avalanche_test(machine, length=length, trials=120, rng=11)
        ratios.append(av["avalanche_ratio"] * 100)

    fig, ax = plt.subplots(figsize=(8.6, 4.0))
    ax.bar([str(l) for l in lengths], ratios, color=S1, width=0.55, zorder=3)
    ax.axhline(50, color=S2, linewidth=2.0, zorder=4)
    ax.text(len(lengths) - 0.5, 52, "ідеал стійкого шифру — 50 %",
            ha="right", fontsize=9, color=S2)
    for i, r in enumerate(ratios):
        ax.text(i, r + 1.5, "%s %%" % _n(r, 2), ha="center", fontsize=9, color=INK)

    ax.set_xlabel("довжина повідомлення, символів")
    ax.set_ylabel("змінено символів шифротексту")
    ax.set_ylim(0, 62)
    ax.set_title("Рис. 7. Дифузія відсутня: один символ впливає рівно на один")
    _finish(ax, "зміна одного символу відкритого тексту, 120 випробувань на стовпчик")
    path = save(fig, "fig7_avalanche.png")

    return {
        "figure": path,
        "lengths": lengths,
        "avalanche_percent": ratios,
        "changed_chars_always_one": all(abs(r / 100 * l - 1.0) < 1e-9
                                        for r, l in zip(ratios, lengths)),
    }


# --------------------------------------------------------------------------- #
#  Демонстрація атак на одному повідомленні
# --------------------------------------------------------------------------- #

def exp_attack_table(plaintext: str) -> dict:
    print("[8] Зведена таблиця атак")
    message = plaintext[:180]
    machine = EnigmaMachine(CODINGAME_ROTORS, 11)
    ciphertext = machine.encode(message)
    truth = machine.effective_key

    rows = []

    r = brute_force_shift(ciphertext, CODINGAME_ROTORS)
    rows.append(("Перебір зсуву", "відомі ротори", "%d варіантів" % r.evaluations,
                 r.elapsed_s, r.key == truth, r.plaintext == message))

    r = known_plaintext_attack(message, ciphertext)
    rows.append(("Відомий відкритий текст", "пара (текст, шифротекст)",
                 "%d символів" % r.evaluations, r.elapsed_s,
                 r.key == truth, r.plaintext == message))

    r = chosen_plaintext_attack(machine.encode, ciphertext)
    rows.append(("Підібраний відкритий текст", "доступ до оракула",
                 "1 запит на 26 символів", r.elapsed_s,
                 r.key == truth, r.plaintext == message))

    r = ciphertext_only_attack(ciphertext, restarts=24, rng=4242,
                               expected_plaintext=message)
    rows.append(("Тільки шифротекст", "нічого, крім шифротексту",
                 "%d оцінок" % r.evaluations, r.elapsed_s,
                 r.key == truth, r.plaintext == message))

    for row in rows:
        print("    %-28s ключ=%-5s текст=%-5s %.3f с"
              % (row[0], row[4], row[5], row[3]))

    return {
        "message_length": len(message),
        "true_shift": machine.shift,
        "rows": [
            {"attack": a, "model": b, "cost": c, "elapsed_s": d,
             "key_recovered": e, "plaintext_recovered": f}
            for a, b, c, d, e, f in rows
        ],
    }


# --------------------------------------------------------------------------- #

def write_summary(results: dict) -> None:
    RES.mkdir(parents=True, exist_ok=True)
    (RES / "experiments.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    f = results["frequency"]
    k = results["keyspace"]
    lines = [
        "# Зведені результати експериментів",
        "",
        "Згенеровано автоматично: `python experiments/run_experiments.py`",
        "",
        "## Статистика тексту",
        "",
        "| Величина | Відкритий текст | Шифротекст | Орієнтир |",
        "|---|---:|---:|---|",
        "| Індекс відповідності | %.4f | %.4f | англ. 0.0667 / випадк. 0.0385 |"
        % (f["plaintext_ioc"], f["ciphertext_ioc"]),
        "| Хі-квадрат до англійської | %.0f | %.0f | менше — ближче до мови |"
        % (f["plaintext_chi2"], f["ciphertext_chi2"]),
        "| Ентропія, біт/символ | %.3f | %.3f | максимум 4.700 |"
        % (f["plaintext_entropy"], f["ciphertext_entropy"]),
        "",
        "## Простір ключів",
        "",
        "| Модель | Ентропія ключа |",
        "|---|---:|",
        "| Номінально, 3 ротори + зсув | 2^%.1f |" % k["nominal_bits"],
        "| Фактично, одна підстановка | 2^%.1f |" % k["effective_bits"],
        "| За Керкгоффсом (ротори відомі) | 2^%.1f |" % k["kerckhoffs_bits"],
        "",
        "## Атаки",
        "",
        "| Атака | Модель зловмисника | Вартість | Час | Ключ | Текст |",
        "|---|---|---|---:|:-:|:-:|",
    ]
    for row in results["attacks"]["rows"]:
        lines.append("| %s | %s | %s | %.3f с | %s | %s |" % (
            row["attack"], row["model"], row["cost"], row["elapsed_s"],
            "так" if row["key_recovered"] else "частково",
            "так" if row["plaintext_recovered"] else "частково",
        ))
    lines.append("")
    (RES / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n    зведення -> docs/results/summary.md")
    print("    сирі дані -> docs/results/experiments.json")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true", help="скорочений прогін")
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    t0 = time.perf_counter()
    plaintext = load_plaintext()
    print("Корпус для експериментів: %d літер\n" % len(plaintext))

    results = {
        "meta": {
            "plaintext_letters": len(plaintext),
            "language_model": default_scorer().source,
            "quick": args.quick,
        },
        "frequency": exp_frequency(plaintext),
        "period": exp_period(plaintext),
        "bruteforce": exp_bruteforce(plaintext),
        "success_vs_length": exp_success_vs_length(plaintext, args.quick),
        "crib": exp_crib(plaintext, args.quick),
        "keyspace": exp_keyspace(),
        "avalanche": exp_avalanche(),
        "attacks": exp_attack_table(plaintext),
    }
    results["meta"]["total_seconds"] = time.perf_counter() - t0
    write_summary(results)
    print("\nГотово за %.1f с" % results["meta"]["total_seconds"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
