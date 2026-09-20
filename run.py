#!/usr/bin/env python3
"""
Точка входу без встановлення пакета.

    python run.py selftest
    python run.py encode --shift 4 --message AAA
    python run.py attack --message "ATTACKATDAWN..." --shift 11
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from enigma.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
