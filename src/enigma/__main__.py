"""Дозволяє запуск пакета як ``python -m enigma ...``."""

from .cli import main

raise SystemExit(main())
