#!/usr/bin/env python3
"""SheXzTool - Defensive Cybersecurity Toolkit.

Attributed to developer brand: SheRaXzy Sentinel.
Run:
    python main.py
Or with CLI options:
    python main.py --help
"""

import sys

# Ensure UTF-8 output encoding for Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from shexztool.cli import main

if __name__ == "__main__":
    sys.exit(main())
