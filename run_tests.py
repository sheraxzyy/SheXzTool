#!/usr/bin/env python3
"""Automated Test Runner for SheXzTool.

Runs the complete defensive cybersecurity test suite.
"""

import sys
import pytest

if __name__ == "__main__":
    sys.exit(pytest.main(["-v", "tests"]))
