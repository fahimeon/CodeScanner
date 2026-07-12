"""Test configuration: make scripts/ importable and expose the fixtures dir."""

import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
STUDY_ROOT = TESTS_DIR.parent
SCRIPTS_DIR = STUDY_ROOT / "scripts"
FIXTURES_DIR = TESTS_DIR / "fixtures"

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
