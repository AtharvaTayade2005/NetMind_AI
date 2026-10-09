"""Root test forwarder for NetMind AI. Runs test suite from netmind.tests.test_ingestion."""

import sys
from pathlib import Path

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from netmind.tests.test_ingestion import *  # noqa: F401, F403
from netmind.tests.test_ingestion import run_all_tests

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
