"""Root test forwarder for NetMind ML test suite."""

import sys
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from netmind.tests.test_ml import *  # noqa: F401, F403
import pytest

if __name__ == "__main__":
    pytest.main(["-v", str(Path(__file__))])
