"""Root forwarder for train_all script."""

import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from netmind.src.ml.train_all import run_training_pipeline

if __name__ == "__main__":
    run_training_pipeline()
