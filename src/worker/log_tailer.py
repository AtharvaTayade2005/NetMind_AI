import sys
from pathlib import Path

# Ensure repository root is in sys.path when executed directly as a script
_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from netmind.src.worker.log_tailer import *  # noqa: F401, F403
from netmind.src.worker.log_tailer import main

if __name__ == "__main__":
    main()
