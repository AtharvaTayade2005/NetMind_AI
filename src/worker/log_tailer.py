"""Root forwarder for worker log_tailer module."""

from netmind.src.worker.log_tailer import *  # noqa: F401, F403
from netmind.src.worker.log_tailer import main

if __name__ == "__main__":
    main()
