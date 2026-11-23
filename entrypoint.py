"""Windows release (PyInstaller) entrypoint."""
import sys

from darkweb_monitor.cli import main

if __name__ == "__main__":
    sys.exit(main())
