"""Windows release entrypoint."""
import os
import sys

# Let PyInstaller's frozen import machinery locate the bundled packages.
# Do NOT prepend ROOT to sys.path here (it shadows the bundled _internal path
# and breaks `from darkweb_monitor...` imports under --onedir).

from darkweb_monitor.cli import main

if __name__ == "__main__":
    main()
