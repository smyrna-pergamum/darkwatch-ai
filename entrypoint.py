"""Release (PyInstaller) entrypoint.

Started without arguments - e.g. double-clicked in Explorer / Finder - it runs the
dashboard server on 127.0.0.1, opens the browser and keeps the console window open
if something goes wrong, so the error can be read. With arguments it is the normal CLI.
"""
import os
import socket
import sys
import threading
import traceback
import webbrowser


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def _pause() -> None:
    try:
        input("\nPress Enter to close this window...")
    except (EOFError, KeyboardInterrupt):
        pass


def _interactive() -> int:
    from config.settings import settings
    from darkweb_monitor import __version__
    from darkweb_monitor.cli import main

    host, port = "127.0.0.1", int(settings.API_PORT)
    url = f"http://{host}:{port}"
    print(f"DarkWeb Monitor {__version__}")
    if _port_open(host, port):
        print(f"Already running (or port {port} is in use) - opening {url}")
        webbrowser.open(url)
        return 0
    print(f"Starting dashboard at {url}  -  keep this window open, close it or press Ctrl+C to stop.\n")
    if not os.environ.get("DWM_NO_BROWSER"):
        def _open() -> None:
            for _ in range(60):  # wait up to ~30 s for the server
                if _port_open(host, port):
                    webbrowser.open(url)
                    return
                threading.Event().wait(0.5)
        threading.Thread(target=_open, daemon=True).start()
    return main(["serve", "--host", host, "--port", str(port)]) or 0


def run() -> int:
    for stream in (sys.stdout, sys.stderr):  # Windows consoles default to a legacy code page
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass
    if len(sys.argv) > 1:
        from darkweb_monitor.cli import main
        return main()
    try:
        code = _interactive()
    except KeyboardInterrupt:
        return 0
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    except Exception:
        traceback.print_exc()
        code = 1
    if code:
        print(f"\nDarkWeb Monitor stopped with an error (exit code {code}).")
        _pause()
    return code


if __name__ == "__main__":
    sys.exit(run())
