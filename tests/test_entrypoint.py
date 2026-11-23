"""Release entrypoint: no arguments (double-click) must start the dashboard, not print help."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def entry(monkeypatch):
    spec = importlib.util.spec_from_file_location("dw_entrypoint", ROOT / "entrypoint.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setenv("DWM_NO_BROWSER", "1")
    monkeypatch.setattr(mod, "_port_open", lambda h, p: False)
    return mod


def test_no_arguments_starts_dashboard_server(entry, monkeypatch):
    calls = []
    import darkweb_monitor.cli as cli
    monkeypatch.setattr(cli, "main", lambda argv=None: calls.append(argv) or 0)
    monkeypatch.setattr("sys.argv", ["DarkWebMonitor.exe"])
    assert entry.run() == 0
    assert calls and calls[0][0] == "serve" and "--host" in calls[0] and "127.0.0.1" in calls[0]


def test_arguments_are_passed_to_the_cli(entry, monkeypatch):
    calls = []
    import darkweb_monitor.cli as cli
    monkeypatch.setattr(cli, "main", lambda argv=None: calls.append(argv) or 0)
    monkeypatch.setattr("sys.argv", ["DarkWebMonitor.exe", "status"])
    assert entry.run() == 0 and calls == [None]


def test_error_keeps_window_open(entry, monkeypatch):
    import darkweb_monitor.cli as cli
    paused = []

    def boom(argv=None):
        raise RuntimeError("port blocked")
    monkeypatch.setattr(cli, "main", boom)
    monkeypatch.setattr(entry, "_pause", lambda: paused.append(True))
    monkeypatch.setattr("sys.argv", ["DarkWebMonitor.exe"])
    assert entry.run() == 1 and paused
