"""Build a self-contained release with PyInstaller.

    python packaging/build.py            -> dist/darkweb-monitor-<version>-<os>-<arch>.zip

Works on Windows, Linux and macOS (run it on each platform; PyInstaller does
not cross-compile). Used by .github/workflows/release.yml.
"""
from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = re.search(r'__version__ = "([^"]+)"', (ROOT / "darkweb_monitor" / "__init__.py").read_text()).group(1)
SEP = ";" if os.name == "nt" else ":"
HIDDEN = [
    "uvicorn.logging", "uvicorn.loops", "uvicorn.loops.auto", "uvicorn.protocols", "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto", "uvicorn.protocols.http.h11_impl", "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto", "uvicorn.lifespan", "uvicorn.lifespan.on", "sqlalchemy.dialects.sqlite",
    "apscheduler.triggers.cron", "apscheduler.triggers.interval", "apscheduler.executors.pool",
    "apscheduler.jobstores.memory", "socks", "h11",
]
EXCLUDE = ["tkinter", "matplotlib", "numpy", "pandas", "scipy", "PyQt5", "PyQt6", "PySide2", "PySide6",
           "IPython", "jupyter", "notebook", "pytest"]


def main() -> int:
    osname = {"Windows": "windows", "Darwin": "macos", "Linux": "linux"}[platform.system()]
    arch = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine().lower(), platform.machine())
    name = "DarkWebMonitor"
    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--console", "--name", name,
           "--distpath", str(ROOT / "build" / "dist"), "--workpath", str(ROOT / "build" / "work"),
           "--specpath", str(ROOT / "build"),
           "--add-data", f"{ROOT / 'dashboard'}{SEP}dashboard",
           "--collect-submodules", "darkweb_monitor", "--collect-submodules", "config"]
    for h in HIDDEN:
        cmd += ["--hidden-import", h]
    for x in EXCLUDE:
        cmd += ["--exclude-module", x]
    cmd.append(str(ROOT / "entrypoint.py"))
    print(" ".join(cmd))
    subprocess.check_call(cmd, cwd=ROOT)
    app = ROOT / "build" / "dist" / name
    # portable layout: config + docs next to the executable, data/ created on first run
    shutil.copy(ROOT / ".env.example", app / ".env.example")
    env = (ROOT / ".env.example").read_text(encoding="utf-8")
    (app / ".env").write_text(env, encoding="utf-8")
    for f in ("README.md", "LICENSE", "CHANGELOG.md"):
        if (ROOT / f).exists():
            shutil.copy(ROOT / f, app / f)
    (ROOT / "docs").exists() and shutil.copytree(ROOT / "docs", app / "docs", dirs_exist_ok=True)
    out = ROOT / "dist" / f"darkweb-monitor-{VERSION}-{osname}-{arch}.zip"
    out.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in app.rglob("*"):
            if p.is_file():
                z.write(p, Path(f"darkweb-monitor-{VERSION}") / p.relative_to(app))
    print("built", out, f"{out.stat().st_size / 1e6:.1f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
