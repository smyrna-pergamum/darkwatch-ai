import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from sqlalchemy import create_engine, inspect

from config.settings import settings
from darkweb_monitor.crawler.tor_client import TorClient, TorUnavailable, ensure_tor
from darkweb_monitor.storage import db


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/big":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<p>" + b"A" * 50000 + b"</p>")
        elif self.path == "/img":
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.end_headers()
            self.wfile.write(b"\x89PNG....")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_size_cap_and_content_type(server, monkeypatch):
    monkeypatch.setattr(settings, "MAX_RESPONSE_BYTES", 1000)
    c = TorClient()
    r = c.get(server + "/big")
    assert r.ok and r.truncated and len(r.text) == 1000
    r = c.get(server + "/img")
    assert r.error.startswith("skipped content-type")
    assert c.get(server + "/nope").error == "HTTP 404"


def test_ensure_tor_modes(monkeypatch):
    monkeypatch.setattr(settings, "TOR_REQUIRED", True)
    monkeypatch.setattr(settings, "TOR_ENABLED", False)
    with pytest.raises(TorUnavailable):
        ensure_tor()
    monkeypatch.setattr(settings, "TOR_REQUIRED", False)
    ensure_tor()  # lab mode: warning only


def test_v1_database_is_upgraded_in_place(tmp_path):
    url = f"sqlite:///{(tmp_path / 'v1.db').as_posix()}"
    eng = create_engine(url)
    with eng.begin() as c:
        c.exec_driver_sql("CREATE TABLE targets (id INTEGER PRIMARY KEY, url VARCHAR(512) UNIQUE NOT NULL, label VARCHAR(256), keywords TEXT, active BOOLEAN, created_at DATETIME, last_crawled DATETIME)")
        c.exec_driver_sql("CREATE TABLE alerts (id INTEGER PRIMARY KEY, page_id INTEGER, severity VARCHAR(32), title VARCHAR(512) NOT NULL, description TEXT, notified BOOLEAN, created_at DATETIME)")
        c.exec_driver_sql("INSERT INTO targets (url, label) VALUES ('http://old.onion/', 'legacy')")
        c.exec_driver_sql("INSERT INTO alerts (severity, title) VALUES ('high', 'old alert')")
    db.configure(url)
    db.init_db()
    cols = {c["name"] for c in inspect(db.engine()).get_columns("targets")}
    assert {"crawl_mode", "schedule_interval_min", "approval"} <= cols
    from darkweb_monitor.storage.models import Alert, Target
    with db.session_scope() as s:
        t = s.query(Target).one()
        assert t.label == "legacy" and t.approval == "approved" and t.crawl_mode == "standard"
        assert s.query(Alert).one().status == "new"
