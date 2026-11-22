"""Test setup. Every run builds a fresh PKI and database in a temporary folder, so the real keys in
certs/ and the real lab.db are never read or changed. Revocation state is restored after each test."""
import os, sys, tempfile, subprocess, threading
from http.server import ThreadingHTTPServer
import pytest
from werkzeug.serving import make_server

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
RUN = tempfile.mkdtemp(prefix="dhanshiri-run-")
os.environ["DHANSHIRI_CERTS"] = os.path.join(RUN, "certs")
os.environ["DHANSHIRI_STATE"] = os.path.join(RUN, "state")
os.makedirs(os.environ["DHANSHIRI_STATE"], exist_ok=True)
sys.path.insert(0, _ROOT); sys.path.insert(0, _HERE)

subprocess.run([sys.executable, os.path.join(_ROOT, "make_certs.py")], cwd=_ROOT, env=os.environ,
               check=True, capture_output=True)

import app as dapp          # noqa: E402
import pki_http             # noqa: E402
from helpers import free_port, CERTS  # noqa: E402

dapp.init_db()

@pytest.fixture(autouse=True)
def clear_login_lockouts():
    """Failed-login counters live in process memory. Clear them so one test's lockout cannot break another."""
    dapp.FAILS.clear()
    yield
    dapp.FAILS.clear()

# CRL server for the report-verification tests (same code the lab runs on 127.0.0.1:2560)
_crl_port = free_port()
threading.Thread(target=ThreadingHTTPServer(("127.0.0.1", _crl_port), pki_http.H).serve_forever, daemon=True).start()
os.environ["DHANSHIRI_CRL_URL"] = f"http://127.0.0.1:{_crl_port}/crl/issuing.crl"

def _start(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]

@pytest.fixture(scope="session")
def portal_port():
    """The customer portal: server certificate only, no client certificate."""
    return _start(make_server("127.0.0.1", free_port(), dapp.app, threaded=True,
                              ssl_context=dapp.make_ssl_context(False)))

@pytest.fixture(scope="session")
def mtls_port():
    """The branch upload service: asks for a client certificate."""
    return _start(make_server("127.0.0.1", free_port(), dapp.app, threaded=True,
                              ssl_context=dapp.make_ssl_context(True)))

@pytest.fixture(autouse=True)
def restore_revocations():
    f = os.path.join(CERTS, "revoked.json")
    before = open(f, "rb").read()
    yield
    open(f, "wb").write(before)

@pytest.fixture(scope="session")
def genuine_pdf():
    """A real signed statement, downloaded through the customer portal as rahim."""
    from helpers import login, WORK
    c = dapp.app.test_client()
    login(c, "rahim", "Rahim@123")
    no = c.get("/api/accounts").get_json()["accounts"][0]["no"]
    url = c.get(f"/api/accounts/{no}/link").get_json()["url"]
    r = c.get(url)
    assert r.status_code == 200 and r.data.startswith(b"%PDF"), r.status_code
    path = os.path.join(WORK, "statement.pdf")
    open(path, "wb").write(r.data)
    return path
