"""Defensive web-application tests for the synthetic Dhanshiri lab only.
These tests exercise the local Flask test client; no external targets are contacted."""
import contextlib, io, os, re, sqlite3
from urllib.parse import quote
from helpers import db_count
from config import DB
import app as dapp
from helpers import login


def client_and_csrf(username="rahim", password="Rahim@123"):
    c = dapp.app.test_client()
    csrf = c.get("/api/me").get_json()["csrf"]
    return c, csrf

def logged_in(username="rahim", password="Rahim@123"):
    c = dapp.app.test_client()
    return c, login(c, username, password)


def test_web_sqli_login_payload_does_not_bypass_auth():
    c, csrf = client_and_csrf()
    r = c.post("/api/login", json={"username": "' OR '1'='1' --", "password": "anything"}, headers={"X-CSRF": csrf})
    assert r.status_code in (401, 429)
    assert c.get("/api/me").get_json()["user"] is None


def test_web_sqli_account_parameter_is_treated_as_data():
    c = dapp.app.test_client(); csrf = login(c, "rahim", "Rahim@123")
    r = c.get("/api/accounts/0000%27%20OR%201%3D1--")
    assert r.status_code == 404
    assert "balance" not in r.get_json()


def test_web_csrf_missing_token_rejected():
    c = dapp.app.test_client(); login(c, "rahim", "Rahim@123")
    r = c.post("/api/accounts/open", json={})
    assert r.status_code == 400


def test_web_idor_other_customer_account_hidden():
    c = dapp.app.test_client(); login(c, "rahim", "Rahim@123")
    con = sqlite3.connect(DB)
    other = con.execute("SELECT no FROM accounts WHERE user_id=(SELECT id FROM users WHERE username='karim')").fetchone()[0]
    con.close()
    r = c.get(f"/api/accounts/{other}")
    assert r.status_code == 404


def test_web_role_escalation_customer_cannot_open_admin_api():
    c = dapp.app.test_client(); login(c, "rahim", "Rahim@123")
    assert c.get("/api/admin/certs").status_code == 403


def test_web_xss_payload_is_returned_as_plain_json_data():
    c, csrf = client_and_csrf()
    payload = "<script>alert('xss')</script>"
    r = c.post("/api/register", json={"name": payload, "username": "xss_probe", "password": "StrongPass123", "phone": "01700000999", "nid": ""}, headers={"X-CSRF": csrf})
    assert r.status_code == 200
    con = sqlite3.connect(DB); row = con.execute("SELECT name FROM users WHERE username='xss_probe'").fetchone(); con.close()
    assert row[0] == payload
    # The React UI renders text via JSX interpolation; it must not use raw HTML injection.
    source = open(dapp.BASE + "/frontend/src/App.jsx", encoding="utf-8").read()
    assert "dangerouslySetInnerHTML" not in source


def test_web_login_rate_limit_after_five_bad_passwords():
    c, csrf = client_and_csrf()
    statuses = [c.post("/api/login", json={"username":"rahim", "password":"wrong"}, headers={"X-CSRF":csrf}).status_code for _ in range(6)]
    assert statuses[-1] == 429


def test_web_security_headers_present():
    c = dapp.app.test_client(); r = c.get("/api/me")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "default-src 'self'" in r.headers.get("Content-Security-Policy", "")
    assert r.headers.get("Referrer-Policy") == "no-referrer"


def test_web_transfer_rejects_invalid_and_over_limit_amounts():
    c = dapp.app.test_client(); csrf = login(c, "rahim", "Rahim@123")
    own_no = c.get("/api/accounts").get_json()["accounts"][0]["no"]
    for amount in (-1, 0, 500001, "not-a-number"):
        r = c.post("/api/transfer", json={"from": own_no, "to": "0204-000456", "amount": amount, "ref": "test-ref-0001"}, headers={"X-CSRF":csrf})
        assert r.status_code == 400


def test_web_https_security_headers_include_hsts_when_secure_mode(monkeypatch):
    monkeypatch.setattr(dapp, "HTTPS", True)
    try:
        r = dapp.app.test_client().get("/api/me")
        assert "max-age=31536000" in r.headers.get("Strict-Transport-Security", "")
    finally:
        monkeypatch.setattr(dapp, "HTTPS", False)


# ---------- Stored and reflected XSS ----------

def _account_no(username):
    con = sqlite3.connect(DB); no = con.execute("SELECT a.no FROM accounts a JOIN users u ON u.id=a.user_id WHERE u.username=?", (username,)).fetchone()[0]; con.close(); return no

def test_web_stored_xss_note_is_returned_as_plain_json_text():
    payload = "<img src=x onerror=alert(1)>"
    c, csrf = logged_in()
    own = c.get("/api/accounts").get_json()["accounts"][0]["no"]
    r = c.post("/api/transfer", json={"from": own, "to": _account_no("karim"), "amount": "1", "note": payload, "ref": "xss-stored-0001"}, headers={"X-CSRF": csrf})
    assert r.status_code == 200
    body = c.get(f"/api/accounts/{own}")
    assert body.headers["Content-Type"].startswith("application/json")
    assert body.headers.get("X-Content-Type-Options") == "nosniff"
    assert any(payload in t["descr"] for t in body.get_json()["txns"])  # stored as data, returned as data

def test_web_reflected_xss_in_verify_url_is_not_echoed():
    """A script in the verification URL must never come back in the response, and the page must carry a CSP."""
    payload = "<script>alert(1)</script>"
    for path in ("/api/verify/" + quote(payload, safe=""), "/verify/" + quote(payload, safe="")):
        r = dapp.app.test_client().get(path)
        assert payload not in r.get_data(as_text=True), path
        assert "default-src 'self'" in r.headers.get("Content-Security-Policy", ""), path
        assert r.headers.get("X-Content-Type-Options") == "nosniff", path


# ---------- Session and cookie security ----------

def test_web_session_cookie_is_httponly_and_samesite():
    c = dapp.app.test_client(); csrf = c.get("/api/me").get_json()["csrf"]
    r = c.post("/api/login", json={"username": "rahim", "password": "Rahim@123"}, headers={"X-CSRF": csrf})
    cookies = r.headers.getlist("Set-Cookie")
    assert cookies, "login should set a session cookie"
    assert any("HttpOnly" in k and "SameSite=Lax" in k for k in cookies)

# ---------- Unauthorized and duplicate transactions ----------

def test_web_unauthorized_transaction_from_other_account_refused():
    c, csrf = logged_in()
    victim = _account_no("karim")
    con = sqlite3.connect(DB); before = con.execute("SELECT balance FROM accounts WHERE no=?", (victim,)).fetchone()[0]; con.close()
    r = c.post("/api/transfer", json={"from": victim, "to": _account_no("rahim"), "amount": "100", "ref": "unauth-0001"}, headers={"X-CSRF": csrf})
    assert r.status_code == 400
    con = sqlite3.connect(DB); after = con.execute("SELECT balance FROM accounts WHERE no=?", (victim,)).fetchone()[0]; con.close()
    assert after == before

def test_web_duplicate_transaction_is_applied_once():
    c, csrf = logged_in()
    own = c.get("/api/accounts").get_json()["accounts"][0]["no"]; to = _account_no("karim")
    body = {"from": own, "to": to, "amount": "25", "note": "dup-test", "ref": "dup-ref-00001"}
    first = c.post("/api/transfer", json=body, headers={"X-CSRF": csrf})
    second = c.post("/api/transfer", json=body, headers={"X-CSRF": csrf})
    assert first.status_code == 200 and second.status_code == 409
    con = sqlite3.connect(DB); n = con.execute("SELECT COUNT(*) FROM txns t JOIN accounts a ON a.id=t.account_id WHERE a.no=? AND t.descr LIKE '%dup-test%'", (own,)).fetchone()[0]; con.close()
    assert n == 1

# ---------- Malicious file upload (branch channel) ----------

def _branch_client():
    from config import CERTS
    c = dapp.app.test_client()
    c.environ_base.update({"SSL_CLIENT_CERT": open(os.path.join(CERTS, "client-branch-rangpur.crt")).read(), "SERVER_PORT": "8444"})
    return c

def _start(c, name, data):
    import hashlib
    sha = hashlib.sha256(data).hexdigest(); key = sha[:32]
    return c.post("/upload-api/start", json={"key": key, "name": name, "total": 1, "sha256": sha}), key

def test_web_upload_path_traversal_and_wrong_extension_refused():
    c = _branch_client()
    assert _start(c, "../../evil.pdf", b"%PDF-x")[0].status_code == 400
    assert _start(c, "shell.php", b"<?php ?>")[0].status_code == 400
    assert _start(c, "page.html", b"<html>")[0].status_code == 400

def test_web_upload_with_html_content_under_pdf_name_refused_and_not_stored():
    c = _branch_client(); data = b"<html><script>alert(1)</script></html>"
    before = db_count("uploads")
    r, key = _start(c, "scan.pdf", data)
    assert r.status_code == 200
    c.put(f"/upload-api/chunk/{key}/0", data=data)
    r = c.post(f"/upload-api/finish/{key}")
    assert r.status_code == 415
    assert db_count("uploads") == before


# ---------- Review fixes ----------

def test_web_one_mobile_number_cannot_open_two_customers():
    c = dapp.app.test_client(); csrf = c.get("/api/me").get_json()["csrf"]
    body = {"name": "Second Person", "username": "second_user", "password": "Second@123", "phone": "01700000001"}
    r = c.post("/api/register", json=body, headers={"X-CSRF": csrf})
    assert r.status_code == 409 and "mobile number" in r.get_json()["error"]

def test_web_one_national_id_cannot_open_two_customers():
    c = dapp.app.test_client(); csrf = c.get("/api/me").get_json()["csrf"]
    base = {"name": "First Holder", "password": "First@1234", "phone": "01711111111", "nid": "1234567890123"}
    assert c.post("/api/register", json={**base, "username": "nid_first"}, headers={"X-CSRF": csrf}).status_code == 200
    r = c.post("/api/register", json={**base, "username": "nid_second", "phone": "01722222222"}, headers={"X-CSRF": csrf})
    assert r.status_code == 409 and "National ID" in r.get_json()["error"]

def test_web_login_without_prior_session_gets_a_real_csrf_token():
    c = dapp.app.test_client()
    csrf = c.get("/api/me").get_json()["csrf"]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        c.post("/api/login", json={"username": "karim", "password": "Karim@123"}, headers={"X-CSRF": csrf})
    code = re.search(r"OTP for \S+: (\d{6})", buf.getvalue()).group(1)
    r = c.post("/api/login/otp", json={"code": code}, headers={"X-CSRF": csrf})
    assert r.status_code == 200 and r.get_json()["csrf"]

def test_web_unknown_api_path_returns_json_404():
    r = dapp.app.test_client().get("/api/does-not-exist")
    assert r.status_code == 404 and r.headers["Content-Type"].startswith("application/json")

def test_web_session_key_file_is_owner_only():
    import stat
    p = os.path.join(dapp.STATE, ".secret")
    assert os.path.exists(p)
    if os.name != "nt":
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600

def test_web_page_is_never_served_stale():
    """A browser must re-check the page, otherwise an old page (with old buttons) can keep showing after an update."""
    r = dapp.app.test_client().get("/")
    assert r.status_code == 200 and "no-cache" in r.headers.get("Cache-Control", "")
