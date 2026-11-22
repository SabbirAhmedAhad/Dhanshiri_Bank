"""Test suite for the Dhanshiri lab PKI. Categories follow the course guide, Section 7.
Each test name starts with its category: chain_, issuance_, expiry_, revocation_, downgrade_,
signing_, ai_, upload_, auth_ . docs/test-results.md is generated from a run of this file."""
import json, os, re, socket, ssl, sqlite3, subprocess
import pytest, urllib3
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID as EKU
from config import CERTS, DB, BASE
from helpers import (make_leaf, as_files, https_session, make_rogue_ca, db_count, last_refusal, login,
                     upload, run, PORTAL_HOST, UPLOAD_HOST, WORK)
import app as dapp
import policy

RE = (urllib3.exceptions.HTTPError, OSError)  # any refused connection
CLIENT = EKU.CLIENT_AUTH
REVOKED = os.path.join(CERTS, "revoked.json")

def _rangpur():
    return os.path.join(CERTS, "client-branch-rangpur.crt"), os.path.join(CERTS, "client-branch-rangpur.key")

def _try_tls(port, host, version, ciphers="DEFAULT:@SECLEVEL=0", ca=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True; ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(ca or os.path.join(CERTS, "root.crt"))
    ctx.minimum_version = version; ctx.maximum_version = version
    ctx.set_ciphers(ciphers)
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        with ctx.wrap_socket(s, server_hostname=host) as ss:
            return ss.version(), ss.cipher()
    finally:
        s.close()

def _revoke_as_two_officers(serial_name):
    """Real four-eyes flow: it.officer requests, head.of.it approves."""
    it = dapp.app.test_client(); c1 = login(it, "it.officer", "Admin@123")
    assert it.post("/api/admin/requests", json={"action": "revoke_cert", "target": serial_name},
                   headers={"X-CSRF": c1}).status_code == 200
    rid = it.get("/api/admin/requests").get_json()["requests"][0]["id"]
    hoi = dapp.app.test_client(); c2 = login(hoi, "head.of.it", "Admin@456")
    r = hoi.post(f"/api/admin/requests/{rid}/approve", headers={"X-CSRF": c2})
    assert r.status_code == 200, r.get_json()
    return r.get_json()["message"]

# ---------- Chain and trust ----------

def test_chain_valid_server_chain_accepted(portal_port):
    r = https_session(PORTAL_HOST).get(f"https://127.0.0.1:{portal_port}/api/me", timeout=10)
    assert r.status_code == 200

def test_chain_untrusted_ca_rejected(portal_port):
    _, rogue_root = make_rogue_ca()
    with pytest.raises(RE):
        https_session(PORTAL_HOST, ca=rogue_root).get(f"https://127.0.0.1:{portal_port}/api/me", timeout=10)

def test_chain_hostname_mismatch_rejected(portal_port):
    with pytest.raises(RE):
        https_session("evil.dhanshiri.test").get(f"https://127.0.0.1:{portal_port}/api/me", timeout=10)

def test_chain_upload_untrusted_client_cert_refused(mtls_port):
    (rc, rk), _ = make_rogue_ca()
    rogue = make_leaf("client-rogue", CLIENT, ca=(rc, rk))
    before = db_count("uploads")
    with pytest.raises(RE):
        upload(https_session(UPLOAD_HOST, *as_files(*rogue, "rogue")), mtls_port)
    assert db_count("uploads") == before  # nothing stored

# ---------- Wrong issuance ----------

def test_issuance_unlogged_cert_raises_alert():
    make_leaf("client-rogue-unlogged", CLIENT, save_as="client-rogue-unlogged")
    out = run(["check_issuance.py"])
    assert "ALERT: certificate not in issuance log: client-rogue-unlogged.crt" in out

def test_issuance_out_of_policy_cert_is_flagged():
    cert, _ = make_leaf("client-overlong", CLIENT, start=0, end=3000, san=["evil.example.com"])
    breaches = policy.logissue("client-overlong", cert)
    assert any("validity" in b for b in breaches) and any("outside" in b for b in breaches)
    last = json.loads(open(policy.LOG).read().splitlines()[-1])
    assert last["alert"] is True
    assert "out-of-policy at issuance: client-overlong" in run(["check_issuance.py"])

def test_issuance_wrong_type_server_cert_refused_as_branch_client(mtls_port):
    cert_pem = os.path.join(CERTS, "server.crt"); key_pem = os.path.join(CERTS, "server.key")
    before = db_count("uploads")
    with pytest.raises(RE):
        upload(https_session(UPLOAD_HOST, cert_pem, key_pem), mtls_port)
    assert db_count("uploads") == before

# ---------- Expiry and revocation ----------

def test_expiry_expired_client_cert_refused(mtls_port):
    cert, key = make_leaf("client-expired", CLIENT, start=-400, end=-10)
    before = db_count("uploads")
    with pytest.raises(RE):
        upload(https_session(UPLOAD_HOST, *as_files(cert, key, "expired")), mtls_port)
    assert db_count("uploads") == before

def test_expiry_warning_raised_for_cert_near_expiry():
    make_leaf("client-test-soon", CLIENT, start=-1, end=10, save_as="client-test-soon")
    c = dapp.app.test_client(); login(c, "it.officer", "Admin@123")
    certs = {x["name"]: x for x in c.get("/api/admin/certs").get_json()["certs"]}
    assert certs["client-test-soon"]["warn"] is True and certs["client-test-soon"]["days"] <= 10
    assert certs["client-branch-rangpur"]["warn"] is False

def test_revocation_revoked_branch_cert_refused_and_logged(mtls_port):
    cert, key = make_leaf("client-test-revoke", CLIENT, save_as="client-test-revoke")
    assert "revoked" in _revoke_as_two_officers("client-test-revoke")
    before_up, before_ref = db_count("uploads"), db_count("refused")
    r = upload(https_session(UPLOAD_HOST, *as_files(cert, key, "revoked")), mtls_port)
    assert r.status_code == 403 and "revoked" in r.json()["error"]
    assert db_count("uploads") == before_up and db_count("refused") == before_ref + 1

def test_revocation_unreachable_crl_fails_closed(genuine_pdf):
    out = run(["verify_statement.py", genuine_pdf], {"DHANSHIRI_CRL_URL": "http://127.0.0.1:1/crl.crl"})
    assert "RESULT: INVALID" in out and "fail-closed" in out

# ---------- Downgrade ----------

def test_downgrade_tls11_refused(portal_port):
    with pytest.raises(ssl.SSLError):
        _try_tls(portal_port, PORTAL_HOST, ssl.TLSVersion.TLSv1_1)

def test_downgrade_weak_cipher_refused_and_strong_suite_accepted(portal_port):
    with pytest.raises(ssl.SSLError):
        _try_tls(portal_port, PORTAL_HOST, ssl.TLSVersion.TLSv1_2, "AES128-SHA:@SECLEVEL=0")
    version, cipher = _try_tls(portal_port, PORTAL_HOST, ssl.TLSVersion.TLSv1_2, "ECDHE+AESGCM:@SECLEVEL=0")
    assert version == "TLSv1.2" and "ECDHE" in cipher[0] and "GCM" in cipher[0]

# ---------- Report signing ----------

def test_signing_genuine_report_verifies(genuine_pdf):
    assert "RESULT: VALID" in run(["verify_statement.py", genuine_pdf])

def test_signing_edited_report_fails(genuine_pdf):
    data = bytearray(open(genuine_pdf, "rb").read())
    first_range = int(re.search(rb"/ByteRange\s*\[\s*0\s+(\d+)", data).group(1))
    data[min(300, first_range - 1)] ^= 0x01          # one byte changed inside the signed area
    edited = os.path.join(WORK, "edited.pdf"); open(edited, "wb").write(data)
    assert "RESULT: INVALID" in run(["verify_statement.py", edited])

def test_signing_report_with_revoked_key_is_flagged(genuine_pdf):
    docsign = x509.load_pem_x509_certificate(open(os.path.join(CERTS, "docsign.crt"), "rb").read())
    open(REVOKED, "w").write(json.dumps({str(docsign.serial_number): "2026-11-22T00:00:00+00:00"}))
    assert "REVOKED" in run(["verify_statement.py", genuine_pdf])
    con = sqlite3.connect(DB); code = con.execute("SELECT code FROM statements ORDER BY rowid DESC LIMIT 1").fetchone()[0]; con.close()
    c = dapp.app.test_client()
    r = c.get(f"/api/verify/{code}")
    assert r.status_code == 200 and r.get_json()["genuine"] is False

# ---------- AI-driven threat (guide Section 8) ----------

def test_ai_single_officer_urgent_revocation_refused():
    make_leaf("client-test-ai", CLIENT, save_as="client-test-ai")
    it = dapp.app.test_client(); c1 = login(it, "it.officer", "Admin@123")
    it.post("/api/admin/requests", json={"action": "revoke_cert", "target": "client-test-ai"}, headers={"X-CSRF": c1})
    rid = it.get("/api/admin/requests").get_json()["requests"][0]["id"]
    r = it.post(f"/api/admin/requests/{rid}/approve", headers={"X-CSRF": c1})
    assert r.status_code == 403 and "different officer" in r.get_json()["error"]
    ai_serial = str(x509.load_pem_x509_certificate(open(os.path.join(CERTS, "client-test-ai.crt"), "rb").read()).serial_number)
    assert ai_serial not in open(REVOKED).read()  # nothing was revoked
    cust = dapp.app.test_client(); c2 = login(cust, "rahim", "Rahim@123")
    r = cust.post("/api/admin/requests", json={"action": "revoke_cert", "target": "client-test-ai"}, headers={"X-CSRF": c2})
    assert r.status_code == 403  # a customer cannot even open the request

# ---------- Upload service (R6) ----------

def test_upload_missing_client_cert_refused_and_logged(mtls_port):
    before_up = db_count("uploads")
    r = upload(https_session(UPLOAD_HOST), mtls_port)
    assert r.status_code == 403 and "client certificate required" in r.json()["error"]
    assert last_refusal()[1] == "client certificate required"
    assert db_count("uploads") == before_up

def test_upload_legitimate_branch_cert_accepted(mtls_port):
    before = db_count("uploads")
    r = upload(https_session(UPLOAD_HOST, *_rangpur()), mtls_port)
    assert r.status_code == 200 and r.json()["status"] == "stored"
    assert db_count("uploads") == before + 1

# ---------- Authentication ----------

def test_auth_wrong_otp_refused():
    c = dapp.app.test_client()
    csrf = c.get("/api/me").get_json()["csrf"]
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        c.post("/api/login", json={"username": "karim", "password": "Karim@123"}, headers={"X-CSRF": csrf})
    real = re.search(r"OTP for \S+: (\d{6})", buf.getvalue()).group(1)
    wrong = "000000" if real != "000000" else "111111"
    r = c.post("/api/login/otp", json={"code": wrong}, headers={"X-CSRF": csrf})
    assert r.status_code == 401 and c.get("/api/me").get_json()["user"] is None

# ---------- Key protection (R9, threat: key theft) ----------

def test_keys_private_files_mode_0600_and_ignored_by_git():
    import stat
    for n in ["issuing.key", "docsign.key", "server.key", "tsa.key", "ocsp.key", "client-branch-rangpur.key"]:
        p = os.path.join(CERTS, n)
        if os.name == "nt":
            acl = subprocess.run(["icacls", p], capture_output=True, text=True).stdout
            acl = acl.replace(p, "")  # the file path itself contains "\Users"; check only the permission entries
            for group in ("Everyone:(", "Users:(", "Authenticated Users:("):
                assert group not in acl, (n, group)
        else:
            assert stat.S_IMODE(os.stat(p).st_mode) == 0o600, n
    assert "certs/" in open(os.path.join(BASE, ".gitignore")).read()

# ---------- Issuance log integrity (X4) ----------

def test_issuance_log_tamper_detected():
    path = policy.LOG
    original = open(path).read()
    try:
        lines = original.splitlines(); entry = json.loads(lines[0]); entry["days"] = 1
        lines[0] = json.dumps(entry); open(path, "w").write("\n".join(lines) + "\n")
        assert "log tampered" in run(["check_issuance.py"])
    finally:
        open(path, "w").write(original)

def test_signing_verify_page_does_not_disclose_balance(genuine_pdf):
    """The public verification endpoint gives a verifier only: genuine yes/no, last four digits, issue date."""
    con = sqlite3.connect(DB); code = con.execute("SELECT code FROM statements ORDER BY rowid DESC LIMIT 1").fetchone()[0]; con.close()
    body = dapp.app.test_client().get(f"/api/verify/{code}").get_json()
    assert set(body) == {"genuine", "last4", "at"}, body
    assert body["genuine"] is True and len(body["last4"]) == 4
