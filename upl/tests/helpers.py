"""Shared helpers: certificate factory, HTTPS client that checks a chosen name, login through the real OTP flow."""
import contextlib, datetime as dt, hashlib, io, os, pathlib, re, socket, sqlite3, subprocess, sys, tempfile
import json, urllib3
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec
from config import CERTS, DB

ROOT = pathlib.Path(__file__).resolve().parents[1]
UPLOAD_HOST = "upload.dhanshiri.test"
PORTAL_HOST = "ibank.dhanshiri.test"
WORK = tempfile.mkdtemp(prefix="dhanshiri-art-")
KU = dict(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
          key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False)

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

class _Resp:
    def __init__(self, r):
        self.status_code = r.status; self.data = r.data
    def json(self):
        return json.loads(self.data)

class Client:
    """Small HTTPS client on urllib3. We use it instead of requests because requests, with a
    client certificate and a name check, failed in the lab even though the same chain verifies
    with plain ssl and with urllib3 directly. The name check is still done against `name`."""
    def __init__(self, name, cert=None, key=None, ca=None):
        kw = dict(ca_certs=ca or os.path.join(CERTS, "root.crt"), cert_reqs="CERT_REQUIRED",
                  assert_hostname=name, retries=False)
        if cert: kw.update(cert_file=cert, key_file=key)
        self.pm = urllib3.PoolManager(**kw)
    def _req(self, method, url, **kw):
        kw.pop("timeout", None); body, headers = kw.pop("data", None), {}
        if "json" in kw:
            body = json.dumps(kw.pop("json")).encode(); headers["Content-Type"] = "application/json"
        return _Resp(self.pm.request(method, url, body=body, headers=headers, redirect=False, timeout=10))
    def get(self, url, **kw): return self._req("GET", url, **kw)
    def post(self, url, **kw): return self._req("POST", url, **kw)
    def put(self, url, **kw): return self._req("PUT", url, **kw)

def https_session(name, cert=None, key=None, ca=None):
    return Client(name, cert=cert, key=key, ca=ca)

def _pem_key(k):
    return k.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())

def issuing_ca():
    c = x509.load_pem_x509_certificate(open(os.path.join(CERTS, "issuing.crt"), "rb").read())
    k = ser.load_pem_private_key(open(os.path.join(CERTS, "issuing.key"), "rb").read(), None)
    return c, k

def make_leaf(cn, eku, start=-1, end=365, san=None, ca=None, save_as=None):
    """Issue a leaf certificate. start/end are days from now. ca=(cert, key) defaults to the lab's issuing CA.
    save_as=name writes CERTS/name.crt and .key, where the admin page and check_issuance.py look."""
    ic, ik = ca or issuing_ca()
    now = dt.datetime.now(dt.timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .issuer_name(ic.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now + dt.timedelta(days=start)).not_valid_after(now + dt.timedelta(days=end))
         .add_extension(x509.BasicConstraints(False, None), True)
         .add_extension(x509.KeyUsage(**KU), True)
         .add_extension(x509.ExtendedKeyUsage([eku]), False))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in san]), False)
    cert = b.sign(ik, hashes.SHA256())
    if save_as:
        open(os.path.join(CERTS, save_as + ".crt"), "wb").write(cert.public_bytes(ser.Encoding.PEM))
        open(os.path.join(CERTS, save_as + ".key"), "wb").write(_pem_key(key))
    return cert, key

def as_files(cert, key, name):
    """Write a cert/key pair to a scratch folder; returns (cert_path, key_path) for requests."""
    cp, kp = os.path.join(WORK, name + ".crt"), os.path.join(WORK, name + ".key")
    open(cp, "wb").write(cert.public_bytes(ser.Encoding.PEM))
    open(kp, "wb").write(_pem_key(key))
    return cp, kp

def make_rogue_ca():
    """A CA the lab does not trust. Returns ((cert, key), path_to_root_pem)."""
    now = dt.datetime.now(dt.timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue Test CA (not Dhanshiri)")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(True, None), True)
            .add_extension(x509.KeyUsage(**{**KU, "key_cert_sign": True, "crl_sign": True}), True)
            .sign(key, hashes.SHA256()))
    path = os.path.join(WORK, "rogue-root.crt")
    open(path, "wb").write(cert.public_bytes(ser.Encoding.PEM))
    return (cert, key), path

def db_count(table):
    con = sqlite3.connect(DB)
    n = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    con.close(); return n

def last_refusal():
    con = sqlite3.connect(DB)
    row = con.execute("SELECT who, reason FROM refused ORDER BY id DESC LIMIT 1").fetchone()
    con.close(); return row

def login(client, user, password):
    """Real login: password, then the OTP the lab prints to the console (SMS simulation). Returns the new CSRF token."""
    csrf = client.get("/api/me").get_json()["csrf"]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        client.post("/api/login", json={"username": user, "password": password}, headers={"X-CSRF": csrf})
    otp = re.search(r"OTP for \S+: (\d{6})", buf.getvalue()).group(1)
    r = client.post("/api/login/otp", json={"code": otp}, headers={"X-CSRF": csrf})
    assert r.status_code == 200, r.get_json()
    return r.get_json()["csrf"]

def upload(session, port, data=None, name="scan.pdf"):
    """Start, send one chunk, finish. Returns the response of the first failing step, or of finish."""
    data = data or (b"%PDF-1.4\n" + os.urandom(248))
    sha = hashlib.sha256(data).hexdigest(); key = sha[:32]
    base = f"https://127.0.0.1:{port}/upload-api"
    st = session.post(f"{base}/start", json=dict(key=key, name=name, total=1, sha256=sha), timeout=10)
    if st.status_code != 200: return st
    session.put(f"{base}/chunk/{key}/0", data=data, timeout=10)
    return session.post(f"{base}/finish/{key}", timeout=10)

def run(args, env_extra=None):
    env = dict(os.environ, **(env_extra or {}))
    r = subprocess.run([sys.executable] + args, cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    return r.stdout + r.stderr
