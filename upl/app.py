"""Dhanshiri Bank - Flask API + React (frontend/dist). ALL DATA IS SYNTHETIC.
python app.py -> http://localhost:5000   |   python app.py --https (after make_certs.py) -> :8443 portal, :8444 branch mTLS"""
import datetime as dt, hashlib, io, json, os, re, secrets, sqlite3, ssl, sys, time
from functools import wraps
from flask import Flask, abort, g, jsonify, request, send_file, send_from_directory, session
from itsdangerous import BadSignature, URLSafeTimedSerializer
from cryptography.fernet import Fernet
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

from config import BASE, CERTS, STATE, DB
from policy import protect_key
HTTPS = "--https" in sys.argv
app = Flask(__name__)
def secret(n, make):
    p = os.path.join(STATE, n)
    if not os.path.exists(p):
        open(p, "w").write(make()); protect_key(p)  # session key and field-encryption key: owner-only
    return open(p).read()
app.secret_key = secret(".secret", lambda: secrets.token_hex(32))
FER = Fernet(secret(".fkey", lambda: Fernet.generate_key().decode()).encode())  # field/file encryption at rest
LINK = URLSafeTimedSerializer(app.secret_key, salt="download")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=HTTPS, MAX_CONTENT_LENGTH=2 * 1024 * 1024)
now = lambda: dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M")

def init_db():
    con = sqlite3.connect(DB)
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, pw TEXT, name TEXT, role TEXT, phone TEXT, nid BLOB);
    CREATE TABLE IF NOT EXISTS accounts(id INTEGER PRIMARY KEY, user_id INT, no TEXT UNIQUE, balance INT);
    CREATE TABLE IF NOT EXISTS txns(id INTEGER PRIMARY KEY, account_id INT, at TEXT, descr TEXT, amount INT, after INT);
    CREATE TABLE IF NOT EXISTS statements(code TEXT PRIMARY KEY, account_no TEXT, at TEXT);
    CREATE TABLE IF NOT EXISTS uploads(key TEXT PRIMARY KEY, at TEXT, cn TEXT, serial TEXT, name TEXT, total INT, sha TEXT, done INT DEFAULT 0, blob BLOB);
    CREATE TABLE IF NOT EXISTS admin_requests(id INTEGER PRIMARY KEY, action TEXT, target TEXT, req_by TEXT, at TEXT, status TEXT, approver TEXT);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at TEXT, usr TEXT, event TEXT);
    CREATE TABLE IF NOT EXISTS refused(id INTEGER PRIMARY KEY, at TEXT, who TEXT, reason TEXT);
    CREATE TABLE IF NOT EXISTS chunks(key TEXT, n INT, data BLOB, PRIMARY KEY(key, n));
    CREATE TABLE IF NOT EXISTS transfer_refs(ref TEXT PRIMARY KEY, at TEXT, from_no TEXT);""")
    try: con.execute("ALTER TABLE users ADD COLUMN nid_hash TEXT")  # existing databases
    except sqlite3.OperationalError: pass
    con.commit()
    if not con.execute("SELECT 1 FROM users").fetchone():
        for u, p, n, role, ph, no, bal in [("rahim", "Rahim@123", "Rahim Uddin", "customer", "01700000001", "0101-000123", 15000000),
                                           ("karim", "Karim@123", "Karim Ahmed", "customer", "01700000002", "0204-000456", 8000000),
                                           ("officer.nasrin", "Officer@123", "Nasrin Akter, Branch Officer", "officer", "01700000003", None, 0)]:
            uid = con.execute("INSERT INTO users(username,pw,name,role,phone) VALUES(?,?,?,?,?)", (u, generate_password_hash(p), n, role, ph)).lastrowid
            if no:
                aid = con.execute("INSERT INTO accounts(user_id,no,balance) VALUES(?,?,?)", (uid, no, bal)).lastrowid
                con.execute("INSERT INTO txns(account_id,at,descr,amount,after) VALUES(?,?,?,?,?)", (aid, now(), "Opening balance", bal, bal))
        con.commit()
    for u, p, n, ph in [("it.officer", "Admin@123", "Farhan, IT Officer", "01700000004"), ("head.of.it", "Admin@456", "Nusrat, Head of IT", "01700000005")]:
        con.execute("INSERT OR IGNORE INTO users(username,pw,name,role,phone) VALUES(?,?,?,'admin',?)", (u, generate_password_hash(p), n, ph))
    con.commit(); con.close()

def db():
    if "db" not in g: g.db = sqlite3.connect(DB); g.db.row_factory = sqlite3.Row
    return g.db
@app.teardown_appcontext
def _close(e):
    d = g.pop("db", None)
    if d: d.close()

@app.before_request
def _load():
    if request.environ.get("SERVER_PORT") == "8444" and not request.path.startswith("/upload-api/"): abort(404)  # mTLS port serves only the upload API
    g.user = db().execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone() if "uid" in session else None
    if request.method in ("POST", "PUT") and not request.path.startswith("/upload-api/") and not secrets.compare_digest(request.headers.get("X-CSRF", ""), session.get("csrf", "x")):
        abort(400, "bad CSRF token")

@app.after_request
def _hdr(r):
    r.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                      "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"})
    if request.path.startswith(("/api", "/dl", "/upload-api")): r.headers["Cache-Control"] = "no-store"
    if HTTPS: r.headers["Strict-Transport-Security"] = "max-age=31536000"
    return r

@app.errorhandler(HTTPException)
def _err(e): return jsonify(error=e.description), e.code

def role_required(*roles):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if not g.user: return jsonify(error="Please log in."), 401
            if roles and g.user["role"] not in roles: return jsonify(error="Not allowed."), 403
            return f(*a, **k)
        return w
    return deco

def mask(blob):
    try: v = FER.decrypt(blob).decode(); return "•" * (len(v) - 3) + v[-3:]
    except Exception: return None
def pub(u): return {"name": u["name"], "username": u["username"], "role": u["role"], "nid": mask(u["nid"]) if u["nid"] else None} if u else None

FAILS = {}
def locked(k): c, t = FAILS.get(k, (0, 0)); return c >= 5 and time.time() - t < 300
def fail(k): FAILS[k] = (FAILS.get(k, (0, 0))[0] + 1, time.time())

@app.get("/api/me")
def me():
    session.setdefault("csrf", secrets.token_hex(16)); return jsonify(user=pub(g.user), csrf=session["csrf"])

@app.post("/api/login")
def login():
    j = request.get_json(silent=True) or {}; u = str(j.get("username", "")).strip().lower()[:64]; k = (u, request.remote_addr)
    if locked(k): return jsonify(error="Too many attempts. Wait 5 minutes."), 429
    row = db().execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
    ok = check_password_hash(row["pw"] if row else generate_password_hash("x"), str(j.get("password", ""))) and row  # same work either way
    if not ok: fail(k); return jsonify(error="Wrong username or password."), 401
    otp = f"{secrets.randbelow(10**6):06d}"; csrf = session.get("csrf") or secrets.token_hex(16)
    session.clear(); session.update(csrf=csrf, pre=row["id"], otp=hashlib.sha256((otp + app.secret_key).encode()).hexdigest(), otp_exp=time.time() + 300)
    print(f"[SMS simulation] OTP for {row['phone']}: {otp}")  # real system: SMS gateway
    return jsonify(otp=True, phone="•••••••" + row["phone"][-3:])

@app.post("/api/login/otp")
def login_otp():
    j = request.get_json(silent=True) or {}; k = ("otp", session.get("pre"), request.remote_addr)
    if "pre" not in session or locked(k): return jsonify(error="Start again."), 400
    h = hashlib.sha256((str(j.get("code", "")).strip() + app.secret_key).encode()).hexdigest()
    if time.time() > session["otp_exp"] or not secrets.compare_digest(h, session["otp"]): fail(k); return jsonify(error="Wrong or expired code."), 401
    uid = session["pre"]; session.clear(); session["uid"] = uid; session["csrf"] = secrets.token_hex(16)
    row = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone(); return jsonify(user=pub(row), csrf=session["csrf"])

@app.post("/api/register")
def register():
    j = request.get_json(silent=True) or {}
    name, u, p, ph, nid = (str(j.get(x, "")).strip() for x in ("name", "username", "password", "phone", "nid"))
    u = u.lower()
    if not 2 <= len(name) <= 60: return jsonify(error="Enter your full name."), 400
    if not re.fullmatch(r"[a-z0-9_]{3,20}", u): return jsonify(error="Username: 3-20 letters, digits or _."), 400
    if len(p) < 8: return jsonify(error="Password must be at least 8 characters."), 400
    if not re.fullmatch(r"01\d{9}", ph): return jsonify(error="Enter an 11-digit mobile number starting with 01."), 400
    if nid and not re.fullmatch(r"\d{10}|\d{13}|\d{17}", nid): return jsonify(error="NID must be 10, 13 or 17 digits."), 400
    nid_hash = hashlib.sha256(nid.encode()).hexdigest() if nid else None
    try:
        with db() as con:
            if con.execute("SELECT 1 FROM users WHERE phone=?", (ph,)).fetchone(): return jsonify(error="This mobile number is already registered."), 409
            if nid_hash and con.execute("SELECT 1 FROM users WHERE nid_hash=?", (nid_hash,)).fetchone(): return jsonify(error="This National ID is already registered."), 409
            new_account(con, con.execute("INSERT INTO users(username,pw,name,role,phone,nid,nid_hash) VALUES(?,?,?,?,?,?,?)", (u, generate_password_hash(p), name, "customer", ph, FER.encrypt(nid.encode()) if nid else None, nid_hash)).lastrowid, 1000000, "Opening balance")
    except sqlite3.IntegrityError: return jsonify(error="That username is not available."), 409
    return jsonify(ok=True)

@app.post("/api/logout")
def logout(): session.clear(); return jsonify(ok=True)

def new_account(con, uid, opening, note):
    while True:
        no = f"{secrets.randbelow(9000) + 1000}-{secrets.randbelow(900000) + 100000}"
        if not con.execute("SELECT 1 FROM accounts WHERE no=?", (no,)).fetchone(): break
    aid = con.execute("INSERT INTO accounts(user_id,no,balance) VALUES(?,?,?)", (uid, no, opening)).lastrowid
    con.execute("INSERT INTO txns(account_id,at,descr,amount,after) VALUES(?,?,?,?,?)", (aid, now(), note, opening, opening)); return no

def own(no): return db().execute("SELECT * FROM accounts WHERE no=? AND user_id=?", (no, g.user["id"])).fetchone() or abort(404, "Account not found.")
fmt = lambda p: f"{p / 100:,.2f}"

@app.get("/api/accounts")
@role_required("customer")
def accounts(): return jsonify(accounts=[dict(r) for r in db().execute("SELECT no,balance FROM accounts WHERE user_id=?", (g.user["id"],))])

@app.post("/api/accounts/open")
@role_required("customer")
def open_account():
    con = db()
    if con.execute("SELECT COUNT(*) FROM accounts WHERE user_id=?", (g.user["id"],)).fetchone()[0] >= 5: return jsonify(error="You can have at most 5 accounts."), 400
    with con: no = new_account(con, g.user["id"], 0, "Account opened")
    return jsonify(no=no)

@app.get("/api/accounts/<no>")
@role_required("customer")
def account(no):
    a = own(no); t = db().execute("SELECT at,descr,amount,after FROM txns WHERE account_id=? ORDER BY id DESC LIMIT 30", (a["id"],)).fetchall()
    return jsonify(no=a["no"], balance=a["balance"], txns=[dict(r) for r in t])

class InsufficientFunds(Exception): pass

@app.post("/api/transfer")
@role_required("customer")
def transfer():
    con = db(); j = request.get_json(silent=True) or {}
    ref = str(j.get("ref", ""))
    if not re.fullmatch(r"[A-Za-z0-9-]{8,64}", ref): return jsonify(error="Missing transfer reference."), 400
    try:
        amt = round(float(j.get("amount")) * 100)
        src = con.execute("SELECT * FROM accounts WHERE no=? AND user_id=?", (j.get("from"), g.user["id"])).fetchone()
        dst = con.execute("SELECT * FROM accounts WHERE no=?", (str(j.get("to", "")).strip(),)).fetchone()
    except (TypeError, ValueError, OverflowError): src = dst = None; amt = 0
    note = str(j.get("note", ""))[:60]
    if not src or not dst or src["id"] == dst["id"] or not 0 < amt <= 50000000: return jsonify(error="Invalid transfer details (limit BDT 500,000 per transfer)."), 400
    try:
        with con:  # one database transaction: the reference, both balances and both history lines commit together or not at all
            con.execute("INSERT INTO transfer_refs(ref,at,from_no) VALUES(?,?,?)", (ref, now(), src["no"]))  # UNIQUE: a repeat fails here
            ok = con.execute("UPDATE accounts SET balance=balance-? WHERE id=? AND balance>=?", (amt, src["id"], amt)).rowcount
            if not ok: raise InsufficientFunds()
            con.execute("UPDATE accounts SET balance=balance+? WHERE id=?", (amt, dst["id"]))
            for acc, sign, d in [(src, -1, f"Transfer to {dst['no']}"), (dst, 1, f"Transfer from {src['no']}")]:
                bal = con.execute("SELECT balance FROM accounts WHERE id=?", (acc["id"],)).fetchone()[0]
                con.execute("INSERT INTO txns(account_id,at,descr,amount,after) VALUES(?,?,?,?,?)", (acc["id"], now(), d + (f" - {note}" if note else ""), sign * amt, bal))
    except sqlite3.IntegrityError:
        return jsonify(error="Duplicate transaction: this transfer was already sent."), 409
    except InsufficientFunds:
        return jsonify(error="Insufficient balance."), 400
    return jsonify(ok=True)

@app.get("/api/accounts/<no>/link")
@role_required("customer")
def link(no): own(no); return jsonify(url="/dl/" + LINK.dumps([no, g.user["id"]]) + ".pdf", expires_in=120)

def sign_pdf(data):
    C = lambda n: os.path.join(CERTS, n)
    try:
        from pyhanko.sign import signers, timestamps
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        from pyhanko.keys import load_cert_from_pemder, load_private_key_from_pemder
        signer = signers.SimpleSigner.load(C("docsign.key"), C("docsign.crt"), ca_chain_files=(C("issuing.crt"),))
        ts = timestamps.DummyTimeStamper(tsa_cert=load_cert_from_pemder(C("tsa.crt")), tsa_key=load_private_key_from_pemder(C("tsa.key"), None),
                                         certs_to_embed=[load_cert_from_pemder(C("issuing.crt"))])
        meta = signers.PdfSignatureMetadata(field_name="DhanshiriSig", reason="Official bank statement", md_algorithm="sha256")
        return signers.PdfSigner(meta, signer=signer, timestamper=ts).sign_pdf(IncrementalPdfFileWriter(io.BytesIO(data))).getvalue()
    except Exception as e:  # fail closed: never hand out an unsigned "official" statement
        app.logger.error("signing failed: %s", e); abort(503, "Statement signing is unavailable. Try again later.")

@app.get("/dl/<tok>.pdf")
@role_required("customer")
def download(tok):
    try: no, uid = LINK.loads(tok, max_age=120)
    except BadSignature: abort(410, "Link expired. Request a new download.")
    if uid != g.user["id"]: abort(404, "Account not found.")
    a = own(no); t = db().execute("SELECT * FROM txns WHERE account_id=? ORDER BY id", (a["id"],)).fetchall()
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.graphics.barcode.qr import QrCodeWidget
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics import renderPDF
    code = secrets.token_urlsafe(8); buf = io.BytesIO(); c = canvas.Canvas(buf, pagesize=A4); y = 800
    c.setFont("Helvetica-Bold", 14); c.drawString(50, y, "Dhanshiri Bank Ltd - Account Statement"); c.setFont("Helvetica", 10); y -= 22
    for line in [f"Customer: {g.user['name']}", f"Account: {a['no']}", f"Generated: {now()} UTC", f"Closing balance: BDT {fmt(a['balance'])}", f"Statement code: {code}"]:
        c.drawString(50, y, line); y -= 15
    q = QrCodeWidget(request.host_url + "verify/" + code); b = q.getBounds(); d = Drawing(80, 80, transform=[80 / (b[2] - b[0]), 0, 0, 80 / (b[3] - b[1]), 0, 0]); d.add(q)
    renderPDF.draw(d, c, 460, 715); c.setFont("Helvetica", 7); c.drawString(440, 705, "Scan to verify this statement is genuine")
    y = 690; c.setFont("Helvetica-Bold", 9); c.drawString(50, y, "Date"); c.drawString(140, y, "Description"); c.drawString(400, y, "Amount"); c.drawString(480, y, "Balance"); c.setFont("Helvetica", 9)
    for r in t:
        y -= 14
        if y < 50: c.showPage(); y = 800; c.setFont("Helvetica", 9)
        c.drawString(50, y, r["at"]); c.drawString(140, y, r["descr"][:42]); c.drawRightString(455, y, fmt(r["amount"])); c.drawRightString(540, y, fmt(r["after"]))
    c.save(); data = sign_pdf(buf.getvalue())
    with db() as con: con.execute("INSERT INTO statements(code,account_no,at) VALUES(?,?,?)", (code, no, now()))
    return send_file(io.BytesIO(data), mimetype="application/pdf", as_attachment=True, download_name=f"statement-{no}.pdf")

@app.get("/api/verify/<code>")  # public: shows only what the holder chose to share by handing out the PDF
def verify(code):
    r = db().execute("SELECT account_no, at FROM statements WHERE code=?", (code,)).fetchone()
    if not r: return jsonify(error="Dhanshiri Bank did not issue a statement with this code."), 404
    # fail closed: if we cannot read the revocation state we must not say the statement is genuine
    try:
        from cryptography import x509; import pki_http
        serial = x509.load_pem_x509_certificate(open(os.path.join(CERTS, "docsign.crt"), "rb").read()).serial_number
        revoked_now = serial in pki_http.revoked()
    except Exception as e:
        app.logger.error("verify: cannot read revocation state: %s", e)
        return jsonify(error="Cannot confirm the signing certificate right now. Try again later."), 503
    # data minimisation: only what a verifier needs to match the report in hand (no balance, no full account number)
    return jsonify(genuine=not revoked_now, last4=r["account_no"][-4:], at=r["at"])

# ---- branch upload (mTLS port 8444): resumable, idempotent, encrypted at rest ----
def refuse(why, who="unknown"):  # every refused branch attempt is logged, nothing is stored
    try:
        with db() as con: con.execute("INSERT INTO refused(at,who,reason) VALUES(?,?,?)", (now(), who, why))
    except Exception: pass
    abort(403, why)

def branch():
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID as EKU
    from cryptography.hazmat.primitives import serialization
    from pki_http import revoked
    # Werkzeug does not populate SSL_CLIENT_CERT. Read the peer certificate
    # from its TLS socket; otherwise a valid mTLS connection would be refused.
    pem = request.environ.get("SSL_CLIENT_CERT")
    if not pem:
        sock = request.environ.get("werkzeug.socket")
        try:
            der = sock.getpeercert(binary_form=True) if sock else None
            pem = x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM).decode() if der else None
        except Exception:
            pem = None
    if not pem:
        refuse("client certificate required")
    try:
        c = x509.load_pem_x509_certificate(pem.encode() if isinstance(pem, str) else pem)
        rv = revoked()  # raises if revocation state is missing/corrupt: fail closed
    except Exception as e:
        app.logger.error("branch certificate/revocation check unavailable: %s", e)
        abort(503, "Certificate status cannot be confirmed; upload refused.")
    cn = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if c.not_valid_after_utc < dt.datetime.now(dt.timezone.utc): refuse("client certificate expired", cn)
    if c.serial_number in rv: refuse("client certificate revoked", cn)
    try: ok = EKU.CLIENT_AUTH in c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound: ok = False
    if not ok: refuse("certificate is not a client certificate", cn)
    return cn, f"{c.serial_number:x}"

def mine(key, cn):
    u = db().execute("SELECT * FROM uploads WHERE key=?", (key,)).fetchone()
    return u if u and u["cn"] == cn else abort(404, "Unknown upload.")

@app.post("/upload-api/start")
def up_start():
    cn, sn = branch(); j = request.get_json(silent=True) or {}
    key, name, total, sha = str(j.get("key", "")), str(j.get("name", ""))[:80], j.get("total"), str(j.get("sha256", ""))
    if not re.fullmatch(r"[0-9a-f]{32}", key) or not isinstance(total, int) or not 1 <= total <= 2000: abort(400, "bad upload request")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,70}\.(pdf|jpe?g|png)", name, re.I): abort(400, "file name must be letters, digits, dashes or underscores, ending in .pdf, .jpg or .png")
    with db() as con: con.execute("INSERT OR IGNORE INTO uploads(key,at,cn,serial,name,total,sha) VALUES(?,?,?,?,?,?,?)", (key, now(), cn, sn, name, total, sha))
    u = mine(key, cn); have = [r[0] for r in db().execute("SELECT n FROM chunks WHERE key=?", (key,))]
    return jsonify(done=bool(u["done"]), have=have)

@app.put("/upload-api/chunk/<key>/<int:n>")
def up_chunk(key, n):
    u = mine(key, branch()[0])
    if u["done"] or not 0 <= n < u["total"]: abort(400, "bad chunk")
    with db() as con: con.execute("INSERT OR IGNORE INTO chunks(key,n,data) VALUES(?,?,?)", (key, n, request.get_data()))  # a retried chunk is harmless
    return jsonify(ok=True)

FILE_SIGNATURES = {"pdf": [b"%PDF-"], "jpg": [b"\xff\xd8\xff"], "jpeg": [b"\xff\xd8\xff"], "png": [b"\x89PNG\r\n\x1a\n"]}

@app.post("/upload-api/finish/<key>")
def up_finish(key):
    u = mine(key, branch()[0])
    if u["done"]: return jsonify(status="stored", already=True)
    rows = db().execute("SELECT data FROM chunks WHERE key=? ORDER BY n", (key,)).fetchall()
    if len(rows) != u["total"]: abort(409, f"{u['total'] - len(rows)} chunks missing; resume the upload")
    data = b"".join(r[0] for r in rows)
    if hashlib.sha256(data).hexdigest() != u["sha"]: abort(422, "checksum mismatch; upload again")
    ext = u["name"].lower().rsplit(".", 1)[-1]
    if not any(data.startswith(m) for m in FILE_SIGNATURES[ext]):  # content must be the type its name claims
        with db() as con:
            con.execute("INSERT INTO refused(at,who,reason) VALUES(?,?,?)", (now(), u["cn"], "file content does not match its type"))
            con.execute("DELETE FROM chunks WHERE key=?", (key,)); con.execute("DELETE FROM uploads WHERE key=?", (key,))
        abort(415, "file content does not match its type; nothing stored")
    with db() as con:
        con.execute("UPDATE uploads SET done=1, blob=? WHERE key=?", (FER.encrypt(data), key)); con.execute("DELETE FROM chunks WHERE key=?", (key,))
    return jsonify(status="stored", bytes=len(data), sha256=u["sha"])

@app.get("/api/uploads")
@role_required("officer", "admin")
def uploads():
    r = db().execute("SELECT at,cn,name,total,done FROM uploads ORDER BY at DESC LIMIT 8").fetchall()
    return jsonify(uploads=[{"at": x["at"], "branch": x["cn"], "name": x["name"], "done": bool(x["done"])} for x in r])

# ---- administration: every change needs two different logged-in officers ----
def audit(ev):
    db().execute("INSERT INTO audit(at,usr,event) VALUES(?,?,?)", (now(), g.user["username"], ev)); db().commit()

@app.get("/api/admin/requests")
@role_required("admin")
def adm_list():
    q = lambda sql: [dict(x) for x in db().execute(sql).fetchall()]
    return jsonify(requests=q("SELECT * FROM admin_requests ORDER BY id DESC LIMIT 10"), audit=q("SELECT at,usr,event FROM audit ORDER BY id DESC LIMIT 10"), me=g.user["username"])

@app.post("/api/admin/requests")
@role_required("admin")
def adm_new():
    j = request.get_json(silent=True) or {}; act, tgt = j.get("action"), str(j.get("target", "")).strip()
    if act == "revoke_cert" and re.fullmatch(r"client-[a-z0-9-]+|docsign|server|tsa", tgt) and os.path.exists(os.path.join(CERTS, tgt + ".crt")): pass
    elif act == "reset_password" and db().execute("SELECT 1 FROM users WHERE username=? AND role!='admin'", (tgt,)).fetchone(): pass
    else: return jsonify(error="Unknown action or target."), 400
    with db() as con: con.execute("INSERT INTO admin_requests(action,target,req_by,at,status) VALUES(?,?,?,?,'pending')", (act, tgt, g.user["username"], now()))
    audit(f"requested {act} {tgt}"); return jsonify(ok=True)

@app.post("/api/admin/requests/<int:rid>/<verb>")
@role_required("admin")
def adm_decide(rid, verb):
    if verb not in ("approve", "reject"): abort(404)
    r = db().execute("SELECT * FROM admin_requests WHERE id=? AND status='pending'", (rid,)).fetchone() or abort(404, "Request not found.")
    if r["req_by"] == g.user["username"]: abort(403, "A different officer must decide this request.")
    msg = "Request rejected."
    if verb == "approve" and r["action"] == "revoke_cert":
        from cryptography import x509
        c = x509.load_pem_x509_certificate(open(os.path.join(CERTS, r["target"] + ".crt"), "rb").read()); f = os.path.join(CERTS, "revoked.json")
        try: d = json.load(open(f))
        except Exception: d = {}
        if isinstance(d, list): d = {str(x): "1970-01-01T00:00:00+00:00" for x in d}
        d.setdefault(str(c.serial_number), dt.datetime.now(dt.timezone.utc).isoformat()); json.dump(d, open(f, "w")); msg = f"Certificate {r['target']} revoked."
    elif verb == "approve":
        tmp = secrets.token_urlsafe(9)
        with db() as con: con.execute("UPDATE users SET pw=? WHERE username=?", (generate_password_hash(tmp), r["target"]))
        msg = f"Temporary password for {r['target']}: {tmp}. Shown once; hand it over in person."
    with db() as con: con.execute("UPDATE admin_requests SET status=?, approver=? WHERE id=?", ("approved" if verb == "approve" else "rejected", g.user["username"], rid))
    audit(f"{'approved' if verb == 'approve' else 'rejected'} request {rid} ({r['action']} {r['target']})"); return jsonify(message=msg)

@app.get("/api/admin/certs")
@role_required("admin")
def adm_certs():
    from cryptography import x509; import glob, pki_http
    rv, out = pki_http.revoked(), []
    for f in sorted(glob.glob(os.path.join(CERTS, "*.crt"))):
        nm = os.path.basename(f)[:-4]
        if nm in ("fullchain", "ca-bundle"): continue
        c = x509.load_pem_x509_certificate(open(f, "rb").read()); d = (c.not_valid_after_utc - dt.datetime.now(dt.timezone.utc)).days
        out.append(dict(name=nm, days=d, revoked=c.serial_number in rv, warn=d < 30))
    return jsonify(certs=out, refused=[dict(x) for x in db().execute("SELECT at,who,reason FROM refused ORDER BY id DESC LIMIT 8")])

HIDDEN_COLS = {"users": ["pw", "nid"], "uploads": ["blob"], "chunks": ["data"]}  # hashes, National ID, encrypted files

@app.get("/api/admin/db")  # read-only view for admins: latest 50 rows per table, secrets left out
@role_required("admin")
def adm_db():
    con = db(); out = []
    for (t,) in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall():
        cols = [c[1] for c in con.execute(f"PRAGMA table_info({t})") if c[1] not in HIDDEN_COLS.get(t, [])]
        count = con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        rows = [dict(r) for r in con.execute(f"SELECT {', '.join(cols)} FROM {t} ORDER BY rowid DESC LIMIT 50")]
        out.append(dict(table=t, count=count, columns=cols, rows=rows))
    audit("viewed database (read-only)")
    return jsonify(tables=out)

DIST = os.path.join(BASE, "frontend", "dist")
@app.get("/", defaults={"p": ""})
@app.get("/<path:p>")
def spa(p):
    if p == "api" or p.startswith("api/"): abort(404, "Not found.")
    if not os.path.exists(os.path.join(DIST, "index.html")): return "Frontend not built: cd frontend && npm install && npm run build", 500
    if p and os.path.isfile(os.path.join(DIST, p)): resp = send_from_directory(DIST, p)
    else: resp = send_from_directory(DIST, "index.html")
    resp.headers["Cache-Control"] = "no-cache"  # the page must always be fresh; the hashed JS/CSS it names can be cached
    return resp

def make_ssl_context(mtls):
    """TLS 1.2 minimum (1.3 preferred), ECDHE+AEAD suites only. mtls=True: ask for a branch client cert.
    CERT_OPTIONAL, not CERT_REQUIRED: a missing cert reaches the app, which refuses and LOGS it (R6).
    A cert that fails chain validation is still refused by the TLS layer, before any app code runs."""
    x = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    x.minimum_version = ssl.TLSVersion.TLSv1_2
    x.options |= ssl.OP_NO_COMPRESSION
    x.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    x.load_cert_chain(os.path.join(CERTS, "fullchain.crt"), os.path.join(CERTS, "server.key"))
    if mtls:
        x.verify_mode = ssl.CERT_OPTIONAL
        x.load_verify_locations(os.path.join(CERTS, "ca-bundle.crt"))
    return x

if __name__ == "__main__":
    init_db()
    if HTTPS:
        import threading
        from werkzeug.serving import make_server
        import pki_http
        C = lambda n: os.path.join(CERTS, n)
        if not os.path.exists(C("server.crt")): sys.exit("Run first:  python make_certs.py")
        ctx = make_ssl_context
        run = lambda port, x: make_server("127.0.0.1", port, app, threaded=True, ssl_context=x).serve_forever()
        from werkzeug.wrappers import Response
        redir = lambda env, sr: Response("", 301, {"Location": "https://ibank.dhanshiri.test:8443" + env.get("PATH_INFO", "/")})(env, sr)
        threading.Thread(target=lambda: make_server("127.0.0.1", 8080, redir).serve_forever(), daemon=True).start()  # HTTP -> HTTPS
        threading.Thread(target=pki_http.serve, daemon=True).start(); threading.Thread(target=run, args=(8444, ctx(True)), daemon=True).start()
        print("Portal https://ibank.dhanshiri.test:8443 | branch mTLS :8444 | OCSP/CRL http://127.0.0.1:2560"); run(8443, ctx(False))
    else:
        # python app.py          -> only this PC (127.0.0.1:5000)
        # python app.py --lan    -> anyone on the same network can open http://<your-IP>:5000 (demo only)
        app.run(host="0.0.0.0" if "--lan" in sys.argv else "127.0.0.1", port=5000)
