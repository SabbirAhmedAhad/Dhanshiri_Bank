"""python check_issuance.py - verifies the hash-chained issuance log and alerts on certificates that are not in it."""
import glob, hashlib, json, os
from cryptography import x509
from config import CERTS as C
rows = [json.loads(l) for l in open(os.path.join(C, "issuance.log"))]; prev = "0" * 64; bad = 0
for e in rows:
    h = e.pop("hash")
    if e["prev"] != prev or hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest() != h: print("ALERT: log tampered at", e["name"]); bad += 1
    if e["alert"]: print("ALERT: out-of-policy at issuance:", e["name"]); bad += 1
    prev = h
logged = {e["serial"] for e in rows}
for f in glob.glob(os.path.join(C, "*.crt")):
    if os.path.basename(f) in ("fullchain.crt", "ca-bundle.crt"): continue
    if f"{x509.load_pem_x509_certificate(open(f, 'rb').read()).serial_number:x}" not in logged: print("ALERT: certificate not in issuance log:", os.path.basename(f)); bad += 1
print("OK: log intact, nothing unlogged." if not bad else f"{bad} alert(s).")
