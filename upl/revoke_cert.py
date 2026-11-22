r"""python revoke_cert.py certs\client-branch-rangpur.crt --approver1 it.officer --approver2 head.of.it
NOTE: approver names are typed, not authenticated (lab simulation of 4-eyes)."""
import argparse, datetime as dt, json, os
from cryptography import x509
a = argparse.ArgumentParser(); a.add_argument("cert"); a.add_argument("--approver1", required=True); a.add_argument("--approver2", required=True)
a = a.parse_args()
if a.approver1.strip().lower() == a.approver2.strip().lower(): raise SystemExit("REFUSED: two different approvers are required.")
c = x509.load_pem_x509_certificate(open(a.cert, "rb").read())
from config import CERTS
f = os.path.join(CERTS, "revoked.json")
try: d = json.load(open(f))
except Exception: d = {}
if isinstance(d, list): d = {str(s): "1970-01-01T00:00:00+00:00" for s in d}
d.setdefault(str(c.serial_number), dt.datetime.now(dt.timezone.utc).isoformat()); json.dump(d, open(f, "w"))
print(f"REVOKED serial {c.serial_number:x} ({c.subject.rfc4514_string()}) by {a.approver1} + {a.approver2}.")
