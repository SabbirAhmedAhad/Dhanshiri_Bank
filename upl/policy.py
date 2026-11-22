"""Issuance policy checks (certificate policy section 4). Used by make_certs.py and by tests.
Every issued certificate is appended to an append-only, hash-chained log (X4). Certificates that
break the policy are logged with alert=true, and check_issuance.py prints an ALERT for them."""
import datetime as dt, hashlib, json, os, subprocess
from cryptography import x509
from config import CERTS

LOG = os.path.join(CERTS, "issuance.log")
MAXD = dict(root=5475, issuing=1825, server=90, client=365, docsign=730, ocsp=365, tsa=1095)
ZONE = "dhanshiri.test"

def sans(c):
    try: return c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound: return []

def policy_breaches(name, c):
    days = (c.not_valid_after_utc - c.not_valid_before_utc).days
    out = []
    if days > MAXD.get(name.split("-")[0], 0): out.append(f"validity {days} days exceeds policy")
    out += [f"SAN {s} outside {ZONE}" for s in sans(c) if not s.endswith(ZONE)]
    return out

def logissue(name, c):
    prev = json.loads(open(LOG).read().splitlines()[-1])["hash"] if os.path.exists(LOG) else "0" * 64
    breaches = policy_breaches(name, c)
    e = dict(at=dt.datetime.now(dt.timezone.utc).isoformat(), name=name, serial=f"{c.serial_number:x}",
             days=(c.not_valid_after_utc - c.not_valid_before_utc).days, sans=sans(c),
             alert=bool(breaches), breaches=breaches, prev=prev)
    e["hash"] = hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest()
    os.makedirs(CERTS, exist_ok=True)
    open(LOG, "a").write(json.dumps(e) + "\n")
    return breaches

def protect_key(path):
    """Owner-only access. Linux/macOS: chmod 0600. Windows: chmod does not do this, so remove inherited
    ACEs and keep only the current user and SYSTEM (icacls)."""
    if os.name == "nt":
        user = os.environ.get("USERNAME", "")
        subprocess.run(["icacls", path, "/inheritance:r", "/grant:r", f"{user}:F", "SYSTEM:F"],
                       capture_output=True, check=False)
    else:
        os.chmod(path, 0o600)
