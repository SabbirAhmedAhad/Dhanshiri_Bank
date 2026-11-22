"""OCSP responder + CRL + CA download on http://127.0.0.1:2560. revoked.json = {serial: iso-time}."""
import datetime as dt, glob, json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization as ser

from config import CERTS as C
P = lambda n: os.path.join(C, n)
def revoked_map():
    # Fail closed: missing/corrupt revocation state must never be interpreted as "no revocations".
    with open(P("revoked.json"), encoding="utf-8") as f:
        d = json.load(f)
    if isinstance(d, list): d = {str(s): "1970-01-01T00:00:00+00:00" for s in d}  # old format
    return {int(k): dt.datetime.fromisoformat(v) for k, v in d.items()}
revoked = lambda: set(revoked_map())
cert = lambda n: x509.load_pem_x509_certificate(open(P(n), "rb").read())
key = lambda n: ser.load_pem_private_key(open(P(n), "rb").read(), None)

def crl_der():
    iss, n = cert("issuing.crt"), dt.datetime.now(dt.timezone.utc)
    b = x509.CertificateRevocationListBuilder().issuer_name(iss.subject).last_update(n).next_update(n + dt.timedelta(days=2))
    b = b.add_extension(x509.CRLNumber(int(n.timestamp())), False)
    b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key("issuing.key").public_key()), False)
    for s, t in revoked_map().items():
        b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(s).revocation_date(t).build())
    return b.sign(key("issuing.key"), hashes.SHA256()).public_bytes(ser.Encoding.DER)

def ocsp_der(body):
    req, iss, oc = ocsp.load_der_ocsp_request(body), cert("issuing.crt"), cert("ocsp.crt")
    found = next((c for c in map(lambda f: x509.load_pem_x509_certificate(open(f, "rb").read()), glob.glob(P("*.crt")))
                  if c.serial_number == req.serial_number and c.issuer == iss.subject), None)
    if not found:
        return ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.UNAUTHORIZED).public_bytes(ser.Encoding.DER)
    rt, n = revoked_map().get(req.serial_number), dt.datetime.now(dt.timezone.utc)
    b = ocsp.OCSPResponseBuilder().add_response(cert=found, issuer=iss, algorithm=req.hash_algorithm,
        cert_status=ocsp.OCSPCertStatus.REVOKED if rt else ocsp.OCSPCertStatus.GOOD, this_update=n,
        next_update=n + dt.timedelta(days=1), revocation_time=rt, revocation_reason=x509.ReasonFlags.unspecified if rt else None)
    b = b.responder_id(ocsp.OCSPResponderEncoding.HASH, oc).certificates([oc])
    return b.sign(key("ocsp.key"), hashes.SHA256()).public_bytes(ser.Encoding.DER)

class H(BaseHTTPRequestHandler):
    def send(self, code, body, ct):
        self.send_response(code); self.send_header("Content-Type", ct); self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        self.send(200, ocsp_der(self.rfile.read(int(self.headers.get("Content-Length", 0)))), "application/ocsp-response")
    def do_GET(self):
        if self.path == "/crl/issuing.crl": self.send(200, crl_der(), "application/pkix-crl")
        elif self.path in ("/pki/root.crt", "/pki/issuing.crt"): self.send(200, open(P(self.path[5:]), "rb").read(), "application/x-pem-file")
        else: self.send(404, b"not found", "text/plain")
    def log_message(self, *a): pass

def serve(port=2560): ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
