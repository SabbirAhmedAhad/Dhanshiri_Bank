"""Builds the lab PKI (pure Python, works on Windows):
Root CA (P-384, 15y, key discarded) -> Issuing CA (P-256, 5y, pathlen 0, names limited to dhanshiri.test)
  -> server (TLS), client (mTLS branch), docsign (PDF), ocsp, tsa certificates."""
import datetime as dt, os
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID as EKU, AuthorityInformationAccessOID as AIA
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from config import CERTS as OUT
from policy import logissue, protect_key
os.makedirs(OUT, exist_ok=True)
now = dt.datetime.now(dt.timezone.utc)
URI = x509.UniformResourceIdentifier
N = lambda cn: x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Dhanshiri Bank Ltd"),
                          x509.NameAttribute(NameOID.COMMON_NAME, cn)])
def ku(**k):
    d = dict(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False,
             key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False)
    d.update(k); return x509.KeyUsage(**d)
def w(name, data):
    p = os.path.join(OUT, name); open(p, "wb").write(data)
    if name.endswith(".key"): protect_key(p)
PEM = ser.Encoding.PEM

def issue(cn, key, days, hash_, exts, issuer=None, issuer_key=None):
    b = (x509.CertificateBuilder().subject_name(N(cn)).issuer_name(issuer.subject if issuer else N(cn))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now).not_valid_after(now + dt.timedelta(days=days))
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False))
    if issuer:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False)
        b = b.add_extension(x509.AuthorityInformationAccess([
            x509.AccessDescription(AIA.OCSP, URI("http://ocsp.dhanshiri.test:2560")),
            x509.AccessDescription(AIA.CA_ISSUERS, URI("http://crl.dhanshiri.test:2560/pki/issuing.crt"))]), False)
        b = b.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
            [URI("http://crl.dhanshiri.test:2560/crl/issuing.crl")], None, None, None)]), False)
    for e, crit in exts: b = b.add_extension(e, crit)
    return b.sign(issuer_key or key, hash_)

def save(name, cert, key=None):
    for b in logissue(name, cert): print("ALERT out-of-policy certificate:", name, b)
    w(name + ".crt", cert.public_bytes(PEM))
    if key: w(name + ".key", key.private_bytes(PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))

# 1. Root (offline): sign the issuing CA, then throw the key away
rk = ec.generate_private_key(ec.SECP384R1())
root = issue("Dhanshiri Root CA", rk, 5475, hashes.SHA384(), [
    (x509.BasicConstraints(True, 1), True), (ku(key_cert_sign=True, crl_sign=True), True)])
# 2. Issuing CA: pathlen 0, only *.dhanshiri.test
ik = ec.generate_private_key(ec.SECP256R1())
iss = issue("Dhanshiri Issuing CA", ik, 1825, hashes.SHA384(), [
    (x509.BasicConstraints(True, 0), True), (ku(key_cert_sign=True, crl_sign=True), True),
    (x509.NameConstraints([x509.DNSName("dhanshiri.test")], None), True)], root, rk)
save("root", root); save("issuing", iss, ik)

BASIC = (x509.BasicConstraints(False, None), True)
def leaf(name, cn, days, kus, ekus, san=None, extra=()):
    k = rsa.generate_private_key(65537, 2048) if name == "tsa" else ec.generate_private_key(ec.SECP256R1())  # pyHanko's local TSA needs RSA
    ex = [BASIC, (ku(**kus), True), (x509.ExtendedKeyUsage(ekus), ekus_crit.get(name, False))] + list(extra)
    if san: ex.append((x509.SubjectAlternativeName([x509.DNSName(s) for s in san]), False))
    save(name, issue(cn, k, days, hashes.SHA256(), ex, iss, ik), k)
ekus_crit = {"tsa": True}
leaf("server", "ibank.dhanshiri.test", 90, dict(digital_signature=True), [EKU.SERVER_AUTH],
     ["ibank.dhanshiri.test", "upload.dhanshiri.test"])
leaf("client-branch-rangpur", "branch-rangpur.agents.dhanshiri.test", 365, dict(digital_signature=True), [EKU.CLIENT_AUTH],
     ["branch-rangpur.agents.dhanshiri.test"])
leaf("docsign", "Dhanshiri Statement Signing", 730, dict(digital_signature=True, content_commitment=True),
     [x509.ObjectIdentifier("1.3.6.1.5.5.7.3.36")])
leaf("ocsp", "Dhanshiri OCSP Responder", 365, dict(digital_signature=True), [EKU.OCSP_SIGNING],
     extra=[(x509.OCSPNoCheck(), False)])
leaf("tsa", "Dhanshiri Timestamp Authority", 1095, dict(digital_signature=True), [EKU.TIME_STAMPING])

r, i = root.public_bytes(PEM), iss.public_bytes(PEM)
w("fullchain.crt", open(os.path.join(OUT, "server.crt"), "rb").read() + i)
w("ca-bundle.crt", r + i)
if not os.path.exists(os.path.join(OUT, "revoked.json")): w("revoked.json", b"[]")
print("PKI ready in certs/ : root, issuing, server, client-branch-rangpur, docsign, ocsp, tsa. Root key discarded.")
