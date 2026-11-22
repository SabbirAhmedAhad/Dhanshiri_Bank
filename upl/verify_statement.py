"""python verify_statement.py statement.pdf

Three checks, all must pass before a report is accepted:
  1. the signature still matches the bytes (an edited copy fails),
  2. the signer certificate chains to the Dhanshiri root,
  3. the signer certificate is not on the CRL published by the issuing CA.

Fail closed: if the CRL cannot be fetched, or its signature or next-update time is bad,
the report is NOT accepted (decision R7, see docs/revocation-and-failure-policy.md)."""
import datetime as dt, os, sys, urllib.request
from cryptography import x509
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.keys import load_cert_from_pemder
from pyhanko_certvalidator import ValidationContext
from config import CERTS, CRL_URL

P = lambda n: os.path.join(CERTS, n)

def fetch_revoked_serials():
    """Return the set of revoked serials from the CRL. Raises if the CRL is unusable."""
    crl = x509.load_der_x509_crl(urllib.request.urlopen(CRL_URL, timeout=5).read())
    issuing = x509.load_pem_x509_certificate(open(P("issuing.crt"), "rb").read())
    if not crl.is_signature_valid(issuing.public_key()):
        raise ValueError("CRL signature does not verify")
    if crl.next_update_utc and crl.next_update_utc < dt.datetime.now(dt.timezone.utc):
        raise ValueError("CRL is past its next-update time")
    return {r.serial_number for r in crl}

def main(path):
    vc = ValidationContext(trust_roots=[load_cert_from_pemder(P("root.crt"))],
                           other_certs=[load_cert_from_pemder(P("issuing.crt"))])
    sigs = list(PdfFileReader(open(path, "rb")).embedded_signatures)
    if not sigs:
        return "RESULT: INVALID - no signature found (unsigned file)."
    try:
        revoked = fetch_revoked_serials()
    except Exception as e:
        return f"RESULT: INVALID - cannot check revocation ({type(e).__name__}: {e}). Not accepted (fail-closed)."
    for s in sigs:
        try:
            st = validate_pdf_signature(s, vc)
            print(st.pretty_print_details())
            if s.signer_cert.serial_number in revoked:
                return "RESULT: INVALID - signing certificate has been REVOKED."
            return "RESULT: " + ("VALID" if st.bottom_line else "INVALID")
        except Exception as e:
            return f"RESULT: INVALID - modified after signing or signature broken ({type(e).__name__})."
    return "RESULT: INVALID"

if __name__ == "__main__":
    if len(sys.argv) != 2: sys.exit("usage: python verify_statement.py file.pdf")
    print(main(sys.argv[1]))
