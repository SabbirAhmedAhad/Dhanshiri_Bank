"""Paths for the lab. Environment variables let the test suite run in a temporary directory
so it never touches real keys or the real lab database."""
import os

BASE = os.path.dirname(os.path.abspath(__file__))
CERTS = os.environ.get("DHANSHIRI_CERTS", os.path.join(BASE, "certs"))
STATE = os.environ.get("DHANSHIRI_STATE", BASE)          # .secret, .fkey, lab.db
DB = os.path.join(STATE, "lab.db")
CRL_URL = os.environ.get("DHANSHIRI_CRL_URL", "http://127.0.0.1:2560/crl/issuing.crl")
