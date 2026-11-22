"""Branch PC: resumable, idempotent upload over mTLS. Safe to re-run after a dropped link.
python branch_client.py [file]   (default: makes a small demo scan)"""
import hashlib, os, sys, time, requests
from config import CERTS as C
U = "https://upload.dhanshiri.test:8444/upload-api"
kw = dict(verify=os.path.join(C, "root.crt"), cert=(os.path.join(C, "client-branch-rangpur.crt"), os.path.join(C, "client-branch-rangpur.key")), timeout=15)
data = open(sys.argv[1], "rb").read() if len(sys.argv) > 1 else b"DEMO SCAN " * 50000
name = os.path.basename(sys.argv[1]) if len(sys.argv) > 1 else "demo-registration-form.bin"
CH = 64 * 1024; n = -(-len(data) // CH); sha = hashlib.sha256(data).hexdigest(); key = sha[:32]  # same file => same key => resume
def retry(f):
    for i in range(8):
        try: return f()
        except requests.RequestException as e: print("link problem, retrying:", type(e).__name__); time.sleep(min(2 ** i, 30))
    sys.exit("giving up; run again to resume")
st = retry(lambda: requests.post(f"{U}/start", json=dict(key=key, name=name, total=n, sha256=sha), **kw)).json()
if st.get("done"): sys.exit("already uploaded")
have = set(st.get("have", []))
for i in range(n):
    if i in have: continue
    r = retry(lambda: requests.put(f"{U}/chunk/{key}/{i}", data=data[i * CH:(i + 1) * CH], **kw))
    if r.status_code != 200: sys.exit(f"{r.status_code} {r.text}")
r = retry(lambda: requests.post(f"{U}/finish/{key}", **kw)); print(r.status_code, r.text)
