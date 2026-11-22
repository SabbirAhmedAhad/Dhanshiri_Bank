# Dhanshiri Bank - React + Flask + lab PKI (Windows / VS Code)
Setup (ekbar): `py -m venv .venv`, `.venv\Scripts\Activate.ps1`, `pip install -r requirements.txt`, `python make_certs.py`
hosts (Admin PowerShell): `Add-Content C:\Windows\System32\drivers\etc\hosts "127.0.0.1 ibank.dhanshiri.test upload.dhanshiri.test ocsp.dhanshiri.test crl.dhanshiri.test tsa.dhanshiri.test"`
Lab root: `certutil -user -addstore Root certs\root.crt`  (shesh e `-delstore Root "Dhanshiri Root CA"`)

Run: `python app.py --https` -> https://ibank.dhanshiri.test:8443 (HTTP :8080 redirects). UI only: `python app.py` -> http://localhost:5000
Logins (OTP server console-e print hoy = SMS simulation):
- Customer: rahim / Rahim@123 , karim / Karim@123 (new customer register korle BDT 10,000 opening)
- Branch officer: officer.nasrin / Officer@123 (branch uploads dekhe)
- Admin (dual approval): it.officer / Admin@123 , head.of.it / Admin@456

Demo: customer login -> Signed statement (PDF) -> `python verify_statement.py statement-0101-000123.pdf` (VALID; ek byte bodle INVALID) -> QR/`/verify/<code>`
Branch upload (resumable, mTLS :8444): `python branch_client.py`. Admin page: revoke cert / reset password need a 2nd officer.
`python check_issuance.py` = issuance log alert. Refused uploads + cert expiry admin page-e.

Done: TLS1.2+ (ECDHE AEAD only), HSTS, mTLS port serves only /upload-api, fail-closed signing, OTP login, NID encrypted+masked, lockout, 2-min download links.
Not done: TPM key storage, old-branch-PC gateway, emergency offline runbook code, per-user certs. Shob data synthetic; certs\ keys share korbe na.

## Tests (CSE487 Track 2)

```
pip install -r requirements-dev.txt
python -m pytest tests -v
```

The suite builds its own PKI and database in a temporary folder, so `certs/` and `lab.db` are not touched.
It starts a real portal listener, a real mTLS upload listener and a CRL server on random local ports.
Results are written up in `docs/7-test-results.md`. Documentation index: `docs/README.md`.

Changes made for the course review: verify endpoint fails closed; `verify_statement.py` checks the CRL and fails closed;
paths read from `config.py` (environment overrides); issuance policy moved to `policy.py`; listener uses `CERT_OPTIONAL`
so missing branch certificates are logged by the app; 23 tests added.

## Web application security additions

A second test module, `tests/test_web_security.py`, adds local checks for SQL injection attempts,
XSS-safe rendering, CSRF, IDOR/account isolation, role authorization, login lockout, security headers,
and transfer amount validation. These tests are for this synthetic local application only.

Run all tests:

```bash
pip install -r requirements-dev.txt
python -m pytest tests -v
```

Build the React frontend after installing its dependencies:

```bash
cd frontend
npm ci
npm run build
cd ..
```

The admin dashboard now includes a Web Application Security Checks coverage panel. It distinguishes
implemented controls from items that still need work; it is not a live vulnerability scanner.

Important remaining hardening: replace the process-local login lockout with persistent distributed
rate limiting; use a real SMS/OTP provider; add upload content-type and file-signature validation,
malware scanning and safe storage policy; add automated browser-level XSS/CSRF tests; and perform
an authorized Burp Suite / OWASP ZAP assessment before any real deployment. Never expose this demo
bank app to the public internet or use real customer data.

## Frontend refresh (blue glassmorphism banking UI)
The React source in `frontend/src/` now uses a blue-sky / glassmorphism visual system inspired by the supplied Dhanshiri Bank reference: public landing page, split login/register experience, responsive customer workspace sidebar, account panels, transfer form, branch/admin workspace styling, and statement verification screen. Existing API routes and PKI workflows are retained.

After extracting the project, rebuild the production frontend so Flask serves the refreshed UI:
```bash
cd frontend
npm ci
npm run build
cd ..
python app.py
```
The source files are updated in this archive. The prebuilt `frontend/dist` bundle may be older until the build command above completes successfully.
