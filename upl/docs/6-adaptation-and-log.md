# 6. Adaptation plan, learning log, interaction matrix and resources (R18, A6, A8)

## A. Adaptation plan (R18: at least three changes)

| Change | Trigger | Concrete design change |
|---|---|---|
| 1. Post-quantum migration | NIST or the regulator names a deadline for post-quantum signatures; or the X3 test shows the hybrid key exchange is available in our TLS library | Step 1: enable hybrid X25519+ML-KEM key exchange on the portal (X3). Step 2: move the CA and docsign to ML-DSA (FIPS 204) when libraries and verifiers support it; run dual signatures (classical and PQ) for two years. Step 3: retire RSA and ECDSA-only chains. Inventory of current crypto is in §C. |
| 2. Shorter certificate lifetimes | A public CA or browser policy cuts maximum lifetime again; or a renewal fails in production | Server certificates move to 30 days, renewed automatically with ACME (X1). Branch client certificates move to 90 days, with renewal from the branch PC. Docsign stays at 1 to 2 years for the signing life, with a separate timestamp (already planned). |
| 3. AI impersonation becomes cheaper | A second attempt in the test or real life gets past call-back; or a voice-cloning incident reaches the news | Remove phone as an approval channel. Admin approvals need FIDO2 hardware keys for both approvers. Agents that request certificates get their own identities and cannot approve (file 4 §4.4). |
| 4. Legal change | The Personal Data Protection law is enacted, or the cyber law changes the breach-notice period | Update the retention rule for logs with patient identifiers to the new period; add the notification step to the compromise procedure; re-run the legal review (file 5). |
| 5. TPM or HSM for keys | Budget approved, or a server audit fails on key storage | Move the issuing key and docsign key into a TPM or USB token (X2). Keys become non-exportable. Keep the same policy, change only the storage. |

## B. Learning log

Format: date, what happened, what we learned, what we changed. Team members add their own entries; the entries below record the build session.

| Date | What happened | What we learned | What changed |
|---|---|---|---|
| 2026-11-22 | Read the code against the guide. Found the verify endpoint failed open (`except: sig_ok = True`). | A check that fails must refuse, not pass. Reading error handlers finds these. | Verify now returns 503 and does not say "genuine" if revocation state cannot be read. |
| 2026-11-22 | Believed the branch mTLS code could not read the client certificate (`SSL_CLIENT_CERT`). | Checking the library source (Werkzeug 3.1.9) showed it sets the header. The belief was wrong. | No change. Recorded the false alarm here so it is not repeated in the report. |
| 2026-11-22 | `requests` with a client certificate and a name check failed, though the same chain verified with ssl and with urllib3. | Test tools can hide the real cause. Probe at the lowest level first. | Test client changed to urllib3 with the name check passed in. |
| 2026-11-22 | Verifier accepted a revoked signer when the CRL was missing. | A verifier needs a revocation source of its own. Fail-closed is the safe default for reports. | `verify_statement.py` checks the CRL signature and next-update time; unreachable means not accepted. |
| 2026-11-22 | Test runs were writing into the real `certs/` and `lab.db`. | Test isolation is part of the design. | `config.py` reads environment variables; each run uses a temporary folder. |
| 2026-11-22 | Missing-cert uploads were refused at TLS and not logged. | Where a check happens decides whether it is logged. | Listener uses `CERT_OPTIONAL`; app logs missing certificates (trade-off T-4). |
| 2026-11-22 | Public verify page showed the closing balance to anyone with a code. | Minimise what a public check returns; the verifier needs only enough to match the report in hand. | Endpoint, `statements` table and UI changed; frontend rebuilt; test added. |
| 2026-11-22 | Not yet done: a TLS-level logging hook; an external TLS scan; X6 OCSP stapling. | — | Listed for the next iteration. |

Team entries (to be added by each member): what each person did, what they found hard, one thing they would do differently.

## C. Interaction matrix (A6)

| From \ To | Patient browser | Branch PC | Portal | Upload API | CA (issuing) | Revocation (CRL/OCSP) | Verifier | Admin officers |
|---|---|---|---|---|---|---|---|---|
| Patient browser | — | — | HTTPS, portal cert, login with OTP | — | — | — | — | — |
| Branch PC | — | — | — | mTLS, branch cert, chunked upload | — | — | — | — |
| Portal | — | — | — | — | Uses issued server cert | — | Serves `/verify` | — |
| Upload API | — | — | — | — | Uses issued server cert | Checks `revoked.json` each request | — | Writes upload records |
| Issuing CA | — | — | — | — | — | Signs CRL and OCSP responses | — | Approval via admin system (two people) |
| Revocation endpoint | — | — | — | — | — | — | Verifier fetches CRL | Source is revocation approvals |
| Verifier | — | — | HTTPS to `/verify` | — | Trusts root certificate | Fetches CRL | — | — |
| Admin officers | — | — | HTTPS, OTP login | — | Request issuance and revocation | — | — | Second officer approves |

Each cell names the protocol and the credential used. Where a cell is empty, there is no direct flow.

## D. Resources register (A8)

| Resource | Type | Licence (verify in package) | Used for | Notes |
|---|---|---|---|---|
| Python 3.12 | Language | PSF licence | All server code | |
| Flask 3.x, Werkzeug 3.x, itsdangerous | Web framework | BSD-3 | Portal and API | Werkzeug dev server used for lab only; production needs a real WSGI server |
| cryptography | Crypto library | Apache-2.0 or BSD-3 | Certificates, OCSP, CRL, field encryption | |
| pyHanko, pyhanko-certvalidator | PDF signing and validation | MIT | Statement signing, verification | Lab timestamper is local |
| reportlab | PDF generation | BSD | Statement PDFs | |
| urllib3 | HTTP client | MIT | Tests | |
| pytest | Test runner | MIT | Test suite | |
| OpenSSL 3.0 | TLS library and CLI | Apache-2.0 | Probes, Python ssl | |
| React 18, Vite 5 | Frontend | MIT | Portal UI | Built into `frontend/dist` |
| Claude (Anthropic) | AI assistant | Provider terms | Drafting code and documents | Team reviewed all output. No keys or secrets were given to the assistant. Disclosed in the report. |

## E. Open issues (for the report's limitations section)

1. Resolved: `/api/verify` no longer returns the closing balance. It returns genuine, last four digits and issue date only. The frontend was changed and rebuilt; test `signing_verify_page_does_not_disclose_balance`.
2. The lab does not run a full external TLS scan. Add testssl.sh output to evidence.
3. TLS-level refusals of bad client certificates are not in the `refused` table (trade-off T-4).
4. The root CA key is discarded in the lab, so the offline root process is described, not shown.
5. No OCSP stapling (X6), no automated renewal (X1), no TPM (X2), no SSH certificates (X5).

## Review pass (full project audit)
| Finding | Fix | Test |
|---|---|---|
| Same mobile number or National ID could open many customers, each with BDT 10,000 | Phone and NID (hashed) checked at registration; 409 on repeat | `test_web_one_mobile_number_cannot_open_two_customers`, `test_web_one_national_id_cannot_open_two_customers` |
| Login without a prior /api/me left the CSRF token empty and caused a server error | Fresh token generated when none exists | `test_web_login_without_prior_session_gets_a_real_csrf_token` |
| Unknown /api paths returned the web page | Unknown /api paths return JSON 404 | `test_web_unknown_api_path_returns_json_404` |
| Session key and field-encryption key were world-readable on Linux | Owner-only permissions via `protect_key()` | `test_web_session_key_file_is_owner_only` |
| Upload size is not capped in total (each chunk is capped at 2 MB, but there is no total limit) | Not fixed yet; listed as a limit | none |
| Failed-login counters are kept in memory and never pruned | Not fixed yet; memory grows slowly with many unique usernames | none |
