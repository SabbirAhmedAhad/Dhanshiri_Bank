# 2. Certificate policy and controls (R4–R9)

## A. Certificate policy (R4)

### A.1 Scope and hierarchy
This policy applies to every certificate issued by the Dhanshiri lab CA. The hierarchy is a two-tier PKI:

- Root CA, `Dhanshiri Root CA`: ECDSA P-384, SHA-384, valid 15 years. Its key signs the issuing CA and is then discarded in the lab. In production it would be offline, on hardware, with a two-person ceremony.
- Issuing CA, `Dhanshiri Issuing CA`: ECDSA P-256, SHA-384, valid 5 years, path length 0, name constraint `dhanshiri.test`. Online, but only signs leaf certificates.

### A.2 Certificate types

| Type | Used by | Key | Validity | Key usage | Extended key usage | Approval |
|---|---|---|---|---|---|---|
| Server (TLS) | portal and upload service | ECDSA P-256 | 90 days | digitalSignature | serverAuth | IT officer requests; second IT officer approves |
| Branch client (mTLS) | each branch device | ECDSA P-256 | 365 days | digitalSignature | clientAuth | Branch manager request; IT approves |
| Document signing | statement and report PDFs | ECDSA P-256 | 730 days | digitalSignature, contentCommitment | document signing (1.3.6.1.5.5.7.3.36) | Head of IT approves |
| OCSP responder | revocation responder | ECDSA P-256 | 365 days | digitalSignature | OCSPSigning, OCSPNoCheck | Head of IT |
| Timestamp authority | PDF timestamps | RSA-2048 | 1095 days | digitalSignature | timeStamping (critical) | Head of IT |

Deviation: the timestamp authority uses RSA-2048 because the pyHanko local timestamper needs an RSA key. The reason is recorded in file 3 §B.

### A.3 Algorithms and key sizes
- Signatures: ECDSA P-256 with SHA-256 for leaves; SHA-384 for CA certificates. Meets NIST SP 800-57 and SP 800-52 Rev. 2 expectations for 2026.
- No RSA below 2048; no SHA-1; no MD5.
- Key exchange: ECDHE only (ephemeral).

### A.4 Names
Every certificate name must end in `dhanshiri.test`. The issuing CA's name constraint enforces this. `policy.py` also raises an alert if a logged certificate breaks the rule or its validity.

### A.5 Issuance approval
A certificate is issued only by the CA process, which records it in the hash-chained issuance log. `check_issuance.py` alerts if a certificate exists without an entry, or if an entry breaks policy. In the lab, `make_certs.py` performs the issuance. In production, an officer requests and a second officer approves before the CA signs.

### A.6 Who may do what
Revocation and password reset need two different officers (the app enforces this). Customers and branch users cannot open admin requests.

## B. TLS policy and the old branch PC (R5)

- Minimum TLS 1.2; TLS 1.3 preferred. TLS 1.0 and 1.1 are refused.
- TLS 1.2 suites: ECDHE with AES-GCM or ChaCha20-Poly1305 only. No CBC, no RSA key exchange, no static DH.
- No TLS compression. HSTS with `max-age=31536000` on the HTTPS portal. HTTP on port 8080 redirects to HTTPS.
- Full chain served (`fullchain.crt`: leaf plus issuing CA). Clients trust the root.

Checks: the downgrade tests in `7-test-results.md` show that the server answers TLS 1.1 with a protocol-version alert, refuses `AES128-SHA`, and accepts ECDHE+AES-GCM over TLS 1.2. A manual probe also showed TLS 1.3 accepted; that probe is not in the suite yet. We did not run a full external scan (for example testssl.sh). Adding one is in the learning log.

Decision on the old branch PC (cannot upgrade until next year): it is blocked from the upload service. It does not get a legacy TLS listener. Until the new PC arrives, that branch sends paper forms to the head office for entry on a supported PC, using `branch_client.py` from there. The cost is a day of delay on that branch. The alternative (a TLS 1.0 listener for one PC) would expose every branch to the downgrade threats T07 and T08. See file 3 §B.

## C. Branch client certificates (R6)

Each branch device has its own certificate (`client-branch-<place>`). The upload service asks for a certificate, and the app checks: presence, expiry, revocation, and EKU clientAuth. The five refusal tests are:
1. missing certificate: refused by app, logged in `refused` (`upload_missing_client_cert_refused_and_logged`)
2. untrusted CA: refused at TLS, nothing stored (`chain_upload_untrusted_client_cert_refused`)
3. expired: refused at TLS, nothing stored (`expiry_expired_client_cert_refused`)
4. revoked: refused by app, logged (`revocation_revoked_branch_cert_refused_and_logged`)
5. wrong type (server certificate): refused at TLS, nothing stored (`issuance_wrong_type_server_cert_refused_as_branch_client`)

Design note: the listener uses `CERT_OPTIONAL` so that a missing certificate reaches the app and is logged. A certificate that fails chain validation is refused by the TLS layer before app code runs, so that refusal is not in the `refused` table. It appears only in the server's error output. This trade-off is in file 3 §B.

## D. Revocation, renewal, expiry and failure policy (R7)

### D.1 Mechanisms
- CRL: `http://crl.dhanshiri.test:2560/crl/issuing.crl`, signed by the issuing CA, next-update 2 days. Generated from `revoked.json`.
- OCSP: `http://ocsp.dhanshiri.test:2560`, next-update 1 day, responder certificate has OCSPNoCheck.
- The upload service checks `revoked.json` on every request, so its revocation effect is immediate.

### D.2 Revocation procedure
1. Requester (officer A) opens a revoke request naming the certificate.
2. Approver (officer B, different person) approves in the admin page. The certificate serial is added to `revoked.json`, and an audit entry is written.
3. The upload service refuses the certificate on its next request (seconds). Relying parties that use CRLs see it at the next CRL fetch (up to 2 days). The test `revocation_revoked_branch_cert_refused_and_logged` covers the first case.
4. Reissue a replacement certificate through the issuance process and notify the branch.

### D.3 Renewal procedure
- Admin page lists all certificates with days remaining. Certificates with under 30 days show a warning (`expiry_warning_raised_for_cert_near_expiry`).
- Renew 30 days before expiry: issue a new key and certificate, deploy, then revoke or let the old one lapse. Never reuse the key pair.

### D.4 Fail-open or fail-closed
- Report verification (`verify_statement.py` and `/api/verify`) is fail-closed. If the CRL cannot be fetched, or its signature or next-update time is wrong, the report is not accepted. Test: `revocation_unreachable_crl_fails_closed`.
- Branch upload is effectively fail-closed, because the check is local (`revoked.json`) and does not depend on a network.
- Justification: a forged medical or employment report has high impact; a valid report refused during an outage can be re-verified later. The cost is availability. The mitigation is a CRL mirror and the 2-day cache.

### D.5 Expiry warnings
The admin page warns at 30 days. Production would also send email to the IT officers at 30, 14 and 7 days.

## E. Report signing and verification (R8)

Signing: each report PDF is signed with the `docsign` certificate using pyHanko (PAdES-style, field `DhanshiriSig`). The signature covers the full byte range, so an edit after signing breaks it. The signature includes a timestamp from the lab TSA (DummyTimeStamper in the lab, which is not a real RFC 3161 service; production would use a public or licensed TSA).

Decision on signer: one organisation-level signing certificate, not one per pathologist. Reason: fewer keys to protect and renew, and revocation is simpler. The cost is that one revocation affects all signed reports. Per-person certificates are the adaptation option (file 6).

### Verification steps for a referring doctor or employer (no technical knowledge needed)
1. Open the PDF in Adobe Reader or another PDF viewer. Do not open it in a web browser preview, because previews do not check signatures.
2. Find the signature panel (a blue banner or a "Signatures" pane). It should name "Dhanshiri Statement Signing" and say the signature is valid and the document has not changed.
3. If the viewer says the signature is invalid, or that the document was modified after signing, stop. Do not accept the report.
4. Scan the QR code on the report. The page must be on the lab's own domain. It should say "genuine" and show the last four digits and issue date that match the report. It shows no balance or other details: if it shows more than that, stop and report it.
5. If the QR code cannot be used, call the lab on the number you already hold in your files, not a number printed on the report.
6. Record the check (name, date, time, result) in your file.

If the verifier has the lab root certificate installed, step 2 shows "valid". Without it, the viewer shows "signature valid, but signer not trusted", which means the verifier must install `root.crt` first. The lab provides it on the verification page.

## F. Key management (R9)

| Key | Created by | Stored | Backed up | Rotated | Replaced after compromise |
|---|---|---|---|---|---|
| Root CA | make_certs (lab) / ceremony (real) | discarded in lab; offline HSM in production | sealed copy, two custodians | 15 years | new root; all leaves reissued; distribution of new root |
| Issuing CA | make_certs / ceremony | `certs/issuing.key`, 0600; TPM target | encrypted copy, two custodians | 5 years | new issuing CA under root; revoke all leaves from old CA |
| Docsign | make_certs | `certs/docsign.key`, 0600, server only | encrypted, offline | 2 years | revoke serial, reissue, re-verify recent reports |
| Server TLS | make_certs | `certs/server.key`, 0600 | not backed up (reissue instead) | 90 days | revoke, reissue, restart service |
| Branch client | make_certs per branch | device store, 0600 | not backed up | 365 days | revoke, reissue, redeploy |
| OCSP and TSA | make_certs | 0600 | encrypted | 1 and 3 years | revoke and reissue |
| `.secret`, `.fkey` | app first run | server only | encrypted, offline | never without re-encryption | re-encrypt data with new key |

No private key appears in a repository (git-ignored, and a test checks it), in chat, or in an AI tool. Keys are never pasted into tickets or email.

### Compromise steps (for a suspected key theft)
1. Within 1 hour: freeze signing with that key (take the service down or switch the signer). Open a revocation request, and have a second officer approve it.
2. Same day: reissue a replacement and deploy. Notify the head of IT, the management, and the regulator if the law requires (file 5 §A).
3. Within 24 hours: list every report signed in the exposure window, mark them for re-verification, and tell referring doctors and employers which report IDs to re-check.
4. Within 7 days: complete an incident report and update the risk register.

The Eid case in file 5 §B shows how this runs when the timing is hard.
