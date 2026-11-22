# 3. Standards comparison and trade-offs (R10, R11)

## A. Standards comparison (R10)

| Standard or guide | What it requires | Our design | Conformance |
|---|---|---|---|
| RFC 5280 (X.509 profile) | Path validation, basicConstraints critical on CAs, keyUsage, EKU, CRL distribution points, AKI/SKI | All required extensions set; CA basicConstraints critical; CRL DP and AIA set in leaves | Conforms |
| RFC 8446 (TLS 1.3) | Preferred protocol; no downgrade to unsafe modes | TLS 1.3 accepted, preferred by default | Conforms |
| RFC 5246 (TLS 1.2) and RFC 9325 (TLS best practice, 2022) | Only AEAD suites with ephemeral keys; no compression; no SSL 3 or TLS 1.0 and 1.1 | ECDHE+AESGCM and ECDHE+CHACHA20 only; no compression; TLS 1.2 minimum | Conforms |
| NIST SP 800-52 Rev. 2 | Server TLS guidance: TLS 1.2 or higher, approved suites, certificate types | TLS 1.2 floor; approved suites; P-256 | Conforms |
| NIST SP 800-57 Part 1 Rev. 5 | Key lifetimes; separate keys for separate purposes; cryptoperiods | Separate keys for CA, TLS, signing, OCSP, TSA; cryptoperiods in file 2 §F | Partly: no formal key-management plan beyond the table; signing and TLS keys share one host |
| CA/Browser Forum Baseline Requirements | Public TLS certificates: max 398 days; name validation; revocation | Server 90 days, branch 365 days (within 398); docsign 730 days (outside the 398 limit, which applies to public TLS only) | Gap, justified: the BR applies to public CAs; our CA is private. Recorded in §B |
| OWASP Transport Layer Security Cheat Sheet | Enforce TLS 1.2+, HSTS, HTTP redirect, strong suites | All implemented | Conforms |
| RFC 6960 (OCSP), RFC 5280 CRL | Revocation information with validity window | OCSP and CRL with next-update times | Conforms; OCSP stapling not done (X6) |
| RFC 3161 (timestamps) | Trusted timestamp for signatures | Lab timestamper is local and dummy | Gap: lab only. Real use needs a real TSA |
| ETSI EN 319 142 (PAdES) | Signed PDF profile and verification | pyHanko PAdES-style signature | Partly: long-term validation (LTV) not implemented |
| ICT Act 2006 and Certifying Authority Rules (Bangladesh) | Licensed CA for legal effect of digital signatures | Private CA, no licence | Gap: legal analysis in file 5 §A-3 |

Gaps and conflicts resolved:
1. RFC 9325 and TLS 1.2 vs the old branch PC. Resolved by blocking the PC (file 2 §B), not by enabling weaker TLS. Reason: the security cost falls on every branch.
2. CA/B BR 398-day limit vs 730-day signing certificate. Resolved as a documented deviation: the BR applies to public TLS certificates, and the signing certificate is a private-CA certificate. A shorter lifetime (365 days) would cost one more renewal per two years; we chose 730 with a 30-day warning.
3. OCSP availability vs fail-closed verification. Resolved by fail-closed report verification with a CRL cache (file 2 §D.4), because the CA/B BR and RFC 5280 do not say what a relying party must do when status is unknown; the choice is ours and is justified by impact.
4. SP 800-57 separation of keys vs one host for signing and TLS. Resolved as a risk accepted for the lab; production would move the docsign key to a TPM or HSM (file 6).

## B. Trade-offs (R11)

Each trade-off has the alternatives, the choice, the reasons, the remaining risk and the linked test.

### T-1 Legacy TLS for the old branch PC
- Alternatives: (a) keep TLS 1.0 on a separate listener; (b) upgrade the PC early; (c) block the PC and use a supported PC for its uploads.
- Choice: (c).
- Reasons: (a) exposes every branch to downgrade (T07, T08) for one device. (b) is not possible before next year. (c) costs about a day of delay on one branch.
- Remaining risk: paper handling for that branch; delay and transcription errors.
- Test: `downgrade_tls11_refused`.

### T-2 Certificate lifetime vs renewal workload
- Alternatives: 30-day, 90-day, 365-day or 2-year server certificates.
- Choice: 90 days for TLS servers, 365 days for branch clients, 730 days for docsign.
- Reasons: short TLS lifetimes limit the damage from a stolen key, but renewals have a cost for two officers with no PKI experience. 90 days with an automated renewal (X1) would be ideal, but X1 is not done, so renewal is manual, with a warning 30 days before expiry.
- Remaining risk: a missed renewal takes the portal down (as happened in 2025).
- Test: `expiry_warning_raised_for_cert_near_expiry`.

### T-3 Fail-open vs fail-closed revocation for report verification
- Alternatives: fail-open (accept when CRL unreachable), fail-closed (refuse).
- Choice: fail-closed.
- Reasons: a forged report has legal and financial consequences; a report refused during an outage can be re-checked later.
- Remaining risk: availability; a CRL outage stops verifications. Mitigation: CRL mirror and 2-day cache (not built yet).
- Test: `revocation_unreachable_crl_fails_closed`.

### T-4 TLS-level refusal vs app-level logging for branch certificates
- Alternatives: (a) CERT_REQUIRED (TLS refuses missing certificates; nothing logged in the app); (b) CERT_OPTIONAL and let the app check and log.
- Choice: (b) for presence, with TLS still refusing bad chains.
- Reasons: R6 says refusals must be logged. (b) logs missing and revoked cases in the database.
- Remaining risk: certificates that fail chain validation are refused silently by TLS; they appear only in the server log, not in the `refused` table. The guide's "logged" requirement is met for four of the five cases; the untrusted-CA and wrong-type cases are logged to the server's error output only. Fix: a TLS-level logging hook (learning log).
- Tests: `upload_missing_client_cert_refused_and_logged`, `revocation_revoked_branch_cert_refused_and_logged`, `chain_upload_untrusted_client_cert_refused`.

### T-5 Private CA vs licensed CA for signatures
- Alternatives: (a) private CA (free, fast, full control); (b) licensed CA from the Bangladesh CCA-licensed certifying authority (legal weight, cost, slower).
- Choice: (a) for internal and lab use; (b) is the production recommendation for reports used in legal or employment decisions.
- Reasons: the budget is small and the lab does not need legal effect. A licensed CA is needed if reports must hold up as legal evidence (file 5 §A-3).
- Remaining risk: a court may not accept the private signature without expert evidence.
- Test: `signing_genuine_report_verifies` (validates the chain to the lab root, which is the same mechanism).

## C. Extension chosen

Groups of 3 must do one extension. We chose X4: an append-only, hash-chained issuance log with alerts for out-of-policy certificates. It is in `policy.py`, `make_certs.py` and `check_issuance.py`, and it is covered by `issuance_out_of_policy_cert_is_flagged`, `issuance_unlogged_cert_raises_alert` and `issuance_log_tamper_detected`. The "out-of-policy" alert appears in the demonstration.
