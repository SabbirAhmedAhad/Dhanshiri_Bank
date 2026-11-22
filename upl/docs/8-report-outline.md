# 8. Report outline (R16), presentation (R17), innovation statement

The guide's 16 sections, with the file in this folder that holds the content. Team members fill in the blanks and add their names.

| # | Section | Source in this repo | Status |
|---|---|---|---|
| 1 | Introduction and scope | `docs/README.md`, guide §3 | Team to write the prose |
| 2 | Background and the incidents | guide §2 | Team |
| 3 | System description (R1) | `1-system-and-threats.md` §1.1–1.3 | Done (draft) |
| 4 | Assets and stakeholders (R1, R2) | `1-system-and-threats.md` §1.4–1.5 | Done (draft) |
| 5 | Threat model and attack trees (R3) | `1-system-and-threats.md` §1.6–1.7 | Done (draft) |
| 6 | Certificate policy and hierarchy (R4) | `2-policy-and-controls.md` §A | Done (draft) |
| 7 | TLS and the old branch PC (R5) | `2-policy-and-controls.md` §B | Done (draft); external scan missing |
| 8 | Client certificates for branches (R6) | `2-policy-and-controls.md` §C | Done (draft) |
| 9 | Revocation, renewal, failure policy (R7) | `2-policy-and-controls.md` §D | Done (draft) |
| 10 | Report signing and verification (R8) | `2-policy-and-controls.md` §E | Done (draft); test with a non-technical tester still to do |
| 11 | Key management (R9) | `2-policy-and-controls.md` §F | Done (draft) |
| 12 | Standards and trade-offs (R10, R11) | `3-justification.md` | Done (draft) |
| 13 | Implementation and testing (R12) | `7-test-results.md`, `tests/`, demonstration video | Tests done; video to record |
| 14 | AI-driven threat (R13) | `4-ai-threat.md` | Done; manual role-play to run |
| 15 | Legal and ethical analysis (R14, R15) | `5-legal-and-ethics.md` | Draft; legal check [verify] items to complete |
| 16 | Adaptation plan, learning log, conclusion (R18) | `6-adaptation-and-log.md` | Done; team entries to add |

Also in the report: an innovation statement (one page). Suggested content: the combination of a zone-limited issuing CA, a hash-chained issuance log with alerts (X4), and a verifier that fails closed on revocation, all tested with a suite that runs in one command and needs no outside service.

Also in the report: an honest "what is not done" list (file 6 §E).

## 4. Presentation (R17)

Every member presents a part. Suggested split for a group of 4 (adjust to group size):
1. Problem and stakeholders, in plain words (who is affected and why a forged report matters).
2. The trust chain: root, issuing CA, and what each certificate is for (non-technical analogy: an ID card issued by an office that is itself vouched for).
3. What we protected and how we tested it (live: one genuine report verifies, one edited report fails, one revoked signer is flagged).
4. Hard decisions: the old branch PC, fail-closed revocation, the Eid case.
5. Legal, ethics and what we would change next (adaptation plan).

A non-technical listener should leave knowing: what was protected, from whom, and why the system refuses when it is unsure.

Viva preparation: prepare short answers for "why not one certificate per pathologist", "why fail closed", "what happens if the CRL server is down", "why RSA for the timestamp", and "how do you know your tests prove anything".
