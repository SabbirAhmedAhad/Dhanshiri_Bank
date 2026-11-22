# 5. Legal and ethical analysis (guide Sections 9 and 10)

Important: the laws below were checked against what we know as of this writing. Before submission, check the current title and text of each law on the Laws of Bangladesh portal (bdlaws.minlaw.gov.bd) and the Office of the Controller of Certifying Authorities website. Several laws changed in 2025–2026. Items marked [verify] need that check.

## A. Legal analysis (R14)

### A-1 Cyber offences (LW1)
- Which attacker actions in the threat model are offences? Stealing a private key, forging a statement, impersonating an officer to obtain a revocation, and tampering with the issuance log would all be offences under the cyber-security law in force [verify: the Digital Security Act 2018 and any 2025 replacement ordinance; check the current title and offence sections]. The ICT Act 2006 (as amended) also covers unauthorised access and forgery of electronic records [verify section numbers].
- What makes our testing lawful? Testing is limited to our own lab: our own certificates, our own data, our own machines, `.test` names that resolve only to localhost, and synthetic data. Authorisation statement: "All tests were run by the project team, against the project's own lab on the team's own machines. No third-party system, network or person was tested. No real patient data was used."
- What must Dhrubotara keep and report after a key compromise? The duty to report depends on the law in force [verify]. Practically: keep the issuance and revocation logs, the audit trail, and the incident record for the period set by the data-protection and cyber law; notify the CCA or the CERT authority if the law names it [verify].

### A-2 Data protection (LW2)
- Are lab results sensitive personal data? Yes in the ordinary sense: health information. Bangladesh's Personal Data Protection law was a draft at our last check [verify status]. Under the draft and under good practice, health data needs a higher level of security and limited access.
- Security duties: encryption at rest (the app uses Fernet for NID and uploads), access control (role checks), logging (audit and refusal logs), and minimisation (the public verification page shows the minimum; see file 6 §E for the open issue).
- What does a breach require? Notification to the regulator and affected people within the period the law sets [verify]. The incident process in file 2 §F is the basis.
- How long may logs with patient identifiers be kept? Keep only as long as needed for security and legal duties; for the lab, we propose 1 year for refusal logs and the period set by the medical records rule for report records [verify].
- NID Act: the National Identity Registration Act 2010 governs NID use [verify]. Storing NID numbers needs a purpose and encryption; we store them encrypted and masked.
- GDPR and US HIPAA (LW2): if the lab serves EU or US patients, GDPR Article 32 (security of processing) and the HIPAA Security Rule (45 CFR 164.312, technical safeguards: access control, audit controls, integrity, transmission security) would apply. Our design covers those safeguards in outline. The same design would be judged adequate under HIPAA for the technical rules, but HIPAA also needs risk analysis and policies, which this report begins.

### A-3 Digital signatures (LW3)
- Does a signature from Dhrubotara's private CA have legal effect? The ICT Act 2006 (as amended) recognises electronic signatures and records, but the reliability of a signature depends on the certifying authority. A signature from an unlicensed CA may still be evidence, but it does not get the presumption a licensed CA signature gets [verify section and rule numbers under the Certifying Authority Rules].
- When would Dhrubotara need a licensed CA? When reports are used as legal evidence or for decisions where the recipient must rely on the signature without proof (for example visa or job medical checks, if the authority requires a licensed signature). The cost and time of a licence are the trade-off (file 3 §B, T-5).
- CCA guidelines: follow them for key length, storage and audit even for a private CA. We do.

### A-4 Telecoms and lawful access
- Does any rule limit encryption or require lawful access? The Telecommunications Act 2001 (as amended) and the ICT Act give authorities powers to request data and to order blocking. Some provisions have been read to require lawful access on request [verify current text]. No rule we know requires a general encryption backdoor.
- How should Dhrubotara answer a lawful request? Check the request is in writing and from an authority with a legal power to ask. Provide only the data the request names. Keep a record of the request and the response. Do not weaken TLS or give out private keys; a court order can compel data, not keys (the design keeps keys server-side for this reason). Consult a lawyer for each case.

### A-5 Software licences and ownership (LW3)
- The tools: Python (PSF licence), Flask (BSD-3), Werkzeug (BSD-3), cryptography (Apache-2.0 or BSD-3), pyHanko (MIT), reportlab (BSD), React (MIT), Vite (MIT), pytest (MIT), urllib3 (MIT), OpenSSL (Apache-2.0). Permissive licences allow our use, but we must keep their notices if we redistribute. [verify each licence file in the installed packages]
- Our own code: no licence chosen yet. Choose one (for example MIT or Apache-2.0) before publishing. Copyright Act 2023 gives authorship to the people who wrote the code; team members should agree who owns what, and record it.
- AI-generated code: the team must review and understand all code, and state in the report which parts were drafted with AI assistance. Ownership of AI output is a matter for the AI provider's terms and the copyright law [verify].

### A-6 Copyright
- Copyright Act 2023 applies to our report text, diagrams and code. We cite standards by name and number and do not copy their text.

## B. Ethical analysis (R15, Section 10)

Chosen dilemma: key compromise on the eve of Eid.

### B-1 Scenario
A pathologist's signing key may have been copied. Revoking it now stops forged reports but delays emergency reports for days, because the reports cannot be signed until a new key is issued. Waiting risks forged reports being accepted by doctors and employers. Should doctors and employers also be told to re-check recent reports?

### B-2 Two duties in conflict
- Duty to prevent harm to patients and third parties who rely on reports: revoke now, so no further forged report is accepted.
- Duty to treat patients who need emergency reports: keep signing, so care is not delayed.

These are both defensible. Neither can be dropped.

### B-3 Professional code
ACM Code of Ethics and Professional Conduct (2018):
- 1.2 Avoid harm: consider harm to patients, employers and the public from a forged report and from a delayed one.
- 1.3 Be honest and trustworthy: tell doctors and employers what happened and what to re-check.
- 1.4 Be fair and take action not to discriminate: emergency patients must not be left behind because a process is slow.
- 1.6 Respect privacy: notify only the people who need to know which report IDs to re-check.
- 2.9 Design and implement systems that are robustly and usably secure: the design must make revocation fast and the emergency path safe.

### B-4 Framework: the Markkula Center's six lenses
- Rights: patients' right to accurate reports; the right of the public not to be deceived by forged documents.
- Justice: fair access to emergency care; fair distribution of the cost of re-checking.
- Utilitarian: the total harm from delayed reports against the total harm from forged reports.
- Common good: trust in lab reports as a shared public good.
- Virtue: honesty to doctors and employers about the uncertainty.
- Care: attention to the patient waiting for a result and the pathologist under pressure.

### B-5 Opposing view
Some argue that re-checking all recent reports is disproportionate, because most reports are genuine, and that the risk is low if the key was only copied and not used. This view has force: it protects the emergency path. The reply is that a forged report with a stolen key is hard to spot, and the cost of a false "genuine" is high for employers and visa decisions.

### B-6 Decision
1. Revoke the key at once (two-person approval, but the approval is expedited to 1 hour).
2. Issue an emergency replacement key within the same day under the compromise procedure in file 2 §F.
3. Keep the lab open for emergency reports. Each emergency report issued during the gap carries a visible note: "Issued under emergency procedure; verify at /verify/<code>".
4. Tell referring doctors and employers which report IDs were signed by the old key in the exposure window and ask them to re-verify, without giving details beyond what is needed (principle 1.6).
5. Re-check the reports signed in the window within 24 hours, and re-issue any that are wrong.

### B-7 Safeguards
- Two-person rule is kept, with an emergency rota so the second person can be reached within the hour.
- Every emergency report is marked and logged.
- The re-check list is limited to report IDs and dates, not patient names, in the message to doctors.
- A review in 30 days looks at whether the emergency path was used correctly.

### B-8 Change to the design
The compromise case shows that a report needs to say which key signed it and when, and that the verifier needs to know whether a report is inside an emergency window. We add: an "emergency" flag in the signed metadata, and a re-check list generated from the signature timestamp range (adaptation plan, file 6 §A).
