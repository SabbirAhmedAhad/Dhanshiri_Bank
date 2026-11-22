# 4. AI-driven threat task (guide Section 8)

## 4.1 Analyse

Threat: an attacker uses a cloned voice, a deepfake video call, or an AI-written message that imitates the managing director, a pathologist, or the IT team. Goals: (1) a certificate issued that should not be; (2) a valid certificate revoked during a fake emergency; (3) private key files sent to the caller. The 2026 incident in the guide, where a caller asked an IT officer for "the server certificate files", is the reference case.

### Attack tree

```
X1 Obtain certificate files or revocation by impersonation
├─ X1a Voice call to IT: "urgent, send server.key for the outage"
│     controls bypassed: none technical (the officer trusts the voice)
├─ X1b Email from "MD" with a signed-looking PDF request to revoke a branch client
│     controls bypassed: sender identity only
├─ X1c Video call with fake pathologist asking for an immediate docsign issuance
│     controls bypassed: none technical
└─ X1d Insider uses a real account after being pressured: two-person rule is the control
```

Technical controls the attack gets around: none of the key or certificate controls stop X1a, because the officer can hand over a file that the attacker needs. The controls that remain are the ones that require a second person or a fixed channel: two-person approval in the admin app, the issuance log, and the 0600 key files that stop copying unless someone has server access.

## 4.2 Mitigate

Process controls
- No private key leaves the server by any channel. Keys are never sent by email, chat or phone. The guide's "send the certificate files" request is refused by policy, whoever asks.
- Call-back: any urgent request from a senior person is confirmed by calling a number held in the staff directory, never a number supplied in the request.
- Code word for emergencies agreed in writing by the head of IT and the MD, changed each quarter.
- Two-person approval for revocation, reset and issuance (already in the app for revocation and reset).

Technical controls
- Admin requests need a second officer (`adm_decide` refuses same-person approval).
- Issuance log with alert, so a certificate issued outside policy is seen (X4).
- Keys stored with 0600 permissions and git-ignored (`keys_private_files_mode_0600_and_ignored_by_git`).
- Name constraints on the issuing CA, so even a rogue issuance cannot cover names outside `dhanshiri.test`.

Balance with emergencies: a patient harm case (for example a missed critical result) cannot wait for a second approver if one is away. The emergency path is: the on-duty second approver is named on a rota, reachable by phone, and approval within 1 hour is a target. If no second approver can be reached within 1 hour, the request is held and the head of IT decides, with the decision logged. This keeps speed for real emergencies while still making fake ones hard.

## 4.3 Test

Role-play test, as the guide allows (no fake voice or video of any real person):
- Scenario: a written message as the caller asks "it.officer" to revoke `client-branch-rangpur` now, "the MD is in a meeting, no time to check".
- Expected: the request is opened by it.officer. Approval by it.officer is refused. The revocation list is unchanged. The attempt is visible in the audit trail.
- Automated version: `ai_single_officer_urgent_revocation_refused` (in `7-test-results.md`). Result: PASS.
- Manual part (role-play): a team member plays the caller, another plays the officer, and they follow the call-back rule. Record the outcome in the learning log. Do not record real voices.

## 4.4 Look ahead

As impersonation improves, voice and video are no longer proof of identity. Changes we would make:
1. Remove phone as an approval channel entirely. Approvals happen only inside the admin system, with hardware-backed login (FIDO2 security keys for the two approvers).
2. AI agents that request certificates automatically (for example ACME clients, X1) need their own identity: a short-lived certificate per agent, scoped names, and a rule that an agent can request but never approve.
3. Monitoring for unusual requests: alert when a revocation or issuance happens outside office hours, or when the same officer requests several times.
4. Dual control for key export, where the export itself requires two approvers and is logged.

These changes are in the adaptation plan (file 6 §A).
