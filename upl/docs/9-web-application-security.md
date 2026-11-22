# Web Application Security Testing (local synthetic lab)

This supplement extends the existing PKI test suite. It does not replace the course-required PKI,
certificate, TLS, signing or AI-threat tests. Run only against the team's own isolated lab.

## Automated tests added

| Test | Method | Expected result |
|---|---|---|
| SQL injection – login | Submit `' OR '1'='1' --` as a username | Authentication remains rejected |
| SQL injection – account lookup | Supply an encoded SQL-like account identifier | 404; no account data disclosed |
| CSRF | POST a state-changing endpoint without `X-CSRF` | 400 rejected |
| IDOR | Log in as Rahim and request Karim's account number | 404; no balance or transactions disclosed |
| Role escalation | Customer requests admin certificate endpoint | 403 rejected |
| XSS storage/rendering | Register a synthetic name containing `<script>` | Stored as text; React source must not use `dangerouslySetInnerHTML` |
| Brute-force | Submit six incorrect passwords for the same test identity | Lockout response 429 after the threshold |
| Security headers | Inspect response headers | nosniff, frame denial, CSP and no-referrer present |
| Transaction validation | Try negative, zero, over-limit and non-numeric amounts | 400; no transfer processed |
| HSTS | Enable secure-mode flag and inspect response | HSTS max-age header present |

## Manual frontend checks still required

Use browser DevTools and Burp Suite Community or OWASP ZAP against `localhost` only:

1. Submit harmless SQLi strings in login, registration and search/input fields; confirm no bypass,
   database error, or data disclosure.
2. Enter harmless HTML/script test strings into profile/name/note fields; confirm the browser displays
   text rather than executing it. Check both stored and reflected output.
3. Remove/change the CSRF header in a captured state-changing request; confirm rejection.
4. Change account identifiers in requests while logged in as another synthetic customer; confirm 404/403.
5. Reuse a logged-out session cookie and inspect cookie flags in HTTPS mode.
6. Try a harmless text file with a misleading extension and an oversized file against the upload
   service; confirm it is rejected. Upload validation and malware scanning are not yet implemented.
7. Inspect HSTS, CSP, frame protection and HTTP-to-HTTPS redirect in HTTPS mode.
8. Attempt duplicate transfers and refresh/replay a transfer request; transaction idempotency is not
   yet implemented and must be added before real-money use.

## Limitations / honest reporting

The new pytest cases are source-level local test coverage, not proof of a complete penetration test.
The UI panel is a coverage checklist, not a scanner. Login lockout is currently process-local and
will reset on restart. The demo OTP is printed to the server console. No production banking use,
public deployment, or real customer data is permitted. Re-run the suite in the team's own Python
and Node environment and record actual observed results and evidence before reporting PASS.

## Automated checks (tests/test_web_security.py)
- SQL injection: login payload and account parameter are treated as data (`test_web_sqli_*`).
- Stored XSS: a note with an HTML payload is stored and returned as JSON text, with `nosniff` (`test_web_stored_xss_*`).
- Reflected XSS: a script in the verification URL is never echoed, and the page carries a CSP (`test_web_reflected_xss_*`).
- CSRF: state-changing requests need the session token (`test_web_csrf_*`).
- IDOR: another customer's account is hidden (`test_web_idor_*`).
- Brute force: five wrong passwords trigger a lockout (`test_web_login_rate_limit_*`).
- Session and cookies: HttpOnly and SameSite=Lax (`test_web_session_cookie_*`).
- Malicious upload: path traversal and wrong extensions are refused; a file whose content does not match its name is refused (415) and nothing is stored (`test_web_upload_*`).
- Security headers and HSTS (`test_web_security_headers_*`, `test_web_https_*`).
- Unauthorized transaction: a transfer from another customer's account is refused and changes no balance (`test_web_unauthorized_*`).
- Duplicate transaction: a repeated reference returns 409 and is applied once (`test_web_duplicate_*`).

## Limits, stated plainly
- No antivirus or malware scanning of uploads: only name, extension and file signature are checked.
- The login lockout counter is in process memory; it resets when the server restarts.
- These are local tests against the lab app. They are not an external penetration test.
