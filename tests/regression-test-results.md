# Regression Test Results — BOLA Remediation

**Environment:** Local OWASP crAPI Docker deployment  
**Date:** [fill date/time]  
**Tester:** [your name]  
**Proxy:** Burp Suite Community Edition

## Authorization matrix

| ID | Authenticated user | Requested vehicle owner | Expected | Observed status | Pass/Fail | Evidence file |
|---|---|---|---|---|---|---|
| T1 | Client A | Client A | Allowed (normally 200) | Allowd | Pass | `../evidence/after-patch/02-client-a-own-vehicle.png` |
| T2 | Client A | Client B | Denied (implementation currently expected 404) | Denied | Pass | `../evidence/after-patch/03-client-a-other-vehicle.png` |

## Community response verification

| Check | Expected | Observed | Pass/Fail |
|---|---|---|---|
| Recent posts response | No `vehicleid` field in public author object | No `vehicleid` | Pass |

## Test procedure

1. Authenticate as Client A and capture the request for Vehicle A.
2. In Burp Repeater, request Vehicle A using Client A's token.
3. Keep Client A's token but replace the vehicle UUID with Client B's vehicle UUID.
4. Record status and sanitized response.
5. Repeat the two checks as Client B.
6. Confirm both owner-to-own-vehicle requests remain allowed and both cross-user requests are denied.

## Security handling

Never commit raw JWTs, cookies, passwords, private keys, `.env` files, database dumps, or unredacted personal data. Redact the complete Authorization header in screenshots and text captures.
