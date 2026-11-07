# Before-patch evidence — pending

Add evidence only after reconstructing the original vulnerable build and reproducing the behavior again.

Required captures:

1. Community recent-posts response showing the other test user's vehicle identifier.
2. Burp Repeater request using Client A's authenticated session and Client B's vehicle UUID.
3. Matching response showing Client B's vehicle location/owner data.

Redact JWTs, cookies and credentials. Do not create or alter screenshots to make them look like earlier captures. Record the actual date of reconstruction in the report.
