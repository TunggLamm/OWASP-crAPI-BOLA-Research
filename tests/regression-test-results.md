# Regression Test Results — BOLA Remediation

- **Environment:** Local OWASP crAPI Docker deployment
- **Date:** November 2026
- **Tester:** Khieu Tung Lam
- **Proxy:** Burp Suite Community Edition

## 1. Authorization Test Cases (Identity Service)

| ID | Authenticated User | Target Vehicle | Request Path | Expected | Observed Status | Result | Evidence |
|---|---|---|---|---|---|---|---|
| **TC1** | Client A (`clientA@example.com`) | Client A's vehicle | `GET /identity/api/v2/vehicle/1d65151b-a248-4713-ae07-1c481f309d77/location` | Allowed (`200 OK`) | `200 OK` | **Pass** | [`../evidence/after-patch/02-client-a-own-vehicle.png`](../evidence/after-patch/02-client-a-own-vehicle.png) |
| **TC2** | Client A (`clientA@example.com`) | Client B's vehicle | `GET /identity/api/v2/vehicle/323e8a0f-95cb-448b-a234-9c58c101a9cc/location` | Denied (`404 Not Found`) | `404 Not Found` | **Pass** | [`../evidence/after-patch/03-client-a-other-vehicle.png`](../evidence/after-patch/03-client-a-other-vehicle.png) |

## 2. Data Minimization Check (Community Service)

| Check | Endpoint | Expected | Observed | Result | Evidence |
|---|---|---|---|---|---|
| Recent posts response | `GET /community/api/v2/community/posts/recent` | `vehicleid` and `email` omitted from public `author` object | Only `nickname`, `profile_pic_url`, and `created_at` returned (`200 OK`) | **Pass** | [`../evidence/after-patch/04-community-no-vehicleid.png`](../evidence/after-patch/04-community-no-vehicleid.png) |

## 3. Test Procedure

1. Authenticate as **Client A** and capture the JWT token.
2. **TC1 (Authorized):** In Burp Repeater, request Client A's own vehicle (`1d65151b-a248-4713-ae07-1c481f309d77`) using Client A's token and verify `200 OK` with vehicle location details.
3. **TC2 (Unauthorized / BOLA attempt):** Keep Client A's token, replace the UUID with Client B's vehicle (`323e8a0f-95cb-448b-a234-9c58c101a9cc`), and verify the server blocks access with `404 Not Found`.
4. **Community Check:** Request `/community/api/v2/community/posts/recent` and verify that `vehicleid` and `email` are no longer leaked in post author metadata.
