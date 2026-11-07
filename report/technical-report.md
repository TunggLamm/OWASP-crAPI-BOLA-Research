# Broken Object Level Authorization in OWASP crAPI
## Vulnerability Research, Source-Code Analysis and Remediation

**Researcher:** Khieu Tung Lam
**Date:** November 2026  
**Application:** OWASP crAPI, locally deployed  
**Classification:** BOLA / IDOR — OWASP API1:2023

## 1. Executive Summary

This research examined a Broken Object Level Authorization (BOLA) condition in the vehicle-location API of OWASP crAPI. In the vulnerable implementation, an authenticated test user could obtain another test user's vehicle location by supplying that vehicle's UUID in the request path.

The root cause was identified in the Identity Service: the service retrieved a vehicle using the client-supplied UUID but did not enforce that the vehicle belonged to the authenticated user before returning location and owner information.

The remediation constrained the vehicle lookup by both vehicle UUID and the authenticated user's ID. A separate Community Service change removed the `vehicleid` field from the public author object to reduce unnecessary exposure of vehicle identifiers. This Community change is defense-in-depth and is not the authorization fix.

## 2. Scope and Environment

- Target: OWASP crAPI running locally in Docker.
- Frontend: `http://localhost:8888`.
- Email testing: MailHog at `http://localhost:8025`.
- Proxy/testing: Burp Suite Community Edition.
- Identity backend: Java / Spring Boot.
- Community backend: Go.
- Test identities: two locally created test users, Client A and Client B, each associated with a separate test vehicle.
- Source revision/commit: [record the exact source revision if available].

All tests were restricted to the researcher's local lab.

## 3. Vulnerability Discovery

### 3.1 Community response observation

The recent-posts API was inspected in Burp Suite:

```http
GET /community/api/v2/community/posts/recent
```

In the vulnerable lab response, the author data included a vehicle identifier associated with another test user. This identifier was then used to test the vehicle-location endpoint.

**Evidence:** `../evidence/before-patch/01-community-response.png` [add after baseline reconstruction].

### 3.2 Vehicle-location endpoint

The vehicle-location request observed for the authenticated test user used:

```http
GET /identity/api/v2/vehicle/{vehicleId}/location
Authorization: Bearer [REDACTED]
```

The response included the vehicle UUID, location coordinates, owner's name and owner's email address.

### 3.3 Proof of Concept

The test kept Client A's authenticated session/token and replaced only the vehicle UUID with the UUID belonging to Client B:

```http
GET /identity/api/v2/vehicle/[CLIENT_B_VEHICLE_UUID]/location HTTP/1.1
Host: localhost:8888
Authorization: Bearer [CLIENT_A_TOKEN_REDACTED]
```

**Observed vulnerable behavior:** [insert exact HTTP status and sanitized response from the reconstructed baseline].

The response should be included only after the vulnerable baseline has been rebuilt and the behavior re-observed. Do not recreate a screenshot from memory or present an after-patch response as before-patch evidence.

## 4. Root Cause Analysis

### 4.1 `VehicleController.java`

The controller accepted `carId` from the URL and delegated retrieval to the service. In the vulnerable implementation, the service call received the vehicle ID but did not receive or otherwise use the authenticated user's identity for object-level authorization.

### 4.2 `VehicleServiceImpl.java`

The vulnerable lookup was:

```java
vehicleDetails = vehicleDetailsRepository.findByUuid(carId);
```

This lookup selected a vehicle by UUID alone. The service subsequently read the owner to construct the response, but checking that an owner exists is not the same as checking that the owner is the authenticated requester.

### 4.3 `VehicleDetailsRepository.java`

The original repository method was:

```java
VehicleDetails findByUuid(UUID uuid);
```

This method constrained the lookup by UUID only; it did not constrain it by the vehicle owner.

### 4.4 Root cause statement

The endpoint authenticated the caller but did not enforce object-level authorization for the requested vehicle. The backend trusted the client-supplied vehicle UUID as the lookup criterion and returned the resource without confirming that the authenticated user owned it.

## 5. Impact

In the local lab, successful reproduction exposed another test user's:

- Vehicle location coordinates.
- Full name.
- Email address.

In a real deployment, unauthorized access to vehicle-location information could create privacy and physical-safety risks. The actual impact depends on the product, data sensitivity, and operational context.

## 6. Remediation

### 6.1 Identity Service — enforce ownership in the lookup

The patched implementation obtains the current user from the application's validated authentication mechanism and retrieves a vehicle only when both the requested UUID and owner ID match.

Conceptually, the lookup is equivalent to:

```sql
SELECT *
FROM vehicle_details
WHERE uuid = :vehicleUuid
  AND owner_id = :authenticatedUserId;
```

The owner ID must be derived on the server from the authenticated identity, not accepted from an untrusted client-supplied field.

The implementation used in this project: [paste the final, reviewed method signature and repository method, or link to the patch file].

### 6.2 Community Service — minimize response data

The Community response was changed to omit `vehicleid` from the public author object. This limits unnecessary disclosure of the identifier, but it is not a substitute for authorization. The Identity API must still enforce ownership even when an attacker already knows or obtains a UUID through another channel.

## 7. Verification

The patched Identity and Community images were rebuilt and deployed locally. The four authorization scenarios were tested in Burp Repeater.

| Test | Expected behavior | Observed status | Evidence |
|---|---|---|---|
| Client A requests Vehicle A | Allowed | [fill exact code] | `../evidence/after-patch/02-client-a-own-vehicle.png` |
| Client A requests Vehicle B | Denied | [fill exact code] | `../evidence/after-patch/03-client-a-other-vehicle.png` |
| Client B requests Vehicle B | Allowed | [fill exact code] | `../evidence/after-patch/04-client-b-own-vehicle.png` |
| Client B requests Vehicle A | Denied | [fill exact code] | `../evidence/after-patch/05-client-b-other-vehicle.png` |

Community response verification:

- The patched recent-posts response was inspected.
- The `vehicleid` field was absent from the author objects in the captured response.
- Evidence: `../evidence/after-patch/01-community-response.png`.

**Conclusion must be finalized only after exact response codes, response bodies and screenshots are attached.**

## 8. Limitations

- This was performed against a deliberately vulnerable local training application, not a production target.
- The Community identifier-removal change reduces discoverability but does not itself fix BOLA.
- The report's before-patch evidence will be added after reproducing the original vulnerable state from the corresponding unmodified source/image.
- Test results should be reproducible using the documented source revision, Docker configuration and test accounts recreated in the lab.

## 9. References

1. OWASP crAPI: https://owasp.org/www-project-crAPI/
2. OWASP crAPI source: https://github.com/OWASP/crAPI
3. OWASP API Security Top 10 — API1:2023: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
