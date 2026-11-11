# Broken Object Level Authorization (BOLA) in OWASP crAPI
## Vulnerability Analysis and Remediation Report

- **Researcher:** Khieu Tung Lam
- **Date:** November 2026
- **Target Application:** OWASP crAPI (Local Docker Deployment)
- **Vulnerability Category:** Broken Object Level Authorization (BOLA / IDOR) — OWASP API1:2023
- **Related Finding:** Excessive Data Exposure / BOPLA — OWASP API3:2023

---

## 1. Executive Summary

This report documents a Broken Object Level Authorization (BOLA) vulnerability in the vehicle location API of OWASP crAPI (`GET /identity/api/v2/vehicle/{carId}/location`). In the vulnerable version, any authenticated user could view another user's GPS coordinates and personal details simply by replacing the `carId` (vehicle UUID) in the request URL.

**Root Cause:** The Identity Service queried the database using only the client-supplied `carId` without verifying whether the authenticated user owned that vehicle. Additionally, the Community Service (`GET /community/api/v2/community/posts/recent`) leaked users' `vehicleid` and `email` in public forum posts, making it trivial to harvest target vehicle UUIDs.

**Remediation:**
1. **Identity Service (Primary Fix):** Extracted the authenticated user from the JWT token (`userService.getUserFromToken(request)`) and verified ownership (`vehicleDetails.getOwner().getId().equals(user.getId())`) before returning location data.
2. **Community Service (Defense-in-Depth):** Hid `email` and `vehicleid` from public JSON serialization (`json:"-"`) and removed the unnecessary database query for `vehicle_details` when loading post authors.

---

## 2. Lab Environment

- **Target:** OWASP crAPI (`https://github.com/OWASP/crAPI`) running locally via Docker Compose
- **Web Portal:** `http://localhost:8888`
- **Mail Server (MailHog):** `http://localhost:8025`
- **Testing Tool:** Burp Suite Community Edition (Proxy & Repeater)
- **Services Analyzed:**
  - **Identity Service:** Java / Spring Boot
  - **Community Service:** Go (Golang)
- **Test Accounts:**
  - **Client A (`clientA@example.com`):** Owns Vehicle A (`1d65151b-a248-4713-ae07-1c481f309d77`)
  - **Client B (`clientB@example.com`):** Owns Vehicle B (`323e8a0f-95cb-448b-a234-9c58c101a9cc`)

---

## 3. Vulnerability Discovery & Proof of Concept (Before Patch)

### 3.1. Step 1 — Harvesting Vehicle UUIDs via Community API

While browsing the community forum, Burp Suite captured the following request:

```http
GET /community/api/v2/community/posts/recent?limit=30&offset=0 HTTP/1.1
Host: localhost:8888
Authorization: Bearer <CLIENT_A_JWT>
```

**Observed Vulnerable Response (`200 OK`):**
Each post in the JSON response exposed the author's `email` and `vehicleid` in plain text, even though the UI only needed the author's `nickname`:

```json
"author": {
  "nickname": "Robot",
  "email": "robot001@example.com",
  "vehicleid": "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5",
  "profile_pic_url": "",
  "created_at": "2026-11-03T19:17:04.448Z"
}
```

- **Evidence:** [`../evidence/before-patch/01-community-response.png`](../evidence/before-patch/01-community-response.png)

### 3.2. Step 2 — Exploiting BOLA on the Vehicle Location Endpoint

Using **Client A's** JWT token, a request was sent to the vehicle location endpoint with **Client B's** vehicle UUID (`323e8a0f-95cb-448b-a234-9c58c101a9cc`):

```http
GET /identity/api/v2/vehicle/323e8a0f-95cb-448b-a234-9c58c101a9cc/location HTTP/1.1
Host: localhost:8888
Authorization: Bearer <CLIENT_A_JWT>
```

**Observed Vulnerable Response (`200 OK`):**
The server failed to check ownership and returned Client B's live GPS location, full name, and email address:

```json
{
  "carId": "323e8a0f-95cb-448b-a234-9c58c101a9cc",
  "vehicleLocation": {
    "id": 1,
    "latitude": "32.778889",
    "longitude": "-91.919243"
  },
  "fullName": "client B",
  "email": "clientB@example.com"
}
```

- **Evidence:** [`../evidence/before-patch/02-bola-vehicle-location-poc.png`](../evidence/before-patch/02-bola-vehicle-location-poc.png)

---

## 4. Root Cause Analysis

### 4.1. Identity Service (`Java / Spring Boot`)

1. **Controller (`VehicleController.java`):**
   `getLocationBOLA(@PathVariable("carId") UUID carId)` only accepted `carId` from the URL path and did not pass `HttpServletRequest` (which carries the authenticated user's JWT) to the service layer.
2. **Service (`VehicleServiceImpl.java`):**
   The service looked up the vehicle solely by UUID:
   ```java
   vehicleDetails = vehicleDetailsRepository.findByUuid(carId);
   ```
   It checked `if (vehicleDetails.getOwner() != null)` to build the response, but **never compared the owner ID with the currently logged-in user's ID**.

### 4.2. Community Service (`Go`)

In `services/community/api/models/user.go`, the `Author` struct serialized `Email` and `VehicleID` directly into JSON (`json:"email"` and `json:"vehicleid"`), and `FindAuthorByEmail` explicitly queried the `vehicle_details` table to populate `vehicleID` for every post author.

---

## 5. Impact

An authenticated attacker can:
- Harvest valid vehicle UUIDs of other users from public forum posts.
- Track the real-time GPS coordinates (`latitude`, `longitude`) of any user's vehicle.
- Access personal information (`fullName`, `email`) linked to the vehicle owner.

---

## 6. Remediation

Full unified diffs are available in [`../patches/identity-service.patch`](../patches/identity-service.patch) and [`../patches/community-service.patch`](../patches/community-service.patch).

### 6.1. Fix 1 — Enforce Object-Level Authorization in Identity Service

#### 1. Pass `HttpServletRequest` in `VehicleController.java`
**File:** `services/identity/src/main/java/com/crapi/controller/VehicleController.java`

```java
// Before
@GetMapping("/vehicle/{carId}/location")
public ResponseEntity<?> getLocationBOLA(@PathVariable("carId") UUID carId) {
    VehicleLocationResponse vehicleDetails = vehicleService.getVehicleLocation(carId);
    ...
}

// After
@GetMapping("/vehicle/{carId}/location")
public ResponseEntity<?> getLocationBOLA(
    @PathVariable("carId") UUID carId,
    HttpServletRequest request) {

    VehicleLocationResponse vehicleDetails =
        vehicleService.getVehicleLocation(carId, request);
    ...
}
```

#### 2. Update Method Signature in `VehicleService.java`
**File:** `services/identity/src/main/java/com/crapi/service/VehicleService.java`

```java
// Before
VehicleLocationResponse getVehicleLocation(UUID carId);

// After
VehicleLocationResponse getVehicleLocation(UUID carId, HttpServletRequest request);
```

#### 3. Verify Vehicle Ownership in `VehicleServiceImpl.java`
**File:** `services/identity/src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java`

```java
@Transactional
@Override
public VehicleLocationResponse getVehicleLocation(
        UUID carId, HttpServletRequest request) {

    VehicleDetails vehicleDetails = null;
    VehicleLocationResponse vehicleLocationForm = null;
    UserDetails userDetails = null;

    try {
        // 1. Identify the authenticated user from the JWT token
        User user = userService.getUserFromToken(request);

        // 2. Fetch the requested vehicle
        vehicleDetails = vehicleDetailsRepository.findByUuid(carId);

        if (vehicleDetails != null
                && vehicleDetails.getOwner() != null
                && user != null) {

            // 3. Enforce ownership: vehicle owner ID must match authenticated user ID
            if (vehicleDetails.getOwner().getId().equals(user.getId())) {
                userDetails = userDetailsRepository.findByUser_id(
                    vehicleDetails.getOwner().getId()
                );

                vehicleLocationForm = new VehicleLocationResponse(
                    carId,
                    (userDetails != null ? userDetails.getName() : null),
                    (userDetails != null ? userDetails.getUser().getEmail() : null),
                    vehicleDetails.getVehicleLocation()
                );

                return vehicleLocationForm;
            } else {
                log.warn(
                    "BOLA attempt detected: User {} tried to access vehicle {}",
                    user.getEmail(),
                    carId
                );
            }
        }
    } catch (Exception exception) {
        log.error("Fail to get vehicle location-> Message: {}", exception);
    }

    return null;
}
```

When ownership verification fails, the service logs a warning and returns `null`, causing the controller to return `HTTP 404 Not Found` (`Sorry we didn't get vehicle for user: `). Unit tests in `VehicleServiceImplTest.java` were also updated to mock `userService.getUserFromToken(request)` and cover both authorized and unauthorized access.

---

### 6.2. Fix 2 — Minimize Data Exposure in Community Service

**File:** `services/community/api/models/user.go`

1. Updated `Author` struct tags so `Email` and `VehicleID` are omitted from JSON/BSON responses:
   ```go
   type Author struct {
       Nickname  string    `gorm:"size:255;not null;unique" json:"nickname"`
       Email     string    `gorm:"size:100;not null;unique" json:"-"`
       VehicleID string    `gorm:"size:100;not null;unique" json:"-" bson:"-"`
       Picurl    string    `gorm:"size:30000;not null;unique" json:"profile_pic_url"`
       CreatedAt time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"`
   }
   ```
2. Removed the unnecessary `vehicle_details` query inside `FindAuthorByEmail`.

---

## 7. Verification & Regression Testing (After Patch)

After applying the patches, the Docker images were rebuilt and redeployed:

```powershell
# Rebuild Identity Service
cd services/identity
docker build -t crapi/crapi-identity:latest .

# Rebuild Community Service
cd ../community
docker build -t crapi/crapi-community:latest .

# Restart containers
cd ../../deploy/docker
docker compose -f docker-compose.yml --compatibility up -d
```

### 7.1. BOLA Authorization Test Cases (Identity API)

Two test cases were executed in Burp Repeater using **Client A's** authenticated session:

| Test Case | Scenario | Request Path | Expected | Observed Status | Observed Response | Evidence |
|---|---|---|---|---|---|---|
| **TC1** | Client A requests **Client A's** own vehicle | `GET /identity/api/v2/vehicle/1d65151b-a248-4713-ae07-1c481f309d77/location` | Allowed | `200 OK` | Returns Client A's vehicle location & owner info | [`02-client-a-own-vehicle.png`](../evidence/after-patch/02-client-a-own-vehicle.png) |
| **TC2** | Client A requests **Client B's** vehicle | `GET /identity/api/v2/vehicle/323e8a0f-95cb-448b-a234-9c58c101a9cc/location` | Denied | `404 Not Found` | `{"message":"Sorry we didn't get vehicle for user: ","status":0}` | [`03-client-a-other-vehicle.png`](../evidence/after-patch/03-client-a-other-vehicle.png) |

### 7.2. Data Minimization Check (Community API)

| Check | Endpoint | Observed Status | Observed Result | Evidence |
|---|---|---|---|---|
| Recent Posts API | `GET /community/api/v2/community/posts/recent` | `200 OK` | `author` object only contains `nickname`, `profile_pic_url`, and `created_at`. Both `email` and `vehicleid` are removed. | [`04-community-no-vehicleid.png`](../evidence/after-patch/04-community-no-vehicleid.png) |

---

## 8. Limitations & Conclusion

- **Lab Scope:** All testing and patching were conducted against a local OWASP crAPI training environment.
- **Defense-in-Depth:** Removing `vehicleid` from the Community API reduces UUID leakage, but the actual BOLA fix is the ownership check inside the Identity Service.
- **Conclusion:** By verifying that the authenticated user owns the requested vehicle before returning location data, the BOLA vulnerability (`OWASP API1:2023`) is resolved without breaking normal functionality for legitimate vehicle owners.

---

## 9. References

1. OWASP crAPI Project: https://owasp.org/www-project-crAPI/
2. OWASP crAPI Repository: https://github.com/OWASP/crAPI
3. OWASP API Security Top 10 (API1:2023 — Broken Object Level Authorization): https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
