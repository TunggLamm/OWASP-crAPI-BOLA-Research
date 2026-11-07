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

## 7. Remediation

### 7.1. Overall Remediation Strategy

As discussed in the previous sections, the identified exploitation scenario involved a primary Broken Object Level Authorization (BOLA) vulnerability in the Identity Service, accompanied by unnecessary exposure of user-related information through the Community Service.

**1. Primary Vulnerability – Broken Object Level Authorization (BOLA / OWASP API1:2023) in the Identity Service**

The endpoint `GET /identity/api/v2/vehicle/{carId}/location` retrieved vehicle information using the client-supplied `carId` without verifying whether the authenticated requester was authorized to access the requested vehicle.

**2. Related Information Exposure – Potential Broken Object Property Level Authorization (BOPLA / OWASP API3:2023) in the Community Service**

The endpoint `GET /community/api/v2/community/posts/recent` returned unnecessary author-related properties, including `vehicleid` (the vehicle UUID) and `email`.

Although these properties were not required for displaying public community posts, their inclusion exposed additional information about other users and facilitated the discovery of vehicle UUIDs.

The exposure of these identifiers should not be considered a standalone BOLA vulnerability. However, it provided useful information that made the primary vulnerability easier to exploit.

Following the principles of **Defense in Depth** and **Data Minimization**, remediation was implemented across both services:

- **Identity Service – Object-Level Authorization:** Retrieve the authenticated user from the JWT associated with the incoming HTTP request and verify that the user's ID matches the vehicle owner's ID before returning vehicle location information.
- **Community Service – Data Minimization:** Prevent unnecessary user attributes, specifically `vehicleid` and `email`, from being included in public JSON responses. The unnecessary database lookup used to retrieve the vehicle UUID was also removed from the author lookup logic.

The Identity Service authorization check is the primary security fix. The Community Service modification provides an additional layer of data protection.

---

### 7.2. Identity Service Remediation – Fixing BOLA

#### Step 1: Add HttpServletRequest to the Controller Layer

**File:** `services/identity/src/main/java/com/crapi/controller/VehicleController.java`

In the original implementation, the `getLocationBOLA` method only received the `carId` from the URL path.

To identify the authenticated requester, an additional `HttpServletRequest request` parameter was introduced. This allows the incoming HTTP request, including its `Authorization: Bearer <JWT>` header, to be passed to the service layer.

**Before remediation (Vulnerable Code):**

```java
@GetMapping("/vehicle/{carId}/location")
public ResponseEntity<?> getLocationBOLA(@PathVariable("carId") UUID carId) {
    VehicleLocationResponse vehicleDetails =
        vehicleService.getVehicleLocation(carId);

    if (vehicleDetails != null)
        return ResponseEntity.ok().body(vehicleDetails);
    else
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
            .body(new CRAPIResponse(
                UserMessage.DID_NOT_GET_VEHICLE_FOR_USER
            ));
}
```

**After remediation (Patched Code):**

```java
@GetMapping("/vehicle/{carId}/location")
public ResponseEntity<?> getLocationBOLA(
    @PathVariable("carId") UUID carId,
    HttpServletRequest request) {

    VehicleLocationResponse vehicleDetails =
        vehicleService.getVehicleLocation(carId, request);

    if (vehicleDetails != null)
        return ResponseEntity.ok().body(vehicleDetails);
    else
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
            .body(new CRAPIResponse(
                UserMessage.DID_NOT_GET_VEHICLE_FOR_USER
            ));
}
```

The main change is that the controller now forwards the HTTP request to the service layer, allowing the service to identify the currently authenticated user through the application's existing authentication mechanism.

#### Step 2: Update the VehicleService Interface

**File:** `services/identity/src/main/java/com/crapi/service/VehicleService.java`

The method signature was updated to accept an additional `HttpServletRequest` parameter.

**Before remediation:**

```java
VehicleLocationResponse getVehicleLocation(UUID carId);
```

**After remediation:**

```java
VehicleLocationResponse getVehicleLocation(
    UUID carId,
    HttpServletRequest request
);
```

This change allows the authenticated request context to be passed from the controller to the service implementation.

#### Step 3: Implement Ownership Verification in the Service Layer

**File:** `services/identity/src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java`

The main security improvement was implemented in the `getVehicleLocation` method.

The application now calls `userService.getUserFromToken(request)` to retrieve the user associated with the JWT in the incoming request.

After retrieving the requested vehicle using its UUID, the service compares the vehicle owner's ID with the authenticated user's ID.

If the IDs do not match, the application rejects the request by returning `null`. The controller subsequently responds with HTTP `404 Not Found`, avoiding unnecessary disclosure of whether the requested vehicle exists.

The application also records a warning message when an authenticated user attempts to access a vehicle belonging to another user.

**Before remediation (Vulnerable Code):**

```java
@Transactional
@Override
public VehicleLocationResponse getVehicleLocation(UUID carId) {
    VehicleDetails vehicleDetails = null;
    VehicleLocationResponse vehicleLocationForm = null;
    UserDetails userDetails = null;
    Random random = new Random();

    try {
        vehicleDetails = vehicleDetailsRepository.findByUuid(carId);

        if (vehicleDetails != null) {
            if (vehicleDetails.getOwner() != null) {
                userDetails = userDetailsRepository.findByUser_id(
                    vehicleDetails.getOwner().getId()
                );

                vehicleLocationForm =
                    new VehicleLocationResponse(
                        carId,
                        (userDetails != null ? userDetails.getName() : null),
                        (userDetails != null
                            ? userDetails.getUser().getEmail() : null),
                        vehicleDetails.getVehicleLocation()
                    );

                return vehicleLocationForm;
            }
        }
    } catch (Exception exception) {
        log.error("Fail to get vehicle location-> Message: {}", exception);
    }

    return null;
}
```

**After remediation (Patched Code):**

```java
@Transactional
@Override
public VehicleLocationResponse getVehicleLocation(
        UUID carId, HttpServletRequest request) {

    VehicleDetails vehicleDetails = null;
    VehicleLocationResponse vehicleLocationForm = null;
    UserDetails userDetails = null;

    try {
        // Retrieve the authenticated user from the request JWT
        User user = userService.getUserFromToken(request);

        // Retrieve the requested vehicle
        vehicleDetails = vehicleDetailsRepository.findByUuid(carId);

        if (vehicleDetails != null
                && vehicleDetails.getOwner() != null
                && user != null) {

            // Verify that the authenticated user owns the requested vehicle
            if (vehicleDetails.getOwner().getId().equals(user.getId())) {

                userDetails = userDetailsRepository.findByUser_id(
                    vehicleDetails.getOwner().getId()
                );

                vehicleLocationForm =
                    new VehicleLocationResponse(
                        carId,
                        (userDetails != null
                            ? userDetails.getName() : null),
                        (userDetails != null
                            ? userDetails.getUser().getEmail() : null),
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
        log.error(
            "Fail to get vehicle location-> Message: {}",
            exception
        );
    }

    return null;
}
```

**Explanation of the security improvement:**

The original implementation retrieved vehicle information solely by its UUID.

The patched implementation introduces an additional ownership verification step:

```java
vehicleDetails.getOwner().getId().equals(user.getId())
```

This comparison ensures that the vehicle owner matches the currently authenticated user.

Consequently:

- If the authenticated user owns the requested vehicle, the application returns the vehicle location.
- If the requested vehicle belongs to another user, the application denies access and returns no vehicle information.
- If the vehicle does not exist, has no valid owner, or the authenticated user cannot be retrieved, the service also returns no vehicle information.

This establishes object-level authorization before any vehicle information is returned to the client.

#### Step 4: Update Unit Tests for Authorization Logic

**File:** `services/identity/src/test/java/com/crapi/service/Impl/VehicleServiceImplTest.java`

The existing unit tests were updated to reflect the modified `getVehicleLocation` method signature and the newly introduced ownership verification logic.

The test suite was modified to mock the `userService.getUserFromToken(request)` method, allowing the authenticated user to be controlled during individual test scenarios.

Additional test coverage was introduced to verify that a user cannot retrieve vehicle information belonging to another account.

The updated tests cover the following authorization scenarios:

- **Authorized Access:** The authenticated user owns the requested vehicle, and the service returns the corresponding vehicle location response.
- **Unauthorized Access:** The authenticated user attempts to retrieve a vehicle owned by another user, and the service denies access by returning `null`.

These changes help validate the ownership verification logic independently of the HTTP controller and reduce the risk of introducing authorization regressions in future modifications.

---

### 7.3. Community Service Remediation – Reducing Unnecessary Data Exposure

**File:** `services/community/api/models/user.go`

The Community Service response originally included author-related properties such as `email` and `vehicleid`.

Although these properties were not necessary for displaying public community posts, they were included in the serialized author object.

To minimize unnecessary data exposure, the `Author` structure and the author lookup logic were modified.

#### Step 1: Modify the Author Struct

The JSON struct tags were updated to prevent the `Email` and `VehicleID` fields from appearing in public JSON responses.

For `VehicleID`, the BSON struct tag was also configured to exclude the field from BSON serialization and deserialization.

**Before remediation (Vulnerable Code):**

```go
// Author model
type Author struct {
    Nickname  string    `gorm:"size:255;not null;unique" json:"nickname"`
    Email     string    `gorm:"size:100;not null;unique" json:"email"`
    VehicleID string    `gorm:"size:100;not null;unique" json:"vehicleid"`
    Picurl    string    `gorm:"size:30000;not null;unique" json:"profile_pic_url"`
    CreatedAt time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"`
}
```

**After remediation (Patched Code):**

```go
// Author model
type Author struct {
    Nickname  string    `gorm:"size:255;not null;unique" json:"nickname"`
    Email     string    `gorm:"size:100;not null;unique" json:"-"`
    VehicleID string    `gorm:"size:100;not null;unique" json:"-" bson:"-"`
    Picurl    string    `gorm:"size:30000;not null;unique" json:"profile_pic_url"`
    CreatedAt time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"`
}
```

The `json:"-"` tag prevents the corresponding field from being included in JSON output.

The `bson:"-"` tag additionally instructs BSON serializers to ignore the `VehicleID` field.

These tags control serialization behavior; they do not, by themselves, delete existing database records or remove the underlying struct fields.

#### Step 2: Remove the Unnecessary Vehicle UUID Lookup

The original `FindAuthorByEmail` function queried the `vehicle_details` table to retrieve the vehicle UUID associated with an author.

This lookup was unnecessary for constructing the public community post response.

**Before remediation (Vulnerable Code):**

```go
nickname = name

row2 := db.Table("vehicle_details").
    Where("owner_id = ?", id).
    Select("uuid").Row()

err = row2.Scan(&uuid)
if err != nil {
    log.Println("Error in FindAuthorByEmail", err)
}

vehicleID = uuid

return number, err
```

**After remediation (Patched Code):**

```go
nickname = name

// Removed the unnecessary vehicle UUID lookup because
// the community post response does not require this information.

// row2 := db.Table("vehicle_details").
//     Where("owner_id = ?", id).Select("uuid").Row()
// err = row2.Scan(&uuid)
// if err != nil {
//     log.Println("Error in FindAuthorByEmail", err)
// }
// vehicleID = uuid

return number, err
```

By removing this database lookup, the Community Service no longer retrieves the vehicle UUID solely for populating the author information.

Combined with the updated JSON serialization tags, this modification minimizes the exposure of unnecessary user-related properties in community responses.

**Security Note:** This Community Service modification is an additional data-minimization measure. It does not replace the mandatory object-level authorization check in the Identity Service. Even when a vehicle UUID is known, the Identity Service must independently verify the requester's authorization.

---

### 7.4. Post-Remediation Verification

After modifying the source code, new Docker images were built for the Identity Service and Community Service.

The updated containers were then recreated using Docker Compose.

**Identity Service image build:**

```powershell
cd services/identity

docker build -t crapi/crapi-identity:latest .
```

**Community Service image build:**

```powershell
cd services/community

docker build -t crapi/crapi-community:latest .
```

**Container deployment:**

```powershell
cd deploy/docker

docker compose -f docker-compose.yml --compatibility up -d
```

The updated services and their dependencies were checked using:

```powershell
docker compose ps
```

Both the Identity Service and Community Service were required to reach a healthy running state before further security testing.

#### 7.4.1. Community API Response Verification

**Endpoint:**

`GET /community/api/v2/community/posts/recent`

The API response was inspected again after deploying the patched Community Service.

The author objects contained only the required public attributes:

- `nickname`
- `profile_pic_url`
- `created_at`

The `email` and `vehicleid` fields were no longer present in the JSON response.

The community post data remained accessible, indicating that the modification did not prevent the endpoint from returning its intended public content.

#### 7.4.2. Identity API Authorization Verification

The patched Identity Service was tested using two separate user accounts and two independently owned vehicles.

The following test cases were executed using Burp Suite Repeater.

| Test Case | Authenticated User | Requested Vehicle | Expected Result |
|---|---|---|---|
| 1 | Client A | Client A's vehicle | 200 OK |
| 2 | Client A | Client B's vehicle | 404 Not Found |
| 3 | Client B | Client B's vehicle | 200 OK |
| 4 | Client B | Client A's vehicle | 404 Not Found |

**Observed Results:**

1. **Authorized Access:** When a user requested a vehicle owned by their own account, the application successfully verified the ownership relationship and returned HTTP `200 OK` with the corresponding vehicle location information.

2. **Unauthorized Cross-User Access:** When an authenticated user supplied the UUID of a vehicle owned by another user, the Identity Service rejected the request and returned HTTP `404 Not Found`.

3. **Response Consistency:** The application continued to support legitimate vehicle location requests while preventing unauthorized cross-user access.

All four authorization scenarios were successfully tested using the two test accounts.

The application also recorded warning messages for detected cross-user access attempts through the Identity Service logging mechanism.

#### 7.4.3. Unit and Manual Regression Testing

Two complementary testing approaches were used to verify the remediation:

**Unit Testing**

The Identity Service unit tests were updated to cover the modified vehicle location retrieval logic. The authenticated user was mocked through `userService.getUserFromToken(request)`, allowing the ownership verification behavior to be tested independently of the HTTP layer.

**Manual API Regression Testing**

Burp Suite Repeater was used to test the actual HTTP behavior of the deployed application with two independent accounts.

The four cross-user authorization scenarios described above were successfully reproduced and verified.

Together, these testing approaches provide coverage of both the service-level authorization logic and the externally observable API behavior.

#### 7.4.4. Overall Verification Summary

The remediation was considered successful for the tested scenarios because:

- Legitimate vehicle owners retained access to their own vehicle information.
- Authenticated users could no longer retrieve vehicle location information belonging to other users through the tested endpoint.
- The Community API no longer exposed the unnecessary `vehicleid` and `email` properties in its public JSON response.
- The Identity Service maintained its expected behavior for authorized requests while rejecting unauthorized cross-user access.

The results demonstrate that the implemented ownership verification successfully mitigated the tested BOLA scenarios in the local OWASP crAPI environment.

---

### 7.5. Remediation Limitations and Additional Considerations

The implemented authorization check addresses the identified BOLA vulnerability in the vehicle location endpoint.

However, object-level authorization should be consistently enforced across all API endpoints that access user-owned resources.

The Community Service data-minimization changes reduce unnecessary exposure of vehicle identifiers but should not be considered a standalone BOLA mitigation.

Further improvements may include:

- Using repository queries that constrain both the vehicle UUID and authenticated owner ID, reducing the retrieval of unauthorized entities.
- Maintaining consistent object-level authorization checks across all vehicle-related operations.
- Expanding automated unit and integration tests for cross-user access scenarios.
- Reviewing other API responses for unnecessary exposure of sensitive user properties.
- Monitoring authorization failures without logging sensitive authentication credentials.

The remediation should therefore be understood as a verified fix for the tested vehicle location endpoint and associated Community response, rather than proof that every potential authorization issue throughout the entire application has been eliminated.

## 8. Verification

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

## 9. Limitations

- This was performed against a deliberately vulnerable local training application, not a production target.
- The Community identifier-removal change reduces discoverability but does not itself fix BOLA.
- The report's before-patch evidence will be added after reproducing the original vulnerable state from the corresponding unmodified source/image.
- Test results should be reproducible using the documented source revision, Docker configuration and test accounts recreated in the lab.

## 10. References

1. OWASP crAPI: https://owasp.org/www-project-crAPI/
2. OWASP crAPI source: https://github.com/OWASP/crAPI
3. OWASP API Security Top 10 — API1:2023: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
